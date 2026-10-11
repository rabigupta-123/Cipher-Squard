import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Request and response hardening for the loopback analysis service.
 *
 * Every limit in this file exists because the input is hostile. A body arrives over a socket from
 * a process on the same host, which means a malformed request, an absurd Content-Length, a
 * traversal sequence or a header injection attempt is a realistic input rather than a theoretical
 * one. Nothing here trusts the caller: the declared length, the actual stream, the declared
 * Content-Type and the request path are all treated as claims to be checked.
 *
 * Design rules used throughout:
 *
 *   - Reject rather than coerce. A request that is not exactly what the endpoint accepts is an
 *     error, not something to be repaired into plausibility.
 *   - Every bound is named and stated in the error response, so a client can tell "too big" from
 *     "malformed" without reading a log.
 *   - Nothing user-controlled is ever copied into a response header. {@link #send} rejects header
 *     values containing CR or LF, which closes response splitting and CRLF injection.
 *   - Errors are JSON, always, so a client never has to parse an HTML error page from a server
 *     that only ever emits JSON.
 *
 * This class is transport only. It holds no domain state, opens no files and makes no
 * authentication decisions; those belong to {@link App}.
 */
public final class Http {

    // ==================================================================
    // Limits
    // ==================================================================

    /** Ceiling on a request body. Matches {@link Config#MAX_REQUEST_BODY_BYTES}. */
    public static final long MAX_BODY_BYTES = Config.MAX_REQUEST_BODY_BYTES;

    /**
     * Ceiling on a single request line plus all request headers, in bytes.
     *
     * The JDK server already caps header size, but it caps each header and the count separately.
     * A request that is well under both caps individually can still be large in aggregate, and
     * this is a total budget so the aggregate is bounded too.
     */
    public static final int MAX_REQUEST_HEADER_BYTES = 32 * 1024;

    /** Ceiling on the number of request headers accepted from one client. */
    public static final int MAX_REQUEST_HEADERS = 64;

    /** Ceiling on the decoded length of any single header value. */
    public static final int MAX_HEADER_VALUE_CHARS = 8 * 1024;

    /** Ceiling on a request path, before decoding. */
    public static final int MAX_PATH_CHARS = 2 * 1024;

    /** Ceiling on a query string, before decoding. */
    public static final int MAX_QUERY_CHARS = 4 * 1024;

    /** Ceiling on a single query-string parameter's decoded value. */
    public static final int MAX_QUERY_VALUE_CHARS = 512;

    /** Ceiling on the number of query parameters parsed from one request. */
    public static final int MAX_QUERY_PARAMS = 32;

    /** Ceiling on a percent-decoded request body interpreted as text. */
    public static final int MAX_BODY_TEXT_CHARS = 8 * 1024 * 1024;

    private Http() {
    }

    // ==================================================================
    // Failure type
    // ==================================================================

    /**
     * A request that must be refused, carrying the status code and a stable machine-readable
     * reason.
     *
     * A typed failure is used instead of returning null so that no call site can forget to check.
     * {@link #reason} is a fixed token from a closed set, never caller-supplied text, because it
     * is echoed into the JSON body.
     */
    public static final class RequestException extends Exception {
        private static final long serialVersionUID = 1L;
        public final int status;
        public final String reason;

        public RequestException(int status, String reason, String detail) {
            super(detail == null ? reason : detail);
            this.status = status;
            this.reason = reason;
        }
    }

    // ==================================================================
    // Response
    // ==================================================================

    /**
     * A response under construction.
     *
     * Headers are collected in insertion order and validated on {@link #send}, not on add, so a
     * route can assemble a response freely and still cannot inject a header by accident.
     */
    public static final class Response {
        public int status = 200;
        public byte[] body = new byte[0];
        public String contentType = "application/json; charset=utf-8";
        private final Map<String, String> headers = new LinkedHashMap<>();

        public Response status(int s) {
            this.status = s;
            return this;
        }

        /** Sets the body as UTF-8 encoded text. */
        public Response text(String s) {
            this.body = (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
            return this;
        }

        /** Sets the body directly as raw bytes, preserving exact binary representation. */
        public Response bytes(byte[] b) {
            this.body = (b == null ? new byte[0] : b);
            return this;
        }

        public Response json(Object value) {
            this.contentType = "application/json; charset=utf-8";
            return text(Json.write(value));
        }

        public Response header(String name, String value) {
            if (name == null || value == null) return this;
            headers.put(name, value);
            return this;
        }

        public Map<String, String> headers() {
            return headers;
        }

        // ---- the static-document exception ---------------------------------
        //
        // Every other route in this service returns JSON or STIX, so `send` pins the
        // Content-Type and a `default-src 'none'` CSP that a route cannot weaken. That is the
        // right default, but it also means this class cannot express the one body that *is* a
        // document: the analyst console shipped as a single self-contained HTML file.
        //
        // Rather than let a route set Content-Type or CSP freely -- which would make every
        // response body attacker-relabelable and turn the API's XSS posture into a suggestion --
        // the capability is opt-in per response and still lands on a fixed policy computed here.
        // A route that sets `documentCsp` gets:
        //   * Content-Type text/html, and
        //   * exactly the CSP string the route supplies, which must be a nonce policy.
        // Nothing else changes: nosniff, DENY, no-store and no-referrer still apply.
        //
        // The risk this admits is narrow and deliberate: a route able to set `documentCsp`
        // could serve markup that its own nonce unlocks. Only the static console route sets it,
        // it serves a fixed file from disk rather than anything a caller supplied, and the nonce
        // is generated per request here rather than by the route.

        /** Non-null marks this response as the static HTML console. */
        public String documentCsp;

        /**
         * Marks the body as the analyst console document.
         *
         * @param csp a nonce policy; must contain {@code script-src 'nonce-...'} or the
         *            response is downgraded back to the API policy and the nonce will not
         *            execute, which is a safe failure.
         */
        public Response document(String csp) {
            this.contentType = "text/html; charset=utf-8";
            this.documentCsp = csp;
            return this;
        }
    }

    // ==================================================================
    // Response emission
    // ==================================================================

    /**
     * Writes a response with the standard hardening headers applied.
     *
     * The security headers are set here rather than at each route so that a new route cannot ship
     * without them. {@code Server} and {@code Date} are suppressed: the JDK server's default
     * banner advertises the exact implementation and version, which is free reconnaissance, and a
     * response that carries no identifying header is a smaller surface.
     */
    public static void send(HttpExchange ex, Response r) throws IOException {
        try {
            Headers h = ex.getResponseHeaders();

            // Route headers are applied first so the security headers below always have the last
            // word. A handler that set "Cache-Control: public" must not be able to weaken the
            // no-store invariant, and must not be able to relabel its own body as HTML.
            for (Map.Entry<String, String> e : r.headers.entrySet()) {
                String name = e.getKey();
                String value = e.getValue();
                // A value carrying CR or LF would let a caller append headers of its own. The
                // response is already fully determined at this point, so the only correct action
                // is to refuse to send the header at all.
                if (name.indexOf('\r') >= 0 || name.indexOf('\n') >= 0
                        || name.indexOf(':') >= 0 || name.isEmpty()) {
                    continue;
                }
                if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                    continue;
                }
                // Names this class owns. Content-Type decides how a browser treats a body, and
                // the rest are security invariants, so a route cannot set them.
                if (isReserved(name)) {
                    continue;
                }
                h.set(name, value);
            }

            h.set("Content-Type", r.contentType);

            // Required by the brief, and each earns its place:
            //   nosniff  - stop the browser guessing a type and executing a body as script
            //   DENY     - this is an API; there is no frame that should ever embed it
            //   no-store - a verdict is not cacheable evidence, and a cached one cannot be revoked
            //   CSP      - this service returns JSON and STIX, never markup or script. `default-src
            //              'none'` denies everything, and it is a real instruction to a browser
            //              rather than an assumption that the payload happens to be inert. 'unsafe-
            //              inline' is deliberately absent, because there is nothing to allow.
            h.set("X-Content-Type-Options", "nosniff");
            h.set("X-Frame-Options", "DENY");
            h.set("Access-Control-Allow-Origin", "*");
            h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            h.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Demo-Mode");
            h.set("Content-Security-Policy", documentPolicy(r));
            h.set("Cache-Control", "no-store");
            h.set("Pragma", "no-cache");
            h.set("Referrer-Policy", "no-referrer");

            // Content-Length must describe the body actually written, and must not be set twice.
            h.set("Content-Length", Integer.toString(r.body.length));

            int code = r.status;
            // 204 and 304 must not carry a body; the JDK server enforces this but an explicit
            // guard keeps the invariant local and testable.
            if (code == 204 || code == 304) {
                r.body = new byte[0];
                h.set("Content-Length", "0");
            }

            // HEAD is a GET that returns no body but identical headers, so Content-Length
            // describes the body a GET would have produced.
            boolean head = "HEAD".equalsIgnoreCase(ex.getRequestMethod());

            ex.sendResponseHeaders(code, head ? -1 : r.body.length);
            if (!head && r.body.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(r.body);
                }
            } else if (!head) {
                ex.getResponseBody().close();
            }
        } finally {
            ex.close();
        }
    }

    /** Header names {@link #send} owns, which a route may not set or override. */
    private static boolean isReserved(String name) {
        return "content-type".equalsIgnoreCase(name)
                || "content-length".equalsIgnoreCase(name)
                || "x-content-type-options".equalsIgnoreCase(name)
                || "x-frame-options".equalsIgnoreCase(name)
                || "content-security-policy".equalsIgnoreCase(name)
                || "cache-control".equalsIgnoreCase(name)
                || "pragma".equalsIgnoreCase(name)
                || "referrer-policy".equalsIgnoreCase(name);
    }

    /**
     * The CSP to send with a response.
     *
     * The API policy is {@code default-src 'none'}: this service returns JSON and STIX, never
     * markup or script, so everything is denied and there is nothing to allow.
     *
     * The one exception is the analyst console, a self-contained HTML document that must be
     * allowed to run its own inline script and style. It is still locked down: the policy must
     * be a nonce policy naming the exact per-request nonce, connections are confined to this
     * same origin, and framing, base-uri and form submission are all denied. A policy that does
     * not name a script nonce is refused, which leaves the console inert rather than unsafe --
     * a deliberate fail-closed choice, because a console that silently stops working is a
     * visible bug while a console running under a permissive policy is an invisible one.
     */
    private static String documentPolicy(Response r) {
        String api = "default-src 'none'; frame-ancestors 'none'";
        String csp = r.documentCsp;
        if (csp == null) return api;
        if (csp.indexOf('\r') >= 0 || csp.indexOf('\n') >= 0) return api;
        if (!csp.contains("script-src 'nonce-")) return api;
        return csp + "; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    }

    /**
     * Builds a JSON error response.
     *
     * The message is a fixed string per reason. The caller's own text is deliberately not echoed:
     * an error body that reflects hostile input is a reflected-content problem even with
     * {@code nosniff}, and it is not something a caller needs in order to fix a request.
     */
    public static Response error(int status, String reason, String message) {        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("error", reason);
        m.put("message", message);
        m.put("status", status);
        return new Response().status(status).json(m);
    }

    public static Response error(RequestException e) {
        return error(e.status, e.reason, e.getMessage());
    }

    // ==================================================================
    // Request inspection
    // ==================================================================

    /**
     * The bounded, validated view of one request.
     *
     * Every field is final and already checked. A route reads this and never touches the
     * underlying exchange, so no route can accidentally bypass a limit.
     */
    public static final class Request {
        public final String method;
        public final String path;
        public final InetSocketAddress remote;
        public final Map<String, String> query;
        public final byte[] body;
        public final String bodyText;

        Request(String method, String path, InetSocketAddress remote,
                Map<String, String> query, byte[] body, String bodyText) {
            this.method = method;
            this.path = path;
            this.remote = remote;
            this.query = query;
            this.body = body;
            this.bodyText = bodyText;
        }

        /** The client address as a literal string. Never used as a trust decision on its own. */
        public String remoteAddress() {
            if (remote == null || remote.getAddress() == null) return "unknown";
            return remote.getAddress().getHostAddress();
        }

        public String queryParam(String name) {
            return query.get(name);
        }
    }

    /**
     * Validates and materialises a request.
     *
     * Order matters and is deliberate: cheap structural checks run before the body is read, so a
     * malformed request is refused without ever pulling its body across the socket.
     */
    public static Request read(HttpExchange ex) throws RequestException, IOException {
        String method = ex.getRequestMethod();
        if (method == null || method.isEmpty() || method.length() > 16) {
            throw new RequestException(400, "bad_request", "missing or oversized HTTP method");
        }

        InetSocketAddress remote = ex.getRemoteAddress();

        // --- path ---
        String rawPath = ex.getRequestURI().getRawPath();
        String path = canonicalPath(rawPath);

        // --- headers ---
        checkHeaderBudget(ex);

        // --- query ---
        Map<String, String> query = parseQuery(ex.getRequestURI().getRawQuery());

        // --- body ---
        byte[] body = readBody(ex, method);

        return new Request(method, path, remote, query, body, null);
    }

    /**
     * Canonicalises and validates the request path.
     *
     * Traversal is handled structurally rather than by searching for "..": the path is split on
     * '/', '.' and '..' segments are resolved with a depth counter, and any attempt to climb
     * above the root is an error. This cannot be bypassed by encoding tricks because decoding
     * happens first and the segment walk happens on the decoded result.
     *
     * Backslashes are rejected outright rather than normalised: on a service with no filesystem
     * route they are never legitimate, and a platform that treats them as separators is exactly
     * the confusion this avoids.
     */
    public static String canonicalPath(String raw) throws RequestException {
        if (raw == null || raw.isEmpty()) {
            throw new RequestException(400, "bad_path", "empty request path");
        }
        if (raw.length() > MAX_PATH_CHARS) {
            throw new RequestException(414, "path_too_long",
                    "request path exceeds " + MAX_PATH_CHARS + " characters");
        }
        if (raw.indexOf('\\') >= 0) {
            throw new RequestException(400, "bad_path", "backslash is not valid in a request path");
        }
        // Reject NUL and other control characters: they have no meaning in a path and have been
        // used to truncate a path in a downstream consumer.
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                throw new RequestException(400, "bad_path",
                        "control character in request path");
            }
        }

        // Percent-decode each segment, then resolve. Decoding before the walk is what closes
        // "%2e%2e%2f" and friends.
        String decoded = percentDecode(raw, "path");

        List<String> out = new ArrayList<>();
        for (String seg : decoded.split("/", -1)) {
            if (seg.isEmpty() || seg.equals(".")) {
                continue;
            }
            if (seg.equals("..")) {
                if (out.isEmpty()) {
                    // Climbing above the root. Not silently clamped: a request that tries to
                    // escape the path space is refused, because a clamped answer would tell the
                    // caller the escape was harmless.
                    throw new RequestException(400, "path_traversal",
                            "path escapes the root");
                }
                out.remove(out.size() - 1);
                continue;
            }
            out.add(seg);
        }
        if (out.isEmpty()) {
            // The root is a real resource, not an error. "/" and "/." and "//" all denote it, and
            // the console is served from it, so it canonicalises to "/" and continues to the route
            // table. Everything that tried to *escape* the root above was already refused, so
            // reaching here with an empty list means the caller only ever asked for the root.
            return "/";
        }
        // Re-encode to a stable comparison form. The routes match on this exact string.
        return "/" + String.join("/", out);
    }

    /**
     * Parses a query string under bounds.
     *
     * Repeated keys take the first occurrence rather than the last. "first" is the safer default
     * when a filter is applied to it: a caller that appends a second value cannot widen a
     * previously-set one, and the behaviour is deterministic either way.
     */
    public static Map<String, String> parseQuery(String raw) throws RequestException {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        if (raw.length() > MAX_QUERY_CHARS) {
            throw new RequestException(414, "query_too_long",
                    "query string exceeds " + MAX_QUERY_CHARS + " characters");
        }
        String decoded = percentDecode(raw, "query");
        int count = 0;
        for (String pair : decoded.split("&", -1)) {
            if (pair.isEmpty()) continue;
            if (++count > MAX_QUERY_PARAMS) {
                throw new RequestException(414, "too_many_parameters",
                        "more than " + MAX_QUERY_PARAMS + " query parameters");
            }
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            k = k.trim();
            if (k.isEmpty()) continue;
            if (k.length() > 128) {
                throw new RequestException(414, "bad_parameter", "query parameter name too long");
            }
            if (v.length() > MAX_QUERY_VALUE_CHARS) {
                throw new RequestException(414, "bad_parameter",
                        "query parameter '" + safeName(k) + "' exceeds "
                                + MAX_QUERY_VALUE_CHARS + " characters");
            }
            out.putIfAbsent(k, v);
        }
        return out;
    }

    /**
     * Applies a total budget to the request line and headers.
     *
     * The JDK server bounds each header and the header count separately; this bounds their sum so
     * that "many small headers" is not a cheaper attack than "one large header".
     */
    private static void checkHeaderBudget(HttpExchange ex) throws RequestException {
        int total = 0;
        int count = 0;
        for (Map.Entry<String, List<String>> e : ex.getRequestHeaders().entrySet()) {
            if (++count > MAX_REQUEST_HEADERS) {
                throw new RequestException(431, "too_many_headers",
                        "more than " + MAX_REQUEST_HEADERS + " request headers");
            }
            String name = e.getKey();
            if (name == null || name.isEmpty() || name.length() > 256) {
                throw new RequestException(431, "bad_header", "oversized or empty header name");
            }
            // A request header name carrying CR, LF or NUL is a framing attack, not a header.
            for (int i = 0; i < name.length(); i++) {
                char c = name.charAt(i);
                if (c == '\r' || c == '\n' || c < 0x20 || c == 0x7f) {
                    throw new RequestException(431, "bad_header",
                            "control character in request header name");
                }
            }
            for (String v : e.getValue()) {
                if (v == null) continue;
                if (v.length() > MAX_HEADER_VALUE_CHARS) {
                    throw new RequestException(431, "header_too_large",
                            "header '" + safeName(name) + "' exceeds "
                                    + MAX_HEADER_VALUE_CHARS + " characters");
                }
                for (int i = 0; i < v.length(); i++) {
                    char c = v.charAt(i);
                    if (c == '\r' || c == '\n' || c == 0x00) {
                        // CRLF in a request header value is header injection / request
                        // smuggling. There is no legitimate reason for it in this service.
                        throw new RequestException(431, "header_injection",
                                "control character in request header '" + safeName(name) + "'");
                    }
                }
                total += name.length() + v.length() + 4;
            }
        }
        if (total > MAX_REQUEST_HEADER_BYTES) {
            throw new RequestException(431, "headers_too_large",
                    "request headers exceed " + MAX_REQUEST_HEADER_BYTES + " bytes in total");
        }
    }

    /**
     * Reads the body under a hard ceiling.
     *
     * Three separate defences, because any one of them alone is insufficient:
     *
     *   1. A declared {@code Content-Length} over the limit is refused before a byte is read.
     *   2. A negative, non-numeric or duplicated length is refused as malformed.
     *   3. The stream is read with an explicit one-byte-over-limit probe, so a client that lies
     *      about the length is caught by the read rather than by the declaration.
     *
     * The read stops at the limit and never allocates for more, so the declared length cannot be
     * used to exhaust memory.
     */
    private static byte[] readBody(HttpExchange ex, String method) throws RequestException, IOException {
        // A repeated Content-Length is the other half of the smuggling problem: two declarations
        // that a downstream hop may resolve differently, so this server's view of the body length
        // need not match the next hop's. Refuse the request rather than pick a winner.
        List<String> allLens = ex.getRequestHeaders().get("Content-Length");
        if (allLens != null && allLens.size() > 1) {
            throw new RequestException(400, "conflicting_framing",
                    "Content-Length must not be repeated");
        }
        String rawLen = firstHeader(ex, "Content-Length");
        boolean bodiless = "GET".equalsIgnoreCase(method)
                || "HEAD".equalsIgnoreCase(method)
                || "DELETE".equalsIgnoreCase(method);

        long declared = -1;
        if (rawLen != null) {
            if (rawLen.length() > 20) {
                throw new RequestException(431, "bad_content_length",
                        "Content-Length is not a plausible integer");
            }
            try {
                declared = Long.parseLong(rawLen.trim());
            } catch (NumberFormatException e) {
                throw new RequestException(400, "bad_content_length",
                        "Content-Length is not an integer");
            }
            if (declared < 0) {
                throw new RequestException(400, "bad_content_length",
                        "Content-Length must not be negative");
            }
            if (declared > MAX_BODY_BYTES) {
                throw new RequestException(413, "body_too_large",
                        "request body exceeds the " + MAX_BODY_BYTES + " byte limit");
            }
        }

        // Transfer-Encoding alongside Content-Length is a smuggling primitive: the two describe
        // different bodies and a disagreement between intermediaries is how a request gets
        // reinterpreted. This service never accepts chunked bodies, so the combination is refused.
        String te = firstHeader(ex, "Transfer-Encoding");
        if (te != null && !te.isBlank() && declared >= 0) {
            throw new RequestException(400, "conflicting_framing",
                    "Content-Length and Transfer-Encoding must not both be present");
        }
        if (te != null && !te.isBlank() && !te.trim().equalsIgnoreCase("identity")) {
            throw new RequestException(400, "unsupported_transfer_encoding",
                    "only identity transfer encoding is accepted");
        }

        if (bodiless && declared > 0) {
            throw new RequestException(400, "unexpected_body",
                    "this method must not carry a body");
        }

        if (declared < 0) {
            // No declared length. Either there is no body, or the client is streaming. Both are
            // refused for a write method, which must declare its size.
            if (!bodiless) {
                throw new RequestException(411, "length_required",
                        "Content-Length is required for this method");
            }
            return new byte[0];
        }

        try (InputStream in = ex.getRequestBody()) {
            return readBounded(in, declared);
        }
    }

    /**
     * Reads at most {@code expected} bytes, and refuses if the stream carries more.
     *
     * The extra byte read past the ceiling is what detects a client that under-declared its
     * length. Without it, a short {@code Content-Length} would truncate an oversized body into
     * something that parses cleanly.
     */
    static byte[] readBounded(InputStream in, long expected) throws IOException, RequestException {
        long cap = Math.min(MAX_BODY_BYTES, expected);
        byte[] buf = new byte[(int) Math.min(cap, 64 * 1024)];
        java.io.ByteArrayOutputStream out =
                new java.io.ByteArrayOutputStream((int) Math.min(cap, 64 * 1024));
        long total = 0;
        byte[] one = new byte[1];
        while (total <= MAX_BODY_BYTES) {
            if (total == cap) {
                // At the declared length. One more byte proves whether the declaration was true.
                int extra = in.read(one, 0, 1);
                if (extra > 0) {
                    throw new RequestException(413, "body_too_large",
                            "request body is longer than the declared Content-Length of "
                                    + expected + " and exceeds the " + MAX_BODY_BYTES
                                    + " byte limit");
                }
                break;
            }
            int want = (int) Math.min(buf.length, cap - total);
            int n = in.read(buf, 0, want);
            if (n < 0) break;
            if (n == 0) continue;
            total += n;
            out.write(buf, 0, n);
        }
        if (total > MAX_BODY_BYTES) {
            throw new RequestException(413, "body_too_large",
                    "request body exceeds the " + MAX_BODY_BYTES + " byte limit");
        }
        return out.toByteArray();
    }

    /** First value of a header, or null. Handles the multiple-value case without assuming one. */
    public static String firstHeader(HttpExchange ex, String name) {
        List<String> v = ex.getRequestHeaders().get(name);
        if (v == null || v.isEmpty()) return null;
        String s = v.get(0);
        return s == null ? null : s;
    }

    /**
     * Validates {@code Content-Type} against an expected value.
     *
     * Parameters are parsed rather than compared as a whole string, so {@code application/json;
     * charset=UTF-8} and {@code application/json} are both accepted while {@code application/jsonp}
     * is not. A prefix match on the raw header would accept the second one and the third one
     * equally, which is how a JSONP endpoint turns into an XSS endpoint.
     */
    public static void requireContentType(HttpExchange ex, String expected)
            throws RequestException {
        String ct = firstHeader(ex, "Content-Type");
        if (ct == null || ct.isBlank()) {
            throw new RequestException(415, "unsupported_media_type",
                    "Content-Type: " + expected + " is required");
        }
        String base = ct.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (!base.equals(expected)) {
            throw new RequestException(415, "unsupported_media_type",
                    "Content-Type must be " + expected + ", got " + base);
        }
    }

    // ==================================================================
    // Decoding
    // ==================================================================

    /**
     * Percent-decodes a string, rejecting malformed escapes.
     *
     * Decoding is strict rather than lenient. A lone '%' or a truncated escape is an error, not a
     * literal: a lenient decoder turns "%zz" into "%zz" on one hop and something else on the next,
     * and the disagreement between two interpretations of the same bytes is the bug class this
     * avoids.
     */
    public static String percentDecode(String s, String what) throws RequestException {
        if (s == null) return "";
        if (s.indexOf('%') < 0 && s.indexOf('+') < 0) return s;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '+') {
                out.write(' ');
            } else if (c == '%') {
                if (i + 2 >= s.length()) {
                    throw new RequestException(400, "bad_encoding",
                            "truncated percent escape in " + what);
                }
                int hi = hex(s.charAt(i + 1));
                int lo = hex(s.charAt(i + 2));
                if (hi < 0 || lo < 0) {
                    throw new RequestException(400, "bad_encoding",
                            "invalid percent escape in " + what);
                }
                out.write((hi << 4) | lo);
                i += 2;
            } else {
                // A character above 0x7F cannot be part of a percent escape, so it is encoded as
                // UTF-8 before the result is decoded below.
                if (c < 0x80) {
                    out.write(c);
                } else {
                    byte[] enc = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                    out.write(enc, 0, enc.length);
                }
            }
        }
        return decodeUtf8Strict(out.toByteArray(), what);
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /**
     * Decodes UTF-8 strictly.
     *
     * Malformed or unmappable bytes are an error rather than U+FFFD. Silently substituting
     * replacement characters would let invalid input through as valid text, which matters for a
     * header or path that is then compared against an expected value.
     */
    public static String decodeUtf8Strict(byte[] bytes, String what) throws RequestException {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer cb = dec.decode(ByteBuffer.wrap(bytes));
            String s = cb.toString();
            // A NUL is a C-string terminator. Its presence in a decoded path or header means the
            // input was built for an API that would truncate, and this one must not.
            if (s.indexOf('\u0000') >= 0) {
                throw new RequestException(400, "bad_encoding",
                        "NUL byte in " + what);
            }
            return s;
        } catch (CharacterCodingException e) {
            throw new RequestException(400, "bad_encoding",
                    "invalid UTF-8 in " + what);
        }
    }

    /** Decodes bytes to text strictly, for a body the caller wants as a string. */
    public static String decodeBody(byte[] body) throws RequestException {
        return decodeUtf8Strict(body, "request body");
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    /**
     * Reduces a header or parameter name to a safe token for use in an error message.
     *
     * The name is caller-supplied, so it is filtered to an allow-listed character set before
     * being placed in a response. This keeps an error body free of reflected hostile input.
     */
    static String safeName(String s) {
        if (s == null) return "parameter";
        StringBuilder sb = new StringBuilder(Math.min(s.length(), 32));
        for (int i = 0; i < s.length() && sb.length() < 32; i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            sb.append(ok ? c : '?');
        }
        return sb.toString();
    }

    /**
     * The set of methods this service answers, for a correct {@code Allow} header.
     *
     * Returned rather than hard-coded at each route so that a 405 response and the routing table
     * cannot disagree.
     */
    public static String allowHeader(Set<String> methods) {
        List<String> l = new ArrayList<>(methods);
        l.sort(String::compareTo);
        return String.join(", ", l);
    }
}
