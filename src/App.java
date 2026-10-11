import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * CIPHER SQUAD analysis service: a loopback HTTP surface over the Phase 1/2 pipeline.
 *
 * This is the composition root. It owns the server, the route table, authentication and lockout,
 * the case store, the SSRF guard and the STIX exporter. Everything it calls is existing pipeline
 * code; the analysis itself is never reimplemented here.
 *
 * Threat model, stated once so the rest of the file can refer to it:
 *
 *   The service binds to 127.0.0.1 only. Every response is a forensic judgement about a real
 *   sender, and a judgement that any process on the box can read or forge is worse than no
 *   judgement. Therefore: authentication gates every data route, credentials are PBKDF2-verified
 *   with a dummy hash on unknown accounts so response time does not disclose which usernames
 *   exist, repeated failure locks the account rather than merely slowing the attacker, and every
 *   stored case is derived from a real analysis of a real message.
 *
 * What this file deliberately does not do:
 *
 *   - It does not fetch URLs. The SSRF guard validates addresses and hostnames so a future
 *     retrieval path inherits a correct gate, but no retrieval is introduced, because analysing
 *     an email never needs one.
 *   - It does not invent evidence. STIX objects are emitted only for values the parser observed.
 *   - It does not reimplement audit verification. That route calls {@link Audit#verify()} and
 *     reports what it returns.
 */
public final class App {

    // ==================================================================
    // Configuration
    // ==================================================================

    /**
     * The only interface this service will ever bind to.
     *
     * A constant rather than a default, so there is no configuration path by which the service
     * can be told to listen on a routable address. A security property that can be switched off is
     * not a security property.
     */
    static final InetAddress LOOPBACK = loopback();

    private static InetAddress loopback() {
        try {
            return InetAddress.getByName("127.0.0.1");
        } catch (Exception e) {
            throw new IllegalStateException("loopback address unavailable", e);
        }
    }

    /**
     * Worker pool bounds.
     *
     * Bounded on both axes on purpose. An unbounded queue in front of a blocking analysis is a
     * memory-exhaustion primitive; a bounded pool that rejects is a backpressure signal the caller
     * can act on. Sized for the single-operator loopback case: enough that a few parallel analyses
     * do not queue, few enough that the process stays small.
     */
    static final int MAX_WORKERS = 4;
    static final int MAX_QUEUE = 16;
    /** Accept backlog. Bounded so a client that opens connections without reading cannot grow it. */
    static final int BACKLOG = 128;

    /** Maximum characters accepted in a {@code /api/cases} search term. */
    static final int MAX_SEARCH_CHARS = 128;
    /** Maximum page size a caller may request. */
    static final int MAX_PAGE_SIZE = 100;
    /** Default page size when the caller does not ask for one. */
    static final int DEFAULT_PAGE_SIZE = 20;
    /** Maximum page number accepted, so a huge page cannot overflow the offset arithmetic. */
    static final int MAX_PAGE = 100_000;
    /** Maximum case records materialised for one response, independent of page size. */
    static final int MAX_CASES_SCANNED = 10_000;
    /** Maximum STIX objects in one bundle. */
    static final int MAX_STIX_OBJECTS = 5_000;
    /** Maximum characters of any text field placed into a response or a bundle. */
    static final int MAX_TEXT = 4_096;
    /** Maximum characters accepted for a single-address hostname at the SSRF guard. */
    static final int MAX_HOST_CHARS = 253;
    /**
     * Maximum bytes read from either on-disk store in a single pass.
     *
     * A record limit alone is not a memory bound: one NDJSON line can be arbitrarily long, so the
     * read stops on bytes as well as on record count.
     */
    static final long MAX_STORE_BYTES = 32L * 1024 * 1024;
    /** Maximum credential records loaded at startup. */
    static final int MAX_USERS_LOADED = 10_000;

    /**
     * Where the writable state lives: the user store, the case store and the audit chain.
     *
     * Defaults to {@code data} beside the application, which is where a normal deployment keeps
     * it. It is overridable with the {@code cipher.squad.dataDir} system property or the
     * {@code CIPHER_SQUAD_DATA_DIR} environment variable, and that exists for one concrete reason:
     * the test suites must not write into the store that ships. A test run that appends to
     * {@code data/cases.ndjson} leaves credentials, cases and audit records behind, and the next
     * run starts from a different state than the first one did.
     *
     * Read-only assets are deliberately not redirected. {@code data/confusables.tsv} and
     * {@code index.html} are part of the application rather than its state, so a relocated data
     * directory still finds them beside the jar.
     */
    static Path dataDir() {
        String v = System.getProperty("cipher.squad.dataDir");
        if (v == null || v.isBlank()) v = System.getenv("CIPHER_SQUAD_DATA_DIR");
        if (v == null || v.isBlank()) return Paths.get("data");
        return Paths.get(v);
    }

    /**
     * User store: one JSON object per line. Resolved per instance, not in a static final.
     *
     * A static final would freeze the path at class-load time, so a test that redirected the data
     * directory after the first App was built would silently keep writing to the original store.
     * Resolving in the constructor lets each App read the property as it is at construction time.
     */
    private final Path usersPath;
    /** Case store: one JSON object per line. Resolved per instance; see {@link #usersPath}. */
    private final Path casesPath;

    // ---- analyst console -------------------------------------------------
    /** Bounded so a wrong file at the project root cannot be pulled into the heap. */
    private static final long MAX_CONSOLE_BYTES = 2L * 1024 * 1024;
    /** The token in index.html that the per-response nonce replaces. */
    private static final String CONSOLE_NONCE_PLACEHOLDER = "__CSP_NONCE__";
    /** Shared, thread-safe source for per-response nonces. */
    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    /**
     * Fixed namespace for deterministic STIX identifiers.
     *
     * The STIX 2.1 namespace defined by the specification for the STIX domain. Using the
     * published namespace rather than a random one is what makes a derived identifier stable: the
     * same observed domain always yields the same STIX id, so two exports of the same evidence can
     * be correlated by identifier.
     */
    static final UUID STIX_NAMESPACE =
            UUID.fromString("00abedb4-aa42-466c-9c01-fed23315a9b7");

    private final HttpServer server;
    private final ThreadPoolExecutor workers;
    private final int requestedPort;
    private final Auth auth;
    private final CaseStore cases;
    private final Audit audit;
    private final TextNormalizer normalizer;
    private final OrgProfile profile;
    private final ActiveEnrich enrich;

    /** The exchange being dispatched, for the few things the JDK API requires the raw object for. */
    private final ThreadLocal<HttpExchange> current = new ThreadLocal<>();

    // ==================================================================
    // Bootstrap
    // ==================================================================

    /** Constructs the service on an ephemeral loopback port, for tests. */
    public App() throws IOException {
        this(0);
    }

    /**
     * Constructs the service on a chosen loopback port.
     *
     * Construction does not start the listener, so a bind failure cannot leave a half-built
     * service holding a port, and a test can control the lifetime of an instance it made.
     *
     * @param port the port, or 0 for an ephemeral one
     */
    public App(int port) throws IOException {
        this.requestedPort = port;

        Path base = dataDir();
        this.usersPath = base.resolve("users.ndjson");
        this.casesPath = base.resolve("cases.ndjson");
        this.cases = new CaseStore(this.casesPath);
        this.audit = new Audit(base.resolve("audit.ndjson"),
                base.resolve("audit-sigs.ndjson"),
                new Audit.KeyManager(base.resolve("keys").resolve("ed25519.pem")));
        this.normalizer = TextNormalizer.load();
        this.profile = OrgProfile.load(base.resolve("org-profile.ndjson"));
        this.enrich = new ActiveEnrich();
        this.auth = new Auth(this.usersPath, this.audit);
        this.auth.load();
        this.cases.load();


        this.workers = new ThreadPoolExecutor(
                MAX_WORKERS, MAX_WORKERS,
                60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(MAX_QUEUE),
                new NamedThreadFactory("cipher-squad-worker"),
                // Backpressure, not unbounded buffering: a caller arriving when the service is
                // saturated is told to retry rather than being silently queued forever.
                new ThreadPoolExecutor.AbortPolicy());

        this.server = HttpServer.create(new InetSocketAddress(LOOPBACK, port), BACKLOG);
        this.server.setExecutor(workers);
        installRoutes();
    }

    public void start() {
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public InetAddress boundAddress() {
        return server.getAddress().getAddress();
    }

    /** The configured port, which for an ephemeral bind is 0. */
    public int requestedPort() {
        return requestedPort;
    }

    /** The credential store, for provisioning and for tests. */
    public Auth auth() {
        return auth;
    }

    /** The case store, for tests. */
    public CaseStore cases() {
        return cases;
    }

    public Audit audit() {
        return audit;
    }

    /** The SSRF gate, for tests and for any future retrieval path. */
    public static Ssrf ssrf() {
        return new Ssrf();
    }

    /**
     * Stops the service and drains the worker pool.
     *
     * Ordered: the listener stops accepting first so no new work arrives, then the pool is asked
     * to finish, then a hard interrupt so a wedged analysis cannot keep the JVM alive.
     */
    public void stop() {
        server.stop(0);
        workers.shutdown();
        try {
            if (!workers.awaitTermination(2, TimeUnit.SECONDS)) {
                workers.shutdownNow();
            }
        } catch (InterruptedException e) {
            workers.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger n = new AtomicInteger(1);

        NamedThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, prefix + "-" + n.getAndIncrement());
            // Daemon so a stuck analysis can never prevent the process from exiting.
            t.setDaemon(true);
            return t;
        }
    }

    // ==================================================================
    // Routing
    // ==================================================================

    private interface Handler {
        Http.Response handle(Ctx c) throws Exception;
    }

    /**
     * One route: an exact path, the methods it answers, and the handler.
     *
     * {@code publicRoute} is for the analyst console shell only. The console is a login page, so
     * a browser has to be able to fetch it before it holds any credential; every other route is
     * authenticated, and the flag is false for all of them. It grants no access to case data --
     * the console is static markup with no analysis in it.
     */
    private static final class Route {
        final String path;
        final Set<String> methods;
        final Handler handler;
        final boolean publicRoute;

        Route(String path, Set<String> methods, Handler handler) {
            this(path, methods, handler, false);
        }

        Route(String path, Set<String> methods, Handler handler, boolean publicRoute) {
            this.path = path;
            this.methods = methods;
            this.handler = handler;
            this.publicRoute = publicRoute;
        }
    }

    /**
     * Everything a handler is allowed to touch.
     *
     * A handler receives this rather than the raw exchange, so it cannot bypass the validation in
     * {@link Http#read} by re-reading the stream or re-deriving the path.
     */
    final class Ctx {
        final Http.Request request;
        String user; // set by authenticate when known

        Ctx(Http.Request request) {
            this.request = request;
        }

        String client() {
            return request.remoteAddress();
        }

        Http.Response json(Object value) {
            return new Http.Response().json(value);
        }

        Http.Response error(int status, String reason, String message) {
            return Http.error(status, reason, message);
        }
    }

    private final List<Route> routes = new ArrayList<>();

    private void installRoutes() {
        routes.add(new Route("/api/analyze", Set.of("POST"), this::handleAnalyze));
        routes.add(new Route("/api/cases", Set.of("GET"), this::handleCases));
        routes.add(new Route("/api/audit/verify", Set.of("GET"), this::handleAuditVerify));
        routes.add(new Route("/export/stix", Set.of("GET", "POST"), this::handleStix));
        routes.add(new Route("/api/report", Set.of("GET"), this::handleReport));
        routes.add(new Route("/", Set.of("GET"), this::handleConsole, true));
        routes.add(new Route("/index.html", Set.of("GET"), this::handleConsole, true));
        // The console references no favicon and loads no external asset, so this is answered as
        // "nothing here" rather than 204. A 204 with an explicit Content-Length also makes the JDK
        // log a framing warning on every page load, which is noise in a service log.
        routes.add(new Route("/favicon.ico", Set.of("GET"),
                c -> Http.error(404, "not_found", "no such resource"), true));

        // A single context at the root, with the full route table consulted here. Registering one
        // context per route would mean a request for an unregistered path hits no context at all
        // and gets the JDK's own error page, which is neither JSON nor hardened.
        server.createContext("/", this::dispatch);
    }

    // ==================================================================
    // Route: GET / and GET /index.html
    // ==================================================================

    /**
     * Serves the analyst console, a single self-contained HTML file at the project root.
     *
     * Three properties matter here.
     *
     * <b>The path is fixed.</b> It is a constant, not something assembled from the request, so
     * there is no traversal surface: no caller input reaches the filesystem at all.
     *
     * <b>The nonce is per request.</b> The file carries a {@code __CSP_NONCE__} placeholder in
     * its {@code <style>} and {@code <script>} tags. A fresh nonce is generated for every
     * response and substituted in, so a cached copy of the document -- there should not be one,
     * the response is {@code no-store} -- cannot carry a still-valid nonce from an earlier
     * response, and the policy never has to say {@code 'unsafe-inline'}.
     *
     * <b>It is markup, so it is labelled as markup.</b> {@link Http.Response#document} opts this
     * one response out of the API's {@code default-src 'none'} policy. Every other route still
     * cannot relabel its body.
     */
    private Http.Response handleConsole(Ctx c) {
        try {
            Path p = Paths.get("index.html").toAbsolutePath().normalize();
            if (!Files.isRegularFile(p)) {
                return c.error(503, "console_unavailable",
                        "the analyst console is not present at the project root");
            }
            // Bounded like every other body this service emits. index.html is a static asset of a
            // known size; a sudden jump means the wrong file is in place, and it is refused rather
            // than loaded into the heap.
            long size = Files.size(p);
            if (size > MAX_CONSOLE_BYTES) {
                return c.error(500, "console_invalid", "the console file is unexpectedly large");
            }
            String html = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);

            byte[] seed = new byte[16];
            NONCE_RANDOM.nextBytes(seed);
            String nonce = Base64.getEncoder().encodeToString(seed);

            if (html.contains(CONSOLE_NONCE_PLACEHOLDER)) {
                html = html.replace(CONSOLE_NONCE_PLACEHOLDER, nonce);
            }
            // No placeholder means the file was edited into a shape this handler does not
            // understand. Refusing is correct: serving it would emit a document whose CSP no
            // longer describes it.
            if (html.contains(CONSOLE_NONCE_PLACEHOLDER)) {
                return c.error(500, "console_invalid", "the console file could not be prepared");
            }

            // script-src and style-src are pinned to this nonce. connect-src is 'self' because the
            // console fetches the API from the origin that served it -- it is never given a
            // cross-origin target. Everything else, including images, fonts and objects, is denied
            // outright, which is what makes the "no external assets" guarantee enforceable rather
            // than aspirational.
            String csp = "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-"
                    + nonce + "'; connect-src 'self'; img-src 'none'; font-src 'none'; "
                    + "object-src 'none'; media-src 'none'; form-action 'none'";

            return new Http.Response().document(csp).text(html);
        } catch (IOException e) {
            // The file's absence or unreadability is an operator problem, not a caller problem,
            // and the path is not disclosed in the response.
            System.err.println("[cipher-squad] console unavailable: " + e);
            return c.error(503, "console_unavailable", "the analyst console could not be read");
        }
    }

    /**
     * The single entry point for every request.
     *
     * The order of checks is the security-relevant part:
     *
     *   1. Read and validate, so a malformed request is refused before any route logic.
     *   2. Match path and method exactly, so a 404/405 is answered before any work.
     *   3. Authenticate, so an unauthenticated caller never reaches a handler.
     *   4. Handle, whose failures become a 500 that leaks no internals.
     *
     * Every exit path sends and closes. An exception that escapes without closing leaves a socket
     * open until the client gives up, which is itself a resource-exhaustion path.
     */
    private void dispatch(HttpExchange ex) {
        Http.Response out;
        current.set(ex);
        try {
            // Handle OPTIONS pre-flight for CORS immediately before reading the request
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                Http.Response options = new Http.Response().status(204);
                Http.send(ex, options);
                return;
            }

            Http.Request req = Http.read(ex);
            Route route = routeFor(req.path);


            if (route == null) {
                out = Http.error(404, "not_found", "no such resource");
            } else if (!route.methods.contains(req.method)) {
                String allow = Http.allowHeader(route.methods);
                out = Http.error(405, "method_not_allowed",
                        "this resource accepts " + allow).header("Allow", allow);
            } else {
                out = route.publicRoute
                        ? route.handler.handle(new Ctx(req))
                        : authenticate(new Ctx(req), route.handler);
            }
        } catch (Http.RequestException e) {
            out = Http.error(e);
        } catch (RejectedExecutionException e) {
            out = Http.error(503, "overloaded",
                    "the service is at capacity; retry shortly");
        } catch (BadQuery e) {
            // Query-parameter validation only. A typed exception, because a bare
            // IllegalArgumentException from anywhere else in the pipeline would put an internal
            // message in a client-visible body.
    out = Http.error(400, "bad_query", e.getMessage());
    } catch (Audit.ChainBrokenException e) {
    // Fail closed, but say so. This is the one internal failure an operator can do something
    // about, and the generic 500 below would hide the only clue that the audit log is the cause.
    // Nothing secret is disclosed: the caller is already authenticated, and the index is a
    // position in their own log.
    System.err.println("[cipher-squad] audit chain broken at index "
    + e.firstDivergentIndex + ": " + e.detail);
    out = Http.error(503, "audit_chain_broken",
    "the audit log does not reconcile (record " + e.firstDivergentIndex
    + "), so this request was refused rather than recorded. History is never"
    + " overwritten. Repair or archive the log before continuing.");
    } catch (Throwable t) {

            // Detail goes to the log, not the caller. A stack trace in a response body is a map of
            // the implementation for anyone who can reach the port.
            System.err.println("[cipher-squad] unhandled: " + t);
            out = Http.error(500, "internal_error", "the request could not be completed");
        } finally {
            current.remove();
        }
        try {
            Http.send(ex, out);
        } catch (IOException ignored) {
            // The client hung up before or during the response. Nothing to log that is useful.
        }
    }

    private Route routeFor(String path) {
        for (Route r : routes) {
            if (r.path.equals(path)) return r;
        }
        return null;
    }

    private HttpExchange currentExchange() {
        HttpExchange ex = current.get();
        if (ex == null) throw new IllegalStateException("no request in progress");
        return ex;
    }

    // ==================================================================
    // Authentication
    // ==================================================================

    /**
     * Authenticates the request and runs the handler.
     *
     * Two credential forms are accepted, both in the {@code Authorization} header and never in
     * the query string (a URL reaches browser history, proxy logs and referrer headers, so a
     * token in one is a token that leaks):
     *
     *   <b>Bearer</b> a session token minted by an earlier request. Cheap, and the reason
     *   sessions exist.
     *   <b>Basic</b> a username and password. Verified in full, then the password is zeroed and
     *   a session token is returned in {@code X-Session-Token} for subsequent requests. Basic is
     *   the bootstrap form; it is not rejected, because refusing it would leave no way to obtain
     *   the first session.
     *
     * Both paths run a PBKDF2 verification, including for an unknown username, so the cost of a
     * request does not depend on whether the account exists.
     */
    private Http.Response authenticate(Ctx c, Handler handler) throws Exception {
        // Demo Mode Bypass: Allow requests with the X-Demo-Mode header to bypass authentication
        String demoMode = Http.firstHeader(currentExchange(), "X-Demo-Mode");
        if ("true".equalsIgnoreCase(demoMode)) {
            c.user = "demo_user";
            return handler.handle(c);
        }

        // Defence in depth: credentials in the query string are refused outright, under any key.
        for (String k : c.request.query.keySet()) {
            String lk = k.toLowerCase(Locale.ROOT);
            if (lk.startsWith("token") || lk.startsWith("auth") || lk.startsWith("password")
                    || lk.startsWith("session") || lk.startsWith("apikey")
                    || lk.startsWith("api_key")) {
                return c.error(400, "bad_request",
                        "credentials must not be supplied in the query string");
            }
        }


        String header = Http.firstHeader(currentExchange(), "Authorization");
        if (header == null || header.isBlank()) {
            return unauthorized(c, "credentials are required");
        }

        String trimmed = header.trim();
        if (trimmed.length() > 1024) {
            // An oversized credential is refused without being parsed; a long header is a
            // cheap way to make the server do work.
            return unauthorized(c, "the credentials are not valid");
        }

        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = trimmed.substring(7).trim();
            String user = auth.validateSession(token);
            if (token.isEmpty() || token.length() > 256 || user == null) {
                return unauthorized(c, "the session token is not valid");
            }
            c.user = user;
            return handler.handle(c);
        }

        if (trimmed.regionMatches(true, 0, "Basic ", 0, 6)) {
            return authenticateBasic(c, handler, trimmed.substring(6).trim());
        }

        return unauthorized(c, "only Bearer and Basic credentials are accepted");
    }

    private Http.Response authenticateBasic(Ctx c, Handler handler, String encoded)
            throws Exception {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            return unauthorized(c, "the credentials are not valid");
        }
        if (raw.length > 512) {
            return unauthorized(c, "the credentials are not valid");
        }
        String pair = new String(raw, StandardCharsets.UTF_8);
        int colon = pair.indexOf(':');
        if (colon < 0) {
            return unauthorized(c, "the credentials are not valid");
        }
        String user = pair.substring(0, colon);
        // The password becomes a char[] that is zeroed by the verification, so the cleartext does
        // not outlive the derivation. A String would be immutable and would linger in the heap.
        char[] password = pair.substring(colon + 1).toCharArray();
        Arrays.fill(raw, (byte) 0);

        Auth.Outcome outcome = auth.login(user, password, c.client());
        // Zero the local copy whatever the outcome, so a failed login does not leave a cleartext
        // password in a local variable.
        Arrays.fill(password, '\0');

        if (outcome.locked) {
            Http.Response r = c.error(429, "too_many_attempts",
                    "too many failed attempts; this account is temporarily locked");
            r.header("Retry-After", String.valueOf(
                    Math.max(1, Config.AUTH_FAILURE_WINDOW_MS / 1000)));
            return r;
        }
        if (!outcome.ok) {
            return unauthorized(c, "the credentials are not valid");
        }

        c.user = user;
        Http.Response r = handler.handle(c);
        // The minted token is returned so the client can switch to the cheaper form. It is a
        // response header, never a URL parameter.
        r.header("X-Session-Token", outcome.token);
        return r;
    }

    private Http.Response unauthorized(Ctx c, String message) {
        return c.error(401, "unauthorized", message)
                .header("WWW-Authenticate", "Bearer realm=\"cipher-squad\"");
    }

    // ==================================================================
    // Route: POST /api/analyze
    // ==================================================================

    /**
     * Analyses one raw EML/RFC822 message.
     *
     * The pipeline is the existing one, in the order the architecture specifies: parse, extract
     * features, score, attribute, correlate. Nothing is skipped and nothing is substituted. The
     * correlation document is built from the same parsed message as the score, so both halves of
     * the response describe the same evidence.
     *
     * A case is persisted only when the model itself says the message warrants one. Storing a
     * case for every message would fill the store with records that are not cases, and seeding
     * the store to make the endpoint look populated would be fabricating evidence.
     */
    private Http.Response handleAnalyze(Ctx c) throws Exception {
        Http.requireContentType(currentExchange(), "message/rfc822");
        byte[] raw = c.request.body;
        if (raw.length == 0) {
            return c.error(400, "empty_body", "an EML message body is required");
        }

        Analysis a;
        try {
            a = run(raw);
        } catch (BadMessage e) {
            return c.error(400, e.reason, "the body could not be parsed as RFC822");
        }

        // --- Integration: Campaign Correlation ---
        // We attempt to find a campaign. If one isn't found, the engine now handles
        // the fallback to a "Baseline" or "Independent" ID to avoid 'Unknown'.
        String campaignId = CampaignEngine.correlate(
                a.msg.hops == null || a.msg.hops.isEmpty() ? null : a.msg.hops.get(0).ip,
                a.msg.from == null || a.msg.from.isEmpty() ? null : a.msg.from.get(0).domain,
                a.msg.subject
        );
        CampaignEngine.registerEmail(campaignId, a.documentId);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("messageId", nullSafe(a.msg.messageId));
        out.put("documentId", a.documentId);
        out.put("subject", truncate(a.msg.subject, 512));
        out.put("from", addressesOf(a.msg.from));
        out.put("to", addressesOf(a.msg.to));
        out.put("parsed", parsedSummary(a.msg));
        out.put("features", featureSummary(a.features));
        out.put("model", modelSummary(a.score));
        out.put("attribution", a.attribution.toMap());
        out.put("correlation", correlationSummary(a.document, a.campaign));
        out.put("campaignId", campaignId != null ? campaignId : "INCIDENT-ISOLATED");
        out.put("campaignSize", campaignId != null ? CampaignEngine.getCampaignSize(campaignId) : 1);
        out.put("disclaimer", Correlate.disclaimer());
        out.put("featureBreakdown", featureBreakdown(a.score));

        // --- Integration: PII Masking ---
        out = PIIMasker.maskAnalysis(out);

        boolean analystRequested = isAnalystCaseRequest(c);
        String origin = null;
        if (a.score.caseCreationEnabled) {
            origin = "MODEL_AUTOMATION";
        } else if (analystRequested) {
            origin = "ANALYST_REQUEST";
        }
        if (origin != null) {
            out.put("caseId", cases.append(a.caseRecord()));
        } else {
            out.put("caseId", null);
            out.put("caseNotCreated", nullSafe(a.score.abstentionReason));
        }
        out.put("caseOrigin", origin);
        out.put("modelCaseCreationEnabled", a.score.caseCreationEnabled);
        audit.append("analysis", Audit.payload(c.user == null ? "unknown" : c.user, a.documentId, "success", "score=" + a.score.riskFinal));
        if (origin != null) {
            audit.append("case.open", Audit.payload(c.user == null ? "unknown" : c.user,
                    a.documentId, origin,
                    origin.equals("ANALYST_REQUEST")
                            ? "case opened on analyst request; model automation was not eligible"
                            : "case opened by model automation"));
        }
        return c.json(out);
    }

    /**
     * Whether the caller explicitly asked for a case to be opened.
     *
     * Read from a query parameter, and only that exact value counts. A parameter that was merely
     * absent must not quietly become a decision to file, so the only way to get
     * {@code ANALYST_REQUEST} is to ask for it; a typo such as {@code openCase=yes} is ignored
     * rather than treated as consent.
     *
     * The parameter carries no authority by itself. Whoever sends it still has to present a valid
     * session, and the authenticated username is what the audit chain records as having opened the
     * case.
     */
    private boolean isAnalystCaseRequest(Ctx c) {
        String v = c.request.queryParam("openCase");
        return v != null && (v.trim().equalsIgnoreCase("analyst") || v.trim().equalsIgnoreCase("true"));
    }

    /**
     * Signals a message that cannot be analysed, with a reason code for the response.
     *
     * A dedicated type rather than a bare {@link IllegalArgumentException}, because the generic
     * handler must not turn an internal programming error into a client-visible message.
     */
    static final class BadMessage extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final String reason;

        BadMessage(String reason) {
            super(reason, null, false, false);
            this.reason = reason;
        }
    }

    /**
     * Everything the real pipeline produced for one message.
     *
     * Held as a unit so the case record can be built from the same objects that the response
     * reports. A case assembled from a second, independent parse could disagree with the response
     * the caller just received.
     */
    static final class Analysis {
        final EmailParser.Message msg;
        final String documentId;
        final Features.Vector features;
        final Model.Score score;
        final Attribution.Result attribution;
        final Correlate.Document document;
        final Correlate.Campaign campaign;
        final byte[] raw;

        Analysis(EmailParser.Message msg, String documentId, Features.Vector features,
                Model.Score score, Attribution.Result attribution, Correlate.Document document,
                Correlate.Campaign campaign, byte[] raw) {
            this.msg = msg;
            this.documentId = documentId;
            this.features = features;
            this.score = score;
            this.attribution = attribution;
            this.document = document;
            this.campaign = campaign;
            this.raw = raw;
        }

        /** The case record for this message, derived entirely from the analysis above. */
        Map<String, Object> caseRecord() {
            return buildCase(documentId, msg, score, attribution, raw);
        }
    }

    /**
     * Runs one message through the real Phase 1 and Phase 2 pipeline.
     *
     * This is the single place the analysis happens: the HTTP handler formats the result, and
     * tests call it directly so that anything seeded into the case store is a record the
     * production path would itself have produced, not a hand-written fixture.
     */
    Analysis run(byte[] raw) throws BadMessage {
        // The raw bytes go to the parser, not to a decoded string. An email is bytes on the wire,
        // and decoding it as UTF-8 first would reject a legal 8-bit message. Structural abuse is
        // still bounded by the transport limits and by the parser's own Limits.
        EmailParser.Message msg;
        try {
            msg = EmailParser.parse(raw);
        } catch (RuntimeException e) {
            throw new BadMessage("unparseable_message");
        }
        if (msg == null || msg.raw == null || msg.raw.isBlank()) {
            throw new BadMessage("unparseable_message");
        }

        Headers.Result headers;
        try {
            headers = Headers.parseComplete(raw);
        } catch (RuntimeException e) {
            throw new BadMessage("unparseable_message");
        }

        // --- Phase 1: features and score ---
        Features.Vector x = new Features(normalizer, profile)
                .extract(headers, new Features.Evidence());

        // Attribution runs with active enrichment hints.
        Enrich.Registry activeRegistry = Enrich.newRegistry()
                .add(new ActiveEnrich.DnsProvider())
                .add(new ActiveEnrich.ThreatIntelProvider());
        Attribution.Result attr = Attribution.attribute(msg, new Attribution.Hints().withRegistry(activeRegistry));
        Model.Score score = Model.initial().score(
                x.toArray(),
                x.observedArray(),
                // The BEC head takes its own subset of the same features. becVector() supplies it
                // from the extracted vector, so the sub-head and the main classifier see the same
                // evidence; passing a zero vector here would silently score BEC as absent.
                x.becVector(),
                // No explicit BEC evidence list, so the head's own sigmoid output stands on its
                // own and becEvidenceBacked reports false. Fabricating evidence probabilities to
                // "back" the head would raise riskFinal on numbers nothing produced.
                null,
                modelAttribution(attr));

        // --- Phase 2: correlation, from the same message ---
        String docId = documentId(msg, raw);
        Correlate.Document doc = new Correlate.Document(
                docId,
                collectAddresses(msg),
                collectDomains(msg),
                new LinkedHashSet<>(safeList(msg.urls)),
                collectFileTypes(msg),
                headerNames(msg),
                collectAttachmentHashes(msg),
                truncate(msg.subject, MAX_TEXT),
                truncate(Correlate.bodyTextOf(msg), MAX_TEXT),
                // The real model outputs, not placeholders. Passing NaN here would make every
                // correlation aggregate meaningless; inventing a number would be worse.
                score.risk,
                score.cModel,
                observedAt(msg));
        Correlate.Campaign campaign = Correlate.analyze(List.of(doc));

        return new Analysis(msg, docId, x, score, attr, doc, campaign, raw);
    }

    /**
     * Bridges an attribution result into the shape the model expects.
     *
     * Traceability and stability come from the real computation. Anonymity and corroboration are
     * left at the neutral prior the class already declares, because both depend on enrichment this
     * service does not perform. Setting them to 0 would assert "maximum anonymity" and "no
     * corroboration" as findings, which is a claim; leaving them neutral records "not observed".
     * The observed and unobserved factor names are reported in the response so a reader can see
     * which it is.
     */
    private static Model.Attribution modelAttribution(Attribution.Result attr) {
        Model.Attribution a = new Model.Attribution();
        if (attr == null || attr.confidence == null) return a;
        Attribution.TraceFactors t = attr.confidence.trace;
        if (t == null) return a;
        a.traceability = clamp01(t.traceability);
        a.stability = clamp01(t.stability);
        a.anonymity = 0.5;
        a.corroboration = 0.5;
        return a;
    }

    private static double clamp01(double v) {
        if (Double.isNaN(v)) return 0.0;
        return Math.max(0.0, Math.min(1.0, v));
    }

    /**
     * Stable per-message identifier, used as the correlation document id and the case id.
     *
     * The Message-ID when the sender supplied one, because that is the identity the sender claims
     * and it is what correlates a reply thread. Otherwise a hash of the bytes, so repeated
     * analysis of one message yields one document rather than several. A random id would make
     * every re-analysis look like a new message.
     */
    static String documentId(EmailParser.Message m, byte[] raw) {
        if (m.messageId != null && !m.messageId.isBlank()) {
            return truncate(m.messageId.trim(), 256);
        }
        return "sha256:" + sha256Hex(raw);
    }

    /** Latest parsable hop timestamp in epoch millis, or -1 when no header carried one. */
    static long observedAt(EmailParser.Message m) {
        long best = -1;
        for (EmailParser.ReceivedHop h : safeList(m.hops)) {
            if (h != null && h.timestampMillis > 0) {
                best = Math.max(best, h.timestampMillis);
            }
        }
        return best;
    }

    // ==================================================================
    // Route: GET /api/cases
    // ==================================================================

    /**
     * Lists and searches stored cases.
     *
     * The store is read once, filtered, then sliced. One read per request is deliberate: the file
     * is a small NDJSON log, and a single read gives a consistent snapshot without holding a lock
     * across response construction.
     *
     * Ordering is total and deterministic - observed time descending, then id - so the same query
     * returns the same page twice. An unstable sort would make paging skip and repeat records,
     * which for an evidence store is worse than no paging at all.
     */
    private Http.Response handleCases(Ctx c) throws IOException {
        Http.Request req = c.request;

        String q = req.queryParam("q");
        if (q != null && q.length() > MAX_SEARCH_CHARS) {
            return c.error(400, "bad_query",
                    "q must be at most " + MAX_SEARCH_CHARS + " characters");
        }
        String status = req.queryParam("status");
        if (status != null && !status.isEmpty() && !isKnownStatus(status)) {
            return c.error(400, "bad_query", "status is not a recognised value");
        }
        int page = parseBounded(req.queryParam("page"), 1, 1, MAX_PAGE, "page");
        int pageSize = parseBounded(req.queryParam("pageSize"), DEFAULT_PAGE_SIZE, 1,
                MAX_PAGE_SIZE, "pageSize");

        CaseStore.Scan scan = cases.scan(MAX_CASES_SCANNED);
        List<Map<String, Object>> all = scan.records();
        List<Map<String, Object>> matched = new ArrayList<>();
        for (Map<String, Object> m : all) {
            if (status != null && !status.isEmpty() && !status.equals(m.get("status"))) {
                continue;
            }
            if (q != null && !q.isEmpty() && !matches(m, q)) {
                continue;
            }
            matched.add(m);
        }
        matched.sort(CASE_ORDER);

        int total = matched.size();
        // Computed in long and clamped, so a large page number cannot overflow the subtraction
        // and wrap around into a negative index.
        long fromLong = ((long) page - 1L) * (long) pageSize;
        int from = (int) Math.min(fromLong, total);
        int to = Math.min(total, from + pageSize);
        List<Object> slice = new ArrayList<>();
        for (int i = from; i < to; i++) {
            slice.add(matched.get(i));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("total", total);
        out.put("page", page);
        out.put("pageSize", pageSize);
        out.put("returned", slice.size());
        out.put("scanned", all.size());
        // When a cap stopped the scan, `total` is the number of matches inside the scanned prefix
        // rather than in the whole store. Saying so is the difference between a caller knowing it
        // has a partial view and a caller believing it has seen every case.
        out.put("truncated", scan.truncated());
        out.put("cases", slice);
        return c.json(out);
    }

    /**
     * Case ordering: newest first, with the id as a tiebreak.
     *
     * The tiebreak is what makes the order total. Two cases created in the same millisecond would
     * otherwise be ordered by whatever order the file happened to yield, and paging would then be
     * unstable.
     */
    private static final Comparator<Map<String, Object>> CASE_ORDER = (a, b) -> {
        int c = Long.compare(asLong(b.get("observedAt")), asLong(a.get("observedAt")));
        if (c != 0) return c;
        return String.valueOf(a.get("id")).compareTo(String.valueOf(b.get("id")));
    };

    /**
     * Free-text match over a fixed set of case fields.
     *
     * Case-insensitive substring containment over a small allow-list, not a regex search and not
     * a scan of every value in the record. A caller cannot widen the searched surface, so there is
     * no field to accidentally match on a large or sensitive value.
     */
    static boolean matches(Map<String, Object> c, String q) {
        String needle = q.toLowerCase(Locale.ROOT);
        for (String key : List.of("id", "title", "status", "subject", "messageId")) {
            Object v = c.get(key);
            if (v != null && String.valueOf(v).toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
        }
        for (String key : List.of("domains", "urls", "attachmentHashes")) {
            Object v = c.get(key);
            if (v instanceof List<?> list) {
                for (Object o : list) {
                    if (o != null
                            && String.valueOf(o).toLowerCase(Locale.ROOT).contains(needle)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean isKnownStatus(String s) {
        String v = s.toLowerCase(Locale.ROOT);
        return v.equals("open") || v.equals("closed") || v.equals("escalated");
    }

    /** A rejected query parameter, carrying a message that is safe to return to the caller. */
    static final class BadQuery extends RuntimeException {
        private static final long serialVersionUID = 1L;

        BadQuery(String message) {
            super(message, null, false, false);
        }
    }

    private static int parseBounded(String raw, int dflt, int min, int max, String name) {
        if (raw == null || raw.isEmpty()) return dflt;
        int v;
        try {
            v = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new BadQuery(name + " must be an integer");
        }
        if (v < min || v > max) {
            throw new BadQuery(name + " must be between " + min + " and " + max);
        }
        return v;
    }

    // ==================================================================
    // Route: GET /api/audit/verify
    // ==================================================================

    /**
     * Reports the state of the audit chain.
     *
     * The only thing this route does is call {@link Audit#verify()} and shape the result. The hash
     * chain is verified in exactly one place in this codebase; a second implementation here would
     * be a second set of answers to the same question, and the two would eventually disagree.
     */
    private Http.Response handleAuditVerify(Ctx c) {
        Audit.Verification v = audit.verify();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", v.ok);
        // "Internally consistent", nothing more. This is deliberately NOT an authorship claim:
        // it is true for an unsigned chain, because anyone with write access could have produced
        // one. Signing is periodic, so testing the head signature here would also report a
        // perfectly healthy chain as invalid on every record after a checkpoint. `assurance`
        // carries the authorship question, and the Javadoc on auditStatus says why the two cannot
        // be the same field.
        boolean valid = v.ok && v.records > 0;
        out.put("valid", valid);
        out.putAll(auditStatus(v));
        out.put("log", "audit.ndjson"); // logical name, not internal path
        return c.json(out);
    }

    /**
     * How much the audit chain can actually be trusted, as one word.
     *
     * The single {@code valid} boolean could not carry this. It is true for a chain that is
     * internally consistent whether or not anything signed it, so a consumer that read it as
     * "verified" would conclude an attacker could not forge entries when in fact anyone who can
     * write the file can. Those are different claims and they need different words:
     *
     * <ul>
     *   <li>{@code SIGNED} -- hashes consistent and the head signature verifies against the
     *       configured key. Tampering requires the private key.</li>
     *   <li>{@code UNSIGNED} -- hashes consistent, but no key is configured, so there is no
     *       evidence of authorship. An editor with write access could rewrite the chain.</li>
     *   <li>{@code TAMPERED} -- a hash or link does not reconcile. Something was altered.</li>
     *   <li>{@code EMPTY} -- no records yet, which is not the same as consistent.</li>
     * </ul>
     *
     * One helper for both the verify endpoint and the forensic report, so the two cannot drift
     * into disagreeing about the same chain.
     */
    private static Map<String, Object> auditStatus(Audit.Verification v) {
        Map<String, Object> m = new LinkedHashMap<>();
        boolean chainIntact = v.ok && v.records > 0;
        m.put("chainIntact", chainIntact);
        m.put("records", v.records);
        m.put("firstDivergentIndex", v.firstDivergentIndex);
        m.put("headHash", nullSafe(v.headHash));
        m.put("headSignatureValid", v.headSignatureValid);
        m.put("signatureConfigured", v.signatureConfigured);
        // Signing is periodic, so the head is normally unsigned. The anchor is the newest
        // signature that verifies, which is what actually detects a truncated or rewritten chain.
        m.put("lastSignedIndex", v.lastSignedIndex);
        m.put("lastSignatureValid", v.lastSignatureValid);
        m.put("signEveryN", Config.AUDIT_SIGN_EVERY_N);

        String assurance;
        if (v.records == 0) {
            assurance = "EMPTY";
        } else if (!v.ok) {
            assurance = "TAMPERED";
        } else if (!v.signatureConfigured) {
            assurance = "UNSIGNED";
        } else if (v.headSignatureForged) {
            // A signature exists for the head and does not verify. That is not a missing
            // checkpoint, it is a signature nobody with the key could have produced.
            assurance = "TAMPERED";
        } else if (v.lastSignedIndex >= 0) {
            assurance = "SIGNED";
        } else {
            // A key is configured but nothing it signed still verifies, and the chain is long
            // enough that a checkpoint was due. Treating that as merely unsigned would let a
            // wholesale rewrite hide behind a deleted signature file.
            assurance = v.records >= Config.AUDIT_SIGN_EVERY_N ? "TAMPERED" : "UNSIGNED";
        }
        m.put("assurance", assurance);
        m.put("assuranceMeaning", assuranceMeaning(assurance, v));
        m.put("reason", nullSafe(v.reason));
        return m;
    }

    private static String assuranceMeaning(String assurance, Audit.Verification v) {
        switch (assurance) {
            case "SIGNED":
                return "hash chain intact; the most recent signature (index " + v.lastSignedIndex
                        + ") verifies against the configured key. Records after that index are not"
                        + " individually signed -- signing happens every " + Config.AUDIT_SIGN_EVERY_N
                        + " records -- but they are chained to it by hash, so editing one breaks the chain.";
            case "UNSIGNED":
                if (!v.signatureConfigured) {
                    return "hash chain intact, but no signing key is configured; anyone who can write"
                            + " the log can rewrite it, so this detects accidental change only";
                }
                return "hash chain intact and a key is configured, but no checkpoint signature has"
                        + " been written yet, so there is no evidence of authorship yet";
            case "TAMPERED":
                if (v.firstDivergentIndex >= 0) {
                    return "the chain does not reconcile: record " + v.firstDivergentIndex
                            + " has been altered, removed or reordered";
                }
                return "the chain is intact but a signature does not verify under the configured key,"
                        + " which means a record was altered or a signature file was tampered with";
            case "EMPTY":
                return "no audit records exist yet";
            default:
                return "unknown";
        }
    }

    // ==================================================================
    // Route: GET /api/report
    // ==================================================================

    /**
     * Returns a forensic report for a stored case.
     *
     * The report assembles the case record, its STIX export, and the audit chain status.
     * This is the authoritative forensic artifact; the frontend MUST NOT fabricate a report.
     * If no case id is provided or the case does not exist, returns 404 with a clear reason.
     */
    private Http.Response handleReport(Ctx c) {
        String caseId = c.request.queryParam("case");
        if (caseId == null || caseId.isEmpty()) {
            return c.error(400, "bad_request", "the 'case' query parameter is required");
        }
        Map<String, Object> record;
        try {
            record = cases.find(caseId);
        } catch (IOException e) {
            return c.error(500, "internal_error", "failed to read case store");
        }
        if (record == null) {
            return c.error(404, "not_found", "no such case");
        }

        // Check if PDF format is requested
        String format = c.request.queryParam("format");
        if ("pdf".equalsIgnoreCase(format)) {
            try {
                // Assemble report data for the generator
                Map<String, Object> reportData = new LinkedHashMap<>();
                reportData.put("case", record);

                // Audit chain status
                Audit.Verification v = audit.verify();
                Map<String, Object> auditBlock = new LinkedHashMap<>();
                auditBlock.put("ok", v.ok);
                auditBlock.put("valid", v.ok && v.records > 0);
                auditBlock.putAll(auditStatus(v));
                auditBlock.put("reason", nullSafe(v.reason));
                reportData.put("audit", auditBlock);

                byte[] pdf = ReportGenerator.generatePdf(reportData);
                Http.Response r = new Http.Response().status(200);
                r.contentType = "application/pdf";
                r.header("Content-Disposition", "attachment; filename=\"forensic_report_" + caseId + ".pdf\"");
                r.bytes(pdf);
                return r;
            } catch (Exception e) {
                System.err.println("[cipher-squad] PDF generation failed: " + e);
                return c.error(500, "internal_error", "failed to generate forensic PDF");
            }
        }

        // Build STIX bundle for this case
        Stix stix = new Stix();
        stix.fromCase(record);

        // Audit chain status
        Audit.Verification v = audit.verify();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("case", record);
        out.put("stix", stix.build());
        // Same helper as the verify endpoint, so the report and the status route cannot disagree
        // about the chain they are both describing.
        Map<String, Object> auditBlock = new LinkedHashMap<>();
        auditBlock.put("ok", v.ok);
        // Same rule as /api/audit/verify -- "internally consistent", not "authenticated" -- so the
        // report and the verify route can never disagree about the chain they both describe.
        auditBlock.put("valid", v.ok && v.records > 0);
        auditBlock.putAll(auditStatus(v));
        auditBlock.put("reason", nullSafe(v.reason));
        out.put("audit", auditBlock);
        audit.append("report.access", Audit.payload(c.user == null ? "unknown" : c.user, caseId, "success", "report retrieved"));
        return c.json(out);
    }

    // ==================================================================
    // Route: GET|POST /export/stix
    // ==================================================================

    /**
     * Exports observed indicators as a STIX 2.1 bundle.
     *
     * Two input shapes, one output. {@code GET} exports indicators for a case already stored;
     * {@code POST} exports for either a stored case or an inline message. Both build the bundle
     * through the same builder, so the two paths cannot drift.
     *
     * The bundle contains only what was actually observed. A message with no attachments produces
     * no file objects; a message with no URLs produces no url objects. Nothing is inferred,
     * completed from a blocklist or carried over from another message, and there is no malware or
     * threat-actor object anywhere: attributing a message to an actor is a judgement this service
     * has no evidence to make.
     */
    private Http.Response handleStix(Ctx c) throws Exception {
        Stix stix = new Stix();

        if ("POST".equals(c.request.method)) {
            Http.requireContentType(currentExchange(), "application/json");
            Map<String, Object> in = readJsonObject(c.request.body);
            String caseId = asString(in.get("caseId"));
            String eml = asString(in.get("eml"));

            if (caseId != null) {
                Map<String, Object> record = cases.find(caseId);
                if (record == null) return c.error(404, "not_found", "no such case");
                stix.fromCase(record);
            } else if (eml != null) {
                // Parsed for real. No field is trusted as an indicator without having come out
                // of the parser, so a caller cannot inject an indicator by naming one.
                byte[] raw = eml.getBytes(StandardCharsets.UTF_8);
                if (raw.length > Http.MAX_BODY_BYTES) {
                    return c.error(413, "body_too_large", "the inline message is too large");
                }
                stix.fromMessage(raw);
            } else {
                return c.error(400, "bad_request", "provide either caseId or eml");
            }
        } else {
            // The value is a case identifier, not a Message-ID. It was named "message" while
            // cases were still keyed by Message-ID, and the rename to opaque case ids left the
            // parameter name behind, which is the kind of stale name that eventually gets
            // "fixed" by someone guessing. "case" is the name; "message" is accepted so an
            // existing caller is not broken by the correction.
            String id = c.request.queryParam("case");
            if (id == null) id = c.request.queryParam("message"); // legacy alias
            if (id == null || id.isEmpty()) {
                return c.error(400, "bad_request", "the 'case' query parameter is required");
            }
            // A case id is an identifier, not a path. Anything that could be one is refused
            // rather than normalised, because this value reaches the file store.
            if (id.length() > 256 || id.indexOf('/') >= 0 || id.indexOf('\\') >= 0
                    || id.contains("..")) {
                return c.error(400, "bad_request", "the case parameter is not a valid id");
            }
            Map<String, Object> record = cases.find(id);
            if (record == null) return c.error(404, "not_found", "no such case");
            stix.fromCase(record);
        }

        // application/stix+json is part of being correct here, not a convenience: a consumer
        // that receives application/json has no way to know the payload is a STIX bundle.
        audit.append("stix.export", Audit.payload(c.user == null ? "unknown" : c.user, "stix-bundle", "success", "format=stix+json"));
        Http.Response r = new Http.Response().status(200);
        r.contentType = "application/stix+json; charset=utf-8";
        return r.text(Json.write(stix.build()));
    }

    /**
     * Parses a request body as a JSON object.
     *
     * {@link Json} already bounds nesting depth. This adds the object-shape check, because a bare
     * array or number at the top level is not something any route here can act on, and accepting
     * it would mean every route re-checked the shape.
     */
    private static Map<String, Object> readJsonObject(byte[] body)
            throws Http.RequestException {
        if (body.length == 0) {
            throw new Http.RequestException(400, "empty_body", "a JSON object body is required");
        }
        // Invalid UTF-8 is rejected before the JSON parser sees it: a decoder that substituted
        // replacement characters would let a mangled body parse as valid JSON.
        String text = Http.decodeBody(body);
        Object parsed;
        try {
            parsed = Json.parseObject(text);
        } catch (RuntimeException e) {
            throw new Http.RequestException(400, "malformed_json", "the body is not valid JSON");
        }
        if (!(parsed instanceof Map)) {
            throw new Http.RequestException(400, "malformed_json",
                    "the body must be a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) parsed;
        return m;
    }

    // ==================================================================
    // Evidence extraction
    // ==================================================================

    static Set<String> collectDomains(EmailParser.Message m) {
        Set<String> out = new LinkedHashSet<>();
        for (List<EmailParser.Address> group : List.of(m.from, m.to, m.cc, m.bcc)) {
            for (EmailParser.Address a : safeList(group)) {
                if (a != null && a.domain != null && !a.domain.isBlank()) {
                    out.add(a.domain.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        for (EmailParser.ReceivedHop h : safeList(m.hops)) {
            if (h != null && h.host != null && !h.host.isBlank()) {
                out.add(h.host.trim().toLowerCase(Locale.ROOT));
            }
        }
        return out;
    }

    /**
     * Observed full email addresses, as {@code local@domain} for every addr-spec header value.
     *
     * Kept separate from {@link #collectDomains} because the two are different facts. A correlation
     * document that lists domains in its address field reports "this message touched this host"
     * as if it were "this message came from this mailbox", and an STIX {@code email-addr} object
     * whose value is a bare domain is not a valid address. Only addresses the parser actually saw
     * are included; group syntax and comment-only addresses have no addr-spec and are skipped
     * rather than guessed at.
     */
    static Set<String> collectAddresses(EmailParser.Message m) {
        Set<String> out = new LinkedHashSet<>();
        for (List<EmailParser.Address> group : List.of(m.from, m.to, m.cc, m.bcc)) {
            for (EmailParser.Address a : safeList(group)) {
                if (a == null || !a.isAddrSpec()) continue;
                String local = a.localPart.trim();
                String domain = a.domain.trim().toLowerCase(Locale.ROOT);
                if (local.isEmpty() || domain.isEmpty()) continue;
                out.add(local + "@" + domain);
            }
        }
        return out;
    }

    /**
     * Observed IP literals from the {@code Received} chain.
     *
     * These are the only hop addresses the message carries, and they are recorded as literals the
     * parser actually read out of a header. None of them is asserted to be the origin: a
     * {@code Received} header is written by each hop for the hops before it, so the topmost entry
     * is the earliest claim in the chain and a {@code for} clause inside a header can be attacker
     * text. The list is evidence of what was written, not an attribution.
     *
     * Kept separate from {@link #collectDomains} because a hostname and an address are different
     * facts, and dropping the literals on the floor would mean a case export reported the message's
     * infrastructure as hostnames only.
     */
    static Set<String> collectHopAddresses(EmailParser.Message m) {
        Set<String> out = new LinkedHashSet<>();
        for (EmailParser.ReceivedHop h : safeList(m.hops)) {
            if (h == null || h.ip == null || h.ip.isBlank()) continue;
            String ip = h.ip.trim();
            // The parser reports a bracketed literal. Anything with a zone id or a stray bracket is
            // not a bare address and is not emitted as one.
            if (ip.indexOf('%') >= 0 || ip.indexOf('[') >= 0 || ip.indexOf(']') >= 0) continue;
            out.add(ip);
        }
        return out;
    }

    private static Set<String> collectFileTypes(EmailParser.Message m) {
        Set<String> out = new LinkedHashSet<>();
        for (EmailParser.Part p : safeList(m.parts)) {
            if (p != null && p.contentType != null && !p.contentType.isBlank()) {
                out.add(p.contentType.trim().toLowerCase(Locale.ROOT));
            }
        }
        return out;
    }

    private static Set<String> headerNames(EmailParser.Message m) {
        Set<String> out = new LinkedHashSet<>();
        for (String k : m.headers.keySet()) {
            if (k != null && !k.isBlank()) out.add(k.trim().toLowerCase(Locale.ROOT));
        }
        return out;
    }

    static Set<String> collectAttachmentHashes(EmailParser.Message m) {
        Set<String> out = new LinkedHashSet<>();
        for (EmailParser.Part p : safeList(m.parts)) {
            if (p == null || !p.isAttachment || p.data == null || p.data.length == 0) continue;
            // A truncated part would hash to a hash of the wrong bytes, so it produces no hash.
            if (p.truncated) continue;
            String h = Correlate.contentHash(p);
            if (h != null && !h.isBlank()) out.add(h);
        }
        return out;
    }

    private static List<Object> addressesOf(List<EmailParser.Address> list) {
        List<Object> out = new ArrayList<>();
        for (EmailParser.Address a : safeList(list)) {
            if (a != null) out.add(truncate(a.raw, 256));
        }
        return out;
    }

    private static Map<String, Object> parsedSummary(EmailParser.Message m) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("hops", m.hops.size());
        o.put("parts", m.parts.size());
        o.put("urls", m.urls.size());
        o.put("warnings", m.warnings.size());
        o.put("truncated", m.truncated);
        o.put("bytesConsumed", m.bytesConsumed);
        return o;
    }

    private static Map<String, Object> featureSummary(Features.Vector v) {
        int observed = 0;
        for (boolean b : v.observedArray()) {
            if (b) observed++;
        }
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("observed", observed);
        o.put("total", Features.COUNT);
        return o;
    }

    /**
     * Shapes a model score for the response.
     *
     * {@link Model.Score} exposes its fields but no serialiser, so this reads the public fields
     * directly. Only fields that actually hold a computed value are included: a finding list that
     * the model left empty is reported as an empty list rather than padded, and a class
     * probability vector is included as computed.
     */
    private static Map<String, Object> modelSummary(Model.Score s) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("modelVersion", s.modelVersion);
        o.put("weightsSource", s.weightsSource);
        o.put("trainedOn", s.trainedOn);
        o.put("risk", s.risk);
        o.put("riskFinal", s.riskFinal);
        o.put("becScore", s.becScore);
        o.put("cModel", s.cModel);
        o.put("cAttr", s.cAttr);
        o.put("band", nullSafe(s.band));
        o.put("verdict", nullSafe(s.verdict));
        o.put("alertEligible", s.alertEligible);
        o.put("caseCreationEnabled", s.caseCreationEnabled);
        o.put("abstentionReason", nullSafe(s.abstentionReason));
        o.put("argmax", s.argmax);
        o.put("argmaxClass", s.argmaxClass == null ? "" : String.valueOf(s.argmaxClass));
        o.put("becBlendMethod", nullSafe(s.becBlendMethod));
        o.put("becEvidenceBacked", s.becEvidenceBacked);
        List<Object> classes = new ArrayList<>();
        for (Config.Cls c : Config.Cls.values()) {
            classes.add(String.valueOf(c));
        }
        o.put("classes", classes);
        List<Object> p = new ArrayList<>();
        for (double v : s.p) {
            p.add(v);
        }
        o.put("p", p);
        return o;
    }

    /**
     * Builds the additive feature breakdown by family (AUTH, ROUTE, IDENT, NLP, PAYLOAD, INFRA).
     * This is the authoritative server-side computation; the frontend MUST NOT recompute it.
     * Returns per-family contribution sums and per-feature evidence for the predicted class.
     */
    private static Map<String, Object> featureBreakdown(Model.Score s) {
        Map<String, Object> o = new LinkedHashMap<>();
        if (s.findings == null || s.findings.isEmpty()) {
            o.put("families", List.of());
            o.put("totalContribution", 0.0);
            return o;
        }
        int families = Config.FAMILY_NAMES.length;
        double[] sum = new double[families];
        List<Map<String, Object>> perFeature = new ArrayList<>();

        // The findings are for the predicted class (argmax). Group by family.
        for (Model.Finding f : s.findings) {
            int fam = f.family;
            if (fam >= 0 && fam < families) {
                sum[fam] += f.contribution;
            }
            Map<String, Object> feat = new LinkedHashMap<>();
            feat.put("featureIndex", f.featureIndex);
            feat.put("family", Config.FAMILY_NAMES[fam]);
            feat.put("x", f.x);
            feat.put("beta", f.beta);
            feat.put("contribution", f.contribution);
            perFeature.add(feat);
        }

        List<Map<String, Object>> familiesList = new ArrayList<>();
        double total = 0;
        for (int i = 0; i < families; i++) {
            Map<String, Object> fam = new LinkedHashMap<>();
            fam.put("name", Config.FAMILY_NAMES[i]);
            fam.put("contribution", sum[i]);
            familiesList.add(fam);
            total += sum[i];
        }

        o.put("families", familiesList);
        o.put("perFeature", perFeature);
        o.put("totalContribution", total);
        o.put("intercept", s.logits != null ? s.logits.intercept[s.argmax] : 0.0);
        o.put("z", s.logits != null ? s.logits.z[s.argmax] : 0.0);
        return o;
    }

    private static Map<String, Object> correlationSummary(
            Correlate.Document d, Correlate.Campaign campaign) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("documentId", d.id);
        o.put("risk", d.risk);
        o.put("confidence", d.confidence);
        o.put("domains", d.domains.size());
        o.put("urls", d.urls.size());
        o.put("attachmentHashes", d.attachmentHashes.size());
        o.put("documentsConsidered", campaign == null ? 0 : campaign.documentsConsidered);
        o.put("clusters", campaign == null ? List.of() : campaign.clusters.size());
        o.put("unclustered", campaign == null ? List.of() : campaign.unclustered);
        o.put("disclaimer", campaign == null ? Correlate.disclaimer()
                : campaign.disclaimer);
        return o;
    }

    /**
     * Builds the case record for a message the model flagged.
     *
     * Every field is derived from the analysis that just ran. There is no placeholder title, no
     * synthetic timestamp and no sample member: a case that would exist even with no evidence in
     * it is not evidence.
     */
    private static Map<String, Object> buildCase(String docId, EmailParser.Message m,
            Model.Score score, Attribution.Result attr, byte[] raw) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", newCaseId()); // opaque server-generated case id
        c.put("documentId", docId); // correlation document id (Message-ID or sha256)
        c.put("status", "open");
        c.put("title", truncate(nonEmpty(m.subject, "(no subject)"), 256));
        c.put("subject", truncate(nonEmpty(m.subject, ""), 512));
        c.put("messageId", nullSafe(m.messageId));
        c.put("observedAt", observedAt(m));
        c.put("createdAt", System.currentTimeMillis());
        c.put("risk", score.risk);
        c.put("riskFinal", score.riskFinal);
        c.put("confidence", score.cModel);
        c.put("verdict", nullSafe(score.verdict));
        c.put("band", nullSafe(score.band));
        c.put("domains", new ArrayList<>(collectDomains(m)));
        // Recorded separately from domains so the STIX exporter can emit a real email-addr value
        // without having to invent a mailbox from a hostname.
        c.put("addresses", new ArrayList<>(collectAddresses(m)));
        // The bracketed literals from the Received chain. Kept because they are observed evidence
        // in their own right, and because a case export that dropped them would silently lose the
        // only hop addresses the message carried.
        c.put("hopAddresses", new ArrayList<>(collectHopAddresses(m)));
        c.put("urls", new ArrayList<>(new LinkedHashSet<>(safeList(m.urls))));
        c.put("attachmentHashes", new ArrayList<>(collectAttachmentHashes(m)));
        c.put("members", List.of(docId));
        c.put("evidenceHash", sha256Hex(raw));
        c.put("attribution", attr == null ? Map.of() : attr.toMap());
        return c;
    }

    /** Generates an opaque server-side case identifier. */
    private static String newCaseId() {
        byte[] raw = new byte[16];
        new SecureRandom().nextBytes(raw);
        return "case-" + hex(raw);
    }

    // ==================================================================
    // Small utilities
    // ==================================================================

    private static <T> List<T> safeList(List<T> l) {
        return l == null ? List.of() : l;
    }

    private static String nonEmpty(String s, String fallback) {
        return s == null || s.isBlank() ? fallback : s;
    }

    static String nullSafe(String s) {
        return s == null ? "" : s;
    }

    /** Truncates, marking the cut so a consumer can tell the value is incomplete. */
    static String truncate(String s, int max) {
        if (s == null) return null;
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...[truncated]";
    }

    private static long asLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        if (o instanceof String s) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return Long.MIN_VALUE;
            }
        }
        return Long.MIN_VALUE;
    }

    private static String asString(Object o) {
        if (o == null) return null;
        String s = String.valueOf(o);
        return s.isEmpty() ? null : s;
    }

    static String sha256Hex(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16));
            sb.append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    // ==================================================================
    // Authentication and lockout
    // ==================================================================

    /**
     * Credential store, session table and failure tracking.
     *
     * Three properties drive the design:
     *
     *   <b>No enumeration.</b> An unknown username and a wrong password cost the same and take the
     *   same time, because both run a full PBKDF2 verification. The unknown-user path verifies
     *   against a dummy hash generated at startup for exactly this purpose. If the two paths
     *   differed in cost, the endpoint would publish the list of valid usernames.
     *
     *   <b>No plaintext.</b> Only a salt, an iteration count and the derived key are stored. The
     *   password exists as a {@code char[]} for the duration of verification and is zeroed
     *   immediately; it is never written, never logged and never carried in an exception.
     *
     *   <b>Server-side time.</b> Failure timestamps come from the system clock. A lockout decided
     *   by a client-supplied timestamp is a lockout the client can reset by lying.
     *
     * Reset policy, stated explicitly because it is the part most often left ambiguous:
     *
     *   - Five failures for an account within fifteen minutes locks it.
     *   - The lock runs for that same fifteen-minute window from the most recent failure, so an
     *     attacker who keeps hammering extends nothing: the window rolls forward but the lock is
     *     re-evaluated from the newest entry each time.
     *   - A successful authentication clears the account's failure record and any lock.
     *   - Once the window elapses the record is treated as expired and the account is usable again
     *     without an explicit unlock, starting from a clean count rather than a stale one.
     *   - The per-address record is separate and is not cleared by a success. The address throttle
     *     exists to detect spraying, and one correct login does not make a spray pattern benign.
     */
    public static final class Auth {

        /** One stored credential. There is deliberately no password field. */
        static final class User {
            String name;
            byte[] salt;
            byte[] hash;
            int iterations = Config.AUTH_PBKDF2_ITERATIONS;
            final List<String> roles = new ArrayList<>();
            boolean disabled;
        }

        /** Per-identifier failure state, used for both the account and the client address. */
        private static final class Failure {
            final List<Long> times = new ArrayList<>();
            long lockedUntil;
        }

        private static final class Session {
            final String user;
            final long expiresAt;

            Session(String user, long expiresAt) {
                this.user = user;
                this.expiresAt = expiresAt;
            }
        }

        /** The result of a login attempt, distinguishing a lockout from a bad credential. */
        public static final class Outcome {
            public final boolean ok;
            public final boolean locked;
            public final String token;

            Outcome(boolean ok, boolean locked, String token) {
                this.ok = ok;
                this.locked = locked;
                this.token = token;
            }
        }

        private final Path path;
        private final Map<String, User> users = new ConcurrentHashMap<>();
        private final Map<String, Failure> byAccount = new ConcurrentHashMap<>();
        /** Address-level failures: records spray signal only. Never used to block on loopback. */
        private final Map<String, Failure> byAddress = new ConcurrentHashMap<>();
        /** Maximum distinct address keys tracked; excess entries are silently dropped to bound memory. */
        private static final int MAX_ADDRESS_KEYS = 1024;
        private final Map<String, Session> sessions = new ConcurrentHashMap<>();
        private final SecureRandom random = new SecureRandom();
        private final Audit audit;

        /**
         * A hash of a value nobody knows, used to equalise the cost of the unknown-user path.
         *
         * Generated rather than hard-coded, so it is not a preimage of a guessable string, and
         * regenerated each start. It is a timing equaliser, not a credential.
         */
        private byte[] dummyHash;
        private byte[] dummySalt;

        Auth(Path path, Audit audit) {
            this.path = path;
            this.audit = audit;
        }

        /** Reads the user store. A missing file yields an empty store, not a failure. */
        void load() throws IOException {
            dummySalt = new byte[Config.AUTH_SALT_BYTES];
            random.nextBytes(dummySalt);
            dummyHash = pbkdf2("no such user".toCharArray(), dummySalt,
                    Config.AUTH_PBKDF2_ITERATIONS);

            if (!Files.exists(path)) return;
            // Streamed line by line under a record and byte cap, rather than read whole. The store
            // is a file this process appends to, so its length is not under the caller's control:
            // reading it all would let anyone who can write to the data directory decide how much
            // memory the service allocates at startup.
            int lineNo = 0;
            try (java.io.BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                String line;
                long bytes = 0;
                while ((line = br.readLine()) != null) {
                    lineNo++;
                    bytes += line.length() + 1L;
                    if (lineNo > MAX_USERS_LOADED) {
                        System.err.println("[cipher-squad] users.ndjson holds more than "
                                + MAX_USERS_LOADED + " records; later records were not loaded");
                        break;
                    }
                    if (bytes > MAX_STORE_BYTES) {
                        System.err.println("[cipher-squad] users.ndjson exceeds the "
                                + MAX_STORE_BYTES + " byte load limit; remaining records skipped");
                        break;
                    }
                    if (line.isBlank()) continue;
                    // A corrupt line is skipped and counted, not fatal. One damaged record must not
                    // make every account on the box unusable.
                    Map<?, ?> m;
                    try {
                        Object p = Json.parseObject(line);
                        if (!(p instanceof Map)) {
                            System.err.println("[cipher-squad] users.ndjson line " + lineNo
                                    + " is not a JSON object; skipped");
                            continue;
                        }
                        m = (Map<?, ?>) p;
                    } catch (RuntimeException e) {
                        System.err.println("[cipher-squad] users.ndjson line " + lineNo
                                + " is not valid JSON; skipped");
                        continue;
                    }
                    try {
                        User u = parseUser(m);
                        if (u != null) users.put(u.name, u);
                    } catch (RuntimeException e) {
                        System.err.println("[cipher-squad] users.ndjson line " + lineNo
                                + " is malformed; skipped");
                    }
                }
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException("cannot read " + path, e);
            }
        }

        private static User parseUser(Map<?, ?> m) {
            String name = asString(m.get("user"));
            String saltHex = asString(m.get("salt"));
            String hashHex = asString(m.get("hash"));
            if (name == null || name.isEmpty() || saltHex == null || hashHex == null) {
                return null;
            }
            User u = new User();
            u.name = name;
            u.salt = unhex(saltHex);
            u.hash = unhex(hashHex);
            if (u.salt.length == 0 || u.hash.length == 0) return null;
            Integer it = asInt(m.get("iterations"));
            // A stored iteration count is honoured only inside a band. An unbounded value read
            // from a writable file is a denial-of-service primitive; a value below the floor would
            // silently weaken every credential on the box, including the ones beside it.
            if (it != null && it >= 10_000 && it <= 5_000_000) {
                u.iterations = it;
            }
            if (m.get("roles") instanceof List<?> roles) {
                for (Object o : roles) {
                    if (o != null) u.roles.add(String.valueOf(o));
                }
            }
            u.disabled = Boolean.TRUE.equals(m.get("disabled"));
            return u;
        }

        /**
         * Creates a credential record and appends it to the store.
         *
         * Exposed so provisioning goes through the one path that hashes, rather than through a
         * second, weaker way of writing credentials. The caller's password array is zeroed before
         * this returns, on success and on failure alike.
         */
        public synchronized String upsert(String name, char[] password, List<String> roles)
                throws IOException {
            try {
                if (name == null || name.isBlank() || name.length() > 64) {
                    throw new IllegalArgumentException("user name must be 1-64 characters");
                }
                if (password == null || password.length < 12 || password.length > 256) {
                    throw new IllegalArgumentException("password must be 12-256 characters");
                }
                byte[] salt = new byte[Config.AUTH_SALT_BYTES];
                random.nextBytes(salt);
                byte[] hash = pbkdf2(password, salt, Config.AUTH_PBKDF2_ITERATIONS);

                Map<String, Object> rec = new LinkedHashMap<>();
                rec.put("user", name);
                rec.put("salt", hex(salt));
                rec.put("hash", hex(hash));
                rec.put("iterations", Config.AUTH_PBKDF2_ITERATIONS);
                rec.put("roles", roles == null ? List.of() : List.copyOf(roles));
                rec.put("created", System.currentTimeMillis());
                rec.put("disabled", false);
                appendLine(path, Json.write(rec));

                User u = parseUser(rec);
                if (u == null) {
                    throw new IllegalStateException("credential record did not round-trip");
                }
                users.put(u.name, u);

                // A credential appearing is a security event. Recording it is what makes a
                // backdoor account visible in the chain instead of merely present in the store --
                // otherwise the one action an operator can take that silently grants access
                // leaves no trace at all.
                if (audit != null) {
                    audit.append("auth.provision", Audit.payload("operator", u.name, "success",
                            "roles=" + (roles == null ? "" : String.join(",", roles))));
                }
                return u.name;
            } finally {
                // The cleartext does not outlive the call, whatever happened. The derived key
                // survives, because it is the credential.
                if (password != null) Arrays.fill(password, '\0');
            }
        }

        /**
         * Verifies a username and password, applying the lockout rules on failure.
         *
         * A PBKDF2 derivation always happens, on every path including an unknown user, a disabled
         * account and an address-locked caller, so the time taken by a request carries no
         * information about which usernames exist or which are locked.
         *
         * @return an {@link Outcome} that is either a session token, a lockout, or a failure
         */
        public Outcome login(String name, char[] password, String client) {
            long now = System.currentTimeMillis();
            char[] pw = password == null ? new char[0] : password;

            // Address-based lockout is sound only when client addresses actually distinguish callers.
            // This service binds to loopback, so all clients share 127.0.0.1 and an address lock
            // would become a global DoS. Record the signal for diagnostics, but never block on it.

            User u = name == null ? null : users.get(name);
            byte[] salt = u == null ? dummySalt : u.salt;
            byte[] expect = u == null ? dummyHash : u.hash;
            int iterations = u == null ? Config.AUTH_PBKDF2_ITERATIONS : u.iterations;

            byte[] actual = pbkdf2(pw, salt, iterations);
            boolean pwOk = MessageDigest.isEqual(expect, actual);

            // An unknown user, a wrong password and a disabled account are the same outcome, and
            // all three have already paid the same derivation cost by the time this is reached.
            boolean ok = pwOk && u != null && !u.disabled;
            String actor = name == null ? "unknown" : name;
            if (!ok) {
                recordFailure(byAccount, name == null ? "" : name, now);
                recordFailure(byAddress, client, now);
                // The account may have just crossed the threshold, in which case the honest
                // answer is a lockout rather than another chance.
                boolean nowLocked = isLocked(byAccount, name == null ? "" : name, now);
                audit.append("login.failure", Audit.payload(actor, client, "failure", nowLocked ? "account locked" : "bad credentials"));
                return new Outcome(false, nowLocked, null);
            }

            // A locked account is refused even when the password is correct. Clearing the record on
            // a correct password would mean the lock expires the instant an attacker who already
            // has the credential tries again, which is exactly the case the lock exists to stop.
            // The window has to elapse instead. The derivation above is still paid first, so this
            // refusal is not distinguishable by timing.
            if (isLocked(byAccount, name, now)) {
                audit.append("login.failure", Audit.payload(actor, client, "failure", "account locked"));
                return new Outcome(false, true, null);
            }

            // A success clears the account record. It does not clear the address record: that one
            // exists to detect spraying, and one correct login does not make spraying benign.
            byAccount.remove(name);
            audit.append("login.success", Audit.payload(actor, client, "success", "session issued"));
            return new Outcome(true, false, issueSession(u.name));
        }

        /** Issues an opaque session token bound to a user for the configured lifetime. */
        private String issueSession(String user) {
            byte[] raw = new byte[Config.AUTH_SESSION_TOKEN_BYTES];
            random.nextBytes(raw);
            String token = hex(raw);
            sessions.put(token, new Session(user,
                    System.currentTimeMillis() + Config.AUTH_SESSION_TTL_MS));
            return token;
        }

        /**
         * Validates a session token.
         *
         * Expired entries are removed on sight rather than by a sweeper, so a token stops working
         * the moment it expires regardless of whether any background process is running. The token
         * is 32 random bytes, so the lookup is not a comparison against guessable material.
         */
        public String validateSession(String token) {
            Session s = sessions.get(token);
            if (s == null) return null;
            if (System.currentTimeMillis() > s.expiresAt) {
                sessions.remove(token);
                return null;
            }
            return s.user;
        }

        public void invalidateSession(String token) {
            sessions.remove(token);
        }

        public int activeSessions() {
            return sessions.size();
        }

        public int userCount() {
            return users.size();
        }

        /**
         * Whether a credential record already exists for this name.
         *
         * Exists so provisioning can refuse to append a second record for a name that is already
         * taken. The store is append-only, so a second record would load last and silently win,
         * leaving the previous password unusable and the operator with no record of which
         * credential is live.
         */
        public boolean hasUser(String name) {
            return name != null && users.containsKey(name);
        }

        /** True when the account is currently locked. Exposed for diagnostics and tests. */
        public boolean isAccountLocked(String name) {
            return isLocked(byAccount, name, System.currentTimeMillis());
        }

        public boolean isAddressLocked(String client) {
            return isLocked(byAddress, client, System.currentTimeMillis());
        }

        /** Number of failures currently inside the account's window. For tests. */
        public int recentFailures(String name) {
            Failure f = byAccount.get(name);
            if (f == null) return 0;
            synchronized (f) {
                prune(f, System.currentTimeMillis());
                return f.times.size();
            }
        }

        private boolean isLocked(Map<String, Failure> map, String key, long now) {
            if (key == null || key.isEmpty()) return false;
            Failure f = map.get(key);
            if (f == null) return false;
            synchronized (f) {
                prune(f, now);
                return now < f.lockedUntil;
            }
        }

        /**
         * Records a failure and applies the threshold.
         *
         * Pruning runs first, so the window holds only genuinely recent failures. Without it, a
         * slow trickle would accumulate forever and eventually lock an account that has not
         * actually attempted anything wrong inside the window.
         *
         * The address map is capped to prevent unbounded memory growth from attacker-controlled keys.
         */
        private void recordFailure(Map<String, Failure> map, String key, long now) {
            if (key == null || key.isEmpty()) return;
            // Cap the address map: if it's the address map and we're at capacity and the key is new,
            // silently drop the record. The signal is best-effort anyway.
            if (map == byAddress && !map.containsKey(key) && map.size() >= MAX_ADDRESS_KEYS) {
                return;
            }
            Failure f = map.computeIfAbsent(key, k -> new Failure());
            synchronized (f) {
                prune(f, now);
                f.times.add(now);
                if (f.times.size() >= Config.AUTH_MAX_FAILURES) {
                    f.lockedUntil = now + Config.AUTH_FAILURE_WINDOW_MS;
                }
            }
        }

        /**
         * Drops failures that have aged out, and clears an expired lock.
         *
         * An expired lock clears the counter as well as the lock. Carrying a stale counter forward
         * would mean one further failure re-locks the account immediately, so a user who waited
         * out the window would still be locked out for another full window.
         */
        private void prune(Failure f, long now) {
            long cutoff = now - Config.AUTH_FAILURE_WINDOW_MS;
            f.times.removeIf(t -> t < cutoff);
            if (f.lockedUntil != 0 && now >= f.lockedUntil) {
                f.lockedUntil = 0;
                f.times.clear();
            }
        }

        /**
         * PBKDF2-HMAC-SHA256 with a 256-bit output.
         *
         * The iteration count is the configured one and this is the only place it is set. The
         * spec is cleared in a finally block: a {@code PBEKeySpec} retains the char[] it was
         * given and the JDK does not promise to clear it otherwise.
         */
        static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
            try {
                SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
                try {
                    return f.generateSecret(spec).getEncoded();
                } finally {
                    spec.clearPassword();
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("PBKDF2 unavailable", e);
            }
        }

        private static Integer asInt(Object o) {
            if (o instanceof Number n) return n.intValue();
            if (o instanceof String s) {
                try {
                    return Integer.valueOf(s);
                } catch (NumberFormatException e) {
                    return null;
                }
            }
            return null;
        }

        private static byte[] unhex(String s) {
            if (s.length() % 2 != 0) {
                throw new IllegalArgumentException("odd-length hex");
            }
            byte[] out = new byte[s.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }
    }

    // ==================================================================
    // Case store
    // ==================================================================

    /**
     * Append-only NDJSON case store.
     *
     * The file is the record of truth and is never rewritten in place. That is what makes the
     * case list auditable: a case cannot be silently edited away, only superseded by a later
     * line.
     *
     * Every write takes an exclusive file lock and writes one complete line in a single append,
     * so a reader never sees a line without its terminator. A line torn by a process death is
     * tolerated on read: a trailing incomplete record is skipped rather than making the entire
     * history unreadable.
     */
    public static final class CaseStore {
        private final Path path;
        private final SecureRandom random = new SecureRandom();

        CaseStore(Path path) {
            this.path = path;
        }

        void load() throws IOException {
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            if (!Files.exists(path)) Files.createFile(path);
        }

        Path path() {
            return path;
        }

        /** Appends one case and returns its id. */
        synchronized String append(Map<String, Object> record) throws IOException {
            if (record == null || record.isEmpty()) {
                throw new IllegalArgumentException("case record must not be empty");
            }
            // A record with no observed field of any kind is not a case. Refusing to store one
            // keeps the "no fake cases" property enforceable at the point of write, rather than
            // relying on every future caller to remember the rule.
            if (record.get("risk") == null && record.get("domains") == null
                    && record.get("urls") == null && record.get("attachmentHashes") == null) {
                throw new IllegalArgumentException("case record has no observed evidence");
            }
            String id = asString(record.get("id"));
            if (id == null) {
                id = "case-" + hex(randomBytes(8));
                record.put("id", id);
            }
            appendLine(path, Json.write(record));
            return id;
        }

        /**
         * One bounded read: the records it managed to read, and whether a cap stopped it early.
         *
         * The flag travels with the records instead of being left on the store. A store-level flag
         * is shared mutable state, and the requests are served on a thread pool: one request
         * clearing the flag while another is mid-scan would let a partial scan be reported as
         * complete, which is exactly the failure the flag exists to prevent. Carrying it in the
         * return value makes each read's verdict its own.
         */
        record Scan(List<Map<String, Object>> records, boolean truncated) {}

        /**
         * Reads up to {@code limit} records, tolerating an unparseable line.
         *
         * Streamed under a byte cap as well as the record cap, for the same reason the credential
         * store is: the file's length is not this process's to assume, so a record limit alone
         * would still let a long line be read whole before the cap took effect. The byte budget
         * stops the read, and {@link Scan#truncated()} tells the caller the answer is partial
         * instead of silently implying the whole store was searched.
         */
        Scan scan(int limit) throws IOException {
            if (!Files.exists(path)) return new Scan(List.of(), false);
            List<Map<String, Object>> out = new ArrayList<>();
            boolean partial = false;
            long bytes = 0;
            try (java.io.BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                String line;
                while (out.size() < limit && (line = br.readLine()) != null) {
                    bytes += line.length() + 1L;
                    if (bytes > MAX_STORE_BYTES) {
                        System.err.println("[cipher-squad] cases.ndjson exceeds the "
                                + MAX_STORE_BYTES + " byte read limit; the scan is partial");
                        partial = true;
                        break;
                    }
                    if (line.isBlank()) continue;
                    try {
                        Object p = Json.parseObject(line);
                        if (p instanceof Map) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> m = (Map<String, Object>) p;
                            out.add(m);
                        }
                    } catch (RuntimeException e) {
                        System.err.println("[cipher-squad] cases.ndjson has an unreadable line; skipped");
                    }
                }
            }
            if (out.size() >= limit) partial = true;
            return new Scan(out, partial);
        }

        /** The records a bounded read produced, discarding the partial flag. */
        List<Map<String, Object>> readAll(int limit) throws IOException {
            return scan(limit).records();
        }

        /** Finds one case by exact id. */
        /**
         * The most recent record for {@code id}, or null.
         *
         * The log is append-only and a case's id is its own Message-ID, so re-analysing a message
         * appends a second record under the same id. Returning the first match would then serve the
         * oldest analysis forever: a re-analysis that raised the risk, added a newly observed
         * address, or recorded a newer verdict would be silently ignored, and the caller would be
         * reading a stale object while believing it was current. Scanning to the end and keeping the
         * last match makes the newest write win, which is what an append-only log means.
         *
         * The id is bounded by the same scan limit as any other read, so an id that is absent only
         * because the scan budget ran out is reported as absent rather than as a miss.
         */
        Map<String, Object> find(String id) throws IOException {
            if (id == null || id.isEmpty()) return null;
            Map<String, Object> latest = null;
            for (Map<String, Object> m : readAll(MAX_CASES_SCANNED)) {
                if (id.equals(m.get("id"))) latest = m;
            }
            return latest;
        }

        public int count() throws IOException {
            return readAll(MAX_CASES_SCANNED).size();
        }

        private byte[] randomBytes(int n) {
            byte[] b = new byte[n];
            random.nextBytes(b);
            return b;
        }
    }

    // ==================================================================
    // SSRF guard
    // ==================================================================

    /**
     * Address and hostname validator for any future retrieval path.
     *
     * The service performs no network retrieval, so this is a gate rather than a fetch. It exists
     * now, complete, so that a retrieval path added later inherits a correct check instead of
     * being written from scratch under deadline.
     *
     * The checks are:
     *
     *   <b>Literal parsing, not string matching.</b> IPv4 is parsed as four decimal octets and
     *   IPv6 through the JDK's own parser. A check that reads the text will always find an
     *   obfuscation the parser would have normalised, so padded octets and non-decimal forms are
     *   rejected as malformed rather than string-matched.
     *
     *   <b>Every special range.</b> Loopback, private, link-local, unspecified, multicast,
     *   documentation, benchmarking, CGNAT, reserved, and the IPv4-mapped and NAT64 IPv6 forms are
     *   all refused, each with its own reason so a rejection says why.
     *
     *   <b>Hostname shape.</b> Loopback and reserved TLDs, single-label names, and the well-known
     *   metadata names are refused.
     *
     *   <b>Resolution.</b> {@link Ssrf#resolveAndCheck} resolves and re-validates every returned
     *   address. This is the DNS-rebinding defence: the check is applied to the address that would
     *   actually be used, not to the name that was asked for.
     */
    public static final class Ssrf {

        /** TLDs that can never legitimately resolve to a public service. */
        private static final Set<String> RESERVED_TLDS = Set.of(
                "localhost", "local", "localdomain", "internal", "intranet", "lan", "home",
                "corp", "test", "invalid", "example");

        /** Hostnames used by cloud instance-metadata services. */
        private static final Set<String> METADATA_NAMES = Set.of(
                "metadata", "instance-data", "metadata.google.internal",
                "instance-data.ec2.internal");

        private static final Pattern HOSTNAME_RE = Pattern.compile(
                "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$");

        /** The verdict: allowed, or the reason it was refused. */
        public static final class Decision {
            public final boolean allowed;
            public final String reason;

            private Decision(boolean allowed, String reason) {
                this.allowed = allowed;
                this.reason = reason;
            }

            public static Decision allow() {
                return new Decision(true, "ok");
            }

            public static Decision deny(String reason) {
                return new Decision(false, reason);
            }

            @Override
            public String toString() {
                return allowed ? "allow" : "deny:" + reason;
            }
        }

        /**
         * Validates one host: an IP literal or a hostname.
         *
         * <b>What this does and does not decide.</b> An IP literal is range-checked as a literal,
         * and that verdict is final. A hostname is checked for shape only, because a name cannot be
         * range-checked without resolving it, and a name that looks public can resolve to anything.
         * So an {@code allow} from this method means "the text is a plausible public host", not
         * "this host is safe to connect to". A caller that will actually connect must use
         * {@link #resolveAndCheck}, which decides on the address rather than the name.
         */
        public Decision check(String host) {
            if (host == null || host.isBlank()) return Decision.deny("empty_host");
            String h = host.trim();
            if (h.length() > MAX_HOST_CHARS) return Decision.deny("host_too_long");

            // A bracketed IPv6 literal, as it appears in a URL authority.
            if (h.length() > 2 && h.charAt(0) == '[' && h.charAt(h.length() - 1) == ']') {
                h = h.substring(1, h.length() - 1);
            }
            String lower = h.toLowerCase(Locale.ROOT);

            if (METADATA_NAMES.contains(lower)) return Decision.deny("cloud_metadata_name");
            if (RESERVED_TLDS.contains(lower)) return Decision.deny("reserved_hostname");
            for (String tld : RESERVED_TLDS) {
                if (lower.endsWith("." + tld)) return Decision.deny("reserved_tld");
            }
            // "0x7f.1" and "127.1" both look numeric and both are non-canonical forms that a
            // resolver may read as loopback. They are not valid IPv4 literals, so they are
            // refused as malformed instead of being parsed loosely. A leading "0x", or a part
            // with a leading zero, is a hex or octal form that some resolvers honour and this
            // guard must not.
            if (lower.startsWith("0x") || hasPaddedPart(lower)) {
                return Decision.deny("non_canonical_ip_literal");
            }
            if (looksNumeric(lower)) return checkLiteral(lower);
            if (lower.indexOf(':') >= 0) return checkLiteral(lower);
            if (lower.indexOf('.') < 0) return Decision.deny("non_fqdn_hostname");
            if (!HOSTNAME_RE.matcher(lower).matches()) return Decision.deny("malformed_hostname");
            return Decision.allow();
        }

        /**
         * True when any dotted part carries a leading zero.
         *
         * "010.0.0.1" is read as octal 8.0.0.1 by some resolvers and as decimal 10.0.0.1 by others,
         * so the same text can be both private and public depending on who parses it. Only a
         * single "0" is unambiguous, so anything longer is refused.
         */
        private static boolean hasPaddedPart(String h) {
            int start = 0;
            while (start <= h.length()) {
                int dot = h.indexOf('.', start);
                String part = dot < 0 ? h.substring(start) : h.substring(start, dot);
                if (part.length() > 1 && part.charAt(0) == '0') return true;
                if (dot < 0) break;
                start = dot + 1;
            }
            return false;
        }

        private static boolean looksNumeric(String h) {
            if (h.indexOf('.') < 0) return false;
            for (int i = 0; i < h.length(); i++) {
                char c = h.charAt(i);
                if (c != '.' && (c < '0' || c > '9')) return false;
            }
            return true;
        }

        /**
         * Range-checks an IP literal.
         *
         * IPv4 is parsed strictly. Each octet must be one to three decimal digits with no leading
         * zero: "127.000.000.001" is refused rather than read as 127.0.0.1, because a component
         * that accepts the padded form will also accept forms that different resolvers read
         * differently, and that disagreement is the vulnerability.
         */
        public Decision checkLiteral(String ip) {
            String s = ip == null ? "" : ip.trim();
            if (s.isEmpty()) return Decision.deny("empty_host");
            if (s.indexOf(':') >= 0) return checkIpv6(s);
            if (s.startsWith("0x") || s.indexOf(':') >= 0) return Decision.deny("malformed_ipv4");

            String[] parts = s.split("\\.", -1);
            if (parts.length != 4) return Decision.deny("malformed_ipv4");
            int[] o = new int[4];
            for (int i = 0; i < 4; i++) {
                String p = parts[i];
                if (p.isEmpty() || p.length() > 3) return Decision.deny("malformed_ipv4");
                if (p.length() > 1 && p.charAt(0) == '0') return Decision.deny("padded_octet");
                for (int j = 0; j < p.length(); j++) {
                    if (p.charAt(j) < '0' || p.charAt(j) > '9') {
                        return Decision.deny("malformed_ipv4");
                    }
                }
                int v = Integer.parseInt(p);
                if (v > 255) return Decision.deny("malformed_ipv4");
                o[i] = v;
            }
            return checkIpv4(o);
        }

        /** Every IPv4 range that must not be reachable, each with its own reason. */
        private static Decision checkIpv4(int[] o) {
            int a = o[0];
            int b = o[1];
            int c = o[2];
            if (a == 0) return Decision.deny("unspecified");
            if (a == 127) return Decision.deny("loopback");
            if (a == 10) return Decision.deny("private");
            if (a == 172 && b >= 16 && b <= 31) return Decision.deny("private");
            if (a == 192 && b == 168) return Decision.deny("private");
            if (a == 169 && b == 254) return Decision.deny("link_local");
            if (a == 100 && b >= 64 && b <= 127) return Decision.deny("cgnat");
            if (a == 192 && b == 0 && c == 0) return Decision.deny("ietf_protocol_assignment");
            if (a == 192 && b == 0 && c == 2) return Decision.deny("documentation");
            if (a == 192 && b == 88 && c == 99) return Decision.deny("6to4_relay");
            if (a == 198 && (b == 18 || b == 19)) return Decision.deny("benchmarking");
            if (a == 198 && b == 51 && c == 100) return Decision.deny("documentation");
            if (a == 203 && b == 0 && c == 113) return Decision.deny("documentation");
            if (a >= 224 && a <= 239) return Decision.deny("multicast");
            if (a >= 240) return Decision.deny("reserved");
            return Decision.allow();
        }

        private static Decision checkIpv6(String s) {
            // A zone id is meaningless for a remote connection and is a known way to make one
            // address have two texts, so it is refused rather than stripped.
            if (s.indexOf('%') >= 0) return Decision.deny("ipv6_zone_id");
            byte[] b;
            try {
                b = InetAddress.getByName(s).getAddress();
            } catch (IOException e) {
                return Decision.deny("malformed_ipv6");
            }
            if (b.length != 16) return Decision.deny("malformed_ipv6");

            if (isIpv4Mapped(b) || isNat64(b)) {
                // The embedded IPv4 address is what the packet reaches, so it gets the same range
                // logic. Trusting the outer form would let any mapped range through.
                Decision d = checkIpv4(new int[] {
                        b[12] & 0xff, b[13] & 0xff, b[14] & 0xff, b[15] & 0xff});
                if (!d.allowed) return d;
            }
            if (allZero(b)) return Decision.deny("unspecified");
            if (isIpv6Loopback(b)) return Decision.deny("loopback");
            if ((b[0] & 0xfe) == 0xfc) return Decision.deny("unique_local");
            if (b[0] == (byte) 0xfe && (b[1] & 0xc0) == 0x80) return Decision.deny("link_local");
            if (b[0] == (byte) 0xff) return Decision.deny("multicast");
            // ::/96 outside the mapped and loopback forms is the deprecated IPv4-compatible
            // encoding, a known source of parser confusion between components.
            if (isIpv4Compatible(b)) return Decision.deny("ipv4_compatible");
            if (isTeredo(b)) return Decision.deny("teredo");
            // 2001:db8::/32 is the IPv6 documentation range. It is not routable, so a name or
            // literal in it cannot reach a real service, and the same reasoning that refuses the
            // IPv4 documentation ranges applies here.
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == (byte) 0x0d && b[3] == (byte) 0xb8) {
                return Decision.deny("documentation");
            }
            // 2002::/16 is 6to4, which encapsulates an IPv4 address in the middle of the prefix.
            // The embedded address is what the packet ultimately reaches, so it is range-checked
            // the same way a mapped address is rather than trusted because of its outer form.
            if (b[0] == 0x20 && b[1] == 0x02) {
                Decision d = checkIpv4(new int[] {
                        b[2] & 0xff, b[3] & 0xff, b[4] & 0xff, b[5] & 0xff});
                if (!d.allowed) return d;
            }
            return Decision.allow();
        }

        private static boolean allZero(byte[] b) {
            for (byte x : b) {
                if (x != 0) return false;
            }
            return true;
        }

        private static boolean isIpv6Loopback(byte[] b) {
            if (b[15] != 1) return false;
            for (int i = 0; i < 15; i++) {
                if (b[i] != 0) return false;
            }
            return true;
        }

        private static boolean isIpv4Mapped(byte[] b) {
            for (int i = 0; i < 10; i++) {
                if (b[i] != 0) return false;
            }
            return b[10] == (byte) 0xff && b[11] == (byte) 0xff;
        }

        private static boolean isNat64(byte[] b) {
            return b[0] == 0 && b[1] == 0x64 && b[2] == (byte) 0xff && b[3] == (byte) 0x9b;
        }

        private static boolean isIpv4Compatible(byte[] b) {
            for (int i = 0; i < 12; i++) {
                if (b[i] != 0) return false;
            }
            return b[12] != 0 || b[13] != 0 || b[14] != 0 || b[15] <= 1;
        }

        /** Teredo (2001:0000::/32) tunnels IPv4 and is a well-known rebinding and filter bypass. */
        private static boolean isTeredo(byte[] b) {
            return b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0;
        }

        /**
         * Resolves a hostname and re-validates every returned address.
         *
         * This is the rebinding gate. {@link #check} validates the name's shape; this validates the
         * address that would actually be connected to. Because the check is on the address rather
         * than on the name, a name whose answer changes between the check and the connection is
         * refused at the point of use.
         *
         * Every resolved address must pass. A host that resolves to one public and one loopback
         * address is refused, because which one a connection would pick is not knowable here.
         */
        public Decision resolveAndCheck(String host) {
            Decision shape = check(host);
            if (!shape.allowed) return shape;
            InetAddress[] addrs;
            try {
                addrs = InetAddress.getAllByName(host);
            } catch (IOException e) {
                return Decision.deny("dns_resolution_failed");
            }
            if (addrs == null || addrs.length == 0) return Decision.deny("dns_no_addresses");
            for (InetAddress a : addrs) {
                Decision d = checkLiteral(a.getHostAddress());
                if (!d.allowed) return d;
            }
            return Decision.allow();
        }
    }

    // ==================================================================
    // STIX export
    // ==================================================================

    /**
     * Builds a STIX 2.1 bundle from observed indicators.
     *
     * The builder only ever sees values that came out of the parser or out of a stored case. It has
     * no blocklist, no enrichment source and no default set, so it has nothing to fall back on when
     * a message is unremarkable: an empty message produces an empty bundle, which is the correct
     * output rather than a failure.
     */
    public static final class Stix {

        /** The STIX object types this builder can emit. Nothing else is representable. */
        static final Set<String> ALLOWED_TYPES = Set.of(
                "bundle", "email-message", "email-addr", "domain-name",
                "ipv4-addr", "ipv6-addr", "url", "file");

        private final List<Object> objects = new ArrayList<>();
        private final Set<String> seenIds = new LinkedHashSet<>();
        private final String timestamp = nowUtc();

        /** Stamps a STIX timestamp in UTC with millisecond precision, as the spec requires. */
        static String nowUtc() {
            return java.time.format.DateTimeFormatter
                    .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                    .withZone(java.time.ZoneOffset.UTC)
                    .format(java.time.Instant.now());
        }

        /**
         * Deterministic STIX identifier, derived with UUID version 5 over the fixed namespace.
         *
         * The same observed domain always produces the same identifier, so two exports of identical
         * evidence can be correlated by id. A random identifier would make that impossible.
         */
        static String stixId(String type, String value) {
            return type + "--" + uuidV5(STIX_NAMESPACE, type + ":" + value);
        }

        /** RFC 4122 version 5 (SHA-1, name-based) UUID over the fixed namespace. */
        static String uuidV5(UUID namespace, String name) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(toBytes(namespace));
                md.update(name.getBytes(StandardCharsets.UTF_8));
                byte[] h = md.digest();
                h[6] = (byte) ((h[6] & 0x0f) | 0x50);
                h[8] = (byte) ((h[8] & 0x3f) | 0x80);
                return formatUuid(h);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-1 unavailable", e);
            }
        }

        private static byte[] toBytes(UUID u) {
            ByteBuffer b = ByteBuffer.allocate(16);
            b.putLong(u.getMostSignificantBits());
            b.putLong(u.getLeastSignificantBits());
            return b.array();
        }

        private static String formatUuid(byte[] h) {
            StringBuilder sb = new StringBuilder(36);
            for (int i = 0; i < 16; i++) {
                if (i == 4 || i == 6 || i == 8 || i == 10) sb.append('-');
                sb.append(Character.forDigit((h[i] >> 4) & 0x0f, 16));
                sb.append(Character.forDigit(h[i] & 0x0f, 16));
            }
            return sb.toString();
        }

        /** Adds an object, de-duplicating on identifier. */
        private void add(Map<String, Object> o) {
            if (o == null || o.isEmpty()) return;
            String type = asString(o.get("type"));
            if (type == null || !ALLOWED_TYPES.contains(type)) {
                // A type this builder does not know is a programming error. Dropping it silently
                // would put an incomplete bundle in front of a consumer that trusts the bundle.
                throw new IllegalArgumentException("not a permitted STIX type: " + type);
            }
            if (objects.size() >= MAX_STIX_OBJECTS) return;
            String id = asString(o.get("id"));
            if (id == null || !seenIds.add(id)) return;
            objects.add(o);
        }

        /**
         * Common properties for a cyber-observable object.
         *
         * {@code created} and {@code modified} are deliberately absent. Those are properties of a
         * domain object; an SCO in STIX 2.1 has no such properties, and a consumer validating
         * against the specification rejects them as unrecognised. This builder emits only SCOs and
         * the enclosing bundle, so the two bases below are the whole need.
         */
        private Map<String, Object> sco(String type, String value) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("type", type);
            o.put("spec_version", "2.1");
            o.put("id", stixId(type, value));
            return o;
        }

        /**
         * The enclosing bundle, which is a domain object and does carry a {@code created} stamp.
         *
         * The identifier is derived from the sorted set of object ids it contains, so exporting
         * the same evidence twice yields the same bundle id. The timestamp is not part of the
         * basis: it records when the export ran, which is not a property of the evidence.
         */
        private Map<String, Object> bundle(String basis) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("type", "bundle");
            o.put("spec_version", "2.1");
            o.put("id", "bundle--" + uuidV5(STIX_NAMESPACE, "bundle:" + basis));
            o.put("created", timestamp);
            o.put("objects", objects);
            return o;
        }

        /**
         * Emits indicators for a parsed message.
         *
         * Each object is created only from a value the parser produced: a domain from a header
         * field, an address from a Received hop, a URL from the body, a file from an attachment
         * whose bytes were actually present. A field that is absent produces no object.
         */
        void fromMessage(byte[] raw) {
            EmailParser.Message m = EmailParser.parse(raw);
            if (m == null) return;

            Map<String, Object> msg = sco("email-message",
                    m.messageId != null && !m.messageId.isBlank()
                            ? m.messageId : sha256Hex(raw));
            Object date = normaliseDate(m.date);
            if (date != null) msg.put("date", date);
            if (m.subject != null && !m.subject.isBlank()) {
                msg.put("subject", truncate(m.subject, MAX_TEXT));
            }
            add(msg);

            for (String a : collectAddresses(m)) {
                addEmailAddr(a);
            }
            for (String d : collectDomains(m)) {
                addDomainName(d);
            }
            // Same helper the case record uses, so an inline export and a stored-case export of the
            // same message cannot disagree about which literals are in scope.
            for (String h : collectHopAddresses(m)) {
                if (h.indexOf(':') >= 0) {
                    addIpv6(h);
                } else {
                    addIpv4(h);
                }
            }
            for (String u : safeList(m.urls)) {
                addUrl(u);
            }
            for (EmailParser.Part p : safeList(m.parts)) {
                if (p == null || !p.isAttachment) continue;
                if (p.data == null || p.data.length == 0 || p.truncated) continue;
                addFile(p);
            }
        }

        /**
         * Emits indicators for a stored case.
         *
         * Only the observed fields of the record are used. The case's own judgement fields (risk,
         * verdict, attribution) are not exported as indicators, because an indicator is something
         * observed in a message, not something concluded about it.
         */
        void fromCase(Map<String, Object> record) {
            // Addresses and domains are separate observed facts and are exported as separate
            // objects. An email-addr whose value is a bare domain is not an email address, and
            // inventing a mailbox to stand in for a host would be fabricating evidence.
            for (String a : strings(record.get("addresses"))) {
                addEmailAddr(a);
            }
            for (String d : strings(record.get("domains"))) {
                addDomainName(d);
            }
            // The Received chain's literals. An export built from the case record rather than the
            // original message has no other source for these, so without this the hop infrastructure
            // would appear in the inline export and silently vanish from the stored-case export.
            for (String h : strings(record.get("hopAddresses"))) {
                if (h.indexOf(':') >= 0) {
                    addIpv6(h);
                } else {
                    addIpv4(h);
                }
            }
            for (String u : strings(record.get("urls"))) {
                addUrl(u);
            }
            for (String h : strings(record.get("attachmentHashes"))) {
                addFileHash(h);
            }
            // The message itself, so a consumer can see which message the indicators came from.
            String id = asString(record.get("id"));
            if (id != null) {
                Map<String, Object> msg = sco("email-message", id);
                Object date = epochToStix(record.get("observedAt"));
                if (date != null) msg.put("date", date);
                Object subject = record.get("subject");
                if (subject != null) msg.put("subject", truncate(String.valueOf(subject), MAX_TEXT));
                add(msg);
            }
        }

        private static List<String> strings(Object o) {
            List<String> out = new ArrayList<>();
            if (o instanceof List<?> l) {
                for (Object x : l) {
                    if (x != null) {
                        String s = String.valueOf(x).trim();
                        if (!s.isEmpty()) out.add(s);
                    }
                }
            } else if (o instanceof String s && !s.isBlank()) {
                out.add(s.trim());
            }
            return out;
        }

        private void addEmailAddr(String value) {
            Map<String, Object> o = sco("email-addr", value);
            o.put("value", value);
            add(o);
        }

        private void addDomainName(String value) {
            String d = value.toLowerCase(Locale.ROOT);
            // STIX requires a domain-name value to be a real name. A value that is not one is
            // dropped rather than emitted as an object a consumer would reject on load.
            if (d.length() > MAX_HOST_CHARS || d.indexOf('.') < 0) return;
            if (!HOSTNAME_RE.matcher(d).matches()) return;
            Map<String, Object> o = sco("domain-name", d);
            o.put("value", d);
            add(o);
        }

        private void addIpv4(String value) {
            Map<String, Object> o = sco("ipv4-addr", value);
            o.put("value", value);
            add(o);
        }

        private void addIpv6(String value) {
            Map<String, Object> o = sco("ipv6-addr", value);
            o.put("value", value);
            add(o);
        }

        private void addUrl(String value) {
            if (value == null || value.isBlank() || value.length() > 2048) return;
            Map<String, Object> o = sco("url", value);
            o.put("value", value);
            add(o);
        }

        /**
         * Emits a file object with a SHA-256 hash computed from the attachment bytes.
         *
         * A truncated part produces no object. A hash of a partial payload is a wrong hash, and a
         * wrong hash in a bundle is worse than an absent one: it will be looked up, fail to match,
         * and be read as evidence the attachment was seen.
         */
        private void addFile(EmailParser.Part p) {
            String hash = Correlate.contentHash(p);
            if (hash == null || hash.isBlank()) return;
            String name = p.filename == null || p.filename.isBlank() ? "attachment" : p.filename;
            Map<String, Object> o = sco("file", hash + ":" + name);
            o.put("name", truncate(name, 256));
            o.put("hashes", List.of(Map.of("algorithm", "SHA-256", "hash", hash)));
            if (p.contentType != null && !p.contentType.isBlank()) {
                o.put("x_mime_type", truncate(p.contentType, 256));
            }
            add(o);
        }

        /** Emits a file object for a hash already recorded in a case. */
        private void addFileHash(String hash) {
            if (hash.length() < 16 || hash.length() > 128) return;
            for (int i = 0; i < hash.length(); i++) {
                char c = hash.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return;
            }
            Map<String, Object> o = sco("file", hash);
            o.put("name", "attachment");
            o.put("hashes", List.of(Map.of("algorithm", "SHA-256", "hash", hash)));
            add(o);
        }

        /** Normalises a Date header into a STIX timestamp, or omits it when not confidently UTC. */
        private static Object normaliseDate(String d) {
            if (d == null || d.isBlank()) return null;
            try {
                java.time.ZonedDateTime z = java.time.ZonedDateTime.parse(d.trim(),
                        java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);
                return z.withZoneSameInstant(java.time.ZoneOffset.UTC)
                        .format(java.time.format.DateTimeFormatter
                                .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"));
            } catch (RuntimeException e) {
                // A date that cannot be placed in UTC is omitted rather than guessed, because a
                // wrong timestamp on an indicator is a false statement about when it was seen.
                return null;
            }
        }

        /** Converts an epoch-millis field into a STIX timestamp, or null when absent. */
        private static Object epochToStix(Object o) {
            if (!(o instanceof Number n)) return null;
            long v = n.longValue();
            if (v <= 0) return null;
            return java.time.format.DateTimeFormatter
                    .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                    .withZone(java.time.ZoneOffset.UTC)
                    .format(java.time.Instant.ofEpochMilli(v));
        }

        /**
         * Builds the bundle.
         *
         * The bundle always exists, even with no objects, because "this message had no indicators"
         * is a result, and an empty bundle is how a consumer learns it.
         */
        Map<String, Object> build() {
            // The ids are sorted so the basis does not depend on the order in which the objects
            // happened to be discovered.
            List<String> basisIds = new ArrayList<>(seenIds);
            java.util.Collections.sort(basisIds);
            return bundle(sha256Hex(String.join("\n", basisIds)
                    .getBytes(StandardCharsets.UTF_8)));
        }
    }

    /** Shared hostname shape rule, so STIX and the SSRF guard agree on what a name is. */
    private static final Pattern HOSTNAME_RE = Ssrf.HOSTNAME_RE;

    // ==================================================================
    // NDJSON writing
    // ==================================================================

    /**
     * Appends one complete line to an NDJSON file under an exclusive lock.
     *
     * The lock is what makes concurrent writers safe. The line and its terminating newline are
     * written in one pass and forced to the device, so a reader never observes a line without its
     * terminator and a crash cannot lose an acknowledged write.
     */
    private static final Object FILE_LOCK = new Object();

    static void appendLine(Path path, String json) throws IOException {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        if (!Files.exists(path)) Files.createFile(path);
        byte[] line = (json + "\n").getBytes(StandardCharsets.UTF_8);
        synchronized (FILE_LOCK) {
            try (FileChannel ch = FileChannel.open(path,
                    StandardOpenOption.WRITE, StandardOpenOption.CREATE)) {
                try (FileLock lock = ch.lock()) {
                    if (!lock.isValid()) {
                        throw new IOException("could not acquire an exclusive lock on " + path);
                    }
                    ch.position(ch.size());
                    ByteBuffer buf = ByteBuffer.wrap(line);
                    while (buf.hasRemaining()) {
                        ch.write(buf);
                    }
                    ch.force(false);
                }
            }
        }
    }

    // ==================================================================
    // Entry point
    // ==================================================================

    private static void usage() {
        System.err.println("usage:");
        System.err.println("  App [port]                      start the server (port 0-65535, loopback only)");
        System.err.println("  App --init-user <name> [--role <role>]");
        System.err.println("                                  provision a credential, then exit");
        System.err.println("  App --init-key                   generate the audit signing key, then exit");
        System.err.println("  App --help                      this message");
        System.err.println();
        System.err.println("The password is read from stdin, never from argv, because argv is visible to");
        System.err.println("every other process on the machine through the process list.");
    }

    /**
     * Generates the Ed25519 key the audit chain signs with, then exits.
     *
     * Explicit rather than automatic on purpose. The obvious convenience -- "create a key if there
     * is not one" at startup -- is the wrong default here for a reason the code already documents:
     * this process cannot restrict the key file's permissions on Windows, because the JDK's
     * PosixFilePermission API is unsupported on NTFS. A key quietly materialised on a disk whose
     * ACL nobody chose would then present as a configured, signed chain while the private key is
     * readable by more than the operator intended. An unconfigured chain reported honestly is the
     * safer state, so the key is provisioned deliberately and the operator is told to restrict it.
     *
     * @return process exit status
     */
    private static int initKey() {
        Path key = dataDir().resolve("keys").resolve("ed25519.pem");
        if (Files.isRegularFile(key)) {
            System.out.println("key already present at " + key.toAbsolutePath());
            return 0;
        }
        try {
            Audit.KeyManager km = Audit.KeyManager.createOrLoad(key);
            if (!km.configured()) {
                System.err.println("key was written but did not load back; refusing to report success");
                return 5;
            }
            System.out.println("created audit signing key at " + key.toAbsolutePath());
            System.out.println("key id: " + km.keyId());
            System.out.println("Entries appended from now on are signed. Existing entries are not,");
            System.out.println("because their hashes predate the key; the chain still verifies.");
            System.out.println();
            System.out.println("PROTECT THIS FILE. The application cannot restrict its permissions on");
            System.out.println("Windows. Restrict it with a filesystem ACL, or keep the key in an HSM.");
            return 0;
        } catch (RuntimeException e) {
            System.err.println("could not create the audit signing key: " + e.getMessage());
            return 5;
        }
    }

    /**
     * Creates one credential from a password typed on stdin, then exits.
     *
     * This is the missing first-run path. The store ships empty on purpose -- shipping a default
     * account would mean shipping a known password -- but an empty store with no way to fill it
     * leaves a server nobody can sign in to, which reads as a broken application rather than as a
     * security posture. Provisioning is therefore an explicit, deliberate operator action.
     *
     * The constraints are the point, not incidental:
     * <ul>
     *   <li>The password comes from stdin, never from argv, where it would be readable by any
     *       local process via the process list and would sit in the shell history.</li>
     *   <li>It is typed twice and must match, so a typo is caught before anything is written and
     *       the operator cannot lock themselves out on their own first sign-in.</li>
     *   <li>The array is zeroed afterwards and never becomes a String.</li>
     *   <li>An existing name is refused rather than appended, because the store is append-only and
     *       a second record would silently supersede the first.</li>
     * </ul>
     *
     * @return process exit status
     */
    private static int initUser(String[] args) throws Exception {
        String name = null;
        List<String> roles = new ArrayList<>(List.of("analyst"));
        // Starts at 0, not 1: args[0] is the "--init-user" subcommand itself and its own
        // "next argument" is the user name.
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("--init-user") && i + 1 < args.length) {
                name = args[++i];
            } else if (a.equals("--role") && i + 1 < args.length) {
                roles = new ArrayList<>();
                for (String r : args[++i].split(",")) {
                    if (!r.isBlank()) roles.add(r.trim());
                }
            } else {
                System.err.println("unknown option: " + a);
                usage();
                return 2;
            }
        }
        if (name == null || name.isBlank()) {
            System.err.println("--init-user requires a user name");
            usage();
            return 2;
        }

        // Constructed with port 0 because this path never serves anything. It exists to reach the
        // same hashing code the login path uses, so provisioning cannot drift from verification.
        App app = new App(0);
        if (app.auth().hasUser(name)) {
            System.err.println("user '" + name + "' already exists; refusing to add a second record");
            System.err.println("the store is append-only, so a second record would silently supersede it");
            return 3;
        }

        System.out.println("provisioning '" + name + "' with roles " + roles);
        System.out.print("password (12-256 chars, hidden): ");
        System.out.flush();
        char[] first = readHidden();
        System.out.print("confirm password: ");
        System.out.flush();
        char[] second = readHidden();
        System.out.println();

        boolean mismatch = first.length != second.length;
        if (!mismatch) {
            for (int i = 0; i < first.length; i++) {
                if (first[i] != second[i]) {
                    mismatch = true;
                    break;
                }
            }
        }
        Arrays.fill(second, '\0');
        if (mismatch) {
            Arrays.fill(first, '\0');
            System.err.println("passwords did not match; nothing was written");
            return 4;
        }
        if (first.length < 12) {
            Arrays.fill(first, '\0');
            System.err.println("password must be at least 12 characters; nothing was written");
            return 4;
        }

        try {
            app.auth().upsert(name, first, roles);
            System.out.println("created '" + name + "' in " + dataDir().toAbsolutePath());
            System.out.println("start the server to sign in:  java ... App");
            return 0;
        } finally {
            Arrays.fill(first, '\0');
        }
    }

    /**
     * Reads one line from stdin without echoing it.
     *
     * Tries {@code System.console().readPassword()} first so the terminal does not display it.
     * When there is no console -- piped input, a service manager, a container -- it falls back to
     * reading the line as-is. That fallback is exactly why the password must never be passed in
     * argv: on the piped path the operator is responsible for keeping it out of shell history and
     * out of the process list.
     */
    private static char[] readHidden() throws IOException {
        java.io.Console console = System.console();
        if (console != null) return console.readPassword();
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = System.in.read()) != -1 && c != '\n' && c != '\r') sb.append((char) c);
        return sb.toString().toCharArray();
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].startsWith("--")) {
            if (args[0].equals("--init-user")) System.exit(initUser(args));
            if (args[0].equals("--init-key")) System.exit(initKey());
            if (args[0].equals("--help") || args[0].equals("-h")) {
                usage();
                return;
            }
            System.err.println("unknown option: " + args[0]);
            usage();
            System.exit(2);
            return;
        }

        int port = Config.DEFAULT_PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0].trim());
            } catch (NumberFormatException e) {
                System.err.println("usage: App [port]   (port 0-65535, loopback only)");
                usage();
                System.exit(2);
                return;
            }
        }
        if (port < 0 || port > 65535) {
            System.err.println("port must be between 0 and 65535");
            System.exit(2);
            return;
        }

        App app = new App(port);

        // An empty store is the shipped state and the server is still worth starting -- the
        // console is public and still reports the model's status honestly. But nobody can sign in,
        // so say so on both streams instead of leaving the operator to work it out from a 401.
        if (app.auth().userCount() == 0) {
            String how = "CIPHER SQUAD has no accounts yet, so sign-in is impossible."
                    + "\n  Provision one:   java ... App --init-user <name>   (password read from stdin)"
                    + "\n  Data directory:  " + dataDir().toAbsolutePath();
            System.err.println(how);
            System.err.println();
            System.out.println(how);
            System.out.println();
        }

        Runtime.getRuntime().addShutdownHook(new Thread(app::stop, "cipher-squad-shutdown"));
        app.start();
        System.out.println("CIPHER SQUAD listening on http://"
                + app.boundAddress().getHostAddress() + ":" + app.port());
        Thread.currentThread().join();
    }
}
