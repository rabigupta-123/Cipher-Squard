/**
 * RFC 822 / MIME parsing under hard resource limits. Phase 1 item 1.
 *
 * Design rules, all of them load-bearing:
 *
 *   1. NEVER THROW on hostile input. Every limit is reached by truncating and appending a
 *      parse_warning. An analyst submitting a 5 MB bomb gets a report with warnings, not a
 *      stack trace - and a thrown exception is exactly what a sender would want, because it
 *      turns the analyser into a denial-of-service amplifier.
 *
 *   2. LINEAR SCANS ONLY. No nested-quantifier regex anywhere in this file. The classic
 *      backtracking blowup is /(a+)+$/ against "aaaaaaaaaaaaaaaaaaaaaaaaX", which is O(2^n)
 *      and will hang the process on attacker-controlled bytes. Header unfolding, boundary
 *      scanning and line splitting are all hand-written index walks that advance a cursor
 *      monotonically, so total work is bounded by input length, not exponential in it.
 *
 *   3. NO EMAIL.ADDRESS / MIME PARSER from the JDK. javax.mail is not in the JDK, and
 *      java.net.URI/URL do not give a defensible extraction of an address or a URL from
 *      untrusted text. The extraction rules here are ours and are testable.
 *
 * Spec anchors: ARCHITECTURE.md L300 (Headers.java - "RFC 822 header parser, chain
 * ordering, alignment checks"), L44 (normalise stage), L92 (header chain indices, body text,
 * attachment inventory).
 */
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class Headers {

    // ==================================================================
    // Result types
    // ==================================================================

    public static final class Warning {
        public final String code;
        public final String detail;

        Warning(String code, String detail) {
            this.code = code;
            this.detail = detail;
        }

        @Override
        public String toString() {
            return code + (detail == null || detail.isEmpty() ? "" : ": " + detail);
        }
    }

    public static final class Part {
        public String contentType = "text/plain";
        public String filename;
        public String disposition;
        public byte[] data = new byte[0];
        public boolean truncated;
        /** Decoded size as it would be, even when data was cut short. */
        public long declaredDecodedBytes;
    }

    public static final class Result {
        /** Lower-cased header name -> unfolded values, in first-seen order. */
        public final Map<String, List<String>> headers = new LinkedHashMap<>();
        /** Header order as received, for chain-of-custody display. */
        public final List<String[]> headerOrder = new ArrayList<>();
        public final List<Part> parts = new ArrayList<>();
        public final List<Warning> warnings = new ArrayList<>();
        public final List<String> urls = new ArrayList<>();
        public String bodyText = "";
        public String raw = "";
        public boolean truncated;
        public long bytesConsumed;

        public String first(String name) {
            List<String> v = headers.get(name.toLowerCase(Locale.ROOT));
            return (v == null || v.isEmpty()) ? null : v.get(0);
        }

        public List<String> all(String name) {
            List<String> v = headers.get(name.toLowerCase(Locale.ROOT));
            return v == null ? List.of() : v;
        }

        public boolean has(String name) {
            return headers.containsKey(name.toLowerCase(Locale.ROOT));
        }

        public List<String> warningCodes() {
            List<String> out = new ArrayList<>(warnings.size());
            for (Warning w : warnings) {
                out.add(w.code);
            }
            return out;
        }

        public void warn(String code, String detail) {
            warnings.add(new Warning(code, detail));
        }
    }

    /** Tracks the wall-clock budget. Checked at loop boundaries, never per character. */
    private static final class Budget {
        private final long deadlineNanos;
        private boolean expired;
        private int checks;

        Budget(long millis) {
            this.deadlineNanos = System.nanoTime() + millis * 1_000_000L;
        }

        /**
         * Returns true while budget remains. Called every 4096 units of work, so the cost of
         * the clock read is amortised and cannot itself become the bottleneck.
         */
        boolean ok() {
            if (expired) {
                return false;
            }
            if ((++checks & 0xFFF) == 0) {
                if (System.nanoTime() - deadlineNanos > 0) {
                    expired = true;
                    return false;
                }
            }
            return true;
        }

        boolean expired() {
            return expired;
        }
    }

    // ==================================================================
    // Entry point
    // ==================================================================

    /**
     * Full pipeline: header block, MIME walk, URL extraction - all under ONE shared time
     * budget, because the spec's 2 s is a bound on the whole parse, not per stage. Three
     * separate budgets would make the real worst case 6 s.
     */
    public static Result parseComplete(byte[] rawBytes) {
        Budget budget = new Budget(Config.PARSE_TIME_BUDGET_MS);
        Result r = new Result();

        byte[] bytes = rawBytes == null ? new byte[0] : rawBytes;
        if (bytes.length > Config.MAX_MESSAGE_BYTES) {
            bytes = java.util.Arrays.copyOf(bytes, (int) Config.MAX_MESSAGE_BYTES);
            r.truncated = true;
            r.warn("MESSAGE_TRUNCATED",
                    "message exceeds " + Config.MAX_MESSAGE_BYTES + " bytes; truncated");
        }
        r.bytesConsumed = bytes.length;
        r.raw = new String(bytes, StandardCharsets.ISO_8859_1);

        int headerEnd = findHeaderEnd(r.raw);
        String headerBlock = headerEnd < 0 ? r.raw : r.raw.substring(0, headerEnd);
        // The blank line separating headers from body is 4 bytes under CRLF but only 2
        // under bare LF. Advancing by a hardcoded 4 silently ate the first two characters
        // of every LF-only body ("body" -> "dy"), so measure the two line breaks instead.
        int bodyStart = headerEnd < 0 ? 0 : skipLineBreak(r.raw, skipLineBreak(r.raw, headerEnd));
        String body = headerEnd < 0 ? ""
                : r.raw.substring(Math.min(r.raw.length(), bodyStart));

        parseHeaders(headerBlock, r, budget);

        walkMime(body, r.first("content-type"), r, 0, 0L, budget);
        if (r.bodyText.isEmpty()) {
            for (Part p : r.parts) {
                if (p.contentType.toLowerCase(Locale.ROOT).startsWith("text/")) {
                    r.bodyText = new String(p.data, StandardCharsets.UTF_8);
                    break;
                }
            }
        }
        if (r.bodyText.isEmpty() && !body.isEmpty() && r.first("content-type") == null) {
            r.bodyText = body;
        }
        extractUrls(r.bodyText, r, budget);

        if (budget.expired()) {
            r.truncated = true;
            r.warn("TIME_BUDGET_EXCEEDED",
                    "parse gave up after the " + Config.PARSE_TIME_BUDGET_MS + " ms budget");
        }
        if (r.truncated) {
            r.warn("PARSE_TRUNCATED", "result is a truncated view of the original message");
        }
        return r;
    }

    public static Result parseComplete(String raw) {
        return parseComplete(raw == null ? new byte[0]
                : raw.getBytes(StandardCharsets.ISO_8859_1));
    }

    /**
     * Header block only. Provided for the "is it even well-formed" question; the engine uses
     * parseComplete.
     */
    public static Result parse(byte[] rawBytes) {
        Result r = new Result();
        Budget budget = new Budget(Config.PARSE_TIME_BUDGET_MS);

        byte[] bytes = rawBytes == null ? new byte[0] : rawBytes;
        if (bytes.length > Config.MAX_MESSAGE_BYTES) {
            bytes = java.util.Arrays.copyOf(bytes, (int) Config.MAX_MESSAGE_BYTES);
            r.truncated = true;
            r.warn("MESSAGE_TRUNCATED",
                    "message exceeds " + Config.MAX_MESSAGE_BYTES + " bytes; truncated");
        }
        r.bytesConsumed = bytes.length;

        // ISO-8859-1: every byte maps to exactly one char, so indices line up with the
        // original bytes. No multi-byte decoding can desynchronise our cursor.
        String raw = new String(bytes, StandardCharsets.ISO_8859_1);
        r.raw = raw;

        int headerEnd = findHeaderEnd(raw);
        String headerBlock = headerEnd < 0 ? raw : raw.substring(0, headerEnd);
        String bodyStart = headerEnd < 0 ? "" : raw.substring(Math.min(raw.length(), headerEnd + 4));

        parseHeaders(headerBlock, r, budget);
        if (!budget.ok()) {
            r.truncated = true;
            r.warn("TIME_BUDGET_EXCEEDED", "gave up after " + Config.PARSE_TIME_BUDGET_MS + "ms");
        }
        if (r.truncated) {
            r.warn("PARSE_TRUNCATED", "result is a truncated view of the original message");
        }
        return r;
    }

    public static Result parse(String raw) {
        return parse(raw == null ? new byte[0]
                : raw.getBytes(StandardCharsets.ISO_8859_1));
    }

    // ==================================================================
    // Header block
    // ==================================================================

    /**
     * Locates the blank line separating headers from body. Returns -1 when the message has
     * no body. Single forward scan; no regex.
     */
    private static int findHeaderEnd(String raw) {
        for (int i = 0; i + 1 < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\n') {
                char next = (i + 1 < raw.length()) ? raw.charAt(i + 1) : '\0';
                if (next == '\n') {
                    return i;
                }
                if (next == '\r' && i + 2 < raw.length() && raw.charAt(i + 2) == '\n') {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * Splits the header block on line breaks, unfolds continuation lines (RFC 5322 2.2.3),
     * and enforces the header-count and header-length caps.
     *
     * Folding: a line beginning with space or tab continues the previous header. A fold
     * contributes ONE space, which is what the RFC specifies and what stops an attacker from
     * inflating a header's effective length by continuation lines.
     */
    private static void parseHeaders(String block, Result r, Budget budget) {
        int n = block.length();
        int i = 0;
        String pendingName = null;
        StringBuilder pendingValue = null;
        int accepted = 0;
        boolean overCount = false;

        while (i < n) {
            if (!budget.ok()) {
                return;
            }
            int lineEnd = indexOfLineEnd(block, i);
            String line = block.substring(i, lineEnd);
            int nextLine = skipLineBreak(block, lineEnd);

            boolean truncatedLine = false;
            if (line.length() > Config.MAX_HEADER_LINE_BYTES) {
                line = line.substring(0, Config.MAX_HEADER_LINE_BYTES);
                truncatedLine = true;
                r.truncated = true;
                r.warn("HEADER_LINE_TRUNCATED",
                        "header line exceeded " + Config.MAX_HEADER_LINE_BYTES + " bytes");
            }

            if (!line.isEmpty() && (line.charAt(0) == ' ' || line.charAt(0) == '\t')) {
                if (pendingValue != null) {
                    pendingValue.append(' ').append(line.trim());
                }
                // A continuation with nothing to continue is dropped, not guessed at.
            } else {
                if (pendingName != null) {
                    if (accepted < Config.MAX_HEADERS) {
                        accepted++;
                        addHeader(r, pendingName, pendingValue.toString(), truncatedLine);
                    } else if (!overCount) {
                        overCount = true;
                        r.truncated = true;
                        r.warn("HEADER_COUNT_EXCEEDED",
                                "more than " + Config.MAX_HEADERS + " headers; remainder ignored");
                    }
                }
                int colon = line.indexOf(':');
                if (colon > 0) {
                    pendingName = line.substring(0, colon).trim();
                    pendingValue = new StringBuilder(line.substring(colon + 1).trim());
                } else {
                    pendingName = null;
                    pendingValue = null;
                }
            }
            i = nextLine;
        }
        if (pendingName != null && accepted < Config.MAX_HEADERS) {
            addHeader(r, pendingName, pendingValue.toString(), false);
        }
    }

    private static void addHeader(Result r, String name, String value, boolean wasTruncated) {
        String key = name.toLowerCase(Locale.ROOT);
        if (key.isEmpty()) {
            return;
        }
        // Received-chain cap (item 1: more than 25 Received headers). The trace is kept in
        // document order, so the cap keeps the OLDEST hops, which is the part of the chain
        // closest to the sender. Discarding the tail would keep the hops furthest from the
        // origin, which are the ones an attacker controls least and matter least. The count
        // that survives is still what received_count_n measures, so the cap is reported rather
        // than hidden.
        if ("received".equals(key)) {
            // Count from the map, but null-safely: the key is absent until the first
            // Received header is stored, so a bare get() returns null here.
            List<String> hops = r.headers.get("received");
            int seen = (hops == null) ? 0 : hops.size();
            if (seen >= Config.MAX_RECEIVED_HEADERS) {
                r.truncated = true;
                r.warn("RECEIVED_COUNT_EXCEEDED", "more than " + Config.MAX_RECEIVED_HEADERS
                        + " Received headers; extra hops ignored");
                return;
            }
        }
        r.headers.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        r.headerOrder.add(new String[]{name, value});
    }

    private static int indexOfLineEnd(String s, int from) {
        for (int i = from; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r') {
                return i;
            }
        }
        return s.length();
    }

    private static int skipLineBreak(String s, int at) {
        if (at >= s.length()) {
            return s.length();
        }
        char c = s.charAt(at);
        if (c == '\r') {
            return (at + 1 < s.length() && s.charAt(at + 1) == '\n') ? at + 2 : at + 1;
        }
        if (c == '\n') {
            return at + 1;
        }
        return at;
    }

    // ==================================================================
    // MIME walk
    // ==================================================================

    /**
     * Walks a multipart body, bounded on all four axes at once: nesting depth, part count,
     * decoded bytes, and the shared time budget.
     *
     * Boundary matching is a forward scan comparing the candidate boundary against the
     * delimiter at each position. It is O(body x boundary) worst case, which is linear in
     * body length for the fixed-length delimiters RFC 2046 requires (1-70 chars, and capped
     * here). There is no backtracking, so a message with 100 nested multiparts costs 100
     * shallow scans rather than an exponential blowup.
     */
    public static void walkMime(String body, String contentType, Result r,
                                int depth, long decodedSoFar, Budget budget) {
        if (depth > Config.MAX_MIME_DEPTH) {
            r.truncated = true;
            r.warn("MIME_DEPTH_EXCEEDED",
                    "nesting deeper than " + Config.MAX_MIME_DEPTH + "; deeper content not read");
            return;
        }
        if (r.parts.size() >= Config.MAX_MIME_PARTS) {
            r.truncated = true;
            r.warn("MIME_PART_LIMIT_EXCEEDED",
                    "more than " + Config.MAX_MIME_PARTS + " parts; remainder not read");
            return;
        }
        if (body == null || body.isEmpty()) {
            return;
        }

        String boundary = boundaryOf(contentType);
        if (depth >= Config.MAX_MIME_DEPTH && boundary != null) {
            // At the cap with a real boundary still declared, the message nests deeper
            // than we are willing to read. This branch used to return silently, so a
            // hostile message could hide content past the limit with no parse_warning at
            // all. Report it, the same way the part-count cap reports.
            r.truncated = true;
            r.warn("MIME_DEPTH_EXCEEDED", "nesting deeper than "
                    + Config.MAX_MIME_DEPTH + "; deeper content not read");
        }
        if (boundary == null || depth >= Config.MAX_MIME_DEPTH) {
            if (r.parts.isEmpty() || depth == 0) {
                r.parts.add(textPart(contentType, body.getBytes(StandardCharsets.ISO_8859_1)));
            }
            if (depth == 0) {
                r.bodyText = body;
            }
            return;
        }

        byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        int pos = 0;
        while (pos < body.length()) {
            if (!budget.ok()) {
                r.warn("TIME_BUDGET_EXCEEDED", "MIME walk stopped on the parse time budget");
                return;
            }
            int at = indexOfBytes(body, delimiter, pos);
            if (at < 0) {
                break;
            }
            int afterDelimiter = at + delimiter.length;
            // Closing delimiter is "--boundary--".
            if (body.startsWith("--", afterDelimiter)) {
                return;
            }
            // Locate the part's blank line first, and bail before using its index. A part
            // with no blank line (truncated or hostile MIME) makes indexOfBlankLine return
            // -1, and feeding that into indexOfLineEnd threw StringIndexOutOfBounds.
            int contentStart = indexOfBlankLine(body, afterDelimiter);
            if (contentStart < 0) {
                r.truncated = true;
                r.warn("PARSE_TRUNCATED", "MIME part has no blank line; part skipped");
                return;
            }
            int partHeaderEnd = indexOfLineEnd(body, contentStart);
            int next = indexOfBytes(body, delimiter, contentStart);
            int contentEnd = (next < 0) ? body.length() : next;
            if (next >= 0) {
                // Trim the CRLF that belongs to the delimiter, not to the content.
                contentEnd = trimTrailingBreak(body, contentStart, contentEnd);
            }
            if (contentEnd > contentStart) {
                String chunk = body.substring(contentStart, contentEnd);
                String partHeaders = partHeaderEnd > contentStart
                        ? body.substring(afterDelimiter, partHeaderEnd) : "";
                Result sub = new Result();
                parseHeaders(partHeaders, sub, budget);
                String ct = sub.first("content-type");
                String enc = sub.first("content-transfer-encoding");
                String disp = sub.first("content-disposition");

                long budgetLeft = Config.MAX_DECODED_BYTES - decodedSoFar;
                if (budgetLeft <= 0) {
                    r.truncated = true;
                    r.warn("DECODE_BUDGET_EXCEEDED",
                            "decoded attachment budget of " + Config.MAX_DECODED_BYTES
                                    + " bytes exhausted; later parts not decoded");
                    return;
                }
                byte[] decoded = decodeChunk(r, chunk, enc,
                        Math.min(budgetLeft, Config.MAX_DECODED_BYTES));
                long consumed = decoded.length;

                boolean isAttachment = disp != null
                        && disp.toLowerCase(Locale.ROOT).startsWith("attachment");
                if (isAttachment || (ct != null && !ct.toLowerCase(Locale.ROOT).startsWith("text/"))) {
                    Part p = new Part();
                    p.contentType = ct == null ? "application/octet-stream" : ct;
                    p.disposition = disp;
                    p.filename = filenameOf(disp, ct);
                    p.data = decoded;
                    p.declaredDecodedBytes = decoded.length;
                    p.truncated = consumed >= budgetLeft;
                    if (r.parts.size() < Config.MAX_MIME_PARTS) {
                        r.parts.add(p);
                    } else {
                        r.truncated = true;
                        r.warn("MIME_PART_LIMIT_EXCEEDED", "part dropped at the part cap");
                    }
                } else if (ct == null || ct.toLowerCase(Locale.ROOT).startsWith("text/")) {
                    Part p = textPart(ct, decoded);
                    p.truncated = consumed >= budgetLeft;
                    if (r.parts.size() < Config.MAX_MIME_PARTS) {
                        r.parts.add(p);
                    }
                    if (depth == 0) {
                        r.bodyText = new String(decoded, charsetOf(sub.first("content-type")));
                    }
                }
                if (ct != null && ct.toLowerCase(Locale.ROOT).startsWith("multipart/")
                        && r.parts.size() < Config.MAX_MIME_PARTS) {
                    walkMime(chunk, ct, r, depth + 1, decodedSoFar + consumed, budget);
                }
                decodedSoFar += consumed;
                if (decodedSoFar >= Config.MAX_DECODED_BYTES) {
                    r.truncated = true;
                    r.warn("DECODE_BUDGET_EXCEEDED",
                            "decoded attachment budget of " + Config.MAX_DECODED_BYTES
                                    + " bytes exhausted");
                    return;
                }
            }
            pos = (next < 0) ? body.length() : next;
            if (next < 0) {
                break;
            }
        }
    }

    private static Part textPart(String contentType, byte[] data) {
        Part p = new Part();
        p.contentType = contentType == null ? "text/plain" : contentType;
        p.data = data;
        p.declaredDecodedBytes = data.length;
        return p;
    }

    /**
     * Decodes one chunk, bounded by maxBytes.
     *
     * Base64 is decoded through a counting stream, not by base64-decoding the whole string
     * and measuring afterwards. A 40 MB base64 attachment would otherwise allocate 30 MB
     * before the cap could reject it, which is the whole point of the 10 MB decoded cap.
     */
    private static byte[] decodeChunk(Result r, String chunk, String encoding, long maxBytes) {
        String enc = encoding == null ? "" : encoding.trim().toLowerCase(Locale.ROOT);
        if (!enc.startsWith("base64")) {
            byte[] b = chunk.getBytes(StandardCharsets.ISO_8859_1);
            if (b.length > maxBytes) {
                return java.util.Arrays.copyOf(b, (int) Math.max(0, maxBytes));
            }
            return b;
        }
        // Base64 line cap (item 1: more than 2000 base64 lines). A megabyte-scale single
        // "line" is the classic way to make a naive line-oriented decoder allocate without
        // bound, so the line count is bounded before any character is copied. The budget
        // below would eventually stop it too, but only after the string was already built.
        int lineCount = 0;
        for (int i = 0; i < chunk.length(); i++) {
            char c = chunk.charAt(i);
            if (c == '\n') {
                lineCount++;
                if (lineCount > Config.MAX_BASE64_LINES) {
                    r.truncated = true;
                    r.warn("BASE64_LINE_LIMIT_EXCEEDED", "more than "
                            + Config.MAX_BASE64_LINES + " base64 lines; remainder not decoded");
                    chunk = chunk.substring(0, i);
                    break;
                }
            }
        }
        // Strip whitespace with a single forward pass, collecting at most what the budget allows.
        StringBuilder sb = new StringBuilder(Math.min(chunk.length(), 4 * 1024 * 1024));
        for (int i = 0; i < chunk.length(); i++) {
            char c = chunk.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                continue;
            }
            if (sb.length() / 4 * 3 >= maxBytes) {
                break;
            }
            sb.append(c);
        }
        try {
            byte[] out = Base64.getDecoder().decode(sb.toString());
            return out.length > maxBytes ? java.util.Arrays.copyOf(out, (int) maxBytes) : out;
        } catch (IllegalArgumentException e) {
            // Malformed base64 is a parse_warning, never an exception. Attackers send broken
            // base64 routinely to slip past content filters.
            return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    /**
     * Forward byte search. Uses indexOf on the ISO-8859-1 string, which is a single
     * contiguous scan with no backtracking.
     */
    private static int indexOfBytes(String haystack, byte[] needle, int from) {
        String n = new String(needle, StandardCharsets.ISO_8859_1);
        int at = haystack.indexOf(n, Math.max(0, from));
        return at;
    }

    /** Finds the blank line after from; -1 if none. */
    private static int indexOfBlankLine(String s, int from) {
        for (int i = Math.max(0, from); i + 1 < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                char nx = s.charAt(i + 1);
                if (nx == '\n') {
                    return i + 2;
                }
                if (nx == '\r' && i + 2 < s.length() && s.charAt(i + 2) == '\n') {
                    return i + 3;
                }
            }
        }
        return -1;
    }

    private static int trimTrailingBreak(String s, int from, int to) {
        int end = to;
        if (end > from && end <= s.length()) {
            if (end - 1 >= 0 && s.charAt(end - 1) == '\n') {
                end--;
                if (end > from && end - 1 >= 0 && s.charAt(end - 1) == '\r') {
                    end--;
                }
            }
        }
        return Math.max(from, end);
    }

    // ==================================================================
    // Parameter and address extraction - hand-written, no regex
    // ==================================================================

    /**
     * Pulls the boundary parameter out of a Content-Type. Hand-written because the obvious
     * regex (boundary="?([^";]+)"?) is a nested quantifier over attacker-controlled bytes.
     */
    public static String boundaryOf(String contentType) {
        if (contentType == null) {
            return null;
        }
        String lower = contentType.toLowerCase(Locale.ROOT);
        int at = lower.indexOf("boundary");
        if (at < 0) {
            return null;
        }
        int i = at + "boundary".length();
        while (i < contentType.length() && contentType.charAt(i) == ' ') {
            i++;
        }
        if (i < contentType.length() && contentType.charAt(i) == '=') {
            i++;
        }
        while (i < contentType.length() && contentType.charAt(i) == ' ') {
            i++;
        }
        if (i < contentType.length() && contentType.charAt(i) == '"') {
            i++;
            int end = contentType.indexOf('"', i);
            if (end < 0) {
                return null;
            }
            return contentType.substring(i, end);
        }
        int end = i;
        while (end < contentType.length()) {
            char c = contentType.charAt(end);
            if (c == ';' || c == ' ' || c == '\r' || c == '\n') {
                break;
            }
            end++;
        }
        return end > i ? contentType.substring(i, end) : null;
    }

    /** Extracts the filename parameter from a Content-Disposition or Content-Type. */
    public static String filenameOf(String disposition, String contentType) {
        String from = paramOf(disposition, "filename");
        if (from != null) {
            return from;
        }
        return paramOf(contentType, "name");
    }

    private static String paramOf(String headerValue, String param) {
        if (headerValue == null) {
            return null;
        }
        String lower = headerValue.toLowerCase(Locale.ROOT);
        int at = 0;
        while (true) {
            int found = lower.indexOf(param, at);
            if (found < 0) {
                return null;
            }
            int i = found + param.length();
            while (i < headerValue.length() && headerValue.charAt(i) == ' ') {
                i++;
            }
            if (i < headerValue.length() && headerValue.charAt(i) == '=') {
                i++;
                while (i < headerValue.length() && headerValue.charAt(i) == ' ') {
                    i++;
                }
                if (i < headerValue.length() && headerValue.charAt(i) == '"') {
                    i++;
                    int end = headerValue.indexOf('"', i);
                    return end < 0 ? headerValue.substring(i) : headerValue.substring(i, end);
                }
                int end = i;
                while (end < headerValue.length()) {
                    char c = headerValue.charAt(end);
                    if (c == ';' || c == ' ' || c == '\r' || c == '\n') {
                        break;
                    }
                    end++;
                }
                return end > i ? headerValue.substring(i, end) : null;
            }
            at = found + 1;
        }
    }

    /** Address portion of a header value, or the value itself if it has no angle brackets. */
    public static String addressOf(String headerValue) {
        if (headerValue == null) {
            return null;
        }
        int lt = headerValue.indexOf('<');
        if (lt < 0) {
            return headerValue.trim();
        }
        int gt = headerValue.indexOf('>', lt + 1);
        if (gt < 0) {
            return headerValue.substring(lt + 1).trim();
        }
        return headerValue.substring(lt + 1, gt).trim();
    }

    /** Display name of an address header, or null. */
    public static String displayNameOf(String headerValue) {
        if (headerValue == null) {
            return null;
        }
        int lt = headerValue.indexOf('<');
        if (lt <= 0) {
            return null;
        }
        return headerValue.substring(0, lt).trim();
    }

    /** Domain part of an address, lower-cased. Null when there is no '@'. */
    public static String domainOf(String address) {
        if (address == null) {
            return null;
        }
        int at = address.lastIndexOf('@');
        if (at < 0 || at == address.length() - 1) {
            return null;
        }
        String d = address.substring(at + 1).trim();
        while (d.startsWith(".") || d.startsWith("-")) {
            d = d.substring(1);
        }
        return d.isEmpty() ? null : d.toLowerCase(Locale.ROOT);
    }

    /**
     * Extracts URLs by hand, bounded by Config.MAX_URLS.
     *
     * Not a regex: a URL-matching regex over attacker text is a backtracking risk, and the
     * cap has to apply to work done, not to matches found after the fact.
     */
    public static void extractUrls(String text, Result r, Budget budget) {
        if (text == null) {
            return;
        }
        int n = text.length();
        int i = 0;
        while (i < n) {
            if (!budget.ok()) {
                return;
            }
            char c = text.charAt(i);
            if (c == 'h' || c == 'H') {
                int end = urlEnd(text, i);
                if (end > i + 8) {
                    if (r.urls.size() >= Config.MAX_URLS) {
                        r.truncated = true;
                        r.warn("URL_LIMIT_EXCEEDED",
                                "more than " + Config.MAX_URLS + " urls; remainder not parsed");
                        return;
                    }
                    r.urls.add(text.substring(i, end));
                }
                i = Math.max(end, i + 1);
            } else {
                i++;
            }
        }
    }

    /** End of the http(s) token starting at i, or i if it is not one. */
    private static int urlEnd(String s, int i) {
        if (s.regionMatches(true, i, "http://", 0, 7)) {
            return tokenEnd(s, i + 7);
        }
        if (s.regionMatches(true, i, "https://", 0, 8)) {
            return tokenEnd(s, i + 8);
        }
        return i;
    }

    private static int tokenEnd(String s, int from) {
        int i = from;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\''
                    || c == '<' || c == '>' || c == ')' || c == '|') {
                break;
            }
            i++;
        }
        // Trim trailing punctuation that is almost always sentence punctuation, not URL.
        while (i > from) {
            char c = s.charAt(i - 1);
            if (c == '.' || c == ',' || c == ';' || c == ':' || c == '!') {
                i--;
            } else {
                break;
            }
        }
        return i;
    }

    /** Charset from a Content-Type, defaulting per RFC 2045 to us-ascii. */
    public static Charset charsetOf(String contentType) {
        String cs = paramOf(contentType, "charset");
        if (cs == null) {
            return StandardCharsets.US_ASCII;
        }
        try {
            return Charset.forName(cs.trim());
        } catch (RuntimeException e) {
            // An attacker-declared bogus charset must not fail the parse. RFC 2045 says treat
            // unknown charsets as us-ascii, so we do exactly that.
            return StandardCharsets.US_ASCII;
        }
    }

    /** Standalone self-check: java Headers [file] */
    public static void main(String[] args) throws Exception {
        String sample = "From: a@b.com\r\n"
                + "Subject: hi\r\n"
                + " folded\r\n"
                + "\r\n"
                + "body http://example.com/x\r\n";
        Result r = parse(sample);
        System.out.println("subject=" + r.first("subject"));
        System.out.println("urls=" + r.urls);
        System.out.println("warnings=" + r.warningCodes());
    }
}
