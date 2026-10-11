/**
 * Security-oriented bounded RFC 822 / MIME parser. Phase 2 deliverable.
 *
 * This is deliberately a SEPARATE parser from the Phase 1 {@code Headers} class rather than a
 * wrapper around it. Phase 1 freezes its limits in {@code Config} (5 MB / 100 headers) because
 * that is what the Phase 1 task text specified. Phase 2 specifies a different set (2 MB / 500
 * headers) for this deliverable. Rather than mutate working Phase 1 configuration - which would
 * silently weaken every other Phase 1 caller - Phase 2 carries its own immutable {@link Limits}
 * with the Phase 2 numbers as the default. The divergence is deliberate and is recorded in
 * docs/PHASE2-NOTES.md. The four shared limits that agree (8 KB header line, depth 8, 200 parts,
 * 10 MB decoded, 2 s budget) carry the same values as Config, but are owned here so the parser
 * cannot drift out from under its own tests.
 *
 * Threat model. The input is a hostile artifact: whoever built the message chose every byte.
 * Therefore:
 *
 *   1. NEVER THROW. Every limit is enforced by truncation plus a recorded warning, and every
 *      parse routine is written so that malformed input yields a partial report. A thrown
 *      exception here would be a free denial-of-service lever against the analyst, which is the
 *      one thing an email parser must never be.
 *
 *   2. NO CATASTROPHIC BACKTRACKING. There is not a single nested-quantifier regex in this file.
 *      Address lists, IP literals, dates, boundaries, quoted-printable and base64 are all decoded
 *      by monotonic cursor walks. The only compiled patterns are a fixed alternation of literal
 *      keys and a date-time formatter, neither of which backtracks. The classic trap,
 *      /(a+)+$/ against "aaaa...X", is O(2^n) and would hang on attacker bytes; the walks here
 *      are O(n) in input length with no recursion over token boundaries.
 *
 *   3. NO RECURSION WITHOUT A HARD DEPTH CEILING. The MIME walk recurses, but only up to
 *      {@link Limits#maxMimeDepth} and only on a container that actually declares a boundary.
 *      A message cannot make this recurse further, so the stack is bounded by a constant
 *      chosen by us, not by the attacker.
 *
 *   4. NO AMPLIFICATION. Decoding is where a small message becomes a large allocation, so every
 *      decoder is handed a pre-computed output cap derived from the remaining decode budget and
 *      then truncates the result. Base64 gets 4 input chars -> 3 output bytes accounted for
 *      before the decode call, so the decoder never sees more input than the budget allows.
 *
 *   5. NO EXECUTION. Nothing in this file renders HTML, evaluates script, launches a process, or
 *      opens a socket. Attachments are decoded as inert bytes and named, never interpreted.
 *      HTML is kept as text for the analyst and is never turned into a DOM.
 *
 * Uncertain input stays uncertain. {@link ReceivedHop} records the individual clause values it
 * could parse and the ones it could not; it does not guess a hostname from an IP, and it does
 * not assume the topmost hop belongs to the originator. Choosing among the observed candidates
 * is {@link Attribution}'s job, and it must justify that choice.
 */
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class EmailParser {

    // ==================================================================
    // Limits
    // ==================================================================

    /**
     * Immutable bound set. Construction clamps every field to a positive value so a
     * misconfigured limit cannot itself become the vulnerability (e.g. a negative decode cap
     * would make the output cap arithmetic wrap and permit an unbounded decode).
     */
    public static final class Limits {
        public final long maxMessageBytes;
        public final int maxHeaders;
        public final int maxHeaderLineBytes;
        public final int maxMimeDepth;
        public final int maxMimeParts;
        public final long maxDecodedBytes;
        public final long parseBudgetMillis;

        public Limits(long maxMessageBytes, int maxHeaders, int maxHeaderLineBytes,
                      int maxMimeDepth, int maxMimeParts, long maxDecodedBytes,
                      long parseBudgetMillis) {
            this.maxMessageBytes = clampLong(maxMessageBytes, 1L);
            this.maxHeaders = clampInt(maxHeaders, 1);
            this.maxHeaderLineBytes = clampInt(maxHeaderLineBytes, 64);
            this.maxMimeDepth = clampInt(maxMimeDepth, 1);
            this.maxMimeParts = clampInt(maxMimeParts, 1);
            this.maxDecodedBytes = clampLong(maxDecodedBytes, 1L);
            this.parseBudgetMillis = parseBudgetMillis < 0 ? 0 : parseBudgetMillis;
        }

        /** The Phase 2 task values. These are the defaults for every {@code parse} call. */
        public static Limits phase2() {
            return new Limits(
                    2L * 1024 * 1024,      // 2 MB raw message
                    500,                   // 500 headers
                    8 * 1024,              // 8 KB header line
                    8,                     // MIME nesting depth
                    200,                   // MIME parts
                    10L * 1024 * 1024,     // 10 MB decoded content
                    2000);                 // 2 s parsing budget
        }

        private static int clampInt(int v, int floor) {
            return v < floor ? floor : v;
        }

        private static long clampLong(long v, long floor) {
            return v < floor ? floor : v;
        }

        @Override
        public String toString() {
            return "Limits{msg=" + maxMessageBytes + ", headers=" + maxHeaders
                    + ", headerLine=" + maxHeaderLineBytes + ", depth=" + maxMimeDepth
                    + ", parts=" + maxMimeParts + ", decoded=" + maxDecodedBytes
                    + ", budgetMs=" + parseBudgetMillis + "}";
        }
    }

    private static final Limits DEFAULT_LIMITS = Limits.phase2();

    /** Upper bound on stored header values, so a giant value cannot be retained after the
     *  8 KB line cap has been applied across many folded continuation lines. */
    private static final int MAX_STORED_HEADER_VALUE = 64 * 1024;

    private static final int MAX_STORED_PARTS = 200;
    private static final int MAX_STORED_URLS = 1000;
    private static final int MAX_STORED_HOPS = 200;
    private static final int MAX_STORED_ADDRESSES = 512;

    // ==================================================================
    // Result types
    // ==================================================================

    /** Non-fatal limit hit. Surfaced rather than thrown; see threat model rule 1. */
    public static final class Warning {
        public final String code;
        public final String detail;

        Warning(String code, String detail) {
            this.code = code;
            this.detail = detail == null ? "" : detail;
        }

        @Override
        public String toString() {
            return detail.isEmpty() ? code : code + ": " + detail;
        }
    }

    /**
     * One address from From/To/Cc/Bcc. Fields are null when the input did not contain them;
     * nothing is inferred. A display name and an addr-spec may both be absent, which is legal for
     * a group construct, so a bare `undisclosed-recipients:;` yields a null domain.
     */
    public static final class Address {
        public final String raw;
        public final String displayName;
        public final String localPart;
        public final String domain;

        Address(String raw, String displayName, String localPart, String domain) {
            this.raw = raw;
            this.displayName = displayName;
            this.localPart = localPart;
            this.domain = domain;
        }

        /** True when the address is structurally an addr-spec, not a group or a comment. */
        public boolean isAddrSpec() {
            return localPart != null && domain != null;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("raw", raw);
            m.put("displayName", displayName);
            m.put("localPart", localPart);
            m.put("domain", domain);
            return m;
        }

        @Override
        public String toString() {
            return raw;
        }
    }

    /**
     * One unfolded header. {@code rawLine} is the first physical line exactly as received, which
     * is what a forensic report needs: unfolding is a normalisation, and showing only the
     * normalised form would hide a folded or malformed original.
     */
    public static final class Header {
        public final String name;
        /** Unfolded value. Not final: RFC 5322 folding is applied as continuation lines arrive. */
        public String value;
        public final String rawFirstLine;
        public final int lineNumber;
        public boolean folded;
        public int lineCount;

        Header(String name, String value, String rawFirstLine, int lineNumber,
               boolean folded, int lineCount) {
            this.name = name;
            this.value = value;
            this.rawFirstLine = rawFirstLine;
            this.lineNumber = lineNumber;
            this.folded = folded;
            this.lineCount = lineCount;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            m.put("value", value);
            m.put("lineNumber", lineNumber);
            m.put("folded", folded);
            m.put("lineCount", lineCount);
            return m;
        }
    }

    /**
     * A reconstructed Received hop.
     *
     * Hops are reported in received order: index 0 is the header physically at the top of the
     * message, which is the hop added by the FIRST relay that accepted the message. Index
     * n-1 was added last, by the relay that delivered it. This ordering is the opposite of the
     * intuitive one and it is the single most common misreading in this domain, so it is stated
     * on the field and enforced by the tests.
     *
     * Every clause is nullable. A hop whose {@code from} component is missing reports null rather
     * than borrowing the IP address as a hostname, because those are different facts and
     * conflating them is how a wrong actor gets named.
     */
    public static final class ReceivedHop {
        /** Position in the message, 0 = topmost = earliest added. */
        public final int index;
        public final String raw;
        /** First whitespace-delimited token, the by-hostname per RFC 5321 4.4. */
        public final String host;
        /** First bracketed IP literal in the header, or null. Not assumed to be the origin. */
        public final String ip;
        /** Epoch millis from the trailing date comment, or Long.MIN_VALUE when unparseable. */
        public final long timestampMillis;
        public final String timestampRaw;
        /** Mail transport protocol, e.g. ESMTPS, SMTP, ESMTPSA. Null when absent. */
        public final String protocol;
        public final String by;
        public final String from;
        public final String with;
        public final String id;
        public final String forClause;
        public final String via;
        /** Clause keywords that were present but not recognised. Recorded, not discarded. */
        public final List<String> unparsedClauseKeys;

        public ReceivedHop(int index, String raw, String host, String ip, long timestampMillis,
                           String timestampRaw, String protocol, String by, String from,
                           String with, String id, String forClause, String via,
                           List<String> unparsedClauseKeys) {
            this.index = index;
            this.raw = raw;
            this.host = host;
            this.ip = ip;
            this.timestampMillis = timestampMillis;
            this.timestampRaw = timestampRaw;
            this.protocol = protocol;
            this.by = by;
            this.from = from;
            this.with = with;
            this.id = id;
            this.forClause = forClause;
            this.via = via;
            this.unparsedClauseKeys = unparsedClauseKeys == null ? List.of() : unparsedClauseKeys;
        }

        public boolean hasTimestamp() {
            return timestampMillis != Long.MIN_VALUE;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", index);
            m.put("host", host);
            // Deliberately named ipObserved: this is what the header says, not an attribution.
            m.put("ipObserved", ip);
            m.put("timestampMillis", hasTimestamp() ? (Object) timestampMillis : null);
            m.put("timestampRaw", timestampRaw);
            m.put("protocol", protocol);
            m.put("by", by);
            m.put("from", from);
            m.put("with", with);
            m.put("id", id);
            m.put("forClause", forClause);
            m.put("via", via);
            m.put("unparsedClauseKeys", unparsedClauseKeys);
            m.put("raw", raw);
            return m;
        }

        @Override
        public String toString() {
            return "hop#" + index + " host=" + host + " ip=" + ip;
        }
    }

    /** A MIME leaf or container node. */
    public static final class Part {
        public int depth;
        public String contentType = "text/plain";
        public String contentTypeRaw = "";
        public String disposition;
        public String filename;
        public String transferEncoding = "7bit";
        public String contentId;
        public String charset;
        /** Decoded payload. Inert bytes. Never rendered, executed, or interpreted. */
        public byte[] data = new byte[0];
        /** Decoded size the content actually claimed, even when {@link #data} was cut short. */
        public long declaredDecodedBytes;
        public boolean truncated;
        public boolean isAttachment;
        public boolean isInline;
        public boolean isContainer;

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("depth", depth);
            m.put("contentType", contentType);
            m.put("disposition", disposition);
            m.put("filename", filename);
            m.put("transferEncoding", transferEncoding);
            m.put("contentId", contentId);
            m.put("charset", charset);
            m.put("decodedBytes", data.length);
            m.put("declaredDecodedBytes", declaredDecodedBytes);
            m.put("truncated", truncated);
            m.put("isAttachment", isAttachment);
            m.put("isInline", isInline);
            m.put("isContainer", isContainer);
            return m;
        }
    }

    /** SPF outcome, gathered from Received-SPF and from Authentication-Results. */
    public static final class SpfInfo {
        public String receivedSpfHeader;
        public String authResultsSpf;
        public String domain;
        /** Normalised verdict when one was actually stated, else null. Never inferred. */
        public String verdict;
        public String explanation;
        public final List<String> contradictions = new ArrayList<>();

        /** UNKNOWN unless a header actually asserted an SPF result. */
        public String effectiveVerdict() {
            if (receivedSpfHeader != null) return normalizeVerdict(receivedSpfHeader);
            if (authResultsSpf != null) return normalizeVerdict(authResultsSpf);
            return "unknown";
        }

        private static String normalizeVerdict(String s) {
            String t = s.toLowerCase(Locale.ROOT);
            if (t.contains("pass")) return "pass";
            if (t.contains("fail")) return "fail";
            if (t.contains("softfail")) return "softfail";
            if (t.contains("neutral")) return "neutral";
            if (t.contains("none")) return "none";
            if (t.contains("temperror")) return "temperror";
            if (t.contains("permerror")) return "permerror";
            return "unknown";
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("receivedSpfHeader", receivedSpfHeader);
            m.put("authResultsSpf", authResultsSpf);
            m.put("domain", domain);
            m.put("verdict", effectiveVerdict());
            m.put("explanation", explanation);
            m.put("contradictions", contradictions);
            return m;
        }
    }

    /** Complete parse result. */
    public static final class Message {
        /** Lower-cased name -> unfolded values in first-seen order. */
        public final Map<String, List<String>> headers = new LinkedHashMap<>();
        /** Headers in wire order, with raw first lines, for chain of custody. */
        public final List<Header> headerList = new ArrayList<>();
        public final List<Part> parts = new ArrayList<>();
        public final List<Warning> warnings = new ArrayList<>();
        public final List<ReceivedHop> hops = new ArrayList<>();
        public List<Address> from = new ArrayList<>();
        public List<Address> to = new ArrayList<>();
        public List<Address> cc = new ArrayList<>();
        public List<Address> bcc = new ArrayList<>();
        public final List<String> urls = new ArrayList<>();
        public final List<String> arcHeaderNames = new ArrayList<>();
        public final SpfInfo spf = new SpfInfo();

        public String subject;
        public String date;
        public String replyTo;
        public String returnPath;
        public String messageId;
        public String inReplyTo;
        public final List<String> references = new ArrayList<>();
        public String dkimSignature;
        public String authenticationResults;

        /** The header block exactly as received, bounded. */
        public String rawHeaderBlock = "";
        /** The complete bounded message as parsed. */
        public String raw = "";
        public String bodyText = "";
        public boolean truncated;
        public long bytesConsumed;
        public Limits limits = DEFAULT_LIMITS;

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

        /** Unique lower-cased domains seen in envelope-ish address headers. */
        public Set<String> domains() {
            Set<String> out = new LinkedHashSet<>();
            for (List<Address> group : List.of(from, to, cc, bcc)) {
                for (Address a : group) {
                    if (a.domain != null) out.add(a.domain);
                }
            }
            for (String r : references) {
                // message-id angle brackets carry no domain of the sender; skip intentionally.
            }
            if (replyTo != null) {
                for (Address a : EmailParser.parseAddressList(replyTo, 0, MAX_STORED_ADDRESSES)) {
                    if (a.domain != null) out.add(a.domain);
                }
            }
            return out;
        }

        /**
         * Text usable for TF-IDF body correlation. Concatenates text/* leaves only. Attachment
         * bytes never enter here, so a 10 MB binary attachment cannot poison the body vector.
         */
        public String correlationText() {
            if (!bodyText.isEmpty()) return bodyText;
            StringBuilder sb = new StringBuilder();
            for (Part p : parts) {
                if (!p.isContainer && p.contentType.toLowerCase(Locale.ROOT).startsWith("text/")) {
                    sb.append(new String(p.data, charsetInstance(p.charset)));
                    sb.append('\n');
                }
            }
            return sb.toString();
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("subject", subject);
            m.put("date", date);
            m.put("replyTo", replyTo);
            m.put("returnPath", returnPath);
            m.put("messageId", messageId);
            m.put("inReplyTo", inReplyTo);
            m.put("references", references);
            m.put("from", from.stream().map(Address::toMap).toList());
            m.put("to", to.stream().map(Address::toMap).toList());
            m.put("cc", cc.stream().map(Address::toMap).toList());
            m.put("bcc", bcc.stream().map(Address::toMap).toList());
            m.put("dkimSignature", dkimSignature);
            m.put("authenticationResults", authenticationResults);
            m.put("arcHeaders", arcHeaderNames);
            m.put("spf", spf.toMap());
            m.put("hops", hops.stream().map(ReceivedHop::toMap).toList());
            // Forensic fields. rawHeaderBlock and the per-header raw first lines are what let an
            // analyst re-derive how the parser saw the original message; without them a report
            // cannot be audited against the source. Both are already bounded by the parse limits.
            m.put("rawHeaderBlock", rawHeaderBlock);
            m.put("headerDetail", headerList.stream().map(Header::toMap).toList());
            m.put("parts", parts.stream().map(Part::toMap).toList());
            m.put("urls", urls);
            m.put("warnings", warningCodes());
            m.put("truncated", truncated);
            m.put("bytesConsumed", bytesConsumed);
            m.put("limits", limits.toString());
            return m;
        }
    }

    // ==================================================================
    // Budget
    // ==================================================================

    /**
     * Wall-clock budget shared by the whole parse, not per stage. The 2 s bound is on the
     * message, so three independent budgets would make the true worst case 6 s. The clock is
     * sampled every 512 work units rather than per character, so budget bookkeeping cannot
     * become the dominant cost on a large message.
     */
    private static final class Budget {
        private final long deadlineNanos;
        private boolean expired;
        private int ticks;

        Budget(long millis) {
            this.deadlineNanos = System.nanoTime() + millis * 1_000_000L;
            // A non-positive budget means "do no work", and it has to be honoured on the first
            // tick. The elapsed-time test below only fires every 512 ticks, so without this a
            // zero budget parsed a whole message and reported nothing.
            this.expired = millis <= 0;
        }

        boolean ok() {
            if (expired) return false;
            if ((++ticks & 0x1FF) == 0 && System.nanoTime() - deadlineNanos > 0) {
                expired = true;
                return false;
            }
            return true;
        }

        boolean expired() {
            return expired;
        }
    }

    // ==================================================================
    // Entry points
    // ==================================================================

    public static Message parse(byte[] rawBytes) {
        return parse(rawBytes, DEFAULT_LIMITS);
    }

    public static Message parse(String raw) {
        return parse(raw == null ? new byte[0] : raw.getBytes(StandardCharsets.ISO_8859_1),
                DEFAULT_LIMITS);
    }

    /**
     * The one real implementation. Guarantees a non-null {@link Message} for any input,
     * including null, empty, binary, and deliberately malformed.
     */
    public static Message parse(byte[] rawBytes, Limits limits) {
        Limits lim = limits == null ? DEFAULT_LIMITS : limits;
        Message m = new Message();
        m.limits = lim;
        Budget budget = new Budget(lim.parseBudgetMillis);

        byte[] bytes = rawBytes == null ? new byte[0] : rawBytes;
        if (bytes.length > lim.maxMessageBytes) {
            bytes = java.util.Arrays.copyOf(bytes, (int) lim.maxMessageBytes);
            m.truncated = true;
            m.warn("MESSAGE_TRUNCATED",
                    "raw message exceeds " + lim.maxMessageBytes + " bytes; truncated");
        }
        m.bytesConsumed = bytes.length;

        // ISO-8859-1 maps every byte to exactly one char, so char indices equal byte indices and
        // no multi-byte decode can desynchronise a cursor. UTF-8 is applied later, per MIME part,
        // where the declared charset is known.
        m.raw = new String(bytes, StandardCharsets.ISO_8859_1);

        int headerEnd = findHeaderEnd(m.raw);
        String headerBlock = headerEnd < 0 ? m.raw : m.raw.substring(0, headerEnd);
        m.rawHeaderBlock = headerBlock;

        int bodyStart = headerEnd < 0
                ? 0
                : skipBreak(m.raw, skipBreak(m.raw, headerEnd));
        String body = headerEnd < 0 ? ""
                : m.raw.substring(Math.min(m.raw.length(), Math.max(0, bodyStart)));

        parseHeaderBlock(headerBlock, m, lim, budget);
        extractRouting(m);
        parseHops(m);
        extractSpfAndArc(m);

        DecodeBudget decodeBudget = new DecodeBudget(lim.maxDecodedBytes);
        walkMime(body, m.first("content-type"), m, 0, lim, decodeBudget, budget);
        buildBodyText(m);
        extractUrls(m.bodyText, m, budget);

        if (budget.expired()) {
            m.truncated = true;
            m.warn("TIME_BUDGET_EXCEEDED",
                    "parse stopped at the " + lim.parseBudgetMillis + " ms budget; result is partial");
        }
        if (m.truncated) {
            m.warn("PARSE_TRUNCATED", "result is a truncated view of the original message");
        }
        return m;
    }

    public static Message parse(String raw, Limits limits) {
        return parse(raw == null ? new byte[0] : raw.getBytes(StandardCharsets.ISO_8859_1), limits);
    }

    /** Running total of decoded bytes across all parts, enforcing the 10 MB ceiling. */
    private static final class DecodeBudget {
        private final long cap;
        private long used;

        DecodeBudget(long cap) {
            this.cap = cap;
        }

        long remaining() {
            long r = cap - used;
            return r < 0 ? 0 : r;
        }

        /** Reserves up to {@code want} bytes and returns how much the caller may actually emit. */
        long take(long want) {
            if (want < 0) want = 0;
            long r = remaining();
            long grant = want < r ? want : r;
            used += grant;
            return grant;
        }
    }

    // ==================================================================
    // Header block
    // ==================================================================

    /**
     * Index of the blank line separating headers from body, or -1 when the message is
     * header-only. Single monotonic scan.
     */
    private static int findHeaderEnd(String raw) {
        for (int i = 0; i + 1 < raw.length(); i++) {
            if (raw.charAt(i) != '\n') continue;
            char next = raw.charAt(i + 1);
            if (next == '\n') return i;
            if (next == '\r' && i + 2 < raw.length() && raw.charAt(i + 2) == '\n') return i;
        }
        return -1;
    }

    private static int skipBreak(String s, int i) {
        if (i < 0) return 0;
        int n = s.length();
        if (i < n && s.charAt(i) == '\r') i++;
        if (i < n && s.charAt(i) == '\n') i++;
        return Math.min(i, n);
    }

    private static void parseHeaderBlock(String block, Message m, Limits lim, Budget budget) {
        int n = block.length();
        int i = 0;
        int lineNo = 0;
        int accepted = 0;
        boolean headerLimitWarned = false;
        boolean lineLimitWarned = false;
        boolean foldLimitWarned = false;

        while (i < n) {
            if (!budget.ok()) return;

            int lineStart = i;
            int nl = indexOfBreak(block, i);
            int lineEnd = nl < 0 ? n : nl;
            String line = block.substring(lineStart, lineEnd);
            i = nl < 0 ? n : advanceBreak(block, nl);
            lineNo++;

            // Blank line ends the block.
            if (line.isEmpty()) continue;

            boolean continuation = (line.charAt(0) == ' ' || line.charAt(0) == '\t');
            if (continuation) {
                if (m.headerList.isEmpty()) {
                    m.warn("HEADER_CONTINUATION_ORPHAN",
                            "line " + lineNo + " is a continuation with no preceding header");
                    continue;
                }
                Header last = m.headerList.get(m.headerList.size() - 1);
                if (last.value.length() < MAX_STORED_HEADER_VALUE) {
                    // A fold collapses to one space per RFC 5322 2.2.3. This is also what stops
                    // an attacker from inflating one header past its cap purely by folding.
                    // The append is clamped to the cap rather than merely gated on it: a
                    // "length < cap" test still lets the final continuation overshoot the cap by
                    // a whole line, so the stored value was not actually bounded by it.
                    String piece = line.trim();
                    int room = MAX_STORED_HEADER_VALUE - last.value.length() - 1;
                    if (room <= 0) {
                        foldLimitWarned = warnFoldCap(m, foldLimitWarned, last);
                    } else {
                        if (piece.length() > room) piece = piece.substring(0, room);
                        last.value = last.value + ' ' + piece;
                        // The map and the Header must be updated together. They are two views of
                        // one header, and leaving the map pointing at the pre-fold String silently
                        // truncated every folded header to its first physical line - which is most
                        // real-world Received headers.
                        List<String> slot = m.headers.get(last.name.toLowerCase(Locale.ROOT));
                        if (slot != null && !slot.isEmpty()) {
                            slot.set(slot.size() - 1, last.value);
                        }
                        if (piece.length() < line.trim().length()) {
                            foldLimitWarned = warnFoldCap(m, foldLimitWarned, last);
                        }
                    }
                } else {
                    foldLimitWarned = warnFoldCap(m, foldLimitWarned, last);
                }
                last.folded = true;
                last.lineCount++;
                continue;
            }

            if (accepted >= lim.maxHeaders) {
                if (!headerLimitWarned) {
                    headerLimitWarned = true;
                    m.warn("HEADER_COUNT_EXCEEDED",
                            "more than " + lim.maxHeaders + " headers; remaining headers dropped");
                }
                continue;
            }

            int colon = line.indexOf(':');
            if (colon <= 0) {
                m.warn("MALFORMED_HEADER_LINE", "line " + lineNo + " has no usable field name");
                continue;
            }

            String name = line.substring(0, colon).trim();
            if (name.isEmpty()) {
                m.warn("MALFORMED_HEADER_LINE", "line " + lineNo + " has an empty field name");
                continue;
            }
            if (!isHeaderName(name)) {
                m.warn("MALFORMED_HEADER_NAME", "line " + lineNo + " name is not RFC 5322 tokens");
            }

            String value = line.substring(colon + 1).trim();
            if (line.length() > lim.maxHeaderLineBytes) {
                value = value.substring(0, Math.min(value.length(), lim.maxHeaderLineBytes));
                if (!lineLimitWarned) {
                    lineLimitWarned = true;
                    m.warn("HEADER_LINE_EXCEEDED",
                            "header line longer than " + lim.maxHeaderLineBytes
                                    + " bytes; value truncated");
                }
            }

            String key = name.toLowerCase(Locale.ROOT);
            Header h = new Header(name, value, line, lineNo, false, 1);
            m.headerList.add(h);
            m.headers.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
            accepted++;
        }
    }

    /** Reports a folded header hitting the stored-value cap, at most once per message. */
    private static boolean warnFoldCap(Message m, boolean alreadyWarned, Header h) {
        if (alreadyWarned) return true;
        // Hitting the stored-value cap is silent data loss. Report it rather than letting a caller
        // believe it is reading the whole header.
        m.warn("HEADER_VALUE_TRUNCATED",
                "folded header '" + h.name + "' exceeded the stored value cap of "
                        + MAX_STORED_HEADER_VALUE + " chars; later continuations dropped");
        return true;
    }

    /** RFC 5322 field name: printable US-ASCII except colon, no whitespace, no control chars. */
    private static boolean isHeaderName(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 33 || c > 126 || c == ':') return false;
        }
        return !s.isEmpty();
    }

    private static int indexOfBreak(String s, int from) {
        for (int i = from; i < s.length(); i++) {
            if (s.charAt(i) == '\n') return i;
            if (s.charAt(i) == '\r') return i;
        }
        return -1;
    }

    private static int advanceBreak(String s, int at) {
        if (at < 0) return s.length();
        int i = at;
        if (i < s.length() && s.charAt(i) == '\r') i++;
        if (i < s.length() && s.charAt(i) == '\n') i++;
        return Math.min(i, s.length());
    }

    // ==================================================================
    // Routing headers
    // ==================================================================

    private static void extractRouting(Message m) {
        m.from = parseAddressList(m.first("from"), 0, MAX_STORED_ADDRESSES);
        m.to = parseAddressList(m.first("to"), 0, MAX_STORED_ADDRESSES);
        m.cc = parseAddressList(m.first("cc"), 0, MAX_STORED_ADDRESSES);
        m.bcc = parseAddressList(m.first("bcc"), 0, MAX_STORED_ADDRESSES);
        m.subject = m.first("subject");
        m.date = m.first("date");
        m.replyTo = m.first("reply-to");
        m.returnPath = m.first("return-path");
        m.messageId = stripBrackets(m.first("message-id"));
        m.inReplyTo = stripBrackets(m.first("in-reply-to"));
        m.dkimSignature = m.first("dkim-signature");
        m.authenticationResults = m.first("authentication-results");
        for (String r : m.all("references")) {
            for (String t : splitReferences(r)) {
                m.references.add(t);
                if (m.references.size() >= MAX_STORED_HOPS) break;
            }
        }
    }

    private static String stripBrackets(String s) {
        if (s == null) return null;
        int a = s.indexOf('<');
        int b = s.lastIndexOf('>');
        if (a >= 0 && b > a) return s.substring(a + 1, b).trim();
        return s.trim();
    }

    /** References may be folded across lines and space-separated. Bounded manual scan. */
    private static List<String> splitReferences(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) return out;
        int n = s.length();
        int i = 0;
        while (i < n) {
            while (i < n && s.charAt(i) != '<') i++;
            if (i >= n) break;
            int j = s.indexOf('>', i + 1);
            if (j < 0) {
                out.add(s.substring(i + 1).trim());
                break;
            }
            out.add(s.substring(i + 1, j).trim());
            i = j + 1;
        }
        return out;
    }

    /**
     * Bounded address-list parser.
     *
     * Splits on commas that are not inside quotes, angle brackets, comments, or a group
     * construct, then reads one address out of each element. Malformed elements yield a raw-only
     * Address with null fields instead of being dropped, because a present-but-unparseable
     * address is evidence too.
     */
    public static List<Address> parseAddressList(String value, int offset, int cap) {
        List<Address> out = new ArrayList<>();
        if (value == null || value.isEmpty() || cap <= 0) return out;

        int n = value.length();
        int i = 0;
        int start = 0;
        boolean inQuote = false;
        boolean inAngle = false;
        int commentDepth = 0;

        while (i <= n) {
            if (i == n) {
                addOne(value.substring(start, i), out, cap);
                break;
            }
            char c = value.charAt(i);
            if (c == '\\' && inQuote && i + 1 < n) {
                i += 2;
                continue;
            }
            if (c == '"' && commentDepth == 0) inQuote = !inQuote;
            else if (!inQuote && c == '(') commentDepth++;
            else if (!inQuote && c == ')' && commentDepth > 0) commentDepth--;
            else if (!inQuote && commentDepth == 0) {
                if (c == '<') inAngle = true;
                else if (c == '>') inAngle = false;
                else if (c == ',' && !inAngle) {
                    addOne(value.substring(start, i), out, cap);
                    start = i + 1;
                    if (out.size() >= cap) return out;
                }
            }
            i++;
        }
        return out;
    }

    private static void addOne(String element, List<Address> out, int cap) {
        if (out.size() >= cap) return;
        String e = element.trim();
        if (e.isEmpty()) return;

        // Group syntax: "name: a@b, c@d;" produces a display name and no addr-spec.
        int colon = e.indexOf(':');
        int semi = e.lastIndexOf(';');
        if (colon > 0 && semi >= 0 && semi < e.length() - 1 + 1) {
            out.add(new Address(e, unquote(e.substring(0, colon).trim()), null, null));
            return;
        }

        String display = null;
        String addr = e;
        int lt = e.lastIndexOf('<');
        int gt = e.lastIndexOf('>');
        if (lt >= 0 && gt > lt) {
            addr = e.substring(lt + 1, gt).trim();
            display = stripComment(e.substring(0, lt).trim());
        } else {
            // Bare addr-spec: take the last whitespace-delimited token so that a trailing
            // comment does not get glued onto the address.
            String noComment = stripComment(e);
            int sp = lastWhitespace(noComment);
            addr = sp < 0 ? noComment : noComment.substring(sp + 1);
            if (sp > 0) display = unquote(noComment.substring(0, sp).trim());
        }

        String local = null;
        String domain = null;
        int at = addr.lastIndexOf('@');
        if (at > 0 && at < addr.length() - 1) {
            local = addr.substring(0, at);
            domain = addr.substring(at + 1).trim().toLowerCase(Locale.ROOT);
            if (domain.isEmpty()) domain = null;
        }
        out.add(new Address(e, display, local, domain));
    }

    /** Removes a trailing RFC 5322 comment, honouring nesting and backslash escapes. */
    private static String stripComment(String s) {
        int depth = 0;
        int end = s.length();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) { i++; continue; }
            if (c == '(') depth++;
            else if (c == ')' && depth > 0) depth--;
            else if (c == ',' && depth == 0) return s.substring(0, i);
        }
        return depth > 0 ? s.substring(0, Math.max(0, end - 1)) : s;
    }

    private static int lastWhitespace(String s) {
        for (int i = s.length() - 1; i >= 0; i--) {
            if (Character.isWhitespace(s.charAt(i))) return i;
        }
        return -1;
    }

    private static String unquote(String s) {
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"') {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    // ==================================================================
    // Received hops
    // ==================================================================

    private static final Set<String> KNOWN_CLAUSE_KEYS = Set.of("by", "from", "with", "id", "for", "via");

    /**
     * True for keywords that are always followed by a separate value token.
     *
     * "with" is included even though it is also sometimes the name of a transport protocol: the
     * value it consumes is then run through {@link #matchProtocol} as well, so "with ESMTPS"
     * populates both the with-clause and the protocol without either losing information.
     */
    private static boolean isBareClauseKeyword(String lower) {
        return lower.equals("by") || lower.equals("from") || lower.equals("with")
                || lower.equals("id") || lower.equals("for") || lower.equals("via");
    }

    /** Recognised transport protocol tokens. Fixed set, matched by prefix test, not regex. */
    private static final List<String> PROTOCOLS =
            List.of("ESMTPSA", "ESMTPS", "ESMTP", "SMTPS", "SMTP", "LMTP", "HTTP", "HTTPAUTH", "IMAP", "POP3");

    private static void parseHops(Message m) {
        List<String> raw = m.all("received");
        int i = 0;
        for (String value : raw) {
            if (i >= MAX_STORED_HOPS) {
                m.warn("RECEIVED_TRUNCATED", "more than " + MAX_STORED_HOPS + " Received headers");
                break;
            }
            m.hops.add(parseHop(value, i));
            i++;
        }
    }

    /**
     * Reconstructs one hop. Every clause is independently nullable; nothing is borrowed from
     * another field to fill a gap. In particular the hostname is NOT reconstructed from the IP.
     */
    static ReceivedHop parseHop(String raw, int index) {
        String s = raw == null ? "" : raw.trim();

        int semi = s.lastIndexOf(';');
        String timestampRaw = null;
        String head = s;
        if (semi >= 0) {
            timestampRaw = s.substring(semi + 1).trim();
            head = s.substring(0, semi).trim();
        }
        long ts = parseRfc5322Date(timestampRaw);

        String host = firstHostToken(head);
        String ip = firstBracketedIp(head);

        String by = null, from = null, with = null, id = null, forClause = null, via = null;
        String protocol = null;
        List<String> unparsed = new ArrayList<>();

        // Walk whitespace-separated tokens, tracking paren depth so that a parenthesised group
        // does not split a clause in half.
        int n = head.length();
        int i = 0;
        while (i < n) {
            while (i < n && isSep(head.charAt(i))) i++;
            if (i >= n) break;
            int start = i;
            int depth = 0;
            StringBuilder tok = new StringBuilder();
            while (i < n) {
                char c = head.charAt(i);
                if (c == '(') { depth++; tok.append(c); i++; continue; }
                if (c == ')') { if (depth > 0) depth--; tok.append(c); i++; continue; }
                if (isSep(c) && depth == 0) break;
                tok.append(c);
                i++;
            }
            String t = tok.toString();
            if (t.isEmpty()) continue;

            if (t.charAt(0) == '(') {
                // Parenthetical: "from mail-x (host [1.2.3.4])" - the IP inside was already
                // captured. If it carries an explicit from=, prefer that spelling.
                int eq = t.indexOf("from=");
                if (eq >= 0 && from == null) {
                    from = firstToken(t.substring(eq + 5));
                }
                continue;
            }

            int eq = t.indexOf('=');
            if (eq > 0) {
                String k = t.substring(0, eq).toLowerCase(Locale.ROOT);
                String v = t.substring(eq + 1);
                switch (k) {
                    case "by" -> { if (by == null) by = usableHost(v); }
                    case "from" -> { if (from == null) from = usableHost(v); }
                    case "with" -> { if (with == null) with = v; }
                    case "id" -> { if (id == null) id = v; }
                    case "for" -> { if (forClause == null) forClause = v; }
                    case "via" -> { if (via == null) via = usableHost(v); }
                    default -> unparsed.add(k);
                }
                continue;
            }

            String lower = t.toLowerCase(Locale.ROOT);
            if (lower.equals("via")) {
                // "via X" - the value is the next token.
                int j = i;
                while (j < n && isSep(head.charAt(j))) j++;
                int vs = j;
                while (j < n && !isSep(head.charAt(j))) j++;
                if (via == null && vs < j) via = head.substring(vs, j);
                i = j;
                continue;
            }
            // RFC 5321 spells most clauses as a bare keyword followed by its value
            // ("by mx.example", "with ESMTPS", "id A1B2", "for <box@host>"). Only the
            // key=value spelling was handled before, which left every normal real-world hop
            // reporting null for by/from/with/id/for.
            if (KNOWN_CLAUSE_KEYS.contains(lower) && isBareClauseKeyword(lower)) {
                int j = i;
                while (j < n && isSep(head.charAt(j))) j++;
                int vs = j;
                while (j < n && !isSep(head.charAt(j))) j++;
                String v = vs < j ? head.substring(vs, j) : null;
                i = j;
                if (lower.equals("with") && protocol == null && v != null) {
                    String p = matchProtocol(v);
                    if (p != null) protocol = p;
                }
                switch (lower) {
                    // by/from/via name a server, so the value is filtered. with/id/for are left
                    // alone: "with ESMTPS", "id A1B2" and "for <box@host>" are all legitimate and
                    // filtering them would discard real evidence.
                    case "by" -> { if (by == null) by = usableHost(v); }
                    case "from" -> { if (from == null) from = usableHost(v); }
                    case "with" -> { if (with == null) with = v; }
                    case "id" -> { if (id == null) id = v; }
                    case "for" -> { if (forClause == null) forClause = v; }
                    case "via" -> { if (via == null) via = usableHost(v); }
                    default -> { }
                }
                continue;
            }
            if (protocol == null) {
                String p = matchProtocol(t);
                if (p != null) {
                    protocol = p;
                    continue;
                }
            }
            unparsed.add(lower.length() > 32 ? lower.substring(0, 32) : lower);
        }

        return new ReceivedHop(index, s, host, ip, ts, timestampRaw, protocol, by, from,
                with, id, forClause, via, unparsed);
    }

    private static String matchProtocol(String tok) {
        String upper = tok.toUpperCase(Locale.ROOT);
        // The token may be a versioned or namespaced protocol such as "ESMTPS" or
        // "smtp/verp". Take the leading alphabetic run and match that.
        int e = 0;
        while (e < upper.length() && Character.isLetter(upper.charAt(e))) e++;
        if (e == 0) return null;
        String head = upper.substring(0, e);
        for (String p : PROTOCOLS) {
            if (head.equals(p)) return head;
        }
        return null;
    }

    private static boolean isSep(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    private static String firstToken(String s) {
        if (s == null) return null;
        int i = 0;
        while (i < s.length() && isSep(s.charAt(i))) i++;
        int start = i;
        while (i < s.length() && !isSep(s.charAt(i))) i++;
        return i > start ? s.substring(start, i) : null;
    }

    /**
     * The by-hostname, which is the token after the leading "from" keyword.
     *
     * RFC 5321 4.4 opens a Received header with the reserved word "from", so the first token is
     * the literal keyword and the hostname is the second. Reading token 0 as the host reports
     * "from" as the mail server for every compliant hop in existence.
     */
    private static String firstHostToken(String s) {
        int start = tokenStart(s, 0);
        if (start >= s.length()) return null;
        String first = s.substring(start, tokenEnd(s, start));

        if (first.equalsIgnoreCase("from")) {
            int j = tokenStart(s, tokenEnd(s, start));
            if (j >= s.length()) return null;
            return usableHost(s.substring(j, tokenEnd(s, j)));
        }

        // No leading "from". When the hop opens with another reserved word, as in
        // "by mx.example with ESMTP", the originating host is simply not stated. Reporting the
        // keyword itself as the mail server invents an infrastructure fact that is not in the
        // message, and attribution compares this field against operator-supplied proxy hosts.
        if (isBareClauseKeyword(first.toLowerCase(Locale.ROOT))) return null;
        return usableHost(first);
    }

    /**
     * Rejects tokens that cannot be a hostname, so {@code host} is either a plausible server name
     * or null.
     *
     * A parenthesised or bracketed token is a comment or an address literal, not a name, and a
     * host that held "([9.9.9.9])" would double-report the address that {@code ip} already
     * carries. A bare clause keyword or protocol token is likewise not a server name.
     */
    private static String usableHost(String tok) {
        if (tok == null) return null;
        String t = tok.trim();
        if (t.isEmpty()) return null;
        char c0 = t.charAt(0);
        if (c0 == '(' || c0 == '[' || c0 == '<' || c0 == '"') return null;
        if (isBareClauseKeyword(t.toLowerCase(Locale.ROOT))) return null;
        if (matchProtocol(t) != null) return null;
        return t;
    }

    /** Index of the first non-separator character at or after {@code from}, or s.length(). */
    private static int tokenStart(String s, int from) {
        int i = Math.max(0, from);
        while (i < s.length() && isSep(s.charAt(i))) i++;
        return i;
    }

    /** Index of the first separator at or after {@code from}, or s.length(). */
    private static int tokenEnd(String s, int from) {
        int i = Math.max(0, from);
        while (i < s.length() && !isSep(s.charAt(i))) i++;
        return i;
    }

    /**
     * First bracketed IP literal. Bracket scan only - a bare "1.2.3.4" outside brackets is not
     * accepted, because unbracketed tokens in a Received header are far more often hostnames or
     * queue IDs than addresses, and guessing there produces a false actor.
     */
    static String firstBracketedIp(String s) {
        int i = 0;
        while (i < s.length()) {
            if (s.charAt(i) == '[') {
                int close = s.indexOf(']', i + 1);
                if (close < 0) return null;
                String inner = s.substring(i + 1, close).trim();
                if (isIpLiteral(inner)) return inner;
                i = close + 1;
                continue;
            }
            i++;
        }
        return null;
    }

    /**
     * Dotted-quad IPv4 or a plausible IPv6 literal, by manual scan. Deliberately not a regex:
     * IP extraction is the highest-value hostile-input path in this parser, so it gets a walk
     * whose cost is provably linear.
     */
    public static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty() || s.length() > 45) return false;
        if (s.indexOf(':') >= 0) return isIpv6(s);
        return isIpv4(s);
    }

    public static boolean isIpv4(String s) {
        int n = s.length();
        if (n < 7 || n > 15) return false;
        int seg = 0;
        int digits = 0;
        int value = 0;
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c == '.') {
                if (digits == 0 || seg == 3) return false;
                seg++;
                digits = 0;
                value = 0;
                if (seg > 3) return false;
            } else if (c >= '0' && c <= '9') {
                if (digits == 0 && c == '0' && i + 1 < n && isDigit(s.charAt(i + 1))) {
                    return false; // leading zero: ambiguous octal, reject
                }
                if (digits >= 3) return false;
                value = value * 10 + (c - '0');
                digits++;
                if (value > 255) return false;
            } else {
                return false;
            }
        }
        return digits > 0 && seg == 3;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /** Structural IPv6 check: hex groups, at most one "::", optional trailing IPv4, no zone id. */
    private static boolean isIpv6(String s) {
        if (s.indexOf('%') >= 0) return false;
        int n = s.length();
        int doubleColon = -1;
        int groups = 0;
        int i = 0;
        while (i < n) {
            if (s.charAt(i) == ':') {
                if (i + 1 < n && s.charAt(i + 1) == ':') {
                    if (doubleColon >= 0) return false;
                    doubleColon = groups;
                    i += 2;
                    if (i == n) break;
                    continue;
                }
                groups++;
                if (groups > 7) return false;
                i++;
                if (i == n) return false;
            }
            int start = i;
            int hex = 0;
            while (i < n && isHex(s.charAt(i))) {
                i++;
                hex++;
                if (hex > 4) return false;
            }
            if (hex == 0) {
                // A bare "::" already consumed the pair; anything else is malformed.
                if (start < n && s.charAt(start) != ':') return false;
                i = start;
                continue;
            }
            if (i < n && s.charAt(i) == '.') {
                if (!isIpv4(s.substring(start))) return false;
                groups++;
                i = n;
                break;
            }
            if (i < n && s.charAt(i) != ':') return false;
        }
        if (doubleColon < 0) return groups == 8;
        return groups < 8;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * RFC 5322 date. Tries a small fixed set of formats; the two-letter and three-letter military
     * zones are normalised because they appear in real headers and a mis-parsed timestamp
     * corrupts the entire relay-ordering analysis downstream.
     *
     * The numeric-offset patterns use lowercase {@code x}, not uppercase {@code X}. {@code X}
     * means the colon-separated ISO form (+00:00) and rejects the +0000 that essentially every
     * real header uses; {@code x} accepts +0000. Getting this backwards silently discarded the
     * timestamp of every hop, which made relay ordering impossible to validate.
     *
     * An optional leading day-of-week is stripped for the fallback shapes, so a header that
     * omits "Mon," still parses instead of falling through to unknown.
     */
    static long parseRfc5322Date(String s) {
        if (s == null) return Long.MIN_VALUE;
        String t = s.trim();
        if (t.isEmpty()) return Long.MIN_VALUE;
        String z = normalizeZone(t);
        String noDow = stripDayOfWeek(z);

        String[] withDow = {
                "EEE, d MMM yyyy HH:mm:ss xx",
                "EEE, d MMM yyyy HH:mm:ss zzz",
                "EEE, d MMM yyyy HH:mm xx",
                "EEE, d MMM yyyy HH:mm zzz",
        };
        for (String fmt : withDow) {
            long v = tryDate(z, fmt);
            if (v != Long.MIN_VALUE) return v;
        }
        String[] withoutDow = {
                "d MMM yyyy HH:mm:ss xx",
                "d MMM yyyy HH:mm:ss zzz",
                "d MMM yyyy HH:mm xx",
                "d MMM yyyy HH:mm zzz",
        };
        for (String fmt : withoutDow) {
            long v = tryDate(noDow, fmt);
            if (v != Long.MIN_VALUE) return v;
        }
        return Long.MIN_VALUE;
    }

    private static long tryDate(String text, String fmt) {
        try {
            ZonedDateTime zdt = ZonedDateTime.parse(text, DateTimeFormatter.ofPattern(fmt, Locale.ROOT));
            return zdt.toInstant().toEpochMilli();
        } catch (DateTimeException | IllegalArgumentException ignored) {
            // Try the next shape. A hostile date simply fails all shapes and stays unknown.
            return Long.MIN_VALUE;
        }
    }

    /** Removes a leading "Mon, " style day-of-week, if present. */
    private static String stripDayOfWeek(String t) {
        int comma = t.indexOf(',');
        if (comma <= 0) return t;
        String head = t.substring(0, comma).trim();
        if (head.length() < 3 || head.length() > 12) return t;
        for (int i = 0; i < head.length(); i++) {
            if (!Character.isLetter(head.charAt(i))) return t;
        }
        return t.substring(comma + 1).trim();
    }

    private static String normalizeZone(String t) {
        if (t.endsWith(" UT")) return t.substring(0, t.length() - 3) + " GMT";
        if (t.endsWith(" Z")) return t.substring(0, t.length() - 2) + " GMT";
        if (t.endsWith(" EST")) return t.substring(0, t.length() - 4) + " -0500";
        if (t.endsWith(" EDT")) return t.substring(0, t.length() - 4) + " -0400";
        if (t.endsWith(" CST")) return t.substring(0, t.length() - 4) + " -0600";
        if (t.endsWith(" CDT")) return t.substring(0, t.length() - 4) + " -0500";
        if (t.endsWith(" MST")) return t.substring(0, t.length() - 4) + " -0700";
        if (t.endsWith(" MDT")) return t.substring(0, t.length() - 4) + " -0600";
        if (t.endsWith(" PST")) return t.substring(0, t.length() - 4) + " -0800";
        if (t.endsWith(" PDT")) return t.substring(0, t.length() - 4) + " -0700";
        return t;
    }

    // ==================================================================
    // SPF / ARC / DKIM
    // ==================================================================

    private static void extractSpfAndArc(Message m) {
        String rsf = m.first("received-spf");
        if (rsf != null) m.spf.receivedSpfHeader = rsf;

        if (m.authenticationResults != null) {
            String v = authResultComponent(m.authenticationResults, "spf");
            if (v != null) m.spf.authResultsSpf = v;
            m.spf.domain = authResultDomain(m.authenticationResults);
        }
        if (m.spf.receivedSpfHeader != null && m.spf.domain == null) {
            m.spf.domain = firstToken(stripLeadingWord(m.spf.receivedSpfHeader));
        }

        if (m.spf.receivedSpfHeader != null && m.spf.authResultsSpf != null) {
            String a = m.spf.effectiveVerdict();
            String b = normalizeSimple(m.spf.authResultsSpf);
            if (!a.equals("unknown") && !b.equals("unknown") && !a.equals(b)) {
                m.spf.contradictions.add("Received-SPF says " + a
                        + " but Authentication-Results says " + b);
            }
        }

        m.arcHeaderNames.clear();
        for (String key : m.headers.keySet()) {
            if (key.startsWith("arc-")) m.arcHeaderNames.add(key);
        }
        m.arcHeaderNames.sort(String::compareTo);
    }

    private static String normalizeSimple(String v) {
        String t = v.toLowerCase(Locale.ROOT);
        if (t.startsWith("pass")) return "pass";
        if (t.startsWith("fail")) return "fail";
        if (t.startsWith("softfail")) return "softfail";
        if (t.startsWith("neutral")) return "neutral";
        if (t.startsWith("none")) return "none";
        if (t.startsWith("temperror")) return "temperror";
        if (t.startsWith("permerror")) return "permerror";
        return "unknown";
    }

    /**
     * Pulls "spf" out of an Authentication-Results value such as
     * "mx.example.com; spf=pass smtp.mailfrom=a.example.com; dkim=pass".
     * Single forward scan, no regex.
     */
    static String authResultComponent(String value, String key) {
        if (value == null) return null;
        int i = 0;
        int n = value.length();
        while (i < n) {
            int start = i;
            while (i < n && value.charAt(i) != ';') i++;
            String segment = value.substring(start, i);
            i++; // consume ';'
            int eq = segment.indexOf('=');
            if (eq < 0) continue;
            String k = segment.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            if (!k.equals(key.toLowerCase(Locale.ROOT))) continue;
            String v = segment.substring(eq + 1).trim();
            int sp = v.indexOf(' ');
            return sp < 0 ? v : v.substring(0, sp);
        }
        return null;
    }

    static String authResultDomain(String value) {
        if (value == null) return null;
        int firstSemi = value.indexOf(';');
        if (firstSemi <= 0) return null;
        String head = value.substring(0, firstSemi).trim();
        int at = head.indexOf('@');
        if (at >= 0) head = head.substring(at + 1);
        head = head.trim();
        if (head.isEmpty()) return null;
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == ':')) return null;
        }
        return head.toLowerCase(Locale.ROOT);
    }

    private static String stripLeadingWord(String s) {
        int sp = s.indexOf(' ');
        return sp < 0 ? s : s.substring(sp + 1);
    }

    // ==================================================================
    // MIME
    // ==================================================================

    /**
     * Bounded MIME walk.
     *
     * Recursion is bounded by {@link Limits#maxMimeDepth} and only occurs for a node that
     * actually declares a parseable boundary, so the maximum stack depth is a constant we chose
     * (8) rather than anything the sender can influence. The whole walk is iterative in the
     * common case: a non-multipart body is decoded and returned without recursing at all.
     */
    private static void walkMime(String body, String contentType, Message m, int depth,
                                 Limits lim, DecodeBudget db, Budget budget) {
        walkMime(body, contentType, m.rawHeaderBlock, m, depth, lim, db, budget);
    }

    private static void walkMime(String body, String contentType, String partHeaders, Message m,
                                 int depth, Limits lim, DecodeBudget db, Budget budget) {
        if (depth > lim.maxMimeDepth) {
            // The depth guard must fire before any silent return, otherwise a nesting bomb with
            // empty bodies at the limit depth produces no warning at all.
            m.warn("MIME_DEPTH_EXCEEDED",
                    "MIME nesting deeper than " + lim.maxMimeDepth + "; deeper content not parsed");
            m.truncated = true;
            return;
        }
        if (body.isEmpty() || m.parts.size() >= lim.maxMimeParts) return;

        if (m.parts.size() >= lim.maxMimeParts) {
            m.warn("MIME_PART_LIMIT", "part count reached " + lim.maxMimeParts + "; remaining parts skipped");
            return;
        }
        if (!budget.ok()) return;

        String type = contentType == null ? "text/plain" : contentType;
        String typeLower = type.toLowerCase(Locale.ROOT);
        String boundary = boundaryOf(type);

        if (boundary == null || !typeLower.startsWith("multipart/")) {
            // A depth-0 leaf inherits the message header block; a nested leaf inherits the
            // block of the part that contained it. Without passing that block down, the part's
            // own Content-Transfer-Encoding, Content-Disposition and Content-ID are invisible
            // and every part is treated as raw 7bit with no filename.
            Part p = decodeLeaf(body, partHeaders, type, depth, m, lim, db);
            if (p != null) m.parts.add(p);
            return;
        }

        // Container node recorded for structure, then descend.
        Part container = new Part();
        container.depth = depth;
        container.contentType = type;
        container.contentTypeRaw = type;
        container.isContainer = true;
        m.parts.add(container);

        for (String segment : splitOnBoundary(body, boundary)) {
            if (m.parts.size() >= lim.maxMimeParts) {
                m.warn("MIME_PART_LIMIT",
                        "part count reached " + lim.maxMimeParts + "; remaining parts skipped");
                return;
            }
            if (!budget.ok()) return;

            int innerHeaderEnd = findHeaderEnd(segment);
            String innerHeaders = innerHeaderEnd < 0 ? segment : segment.substring(0, innerHeaderEnd);
            int innerBodyStart = innerHeaderEnd < 0
                    ? 0
                    : skipBreak(segment, skipBreak(segment, innerHeaderEnd));
            String innerBody = innerHeaderEnd < 0
                    ? ""
                    : segment.substring(Math.min(segment.length(), Math.max(0, innerBodyStart)));

            String innerType = innerHeaderValue(innerHeaders, "content-type");
            if (innerType == null) innerType = "text/plain";

            // Trim the CrLf noise that boundary framing leaves at the start of each segment.
            innerBody = trimLeadingCrlf(innerBody);
            innerHeaders = trimTrailingSpace(innerHeaders);

            walkMime(innerBody, innerType, innerHeaders, m, depth + 1, lim, db, budget);
        }
    }

    /** Case-insensitive single-header lookup inside a nested part's header block. */
    private static String innerHeaderValue(String headers, String name) {
        int i = 0;
        int n = headers.length();
        StringBuilder cur = new StringBuilder();
        String curName = null;
        while (i <= n) {
            int start = i;
            int nl = indexOfBreak(headers, i);
            int end = nl < 0 ? n : nl;
            String line = headers.substring(start, end);
            i = nl < 0 ? n + 1 : advanceBreak(headers, nl);

            if (line.isEmpty()) {
                if (curName != null && curName.equals(name)) return cur.toString().trim();
                curName = null;
                cur.setLength(0);
                continue;
            }
            if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
                if (curName != null) cur.append(' ').append(line.trim());
                continue;
            }
            if (curName != null && curName.equals(name)) return cur.toString().trim();
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            curName = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            cur.setLength(0);
            cur.append(line.substring(colon + 1).trim());
        }
        if (curName != null && curName.equals(name)) return cur.toString().trim();
        return null;
    }

    private static Part decodeLeaf(String body, String headers, String contentType, int depth,
                                   Message m, Limits lim, DecodeBudget db) {
        Part p = new Part();
        p.depth = depth;
        p.contentType = contentType;
        p.contentTypeRaw = contentType;

        String disp = innerHeaderValue(headers, "content-disposition");
        p.disposition = disp;
        String dispLower = disp == null ? "" : disp.trim().toLowerCase(Locale.ROOT);
        p.isAttachment = dispLower.startsWith("attachment");
        p.isInline = dispLower.startsWith("inline");

        p.transferEncoding = transferEncodingOf(headers);
        p.charset = charsetOf(contentType);
        p.filename = filenameOf(headers);
        p.contentId = innerContentIdOf(headers);

        long grant = db.remaining();
        boolean noRoom = grant <= 0 && body != null && !body.isEmpty();
        p.data = decodeTransferEncoding(body, p.transferEncoding, grant, p, m);
        // Reserve what was actually emitted. Reading db.remaining() without consuming it left the
        // ceiling effectively per-part: every part was handed the full 10 MiB grant, so a 12 MiB
        // attachment set decoded in full and nothing was reported. Without this the budget never
        // decreased and DECODED_CONTENT_EXCEEDED could only ever fire on a single oversized part.
        db.take(p.data.length);
        if (noRoom) p.truncated = true;
        // declaredDecodedBytes is a *declared* size only when the decoder actually stopped early.
        // Deriving "truncated" from data.length < estimate was wrong: the base64 estimate ignores
        // "=" padding and the quoted-printable estimate counts soft line breaks ("=\r\n") that
        // decode to nothing, so every padded base64 part and every wrapped QP part looked
        // truncated and emitted a false DECODED_CONTENT_EXCEEDED warning.
        if (!p.truncated) {
            p.declaredDecodedBytes = p.data.length;
        } else {
            m.warn("DECODED_CONTENT_EXCEEDED",
                    "decoded content truncated to the " + lim.maxDecodedBytes + " byte budget");
        }
        return p;
    }

    private static String transferEncodingOf(String headers) {
        String te = innerHeaderValue(headers, "content-transfer-encoding");
        if (te == null) return "7bit";
        int semi = te.indexOf(';');
        String v = (semi < 0 ? te : te.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
        return v.isEmpty() ? "7bit" : v;
    }

    private static String innerContentIdOf(String headers) {
        String cid = innerHeaderValue(headers, "content-id");
        return cid == null ? null : stripBrackets(cid);
    }

    /**
     * Transfer decoding with a hard output grant. The output size is reserved from the decode
     * budget BEFORE the decoder runs, and the input is pre-truncated to what that grant can
     * possibly consume, so no decoder is ever handed input large enough to blow past the cap.
     */
    private static byte[] decodeTransferEncoding(String body, String encoding, long grant,
                                                 Part p, Message m) {
        String enc = encoding == null ? "7bit" : encoding.toLowerCase(Locale.ROOT);

        if (enc.equals("base64")) {
            // 4 chars -> 3 bytes, plus padding slack. Pre-truncate so the decoder's own
            // internal buffer is bounded by the remaining budget.
            long maxChars = (grant / 3 + 4) * 4;
            if (maxChars < 4) {
                p.declaredDecodedBytes = 0;
                return new byte[0];
            }
            String compact = compactBase64(body);
            // Padding-aware estimate: "=" drops output bytes, so naive len/4*3 overstates the
            // decoded size by up to 2 bytes and understates nothing. Counting the pad keeps the
            // declared size honest and the cap comparison exact.
            int pad = 0;
            if (compact.endsWith("==")) pad = 2;
            else if (compact.endsWith("=")) pad = 1;
            p.declaredDecodedBytes = Math.max(0, compact.length() / 4L * 3L - pad);
            if (compact.length() > maxChars) {
                compact = compact.substring(0, (int) (maxChars - (maxChars % 4)));
                p.truncated = true;
            }
            try {
                byte[] out = Base64.getMimeDecoder().decode(compact);
                long allowed = db_grant(grant, out.length);
                if (allowed < out.length) {
                    p.truncated = true;
                    return java.util.Arrays.copyOf(out, (int) allowed);
                }
                return out;
            } catch (IllegalArgumentException e) {
                m.warn("BASE64_DECODE_FAILED", "malformed base64: " + e.getMessage());
                return new byte[0];
            }
        }

        if (enc.equals("quoted-printable")) {
            p.declaredDecodedBytes = body.length();
            ByteArray out = new ByteArray((int) Math.min(grant, body.length()));
            decodeQuotedPrintable(body, out, grant, p);
            return out.toByteArray();
        }

        // 7bit / 8bit / binary / unknown: bytes pass through unchanged.
        p.declaredDecodedBytes = body.length();
        long allowed = db_grant(grant, body.length());
        if (allowed < body.length()) {
            p.truncated = true;
            return body.substring(0, (int) allowed).getBytes(StandardCharsets.ISO_8859_1);
        }
        return body.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static long db_grant(long grant, long requested) {
        return requested < grant ? requested : grant;
    }

    /** Growable byte sink that refuses to exceed its cap. */
    private static final class ByteArray {
        private byte[] buf;
        private int len;

        ByteArray(int initial) {
            this.buf = new byte[Math.max(16, initial)];
        }

        void put(int b) {
            if (len == buf.length) {
                if (len >= Integer.MAX_VALUE / 2) return;
                int n = buf.length * 2;
                buf = java.util.Arrays.copyOf(buf, n);
            }
            buf[len++] = (byte) b;
        }

        int size() {
            return len;
        }

        byte[] toByteArray() {
            return java.util.Arrays.copyOf(buf, len);
        }
    }

    private static void decodeQuotedPrintable(String in, ByteArray out, long cap, Part p) {
        int n = in.length();
        int i = 0;
        while (i < n) {
            if (out.size() >= cap) {
                p.truncated = true;
                return;
            }
            char c = in.charAt(i);
            if (c != '=') {
                out.put(c & 0xFF);
                i++;
                continue;
            }
            // "=" at end of line is a soft break and produces no output.
            if (i + 1 < n && (in.charAt(i + 1) == '\n')) {
                i += 2;
                continue;
            }
            if (i + 2 < n && in.charAt(i + 1) == '\r' && in.charAt(i + 2) == '\n') {
                i += 3;
                continue;
            }
            if (i + 2 < n && isHex(in.charAt(i + 1)) && isHex(in.charAt(i + 2))) {
                out.put((hexVal(in.charAt(i + 1)) << 4) | hexVal(in.charAt(i + 2)));
                i += 3;
                continue;
            }
            out.put('=');
            i++;
        }
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return c - 'a' + 10;
    }

    /** Removes whitespace and non-alphabet characters so a wrapped base64 body decodes cleanly. */
    private static String compactBase64(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=' || isBase64Char(c)) sb.append(c);
        }
        return sb.toString();
    }

    private static boolean isBase64Char(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '+' || c == '/';
    }

    /**
     * Extracts the boundary parameter. Bounded manual scan of quoted or unquoted value; the
     * boundary is attacker-supplied and is used as a literal substring, never as a pattern.
     */
    static String boundaryOf(String contentType) {
        if (contentType == null) return null;
        String lower = contentType.toLowerCase(Locale.ROOT);
        int at = lower.indexOf("boundary=");
        if (at < 0) return null;
        int i = at + "boundary=".length();
        int n = contentType.length();
        if (i >= n) return null;
        StringBuilder sb = new StringBuilder();
        if (contentType.charAt(i) == '"') {
            i++;
            while (i < n) {
                char c = contentType.charAt(i);
                if (c == '\\' && i + 1 < n) {
                    sb.append(contentType.charAt(i + 1));
                    i += 2;
                    continue;
                }
                if (c == '"') break;
                sb.append(c);
                i++;
            }
        } else {
            while (i < n) {
                char c = contentType.charAt(i);
                if (c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
                sb.append(c);
                i++;
            }
        }
        if (sb.length() == 0 || sb.length() > 200) return null;
        return sb.toString();
    }

    static String charsetOf(String contentType) {
        if (contentType == null) return "utf-8";
        String lower = contentType.toLowerCase(Locale.ROOT);
        int at = lower.indexOf("charset=");
        if (at < 0) return "utf-8";
        int i = at + "charset=".length();
        int n = contentType.length();
        if (i < n && contentType.charAt(i) == '"') {
            i++;
            int start = i;
            while (i < n && contentType.charAt(i) != '"') i++;
            return normalizeCharset(contentType.substring(start, i));
        }
        int start = i;
        while (i < n) {
            char c = contentType.charAt(i);
            if (c == ';' || c == ' ' || c == '\t') break;
            i++;
        }
        return normalizeCharset(contentType.substring(start, i));
    }

    /** Only a small allowlist of charsets is honoured; anything else falls back to UTF-8. */
    private static String normalizeCharset(String s) {
        String t = s.trim().toLowerCase(Locale.ROOT).replace("\"", "");
        if (t.isEmpty()) return "utf-8";
        switch (t) {
            case "utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin1", "windows-1252",
                 "windows-1251", "koi8-r", "shift_jis", "iso-2022-jp", "gb2312", "big5",
                 "euc-kr", "iso-8859-15" -> {
                return t;
            }
            default -> {
                return "utf-8";
            }
        }
    }

    static Charset charsetInstance(String name) {
        try {
            return Charset.forName(name);
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    /** Resolves the filename from Content-Disposition, then Content-Type name. */
    static String filenameOf(String partBlock) {
        String disp = innerHeaderValue(partBlock, "content-disposition");
        if (disp != null) {
            String v = dispParam(disp, "filename");
            if (v != null) return v;
            String v2 = dispParam(disp, "filename*");
            if (v2 != null) return v2;
        }
        String ct = innerHeaderValue(partBlock, "content-type");
        if (ct != null) {
            String v = dispParam(ct, "name");
            if (v != null) return v;
        }
        return null;
    }

    /** Reads one parameter value out of a header, quoted or bare, bounded to 256 chars. */
    static String dispParam(String header, String param) {
        if (header == null) return null;
        String needle = param.toLowerCase(Locale.ROOT) + "=";
        String lower = header.toLowerCase(Locale.ROOT);
        int at = lower.indexOf(needle);
        if (at < 0) return null;
        int i = at + needle.length();
        int n = header.length();
        if (i >= n) return null;
        StringBuilder sb = new StringBuilder();
        if (header.charAt(i) == '"') {
            i++;
            while (i < n) {
                char c = header.charAt(i);
                if (c == '\\' && i + 1 < n) {
                    sb.append(header.charAt(i + 1));
                    i += 2;
                    continue;
                }
                if (c == '"') break;
                sb.append(c);
                i++;
            }
        } else {
            while (i < n) {
                char c = header.charAt(i);
                if (c == ';' || c == ' ' || c == '\t') break;
                sb.append(c);
                i++;
            }
        }
        String v = sb.toString().trim();
        if (v.isEmpty() || v.length() > 256) return null;
        return v;
    }

    /**
     * Splits a multipart body on its boundary, returning each segment's content. A boundary must
     * match at the start of a line (optionally after transport padding) so that a boundary
     * string appearing mid-line inside base64 does not split the part. This is a linear scan.
     *
     * The segment immediately before the closing delimiter is emitted, which is the whole point
     * of the structure: returning early on "--boundary--" without flushing the pending segment
     * silently discards the last part of every multipart message, which in a mixed message is
     * usually the attachment the analyst most needs to see.
     */
    static List<String> splitOnBoundary(String body, String boundary) {
        List<String> out = new ArrayList<>();
        String delim = "--" + boundary;
        int n = body.length();
        int pos = 0;
        int segmentStart = -1;
        int guard = 0;

        while (pos < n) {
            if (guard++ > MAX_STORED_PARTS * 4) break;
            int lineStart = pos;
            int nl = indexOfBreak(body, pos);
            int lineEnd = nl < 0 ? n : nl;
            String line = body.substring(lineStart, lineEnd);
            pos = nl < 0 ? n : advanceBreak(body, nl);

            String trimmed = trimTrailingSpace(line);
            if (trimmed.startsWith(delim)) {
                boolean closing = trimmed.length() > delim.length() && trimmed.charAt(delim.length()) == '-';
                if (segmentStart >= 0 && !closing) {
                    out.add(body.substring(segmentStart, lineStart));
                }
                if (closing) {
                    // Flush the final part before the closing delimiter.
                    if (segmentStart >= 0 && lineStart > segmentStart) {
                        out.add(body.substring(segmentStart, lineStart));
                    }
                    return out;
                }
                segmentStart = pos;
            }
        }
        if (segmentStart >= 0) {
            out.add(body.substring(segmentStart));
        }
        return out;
    }

    private static String trimTrailingSpace(String s) {
        int e = s.length();
        while (e > 0 && (s.charAt(e - 1) == ' ' || s.charAt(e - 1) == '\t')) e--;
        return s.substring(0, e);
    }

    private static String trimLeadingCrlf(String s) {
        int i = 0;
        while (i < s.length() && (s.charAt(i) == '\r' || s.charAt(i) == '\n')) i++;
        return s.substring(i);
    }

    // ==================================================================
    // Body / URLs
    // ==================================================================

    private static void buildBodyText(Message m) {
        for (Part p : m.parts) {
            if (p.isContainer) continue;
            String ct = p.contentType.toLowerCase(Locale.ROOT);
            if (ct.startsWith("text/plain")) {
                m.bodyText = new String(p.data, charsetInstance(p.charset));
                return;
            }
        }
        for (Part p : m.parts) {
            if (p.isContainer) continue;
            if (p.contentType.toLowerCase(Locale.ROOT).startsWith("text/")) {
                m.bodyText = new String(p.data, charsetInstance(p.charset));
                return;
            }
        }
    }

    /**
     * Bounded URL extraction. Scans for "http://" / "https://" and consumes the URI by a
     * terminating-delimiter walk, capped per URL and in total. Trims trailing punctuation so a
     * URL at the end of a sentence is not captured with the full stop.
     */
    static void extractUrls(String text, Message m, Budget budget) {
        if (text == null || text.isEmpty()) return;
        int n = text.length();
        int i = 0;
        while (i < n && m.urls.size() < MAX_STORED_URLS) {
            if ((i & 0xFF) == 0 && !budget.ok()) return;
            char c = text.charAt(i);
            if (c != 'h' && c != 'H') {
                i++;
                continue;
            }
            if (!startsWithSchemeAt(text, i, "http://")
                    && !startsWithSchemeAt(text, i, "https://")) {
                i++;
                continue;
            }
            int end = i;
            int limit = Math.min(n, i + 2048);
            while (end < limit && !isUrlTerminator(text.charAt(end))) end++;
            while (end > i && isTrailingPunct(text.charAt(end - 1))) end--;
            String url = text.substring(i, end);
            if (url.length() > "https://".length() + 4 && !m.urls.contains(url)) {
                m.urls.add(url);
            }
            i = Math.max(end, i + 1);
        }
    }

    private static boolean startsWithSchemeAt(String s, int i, String scheme) {
        int n = s.length();
        if (i + scheme.length() > n) return false;
        for (int k = 0; k < scheme.length(); k++) {
            if (Character.toLowerCase(s.charAt(i + k)) != scheme.charAt(k)) return false;
        }
        return true;
    }

    private static boolean isUrlTerminator(char c) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') return true;
        if (c == '"' || c == '\'' || c == '<' || c == '>' || c == '`') return true;
        if (c == ')' || c == ']') return true;
        return c < 32;
    }

    private static boolean isTrailingPunct(char c) {
        return c == '.' || c == ',' || c == ';' || c == ':' || c == '!' || c == '?';
    }

    public static String domainOfUrl(String url) {
        if (url == null) return null;
        int i = url.indexOf("://");
        int start = (i < 0) ? 0 : i + 3;
        if (start >= url.length()) return null;
        int end = start;
        while (end < url.length() && url.charAt(end) != '/' && url.charAt(end) != ':'
                && url.charAt(end) != '?' && url.charAt(end) != '#') end++;
        String host = url.substring(start, end);
        int at = host.lastIndexOf('@');
        if (at >= 0) host = host.substring(at + 1);
        if (host.isEmpty()) return null;
        return host.toLowerCase(Locale.ROOT);
    }

    // ==================================================================
    // Self-test
    // ==================================================================

    public static void main(String[] args) {
        String raw = "Received: from mail.remote.example (unknown [203.0.113.9])\r\n"
                + "\tby mx.corp.example with ESMTPS id abc123\r\n"
                + "\tfor <victim@corp.example>; Mon, 5 Feb 2024 10:11:12 +0000\r\n"
                + "Received: from relay.example (relay.example [10.0.0.4])\r\n"
                + "\tby mx.corp.example; Mon, 5 Feb 2024 10:11:10 +0000\r\n"
                + "Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=a.remote.example; dkim=pass\r\n"
                + "DKIM-Signature: v=1; a=rsa-sha256; d=remote.example; s=sel\r\n"
                + "ARC-Authentication-Results: i=1; mx.corp.example; spf=pass\r\n"
                + "From: \"Remote Sender\" <sender@remote.example>\r\n"
                + "To: victim@corp.example\r\n"
                + "Subject: Quarterly report\r\n"
                + "Date: Mon, 5 Feb 2024 10:11:15 +0000\r\n"
                + "Message-ID: <abc123@remote.example>\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "\r\n"
                + "Body text. Visit https://remote.example/report for details.\r\n";

        Message m = parse(raw);
        System.out.println("subject        : " + m.subject);
        System.out.println("from           : " + (m.from.isEmpty() ? "-" : m.from.get(0)));
        System.out.println("domain         : " + (m.from.isEmpty() ? "-" : m.from.get(0).domain));
        System.out.println("hops           : " + m.hops.size());
        for (ReceivedHop h : m.hops) {
            System.out.println("  " + h + "  ts=" + (h.hasTimestamp() ? h.timestampMillis : "?")
                    + " proto=" + h.protocol + " by=" + h.by + " from=" + h.from
                    + " id=" + h.id + " for=" + h.forClause);
        }
        System.out.println("spf            : " + m.spf.effectiveVerdict()
                + (m.spf.domain == null ? "" : " (" + m.spf.domain + ")"));
        System.out.println("arc headers    : " + m.arcHeaderNames);
        System.out.println("urls           : " + m.urls);
        System.out.println("body           : " + m.bodyText.trim());
        System.out.println("limits         : " + m.limits);
        System.out.println("warnings       : " + m.warningCodes());
        System.out.println("OK EmailParser");
    }
}
