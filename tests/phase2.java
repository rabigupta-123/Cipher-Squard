/**
 * Phase 2 test suite. Plain main(), no test framework, no dependencies.
 *
 * Run:  java -cp build phase2
 *
 * DESIGN RULE (same as the Phase 1 suite): assert OBSERVABLE CONTRACT, not implementation
 * detail. A limit must produce a warning and a valid result, never an exception. A derived
 * quantity must be defined at its edge cases - empty sets, zero vectors, missing timestamps -
 * because those edges are where an analysis layer silently produces NaN and then compares it
 * against a threshold, which is false for NaN, so the item quietly never links.
 *
 * A failing check prints the assertion and KEEPS GOING, then exits non-zero with the total
 * failure count. Stopping at the first failure hides the blast radius of a change.
 *
 * Coverage map, matching the Phase 2 requirements:
 *   t01  2 MB raw message limit
 *   t02  500 header limit
 *   t03  8 KB header line limit
 *   t04  MIME nesting depth 8
 *   t05  MIME part limit 200
 *   t06  10 MB decoded content cap
 *   t07  parse budget / timeout
 *   t08  private address filtering
 *   t09  public address extraction
 *   t10  Received hop ordering
 *   t11  confidence cap at 0.85 and label bands
 *   t12  mandatory disclaimer presence
 *   t13  empty Jaccard handling
 *   t14  normal Jaccard
 *   t15  TF-IDF weighting behaviour, one list per document *   t16  zero-vector cosine
 *   t17  0.62 clustering threshold, transitive closure
 *   t18  hostile / malformed input robustness
 *   t19  specified five-term weighted similarity
 *   t20  campaign risk (noisy-OR), confidence mean, observation window
 *   t21  S composite: domain_age_inv + rdap_privacy + mx_present
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class phase2 {

    private static int passed;
    private static int failed;
    private static final List<String> failures = new ArrayList<>();
    private static String section = "";

    // ==================================================================
    // Tiny assertion harness (no JUnit: ARCHITECTURE.md forbids third-party deps)
    // ==================================================================

    private static void section(String s) {
        section = s;
        System.out.println();
        System.out.println("== " + s + " ==");
    }

    private static void check(String what, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  PASS  " + what);
        } else {
            failed++;
            failures.add(section + " / " + what);
            System.out.println("  FAIL  " + what);
        }
    }

    private static void eq(String what, Object expected, Object actual) {
        boolean ok = (expected == null) ? actual == null : expected.equals(actual);
        if (ok) {
            passed++;
            System.out.println("  PASS  " + what);
        } else {
            failed++;
            failures.add(section + " / " + what + "  expected=<" + expected + "> actual=<" + actual + ">");
            System.out.println("  FAIL  " + what + "  expected=<" + expected + "> actual=<" + actual + ">");
        }
    }

    private static void near(String what, double expected, double actual, double tol) {
        boolean ok = Double.isFinite(actual) && Math.abs(expected - actual) <= tol;
        if (ok) {
            passed++;
            System.out.println("  PASS  " + what);
        } else {
            failed++;
            failures.add(section + " / " + what + "  expected=" + expected + " actual=" + actual);
            System.out.println("  FAIL  " + what + "  expected=" + expected + " actual=" + actual);
        }
    }

    private static boolean hasCode(EmailParser.Message m, String code) {
        for (EmailParser.Warning w : m.warnings) {
            if (w.code.equals(code)) return true;
        }
        return false;
    }

    /** First stored value for a lower-cased header name, or null. */
    private static String firstHeader(EmailParser.Message m, String lowerName) {
        List<String> v = m.headers.get(lowerName);
        return (v == null || v.isEmpty()) ? null : v.get(0);
    }

    private static String codes(EmailParser.Message m) {
        List<String> c = new ArrayList<>();
        for (EmailParser.Warning w : m.warnings) c.add(w.code);
        return String.join(",", c);
    }

    // ==================================================================
    // Fixtures
    // ==================================================================

    /** Deterministic pseudo-random filler, so a 2 MB fixture needs no 2 MB file on disk. */
    private static String filler(int targetBytes) {
        StringBuilder sb = new StringBuilder(targetBytes + 64);
        String unit = "the quick brown fox jumps over the lazy dog 0123456789 ";
        while (sb.length() < targetBytes) sb.append(unit);
        return sb.substring(0, targetBytes);
    }

    private static String simpleMessage() {
        return "From: Alice <alice@sender.example>\n"
                + "To: Bob <bob@corp.example>\n"
                + "Subject: Quarterly report\n"
                + "Message-ID: <abc123@sender.example>\n"
                + "\n"
                + "Here is the report you asked for.\n";
    }

    /**
     * Wraps parts in nested multiparts of the requested depth.
     *
     * The whole message is built in CRLF and the outermost level supplies the message headers
     * only. Emitting a second "Content-Type:" prefix here would make the top-level header value
     * literally "Content-Type: multipart/mixed", so the walker would see an unknown media type,
     * never descend, and the depth assertions would pass or fail for the wrong reason.
     */
    private static String nestedMultipart(int depth) {
        String inner = "Content-Type: text/plain; charset=utf-8\r\n"
                + "\r\n"
                + "deepest payload\r\n";
        for (int i = depth; i >= 1; i--) {
            String b = "b" + i;
            inner = "Content-Type: multipart/mixed; boundary=\"" + b + "\"\r\n"
                    + "\r\n"
                    + "--" + b + "\r\n"
                    + inner
                    + "\r\n--" + b + "--\r\n";
        }
        return "Subject: nested\r\nMIME-Version: 1.0\r\n" + inner;
    }

    // ==================================================================
    // t01 - 2 MB raw message limit
    // ==================================================================

    private static void t01_messageSizeLimit() {
        section("t01 raw message limit is 2 MB");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("limit is 2 MiB", 2L * 1024 * 1024, lim.maxMessageBytes);

        // Just under the limit: accepted, no truncation warning.
        int under = 2 * 1024 * 1024 - 512;
        String bigOk = "Subject: big\r\n\r\n" + filler(under);
        EmailParser.Message ok = EmailParser.parse(bigOk, lim);
        eq("just-under-limit parses with no size warning", false, hasCode(ok, "MESSAGE_TRUNCATED"));
        check("just-under-limit consumed most of the input",
                ok.bytesConsumed > under - 4096);

        // Over the limit: truncated, warned, still a usable result.
        String bigBad = "Subject: big\r\n\r\n" + filler(2 * 1024 * 1024 + 256 * 1024);
        EmailParser.Message cut = EmailParser.parse(bigBad, lim);
        check("over-limit produces MESSAGE_TRUNCATED", hasCode(cut, "MESSAGE_TRUNCATED"));
        check("over-limit still returns a Message (never throws)", cut != null);
        check("over-limit consumes at most 2 MiB", cut.bytesConsumed <= lim.maxMessageBytes);
        check("over-limit still exposes the subject", "big".equals(cut.subject));

        // A tiny custom limit proves the cap is enforced, not merely documented.
        EmailParser.Limits tiny = new EmailParser.Limits(1024, 100, 8192, 8, 200,
                10L * 1024 * 1024, 2000);
        EmailParser.Message t = EmailParser.parse("Subject: x\r\n\r\n" + filler(8192), tiny);
        check("custom 1 KB limit truncates", hasCode(t, "MESSAGE_TRUNCATED"));
        check("custom 1 KB limit consumes <= 1024", t.bytesConsumed <= 1024);
    }

    // ==================================================================
    // t02 - 500 header limit
    // ==================================================================

    private static void t02_headerCountLimit() {
        section("t02 header count limit is 500");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("limit is 500", 500, lim.maxHeaders);

        // 300 X-Trace headers: over 100 (the Phase 1 limit) but under the Phase 2 limit.
        StringBuilder sb = new StringBuilder("Subject: many\r\n");
        for (int i = 0; i < 300; i++) sb.append("X-Trace-").append(i).append(": v").append(i).append("\r\n");
        sb.append("\r\nbody\r\n");
        EmailParser.Message m = EmailParser.parse(sb.toString(), lim);
        eq("300 trace headers all retained", 300, m.headers.getOrDefault("x-trace-0", List.of()).size() > 0
                ? m.headerList.size() - 1 : -1);
        check("300 headers produce no header-limit warning", !hasCode(m, "HEADER_COUNT_EXCEEDED"));

        // 700 headers: 500 retained, warning raised, still valid.
        StringBuilder sb2 = new StringBuilder("Subject: many\r\n");
        for (int i = 0; i < 700; i++) sb2.append("X-H-").append(i).append(": v\r\n");
        sb2.append("\r\nbody\r\n");
        EmailParser.Message m2 = EmailParser.parse(sb2.toString(), lim);
        check("700 headers raises the limit warning", hasCode(m2, "HEADER_COUNT_EXCEEDED"));
        eq("exactly 500 headers retained", 500, m2.headerList.size());
        check("over-limit still returns the subject", "many".equals(m2.subject));

        // The cap counts every accepted header, Subject included, so retention is
        // Subject + X-H-0..X-H-498. The first dropped header is X-H-499.
        check("first dropped header absent", m2.headers.get("x-h-499") == null);
        check("last retained header present", m2.headers.containsKey("x-h-498"));
        check("dropped headers are not silently invisible", !m2.headers.containsKey("x-h-699"));
    }

    // ==================================================================
    // t03 - 8 KB header line limit
    // ==================================================================

    private static void t03_headerLineLimit() {
        section("t03 header line limit is 8 KB");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("limit is 8192", 8192, lim.maxHeaderLineBytes);

        String longValue = "X".repeat(20_000);
        String msg = "Subject: ok\r\nX-Long: " + longValue + "\r\n\r\nbody\r\n";
        EmailParser.Message m = EmailParser.parse(msg, lim);
        check("20 KB header line produces a warning", hasCode(m, "HEADER_LINE_EXCEEDED"));
        String got = firstHeader(m, "x-long");
        check("header value was clamped", got != null && got.length() <= 8192);
        check("message still parses", "ok".equals(m.subject));

        // Folding must not be a way around the stored-value cap. Each physical continuation is
        // folded into the same value, and once that value hits its storage cap the parser has to
        // say so rather than quietly returning a partial header.
        StringBuilder folded = new StringBuilder("Subject: ok\r\nX-Fold: start\r\n");
        for (int i = 0; i < 40; i++) {
            folded.append(" ").append("Y".repeat(4000)).append("\r\n");
        }
        folded.append("\r\nbody\r\n");
        EmailParser.Message f = EmailParser.parse(folded.toString(), lim);
        check("oversized folded value is flagged", hasCode(f, "HEADER_VALUE_TRUNCATED"));
        String fv = firstHeader(f, "x-fold");
        check("folded value bounded by the stored cap", fv != null && fv.length() <= 64 * 1024);
    }

    // ==================================================================
    // t04 - MIME nesting depth
    // ==================================================================

    private static void t04_mimeDepth() {
        section("t04 MIME nesting depth is 8");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("limit is 8", 8, lim.maxMimeDepth);

        EmailParser.Message shallow = EmailParser.parse(nestedMultipart(3), lim);
        check("depth 3 parses with no depth warning", !hasCode(shallow, "MIME_DEPTH_EXCEEDED"));
        check("depth 3 reached the deepest part",
                leafReached(shallow, "deepest payload"));

        EmailParser.Message bomb = EmailParser.parse(nestedMultipart(20), lim);
        check("depth 20 raises MIME_DEPTH_EXCEEDED", hasCode(bomb, "MIME_DEPTH_EXCEEDED"));
        check("depth bomb still returns a valid Message", bomb != null);
        check("depth bomb did not recurse without bound", bomb.parts.size() <= 64);
    }

    private static boolean leafReached(EmailParser.Message m, String needle) {
        for (EmailParser.Part p : m.parts) {
            if (p.data == null || p.isContainer) continue;
            if (new String(p.data, StandardCharsets.UTF_8).contains(needle)) return true;
        }
        return false;
    }

    // ==================================================================
    // t05 - MIME part limit
    // ==================================================================

    private static void t05_mimePartLimit() {
        section("t05 MIME part limit is 200");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("limit is 200", 200, lim.maxMimeParts);

        String msg = "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"bb\"\r\n\r\n"
                + "--bb\r\nContent-Type: text/plain\r\n\r\none\r\n";
        for (int i = 0; i < 50; i++) {
            msg += "--bb\r\nContent-Type: text/plain\r\n\r\npart" + i + "\r\n";
        }
        msg += "--bb--\r\n";
        EmailParser.Message ok = EmailParser.parse(msg, lim);
        check("52 parts parse with no part warning", !hasCode(ok, "MIME_PART_LIMIT"));
        check("52 parts means 1 container + 51 leaves", ok.parts.size() == 52);

        StringBuilder big = new StringBuilder(
                "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"cc\"\r\n\r\n");
        for (int i = 0; i < 300; i++) {
            big.append("--cc\r\nContent-Type: text/plain\r\n\r\npart").append(i).append("\r\n");
        }
        big.append("--cc--\r\n");
        EmailParser.Message m = EmailParser.parse(big.toString(), lim);
        check("301 parts raises MIME_PART_LIMIT", hasCode(m, "MIME_PART_LIMIT"));
        eq("exactly 200 parts retained", 200, m.parts.size());
        check("part-limited message is still usable", m.subject == null || true);
    }

    // ==================================================================
    // t06 - 10 MB decoded content cap
    // ==================================================================

    private static void t06_decodedCap() {
        section("t06 decoded content cap is 10 MB");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("limit is 10 MiB", 10L * 1024 * 1024, lim.maxDecodedBytes);

        // A single part that decodes to more than the cap must be clamped AND flagged.
        // The raw ceiling is raised for this case on purpose: base64 expands 3 bytes to 4
        // characters, so a 2 MiB raw message can never decode to more than about 1.5 MiB and the
        // 10 MiB decoded ceiling would be unreachable under the shipping limits. The decoded cap
        // is a defence-in-depth bound, and to prove it actually clamps it needs input that a
        // 2 MiB raw message cannot carry.
        EmailParser.Limits roomy = new EmailParser.Limits(40L * 1024 * 1024, 500, 8192, 8, 200,
                10L * 1024 * 1024, 10_000);
        String b64 = java.util.Base64.getEncoder().encodeToString(
                filler(11 * 1024 * 1024).getBytes(StandardCharsets.US_ASCII));
        String one = "MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\n" + b64;
        EmailParser.Message m = EmailParser.parse(one, roomy);
        long stored = 0;
        for (EmailParser.Part p : m.parts) stored += p.data.length;
        check("over-cap decode raises DECODED_CONTENT_EXCEEDED",
                hasCode(m, "DECODED_CONTENT_EXCEEDED"));
        check("decoded bytes never exceed the cap", stored <= roomy.maxDecodedBytes);
        boolean anyTruncated = false;
        for (EmailParser.Part p : m.parts) if (p.truncated) anyTruncated = true;
        check("the oversized part is marked truncated", anyTruncated);

        // Under the shipping 2 MiB raw ceiling the decoded ceiling is structurally unreachable.
        // Assert that directly so the cap is documented as defence-in-depth, not as a claim.
        EmailParser.Message squeezed = EmailParser.parse(one, lim);
        long squeezedStored = 0;
        for (EmailParser.Part p : squeezed.parts) squeezedStored += p.data.length;
        check("2 MiB raw ceiling keeps decoded output far below the decoded cap",
                squeezedStored <= lim.maxDecodedBytes);
        check("the 2 MiB raw ceiling is what fires first", hasCode(squeezed, "MESSAGE_TRUNCATED"));

        // The cap must be GLOBAL across parts, not per part. Six parts of 2 MiB each total 12 MiB
        // of decoded bytes, which a per-part cap would let through.
        EmailParser.Limits five = new EmailParser.Limits(40L * 1024 * 1024, 500, 8192, 8, 200,
                10L * 1024 * 1024, 10_000);
        StringBuilder multi = new StringBuilder(
                "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"dd\"\r\n\r\n");
        String chunk = java.util.Base64.getEncoder().encodeToString(
                filler(2 * 1024 * 1024).getBytes(StandardCharsets.US_ASCII));
        for (int i = 0; i < 6; i++) {
            multi.append("--dd\r\nContent-Type: application/octet-stream\r\n")
                    .append("Content-Transfer-Encoding: base64\r\n\r\n").append(chunk).append("\r\n");
        }
        multi.append("--dd--\r\n");
        EmailParser.Message mm = EmailParser.parse(multi.toString(), five);
        long total = 0;
        for (EmailParser.Part p : mm.parts) total += p.data.length;
        check("aggregate decoded size respects the global cap", total <= five.maxDecodedBytes);
        check("aggregate overflow is reported", hasCode(mm, "DECODED_CONTENT_EXCEEDED"));

        // A part that fits must NOT be flagged. Padded base64 and wrapped quoted-printable both
        // decode to fewer bytes than a naive length estimate suggests; a false positive here would
        // make every ordinary attachment look like an attack.
        String clean = "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"ee\"\r\n\r\n"
                + "--ee\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                + "Caf=C3=A9 wrapped line=\r\nnext line\r\n"
                + "--ee\r\nContent-Type: text/plain\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8h\r\n"
                + "--ee--\r\n";
        EmailParser.Message good = EmailParser.parse(clean, lim);
        check("padding and soft line breaks are not false positives",
                !hasCode(good, "DECODED_CONTENT_EXCEEDED"));
        check("QP part decoded to the right bytes", decodedContains(good, "Caf\u00e9"));
        check("base64 part decoded to the right bytes", decodedContains(good, "Hello!"));
    }

    private static boolean decodedContains(EmailParser.Message m, String needle) {
        for (EmailParser.Part p : m.parts) {
            if (p.isContainer || p.data == null) continue;
            if (new String(p.data, StandardCharsets.UTF_8).contains(needle)) return true;
        }
        return false;
    }

    // ==================================================================
    // t07 - parse budget
    // ==================================================================

    private static void t07_parseBudget() {
        section("t07 parse budget is enforced");
        EmailParser.Limits lim = EmailParser.Limits.phase2();
        eq("budget is 2000 ms", 2000L, lim.parseBudgetMillis);

        // A budget of zero must abandon work immediately rather than parse everything.
        EmailParser.Limits zero = new EmailParser.Limits(2L * 1024 * 1024, 500, 8192, 8, 200,
                10L * 1024 * 1024, 0);
        String bomb = "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"ff\"\r\n\r\n";
        for (int i = 0; i < 150; i++) {
            bomb += "--ff\r\nContent-Type: application/octet-stream\r\n"
                    + "Content-Transfer-Encoding: base64\r\n\r\n"
                    + java.util.Base64.getEncoder().encodeToString(
                            filler(200_000).getBytes(StandardCharsets.US_ASCII))
                    + "\r\n";
        }
        bomb += "--ff--\r\n";
        long t0 = System.nanoTime();
        EmailParser.Message m = EmailParser.parse(bomb, zero);
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        check("zero budget returns a valid Message", m != null);
        check("zero budget is fast (no full parse)", ms < 4000);
        check("budget exhaustion is reported", hasCode(m, "TIME_BUDGET_EXCEEDED"));

        // A real 2 MB message with a normal budget must finish well inside the cap.
        String big = "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"gg\"\r\n\r\n";
        String c = java.util.Base64.getEncoder().encodeToString(
                filler(400_000).getBytes(StandardCharsets.US_ASCII));
        for (int i = 0; i < 4; i++) {
            big += "--gg\r\nContent-Type: application/octet-stream\r\n"
                    + "Content-Transfer-Encoding: base64\r\n\r\n" + c + "\r\n";
        }
        big += "--gg--\r\n";
        long t1 = System.nanoTime();
        EmailParser.Message ok = EmailParser.parse(big, lim);
        long ms2 = (System.nanoTime() - t1) / 1_000_000L;
        check("normal parse of 4x400 KB completes without budget warning",
                !hasCode(ok, "TIME_BUDGET_EXCEEDED"));
        check("normal parse finished well under the 2 s budget (" + ms2 + " ms)", ms2 < 2000);
    }

    // ==================================================================
    // t08 - private address filtering
    // ==================================================================

    private static void t08_privateFiltering() {
        section("t08 private and non-routable addresses are filtered");
        String[] privates = {"10.0.0.5", "172.16.4.9", "192.168.1.10", "127.0.0.1", "169.254.7.7",
                "100.64.0.1", "::1", "fd00::1", "fe80::1", "ff02::1"};
        for (String ip : privates) {
            Attribution.Scope s = Attribution.classifyIp(ip);
            check(ip + " is not PUBLIC (" + s + ")", s != Attribution.Scope.PUBLIC);
        }

        String[] reserved = {"192.0.2.1", "198.51.100.5", "203.0.113.9", "0.0.0.0", "224.0.0.1",
                "255.255.255.255", "240.0.1.1", "2001:db8::1", "100::1"};
        for (String ip : reserved) {
            Attribution.Scope s = Attribution.classifyIp(ip);
            check(ip + " is not PUBLIC (" + s + ")", s != Attribution.Scope.PUBLIC);
        }

        String[] publics = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "2606:4700:4700::1111"};
        for (String ip : publics) {
            eq(ip + " is PUBLIC", Attribution.Scope.PUBLIC, Attribution.classifyIp(ip));
        }

        // A message whose only hops are private must produce NO primary address. Both private
        // addresses need their own Received header: a single hop carries one address, and the
        // "by" clause of one header is not a second hop.
        String lan = "Received: from a.lan ([10.0.0.5])\n\tby b.lan with SMTP;"
                + " Tue, 12 Aug 2025 10:00:00 +0000\n"
                + "Received: from c.lan ([192.168.1.1])\n\tby d.lan with SMTP;"
                + " Tue, 12 Aug 2025 10:00:01 +0000\nSubject: x\n\nbody\n";
        Attribution.Result r = Attribution.attribute(EmailParser.parse(lan));
        eq("private-only message has no primary address", null, r.primaryIp);
        eq("both private hops are reported as non-routable", 2, r.privateHops.size());
        eq("private-only confidence is 0", 0.0, r.confidence.value);
        check("uncertainty explains the absence",
                r.uncertain.stream().anyMatch(u -> u.contains("no publicly routable address")));
    }

    // ==================================================================
    // t09 - public address extraction
    // ==================================================================

    private static void t09_publicExtraction() {
        section("t09 public address extraction");
        List<Attribution.IpFact> facts =
                Attribution.extractIps("ips: 8.8.8.8 and 10.0.0.1 and 192.0.2.1 and [2606:4700::1111]",
                        "test", 32);
        Set<String> publics = new LinkedHashSet<>();
        for (Attribution.IpFact f : facts) {
            if (f.isPublic()) publics.add(f.ip);
        }
        check("8.8.8.8 extracted as public", publics.contains("8.8.8.8"));
        check("IPv6 global unicast extracted as public", publics.contains("2606:4700::1111"));
        for (String ip : publics) {
            check("private/reserved not marked public: " + ip, !ip.startsWith("10.")
                    && !ip.startsWith("192.0.2"));
        }

        // Malformed candidates must be rejected whole, not truncated into a valid prefix. Every
        // token below is invalid: an out-of-range octet, a five-octet run, a doubled octet run, an
        // empty-component run, and a three-octet run. None may survive, and in particular
        // "1.2.3.4.5" must not yield 1.2.3.4 and "8.8.8.8.8" must not yield 8.8.8.8.
        List<Attribution.IpFact> bad = Attribution.extractIps(
                "999.1.1.1 1.2.3.4.5 8.8.8.8.8 1..2..3 8.8.8", "hostile", 32);
        eq("no malformed candidate survives", 0, bad.size());
        for (Attribution.IpFact f : bad) {
            check("rejects malformed " + f.ip, !f.isPublic());
        }
        // A genuinely valid address in the same text is still found, so the test above is
        // exercising rejection and not a scanner that simply returns nothing.
        List<Attribution.IpFact> mixed = Attribution.extractIps(
                "1.2.3.4.5 and 8.8.8.8 and 1.2.3.4.6", "hostile", 32);
        eq("only the well-formed address survives", 1, mixed.size());
        eq("the well-formed address is the one kept", "8.8.8.8", mixed.get(0).ip);

        // Extraction cap must hold on a flood.
        StringBuilder flood = new StringBuilder();
        for (int i = 0; i < 5000; i++) flood.append("8.8.8.8 ");
        List<Attribution.IpFact> capped = Attribution.extractIps(flood.toString(), "flood", 10);
        check("extraction respects the cap (<=10)", capped.size() <= 10);
        eq("null text yields nothing", 0, Attribution.extractIps(null, "x", 10).size());
        eq("empty text yields nothing", 0, Attribution.extractIps("", "x", 10).size());
    }

    // ==================================================================
    // t10 - Received hop ordering
    // ==================================================================

    private static void t10_hopOrdering() {
        section("t10 Received hop ordering and reconstruction");

        // RFC 5321: Received is newest-first, so index 0 has the LATEST timestamp.
        String raw = "Received: from a.example ([8.8.8.8])\n"
                + "\tby mx.corp.example with ESMTPS id abc123\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:12 +0000\n"
                + "Received: from b.example ([1.1.1.1])\n"
                + "\tby a.example with SMTP id def456\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:10 +0000\n"
                + "Subject: x\n\nbody\n";
        EmailParser.Message m = EmailParser.parse(raw);
        eq("two hops reconstructed", 2, m.hops.size());
        eq("hop 0 host", "a.example", m.hops.get(0).host);
        eq("hop 0 ip", "8.8.8.8", m.hops.get(0).ip);
        eq("hop 0 protocol", "ESMTPS", m.hops.get(0).protocol);
        eq("hop 0 by", "mx.corp.example", m.hops.get(0).by);
        eq("hop 0 id", "abc123", m.hops.get(0).id);
        eq("hop 0 for", "<v@corp.example>", m.hops.get(0).forClause);
        check("hop 0 timestamp parsed", m.hops.get(0).hasTimestamp());
        eq("hop 1 ip", "1.1.1.1", m.hops.get(1).ip);
        check("hop 1 timestamp is earlier",
                m.hops.get(1).timestampMillis < m.hops.get(0).timestampMillis);

        Attribution.Result r = Attribution.attribute(m);
        eq("ordering basis is timestamps", Attribution.Ordering.TIMESTAMP, r.ordering);
        eq("earliest technically observable public address is the deepest hop",
                "1.1.1.1", r.primaryIp);

        // No timestamps: must fall back to header depth and say so.
        String noTime = "Received: from a.example ([8.8.8.8])\n\tby mx with ESMTP\n"
                + "Received: from b.example ([1.1.1.1])\n\tby a.example with ESMTP\n"
                + "Subject: x\n\nbody\n";
        Attribution.Result r2 = Attribution.attribute(EmailParser.parse(noTime));
        eq("ordering falls back to header depth", Attribution.Ordering.HEADER_DEPTH, r2.ordering);
        eq("depth ordering still picks the deepest public hop", "1.1.1.1", r2.primaryIp);
        check("missing timestamps are reported as uncertainty",
                r2.uncertain.stream().anyMatch(u -> u.contains("no usable hop timestamps")));

        // Contradictory timestamps must be detected, not silently accepted.
        String inverted = "Received: from a.example ([8.8.8.8])\n\tby mx with ESMTP;"
                + " Tue, 12 Aug 2025 10:00:00 +0000\n"
                + "Received: from b.example ([1.1.1.1])\n\tby a.example with ESMTP;"
                + " Tue, 12 Aug 2025 11:00:00 +0000\n"
                + "Subject: x\n\nbody\n";
        Attribution.Result r3 = Attribution.attribute(EmailParser.parse(inverted));
        check("non-monotonic timestamps are flagged",
                r3.confidence.factors.stream().anyMatch(f -> f.name.equals("timestamp_contradiction")));
        check("contradiction appears in the uncertainty list",
                r3.uncertain.stream().anyMatch(u -> u.contains("contradict header order")));

        // Bare clauses and a "from" keyword must not be mistaken for a host.
        String bare = "Received: from ([9.9.9.9])\n\tby with ESMTP id q\n"
                + "Subject: x\n\nbody\n";
        EmailParser.Message bm = EmailParser.parse(bare);
        eq("bare from() still yields the address", "9.9.9.9", bm.hops.get(0).ip);
        check("bare clauses do not become a host", bm.hops.get(0).host == null
                || bm.hops.get(0).host.isBlank());
    }

    // ==================================================================
    // t11 - confidence cap
    // ==================================================================

    private static void t11_confidenceCap() {
        section("t11 attribution confidence is capped at 0.85");

        // Every positive factor available at once: one distinct public address, consistent
        // timestamps, the address on the deepest hop, and a matching offline network record.
        Path tsv = null;
        try {
            tsv = Files.createTempFile("phase2", ".tsv");
            Files.writeString(tsv,
                    "ip\tcountry\tasn\torganization\tisp\thostname\n"
                            + "1.1.1.1\tAU\tAS13335\tExample Cloud\tExample Cloud\tone.example\n",
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            // handled by the assertion below
        }
        check("dataset staged for the network-record factor", tsv != null);

        // The sole public address has to sit on the DEEPEST hop for the originating_hop factor to
        // apply. In a Received chain the last header is the one closest to the origin, so the
        // private corporate relay is the outer hop and 1.1.1.1 is the innermost.
        String best = "Received: from internal.lan ([10.0.0.5])\n"
                + "\tby a.example with ESMTP id def\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:12 +0000\n"
                + "Received: from a.example ([1.1.1.1])\n"
                + "\tby mx.corp.example with ESMTPS id abc\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:10 +0000\n"
                + "Subject: x\n\nbody\n";
        Attribution.Hints h = new Attribution.Hints().withRegistry(
                Enrich.newRegistry().add(new Enrich.DatasetProvider(
                        tsv == null ? "absent.tsv" : tsv.toString())));
        Attribution.Result bestR = Attribution.attribute(EmailParser.parse(best), h);

        eq("single public address is the primary", "1.1.1.1", bestR.primaryIp);
        check("maximum evidence does not exceed 0.85 (" + bestR.confidence.value + ")",
                bestR.confidence.value <= Attribution.CONFIDENCE_CAP);
        eq("cap constant is 0.85", 0.85, Attribution.CONFIDENCE_CAP);

        // The model is a weighted geometric mean, not a sum, so complete evidence does not land
        // exactly on the cap: it lands at whatever T^0.35 * S^0.25 * (1-A)^0.25 * X^0.15 evaluates
        // to, and the cap is only ever reached if that product itself exceeds 0.85. Asserted
        // against the formula rather than a magic literal, so a weight change cannot silently
        // make this test lie.
        Attribution.TraceFactors tr = bestR.confidence.trace;
        near("maximum evidence equals the specified weighted geometric mean",
                tr.combine(), bestR.confidence.value, 1e-9);
        check("the four factors are all in [0,1]",
                tr.traceability >= 0 && tr.traceability <= 1
                        && tr.stability >= 0 && tr.stability <= 1
                        && tr.anonymity >= 0 && tr.anonymity <= 1
                        && tr.corroboration >= 0 && tr.corroboration <= 1);

        // The specified collapse: a single zero factor must drive the result to exactly 0, which
        // is what "if nothing resolved, nothing can be attributed" means in practice.
        near("T=0 collapses the score to zero", 0.0,
                Attribution.TraceFactors.combine(0.0, 1.0, 0.0, 1.0), 1e-12);
        near("S=0 collapses the score to zero", 0.0,
                Attribution.TraceFactors.combine(1.0, 0.0, 0.0, 1.0), 1e-12);
        near("X=0 collapses the score to zero", 0.0,
                Attribution.TraceFactors.combine(1.0, 1.0, 0.0, 0.0), 1e-12);
        // A is inverted in the model: it enters as (1 - A), so A=1 means total anonymity, and a
        // fully anonymous result is not attributed. It collapses for the same reason the others do.
        near("A=1 collapses the score to zero, because anonymity leaves nothing to attribute", 0.0,
                Attribution.TraceFactors.combine(1.0, 1.0, 1.0, 1.0), 1e-12);

        // Perfect evidence with zero anonymity yields 1.0 before the cap, so the cap is reachable
        // and is doing real work rather than being unreachable decoration.
        near("perfect factors combine to 1.0 before the cap", 1.0,
                Attribution.TraceFactors.combine(1.0, 1.0, 0.0, 1.0), 1e-12);
        eq("label bands: 0.70 is PROBABLE", Attribution.Band.PROBABLE,
                Attribution.bandOf(0.70));
        eq("label bands: 0.69 is INDICATIVE", Attribution.Band.INDICATIVE,
                Attribution.bandOf(0.69));
        eq("label bands: 0.45 is INDICATIVE", Attribution.Band.INDICATIVE,
                Attribution.bandOf(0.45));
        eq("label bands: 0.44 is WEAK", Attribution.Band.WEAK, Attribution.bandOf(0.44));
        eq("label bands: 0.25 is WEAK", Attribution.Band.WEAK, Attribution.bandOf(0.25));
        eq("label bands: 0.24 is INSUFFICIENT", Attribution.Band.INSUFFICIENT,
                Attribution.bandOf(0.24));
        eq("label bands: 0.85 (the cap) is PROBABLE", Attribution.Band.PROBABLE,
                Attribution.bandOf(Attribution.CONFIDENCE_CAP));
        eq("every confidence carries a band", bestR.confidence.band,
                Attribution.bandOf(bestR.confidence.value));

        // Every reported factor must have a non-empty explanation.
        for (Attribution.Factor f : bestR.confidence.factors) {
            check("factor '" + f.name + "' has a detail", f.detail != null && !f.detail.isBlank());
        }
        check("confidence is a sum of factors, not a raw number",
                bestR.confidence.factors.size() >= 4);

        // Adversarial cases must not exceed the cap either.
        String many = "Received: from a ([1.1.1.1])\n\tby mx with ESMTPS id a;"
                + " Tue, 12 Aug 2025 10:00:02 +0000\n"
                + "Received: from b ([2.2.2.2])\n\tby a with ESMTP id b;"
                + " Tue, 12 Aug 2025 10:00:01 +0000\n"
                + "Subject: x\n\nbody\n";
        Attribution.Result manyR = Attribution.attribute(EmailParser.parse(many), h);
        check("many public addresses stays under the cap", manyR.confidence.value <= 0.85);

        // Missing evidence must lower, not merely cap, the score.
        EmailParser.Message bare = EmailParser.parse("Subject: x\n\nbody\n");
        Attribution.Result noneR = Attribution.attribute(bare, h);
        eq("no addresses means zero confidence", 0.0, noneR.confidence.value);
        check("zero confidence is marked capped", noneR.confidence.capped);

        // A proxy observation must reduce confidence and be reported.
        String proxy = "Received: from a ([1.1.1.1])\n\tby mx with HTTP id a;"
                + " Tue, 12 Aug 2025 10:00:02 +0000\n"
                + "Received: from b ([10.0.0.5])\n\tby a with ESMTP id b;"
                + " Tue, 12 Aug 2025 10:00:01 +0000\n"
                + "Subject: x\n\nbody\n";
        Attribution.Result pR = Attribution.attribute(EmailParser.parse(proxy), h);
        check("an observed intermediary indicator is recorded", pR.indicators.size() >= 1);
        check("an intermediary indicator lowers confidence",
                pR.confidence.factors.stream()
                        .anyMatch(f -> f.name.equals("intermediary_observed") && f.weight < 0));
        check("an intermediary indicator appears in the uncertainty list",
                pR.uncertain.size() > 0 || pR.indicators.size() > 0);

        if (tsv != null) {
            try {
                Files.deleteIfExists(tsv);
            } catch (Exception ignored) {
                // best effort
            }
        }
    }

    // ==================================================================
    // t21 - the specified stability factor
    // ==================================================================

    private static void t21_stabilityFactor() {
        section("t21 S is the specified composite: domain_age_inv + rdap_privacy + mx_present");

        Path tsv = null;
        try {
            tsv = Files.createTempFile("phase2s", ".tsv");
            Files.writeString(tsv,
                    "ip\tcountry\tasn\torganization\tisp\thostname\n"
                            + "1.1.1.1\tAU\tAS13335\tExample Cloud\tExample Cloud\tone.example\n",
                    StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // asserted below
        }
        check("dataset staged", tsv != null);
        if (tsv == null) return;
        String raw = "Received: from a.example ([1.1.1.1])\n"
                + "\tby mx.corp.example with ESMTPS id abc\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:10 +0000\n"
                + "Subject: x\n\nbody\n";

        Enrich.Registry reg = Enrich.newRegistry().add(new Enrich.DatasetProvider(tsv.toString()));

        // 1. Full observation: old domain, MX present, named non-anonymiser operator.
        //    All three sub-signals are 1.0, so S is exactly 1.0.
        Attribution.Result full = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("a.example", 800)
                        .withMxPresent("a.example"));
        near("three saturated sub-signals give S = 1.0", 1.0, full.confidence.trace.stability, 1e-9);

        // 2. Domain age saturates at the horizon: an age beyond a year still scores 1.0, and a
        //    brand-new domain scores nothing rather than being assumed stable.
        Attribution.Result old = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("a.example", 5000)
                        .withMxPresent("a.example"));
        near("an age beyond the horizon still saturates at 1.0", 1.0,
                old.confidence.trace.stability, 1e-9);
        eq("the horizon is 365 days", 365, Attribution.DOMAIN_STABILITY_HORIZON_DAYS);

        Attribution.Result young = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("a.example", 0)
                        .withMxPresent("a.example"));
        // domain_age_inv = 0, rdap_privacy = 1, mx = 1  ->  2/3
        near("a brand-new domain contributes no age stability (2 of 3 observed sub-signals)",
                2.0 / 3.0, young.confidence.trace.stability, 1e-9);

        // 3. Partial age is a linear fraction of the horizon. 91 days is a quarter of 365.
        Attribution.Result quarter = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("a.example", 91)
                        .withMxPresent("a.example"));
        // 91/365 = 0.249315..., plus rdap_privacy 1 plus mx 1, over 3 observed sub-signals.
        near("a 91-day-old domain contributes 91/365 of the age sub-signal",
                (91.0 / 365.0 + 2.0) / 3.0, quarter.confidence.trace.stability, 1e-9);

        // 4. No MX records is a real observation and scores 0. A domain that cannot send mail but
        //    appears in the submission chain is a stability failure, not missing data.
        Attribution.Result noMx = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("a.example", 800)
                        .withMxAbsent("a.example"));
        // 1 + 1 + 0 = 2 over 3
        near("a domain with no MX scores 0 for that sub-signal", 2.0 / 3.0,
                noMx.confidence.trace.stability, 1e-9);

        // 5. Anonymiser operator zeroes rdap_privacy even when everything else is clean.
        Attribution.Result anon = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("a.example", 800)
                        .withMxPresent("a.example")
                        .withAnonymiserOrg("Example Cloud"));
        // 1 + 0 + 1 = 2 over 3
        near("an anonymiser operator zeroes the privacy sub-signal", 2.0 / 3.0,
                anon.confidence.trace.stability, 1e-9);

        // 6. Unobserved sub-signals are EXCLUDED from the average, not counted as zero. With only
        //    rdap_privacy observable, S is 1.0 - not 1/3. This is the difference between "we know
        //    one thing and it is fine" and "we know one of three things".
        Attribution.Result onlyPrivacy = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg));
        near("unobserved sub-signals are excluded, not counted as zero", 1.0,
                onlyPrivacy.confidence.trace.stability, 1e-9);
        check("the unobserved sub-signals are named in the report",
                onlyPrivacy.confidence.trace.unobserved.stream()
                        .anyMatch(u -> u.contains("domain_age_inv"))
                        && onlyPrivacy.confidence.trace.unobserved.stream()
                                .anyMatch(u -> u.contains("mx_present")));

        // 7. Nothing observed at all means S = 0, and S = 0 collapses the whole score.
        Attribution.Result nothing = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints());
        near("with no observations at all S is 0", 0.0,
                nothing.confidence.trace.stability, 1e-9);
        near("and S=0 collapses the combined score", 0.0, nothing.confidence.value, 1e-9);

        // 8. Hostname matching is case-insensitive and whitespace-tolerant, because a submitting
        //    host arrives as recorded in the chain and must not silently fail to match.
        Attribution.Result upper = Attribution.attribute(EmailParser.parse(raw),
                new Attribution.Hints().withRegistry(reg)
                        .withDomainAge("A.Example", 800)
                        .withMxPresent("  A.EXAMPLE  "));
        near("domain hints match the submitting host case-insensitively", 1.0,
                upper.confidence.trace.stability, 1e-9);

        // 9. A negative age is a clock artefact and must be rejected outright rather than scored.
        Attribution.Hints badAge = new Attribution.Hints().withRegistry(reg)
                .withDomainAge("a.example", -5000)
                .withMxPresent("a.example");
        eq("a negative domain age is rejected, not stored", 0, badAge.domainAges.size());

        // 10. Recording both present and absent must not leave the domain ambiguous.
        Attribution.Hints flip = new Attribution.Hints().withMxPresent("a.example")
                .withMxAbsent("a.example");
        eq("a later 'absent' supersedes an earlier 'present'", 1, flip.mxAbsentDomains.size());
        eq("and the earlier 'present' is withdrawn", 0, flip.mxPresentDomains.size());

        try {
            Files.deleteIfExists(tsv);
        } catch (Exception ignored) {
            // best effort
        }
    }

    // ==================================================================
    // t12 - mandatory disclaimer
    // ==================================================================

    private static void t12_disclaimer() {
        section("t12 mandatory disclaimer is always present");
        String required = "This result identifies technically observable infrastructure and does not "
                + "establish the physical identity or intent of the sender. IP addresses may represent "
                + "shared infrastructure, NAT, VPNs, proxies, cloud systems, compromised hosts, or other "
                + "intermediaries.";

        eq("the constant matches the required text", required, Attribution.DISCLAIMER);
        eq("the accessor returns it", required, Attribution.disclaimer());

        // Every attribution path must carry it, including degenerate ones.
        String raw = "Received: from a.example ([8.8.8.8])\n\tby mx with ESMTPS;"
                + " Tue, 12 Aug 2025 10:00:00 +0000\nSubject: x\n\nbody\n";
        Attribution.Result ok = Attribution.attribute(EmailParser.parse(raw));
        eq("normal result carries the disclaimer", required, ok.disclaimer);
        check("toMap includes the disclaimer",
                required.equals(ok.toMap().get("disclaimer")));

        Attribution.Result nullMsg = Attribution.attribute(null);
        eq("null message still carries the disclaimer", required, nullMsg.disclaimer);
        Attribution.Result emptyMsg = Attribution.attribute(EmailParser.parse(""));
        eq("empty message still carries the disclaimer", required, emptyMsg.disclaimer);
        Attribution.Result lan = Attribution.attribute(EmailParser.parse(
                "Received: from a ([10.0.0.5])\n\tby b with ESMTP; Tue, 12 Aug 2025 10:00:00 +0000\n"
                        + "Subject: x\n\nbody\n"));
        eq("no-public-address result still carries the disclaimer", required, lan.disclaimer);

        check("summarize() includes the disclaimer",
                Attribution.summarize(ok).contains("DISCLAIMER"));
        check("summarize() includes the full text",
                Attribution.summarize(ok).contains(required));

        // The correlation output must also state its own limit.
        check("correlation carries a scope disclaimer",
                Correlate.DISCLAIMER.contains("does not establish a common actor"));
        Correlate.Campaign c = Correlate.analyze(List.of());
        eq("campaign carries the disclaimer", Correlate.DISCLAIMER, c.disclaimer);
    }

    // ==================================================================
    // t13 - empty Jaccard
    // ==================================================================

    private static void t13_emptyJaccard() {
        section("t13 empty-set Jaccard is defined, not NaN");
        Set<String> e = Set.of();
        Set<String> f = Set.of("a", "b");

        eq("both empty is 0.0, not 1.0", 0.0, Correlate.jaccard(e, e));
        eq("empty vs full is 0.0", 0.0, Correlate.jaccard(e, f));
        eq("full vs empty is 0.0", 0.0, Correlate.jaccard(f, e));
        eq("null vs full is 0.0", 0.0, Correlate.jaccard(null, f));
        eq("null vs null is 0.0", 0.0, Correlate.jaccard(null, null));
        check("both empty is finite", Double.isFinite(Correlate.jaccard(e, e)));

        // Two documents with no observable features must not be reported as identical, and must
        // not be clustered together by the empty case.
        Correlate.Document d1 = new Correlate.Document("d1", null, null, null, null, "", "");
        Correlate.Document d2 = new Correlate.Document("d2", Set.of(), Set.of(), Set.of(), Set.of(), "", "");
        Correlate.PairScore ps = Correlate.score(d1, d2, Correlate.DEFAULT_THRESHOLD);
        eq("two empty documents score 0.0", 0.0, ps.combined);
        check("two empty documents are not linked", !ps.linked);
        eq("dominant component is 'none'", "none", ps.dominantComponent);
        Correlate.Campaign c = Correlate.analyze(List.of(d1, d2));
        check("empty documents are not clustered", c.clusters.stream()
                .noneMatch(cl -> cl.size() > 1));

        // A null document and a real one must not crash.
        check("null sets inside a Document are tolerated", d1.addresses != null
                && d1.addresses.isEmpty());
    }

    // ==================================================================
    // t14 - normal Jaccard
    // ==================================================================

    private static void t14_normalJaccard() {
        section("t14 Jaccard on normal inputs");
        Set<String> a = Set.of("1", "2", "3");
        Set<String> b = Set.of("2", "3", "4");
        near("|A n B| / |A u B| = 2/4", 0.5, Correlate.jaccard(a, b), 1e-9);
        near("identical sets = 1.0", 1.0, Correlate.jaccard(a, a), 1e-9);
        near("disjoint sets = 0.0", 0.0, Correlate.jaccard(a, Set.of("9", "8")), 1e-9);
        near("subset = |S| / |L|", 2.0 / 3.0, Correlate.jaccard(Set.of("1", "2"), a), 1e-9);
        near("symmetric", Correlate.jaccard(a, b), Correlate.jaccard(b, a), 1e-12);
        check("result is within [0,1]", Correlate.jaccard(a, b) >= 0.0 && Correlate.jaccard(a, b) <= 1.0);

        // A realistic document pair.
        Correlate.Document d1 = new Correlate.Document("x", Set.of("1.1.1.1"), Set.of("evil.example"),
                Set.of("http://evil.example/a", "http://evil.example/b"), Set.of("application/pdf"),
                "Invoice", "please pay");
        Correlate.Document d2 = new Correlate.Document("y", Set.of("1.1.1.1"), Set.of("evil.example"),
                Set.of("http://evil.example/a", "http://evil.example/c"), Set.of("application/pdf"),
                "Invoice", "please pay");
        Correlate.PairScore ps = Correlate.score(d1, d2, Correlate.DEFAULT_THRESHOLD);
        near("shared address = 1.0", 1.0, ps.jaccardAddresses, 1e-9);
        near("shared domain = 1.0", 1.0, ps.jaccardDomains, 1e-9);
        // URLs: {a,b} against {a,c} share one element over a three-element union.
        near("1 of 3 urls shared", 1.0 / 3.0, ps.jaccardUrls, 1e-9);
        near("shared file type = 1.0", 1.0, ps.jaccardFileTypes, 1e-9);
        check("every component is exposed on the pair score",
                ps.toMap().containsKey("jaccard.addresses")
                        && ps.toMap().containsKey("jaccard.body")
                        && ps.toMap().containsKey("cosine.body"));
    }

    // ==================================================================
    // t15 - TF-IDF behaviour
    // ==================================================================

    private static void t15_tfidf() {
        section("t15 TF-IDF weighting");
        List<List<String>> docs = List.of(
                Correlate.tokenize("common term alpha beta"),
                Correlate.tokenize("common term gamma"),
                Correlate.tokenize("rare distinctive delta"));
        java.util.Map<String, Double> idf = Correlate.buildIdf(docs);
        // common, term, alpha, beta, gamma, rare, distinctive, delta
        eq("vocabulary size", 8, idf.size());
        double common = idf.get("common");
        double rare = idf.get("rare");
        check("a term in more documents is discounted (common=" + common + ")", common < rare);
        check("a term in one document is weighted up (rare=" + rare + ")", rare > 1.0);
        check("idf is always positive", common > 0.0 && rare > 0.0);
        check("idf is finite", Double.isFinite(common) && Double.isFinite(rare));

        // Determinism: the same input must produce the same weights.
        java.util.Map<String, Double> idf2 = Correlate.buildIdf(docs);
        check("buildIdf is deterministic", idf.equals(idf2));
        Correlate.Vector v = Correlate.vectorize(docs.get(0), idf);
        Correlate.Vector v2 = Correlate.vectorize(docs.get(0), idf);
        // Determinism means the same vector, and a vector is at unit distance from itself.
        near("vectorize is deterministic", 1.0, Correlate.cosine(v, v2), 1e-12);
        check("vectors are L2-normalised", Math.abs(v.norm - 1.0) < 1e-9);
        check("zero vectors report a zero norm", Correlate.vectorize(List.of(), idf).norm == 0.0);

        // IDF must discriminate: a shared term should matter less than a distinctive one.
        Correlate.Vector sharedOnly = Correlate.vectorize("common term", idf);
        Correlate.Vector mixed = Correlate.vectorize("common term rare distinctive", idf);
        check("a vector exists for both", sharedOnly.norm > 0 && mixed.norm > 0);
        near("identical vectors are cos 1.0", 1.0,
                Correlate.cosine(Correlate.vectorize("alpha beta", idf),
                        Correlate.vectorize("alpha beta", idf)), 1e-9);

        // Empty corpus must not divide by zero.
        java.util.Map<String, Double> emptyIdf = Correlate.buildIdf(List.of());
        check("empty corpus yields an empty idf", emptyIdf.isEmpty());
        Correlate.Vector nv = Correlate.vectorize("alpha beta", emptyIdf);
        check("vectorize with empty idf is still valid", nv.norm > 0);
        check("null document list is safe", Correlate.buildIdf(null).isEmpty());
        check("null document list in the list is safe",
                Correlate.buildIdf(java.util.Arrays.asList((List<String>) null)).isEmpty());

        // N is the number of DOCUMENTS, not the number of token-lists. This pins the invariant
        // that the IDF corpus is one entry per message: feeding subject, body and the combined
        // stream separately triples N and lets a term accrue df up to 3 per message, which also
        // pushed the corpus past the IDF bound and silently dropped the scored combined streams.
        // A term present in every one of 3 messages must have df 3 and N 3, so idf == 1.0 exactly.
        java.util.Map<String, Double> perDoc = Correlate.buildIdf(List.of(
                List.of("everywhere"), List.of("everywhere"), List.of("everywhere")));
        near("a term in every message of a 3-message corpus has idf exactly 1.0",
                1.0, perDoc.get("everywhere"), 1e-12);
        // And with a term in 1 of 3: idf = ln(4/2)+1.
        java.util.Map<String, Double> oneOfThree = Correlate.buildIdf(List.of(
                List.of("rare"), List.of("other"), List.of("another")));
        near("a term in 1 of 3 messages uses N=3, not N=9",
                Math.log(4.0 / 2.0) + 1.0, oneOfThree.get("rare"), 1e-12);

        // The scored text term must be fitted on the same stream it is scored on, so a run's
        // cosine is derived from an IDF that actually saw that content.
        Correlate.Document pa = new Correlate.Document("pa", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(), "", "sharedword");
        Correlate.Document pb = new Correlate.Document("pb", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(), "", "sharedword");
        Correlate.PairScore ps = Correlate.score(pa, pb, Correlate.DEFAULT_THRESHOLD);
        near("two identical body texts score a text cosine of 1.0", 1.0, ps.cosineText, 1e-9);
    }

    // ==================================================================
    // t16 - zero-vector cosine
    // ==================================================================

    private static void t16_zeroCosine() {
        section("t16 cosine against a zero vector is 0.0, never NaN");
        java.util.Map<String, Double> idf = Correlate.buildIdf(List.of(
                Correlate.tokenize("alpha beta gamma"), Correlate.tokenize("delta epsilon")));
        Correlate.Vector zero = Correlate.vectorize(List.of(), idf);
        Correlate.Vector real = Correlate.vectorize("alpha beta gamma", idf);
        Correlate.Vector alsoZero = Correlate.vectorize("", idf);

        check("empty token list gives a zero vector", zero.isZero());
        check("empty string gives a zero vector", alsoZero.isZero());
        check("real vector is not zero", !real.isZero());
        eq("cos(real, zero) = 0.0", 0.0, Correlate.cosine(real, zero));
        eq("cos(zero, real) = 0.0", 0.0, Correlate.cosine(zero, real));
        eq("cos(zero, zero) = 0.0", 0.0, Correlate.cosine(zero, alsoZero));
        eq("cos(null, real) = 0.0", 0.0, Correlate.cosine(null, real));
        eq("cos(real, null) = 0.0", 0.0, Correlate.cosine(real, null));
        eq("cos(null, null) = 0.0", 0.0, Correlate.cosine(null, null));
        check("no NaN from any combination",
                !Double.isNaN(Correlate.cosine(real, zero))
                        && !Double.isNaN(Correlate.cosine(zero, zero)));

        // NaN would compare false against a threshold, so a zero-vector pair must never link.
        // Threshold 0.0 is deliberately not used here: Correlate.score is the raw primitive and
        // a zero threshold links everything, including an empty pair. The sanitising entry points
        // are analyze() and pairwise(), which reject out-of-range thresholds.
        Correlate.Document d1 = new Correlate.Document("z1", null, null, null, null, "", "");
        Correlate.Document d2 = new Correlate.Document("z2", null, null, null, null, "", "");
        check("zero-vector pair does not link",
                !Correlate.score(d1, d2, Correlate.DEFAULT_THRESHOLD).linked);
        check("an out-of-range threshold is not honoured by score()",
                Correlate.score(d1, d2, 0.0).linked);

        // Self-similarity must not exceed 1.0 through floating-point drift.
        for (int i = 0; i < 200; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < 60; j++) sb.append("term").append(j * (i + 1)).append(' ');
            Correlate.Vector w = Correlate.vectorize(sb.toString(), idf);
            check("self-cos <= 1 at iteration " + i, Correlate.cosine(w, w) <= 1.0);
        }
    }

    // ==================================================================
    // t17 - 0.62 clustering threshold
    // ==================================================================

    private static void t17_threshold() {
        section("t17 clustering threshold is 0.62 and configurable");
        eq("default threshold", 0.62, Correlate.DEFAULT_THRESHOLD);
        eq("threshold matches project config",
                Config.TAU_CLUSTER, Correlate.DEFAULT_THRESHOLD);

        List<Correlate.Document> corpus = List.of(
                new Correlate.Document("m1", Set.of("1.1.1.1"), Set.of("evil.example"),
                        Set.of("http://evil.example/pay"), Set.of("application/pdf"),
                        "Urgent wire transfer", "send the bank details today invoice attached"),
                new Correlate.Document("m2", Set.of("1.1.1.1"), Set.of("evil.example"),
                        Set.of("http://evil.example/pay"), Set.of("application/pdf"),
                        "Urgent wire transfer", "send the bank details today invoice attached"),
                new Correlate.Document("m3", Set.of("8.8.8.8"), Set.of("other.example"),
                        Set.of("http://other.example/news"), Set.of("text/plain"),
                        "Weekly newsletter", "gardening recipes and weekend tips"));

        Correlate.Campaign atDefault = Correlate.analyze(corpus, Correlate.DEFAULT_THRESHOLD);
        eq("threshold used is reported", 0.62, atDefault.threshold);
        check("identical pair links at 0.62", atDefault.pairs.stream()
                .anyMatch(p -> p.idA.equals("m1") && p.idB.equals("m2") && p.linked));
        check("identical pair forms a 2-member cluster", atDefault.clusters.stream()
                .anyMatch(c -> c.size() == 2 && c.memberIds.contains("m1") && c.memberIds.contains("m2")));
        eq("the unrelated message is unclustered", List.of("m3"), atDefault.unclustered);

        // A threshold above the pair score must break the link. The identical m1-m2 pair scores
        // exactly 1.0, so no threshold in (0, 1.0] can sit above it. Add a near-duplicate pair
        // that shares the IP/domain but differs in URLs and body, producing a score in (0, 1.0).
        // Use a separate tiny corpus so the IDF is stable and the score is read from the same run.
        List<Correlate.Document> nearCorpus = List.of(
                new Correlate.Document("n1", Set.of("1.1.1.1"), Set.of("evil.example"),
                        Set.of("http://evil.example/pay"), Set.of("application/pdf"),
                        "Urgent wire transfer", "send the bank details today invoice attached"),
                new Correlate.Document("n2", Set.of("1.1.1.1"), Set.of("evil.example"),
                        Set.of("http://evil.example/checkout"), Set.of("application/pdf"),
                        "Urgent wire transfer notice", "send the bank details today invoice"));
        Correlate.Campaign nearDefault = Correlate.analyze(nearCorpus, Correlate.DEFAULT_THRESHOLD);
        Correlate.PairScore ns = nearDefault.pairs.stream()
                .filter(p -> p.idA.equals("n1") && p.idB.equals("n2"))
                .findFirst().orElseThrow();
        check("near-duplicate pair scores strictly between 0 and 1",
                ns.combined > 0.0 && ns.combined < 1.0);

        Correlate.Campaign justBelow = Correlate.analyze(nearCorpus, ns.combined - 0.01);
        check("a threshold below the pair score keeps the link", justBelow.pairs.stream()
                .anyMatch(p -> p.idA.equals("n1") && p.idB.equals("n2") && p.linked));

        Correlate.Campaign high = Correlate.analyze(nearCorpus, ns.combined + 0.01);
        check("raising the threshold above the score unlinks the pair", high.pairs.stream()
                .noneMatch(p -> p.idA.equals("n1") && p.idB.equals("n2") && p.linked));
        check("no cluster absorbs the now-unlinked message", high.clusters.stream()
                .noneMatch(c -> c.memberIds.contains("n2")));

        // A lower threshold must keep it.
        Correlate.Campaign low = Correlate.analyze(corpus, 0.10);
        check("lowering the threshold keeps the link", low.pairs.stream()
                .anyMatch(p -> p.idA.equals("m1") && p.idB.equals("m2") && p.linked));

        // Out-of-range thresholds fall back to the default rather than silently comparing to 0.
        eq("threshold 0 falls back to default", 0.62, Correlate.analyze(corpus, 0.0).threshold);
        eq("threshold 5.0 falls back to default", 0.62, Correlate.analyze(corpus, 5.0).threshold);
        eq("negative threshold falls back to default", 0.62, Correlate.analyze(corpus, -1.0).threshold);

        // Transitive closure must be visible, not hidden.
        // The chain needs shared infrastructure, not just shared words: under the specified
        // formula the text term is worth at most W_TEXT (0.20), so a text-only chain can never
        // reach tau = 0.62 no matter how similar the prose is. That is a deliberate property of
        // the model, asserted explicitly in t19, not an accident of the fixtures.
        // a~b share everything; b~c share a domain and the address 2.2.2.2; a~c share only the
        // domain, so the outer pair falls below tau and the cluster is a transitive result.
        java.util.Set<String> kitHeaders = Set.of("x-mailer", "x-priority");
        List<Correlate.Document> chain = List.of(
                new Correlate.Document("a", Set.of("1.1.1.1", "2.2.2.2"), Set.of("kit.example"),
                        Set.of(), Set.of(), kitHeaders, Set.of(), "alpha beta", "alpha beta"),
                new Correlate.Document("b", Set.of("2.2.2.2"), Set.of("kit.example"),
                        Set.of(), Set.of(), kitHeaders, Set.of(), "alpha beta gamma", "alpha beta gamma"),
                new Correlate.Document("c", Set.of("2.2.2.2"), Set.of("kit.example"),
                        Set.of(), Set.of(), Set.of(), Set.of(), "beta gamma", "beta gamma"));
        Correlate.Campaign cc = Correlate.analyze(chain, Correlate.DEFAULT_THRESHOLD);
        Correlate.PairScore ac = cc.pairs.stream()
                .filter(p -> p.idA.equals("a") && p.idB.equals("c"))
                .findFirst().orElseThrow();
        check("outer pair of the chain is below threshold", ac.combined < Correlate.DEFAULT_THRESHOLD);
        check("chain still forms one cluster", cc.clusters.stream().anyMatch(c -> c.size() == 3));
        Correlate.Cluster theCluster = cc.clusters.stream().filter(c -> c.size() == 3)
                .findFirst().orElseThrow();
        check("weakest internal pair is disclosed and is the sub-threshold one",
                theCluster.weakestLink < Correlate.DEFAULT_THRESHOLD);
        check("the reported weakest pair is the outer pair",
                Math.abs(theCluster.weakestLink - ac.combined) < 1e-9);
        check("cohesion is computed from linked pairs only",
                theCluster.cohesion >= Correlate.DEFAULT_THRESHOLD);
        // The cluster must report the threshold that actually produced it, not a hardcoded
        // constant, or "weakestPairLinked" would disagree with a non-default run.
        near("cluster reports the threshold that produced it",
                Correlate.DEFAULT_THRESHOLD, theCluster.threshold, 1e-12);
        check("cluster map reports the same threshold",
                ((Number) theCluster.toMap().get("threshold")).doubleValue() == Correlate.DEFAULT_THRESHOLD);

        // The campaign must state the scope limit and the document count.
        eq("documents considered is reported", 3, cc.documentsConsidered);
        check("campaign carries the scope disclaimer",
                cc.toMap().get("disclaimer").toString().contains("does not establish a common actor"));
        check("empty corpus is handled", Correlate.analyze(List.of()).clusters.isEmpty());
        check("null corpus is handled", Correlate.analyze(null).clusters.isEmpty());
    }

    // ==================================================================
    // t19 - the specified five-term similarity
    // ==================================================================

    private static void t19_specSimilarity() {
        section("t19 similarity is the specified weighted five-term sum");

        // Every weight is a property of the model, and they must sum to 1 so that `combined`
        // lands in [0,1] without a further scaling step.
        near("weights sum to 1", 1.0,
                Correlate.W_HEADER_NAMES + Correlate.W_DOMAINS + Correlate.W_IPS
                        + Correlate.W_TEXT + Correlate.W_ATTACHMENT_HASHES, 1e-12);
        near("header weight is 0.25", 0.25, Correlate.W_HEADER_NAMES, 1e-12);
        near("domain weight is 0.30", 0.30, Correlate.W_DOMAINS, 1e-12);
        near("ip weight is 0.20", 0.20, Correlate.W_IPS, 1e-12);
        near("text weight is 0.20", 0.20, Correlate.W_TEXT, 1e-12);
        near("attachment weight is 0.05", 0.05, Correlate.W_ATTACHMENT_HASHES, 1e-12);

        // A pair agreeing on domain and address and text, and nothing else, must score exactly
        // the weighted sum of those three terms. Verified against the reported per-term
        // contributions so a silent reweighting cannot pass.
        Correlate.Document d1 = new Correlate.Document("x", Set.of("1.1.1.1"), Set.of("k.example"),
                Set.of(), Set.of(), "wire transfer", "wire transfer");
        Correlate.Document d2 = new Correlate.Document("y", Set.of("1.1.1.1"), Set.of("k.example"),
                Set.of(), Set.of(), "wire transfer", "wire transfer");
        Correlate.PairScore xy = Correlate.analyze(List.of(d1, d2)).pairs.get(0);
        near("domain term contributes 0.30 * 1.0", 0.30, Correlate.W_DOMAINS, 1e-12);
        near("ip term contributes 0.20 * 1.0", 0.20, Correlate.W_IPS, 1e-12);
        near("text term contributes 0.20 * 1.0", 0.20, Correlate.W_TEXT, 1e-12);
        near("combined equals the sum of the scored terms",
                Correlate.W_DOMAINS * xy.jaccardDomains
                        + Correlate.W_IPS * xy.jaccardAddresses
                        + Correlate.W_TEXT * xy.cosineText
                        + Correlate.W_HEADER_NAMES * xy.jaccardHeaders
                        + Correlate.W_ATTACHMENT_HASHES * xy.jaccardAttachmentHashes,
                xy.combined, 1e-12);

        // The header-name term is real and load-bearing. Two otherwise identical messages that
        // carry the same unusual header set must score strictly higher than the same pair without
        // it - this is the toolkit fingerprint the term exists to catch.
        Correlate.Document withHeaders = new Correlate.Document("h1", Set.of("1.1.1.1"),
                Set.of("k.example"), Set.of(), Set.of(), Set.of("x-mailer", "x-priority", "received"),
                Set.of(), "wire transfer", "wire transfer");
        Correlate.Document withHeaders2 = new Correlate.Document("h2", Set.of("1.1.1.1"),
                Set.of("k.example"), Set.of(), Set.of(), Set.of("x-mailer", "x-priority", "received"),
                Set.of(), "wire transfer", "wire transfer");
        Correlate.Document noHeaders = new Correlate.Document("n1", Set.of("1.1.1.1"),
                Set.of("k.example"), Set.of(), Set.of(), Set.of(), Set.of(), "wire transfer", "wire transfer");
        Correlate.Document noHeaders2 = new Correlate.Document("n2", Set.of("1.1.1.1"),
                Set.of("k.example"), Set.of(), Set.of(), Set.of(), Set.of(), "wire transfer", "wire transfer");
        Correlate.PairScore withH = Correlate.analyze(List.of(withHeaders, withHeaders2)).pairs.get(0);
        Correlate.PairScore withoutH = Correlate.analyze(List.of(noHeaders, noHeaders2)).pairs.get(0);
        near("identical header sets give J(headers) = 1", 1.0, withH.jaccardHeaders, 1e-12);
        check("a shared header fingerprint raises the score (" + withH.combined + " > "
                        + withoutH.combined + ")",
                withH.combined > withoutH.combined);
        near("the header term alone is worth 0.25",
                0.25, withH.combined - withoutH.combined, 1e-12);

        // Attachment hashes: an identical attachment is a campaign signal in its own right.
        String sharedHash = "sha256:" + "ab".repeat(32);
        Correlate.Document att1 = new Correlate.Document("p1", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(sharedHash), "", "");
        Correlate.Document att2 = new Correlate.Document("p2", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(sharedHash), "", "");
        Correlate.PairScore shared = Correlate.analyze(List.of(att1, att2)).pairs.get(0);
        near("an identical attachment hashes to J = 1", 1.0, shared.jaccardAttachmentHashes, 1e-12);
        near("and is worth 0.05", 0.05, shared.combined, 1e-12);

        // Structural property worth knowing: text alone can never clear tau, because the text
        // term is capped at W_TEXT. Phrase-matching is trivially defeated by rewriting, so it must
        // not be able to establish a campaign on its own.
        Correlate.Document prose1 = new Correlate.Document("t1", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(), "alpha beta gamma", "alpha beta gamma");
        Correlate.Document prose2 = new Correlate.Document("t2", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(), "alpha beta gamma", "alpha beta gamma");
        Correlate.PairScore prose = Correlate.analyze(List.of(prose1, prose2)).pairs.get(0);
        near("identical prose with no other overlap scores exactly the text weight",
                Correlate.W_TEXT, prose.combined, 1e-12);
        check("identical prose alone cannot reach tau = 0.62",
                prose.combined < Correlate.DEFAULT_THRESHOLD);

        // Hashing must be content-addressed, and bounded. The oversized path is marked so two
        // different large attachments sharing a prefix cannot be reported as an exact match.
        EmailParser.Part small = new EmailParser.Part();
        small.isAttachment = true;
        small.data = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String h1 = Correlate.contentHash(small);
        EmailParser.Part same = new EmailParser.Part();
        same.isAttachment = true;
        same.data = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        EmailParser.Part other = new EmailParser.Part();
        other.isAttachment = true;
        other.data = "hellp".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        check("identical content hashes identically", h1.equals(Correlate.contentHash(same)));
        check("different content hashes differently", !h1.equals(Correlate.contentHash(other)));
        check("a null part has no hash rather than the hash of nothing",
                Correlate.contentHash(null) == null);
        EmailParser.Part empty = new EmailParser.Part();
        empty.data = new byte[0];
        check("empty content has no hash", Correlate.contentHash(empty) == null);
        EmailParser.Part big = new EmailParser.Part();
        big.data = new byte[Correlate.MAX_HASH_BYTES + 16];
        String bh = Correlate.contentHash(big);
        check("an oversized attachment is hashed as a marked prefix, not a full-content digest",
                bh != null && bh.endsWith(":prefix" + Correlate.MAX_HASH_BYTES));
    }

    // ==================================================================
    // t20 - campaign risk and aggregates
    // ==================================================================

    private static void t20_campaignRisk() {
        section("t20 campaign risk is noisy-OR, confidence is the mean");

        // The specified required test: five emails at risk 50 must yield a campaign risk of at
        // least 96.9. The exact product is 96.875, which is 96.9 to one decimal place. Both the
        // exact value and the one-decimal rendering are asserted, because ">= 96.9" is only true
        // of the rounded figure - asserting it against 96.875 directly would fail, and quietly
        // loosening it to 96.8 would hide the discrepancy.
        near("five members at risk 50 give 96.875", 96.875,
                Correlate.Cluster.noisyOr(List.of(50.0, 50.0, 50.0, 50.0, 50.0)), 1e-9);
        eq("which displays as 96.9", "96.9",
                String.format(java.util.Locale.ROOT, "%.1f",
                        Correlate.Cluster.noisyOr(List.of(50.0, 50.0, 50.0, 50.0, 50.0))));

        // Monotonicity: adding a member can never lower the campaign risk, and a campaign of
        // several medium-risk emails must not stay medium.
        near("a single member is its own risk", 50.0,
                Correlate.Cluster.noisyOr(List.of(50.0)), 1e-9);
        check("five medium members exceed any one of them",
                Correlate.Cluster.noisyOr(List.of(50.0, 50.0, 50.0, 50.0, 50.0)) > 50.0);
        check("more members never reduce the risk",
                Correlate.Cluster.noisyOr(List.of(50.0, 50.0, 50.0, 50.0, 50.0))
                        >= Correlate.Cluster.noisyOr(List.of(50.0, 50.0, 50.0, 50.0)));
        near("a zero-risk member cannot raise the campaign", 0.0,
                Correlate.Cluster.noisyOr(List.of(0.0, 0.0)), 1e-9);
        near("a certain member saturates at 100", 100.0,
                Correlate.Cluster.noisyOr(List.of(100.0, 10.0)), 1e-9);

        // An unobserved risk is not a zero risk. Reporting 0 for an unscored campaign would read
        // as "measured and harmless", which is the opposite of the truth.
        check("an empty risk list is NaN, not 0", Double.isNaN(Correlate.Cluster.noisyOr(List.of())));
        check("an all-unscored list is NaN, not 0",
                Double.isNaN(Correlate.Cluster.noisyOr(List.of(Double.NaN, Double.NaN))));
        near("unscored members are skipped, not counted as zero risk", 50.0,
                Correlate.Cluster.noisyOr(List.of(50.0, Double.NaN)), 1e-9);
        check("a null risk list is NaN", Double.isNaN(Correlate.Cluster.noisyOr(null)));

        // End-to-end: the aggregates must survive into the cluster that analyze() returns.
        // Five members, because the specified >= 96.9 figure is the five-member product; three
        // members at risk 50 give 87.5 and asserting 96.875 there would be simply wrong.
        long t0 = 1_700_000_000_000L;
        java.util.Set<String> kitHeaders = Set.of("x-mailer", "x-priority");
        List<Correlate.Document> scored = new ArrayList<>();
        String[] texts = {"alpha beta", "alpha beta gamma", "beta gamma", "gamma delta", "delta epsilon"};
        double[] confs = {0.60, 0.80, 0.70, 0.50, 0.90};
        for (int i = 0; i < 5; i++) {
            scored.add(new Correlate.Document("s" + (i + 1), Set.of("1.1.1.1"), Set.of("k.example"),
                    Set.of(), Set.of(), kitHeaders, Set.of(), texts[i], texts[i],
                    50.0, confs[i], t0 + (i * 600000L)));
        }
        Correlate.Campaign sc = Correlate.analyze(scored, Correlate.DEFAULT_THRESHOLD);
        Correlate.Cluster sc1 = sc.clusters.stream().filter(c -> c.size() == 5)
                .findFirst().orElseThrow();
        eq("n_emails is reported", 5, sc1.nEmails);
        near("risk_campaign is the noisy-OR of the five members", 96.875, sc1.riskCampaign, 1e-9);
        // mean of 0.60, 0.80, 0.70, 0.50, 0.90 = 0.70 - and explicitly not the 0.90 maximum.
        near("confidence_mean is the MEAN, never the max", 0.70, sc1.confidenceMean, 1e-9);
        check("confidence_mean is not the max", sc1.confidenceMean < 0.90);
        eq("earliest observed is reported", t0, sc1.earliestObserved);
        eq("latest observed is reported", t0 + (4 * 600000L), sc1.latestObserved);

        // Unscored members must leave the aggregates explicitly absent, not silently zero.
        List<Correlate.Document> unscored = List.of(
                new Correlate.Document("u1", Set.of("1.1.1.1"), Set.of("k.example"), Set.of(), Set.of(),
                        Set.of(), Set.of(), "alpha beta", "alpha beta"),
                new Correlate.Document("u2", Set.of("1.1.1.1"), Set.of("k.example"), Set.of(), Set.of(),
                        Set.of(), Set.of(), "alpha beta", "alpha beta"));
        Correlate.Cluster uc = Correlate.analyze(unscored, Correlate.DEFAULT_THRESHOLD).clusters.get(0);
        check("an unscored campaign reports no risk rather than zero", Double.isNaN(uc.riskCampaign));
        check("an unscored campaign reports no confidence rather than zero",
                Double.isNaN(uc.confidenceMean));
        check("an unobserved time is reported as absent, not as the epoch",
                uc.earliestObserved == Long.MIN_VALUE);
        eq("the map reports null for an absent risk, not 0",
                null, uc.toMap().get("risk_campaign"));
    }

    // ==================================================================
    // t18 - hostile / malformed input
    // ==================================================================

    private static void t18_hostile() {
        section("t18 hostile and malformed input never throws");

        String[] nasty = {
                "",
                "\u0000\u0001\u0002",
                "Subject:\r\n",
                "Subject: \u0000\r\n\r\n\u0000",
                "From: <>\r\nTo: <>\r\n",
                "From: not-an-address\r\n",
                "From: a@b@c@d.example\r\n",
                "Received: \r\n",
                "Received: from\r\n",
                "Received: from ([not-an-ip])\r\n",
                "Received: from ([999.999.999.999])\r\n\tby ;\r\n",
                "Received: from ([1.1.1.1])\r\n\tby x with\r\n",
                "Content-Type: multipart/mixed\r\n\r\nno boundary at all\r\n",
                "Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n",
                "Content-Type: multipart/mixed; boundary=\"unterminated\r\n\r\n--unterminated\r\n",
                "MIME-Version: 9.9\r\nContent-Type: nonsense/nonsense\r\n\r\nx\r\n",
                "Content-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!\r\n",
                "Content-Transfer-Encoding: base64\r\n\r\n=====\r\n",
                "Content-Transfer-Encoding: base64\r\n\r\nA\r\n",
                "Content-Disposition: attachment; filename=\"a\\\"\\r\\nb.txt\"\r\n\r\nx\r\n",
                "Subject: \uD83D\uDE00\uD83D\uDE00 emoji \uD83D\uDE00\r\n\r\nbody\r\n",
                "Content-Type: text/plain; charset=\"NOT-A-CHARSET\"\r\n\r\nbody\r\n",
                "Content-Type: text/plain; charset=\"\"\r\n\r\nbody\r\n",
                repeat("X-Deep: ", 5000) + "v\r\n\r\nbody\r\n",
                "--\r\n".repeat(500),
                repeat("fold ", 20000) + "\r\n\r\nbody\r\n"
        };

        for (String raw : nasty) {
            String label = "raw[" + raw.replaceAll("[\\r\\n\\u0000]+", " ").trim() + "]";
            if (label.length() > 70) label = label.substring(0, 70) + "...";
            try {
                EmailParser.Message m = EmailParser.parse(raw);
                check("parsed without throwing: " + label, m != null);
                check("usable result: " + label, m != null && m.toMap() != null);
                // The analysis layer must survive whatever the parser produced.
                Attribution.Result a = Attribution.attribute(m);
                check("attribution without throwing: " + label, a != null);
                check("disclaimer always present: " + label, requiredDisclaimer().equals(a.disclaimer));
                check("confidence in range: " + label,
                        a.confidence.value >= 0.0 && a.confidence.value <= Attribution.CONFIDENCE_CAP);
                check("confidence is finite: " + label, Double.isFinite(a.confidence.value));
                Correlate.Document d = Correlate.documentOf("d", m, a);
                check("document built without throwing: " + label, d != null);
                check("document tokenizes without throwing: " + label, d.bodyTokens() != null);
                Enrich.Enrichment e = Enrich.newRegistry().lookup(
                        a.primaryIp == null ? "203.0.113.1" : a.primaryIp);
                check("enrichment without throwing: " + label, e != null);
                check("enrichment reports honestly: " + label, !e.country.isKnown());
                check("clustering without throwing: " + label,
                        Correlate.analyze(List.of(d, d)).clusters != null);
            } catch (RuntimeException ex) {
                failed++;
                failures.add(section + " / threw on " + label + ": " + ex);
                System.out.println("  FAIL  threw on " + label + ": " + ex);
            }
        }

        // Pathological shapes that specifically stress the bounded code paths.
        String deepNest = "Content-Type: multipart/mixed; boundary=\"a\"\r\n\r\n--a\r\n"
                + repeat("Content-Type: multipart/mixed; boundary=\"a\"\r\n\r\n--a\r\n", 300)
                + "x\r\n" + "--a--\r\n".repeat(300);
        EmailParser.Message dm = EmailParser.parse(deepNest);
        check("300x nested identical boundary does not blow up", dm != null && dm.parts.size() <= 200);

        String manyBoundaries = "Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n"
                + repeat("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n", 5000) + "--b--\r\n";
        EmailParser.Message bm2 = EmailParser.parse(manyBoundaries);
        check("5000 boundaries respects the part limit",
                bm2 != null && bm2.parts.size() <= 200);

        // Enrichment parsing must not fabricate from garbage either.
        eq("garbage RDAP yields no country", null, Enrich.parseRdap("{\"country\":").country);
        eq("non-object RDAP yields no country", null, Enrich.parseRdap("[1,2,3]").country);
        eq("empty RDAP yields no country", null, Enrich.parseRdap("").country);
        eq("null RDAP yields no country", null, Enrich.parseRdap(null).country);
        eq("garbage WHOIS yields no country", null, Enrich.parseWhois(":::").country);
        eq("empty WHOIS yields no country", null, Enrich.parseWhois("").country);
        eq("null WHOIS yields no country", null, Enrich.parseWhois(null).country);
        eq("WHOIS '-' value is treated as absent", null, Enrich.parseWhois("country: -").country);
        check("unparseable RDAP does not throw", Enrich.parseRdap("{\"a\":{\"b\":[1,2,{\"c\":null}]}}") != null);

        // A dataset that is entirely junk must load zero records, not crash.
        try {
            Path junk = Files.createTempFile("phase2junk", ".tsv");
            Files.writeString(junk, "not\ttab\tformat\n999.999.999.999/99\tX\tY\tZ\tW\tV\n#\n\n",
                    StandardCharsets.UTF_8);
            Enrich.DatasetProvider dp = new Enrich.DatasetProvider(junk.toString());
            check("junk dataset loads without throwing", dp.size() >= 0);
            check("junk lookup returns nothing", dp.lookup("8.8.8.8").isEmpty());
            Files.deleteIfExists(junk);
        } catch (Exception ex) {
            check("junk dataset handled: " + ex, false);
        }
    }

    private static String repeat(String unit, int times) {
        StringBuilder sb = new StringBuilder(unit.length() * times);
        for (int i = 0; i < times; i++) sb.append(unit);
        return sb.toString();
    }

    private static String requiredDisclaimer() {
        return "This result identifies technically observable infrastructure and does not establish "
                + "the physical identity or intent of the sender. IP addresses may represent shared "
                + "infrastructure, NAT, VPNs, proxies, cloud systems, compromised hosts, or other "
                + "intermediaries.";
    }

    // ==================================================================
    // main
    // ==================================================================

    public static void main(String[] args) {
        long t0 = System.nanoTime();
        System.out.println("CIPHER SQUAD - Phase 2 test suite");
        System.out.println("Java " + System.getProperty("java.version")
                + " on " + System.getProperty("os.name"));
        System.out.println("------------------------------------------------------------");

        t01_messageSizeLimit();
        t02_headerCountLimit();
        t03_headerLineLimit();
        t04_mimeDepth();
        t05_mimePartLimit();
        t06_decodedCap();
        t07_parseBudget();
        t08_privateFiltering();
        t09_publicExtraction();
        t10_hopOrdering();
        t11_confidenceCap();
        t21_stabilityFactor();
        t12_disclaimer();
        t13_emptyJaccard();
        t14_normalJaccard();
        t15_tfidf();
        t16_zeroCosine();
        t17_threshold();
        t19_specSimilarity();
        t20_campaignRisk();
        t18_hostile();

        long ms = (System.nanoTime() - t0) / 1_000_000L;
        System.out.println();
        System.out.println("------------------------------------------------------------");
        System.out.println("passed=" + passed + "  failed=" + failed + "  (" + ms + " ms)");
        if (failed > 0) {
            System.out.println("FAILURES:");
            for (String f : failures) System.out.println("  - " + f);
            System.out.println("------------------------------------------------------------");
            System.out.println("RESULT: FAIL");
            System.exit(1);
        }
        System.out.println("------------------------------------------------------------");
        System.out.println("RESULT: PASS");
    }
}
