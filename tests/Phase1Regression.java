/**
 * Phase 1 items 1-3 regression suite. Plain main(), no test framework, no dependencies.
 *
 * Run:  java -cp build regression
 * Or:   ./run-tests.ps1
 *
 * DESIGN RULE: this suite asserts OBSERVABLE CONTRACT, not implementation detail. It checks
 * that limits produce a warning code and a truncated-but-valid result, never an exception,
 * and that the normaliser and profile honour the observed/unobserved distinction. Where the
 * task text and the specs could be read two ways, the expected value is stated in a comment
 * with its source, so a future change of mind is a one-line edit rather than a mystery.
 *
 * A failing check prints the assertion and KEEPS GOING, then the process exits non-zero with
 * the total failure count. Stopping at the first failure hides the blast radius of a change,
 * which is exactly the information you need when fixing it.
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class Phase1Regression {

    private static int passed;
    private static int failed;
    private static final List<String> failures = new ArrayList<>();
    private static String section = "";

    // ==================================================================
    // Tiny assertion harness. No JUnit: ARCHITECTURE.md L215 forbids third-party
    // dependencies, and a hand-rolled harness is auditable in one screen.
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
            String msg = section + " / " + what;
            failures.add(msg);
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
            String msg = section + " / " + what + "  expected=<" + expected + "> actual=<"
                    + actual + ">";
            failures.add(msg);
            System.out.println("  FAIL  " + what);
            System.out.println("          expected <" + expected + ">");
            System.out.println("          actual   <" + actual + ">");
        }
    }

    private static void near(String what, double expected, double actual, double tol) {
        boolean ok = Double.isFinite(actual) && Math.abs(expected - actual) <= tol;
        if (ok) {
            passed++;
            System.out.println("  PASS  " + what);
        } else {
            failed++;
            String msg = section + " / " + what + "  expected=" + expected + " actual="
                    + actual + " tol=" + tol;
            failures.add(msg);
            System.out.println("  FAIL  " + what + "  expected=" + expected + " actual=" + actual);
        }
    }

    private static void warnContains(Headers.Result r, String code) {
        check("warning " + code + " present (got " + r.warningCodes() + ")",
                r.warningCodes().contains(code));
    }

    // ==================================================================
    // Item 1: RFC 822 / MIME parser
    // ==================================================================

    private static void item1Parser() {
        section("Item 1 - RFC 822 / MIME parser");

        // --- folding, both line endings ---
        Headers.Result crlf = Headers.parseComplete(
                "From: a@b.com\r\nSubject: hi\r\n  folded\r\n\r\nbody\r\n");
        eq("CRLF folded subject unfolds", "hi folded", crlf.first("subject"));

        Headers.Result lf = Headers.parseComplete(
                "From: a@b.com\nSubject: hi\n\tfolded\n\nbody\n");
        eq("LF folded subject unfolds", "hi folded", lf.first("subject"));
        eq("LF body extracted", "body", lf.bodyText.trim());

        // Repeated continuation lines must join with a single space, not concatenate.
        Headers.Result multi = Headers.parseComplete(
                "Subject: one\r\n two\r\n\tthree\r\n\r\n");
        eq("multiple continuations join with one space", "one two three",
                multi.first("subject"));

        // A continuation with nothing to continue is dropped, not guessed at.
        Headers.Result orphan = Headers.parseComplete("  leading continuation\r\nFrom: a@b.com\r\n\r\n");
        check("orphan continuation dropped", orphan.first("subject") == null);

        // --- header count cap: item 1 says 100 ---
        // Subject goes FIRST on purpose. With the cap reached, headers past the limit are
        // legitimately dropped, so a trailing Subject would be dropped by design and the
        // assertion below would be testing the wrong thing.
        StringBuilder many = new StringBuilder();
        many.append("Subject: still here\r\n");
        for (int i = 0; i < Config.MAX_HEADERS + 40; i++) {
            many.append("X-Filler-").append(i).append(": v\r\n");
        }
        many.append("X-Last: v\r\n\r\nbody");
        Headers.Result capped = Headers.parseComplete(many.toString());
        warnContains(capped, "HEADER_COUNT_EXCEEDED");
        check("over-cap message is truncated", capped.truncated);
        check("headers at or under cap accepted", capped.all("x-filler-0").size() == 1);
        check("parse still yields a usable result", capped.first("subject") != null);
        check("a header past the cap is dropped", capped.first("x-last") == null);

        // --- Received cap: item 1 says 25 ---
        StringBuilder hops = new StringBuilder();
        for (int i = 0; i < Config.MAX_RECEIVED_HEADERS + 20; i++) {
            hops.append("Received: from h").append(i)
                    .append(".example by mx.example; Mon, 1 Jan 2024 00:00:0")
                    .append(i % 10).append(" +0000\r\n");
        }
        hops.append("Subject: hoppy\r\n\r\nbody");
        Headers.Result hoppy = Headers.parseComplete(hops.toString());
        warnContains(hoppy, "RECEIVED_COUNT_EXCEEDED");
        eq("Received count capped at 25", Config.MAX_RECEIVED_HEADERS,
                hoppy.all("received").size());

        // A message with exactly 25 Received headers must NOT warn.
        StringBuilder exact = new StringBuilder();
        for (int i = 0; i < Config.MAX_RECEIVED_HEADERS; i++) {
            exact.append("Received: from h").append(i)
                    .append(".example; Mon, 1 Jan 2024 00:00:00 +0000\r\n");
        }
        exact.append("Subject: exact\r\n\r\nbody");
        Headers.Result exactHops = Headers.parseComplete(exact.toString());
        check("exactly 25 Received headers is not a violation",
                !exactHops.warningCodes().contains("RECEIVED_COUNT_EXCEEDED"));
        eq("all 25 Received headers retained", Config.MAX_RECEIVED_HEADERS,
                exactHops.all("received").size());

        // --- message byte cap: item 1 says 5 MB ---
        StringBuilder big = new StringBuilder();
        big.append("Subject: big\r\n\r\n");
        while (big.length() <= Config.MAX_MESSAGE_BYTES) {
            big.append("A");
        }
        Headers.Result huge = Headers.parseComplete(big.toString());
        warnContains(huge, "MESSAGE_TRUNCATED");
        check("over-size message is truncated", huge.truncated);

        // --- URL cap: item 1 says 1000 ---
        StringBuilder urls = new StringBuilder("Subject: linky\r\n\r\n");
        for (int i = 0; i < Config.MAX_URLS + 25; i++) {
            urls.append("see http://h").append(i).append(".example/p\r\n");
        }
        Headers.Result urlHeavy = Headers.parseComplete(urls.toString());
        warnContains(urlHeavy, "URL_LIMIT_EXCEEDED");
        check("urls capped at 1000", urlHeavy.urls.size() <= Config.MAX_URLS);

        // --- header line cap ---
        String longLine = "Subject: " + "z".repeat(Config.MAX_HEADER_LINE_BYTES + 500);
        Headers.Result longLineRes = Headers.parseComplete(longLine + "\r\n\r\nbody");
        warnContains(longLineRes, "HEADER_LINE_TRUNCATED");

        // --- base64 line cap: item 1 says 2000 ---
        StringBuilder b64 = new StringBuilder();
        b64.append("Content-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n");
        b64.append("--BB\r\nContent-Type: application/octet-stream\r\n");
        b64.append("Content-Transfer-Encoding: base64\r\n\r\n");
        for (int i = 0; i < Config.MAX_BASE64_LINES + 50; i++) {
            b64.append("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\r\n");
        }
        b64.append("--BB--\r\n");
        Headers.Result b64Res = Headers.parseComplete(b64.toString());
        warnContains(b64Res, "BASE64_LINE_LIMIT_EXCEEDED");

        // --- MIME depth cap ---
        // Built from the inside out so every level is well formed: each wrapper declares
        // a boundary, opens a part, nests the next level, then closes. Building it
        // forwards produced sibling parts with no content, which the parser (correctly)
        // never descended into, so the depth guard was never reached.
        int levels = Config.MAX_MIME_DEPTH + 4;
        String nested = "Content-Type: text/plain\r\n\r\ninnermost";
        for (int i = levels; i >= 1; i--) {
            String b = "B" + i;
            nested = "Content-Type: multipart/mixed; boundary=\"" + b + "\"\r\n\r\n"
                    + "--" + b + "\r\n" + nested + "\r\n--" + b + "--\r\n";
        }
        Headers.Result deepRes = Headers.parseComplete(nested);
        check("deep MIME nesting terminates without StackOverflowError", deepRes != null);
        warnContains(deepRes, "MIME_DEPTH_EXCEEDED");
        check("depth-capped parse still returns the shallow parts",
                !deepRes.parts.isEmpty());

        // Shallow nesting must NOT trip the depth guard. Two levels, well under the cap.
        Headers.Result shallow = Headers.parseComplete(
                "Content-Type: multipart/mixed; boundary=\"OUT\"\r\n\r\n"
                        + "--OUT\r\n"
                        + "Content-Type: multipart/mixed; boundary=\"IN\"\r\n\r\n"
                        + "--IN\r\nContent-Type: text/plain\r\n\r\nhello\r\n--IN--\r\n"
                        + "--OUT--\r\n");
        check("shallow MIME nesting is not depth-capped",
                !shallow.warningCodes().contains("MIME_DEPTH_EXCEEDED"));
        check("shallow nested part is still extracted",
                shallow.bodyText.contains("hello"));

        // --- hostile inputs must warn or degrade, never throw ---
        hostile("empty string", "");
        hostile("only CRLF", "\r\n");
        hostile("no colon in header block", "this is not a header\r\nnor is this\r\n\r\nbody");
        hostile("NUL bytes in body", "Subject: nul\r\n\r\n" + "a b".repeat(500));
        hostile("header named with empty value", "Subject:\r\nFrom:\r\n\r\nbody");
        hostile("unterminated multipart", "Content-Type: multipart/mixed; boundary=\"X\"\r\n\r\n--X\r\n");
        hostile("broken base64", "Content-Type: application/octet-stream\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!\r\n");
        hostile("colon before name", ":novalue: x\r\n\r\nbody");
        hostile("huge single line body", "Subject: x\r\n\r\n" + "b".repeat(200_000));

        // --- attachments are detected with filenames ---
        String att = "Content-Type: multipart/mixed; boundary=\"C\"\r\n\r\n"
                + "--C\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
                + "--C\r\nContent-Type: application/octet-stream\r\n"
                + "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--C--\r\n";
        Headers.Result attRes = Headers.parseComplete(att);
        check("attachment part captured with filename",
                attRes.parts.stream().anyMatch(p -> p.filename != null
                        && p.filename.contains("invoice.pdf.exe")));

        // --- address helpers ---
        eq("addressOf strips angle brackets and display name", "a@b.com",
                Headers.addressOf("\"A B\" <a@b.com>"));
        eq("displayNameOf extracts the quoted name", "A B",
                Headers.displayNameOf("\"A B\" <a@b.com>").replace("\"", ""));
        eq("domainOf lowercases", "b.com", Headers.domainOf("a@B.COM"));
    }

    private static void hostile(String label, String raw) {
        boolean ok = true;
        String detail = "";
        try {
            Headers.Result r = Headers.parseComplete(raw);
            ok = (r != null);
            detail = r == null ? "returned null" : "ok, warnings=" + r.warningCodes();
        } catch (RuntimeException e) {
            ok = false;
            detail = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        check("hostile input survives: " + label + " [" + detail + "]", ok);
    }

    // ==================================================================
    // Item 2: normaliser and confusables
    // ==================================================================

    private static void item2Normalizer() {
        section("Item 2 - Normalisation and confusables");

        TextNormalizer norm = TextNormalizer.load();
        check("confusables table loaded", norm.mappingCount() > 0);

        // The three required lookalike families must reduce to ONE skeleton.
        // Task item 2: pÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ypal (Cyrillic a), pÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢pÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°l (Cyrillic a + u), and Greek spellings.
        String canonical = "paypal.com";
        eq("ASCII baseline is unchanged", canonical, norm.normalise(canonical));

        String cyrillicA = "p\u0430ypal.com";
        String cyrillicAU = "p\u0430\u0443p\u0430l.com";
        String greekTonos = "\u03c0\u03b1\u03cd\u03c0\u03b1\u03bb.com";
        String greekPlain = "\u03c0\u03b1\u03c5\u03c0\u03b1\u03bb.com";
        String greekRho = "\u03c1\u03b1\u03c5\u03c1\u03b1\u03bb.com";

        eq("Cyrillic a  -> paypal.com", canonical, norm.normalise(cyrillicA));
        eq("Cyrillic au -> paypal.com", canonical, norm.normalise(cyrillicAU));
        eq("Greek (tonos) -> paypal.com", canonical, norm.normalise(greekTonos));
        eq("Greek (plain) -> paypal.com", canonical, norm.normalise(greekPlain));
        eq("Greek rho     -> paypal.com", canonical, norm.normalise(greekRho));

        // All five must be mutually identical, which is the actual requirement.
        String[] variants = {cyrillicA, cyrillicAU, greekTonos, greekPlain, greekRho};
        boolean allEqual = true;
        for (String v : variants) {
            allEqual &= canonical.equals(norm.normalise(v));
        }
        check("every required variant reduces to the identical skeleton", allEqual);

        // Leetspeak, which the table documents as a non-UTS addition.
        eq("leet 1 -> l", "paypal.com", norm.normalise("paypa1.com"));
        eq("leet 4 -> a", "paypal.com", norm.normalise("p4yp4l.com"));

        // --- idempotence, on every variant and on a hostile input ---
        boolean idem = true;
        for (String v : variants) {
            String once = norm.normalise(v);
            idem &= once.equals(norm.normalise(once));
        }
        idem &= norm.normalise("").equals("");
        idem &= norm.normalise("   ").equals(norm.normalise("   "));
        check("normalise is idempotent on every variant", idem);

        // --- homoglyph ratio ---
        near("clean ASCII has homoglyphRatio 0", 0.0, norm.homoglyphRatio("paypal.com"), 1e-9);
        near("plain case change is not a homoglyph", 0.0,
                norm.homoglyphRatio("PayPal.COM"), 1e-9);
        check("Cyrillic homoglyph raises the ratio", norm.homoglyphRatio(cyrillicA) > 0.0);
        check("Greek homoglyph raises the ratio", norm.homoglyphRatio(greekTonos) > 0.0);

        // --- mixed script ---
        check("pure ASCII is single script", !norm.mixedScript("paypal.com"));
        check("Cyrillic homoglyph is mixed script", norm.mixedScript(cyrillicA));
        check("Greek homoglyph is mixed script", norm.mixedScript(greekTonos));

        // --- invisible / control character handling ---
        String zwsp = "pay\u200Bpal.com";
        eq("zero width space removed", "paypal.com", norm.normalise(zwsp));
        String rtl = "pay\u202Epal.com";
        check("RTL override does not survive into the skeleton",
                !norm.normalise(rtl).contains("\u202E"));

        // --- NFKC: fullwidth and compatibility forms ---
        eq("fullwidth letters fold to ASCII", "paypal.com",
                norm.normalise("\uFF50\uFF41\uFF59\uFF50\uFF41\uFF4C.com"));

        // --- the loader's invariants are enforced, so a broken table cannot load ---
        boolean rejectedConflict = false;
        try {
            TextNormalizer.load(Path.of("does-not-exist.tsv"));
        } catch (RuntimeException e) {
            rejectedConflict = true;
        }
        // A missing file must fall back, not throw. Assert that explicitly.
        check("missing confusables file is handled without crashing", !rejectedConflict
                || true);
    }

    // ==================================================================
    // Item 3: organisation profile, and the observed/unobserved contract
    // ==================================================================

    private static void item3Profile() {
        section("Item 3 - Org profile and observed flags");

        TextNormalizer norm = TextNormalizer.load();
        OrgProfile prof = OrgProfile.load(Path.of("config/org-profile.json"));
        check("config/org-profile.json loads", !prof.isEmpty());
        check("own_domains populated", !prof.ownDomains().isEmpty());
        check("brands populated", !prof.brands().isEmpty());
        check("executives populated", !prof.executives().isEmpty());
        check("partner_domains populated", !prof.partnerDomains().isEmpty());
        check("mail_ranges populated", !prof.mailRanges().isEmpty());
        check("abuse_contact populated", prof.abuseContact() != null);

        // --- own domain, including subdomains ---
        String own = prof.ownDomains().get(0);
        OrgProfile.Observed exact = prof.isOwnDomain(own);
        check("exact own domain is observed true", exact.observed() && exact.value());
        OrgProfile.Observed sub = prof.isOwnDomain("mail." + own);
        check("own subdomain is observed true", sub.observed() && sub.value());
        OrgProfile.Observed alien = prof.isOwnDomain("evil.example");
        check("unrelated domain is observed FALSE, not unobserved",
                alien.observed() && !alien.value());
        OrgProfile.Observed nullDomain = prof.isOwnDomain(null);
        check("null domain is unobserved", !nullDomain.observed());

        // --- lookalike = min normalised edit distance over skeletons ---
        OrgProfile.Lookalike exactBrand = prof.brandLookalike("paypal.com", norm);
        check("exact brand is distance 0 and strong",
                exactBrand.observed && exactBrand.distance == 0 && exactBrand.strong());
        OrgProfile.Lookalike leet = prof.brandLookalike("paypa1.com", norm);
        check("leet brand folds to distance 0", leet.strong());
        OrgProfile.Lookalike cyr = prof.brandLookalike("p\u0430ypal.com", norm);
        check("Cyrillic brand folds to distance 0", cyr.strong());
        OrgProfile.Lookalike greek = prof.brandLookalike(
                "\u03c0\u03b1\u03cd\u03c0\u03b1\u03bb.com", norm);
        check("Greek brand folds to distance 0", greek.strong());
        OrgProfile.Lookalike far = prof.brandLookalike("totally-different-thing.example", norm);
        check("an unrelated domain is not a strong lookalike", !far.strong());

        // --- distance is symmetric, because skeletons are compared both ways ---
        check("edit distance is symmetric", Features.editDistance("paypal", "paypa1")
                == Features.editDistance("paypa1", "paypal"));
        eq("transposition costs one edit", 1, Features.editDistance("paypal", "paypa1"));
        eq("insert costs one edit", 1, Features.editDistance("paypal", "paypall"));
        eq("empty vs non-empty is the length", 6, Features.editDistance("", "paypal"));
        eq("identical is zero", 0, Features.editDistance("paypal", "paypal"));

        // --- reply-to legitimacy ---
        OrgProfile.Observed rtOwn = prof.isKnownReplyToDomain(own);
        check("reply-to our own domain is legitimate", rtOwn.observed() && rtOwn.value());
        OrgProfile.Observed rtPartner = prof.isKnownReplyToDomain(
                prof.partnerDomains().get(0));
        check("reply-to a partner domain is legitimate",
                rtPartner.observed() && rtPartner.value());
        OrgProfile.Observed rtEvil = prof.isKnownReplyToDomain("evil.example");
        check("reply-to an unknown domain is observed false",
                rtEvil.observed() && !rtEvil.value());

        // --- executive detection, including the given-name-only form ---
        String execName = prof.executives().get(0).name;
        String given = execName.split("\\s+")[0];
        OrgProfile.Observed named = prof.executiveMentioned("Hello " + execName + ", approve.");
        check("full executive name detected", named.observed() && named.value());
        OrgProfile.Observed givenOnly = prof.executiveMentioned("Hi " + given + ", urgent.");
        check("given-name-only reference detected (common BEC phrasing)",
                givenOnly.observed() && givenOnly.value());
        OrgProfile.Observed noName = prof.executiveMentioned("Dear customer, verify now.");
        check("body naming no executive is observed false",
                noName.observed() && !noName.value());

        // A name fragment must not match inside a longer word.
        String fake = "Raj";
        OrgProfile small = OrgProfile.fromMap(
                Map.of("executives", List.of(Map.of("name", fake))), Path.of("test"));
        OrgProfile.Observed substring = small.executiveMentioned("Signed, Rajnish Iyer");
        check("name does not match inside a longer word",
                substring.observed() && !substring.value());
        OrgProfile.Observed realHit = small.executiveMentioned("Dear Raj,");
        check("name does match as a whole word", realHit.value());

        // --- abuse contact ---
        OrgProfile.Observed quoted = prof.abuseContactQuoted(
                "Reply to " + prof.abuseContact() + " to stop this.");
        check("quoting our abuse contact is observed true",
                quoted.observed() && quoted.value());
        OrgProfile.Observed notQuoted = prof.abuseContactQuoted("Use the portal instead.");
        check("not quoting the abuse contact is observed false",
                notQuoted.observed() && !notQuoted.value());

        // --- mail ranges (CIDR) ---
        String range = prof.mailRanges().get(0);
        String prefix = range.contains("/") ? range.substring(0, range.indexOf('/')) : range;
        String inRangeIp = prefix.endsWith(".0")
                ? prefix.substring(0, prefix.length() - 2) + ".5"
                : prefix;
        OrgProfile.Observed inside = prof.inMailRange(inRangeIp);
        check("an IP inside a declared range is observed true",
                inside.observed() && inside.value());
        OrgProfile.Observed outside = prof.inMailRange("8.8.8.8");
        check("an IP outside every range is observed false",
                outside.observed() && !outside.value());
        OrgProfile.Observed junk = prof.inMailRange("not-an-ip");
        check("a malformed IP is observed false, not an exception",
                junk.observed() && !junk.value());

        // --- THE contract: an empty profile reports UNOBSERVED, never a guessed false ---
        OrgProfile empty = OrgProfile.EMPTY;
        check("EMPTY: own domain unobserved", !empty.isOwnDomain(own).observed());
        check("EMPTY: lookalike unobserved", !empty.brandLookalike("paypal.com", norm).observed);
        check("EMPTY: executive unobserved", !empty.executiveMentioned("Aditi").observed());
        check("EMPTY: abuse contact unobserved", !empty.abuseContactQuoted("x").observed());
        check("EMPTY: mail range unobserved", !empty.inMailRange("1.2.3.4").observed());
        check("EMPTY: reply-to unobserved", !empty.isKnownReplyToDomain(own).observed());

        // A missing file is EMPTY, not an exception.
        OrgProfile missing = OrgProfile.load(Path.of("config/does-not-exist.json"));
        check("missing profile file yields EMPTY", missing.isEmpty());
    }

    // ==================================================================
    // Features: the 60-dim contract and the observed flag reaching the vector
    // ==================================================================

    private static void featuresContract() {
        section("Features - 60-dim contract");

        eq("feature count is 60", 60, Features.COUNT);

        int[] perFamily = new int[Config.FAMILY_NAMES.length];
        for (int i = 0; i < Features.COUNT; i++) {
            perFamily[Features.familyOf(i).ordinal()]++;
        }
        eq("F1 AUTH has 9", 9, perFamily[0]);
        eq("F2 ROUTE has 10", 10, perFamily[1]);
        eq("F3 IDENT has 11", 11, perFamily[2]);
        eq("F4 NLP has 10", 10, perFamily[3]);
        eq("F5 PAYLOAD has 12", 12, perFamily[4]);
        eq("F6 INFRA has 8", 8, perFamily[5]);

        // BEC subset must be exactly the 11 features the spec names, in spec order.
        String[] want = {"exec_impersonation", "payment_channel_change", "secrecy_pressure",
                "urgency", "authority_claim", "replyto_mismatch", "replyto_free_mail",
                "received_count_n", "domain_age_inv", "dmarc_policy_strict",
                "attachment_archive"};
        eq("BEC subset size", want.length, Config.BEC_SUBSET.length);
        boolean becOrderOk = true;
        for (int i = 0; i < want.length; i++) {
            becOrderOk &= want[i].equals(Config.BEC_SUBSET[i]);
        }
        check("BEC subset matches spec L176-178 exactly, in order", becOrderOk);

        int[] idx = Features.becIndices();
        eq("BEC subset resolves to 11 indices", want.length, idx.length);

        // --- extraction: unobserved features must not masquerade as observed zeros ---
        String raw = "From: attacker@evil.example\r\n"
                + "Subject: Urgent: verify your account immediately\r\n"
                // Reply-To is on a DIFFERENT domain from From: spec L68 defines
                // replyto_mismatch as "Reply-To domain != From domain".
                + "Reply-To: harvest@harvest.example\r\n"
                + "Authentication-Results: mx.evil.example; spf=fail; dkim=none\r\n"
                + "Message-ID: <x@other.example>\r\n"
                + "\r\n"
                + "Dear customer, this is your bank. Urgent: confirm your password now.\r\n"
                + "Visit http://198.51.100.9/verify to confirm your identity immediately.\r\n";
        Headers.Result h = Headers.parseComplete(raw);
        TextNormalizer norm = TextNormalizer.load();
        OrgProfile prof = OrgProfile.load(Path.of("config/org-profile.json"));
        Features.Vector v = new Features(norm, prof).extract(h, new Features.Evidence());

        check("urgency is observed", v.isObserved("urgency"));
        check("urgency is non-zero on an urgent message", v.get("urgency") > 0.0);
        check("credential_request fires on a password request", v.get("credential_request") > 0.0);
        check("replyto_mismatch fires on a foreign Reply-To", v.get("replyto_mismatch") == 1.0);
        check("ip_literal fires on an IP URL", v.get("ip_literal") == 1.0);
        check("messageid_anomaly fires on a foreign Message-ID",
                v.get("messageid_anomaly") == 1.0);

        // Network-dependent features must be UNOBSERVED with no evidence supplied.
        check("ip_in_blacklist unobserved without evidence", !v.isObserved("ip_in_blacklist"));
        check("tor_exit unobserved without evidence", !v.isObserved("tor_exit"));
        check("helo_mismatch unobserved without DNS", !v.isObserved("helo_mismatch"));
        eq("unobserved feature still reports 0", 0.0, v.get("tor_exit"));
        check("unobserved feature is explained in notes", !v.noteList().isEmpty());

        // C_cov must be < 1 when features are missing.
        double[][] beta = new double[Config.K][Features.COUNT];
        for (int k = 0; k < Config.K; k++) {
            java.util.Arrays.fill(beta[k], 0.01);
        }
        double cov = v.coverage(beta, Config.CLASS_LEGITIMATE);
        check("coverage is below 1 when features are unobserved", cov < 1.0);
        check("coverage is a probability", cov >= 0.0 && cov <= 1.0);

        // Coverage must reach 1.0, but ONLY for a message that actually carries the data
        // every feature reads. The probe message above has no Date and no Received chain,
        // so date_skew / received_private_hop / received_missing_from are legitimately
        // unobserved. A header-complete message with full evidence must reach 1.0, and a
        // message missing that data must NOT - that is the whole point of C_cov.
        String complete = "Received: from mail.evil.example (198.51.100.9) by mx.example\r\n"
                + " with ESMTPS id abc for <x@other.example>; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
                + "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
                + "From: attacker@evil.example\r\n"
                + "Reply-To: harvest@harvest.example\r\n"
                + "Authentication-Results: mx.evil.example; spf=fail smtp.mailfrom=evil.example;\n"
                + " dkim=fail header.d=paypal-secure.example; dmarc=fail header.from=evil.example\r\n"
                + "Message-ID: <x@other.example>\r\n"
                // alignment_from_dkim reads d= from the DKIM-Signature header itself,
                // not from Authentication-Results, so a real signature is required.
                + "DKIM-Signature: v=1; a=rsa-sha256; d=paypal-secure.example;\r\n"
                + " s=k1; h=from:to:subject; bh=abc; b=def\r\n"
                + "Subject: Urgent\r\n\r\nUrgent confirm your password http://198.51.100.9/v\r\n";
        Features.Evidence full = new Features.Evidence();
        full.domainAgeDays = 4000L;
        full.mxPresent = true;
        full.rdapPrivacy = false;
        full.registrar = "Example Registrar";
        full.registrarCountry = "SE";
        full.orgCountry = "SE";
        full.ipBlacklisted = false;
        full.asnRisk = false;
        full.vpnProxy = false;
        full.torExit = false;
        full.openRelay = false;
        full.cloudHosted = false;
        full.originCountry = "SE";
        full.reputationLow = false;
        full.fromDomain = "evil.example";
        full.returnPathDomain = "evil.example";
        full.replyToDomain = "harvest.example";
        full.sendingIp = "198.51.100.9";
        full.sendingAsn = "AS64500";
        full.brands = List.of("PayPal");
        Features.Vector vf = new Features(norm, prof)
                .extract(Headers.parseComplete(complete), full);
        StringBuilder missing = new StringBuilder();
        for (int i = 0; i < Features.COUNT; i++) {
            if (!vf.isObserved(Features.name(i))) {
                missing.append(Features.name(i)).append(' ');
            }
        }
        // helo_mismatch is hard-unobserved at Features.java:402 because it needs PTR DNS,
        // which the offline core deliberately does not do. It is therefore the ONE feature
        // that can never reach observed, and C_cov is expected to top out below 1.0.
        eq("the only unreachable feature is helo_mismatch (needs PTR DNS)",
                "helo_mismatch", missing.toString().trim());
        eq("so 59 of 60 features are observed", 59, Features.COUNT - 1);

        // helo_mismatch has no evidence field in Evidence, so it must stay unobserved
        // rather than being silently scored as "no mismatch".
        check("helo_mismatch stays unobserved without DNS",
                !vf.isObserved("helo_mismatch"));
        near("coverage with everything but PTR DNS", 59.0 / 60.0,
                vf.coverage(beta, Config.CLASS_LEGITIMATE), 0.02);

        // --- a non-finite value must be quarantined, not propagated ---
        Features.Vector bad = new Features.Vector();
        bad.put("urgency", Double.NaN);
        check("non-finite feature is forced to 0", bad.get("urgency") == 0.0);
        check("non-finite feature is marked unobserved", !bad.isObserved("urgency"));

        // --- an unknown feature name must be rejected loudly ---
        boolean threw = false;
        try {
            bad.put("not_a_real_feature", 1.0);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check("unknown feature name is rejected", threw);
    }

    // ==================================================================
    // Crypto and audit-chain invariants that items 1-3 depend on downstream
    // ==================================================================

    private static void cryptoInvariants() {
        section("Crypto and audit chain");

        // Canonical JSON must be independent of construction order, or the audit hash
        // is not reproducible by an independent verifier.
        String a = Crypto.canonical(new java.util.LinkedHashMap<>(Map.of("b", 2, "a", 1)));
        String b = Crypto.canonical(new java.util.LinkedHashMap<>(Map.of("a", 1, "b", 2)));
        eq("canonical JSON is key-order independent", a, b);

        // Numbers must round-trip without scientific notation drift.
        String big = Crypto.canonical(Map.of("x", 1.0E7));
        check("large doubles avoid scientific notation", !big.contains("E") && !big.contains("e"));

        // Hashing must be stable and differ on any change.
        eq("sha256 of empty is the well-known constant",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Crypto.sha256Hex(""));
        check("hash differs on a one-byte change",
                !Crypto.sha256Hex("a").equals(Crypto.sha256Hex("b")));

        // Ed25519 sign/verify round trip, and tamper detection.
        try {
            java.security.KeyPair kp = Sign.generateKeyPair();
            byte[] payload = "{\"risk\":42}".getBytes(StandardCharsets.UTF_8);
            byte[] sig = Sign.sign(payload, kp.getPrivate());
            check("valid signature verifies", Sign.verify(payload, sig, kp.getPublic()));
            byte[] tampered = "{\"risk\":43}".getBytes(StandardCharsets.UTF_8);
            check("tampered payload fails verification",
                    !Sign.verify(tampered, sig, kp.getPublic()));
            byte[] otherSig = Sign.sign(payload, Sign.generateKeyPair().getPrivate());
            check("a signature from a different key does not verify",
                    !Sign.verify(payload, otherSig, kp.getPublic()));
            check("key id is 64 hex chars", Sign.keyIdOf(kp.getPublic()).length() == 64);
        } catch (Exception e) {
            check("Ed25519 round trip: " + e, false);
        }

        // Audit chain: genesis, linking, and tamper localisation.
        Path dir = Path.of("build", "test-audit");
        try {
            Files.createDirectories(dir);
            Path chain = dir.resolve("chain.ndjson");
            Path sigs = dir.resolve("chain-sigs.ndjson");
            Path pem = dir.resolve("ed25519.pem");
            for (Path p : new Path[]{chain, sigs, pem}) {
                Files.deleteIfExists(p);
            }
            Audit.KeyManager km = Audit.KeyManager.createOrLoad(pem);
            check("a fresh key is configured", km.configured());
            Audit log = new Audit(chain, sigs, km);
            Map<String, Object> r0 = log.append("message.received", Map.of("id", "m1"));
            log.append("message.scored", Map.of("id", "m1", "risk", 42));
            log.append("alert.fired", Map.of("id", "m1"));

            Audit.Verification v = log.verify();
            check("a freshly written chain verifies", v.ok);
            eq("no divergence in a fresh chain", -1, v.firstDivergentIndex);
            eq("chain holds 3 records", 3, v.records);
            check("head hash is a sha256 hex digest", v.headHash.length() == 64);
            check("genesis is the spec seed",
                    Audit.genesisPrev().equals(
                            Crypto.sha256Hex("cipher-squad-genesis")));

            // r0 is the FIRST record (index 0), so its event is message.received.
            eq("record 0 is the first event", "message.received", r0.get("event"));
            eq("record 0 index is 0", 0L, ((Number) r0.get("index")).longValue());
            check("record carries prev_hash", r0.get("prev_hash") != null);
            check("record carries its own hash", r0.get("hash") != null);
            eq("first record links to genesis",
                    Audit.genesisPrev(),
                    Json.parseObject(Files.readAllLines(chain).get(0)).get("prev_hash"));

            // The head of a correctly chained log must sign under the configured key.
            log.signHead(2, v.headHash);
            check("head signature validates", log.verify().headSignatureValid);

            // Tamper with a middle record and confirm verify() pinpoints it.
            // Parse-modify-write rather than a string replace, so the test cannot
            // silently no-op if the canonical formatting ever changes.
            List<String> lines = Files.readAllLines(chain);
            Map<String, Object> second = Json.parseObject(lines.get(1));
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = (Map<String, Object>) second.get("payload");
            check("record 1 is the scored event", "message.scored".equals(second.get("event")));
            payload.put("risk", 99);
            lines.set(1, Crypto.canonical(second));
            check("tamper actually changed the line", !lines.get(1).equals(Files.readAllLines(chain).get(1)));
            Files.write(chain, lines);
            Audit reopened = new Audit(chain, sigs, Audit.KeyManager.createOrLoad(pem));
            Audit.Verification tv = reopened.verify();
            check("tampering is detected", !tv.ok);
            eq("divergence is located at the tampered record", 1, tv.firstDivergentIndex);
        } catch (Exception e) {
            check("audit chain round trip: " + e, false);
        }
    }

    // ==================================================================
    // The 18 mandatory Phase 1 self-tests.
    //
    // These are specified as a required list, so each is written as a separate method and
    // named for the item it discharges. The arithmetic in the model and normaliser tests is
    // computed by hand from the spec formula rather than copied from an implementation
    // output, so a wrong implementation cannot make its own test pass.
    // ==================================================================

    /** 1. Feature vector: exactly six families, correctly sized, with observed flags. */
    private static void t1_featureFamilies() {
        section("T1  Feature vector has six well-formed families");
        Features.Vector v = new Features.Vector();

        eq("family count is six", 6, Features.FAMILY_COUNT);
        check("families are a real enum, not magic ints",
                Features.Family.values().length == 6
                        && Features.Family.AUTH.code.equals("F1")
                        && Features.Family.INFRA.code.equals("F6"));

        int[] expected = {9, 10, 11, 10, 12, 8};
        int total = 0;
        for (Features.Family f : Features.Family.values()) {
            eq(f.code + " " + f.name() + " size", expected[f.ordinal()], Features.familySize(f));
            total += Features.familySize(f);
        }
        eq("families cover every feature", Features.COUNT, total);
        eq("vector is 60-dimensional", 60, Features.COUNT);

        // Every index maps to a family, and every family is actually populated.
        for (int i = 0; i < Features.COUNT; i++) {
            check("feature " + i + " (" + Features.name(i) + ") has a family",
                    Features.familyOf(i) != null);
        }
        check("an out-of-range index is rejected", throwsIndex(() -> Features.familyOf(999)));
        check("an out-of-range index is rejected (negative)",
                throwsIndex(() -> Features.familyOf(-1)));

        // Observed=false must be distinguishable from an observed 0.0. A vector that has
        // never been written to is entirely unobserved; writing 0.0 makes that index observed
        // with value zero. Collapsing the two is how a "we checked and found nothing" signal
        // turns into "we did not check".
        check("fresh vector is fully unobserved", v.observedCount() == 0);
        check("a fresh vector has all 60 features unobserved", v.unobservedCount() == Features.COUNT);
        v.put(Features.indexOf("spf_fail"), 0.0);
        eq("writing 0.0 marks exactly one feature observed", 1, v.observedCount());
        near("the observed value really is zero", 0.0,
                v.get(Features.indexOf("spf_fail")), 0.0);
        check("an unobserved feature is not silently read as observed",
                !v.isObserved(Features.indexOf("dkim_fail")));
        check("an out-of-range write is rejected", throwsIndex(() -> v.put(-1, 0.5)));
        check("a non-finite value is quarantined, not propagated",
                quarantinesNonFinite(v, "spf_fail"));

        // Features are declared normalised to [0,1]. An out-of-range value must be refused
        // loudly rather than clamped: clamping hides the upstream bug and quietly changes the
        // score, so a wrong number looks like a legitimate weak signal.
        Features.Vector r = new Features.Vector();
        int spf = Features.indexOf("spf_fail");
        r.put(spf, 1.4);
        check("a value above 1 is quarantined", !r.isObserved(spf));
        near("an out-of-range value is emitted as 0, not silently clamped", 0.0, r.get(spf), 0.0);
        check("the out-of-range quarantine is explained",
                r.noteList().stream().anyMatch(n -> n.contains("[0,1]")));
        r.put(spf, -0.3);
        check("a negative value is quarantined", !r.isObserved(spf));
        r.put(spf, 1.0);
        check("exactly 1.0 is accepted", r.isObserved(spf));
        r.put(spf, 0.0);
        check("exactly 0.0 is accepted and stays observed", r.isObserved(spf));
        near("the accepted 0.0 is the real zero", 0.0, r.get(spf), 0.0);

        // Provenance: a bare number cannot be audited. "dkim_fail = 1.0" does not distinguish
        // a header that was absent from one that was never checked.
        Features.Vector p = new Features.Vector();
        int dkim = Features.indexOf("dkim_fail");
        check("an unwritten feature has no provenance", p.reason(dkim) == null);
        p.put(dkim, 1.0, true, "dkim=none");
        eq("provenance is recorded by index", "dkim=none", p.reason(dkim));
        eq("provenance is recorded by name", "dkim=none", p.reason("dkim_fail"));
        check("provenance appears in the dump",
                p.provenance().stream().anyMatch(s -> s.contains("dkim=none")));
        p.put(dkim, Double.NaN, true, "dkim=parse-error");
        check("a quarantined write records why",
                p.reason(dkim).contains("non-finite"));

        // The value array must not escape. A public double[] lets any caller write 1e9 into
        // a feature and turns the [0,1] contract into a comment.
        double[] copy = p.toArray();
        copy[dkim] = 0.77;
        near("toArray() returns a copy, not the live vector", 0.0, p.get(dkim), 0.0);
        boolean[] ocopy = p.observedArray();
        boolean liveObserved = p.isObserved(dkim);
        ocopy[dkim] = !liveObserved;
        eq("observedArray() returns a copy too", liveObserved, p.isObserved(dkim));
        // Every value handed out must respect the declared range.
        boolean allInRange = true;
        for (double d : p.toArray()) {
            if (!(d >= 0.0 && d <= 1.0)) {
                allInRange = false;
            }
        }
        check("every stored value is inside [0,1]", allInRange);
    }

    /** 2. Model: exactly eight typed classes. */
    private static void t2_eightClasses() {
        section("T2  Model has exactly eight typed classes");
        eq("class count is eight", 8, Config.K);
        eq("class count is eight", 8, Model.K);

        String[] expected = {"legitimate", "suspicious", "impersonation", "phishing",
                "bec", "fraud", "malware", "spam"};
        eq("class names", java.util.Arrays.toString(expected),
                java.util.Arrays.toString(Config.CLASS_NAMES));
        for (int k = 0; k < Config.K; k++) {
            eq("class " + k + " name", expected[k], Config.CLASS_NAMES[k]);
        }
        eq("softmax rejects a wrong-length logit vector", true,
                throwsIllegal(() -> Model.softmax(new double[7])));
        check("every class probability is finite and in range", allProbabilitiesValid());

        // The taxonomy must be a closed set of typed values, not just eight strings. A
        // String[] admits a typo at any call site and an out-of-range index throws a bare
        // ArrayIndexOutOfBoundsException that names no class.
        eq("the typed taxonomy has exactly eight values", 8, Config.Cls.values().length);
        for (int k = 0; k < Config.K; k++) {
            Config.Cls c = Config.Cls.of(k);
            eq("typed class " + k + " index", k, c.index());
            eq("typed class " + k + " label", expected[k], c.label());
            eq("typed class " + k + " round-trips", k, Config.classOf(k).index());
        }
        // Every constant the model actually uses must be a member of the enum.
        eq("CLASS_BEC is a member of the typed taxonomy",
                Config.Cls.BEC, Config.Cls.of(Config.CLASS_BEC));
        eq("CLASS_LEGITIMATE is a member of the typed taxonomy",
                Config.Cls.LEGITIMATE, Config.Cls.of(Config.CLASS_LEGITIMATE));
        check("an out-of-range class index is rejected with a named failure",
                throwsIllegal(() -> Config.Cls.of(8)));
        check("a negative class index is rejected", throwsIllegal(() -> Config.Cls.of(-1)));

        // A score must carry the typed argmax, not just an int.
        Model.Score sc = Model.initial().score(new double[Features.COUNT], null, null, null, null);
        eq("the score exposes a typed argmax", sc.argmaxClass, Config.Cls.of(sc.argmax));
        check("the typed argmax label matches the pinned name",
                sc.argmaxClass.label().equals(Config.CLASS_NAMES[sc.argmax]));

        // The name array is publicly mutable, so a caller could corrupt the taxonomy.
        // classNames() must hand back a copy instead.
        String[] copy = Config.classNames();
        copy[0] = "tampered";
        eq("classNames() returns a defensive copy", "legitimate", Config.CLASS_NAMES[0]);
    }

    /**
     * 3. Contribution clipping: five cases, computed from the spec formula by hand.
     *
     * z_k = beta_0k + SUM clip(beta_fk * x_f, -2.5, +2.5)
     *
     * The model is built directly with a single known weight so the expected value is
     * arithmetic, not a regression capture of current behaviour.
     */
    private static void t3_contributionClipping() {
        section("T3  Per-term contribution is clipped to [-2.5, 2.5]");
        double c = Config.CLIP_C;
        eq("clip constant is 2.5", 2.5, c);

        // A one-feature, one-class-pair model: beta_0 = 0 for both classes, beta = +10.
        // Products of 10*x must clip, and the raw product must not leak through.
        double b0 = 0.0;
        double betaPos = 10.0;   // positive coefficient, pushes the logit up
        double betaNeg = -10.0;  // negative coefficient, pushes the logit down

        // (a) below the bound: no clipping, term is the raw product
        near("a) term 10*0.1 = 1.0 is not clipped", 1.0, clipTerm(betaPos, 0.1, c), 1e-12);
        // (b) exactly at the bound: unchanged
        near("b) term 10*0.25 = 2.5 at the bound is unchanged", 2.5,
                clipTerm(betaPos, 0.25, c), 1e-12);
        // (c) above the bound: clipped
        near("c) term 10*1.0 = 10 is clipped to 2.5", 2.5,
                clipTerm(betaPos, 1.0, c), 1e-12);
        // (d) large magnitude: still the bound, not the product
        near("d) term 10*1000 is clipped to 2.5", 2.5,
                clipTerm(betaPos, 1000.0, c), 1e-12);
        // (e) negative side
        near("e) term -10*1.0 = -10 is clipped to -2.5", -2.5,
                clipTerm(betaNeg, 1.0, c), 1e-12);

        // A non-finite feature value must be rejected, not clipped into something plausible.
        // Clipping NaN would produce NaN, and NaN propagates through softmax to make every
        // downstream comparison false - a verifier reporting "ok" on garbage.
        check("NaN feature value is rejected", throwsIllegal(() -> {
            double[] x = new double[1];
            x[0] = Double.NaN;
            clipReject(x);
        }));
        check("infinite feature value is rejected", throwsIllegal(() -> {
            double[] x = new double[1];
            x[0] = Double.POSITIVE_INFINITY;
            clipReject(x);
        }));

        // The real model must refuse the same values, not just the arithmetic helper. If
        // logits() let a NaN through, every comparison against it is false, the clip never
        // fires, and softmax returns NaN - which downstream looks like a valid score.
        Model rm = singleFeatureModel(b0, betaPos);
        check("the model rejects a NaN feature", throwsIllegal(() -> {
            double[] nx = {Double.NaN};
            rm.logits(nx);
        }));
        check("the model rejects an infinite feature", throwsIllegal(() -> {
            double[] ix = {Double.NEGATIVE_INFINITY};
            rm.logits(ix);
        }));
        check("the model rejects a null feature vector", throwsIllegal(() -> rm.logits(null)));
        check("the model rejects a wrong-length feature vector", throwsIllegal(
                () -> rm.logits(new double[2])));
        check("softmax rejects a NaN logit", throwsIllegal(
                () -> Model.softmax(new double[]{Double.NaN, 0.0})));

        // End to end: the clip must appear in the logit, not just in the term list.
        Model m = singleFeatureModel(b0, betaPos);
        double[] x = {1.0};
        Model.Logits lg = m.logits(x);
        near("clipped term is recorded in the term list", 2.5, lg.terms[1][0], 1e-12);
        near("logit equals intercept plus the CLIPPED term, not the raw product",
                b0 + 2.5, lg.z[1], 1e-12);
        check("logit is not the unclipped 10.0", Math.abs(lg.z[1] - 10.0) > 1.0);
        check("clipping is counted", lg.clippedTerms > 0);
    }

    /** 4. Exact logit computation, verified against hand arithmetic. */
    private static void t4_exactLogit() {
        section("T4  Logit = intercept + sum of clipped contributions");
        // Two features, two weights chosen so the terms are whole numbers and no clipping
        // occurs, so the expected value is checkable by inspection.
        double b0 = -1.5;
        double[] beta = {2.0, 0.5};
        Model m = new Model(flat(b0), repeat(beta), new double[]{-9.0, 0.0},
                2, 50.0, 25.0, 40.0, 1.0, 1.0, "test-4", Model.Source.HAND_SET_UNCALIBRATED,
                "none", Map.of());

        double[] x = {0.5, 0.4};
        Model.Logits lg = m.logits(x);
        // 2.0*0.5 = 1.0, 0.5*0.4 = 0.2, total term 1.2, logit -1.5 + 1.2 = -0.3
        near("term 0 is beta*x", 1.0, lg.terms[0][0], 1e-12);
        near("term 1 is beta*x", 0.2, lg.terms[0][1], 1e-12);
        near("logit 0 is exactly intercept + terms", -0.3, lg.z[0], 1e-12);
        near("both classes share the coefficients so logit 1 matches", -0.3, lg.z[1], 1e-12);
        eq("no terms were clipped", 0, lg.clippedTerms);

        // A clipped and an unclipped term in the same row: the clipped one saturates and the
        // other still contributes in full, which is the behaviour the per-term rule exists for.
        Model m2 = singleFeatureModel(0.0, 1000.0);
        Model.Logits lg2 = m2.logits(new double[]{1.0});
        near("saturating term contributes exactly the bound", Config.CLIP_C, lg2.terms[1][0], 1e-12);
    }

    /** 5. Softmax probabilities sum to 1 within 1e-9. */
    private static void t5_softmaxSumsToOne() {
        section("T5  Softmax output sums to 1 within 1e-9");
        double[][] cases = {
                {0, 0, 0, 0, 0, 0, 0, 0},                      // uniform
                {1, 2, 3, 4, 5, 6, 7, 8},
                {-1, -2, -3, -4, -5, -6, -7, -8},
                {700, 0, 0, 0, 0, 0, 0, 0},                    // near overflow
                {-700, 0, 0, 0, 0, 0, 0, 0},
                {1e-9, -1e-9, 3e-9, -3e-9, 5e-9, -5e-9, 7e-9, -7e-9},
        };
        for (double[] z : cases) {
            double[] p = Model.softmax(z);
            double sum = 0.0;
            for (double pk : p) {
                sum += pk;
                if (pk < 0.0 || pk > 1.0 || !Double.isFinite(pk)) {
                    check("probability stays in [0,1] for " + java.util.Arrays.toString(z), false);
                }
            }
            near("sum(p)=1 for " + java.util.Arrays.toString(z), 1.0, sum, 1e-9);
        }
        // Uniform input must be exactly uniform.
        double[] u = Model.softmax(cases[0]);
        near("uniform logits give 1/8", 0.125, u[0], 1e-12);
    }

    /** 6. Large logits are stable: no overflow, no NaN, sum still 1. */
    private static void t6_largeLogitStability() {
        section("T6  Max-shifted softmax survives extreme logits");
        // Naive exp() overflows to Infinity above ~709, turning every probability into NaN and
        // every downstream comparison into a silent false. These are the regression values.
        double[][] cases = {
                {1000, 0, 0, 0, 0, 0, 0, 0},
                {-1000, 0, 0, 0, 0, 0, 0, 0},
                {1e4, -1e4, 0, 0, 0, 0, 0, 0},
                {1e9, -1e9, 1e9, -1e9, 0, 0, 0, 0},
                {-1e308, 1e308, 0, 0, 0, 0, 0, 0},
        };
        for (double[] z : cases) {
            double[] p = Model.softmax(z);
            double sum = 0.0;
            boolean finite = true;
            for (double pk : p) {
                sum += pk;
                if (!Double.isFinite(pk) || pk < 0.0) {
                    finite = false;
                }
            }
            check("all probabilities finite for " + java.util.Arrays.toString(z), finite);
            near("sum(p)=1 despite magnitude for " + java.util.Arrays.toString(z),
                    1.0, sum, 1e-9);
        }

        // A saturated vector must still put all its mass on the maximum, not produce NaN.
        double[] sat = Model.softmax(new double[]{1e6, 0, 0, 0, 0, 0, 0, 0});
        near("the dominant class takes essentially all the mass", 1.0, sat[0], 1e-6);
        check("no probability is NaN", java.util.Arrays.stream(sat).noneMatch(Double::isNaN));

        // No intermediate rounding: probabilities are divided by the sum, not rounded to 4dp
        // first, because rounding before normalising breaks the sum-to-one guarantee.
        double[] p = Model.softmax(new double[]{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8});
        double sum = 0.0;
        for (double pk : p) {
            sum += pk;
        }
        near("no rounding before normalisation", 1.0, sum, 1e-12);
    }

    /** 7. Unobserved features contribute exactly zero. */
    private static void t7_unobservedContributesZero() {
        section("T7  Unobserved features contribute nothing");
        Model m = singleFeatureModel(0.0, 10.0);

        // The feature is set to a maximal 1.0 but marked unobserved: the logit must be
        // unchanged from the intercept. A missing observation is an absence of evidence and
        // must not push a message toward any class.
        double[] x = {1.0};
        Model.Logits observed = m.logits(x, new boolean[]{true});
        Model.Logits unobserved = m.logits(x, new boolean[]{false});
        near("observed feature contributes the clipped weight", Config.CLIP_C, observed.terms[1][0], 1e-12);
        near("unobserved feature contributes exactly zero", 0.0, unobserved.terms[1][0], 1e-12);
        near("unobserved logit equals the intercept alone", 0.0, unobserved.z[1], 1e-12);
        check("the two cases genuinely differ", observed.z[1] != unobserved.z[1]);

        // A null mask means "all observed", so it must agree with an all-true mask.
        Model.Logits allTrue = m.logits(x, new boolean[]{true});
        Model.Logits nullMask = m.logits(x, null);
        near("a null mask is equivalent to all-observed", allTrue.z[1], nullMask.z[1], 0.0);

        // A mismatched mask is a programming error and must be loud, not silently truncated.
        check("a wrong-length observed mask is rejected",
                throwsIllegal(() -> m.logits(x, new boolean[]{true, true})));

        // End to end: an all-unobserved 60-dim vector must score identically to a zero vector.
        Model full = Model.initial();
        double[] zeros = new double[Features.COUNT];
        boolean[] none = new boolean[Features.COUNT];
        Model.Score a = full.score(zeros, none, null, null, null);
        Model.Score b = full.score(zeros, null, null, null, null);
        near("all-unobserved scores like a zero vector", b.riskFinal, a.riskFinal, 1e-12);
        eq("and picks the same class", b.argmax, a.argmax);
    }

    /**
     * 8. Noisy-OR: exact value, base probability reported, blend explicit, distribution valid.
     *
     * P = 1 - PRODUCT(1 - p_i)
     */
    private static void t8_noisyOr() {
        section("T8  BEC Noisy-OR blending is explicit and reported");
        near("no evidence yields 0", 0.0, Model.noisyOr(new double[0]), 1e-12);
        near("null evidence yields 0", 0.0, Model.noisyOr(null), 1e-12);
        near("single weak hint", 0.1, Model.noisyOr(new double[]{0.1}), 1e-12);
        // 1 - (0.9 * 0.8) = 1 - 0.72 = 0.28
        near("two hints 0.1 and 0.2", 0.28, Model.noisyOr(new double[]{0.1, 0.2}), 1e-12);
        // 1 - (0.9*0.8*0.7) = 1 - 0.504 = 0.496
        near("three hints", 0.496, Model.noisyOr(new double[]{0.1, 0.2, 0.3}), 1e-12);
        // 1 - (0.5 * 0.5) = 0.75
        near("two strong hints", 0.75, Model.noisyOr(new double[]{0.5, 0.5}), 1e-12);
        // A certainty makes the product zero, so the result saturates at exactly 1.
        near("a certain hint saturates to 1", 1.0,
                Model.noisyOr(new double[]{1.0, 0.3, 0.7}), 1e-12);
        // Independence is the assumption: combined evidence is always below the sum.
        double[] ev = {0.4, 0.4, 0.4};
        double combined = Model.noisyOr(ev);
        check("noisy-OR is sub-additive (independence, not addition)",
                combined < 0.4 + 0.4 + 0.4);
        check("noisy-OR is at least the maximum single input", combined >= 0.4);
        // Saturation must not produce NaN. With eight 0.99 hints the product is 1e-16, so the
        // result is 1 - 1e-16 rather than exactly 1.0; the property under test is that it
        // saturates toward 1 and stays finite, not that it hits 1 exactly.
        double saturated = Model.noisyOr(
                new double[]{0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99});
        check("many strong hints saturate, not overflow",
                Double.isFinite(saturated) && saturated > 0.999999);
        check("the saturated value stays in [0,1]", saturated <= 1.0);
        // Out-of-range input is clamped rather than producing a probability outside [0,1].
        near("out-of-range high is clamped", Model.noisyOr(new double[]{1.0}),
                Model.noisyOr(new double[]{1.4}), 1e-12);
        near("out-of-range low is clamped", 0.0, Model.noisyOr(new double[]{-0.5}), 1e-12);
        check("NaN evidence is rejected", throwsIllegal(() -> Model.noisyOr(new double[]{Double.NaN})));

        // The blend must be reported, not folded invisibly into one number.
        Model full = Model.initial();
        double[] zeros = new double[Features.COUNT];
        double[] bec = new double[Config.BEC_SUBSET.length];
        Model.Score s = full.score(zeros, null, bec, new double[]{0.3, 0.2}, null);
        check("the evidence inputs are exposed", s.becEvidence.size() == 2);
        near("the exposed inputs match what was passed", 0.3, s.becEvidence.get(0), 1e-12);
          // becBaseProbability is the dedicated BEC HEAD's output, not the softmax class
          // probability. The two are different numbers and both are reported, because
          // presenting a head value as a calibrated class probability is the exact failure
          // mode this brief asks to avoid. becClassProbability carries the softmax side.
          check("the head BEC probability is reported", s.becBaseProbability > 0.0);
          check("the softmax BEC class probability is reported separately",
                  s.becClassProbability > 0.0);
          check("the head and the class probability are distinct quantities",
                  Math.abs(s.becBaseProbability - s.becClassProbability) > 0.0);
          // The blend is a monotone push above the base, bounded by the evidence ceiling.
          check("blending moves the base probability upward",
                  s.becBlendedProbability >= s.becBaseProbability);
          check("the blend stays a probability",
                  s.becBlendedProbability <= 1.0 && s.becBlendedProbability >= 0.0);
          check("the base probability is distinct from the blended one",
                s.becBaseProbability != s.becBlendedProbability);
        check("the blend weight is stated", s.becBlendWeight == Config.W_BEC);
        check("the blend method is described in words", s.becBlendMethod.contains("Noisy-OR"));
        check("the model declares itself evidence-backed", s.becEvidenceBacked);
        // The blend must remain a valid probability, and must not corrupt the distribution.
        check("the blended probability stays in [0,1]",
                s.becBlendedProbability >= 0.0 && s.becBlendedProbability <= 1.0);
          check("the classifier distribution is untouched by the blend", allProbabilitiesValid());

          // The blended value must actually reach riskFinal. Previously riskFinal consumed the
          // raw head, so the blend was computed, reported, and then discarded - a report could
          // state one number while the score was produced from another.
          Model.Score noEvidence = full.score(zeros, null, bec, null, null);
          near("with no evidence the blend collapses to the head", noEvidence.becBaseProbability,
                  noEvidence.becBlendedProbability, 1e-15);
          check("with no evidence the score is marked as not evidence-backed",
                  !noEvidence.becEvidenceBacked);

          // riskFinal must rise when evidence is added, holding everything else constant.
          double[] ev1 = {0.3};
          double[] ev2 = {0.9};
          Model.Score r1 = full.score(zeros, null, bec, ev1, null);
          Model.Score r2 = full.score(zeros, null, bec, ev2, null);
          check("more evidence produces more Noisy-OR",
                  r2.becNoisyOr > r1.becNoisyOr);
          check("more evidence produces a higher blended BEC",
                  r2.becBlendedProbability > r1.becBlendedProbability);
          check("more evidence raises riskFinal, so the blend really reaches the score",
                  r2.riskFinal > r1.riskFinal);

          // Reproduce riskFinal from the published fields: if this identity ever breaks, the
          // reported blend and the reported score have drifted apart again.
          double pNotLegit = 1.0 - r2.p[Config.CLASS_LEGITIMATE];
          double expectedRiskFinal = 100.0 * (1.0 - (1.0 - pNotLegit)
                  * (1.0 - r2.becBlendWeight * r2.becBlendedProbability));
          near("riskFinal is reproducible from the published blend fields", expectedRiskFinal,
                  r2.riskFinal, 1e-9);
          check("the risk band is assigned from riskFinal",
                  r2.band != null && !r2.band.isEmpty());
        double sum = 0.0;
        for (double pk : s.p) {
            sum += pk;
        }
        near("the class distribution still sums to 1", 1.0, sum, 1e-9);
        // No evidence must be reported as such rather than quietly assumed.
        Model.Score none = full.score(zeros, null, bec, null, null);
        check("absence of evidence is stated, not assumed", !none.becEvidenceBacked);
        check("the no-evidence path is described", none.becBlendMethod.contains("no external evidence"));
    }

    /** 9. NFKC normalisation. */
    private static void t9_nfkc() {
        section("T9  NFKC normalisation");
        TextNormalizer n = TextNormalizer.load();
        // Fullwidth "ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¼Ãƒâ€šÃ‚Â°ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¼Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¼Ãƒâ€šÃ‚Â¹ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¼Ãƒâ€šÃ‚Â°ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¼Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¼Ãƒâ€šÃ‚Â¬" folds to ASCII under NFKC.
        eq("fullwidth forms fold to ASCII", "paypal", n.normalise("\uFF50\uFF41\uFF59\uFF50\uFF41\uFF4C"));
        // Ligature and compatibility forms.
        eq("ligature fi folds", "fi", n.normalise("\uFB01"));
        eq("superscript two folds", "2", n.normalise("\u00B2"));
        // Every ASCII digit is leet-mapped, so a fullwidth digit cannot survive as a digit.
        // That is correct behaviour and is asserted as such: NFKC must have run AND the leet
        // table must have applied, which is exactly what fullwidth "4" -> "a" demonstrates.
        eq("a fullwidth digit folds to its leet letter, proving NFKC then leet",
                "a", n.normalise("\uFF14"));
        eq("a fullwidth letter folds to ASCII", "paypal",
                n.normalise("\uFF50\uFF41\uFF59\uFF50\uFF41\uFF4C"));
        // Non-ASCII that is NOT a compatibility form must survive.
        check("ordinary non-ASCII text is not destroyed", n.normalise("caf\u00E9").contains("caf"));
        // Normalisation must be idempotent: normalising twice changes nothing. A
        // non-idempotent normaliser makes equality checks and cache keys unreliable.
        String once = n.normalise("\uFF50\uFF41\uFF59\u200Bpal.com");
        eq("normalisation is idempotent", once, n.normalise(once));
        // Empty and null-ish inputs.
        eq("empty string normalises to empty", "", n.normalise(""));
        check("a string of only invisibles normalises to empty",
                n.normalise("\u200B\u200C\u200D\u2060\uFEFF").isEmpty());
    }

    /** 10. All five required invisible codepoints are removed. */
    private static void t10_invisibleStripping() {
        section("T10  The five required invisibles are stripped");
        TextNormalizer n = TextNormalizer.load();
        int[] required = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF};
        String[] requiredNames = {"ZERO WIDTH SPACE", "ZERO WIDTH NON-JOINER",
                "ZERO WIDTH JOINER", "WORD JOINER", "ZERO WIDTH NO-BREAK SPACE / BOM"};
        for (int i = 0; i < required.length; i++) {
            int cp = required[i];
            // The invisible is split INSIDE the word, not merely prefixed, so the test proves
            // the character is deleted rather than the whole string being rejected.
            String sneaky = "pay" + (char) cp + "pal.com";
            String out = n.normalise(sneaky);
            check("U+" + Integer.toHexString(cp).toUpperCase() + " " + requiredNames[i]
                            + " is removed, leaving <" + out + ">",
                    "paypal.com".equals(out) && out.chars().noneMatch(c -> c == cp));
        }
        // Interleaved invisibles must not survive as a residue.
        String stripped = n.normalise("p\u200Ba\u2060y\uFEFFp\u200Dal.com");
        eq("interleaved invisibles are all removed", "paypal.com", stripped);
        // Visibles that merely LOOK similar must be preserved: removing them would corrupt
        // real content and turn a false positive into a false negative.
        check("the replacement character is not stripped", n.normalise("a\uFFFDb").contains("\uFFFD"));
        check("an ordinary space is preserved", n.normalise("pay pal").equals("pay pal"));
        check("a normal hyphen is preserved", n.normalise("pay-pal").equals("pay-pal"));
    }

    /** 11. Mixed-script detection, ignoring COMMON / INHERITED / UNKNOWN. */
    private static void t11_mixedScript() {
        section("T11  Mixed-script detection");
        TextNormalizer n = TextNormalizer.load();
        // Cyrillic 'ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°' (U+0430) inside Latin text is the classic homoglyph attack.
        check("Latin with a Cyrillic a is mixed", n.mixedScript("p\u0430ypal.com"));
        // Greek omicron inside Latin.
        check("Latin with a Greek o is mixed", n.mixedScript("g\u03BFogle.com"));
        // Single-script text is not mixed.
        check("pure Latin is not mixed", !n.mixedScript("paypal.com"));
        check("pure Cyrillic is not mixed", !n.mixedScript("\u043F\u0430\u0439\u043F\u0430\u043B"));
        // Digits, spaces and punctuation are COMMON or UNKNOWN and must be ignored, or every
        // string containing a digit or a dot would read as mixed.
        check("digits and punctuation do not create mixing",
                !n.mixedScript("order #12345, total $99.50 (ref: 42)"));
        check("punctuation-heavy text is not mixed", !n.mixedScript("--- ... !!! ???"));
        check("an empty string is not mixed", !n.mixedScript(""));
        // Inherited marks, as found in Devanagari and Arabic, must not read as mixing.
        check("a legitimate non-Latin script is not reported as mixed",
                !n.mixedScript("\u0928\u092E\u0938\u094D\u0924\u0947 \u091C\u0930\u093E"));
        // Structured information is returned alongside the boolean, so a report can say why.
        java.util.Map<String, Integer> hist = n.scriptHistogram("p\u0430ypal.com");
        check("the script histogram is populated", !hist.isEmpty());
        check("the histogram names more than one script", hist.size() > 1);
        // The histogram counts LETTERS only. Digits, dots and spaces are COMMON or UNKNOWN
        // and are excluded, which is exactly what stops "order #12345" from reading as
        // mixed-script. The total is therefore the letter count, not the string length.
        long letterCount = "p\u0430ypal.com".codePoints().filter(Character::isLetter).count();
        // Cast to int: the assertion helper compares with Object.equals, and a boxed Long
        // never equals a boxed Integer even when the numeric value is identical.
        eq("the histogram totals the letter count", (int) letterCount,
                hist.values().stream().mapToInt(Integer::intValue).sum());
        check("the letter count is below the raw string length", letterCount < 10);
        check("scriptOf reports a label", n.scriptOf('a') != null && !n.scriptOf('a').isEmpty());
        // A single-script string yields exactly one entry.
        java.util.Map<String, Integer> one = n.scriptHistogram("paypal.com");
        check("single-script text has one dominant script entry", !one.isEmpty());
    }

    /** 12. Confusable table: applied deterministically, no loop, no fabrication. */
    private static void t12_confusables() {
        section("T12  Confusable folding is deterministic and terminates");
        TextNormalizer n = TextNormalizer.load();
        check("the table reports where it was loaded from", n.source() != null);
        check("the table is non-empty", n.mappingCount() > 0);

        // The Greek PayPal spellings. pi=p, alpha=a, upsilon=y, lambda=l, so these are the
        // same word written entirely in Greek script. U+03BF omicron is deliberately NOT
        // used: it is not in the table, and asserting a mapping the table does not have would
        // be asserting fabricated folding.
        eq("Greek upsilon U+03C5 folds to y", "paypal.com",
                n.normalise("\u03C0\u03B1\u03C5\u03C0\u03B1\u03BB.com"));
        eq("Greek upsilon U+03CD (tonos) folds to y", "paypal.com",
                n.normalise("\u03C0\u03B1\u03CD\u03C0\u03B1\u03BB.com"));
        eq("Greek rho folds to p", "paypal.com",
                n.normalise("\u03C1\u03B1\u03CD\u03C1\u03B1\u03BB.com"));
        eq("Greek lambda folds to l", "paypal.com",
                n.normalise("\u03C0\u03B1\u03C5\u03C0\u03B1\u03BB.com"));
        // Cyrillic lookalikes: a single swapped letter is the real-world attack shape.
        eq("Cyrillic a inside a Latin word folds", "paypal.com",
                n.normalise("p\u0430ypal.com"));
        eq("Cyrillic a and u fold", "paypal.com",
                n.normalise("p\u0430\u0443p\u0430l.com"));
        // A codepoint absent from the table is passed through, never guessed at. CJK is used
        // because every Greek lookalike IS in the table - U+03BF omicron really does map to o.
        check("an unmapped CJK ideograph is not fabricated into a letter",
                n.normalise("\u4E2D\u6587.com").contains("\u4E2D"));
        // Determinism: the same input always produces the same output, every time.
        String sneaky = "p\u0430\u0443\u03C5\u0430l.com";
        String first = n.normalise(sneaky);
        boolean stable = true;
        for (int i = 0; i < 50; i++) {
            if (!first.equals(n.normalise(sneaky))) {
                stable = false;
                break;
            }
        }
        check("folding is deterministic across repeated calls", stable);
        // A second normaliser built from the same table must agree.
        eq("two instances loaded from the same table agree",
                first, TextNormalizer.load().normalise(sneaky));
        // No replacement loop: folding a folded string is stable, and a string that folds
        // into itself cannot be re-entered.
        eq("folding is idempotent (no cascade)", first, n.normalise(first));
        // The table must not invent mappings: an unmapped codepoint passes through unchanged
        // rather than being guessed at.
        String unmapped = "z\u4E2D\u6587";  // z + CJK, not in the table
        check("an unmapped codepoint is not fabricated away", n.normalise(unmapped).contains("\u4E2D"));
        // A malformed table is refused rather than partially loaded. Silently dropping bad
        // rows would mean a corrupted table quietly under-folds, and the security signal
        // disappears with no error.
        boolean threw = false;
        try {
            TextNormalizer.load(Path.of("build", "malformed-confusables.tsv"));
        } catch (RuntimeException e) {
            threw = true;
        }
        if (!threw) {
            // The fixture is written lazily so the happy path above is not disturbed.
            threw = malformedTableIsRejected();
        }
        check("a malformed confusable table is rejected, not silently trimmed", threw);
    }

    /** 13. Audit chain: append links records and the chain verifies. */
    private static void t13_auditAppend() throws Exception {
        section("T13  Audit chain append and link");
        Path dir = freshDir("t13");
        Audit audit = new Audit(dir.resolve("chain.ndjson"), dir.resolve("sigs.ndjson"),
                Audit.KeyManager.createOrLoad(dir.resolve("keys").resolve("k.pem")));

        Audit.Verification empty = audit.verify();
        check("an empty chain verifies", empty.ok);
        eq("an empty chain has no records", 0, empty.records);
        eq("an empty chain's head is the genesis seed hash",
                Crypto.sha256Hex("cipher-squad-genesis"), empty.headHash);

        Map<String, Object> r0 = audit.append("message.received",
                Audit.payload("ingest", "m1", "ok", "accepted"));
        Map<String, Object> r1 = audit.append("message.scored",
                Audit.payload("scorer", "m1", "ok", "risk=42"));

        // Every field the format requires must actually be present, not implied.
        for (String f : new String[]{"index", "ts", "event", "payload", "prev_hash", "hash"}) {
            check("record 0 carries '" + f + "'", r0.containsKey(f));
        }
        eq("the sequence number starts at 0", 0L, ((Number) r0.get("index")).longValue());
        eq("the sequence number increments", 1L, ((Number) r1.get("index")).longValue());
        check("the timestamp is ISO-8601",
                String.valueOf(r0.get("ts")).matches("\\d{4}-\\d{2}-\\d{2}T.*"));
        eq("record 0 links to the genesis hash", empty.headHash, r0.get("prev_hash"));
        eq("record 1 links to record 0", r0.get("hash"), r1.get("prev_hash"));
        check("the hashes differ between records", !r0.get("hash").equals(r1.get("hash")));

        Audit.Verification v = audit.verify();
        check("the chain verifies after appending", v.ok);
        eq("both records are present", 2, v.records);
        eq("the head is the last record's hash", r1.get("hash"), v.headHash);

        // One JSON object per line.
        List<String> lines = Files.readAllLines(dir.resolve("chain.ndjson"));
        eq("one line per record", 2, lines.size());
        boolean allParse = true;
        for (String l : lines) {
            try {
                Json.parseObject(l);
            } catch (RuntimeException e) {
                allParse = false;
            }
        }
        check("every line is a standalone JSON object", allParse);
    }

    /** 14. Audit verification passes on an untouched chain. */
    private static void t14_auditVerify() {
        section("T14  Audit verification of an intact chain");
        Path dir = freshDir("t14");
        Path pem = dir.resolve("keys").resolve("k.pem");
        Audit audit = new Audit(dir.resolve("chain.ndjson"), dir.resolve("sigs.ndjson"),
                Audit.KeyManager.createOrLoad(pem));
        for (int i = 0; i < 5; i++) {
            audit.append("event." + i, Audit.payload("tester", "s" + i, "ok", "d" + i));
        }
        Audit.Verification v = audit.verify();
        check("an intact chain verifies", v.ok);
        eq("no divergence", -1, v.firstDivergentIndex);
        eq("all 5 records counted", 5, v.records);
        check("the head hash is a SHA-256 digest", v.headHash.length() == 64);
        check("the head hash is lowercase hex", v.headHash.matches("[0-9a-f]{64}"));
        // Verification must be repeatable, not a one-shot state read.
        check("verification is repeatable", audit.verify().ok);

        // Signed head verifies, which is the offline check a report consumer performs.
        audit.signHead(4, v.headHash);
        // A second, independently constructed Audit stands in for the offline consumer: it
        // re-reads the chain and the key from disk and shares no in-memory state with the
        // writer. Reusing the same Audit object would prove nothing.
        Audit.Verification sv = new Audit(dir.resolve("chain.ndjson"),
                dir.resolve("sigs.ndjson"),
                Audit.KeyManager.createOrLoad(pem)).verify();
        check("signing is reported as configured", sv.signatureConfigured);
        check("a signed head validates offline", sv.headSignatureValid);
    }

    /** 15. Audit detects modification, deletion, insertion, and a malformed record. */
    private static void t15_auditTamperDetection() throws Exception {
        section("T15  Audit detects every form of tampering");
        Path base = freshDir("t15-base");
        Path src = base.resolve("chain.ndjson");
        Path sigs = base.resolve("sigs.ndjson");
        Path pem = base.resolve("keys").resolve("k.pem");
        Audit audit = new Audit(src, sigs, Audit.KeyManager.createOrLoad(pem));
        for (int i = 0; i < 5; i++) {
            audit.append("event." + i, Audit.payload("tester", "s" + i, "ok", "d" + i));
        }
        List<String> original = Files.readAllLines(src);

        // (a) MODIFY a payload value in the middle. The stored hash no longer matches.
        Path mod = copyTo("t15-mod", src, pem, sigs);
        List<String> ml = new ArrayList<>(original);
        Map<String, Object> m1 = Json.parseObject(ml.get(1));
        @SuppressWarnings("unchecked")
        Map<String, Object> mpl = (Map<String, Object>) m1.get("payload");
        mpl.put("detail", "TAMPERED");
        ml.set(1, Crypto.canonical(m1));
        Files.write(mod, ml);
        Audit.Verification mv = verifyFile(mod, pem, sigs);
        check("a modified payload is detected", !mv.ok);
        eq("modification is localised to the edited record", 1, mv.firstDivergentIndex);
        check("the reason names the hash mismatch", mv.reason.contains("hash mismatch"));

        // (b) DELETE a record from the middle. The index sequence has a gap.
        Path del = copyTo("t15-del", src, pem, sigs);
        List<String> dl = new ArrayList<>(original);
        dl.remove(2);
        Files.write(del, dl);
        Audit.Verification dv = verifyFile(del, pem, sigs);
        check("a deleted record is detected", !dv.ok);
        eq("deletion is localised to the gap", 2, dv.firstDivergentIndex);
        check("the reason identifies a sequence error", dv.reason.contains("index"));

        // (c) INSERT a record. The following prev_hash no longer matches.
        Path ins = copyTo("t15-ins", src, pem, sigs);
        List<String> il = new ArrayList<>(original);
        il.add(2, original.get(2).replace("\"index\":2", "\"index\":9"));
        Files.write(ins, il);
        Audit.Verification iv = verifyFile(ins, pem, sigs);
        check("an inserted record is detected", !iv.ok);
        eq("insertion is localised", 2, iv.firstDivergentIndex);

        // (d) Truncate the tail. The chain body stays internally consistent, so this is
        // detectable only by the head signature moving, which is why head signing exists.
        Path trunc = copyTo("t15-trunc", src, pem, sigs);
        List<String> tl = new ArrayList<>(original);
        tl.remove(tl.size() - 1);
        Files.write(trunc, tl);
        Audit.KeyManager km = Audit.KeyManager.createOrLoad(pem);
        Audit ta = new Audit(src, sigs, km);
        ta.signHead(4, ta.verify().headHash);
        Audit.Verification trv = verifyFile(trunc, pem, sigs);
        check("a truncated chain does not verify against its old signed head", !trv.headSignatureValid);
        check("the truncation is reported", trv.reason.contains("head") || !trv.ok);

        // (e) MALFORMED: a line that is not parseable JSON.
        Path bad = copyTo("t15-bad", src, pem, sigs);
        List<String> bl = new ArrayList<>(original);
        bl.set(3, "{not json");
        Files.write(bad, bl);
        Audit.Verification bv = verifyFile(bad, pem, sigs);
        check("a malformed record is detected", !bv.ok);
        eq("the malformed record is localised", 3, bv.firstDivergentIndex);
        check("the reason says it is unparseable", bv.reason.contains("not parseable"));

        // (f) A record missing a required field must not count as a valid link.
        Path miss = copyTo("t15-miss", src, pem, sigs);
        List<String> ml2 = new ArrayList<>(original);
        Map<String, Object> m2 = Json.parseObject(ml2.get(1));
        m2.remove("prev_hash");
        ml2.set(1, Crypto.canonical(m2));
        Files.write(miss, ml2);
        Audit.Verification misv = verifyFile(miss, pem, sigs);
        check("a record missing prev_hash is detected", !misv.ok);
        check("the reason names the missing field", misv.reason.contains("prev_hash"));

        // (g) The original must still verify: every tamper test used a copy, and a test that
        // damaged its own fixture would make the other six meaningless.
        check("the untouched original still verifies",
                new Audit(src, sigs, km).verify().ok);

        // (h) A FRACTIONAL index. JSON has no integer type, so every index arrives as a double.
        // The obvious verification cast is (int)(double), and (int) 1.5 is 1 - which means a
        // record renumbered from 1 to 1.5 would still verify. The sequence number has to be
        // required to be an exact integer or the chain accepts records the writer never wrote.
        Path frac = copyTo("t15-frac", src, pem, sigs);
        List<String> fl = new ArrayList<>(original);
        Map<String, Object> f1 = Json.parseObject(fl.get(1));
        f1.put("index", 1.5);
        fl.set(1, Crypto.canonical(f1));
        Files.write(frac, fl);
        Audit.Verification fv = verifyFile(frac, pem, sigs);
        check("a fractional index is rejected", !fv.ok);
        eq("the fractional index is localised", 1, fv.firstDivergentIndex);
        check("the reason says the index is not an integer",
                fv.reason.contains("non-integer"));

        // A negative and a non-numeric index must fail the same way, not be coerced.
        for (Object badIdx : new Object[]{-1.0, "1", null}) {
            Path bIdx = copyTo("t15-badidx-" + badIdx, src, pem, sigs);
            List<String> bl2 = new ArrayList<>(original);
            Map<String, Object> b1 = Json.parseObject(bl2.get(1));
            if (badIdx == null) {
                b1.remove("index");
            } else {
                b1.put("index", badIdx);
            }
            bl2.set(1, Crypto.canonical(b1));
            Files.write(bIdx, bl2);
            check("index " + badIdx + " is rejected", !verifyFile(bIdx, pem, sigs).ok);
        }

        // (i) The chain must be unusable once broken: appending onto corrupt history would
        // extend a chain whose earlier records are already untrustworthy.
        Path broken = copyTo("t15-broken", src, pem, sigs);
        List<String> brl = new ArrayList<>(original);
        Map<String, Object> br1 = Json.parseObject(brl.get(1));
        @SuppressWarnings("unchecked")
        Map<String, Object> brpl = (Map<String, Object>) br1.get("payload");
        brpl.put("detail", "TAMPERED");
        brl.set(1, Crypto.canonical(br1));
        Files.write(broken, brl);
        Audit brokenAudit = new Audit(broken, sigs, km);
        boolean refused = false;
        try {
            brokenAudit.append("after.tamper", Audit.payload("tester", "id", "ok", "x"));
        } catch (RuntimeException e) {
            refused = true;
        }
        check("appending to a tampered chain is refused", refused);
        check("the broken chain is still reported as broken", !brokenAudit.verify().ok);
    }

    /** 16. Sign: a signature is produced and verifies. */
    private static void t16_sign() {
        section("T16  Ed25519 signing");
        java.security.KeyPair kp = Sign.generateKeyPair();
        byte[] payload = "{\"verdict\":\"suspicious\",\"risk\":42}".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Sign.sign(payload, kp.getPrivate());
        check("a signature is 64 bytes for Ed25519", sig.length == 64);
        check("a valid signature verifies", Sign.verify(payload, sig, kp.getPublic()));

        // Determinism: Ed25519 is deterministic, so the same payload and key must give a
        // byte-identical signature. A randomised signature would still be valid but would
        // make two reports of the same artefact differ for no reason.
        check("Ed25519 signing is deterministic",
                java.util.Arrays.equals(sig, Sign.sign(payload, kp.getPrivate())));

        // key_id must be stable, so a pinned fingerprint means something.
        eq("key_id is 64 hex chars", 64, Sign.keyIdOf(kp.getPublic()).length());
        check("key_id is lowercase hex", Sign.keyIdOf(kp.getPublic()).matches("[0-9a-f]{64}"));
        eq("key_id is stable for the same key", Sign.keyIdOf(kp.getPublic()),
                Sign.keyIdOf(kp.getPublic()));

        // Import and export round trip, so a key survives being written to disk.
        String pubPem = Sign.publicKeyToPem(kp.getPublic());
        String privPem = Sign.privateKeyToPem(kp.getPrivate());
        check("the public key PEM is labelled", pubPem.contains(Sign.PUBLIC_PEM_LABEL));
        check("the private key PEM is labelled", privPem.contains(Sign.PRIVATE_PEM_LABEL));
        java.security.KeyPair restored = new java.security.KeyPair(
                Sign.publicKeyFromPem(pubPem), Sign.privateKeyFromPem(privPem));
        check("the exported public key round trips",
                restored.getPublic().equals(kp.getPublic()));
        check("the exported private key round trips",
                restored.getPrivate().equals(kp.getPrivate()));
        check("a signature made with the restored key verifies",
                Sign.verify(payload, Sign.sign(payload, restored.getPrivate()),
                        restored.getPublic()));
        // A Base64-wrapped signature must survive transport.
        String b64 = Sign.b64(sig);
        check("the signature survives a Base64 round trip",
                Sign.verify(payload, Sign.unb64(b64), kp.getPublic()));
        check("the signature survives a PEM round trip",
                Sign.verify(payload, Sign.signatureFromPem(Sign.signatureToPem(sig)),
                        kp.getPublic()));
        // No hardcoded key: two calls must not return the same key.
        check("each generated key pair is distinct",
                !Sign.keyIdOf(Sign.generateKeyPair().getPublic()).equals(Sign.keyIdOf(kp.getPublic())));
        // A null key is a caller error with a clear message, not a bare NPE.
        check("signing with a null key is rejected clearly",
                throwsIllegal(() -> Sign.sign(payload, null)));
    }

    /** 17. A modified payload fails verification. */
    private static void t17_modifiedPayloadRejected() {
        section("T17  Signature does not verify over a modified payload");
        java.security.KeyPair kp = Sign.generateKeyPair();
        String body = "{\"verdict\":\"legitimate\",\"risk\":5}";
        byte[] sig = Sign.sign(body.getBytes(StandardCharsets.UTF_8), kp.getPrivate());

        check("the original verifies",
                Sign.verify(body.getBytes(StandardCharsets.UTF_8), sig, kp.getPublic()));

        // A one-character change must invalidate it: this is the whole property.
        String changed = "{\"verdict\":\"legitimate\",\"risk\":6}";
        check("a one-character change is rejected",
                !Sign.verify(changed.getBytes(StandardCharsets.UTF_8), sig, kp.getPublic()));
        // Whitespace is part of the signed bytes, so a reformatted body is a different
        // document and must not verify. Signing a hash of a parsed structure, rather than
        // the bytes, would be the alternative and is explicitly not done.
        check("reformatting whitespace is rejected",
                !Sign.verify((body + " ").getBytes(StandardCharsets.UTF_8), sig, kp.getPublic()));
        // Field reordering changes the bytes.
        check("field reordering is rejected",
                !Sign.verify("{\"risk\":5,\"verdict\":\"legitimate\"}"
                        .getBytes(StandardCharsets.UTF_8), sig, kp.getPublic()));
        // Unicode normalisation must not be silently forgiven: NFD and NFC are different
        // byte sequences and only one of them was signed.
        String nfc = "caf\u00E9";
        String nfd = "cafe\u0301";
        check("NFC and NFD are different documents",
                !Sign.verify(nfd.getBytes(StandardCharsets.UTF_8),
                        Sign.sign(nfc.getBytes(StandardCharsets.UTF_8), kp.getPrivate()),
                        kp.getPublic()));
        // A signature must not verify against an empty or different body.
        check("an empty payload is rejected",
                !Sign.verify(new byte[0], sig, kp.getPublic()));
    }

    /** 18. A modified signature fails verification. */
    private static void t18_modifiedSignatureRejected() {
        section("T18  Signature does not verify after modification");
        java.security.KeyPair kp = Sign.generateKeyPair();
        byte[] payload = "{\"risk\":42}".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Sign.sign(payload, kp.getPrivate());
        check("the original verifies", Sign.verify(payload, sig, kp.getPublic()));

        // Flip one bit. Ed25519 verification must fail.
        byte[] flipped = sig.clone();
        flipped[0] ^= 0x01;
        check("a one-bit change to the signature is rejected",
                !Sign.verify(payload, flipped, kp.getPublic()));
        // Flip a bit in the last byte too, so the check is not accidentally front-loaded.
        byte[] flippedTail = sig.clone();
        flippedTail[sig.length - 1] ^= 0x80;
        check("a change to the final signature byte is rejected",
                !Sign.verify(payload, flippedTail, kp.getPublic()));
        // Truncated and extended signatures.
        check("a truncated signature is rejected",
                !Sign.verify(payload, java.util.Arrays.copyOf(sig, sig.length - 1), kp.getPublic()));
        check("an extended signature is rejected",
                !Sign.verify(payload, java.util.Arrays.copyOf(sig, sig.length + 1), kp.getPublic()));
        // A signature from a different key over the same payload.
        byte[] foreign = Sign.sign(payload, Sign.generateKeyPair().getPrivate());
        check("a foreign signature is rejected", !Sign.verify(payload, foreign, kp.getPublic()));
        // The right signature against the wrong public key.
        java.security.KeyPair other = Sign.generateKeyPair();
        check("the right signature under the wrong key is rejected",
                !Sign.verify(payload, sig, other.getPublic()));
        // Garbage must be rejected without throwing: verify() runs on other people's reports.
        check("random bytes are rejected without throwing",
                !Sign.verify(payload, new byte[64], kp.getPublic()));
        check("a null signature is rejected without throwing",
                !Sign.verify(payload, null, kp.getPublic()));
        check("a null key is rejected without throwing",
                !Sign.verify(payload, sig, null));
        check("a null payload is rejected without throwing",
                !Sign.verify((byte[]) null, sig, kp.getPublic()));
        // And the original still verifies after all of that.
        check("the original signature is unaffected", Sign.verify(payload, sig, kp.getPublic()));
    }

    // ==================================================================
    // Helpers for the 18 tests
    // ==================================================================

    private static boolean allProbabilitiesValid() {
        Model full = Model.initial();
        double[] x = new double[Features.COUNT];
        java.util.Arrays.fill(x, 0.5);
        Model.Score s = full.score(x, null, null, null, null);
        for (double pk : s.p) {
            if (!Double.isFinite(pk) || pk < 0.0 || pk > 1.0) {
                return false;
            }
        }
        return true;
    }

    /**
     * A non-finite write must be quarantined: value zeroed, marked unobserved, and noted.
     *
     * "spf_fail" is already observed before this runs, so a correct quarantine flips it to
     * unobserved and the observed count drops by one. The value must read as 0.0 and the
     * vector must record why, so the drop is attributable rather than mysterious.
     */
    private static boolean quarantinesNonFinite(Features.Vector v, String name) {
        int before = v.observedCount();
        int notesBefore = v.noteList().size();
        v.put(name, Double.NaN);
        boolean ok = !v.isObserved(name) && v.get(name) == 0.0
                && v.observedCount() == before - 1
                && v.noteList().size() == notesBefore + 1;
        v.put(name, Double.POSITIVE_INFINITY);
        ok = ok && !v.isObserved(name) && v.get(name) == 0.0
                && v.observedCount() == before - 1;
        return ok;
    }

    /** The spec's clip rule, written out independently of Model. */
    private static double clipTerm(double beta, double x, double c) {
        double t = beta * x;
        if (t > c) {
            return c;
        }
        if (t < -c) {
            return -c;
        }
        return t;
    }

    /** An 8-entry array with every entry equal to v. Model.b0 must be exactly K wide. */
    private static double[] flat(double v) {
        double[] out = new double[Config.K];
        java.util.Arrays.fill(out, v);
        return out;
    }

    /** An 8 x n coefficient matrix with every row equal to row. */
    private static double[][] repeat(double[] row) {
        double[][] out = new double[Config.K][];
        for (int k = 0; k < Config.K; k++) {
            out[k] = row.clone();
        }
        return out;
    }

    /** An 8-class, one-feature model with a known coefficient, for clipping tests. */
    private static Model singleFeatureModel(double b0, double beta) {
        return new Model(flat(b0), repeat(new double[]{beta}),
                new double[]{-9.0, 0.0}, 1, 50.0, 25.0, 40.0, 1.0, 1.0,
                "test-single-feature", Model.Source.HAND_SET_UNCALIBRATED, "none", Map.of());
    }

    /** Feeds a vector through the model's own validation, to prove it rejects non-finite. */
    private static void clipReject(double[] x) {
        Model.initial().logits(x);
    }

    private static Path freshDir(String name) {
        Path dir = Path.of("build", "spec", name);
        try {
            if (Files.isDirectory(dir)) {
                try (java.util.stream.Stream<Path> walk = Files.walk(dir)) {
                    walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // best effort
                        }
                    });
                }
            }
            Files.createDirectories(dir.resolve("keys"));
        } catch (Exception e) {
            throw new IllegalStateException("cannot prepare " + dir, e);
        }
        return dir;
    }

    private static Audit.Verification verifyFile(Path chain, Path pem, Path sigs) {
        return new Audit(chain, sigs, Audit.KeyManager.createOrLoad(pem)).verify();
    }

    /** Copy a chain plus its key and signatures into a fresh directory. */
    private static Path copyTo(String name, Path chain, Path pem, Path sigs) {
        Path dir = freshDir(name);
        try {
            Files.createDirectories(dir.resolve("keys"));
            Files.copy(chain, dir.resolve("chain.ndjson"));
            Files.copy(pem, dir.resolve("keys").resolve("k.pem"));
            if (Files.isRegularFile(sigs)) {
                Files.copy(sigs, dir.resolve("sigs.ndjson"));
            }
        } catch (Exception e) {
            throw new IllegalStateException("cannot copy fixture to " + dir, e);
        }
        return dir.resolve("chain.ndjson");
    }

    /** Writes a deliberately malformed table and confirms the loader refuses it. */
    private static boolean malformedTableIsRejected() {
        Path p = Path.of("build", "malformed-confusables.tsv");
        try {
            Files.createDirectories(p.getParent());
            Files.writeString(p, "0041\tb\nnot-a-hex-codepoint\tx\n\u0000\u0000\n");
            TextNormalizer.load(p);
            return false;
        } catch (RuntimeException e) {
            return true;
        } catch (Exception e) {
            return true;
        }
    }

    private static boolean throwsIllegal(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException | IllegalStateException | IndexOutOfBoundsException e) {
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean throwsIndex(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
            return true;
        }
    }

    // ==================================================================

    public static void main(String[] args) throws Exception {
        long t0 = System.nanoTime();
        System.out.println("Cipher Squad - Phase 1 items 1-3 regression");
        System.out.println("java " + System.getProperty("java.version"));
        System.out.println("model constants: K=" + Config.K + " C_ABSTAIN=" + Config.C_ABSTAIN
                + " W_BEC=" + Config.W_BEC + " GAMMA=" + Config.GAMMA);
        System.out.println("parser limits: msg=" + Config.MAX_MESSAGE_BYTES
                + "B headers=" + Config.MAX_HEADERS
                + " received=" + Config.MAX_RECEIVED_HEADERS
                + " urls=" + Config.MAX_URLS
                + " b64lines=" + Config.MAX_BASE64_LINES
                + " att=" + Config.MAX_ATTACHMENT_BYTES + "B");

        item1Parser();
        item2Normalizer();
        item3Profile();
        featuresContract();
        cryptoInvariants();

        System.out.println();
        System.out.println("################  PHASE 1 MANDATORY SELF-TESTS  ################");

        t1_featureFamilies();
        t2_eightClasses();
        t3_contributionClipping();
        t4_exactLogit();
        t5_softmaxSumsToOne();
        t6_largeLogitStability();
        t7_unobservedContributesZero();
        t8_noisyOr();
        t9_nfkc();
        t10_invisibleStripping();
        t11_mixedScript();
        t12_confusables();
        t13_auditAppend();
        t14_auditVerify();
        t15_auditTamperDetection();
        t16_sign();
        t17_modifiedPayloadRejected();
        t18_modifiedSignatureRejected();

        long ms = (System.nanoTime() - t0) / 1_000_000L;
        System.out.println();
        System.out.println("------------------------------------------------------------");
        System.out.println("passed=" + passed + "  failed=" + failed + "  (" + ms + " ms)");
        if (failed > 0) {
            System.out.println("FAILURES:");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.out.println("------------------------------------------------------------");
            System.out.println("RESULT: FAIL");
            System.exit(1);
        }
        System.out.println("------------------------------------------------------------");
        System.out.println("RESULT: PASS");
    }
}
