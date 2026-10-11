/**
 * Phase 3 test suite. Plain main(), no test framework, no dependencies.
 *
 * Coverage (every item the assignment requires):
 *   t01  binding is loopback-only (127.0.0.1)
 *   t02  routing: GET /api/cases requires auth, POST /api/cases 405
 *   t03  path traversal and malformed paths rejected
 *   t04  oversized request body rejected
 *   t05  malformed percent escapes rejected
 *   t06  authentication: Basic bootstraps session token
 *   t07  lockout after 5 failures within 15 minutes; correct password rejected while locked
 *   t08  SSRF guard rejects private/loopback/link-local/metadata
 *   t09  Audit.verify() called directly (shape sanity)
 *   t10  cases: bounded search/paging and storage semantics
 *   t11  STIX export: GET ?message and POST JSON; observed values only
 */
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

public final class phase3 {

    private static int passed;
    private static int failed;
    private static final List<String> failures = new ArrayList<>();
    private static String section = "";

    /**
     * Distinguishes this JVM run from every previous one.
     *
     * The case store is a persistent NDJSON file that outlives the process, so an identifier
     * reused across runs would make the second run read back the first run's record. That is a
     * self-inflicted collision, not a defect under test, so every message this suite generates
     * carries this tag. The tag is constant for the life of the run, which keeps the two exports
     * the determinism check compares pointed at the same case.
     *
     * It is applied to the message, not to the case. Case ids are server-generated and random
     * ({@code case-} plus 32 hex), so they cannot collide across runs in the first place; tagging
     * one would defeat the point of making them opaque.
     */
    private static final String RUN_TAG = Long.toString(System.nanoTime());

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

    // ==================================================================
    // Fixtures
    // ==================================================================

    private static String eml(String id) {
        return String.join("\r\n",
                "Received: from mta.example.com (mta.example.com [93.184.216.34])",
                "\tby mx1.example.org with ESMTP id x",
                "\tfor <victim@example.org>; Mon, 15 Sep 2025 10:30:00 +0000",
                "From: Alice <alice@evil.test>",
                "To: victim@example.org",
                "Subject: Phase3 Test",
                "Message-ID: <" + id + "@evil.test>",
                "Date: Mon, 15 Sep 2025 10:30:00 +0000",
                "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "Review http://evil.test/p and respond.",
                "");
    }

    // ==================================================================
    // Simple helpers
    // ==================================================================

    private static String basic(String u, String p) {
        byte[] b = (u + ":" + p).getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(b);
    }

    private static String bearer(String t) {
        return "Bearer " + t;
    }

    /** Case-insensitive first value of a response header, or "" when absent. */
    private static String header(HttpResponse<String> r, String name) {
        return r.headers().firstValue(name).orElse("");
    }

    /**
     * Sorted STIX object identifiers in a bundle.
     *
     * Used instead of comparing whole bundles because every bundle carries a fresh "created"
     * timestamp, which makes a byte comparison a coin flip on the millisecond boundary.
     */
    private static java.util.TreeSet<String> objectIds(String bundle) {
        java.util.TreeSet<String> ids = new java.util.TreeSet<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"id\"\\s*:\\s*\"([^\"]+)\"").matcher(bundle);
        while (m.find()) ids.add(m.group(1));
        return ids;
    }

    private static URI uri(int port, String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    /**
     * Sends a request over a raw socket and returns the status line.
     *
     * {@link HttpClient} refuses to send a request whose target it cannot parse, so it cannot be
     * used to test what the server does with a malformed target: the test never reaches the wire.
     * Writing the request bytes directly is the only way to observe the server's own answer to
     * hostile input, which is the behaviour under test.
     */
    private static int rawStatus(int port, String requestLine, String... extraHeaders)
            throws IOException {
        return raw(port, requestLine, extraHeaders).status;
    }

    /**
     * A raw response: the status code and the header block.
     *
     * The body is deliberately not read. A request that declares a {@code Content-Length} it never
     * sends leaves the server still waiting for those bytes while it has already answered, so
     * draining to EOF blocks until the socket times out. Every assertion here is about the status
     * line and the headers, so the read stops after them.
     */
    private record RawResponse(int status, List<String> headers) {
        /** The first value of a header, matched case-insensitively, or null. */
        String header(String name) {
            String prefix = name.toLowerCase(Locale.ROOT) + ":";
            for (String h : headers) {
                if (h.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                    return h.substring(prefix.length()).trim();
                }
            }
            return null;
        }
    }

    private static RawResponse raw(int port, String requestLine, String... extraHeaders)
            throws IOException {
        try (java.net.Socket s = new java.net.Socket("127.0.0.1", port)) {
            s.setSoTimeout(10_000);
            StringBuilder req = new StringBuilder();
            req.append(requestLine).append("\r\n");
            req.append("Host: 127.0.0.1:").append(port).append("\r\n");
            for (String h : extraHeaders) {
                req.append(h).append("\r\n");
            }
            req.append("Connection: close\r\n\r\n");
            s.getOutputStream().write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            java.io.BufferedReader in = new java.io.BufferedReader(
                    new java.io.InputStreamReader(s.getInputStream(), StandardCharsets.ISO_8859_1));
            String line = in.readLine();
            if (line == null) return new RawResponse(-1, List.of());
            String[] parts = line.split(" ");
            int status = parts.length > 1 ? Integer.parseInt(parts[1]) : -1;
            List<String> headers = new ArrayList<>();
            String h;
            while ((h = in.readLine()) != null && !h.isEmpty()) {
                headers.add(h);
            }
            return new RawResponse(status, headers);
        }
    }

    // ==================================================================
    // Test cases
    // ==================================================================

    private static void t01_binding() throws Exception {
        section("t01 - loopback-only bind");
        App app = new App(0);
        app.auth().upsert("test", "pwd1234567890".toCharArray(), List.of("analyst"));
        app.start();
        try {
            InetAddress a = app.boundAddress();
            check("bound to 127.0.0.1", "127.0.0.1".equals(a.getHostAddress()));
            check("port > 0", app.port() > 0);
        } finally {
            app.stop();
        }
    }

    private static void t02_routing() throws Exception {
        section("t02 - routing: auth required and method restrictions");
        App app = new App(0);
        app.auth().upsert("analyst", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            HttpResponse<String> unauth = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check("unauth GET /api/cases -> 401", unauth.statusCode() == 401);
            check("unauth JSON", unauth.headers().firstValue("Content-Type").orElse("").contains("application/json"));

            String basicHdr = basic("analyst", "correct-horse-battery1");
            HttpResponse<String> sess = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t02-1")))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("analyze ok", sess.statusCode() == 200);
            String tok = sess.headers().firstValue("X-Session-Token").orElse("");
            check("session token issued", !tok.isEmpty());

            HttpResponse<String> casesPost = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases"))
                    .header("Authorization", bearer(tok))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("POST /api/cases -> 405", casesPost.statusCode() == 405);
            check("405 JSON", casesPost.headers().firstValue("Content-Type").orElse("").contains("application/json"));
        } finally {
            app.stop();
        }
    }

    private static void t03_traversal() throws Exception {
        section("t03 - path traversal and malformed paths");
        App app = new App(0);
        app.auth().upsert("a", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("a", "correct-horse-battery1");
            HttpResponse<String> s = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t03-1")))
                    .build(), HttpResponse.BodyHandlers.ofString());
            String tok = s.headers().firstValue("X-Session-Token").orElse("");

            // Encoded traversal, over a raw socket because the JDK client normalises it away.
            // The header is written out in full: passing a bare "Bearer ..." string would be a
            // header line with no field name, and the server would reject the request as malformed
            // before the path was ever examined. The traversal defence would then never be tested,
            // and the assertion would pass for the wrong reason.
            String auth = "Authorization: " + bearer(tok);
            check("encoded traversal -> 400 or 404",
                    in(400, 404, rawStatus(p, "GET /api/..%2f..%2fetc%2fpasswd HTTP/1.1", auth)));
            check("double-encoded traversal -> 400 or 404",
                    in(400, 404, rawStatus(p, "GET /api/%252e%252e%252fetc%252fpasswd HTTP/1.1", auth)));
            check("traversal rejected -> 400 or 404",
                    in(400, 404, rawStatus(p, "GET /../../etc/passwd HTTP/1.1", auth)));
            check("null byte in path -> 400 or 404",
                    in(400, 404, rawStatus(p, "GET /api/cases%00.txt HTTP/1.1", auth)));

            // A well-formed but unauthorised path is a 401, which is what proves the raw requests
            // above are reaching the authorisation check rather than failing as bad syntax. If this
            // ever stopped being 401, the traversal results above would be meaningless.
            check("raw request with no credentials -> 401",
                    rawStatus(p, "GET /api/cases HTTP/1.1") == 401);
        } finally {
            app.stop();
        }
    }

    private static boolean in(int a, int b, int actual) {
        return actual == a || actual == b;
    }

    private static void t04_oversized() throws Exception {
        section("t04 - oversized request body");
        App app = new App(0);
        app.auth().upsert("a", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("a", "correct-horse-battery1");
            byte[] big = new byte[3 * 1024 * 1024];
            ThreadLocalRandom.current().nextBytes(big);
            HttpResponse<String> r = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(big))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("oversized body rejected -> 413", r.statusCode() == 413);

            // A declared length past the limit must be refused from the header alone, before any
            // body is read. Sent raw because the JDK client derives the header from the payload and
            // will not let a caller assert a length the payload does not have.
            check("declared oversize -> 413", rawStatus(p,
                    "POST /api/analyze HTTP/1.1",
                    "Authorization: " + basicHdr,
                    "Content-Type: message/rfc822",
                    "Content-Length: 8388608") == 413);
            check("absurd declared length -> 400 or 413", in(400, 413, rawStatus(p,
                    "POST /api/analyze HTTP/1.1",
                    "Authorization: " + basicHdr,
                    "Content-Type: message/rfc822",
                    "Content-Length: 99999999999999999999")));
            check("repeated Content-Length -> 400", rawStatus(p,
                    "POST /api/analyze HTTP/1.1",
                    "Authorization: " + basicHdr,
                    "Content-Type: message/rfc822",
                    "Content-Length: 10",
                    "Content-Length: 20") == 400);
            check("negative Content-Length -> 400", rawStatus(p,
                    "POST /api/analyze HTTP/1.1",
                    "Authorization: " + basicHdr,
                    "Content-Type: message/rfc822",
                    "Content-Length: -5") == 400);
            check("non-numeric Content-Length -> 400", rawStatus(p,
                    "POST /api/analyze HTTP/1.1",
                    "Authorization: " + basicHdr,
                    "Content-Type: message/rfc822",
                    "Content-Length: abc") == 400);
        } finally {
            app.stop();
        }
    }

    private static void t05_badPercent() throws Exception {
        section("t05 - malformed percent escapes");
        App app = new App(0);
        app.auth().upsert("a", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("a", "correct-horse-battery1");
            HttpResponse<String> s = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t05-1")))
                    .build(), HttpResponse.BodyHandlers.ofString());
            String tok = s.headers().firstValue("X-Session-Token").orElse("");
            String auth = bearer(tok);
            // Raw socket: a malformed escape never leaves the JDK client.
            check("truncated percent escape -> 400",
                    rawStatus(p, "GET /api/%2 HTTP/1.1", auth) == 400);
            check("non-hex percent escape -> 400",
                    rawStatus(p, "GET /api/%zz/cases HTTP/1.1", auth) == 400);
            check("bad escape in query -> 400",
                    rawStatus(p, "GET /api/cases?q=%zz HTTP/1.1", auth) == 400);
        } finally {
            app.stop();
        }
    }

    private static void t06_authSession() throws Exception {
        section("t06 - auth bootstraps session token");
        App app = new App(0);
        app.auth().upsert("analyst", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("analyst", "correct-horse-battery1");
            HttpResponse<String> a = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t06-1")))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("200", a.statusCode() == 200);
            check("has X-Session-Token", a.headers().firstValue("X-Session-Token").isPresent());
            String tok = a.headers().firstValue("X-Session-Token").orElse("");
            HttpResponse<String> c = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("bearer works", c.statusCode() == 200);
        } finally {
            app.stop();
        }
    }

    private static void t07_lockout() throws Exception {
        section("t07 - lockout after 5 failures; correct password rejected while locked");
        App app = new App(0);
        app.auth().upsert("victim", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String bad = basic("victim", "wrong-password");
            for (int i = 0; i < 5; i++) {
                HttpResponse<String> r = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases"))
                        .header("Authorization", bad).GET().build(), HttpResponse.BodyHandlers.ofString());
                // failures count; status will be 401
            }
            // now locked? try correct
            String good = basic("victim", "correct-horse-battery1");
            HttpResponse<String> locked = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases"))
                    .header("Authorization", good).GET().build(), HttpResponse.BodyHandlers.ofString());
            // 429, not 401: a correct password is refused because the lock is in force, and the
            // status must say "temporarily locked" rather than "wrong credentials", or a caller
            // would keep retrying the password it already has right.
            check("correct password still refused while locked -> 429", locked.statusCode() == 429);
            check("429 carries Retry-After", locked.headers().firstValue("Retry-After").isPresent());
            // and token not issued
            HttpResponse<String> an = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", good)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t07-1")))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("analyze with locked account -> 429", an.statusCode() == 429);
            check("no session token", an.headers().firstValue("X-Session-Token").isEmpty());

            // The account is locked but the address is a different one: an attacker spraying from
            // elsewhere must not get in either, so the account lock has to stand on its own.
            HttpResponse<String> other = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases"))
                    .header("Authorization", good)
                    .header("X-Forwarded-For", "198.51.100.7")
                    .GET().build(), HttpResponse.BodyHandlers.ofString());
            check("account lock holds independent of client address -> 429", other.statusCode() == 429);

            // Unit level: five wrong attempts were recorded, and the fifth is the one that
            // crossed AUTH_MAX_FAILURES, so the counter reads 5 and the account reports locked.
            eq("five failures recorded", 5, app.auth().recentFailures("victim"));
            check("account reports locked", app.auth().isAccountLocked("victim"));
        } finally {
            app.stop();
        }
    }

    /**
     * The SSRF guard is tested directly against the address ranges it must refuse. Asserting on the
     * endpoints instead would only prove the server is up: no endpoint in this service fetches a
     * URL, so the guard's behaviour is not observable over HTTP, and the honest way to test a
     * decision function is to call it.
     */
    private static void t08_ssrf() throws Exception {
        section("t08 - SSRF guard range decisions");

        String[] mustDeny = {
            "127.0.0.1", "127.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "224.0.0.1", "240.0.0.1", "255.255.255.255",
            "::1", "::", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "fe80::1", "fc00::1",
            "fd00::1", "2001:db8::1", "2001:0:1234::1", "64:ff9b::127.0.0.1",
            "localhost", "metadata.google.internal",
            "internal", "foo.internal", "bar.localhost", "0x7f.1", "2130706433",
            "127.0.0.1.evil.test", "[::1]", "010.0.0.1", "0177.0.0.1", "2002:7f00:1::",
        };
        for (String host : mustDeny) {
            App.Ssrf.Decision d = new App.Ssrf().check(host);
            check("deny " + host + " (" + d.reason + ")", !d.allowed);
        }

        String[] mayAllow = {
            "example.com", "8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::1",
        };
        for (String host : mayAllow) {
            App.Ssrf.Decision d = new App.Ssrf().check(host);
            check("allow " + host, d.allowed);
        }

        // Shape refusals, which are what stops a name from being read loosely as an address.
        eq("empty host denied", false, new App.Ssrf().check("").allowed);
        eq("null host denied", false, new App.Ssrf().check(null).allowed);
        eq("over-long host denied", false,
                new App.Ssrf().check("a".repeat(300) + ".com").allowed);
        eq("non-FQDN denied", false, new App.Ssrf().check("intranetserver").allowed);
        eq("IPv6 zone id denied", false, new App.Ssrf().check("fe80::1%eth0").allowed);
        eq("malformed numeric denied", false, new App.Ssrf().check("1.2.3.999").allowed);
        eq("single-label numeric denied", false, new App.Ssrf().check("1").allowed);

        // A shape-valid name that encodes a metadata address in its labels is a real bypass, and
        // only resolution can catch it. This is why check() decides shape for a name and
        // resolveAndCheck decides on the address: the text is a legal hostname, so a shape check
        // cannot refuse it, and the verdict has to come from the resolved address instead.
        App.Ssrf.Decision shapeOnly = new App.Ssrf().check("169.254.169.254.nip.io");
        check("check() is shape-only for a name (cannot see the embedded address)", shapeOnly.allowed);
        App.Ssrf.Decision resolved = new App.Ssrf().resolveAndCheck("169.254.169.254.nip.io");
        check("resolveAndCheck refuses the same name", !resolved.allowed);
        System.out.println("        (resolveAndCheck reason: " + resolved.reason + ")");

        // The resolution gate decides on the address, so a name that resolves into a reserved range
        // is refused there. localhost is used because it resolves to loopback without a network.
        App.Ssrf.Decision rebind = new App.Ssrf().resolveAndCheck("localhost");
        check("resolveAndCheck refuses a name resolving to loopback", !rebind.allowed);
        check("resolveAndCheck blames the address, not the shape",
                "loopback".equals(rebind.reason) || "reserved_hostname".equals(rebind.reason)
                        || "reserved_tld".equals(rebind.reason));
        eq("resolveAndCheck refuses an unresolvable name", false,
                new App.Ssrf().resolveAndCheck("no-such-host.invalid").allowed);
    }

    /**
     * An {@link Audit} over the ACTIVE data directory, for tests that must verify the same chain
 * the server under test is appending to.
     *
     * {@code new Audit()} resolves to the hardcoded {@code data/} paths and ignores the
     * {@code cipher.squad.dataDir} override that run-tests.ps1 sets, so using it here would verify
 * one chain while the App wrote another, and would rewrite the store that ships with the project.
     */
    private static Audit activeAudit() {
        Path base = App.dataDir();
        return new Audit(base.resolve("audit.ndjson"), base.resolve("audit-sigs.ndjson"),
                new Audit.KeyManager(base.resolve("keys").resolve("ed25519.pem")));
    }

    private static void t09_audit() throws Exception {
        section("t09 - audit chain verification and response hardening");
        App app = new App(0);
        app.auth().upsert("a", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("a", "correct-horse-battery1");
            HttpResponse<String> s = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t09-1-" + RUN_TAG)))
                    .build(), HttpResponse.BodyHandlers.ofString());
            String tok = s.headers().firstValue("X-Session-Token").orElse("");
            HttpResponse<String> v = cli.send(HttpRequest.newBuilder(uri(p, "/api/audit/verify"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("audit 200", v.statusCode() == 200);

            // The endpoint must be reporting the real chain state, not a hardcoded true. Asserted
            // against the verifier's own result so the two cannot drift apart.
            //
            // The verifier is built on the SAME paths the App under test is using, read from the
            // active data directory. Reading Audit.DEFAULT_LOG instead would verify the shipped
            // data/audit.ndjson while the App appends to the redirected test store, so the two
            // would describe different chains -- and the tamper step below would rewrite the file
            // that ships with the project on every run.
            Audit.Verification audit = activeAudit().verify();
            Map<String, Object> jv = Json.parseObject(v.body());
            check("endpoint reports the verifier's verdict",
                    String.valueOf(jv.get("ok")).equals(String.valueOf(audit.ok)));
            check("chain is valid after an append", audit.ok);

            // Tampering must be detected. The chain is the audit property, so a verifier that cannot
            // see a modified line is not verifying anything. The file is restored afterwards.
            Path log = App.dataDir().resolve("audit.ndjson");
            List<String> original = Files.readAllLines(log);
            check("the test chain is non-empty before tampering", !original.isEmpty());
            try {
                List<String> tampered = new ArrayList<>(original);
                int last = tampered.size() - 1;
                check("the tampered line is the one under test",
                        tampered.get(last).contains("\"actor\":\"a\""));
                tampered.set(last, tampered.get(last).replace("\"actor\":\"a\"", "\"actor\":\"z\""));
                Files.write(log, tampered);
                check("a modified line is detected", !activeAudit().verify().ok);
            } finally {
                Files.write(log, original);
            }
            check("chain verifies again once restored", activeAudit().verify().ok);

            // --- response hardening, asserted on a raw response so the header block is exact ---
            RawResponse r = raw(p, "GET /api/audit/verify HTTP/1.1",
                    "Authorization: " + bearer(tok));
            check("raw audit 200", r.status() == 200);
            check("X-Content-Type-Options: nosniff",
                    "nosniff".equals(r.header("X-Content-Type-Options")));
            check("X-Frame-Options: DENY", "DENY".equals(r.header("X-Frame-Options")));
            check("Referrer-Policy: no-referrer",
                    "no-referrer".equals(r.header("Referrer-Policy")));
            check("Cache-Control: no-store",
                    String.valueOf(r.header("Cache-Control")).contains("no-store"));
            String csp = r.header("Content-Security-Policy");
            check("CSP denies all content", csp != null && csp.contains("default-src 'none'"));
            check("CSP denies framing", csp != null && csp.contains("frame-ancestors 'none'"));

            // The hardening must hold on error responses too: a 404 is exactly the response an
            // attacker uses to probe, and it is the one most likely to be built by a separate path.
            RawResponse nf = raw(p, "GET /api/nope HTTP/1.1", "Authorization: " + bearer(tok));
            check("404 is hardened as well", "nosniff".equals(nf.header("X-Content-Type-Options"))
                    && "DENY".equals(nf.header("X-Frame-Options")));

            // A caller must not be able to set or override a security header from its own request.
            for (String spoof : List.of("X-Content-Type-Options: text/html",
                    "X-Frame-Options: ALLOWALL", "Content-Security-Policy: default-src *",
                    "Cache-Control: public")) {
                RawResponse bad = raw(p, "GET /api/audit/verify HTTP/1.1",
                        "Authorization: " + bearer(tok), spoof);
                String overridden = bad.header(spoof.split(":")[0]);
                check("ignores client " + spoof.split(":")[0], !String.valueOf(overridden)
                        .equalsIgnoreCase(spoof.split(":")[1].trim()));
            }
        } finally {
            app.stop();
        }
    }

    private static void t10_cases() throws Exception {
        section("t10 - cases bounded search/paging");
        App app = new App(0);
        app.auth().upsert("a", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("a", "correct-horse-battery1");
            HttpResponse<String> s = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t10-boot-" + RUN_TAG)))
                    .build(), HttpResponse.BodyHandlers.ofString());
            String tok = s.headers().firstValue("X-Session-Token").orElse("");

            // The default model never enables case creation, so the analyze calls above
            // deliberately create nothing. Cases are seeded from the real pipeline so the read
            // paths are exercised against records the production path could have written.
            String idA = app.cases().append(
                    app.run(eml("t10-a-" + RUN_TAG).getBytes(StandardCharsets.UTF_8)).caseRecord());
            String idB = app.cases().append(
                    app.run(eml("t10-b-" + RUN_TAG).getBytes(StandardCharsets.UTF_8)).caseRecord());
            check("two real cases stored", idA != null && idB != null);

            // Paging must be real: pageSize=1 over two seeded cases must return one, and the
            // second page a different one. Asserting only that "total" appears would pass on an
            // endpoint that ignored both the page and the size.
            HttpResponse<String> page1 = cli.send(HttpRequest.newBuilder(
                    uri(p, "/api/cases?pageSize=1&page=1&q=t10-"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("pageSize honored", page1.statusCode() == 200);
            Map<String, Object> j1 = Json.parseObject(page1.body());
            check("total counts matches", num(j1.get("total")) >= 2);
            check("returned is capped at pageSize", num(j1.get("returned")) == 1);

            HttpResponse<String> page2 = cli.send(HttpRequest.newBuilder(
                    uri(p, "/api/cases?pageSize=1&page=2&q=t10-"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            Map<String, Object> j2 = Json.parseObject(page2.body());
            check("second page returns a different case",
                    !String.valueOf(j1.get("cases")).equals(String.valueOf(j2.get("cases"))));

            // A page past the end is empty, not an error and not a wrapped-around first page.
            HttpResponse<String> beyond = cli.send(HttpRequest.newBuilder(
                    uri(p, "/api/cases?pageSize=1&page=9999&q=t10-"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("page past the end is empty", num(Json.parseObject(beyond.body()).get("returned")) == 0);

            // Search must actually filter, not merely accept the parameter. The query is the full
            // unique case id, so exactly one record can match: a search that matched everything
            // would otherwise pass a "results contain the right id" check.
            HttpResponse<String> hit = cli.send(HttpRequest.newBuilder(
                    uri(p, "/api/cases?q=" + URLEncoder.encode(idB, StandardCharsets.UTF_8)))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            Map<String, Object> jh = Json.parseObject(hit.body());
            check("search filters to the matching case", num(jh.get("total")) == 1);
            check("search hit is the right case", idsOf(jh.get("cases")).contains(idB));

            // Search is a deliberate substring match over the observed fields, not a tokenised
            // query, so a shared prefix legitimately matches every record carrying it. Pinning that
            // behaviour keeps a future switch to token matching from silently changing results.
            HttpResponse<String> pref = cli.send(HttpRequest.newBuilder(
                    uri(p, "/api/cases?q=t10-"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("prefix search is a substring match over several records",
                    num(Json.parseObject(pref.body()).get("total")) > 1);

            // A search matching nothing is an empty result, not a 404.
            HttpResponse<String> miss = cli.send(HttpRequest.newBuilder(
                    uri(p, "/api/cases?q=zzz-no-such-case-zzz"))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("search miss is 200 with zero results",
                    miss.statusCode() == 200 && num(Json.parseObject(miss.body()).get("total")) == 0);

            // Out-of-range paging parameters are rejected instead of silently clamped, because a
            // clamped page returns a different case list than the caller asked for.
            for (String q : List.of("page=0", "page=-1", "pageSize=0", "pageSize=999999", "page=abc")) {
                HttpResponse<String> bad = cli.send(HttpRequest.newBuilder(uri(p, "/api/cases?" + q))
                        .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
                check("rejects " + q, bad.statusCode() == 400);
            }

            // --- re-analysis produces a NEW case id (no shadowing possible) ---
            // Case ids are now opaque server-generated values. The same message analysed twice
            // yields two distinct case records, each with its own id and createdAt. The old
            // design keyed on Message-ID, which allowed an attacker to supersede another's case.
            String dupLocal = "t10-dup-" + RUN_TAG;
            String dupId = dupLocal + "@evil.test";
            String caseId1 = app.cases().append(app.run(eml(dupLocal).getBytes(StandardCharsets.UTF_8)).caseRecord());
            check("first write returns a server-generated case id",
                    caseId1 != null && caseId1.startsWith("case-"));
            check("first write is findable by its case id",
                    app.cases().find(caseId1) != null);
            Object firstCreated = app.cases().find(caseId1).get("createdAt");

            // Second analysis of the SAME message produces a DIFFERENT case id
            Map<String, Object> secondRecord = app.run(eml(dupLocal).getBytes(StandardCharsets.UTF_8)).caseRecord();
            secondRecord.put("domains", new ArrayList<>(List.of("reanalysis.test")));
            String caseId2 = app.cases().append(secondRecord);
            check("second write returns a DIFFERENT server-generated case id",
                    caseId2 != null && caseId2.startsWith("case-") && !caseId2.equals(caseId1));
            check("second write is findable by its own case id",
                    app.cases().find(caseId2) != null);
            Map<String, Object> found = app.cases().find(caseId2);
            check("re-analysis does not shadow the first case",
                    found != null && String.valueOf(found.get("domains")).contains("reanalysis.test"));
            check("each case keeps its own createdAt",
                    !String.valueOf(found.get("createdAt")).equals(String.valueOf(firstCreated)));
        } finally {
            app.stop();
        }
    }

    /** The ids present in a "cases" array, for diagnosing a search that matched the wrong set. */
    @SuppressWarnings("unchecked")
    private static List<String> idsOf(Object cases) {
        List<String> out = new ArrayList<>();
        if (cases instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) out.add(String.valueOf(m.get("id")));
            }
        }
        return out;
    }

    /** Coerces a JSON number to long, or -1 when the value is absent or not numeric. */
    private static long num(Object o) {        if (o instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(String.valueOf(o));
        } catch (NumberFormatException e) {
            return -1L;
        }
    }

    private static void t11_stix() throws Exception {
        section("t11 - STIX GET and POST, observed values only");
        App app = new App(0);
        app.auth().upsert("a", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        int p = app.port();
        try {
            String basicHdr = basic("a", "correct-horse-battery1");
            HttpResponse<String> s = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Content-Type", "message/rfc822")
                    .header("Authorization", basicHdr)
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t11-1")))
                    .build(), HttpResponse.BodyHandlers.ofString());
            String tok = s.headers().firstValue("X-Session-Token").orElse("");

            // The shipped weights are uncalibrated, so the model's own gate never enables case
            // creation and the store is legitimately empty. To exercise the case paths the test
            // runs the real pipeline and stores the record the pipeline produced. Nothing is
            // hand-written: the record is the same object handleAnalyze would have written had the
            // model permitted it, so a case that reaches the store here is one the production path
            // could have produced itself.
            App.Analysis a = app.run(eml("t11-1-" + RUN_TAG).getBytes(StandardCharsets.UTF_8));
            String caseId = app.cases().append(a.caseRecord());
            check("a real analysed message produced a case record", caseId != null && !caseId.isEmpty());

            // --- GET by case id ---
            HttpResponse<String> g = cli.send(HttpRequest.newBuilder(
                    uri(p, "/export/stix?case=" + URLEncoder.encode(caseId, StandardCharsets.UTF_8)))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("stix GET -> 200", g.statusCode() == 200);
            check("stix GET content-type", g.headers().firstValue("Content-Type")
                    .orElse("").contains("application/stix+json"));

            // The parameter is a case id, not a Message-ID. "message" stays accepted so an
            // existing caller is not broken by that correction, but it is the legacy spelling
            // and "case" is the name.
            HttpResponse<String> legacy = cli.send(HttpRequest.newBuilder(
                    uri(p, "/export/stix?message=" + URLEncoder.encode(caseId, StandardCharsets.UTF_8)))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("stix GET ?message= alias still resolves", legacy.statusCode() == 200);
            // Not a byte compare: the bundle carries a per-call "created" stamp. The object ids
            // are UUID v5 over the observed values, so they are the stable identity to compare.
            check("alias returns the same object set",
                    objectIds(legacy.body()).equals(objectIds(g.body())));

            String bundle = g.body();
            check("bundle type", bundle.contains("\"type\":\"bundle\""));
            check("spec 2.1", bundle.contains("\"spec_version\":\"2.1\""));
            check("bundle has created", bundle.contains("\"created\":"));
            check("has objects array", bundle.contains("\"objects\":["));

            // Observed values only. The message supplies evil.test, alice@evil.test,
            // victim@example.org, mta.example.com, 93.184.216.34 and evil.test/p.
            check("observed domain exported", bundle.contains("\"domain-name--"));
            check("observed domain value", bundle.contains("evil.test"));
            check("observed email address exported", bundle.contains("alice@evil.test"));
            check("observed address is a full mailbox, not a bare host",
                    bundle.contains("\"value\":\"alice@evil.test\""));
            check("observed IPv4 exported", bundle.contains("93.184.216.34"));
            check("observed URL exported", bundle.contains("evil.test/p"));

            // Nothing may be invented.
            for (String forbidden : List.of("malware", "threat-actor", "indicator--",
                    "malware--", "attack-pattern", "identity--")) {
                check("no fabricated " + forbidden, !bundle.contains(forbidden));
            }
            check("no 'unknown' placeholder IOC", !bundle.contains("\"value\":\"unknown\""));
            check("only permitted types present", everyTypePermitted(bundle));

            // STIX 2.1 correctness: an SCO has no created/modified properties.
            check("SCOs carry no created property", !scoHasTimestamp(bundle, "created"));
            check("SCOs carry no modified property", !scoHasTimestamp(bundle, "modified"));

            // Determinism: the same evidence must yield the same object ids.
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("caseId", caseId);
            HttpResponse<String> po1 = cli.send(HttpRequest.newBuilder(uri(p, "/export/stix"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer(tok))
                    .POST(HttpRequest.BodyPublishers.ofString(Json.write(body)))
                    .build(), HttpResponse.BodyHandlers.ofString());
            HttpResponse<String> po2 = cli.send(HttpRequest.newBuilder(uri(p, "/export/stix"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer(tok))
                    .POST(HttpRequest.BodyPublishers.ofString(Json.write(body)))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("POST by caseId 200", po1.statusCode() == 200);
            check("same evidence yields the same bundle id",
                    sameBundleId(po1.body(), po2.body()));

            // --- POST inline eml ---
            body = new LinkedHashMap<>();
            body.put("eml", eml("t11-2"));
            HttpResponse<String> po = cli.send(HttpRequest.newBuilder(uri(p, "/export/stix"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer(tok))
                    .POST(HttpRequest.BodyPublishers.ofString(Json.write(body)))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("stix POST inline 200", po.statusCode() == 200);
            check("inline export has observed domain", po.body().contains("evil.test"));
            check("inline export has no fabricated malware", !po.body().contains("malware"));

            // An unknown case id is a 404, not an empty bundle: "no such case" and "this case has
            // no indicators" are different answers and must not be reported the same way.
            HttpResponse<String> missing = cli.send(HttpRequest.newBuilder(
                    uri(p, "/export/stix?message=" + URLEncoder.encode("no-such-case", StandardCharsets.UTF_8)))
                    .header("Authorization", bearer(tok)).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("unknown case id -> 404", missing.statusCode() == 404);

            // A body naming neither caseId nor eml is a client error.
            HttpResponse<String> empty = cli.send(HttpRequest.newBuilder(uri(p, "/export/stix"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer(tok))
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("neither caseId nor eml -> 400", empty.statusCode() == 400);
        } finally {
            app.stop();
        }
    }

    /** True when every "type" in the JSON is one this builder is permitted to emit. */
    private static boolean everyTypePermitted(String json) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"type\":\"([a-z0-9-]+)\"").matcher(json);
        Set<String> allowed = Set.of("bundle", "email-message", "email-addr", "domain-name",
                "ipv4-addr", "ipv6-addr", "url", "file");
        while (m.find()) {
            if (!allowed.contains(m.group(1))) return false;
        }
        return true;
    }

    /**
     * True when any object that is not the bundle carries {@code prop}.
     *
     * The bundle is a domain object and does have {@code created}; a cyber-observable object must
     * not. Checked structurally rather than by substring, because a bundle that has
     * {@code created} is correct and a naive search would flag it.
     */
    private static boolean scoHasTimestamp(String json, String prop) {
        int objectsAt = json.indexOf("\"objects\":[");
        if (objectsAt < 0) return false;
        String inner = json.substring(objectsAt);
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"type\":\"([a-z0-9-]+)\"").matcher(inner);
        while (m.find()) {
            if ("bundle".equals(m.group(1))) continue;
            // Look for the property inside this object's own text, up to the next type marker.
            int from = m.end();
            int next = inner.indexOf("\"type\":", from);
            String obj = next < 0 ? inner.substring(from) : inner.substring(from, next);
            if (obj.contains("\"" + prop + "\":")) return true;
        }
        return false;
    }

    private static boolean sameBundleId(String a, String b) {
        java.util.regex.Matcher ma = java.util.regex.Pattern
                .compile("\"id\":\"(bundle--[0-9a-f-]+)\"").matcher(a);
        java.util.regex.Matcher mb = java.util.regex.Pattern
                .compile("\"id\":\"(bundle--[0-9a-f-]+)\"").matcher(b);
        return ma.find() && mb.find() && ma.group(1).equals(mb.group(1));
    }

    /**
     * t12 - the analyst console is served correctly and safely.
     *
     * The console is the one body this service returns as markup, so it is also the one place the
     * API's blanket {@code default-src 'none'} has to be relaxed. These checks pin the relaxation
     * to a per-request nonce and confirm the surrounding security headers still apply.
     */
    private static void t12_console() throws Exception {
        section("t12 - analyst console: static document, nonce CSP, no external assets");
        App app = new App(0);
        app.auth().upsert("analyst", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        int p = app.port();
        try {
            HttpResponse<String> r = cli.send(
                    HttpRequest.newBuilder(uri(p, "/")).GET().build(), HttpResponse.BodyHandlers.ofString());

            check("GET / is 200 without credentials", r.statusCode() == 200);
            check("served as text/html", header(r, "content-type").startsWith("text/html"));

            String csp = header(r, "content-security-policy");
            check("a CSP is present", !csp.isEmpty());
            check("default-src is 'none'", csp.contains("default-src 'none'"));
            check("script-src is nonce based", csp.contains("script-src 'nonce-"));
            check("no 'unsafe-inline'", !csp.contains("unsafe-inline"));
            check("no 'unsafe-eval'", !csp.contains("unsafe-eval"));
            check("connect-src is same-origin", csp.contains("connect-src 'self'"));
            check("img-src denied", csp.contains("img-src 'none'"));
            check("framing denied", csp.contains("frame-ancestors 'none'"));
            check("form-action denied", csp.contains("form-action 'none'"));
            check("base-uri denied", csp.contains("base-uri 'none'"));

            check("nosniff still applied", "nosniff".equals(header(r, "x-content-type-options")));
            check("frame denial header still applied", "DENY".equals(header(r, "x-frame-options")));
            check("still no-store", "no-store".equals(header(r, "cache-control")));

            String html = r.body();
            String nonce = csp.replaceAll(".*script-src 'nonce-([^']+)'.*", "$1");
            check("nonce placeholder was substituted", !html.contains("__CSP_NONCE__"));
            check("script tag carries the header nonce", html.contains("<script nonce=\"" + nonce + "\""));
            check("style tag carries the header nonce", html.contains("<style nonce=\"" + nonce + "\""));
            check("no absolute URL is referenced", !html.contains("http://") && !html.contains("https://"));
            check("no protocol-relative URL is referenced", !html.contains("//cdn"));
            check("no raw-HTML sink is used",
                    !html.contains(".innerHTML") && !html.contains(".outerHTML")
                            && !html.contains("insertAdjacentHTML") && !html.contains("document.write"));
            check("states the uncalibrated model", html.contains("HAND_SET_UNCALIBRATED")
                    || html.contains("Uncalibrated"));
            check("defines the empty state", html.contains("No analysis available"));
            check("defines the Unknown marker", html.contains("\"Unknown\""));

            HttpResponse<String> again = cli.send(
                    HttpRequest.newBuilder(uri(p, "/")).GET().build(), HttpResponse.BodyHandlers.ofString());
            String csp2 = header(again, "content-security-policy");
            String nonce2 = csp2.replaceAll(".*script-src 'nonce-([^']+)'.*", "$1");
            check("the nonce differs between responses", !nonce.equals(nonce2));
            check("each body matches its own nonce",
                    again.body().contains("<script nonce=\"" + nonce2 + "\""));

            HttpResponse<String> idx = cli.send(
                    HttpRequest.newBuilder(uri(p, "/index.html")).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("GET /index.html is 200", idx.statusCode() == 200);

            // The served path is a constant, so no caller input reaches the filesystem. These two
            // confirm that a traversal attempt still cannot be turned into a served file.
            HttpResponse<String> up = cli.send(
                    HttpRequest.newBuilder(uri(p, "/%2e%2e/src/App.java")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check("an encoded traversal is refused", up.statusCode() == 400);
            check("and is never served as the console",
                    !header(up, "content-type").startsWith("text/html"));

            HttpResponse<String> fav = cli.send(
                    HttpRequest.newBuilder(uri(p, "/favicon.ico")).GET().build(), HttpResponse.BodyHandlers.ofString());
            check("favicon is 404 because the console loads no external asset",
                    fav.statusCode() == 404);

            // The console is a shell; it must not be a way to read the case list.
            check("the console contains no case data", !html.contains("\"caseId\"")
                    && !html.contains("users.ndjson") && !html.contains("cases.ndjson"));
        } finally {
            app.stop();
        }
    }

    /**
     * t13 - the forensic report route, and analyst-authority case opening.
     *
     * The report is the authoritative artifact, so it must be assembled server-side, must not be
     * reachable without a session, and must refuse an unknown or absent case rather than
     * inventing one.
     */
    private static void t13_report() throws Exception {
        section("t13 - forensic report and analyst-authority case opening");
        App app = new App(0);
        app.auth().upsert("analyst", "correct-horse-battery1".toCharArray(), List.of("analyst"));
        app.start();
        HttpClient cli = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        int p = app.port();
        String basic = "Basic " + Base64.getEncoder().encodeToString(
                "analyst:correct-horse-battery1".getBytes(StandardCharsets.UTF_8));
        try {
            check("the report needs a session",
                    cli.send(HttpRequest.newBuilder(uri(p, "/api/report?case=case-x")).GET().build(),
                            HttpResponse.BodyHandlers.ofString()).statusCode() == 401);

            check("an absent case parameter is 400",
                    cli.send(HttpRequest.newBuilder(uri(p, "/api/report"))
                                    .header("Authorization", basic).GET().build(),
                            HttpResponse.BodyHandlers.ofString()).statusCode() == 400);
            check("an unknown case is 404",
                    cli.send(HttpRequest.newBuilder(uri(p, "/api/report?case=case-does-not-exist"))
                                    .header("Authorization", basic).GET().build(),
                            HttpResponse.BodyHandlers.ofString()).statusCode() == 404);
            check("the report is GET only",
                    cli.send(HttpRequest.newBuilder(uri(p, "/api/report?case=case-x"))
                                    .header("Authorization", basic)
                                    .POST(HttpRequest.BodyPublishers.noBody()).build(),
                            HttpResponse.BodyHandlers.ofString()).statusCode() == 405);

            // The shipped weights are uncalibrated, so the model must not open a case by itself.
            HttpResponse<String> auto = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Authorization", basic)
                    .header("Content-Type", "message/rfc822")
                    .POST(HttpRequest.BodyPublishers.ofString(eml("report-plain"))).build(),
                    HttpResponse.BodyHandlers.ofString());
            check("an uncalibrated model opens no case on its own",
                    auto.body().contains("\"caseId\":null"));
            check("the abstention reason is reported", auto.body().contains("caseNotCreated"));
            check("the model's automation gate is reported as closed",
                    auto.body().contains("\"modelCaseCreationEnabled\":false"));

            // A near-miss parameter must not be read as consent to file.
            HttpResponse<String> typo = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze?openCase=yes"))
                    .header("Authorization", basic)
                    .header("Content-Type", "message/rfc822")
                    .POST(HttpRequest.BodyPublishers.ofString(eml("report-typo"))).build(),
                    HttpResponse.BodyHandlers.ofString());
            check("a mistyped openCase value does not open a case",
                    typo.body().contains("\"caseId\":null")
                            && !typo.body().contains("ANALYST_REQUEST"));

            HttpResponse<String> on = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/analyze?openCase=analyst"))
                            .header("Authorization", basic)
                            .header("Content-Type", "message/rfc822")
                            .POST(HttpRequest.BodyPublishers.ofString(eml("report-open"))).build(),
                    HttpResponse.BodyHandlers.ofString());
            check("an explicit analyst request opens a case",
                    on.body().contains("\"caseOrigin\":\"ANALYST_REQUEST\""));
            check("and the model gate is still reported closed",
                    on.body().contains("\"modelCaseCreationEnabled\":false"));
            check("no abstention is claimed once a case exists",
                    !on.body().contains("caseNotCreated"));

            String token = on.headers().firstValue("x-session-token").orElse("");
            check("a session token was minted", !token.isEmpty());
            String caseId = null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"caseId\":\"(case-[0-9a-f]{32})\"").matcher(on.body());
            if (m.find()) caseId = m.group(1);
            check("the case id is server generated and opaque", caseId != null);

            if (caseId != null) {
                HttpResponse<String> rep = cli.send(
                        HttpRequest.newBuilder(uri(p, "/api/report?case=" + caseId))
                                .header("Authorization", bearer(token)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                check("the report is 200", rep.statusCode() == 200);
                check("the report is JSON, not markup",
                        header(rep, "content-type").startsWith("application/json"));
                check("the report keeps the deny-all API policy",
                        header(rep, "content-security-policy").contains("default-src 'none'"));
                check("the report carries the case record", rep.body().contains("\"case\""));
                check("the report carries a STIX bundle",
                        rep.body().contains("\"stix\"") && rep.body().contains("bundle"));
                check("the report carries audit state",
                        rep.body().contains("\"audit\"") && rep.body().contains("records"));
                check("the report names the case it was asked for", rep.body().contains(caseId));
                check("the report discloses no store path",
                        !rep.body().contains("users.ndjson") && !rep.body().contains("cases.ndjson"));
            }

            check("a traversal in the case parameter is refused",
                    cli.send(HttpRequest.newBuilder(
                                    uri(p, "/api/report?case=..%2F..%2Fsrc%2FApp.java"))
                            .header("Authorization", bearer(token)).GET().build(),
                            HttpResponse.BodyHandlers.ofString()).statusCode() != 200);
        } finally {
            app.stop();
        }
    }

    /**
     * The additive breakdown is the one part of the response that claims the score is a sum of
     * named parts, so it is also the one part that can be arithmetically wrong in a way nobody
     * would notice by eye. These checks pin the claim:
     *
     *   z = intercept + sum(per-family contributions) = intercept + sum(per-feature contributions)
     *
     * A frontend that renders "AUTH drove this score" is only telling the truth if the parts
     * actually reconstruct the total, so the identity is asserted here rather than trusted.
     */
    private static void t14_breakdown() throws Exception {
        section("t14 - additive feature breakdown reconstructs the logit");
        App app = null;
        try {
            app = new App(0);
            app.auth().upsert("analyst", ("pw-" + RUN_TAG).toCharArray(), List.of("analyst"));
            app.start();
            HttpClient cli = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
            int p = app.port();
            String basic = "Basic " + Base64.getEncoder().encodeToString(
                    ("analyst:pw-" + RUN_TAG).getBytes(StandardCharsets.UTF_8));

            HttpResponse<String> res = cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                    .header("Authorization", basic)
                    .header("Content-Type", "message/rfc822")
                    .POST(HttpRequest.BodyPublishers.ofString(eml("t14-" + RUN_TAG)))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check("analyze -> 200", res.statusCode() == 200);
            Map<String, Object> j = Json.parseObject(res.body());

            Object rawFb = j.get("featureBreakdown");
            check("featureBreakdown is present", rawFb instanceof Map);
            if (!(rawFb instanceof Map)) return;
            Map<String, Object> fb = (Map<String, Object>) rawFb;

            // Every family is reported, present or not. A family that contributed nothing has to
            // appear as 0, or the frontend cannot tell "no contribution" from "not computed".
            List<Object> fams = Json.arr(fb, "families");
            String[] expected = {"AUTH", "ROUTE", "IDENT", "NLP", "PAYLOAD", "INFRA"};
            check("six families reported", fams.size() == expected.length);
            Set<String> names = new java.util.LinkedHashSet<>();
            for (Object o : fams) names.add(Json.str((Map<String, Object>) o, "name"));
            check("families are exactly the six families",
                    names.equals(new java.util.LinkedHashSet<>(Arrays.asList(expected))));

            double familySum = 0;
            for (Object o : fams) familySum += Json.num((Map<String, Object>) o, "contribution");
            double declaredTotal = Json.num(fb, "totalContribution");
            double featureSum = 0;
            List<Object> perFeature = Json.arr(fb, "perFeature");
            for (Object o : perFeature) {
                Map<String, Object> f = (Map<String, Object>) o;
                // Each row carries the evidence behind its own number, not just the total.
                check("per-feature row " + Json.num(f, "featureIndex")
                                + " names a family in the six",
                        expected_set().contains(Json.str(f, "family")));
                double x = Json.num(f, "x"), beta = Json.num(f, "beta");
                double contribution = Json.num(f, "contribution");
                check("per-feature row " + Json.num(f, "featureIndex") + " satisfies x*beta=contribution",
                        close(x * beta, contribution, 1e-9));
                featureSum += contribution;
            }
            check("findings are not empty for a phishing sample", !perFeature.isEmpty());
            check("family contributions sum to totalContribution",
                    close(familySum, declaredTotal, 1e-9));
            check("per-feature contributions sum to totalContribution",
                    close(featureSum, declaredTotal, 1e-9));

            double intercept = Json.num(fb, "intercept");
            double z = Json.num(fb, "z");
            check("z = intercept + totalContribution", close(intercept + declaredTotal, z, 1e-9));

            // The breakdown reports the raw logit. If z were the squashed probability the verdict
            // shows, the two would be equal; they are different numbers and conflating them would
            // make a log-odds contribution look like a share of the score.
            List<Object> probs = Json.arr(Json.obj(j, "model"), "p");
            List<Object> classes = Json.arr(Json.obj(j, "model"), "classes");
            int argmax = (int) Json.num(Json.obj(j, "model"), "argmax");
            // Classes and families are different axes and deliberately different sizes: a class
            // is a verdict, a family is where the evidence came from.
            check("one probability per class", probs.size() == classes.size());
            check("p[argmax] is the largest probability",
                    argmax >= 0 && argmax < probs.size() && isMax(probs, argmax));
            check("argmax indexes the class distribution", argmax >= 0 && argmax < probs.size());
            if (argmax >= 0 && argmax < probs.size()) {
                double predicted = ((Number) probs.get(argmax)).doubleValue();
                check("z is a logit, not the predicted probability", !close(z, predicted, 1e-6));
                check("z is a logit, not the reported risk",
                        !close(z, Json.num(Json.obj(j, "model"), "riskFinal"), 1e-6));
            }
        } finally {
            if (app != null) app.stop();
        }
}


/**
     * Recursively deletes a directory tree, if present.
     *
     * Used to give one test an exact starting state. Ordering a delete by modification time would
     * be faster and wrong: a child modified after its parent is visited first, and on the trees
     * that matter here (keys/, audit.ndjson) that is the normal case, so the parent would be
     * deleted before its child and the walk would fail on a non-empty directory.
     */
    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (var s = Files.walk(root)) {
            s.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            if (e.getCause() instanceof IOException io) {
                throw io;
            }
            throw e;
        }
    }

    /**
     * Audit assurance: EMPTY -> UNSIGNED -> SIGNED -> parity -> TAMPERED.
     *
     * The whole test runs in its own data directory, set through the documented
     * {@code cipher.squad.dataDir} override and restored afterwards. Sharing the suite's directory
     * made this test unfalsifiable rather than merely fragile: t01-t14 append on every
     * authentication, so by the time step A ran there were already dozens of records, and the
     * signing checkpoints landed on whatever count earlier tests happened to leave behind. The
     * first assertion ("no records") could never have passed for a reason that had anything to do
     * with the code under test.
     *
     * Two details that are the whole point of the test, and that the previous version got wrong:
     *
     * - Provisioning and logging in both append. {@code auth.upsert} writes an auth.provision
     *   record and a Basic login writes a login.success record, so a chain cannot be observed at
     *   zero records over HTTP. Step A therefore reads the engine directly, before any credential
     *   exists, which is the only moment the EMPTY state is real.
     * - The key must exist BEFORE the App that will sign with it is constructed. Provisioning it
     *   afterwards left the running instance reporting signatureConfigured=false for reasons that
     *   had nothing to do with signing.
     */
    private static void t15_auditAssurance() throws Exception {
        section("t15 - audit assurance and signing");
        String saved = System.getProperty("cipher.squad.dataDir");
        Path root = App.dataDir().resolve("t15-audit");
        deleteTree(root);
        Files.createDirectories(root);
        System.setProperty("cipher.squad.dataDir", root.toString());
        App app = null;
        try {
            // ---- Step A: a fresh chain is EMPTY ----
            // Read before provisioning: every credential this test creates appends a record.
            app = new App(0);
            Audit.Verification fresh = app.audit().verify();
            check("t15 step A: records == 0", fresh.records == 0);
            check("t15 step A: lastSignedIndex == -1", fresh.lastSignedIndex == -1);
            check("t15 step A: signatureConfigured == false", !fresh.signatureConfigured);
            check("t15 step A: headSignatureValid == false", !fresh.headSignatureValid);
            app.stop();
            app = null;

            // ---- Step B: key configured, fewer than N records -> UNSIGNED ----
            // Key first: the App constructed below loads it at construction time.
            Path keyPath = root.resolve("keys").resolve("ed25519.pem");
            Files.createDirectories(keyPath.getParent());
            Audit.KeyManager key = Audit.KeyManager.createOrLoad(keyPath);
            check("t15 step B: key generated and loads back", key.configured());
            app = new App(0);
            check("t15 step B: App sees the key", app.audit().verify().signatureConfigured);
            app.auth().upsert("bob", "bobPassword123".toCharArray(), List.of("analyst"));
            app.start();
            HttpClient cli = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();
            int p = app.port();
            String bobBasic = basic("bob", "bobPassword123");
            int N = Config.AUDIT_SIGN_EVERY_N;
            // Each Basic request appends login.success, and each analysis appends its own record,
            // so 10 analyses add ~20 records. That stays well under the first checkpoint at
            // index N-1, which is what makes UNSIGNED the correct answer here rather than a race.
            for (int i = 0; i < 10; i++) {
                cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                        .header("Authorization", bobBasic)
                        .header("Content-Type", "message/rfc822")
                        .POST(HttpRequest.BodyPublishers.ofString(eml("t15b-" + RUN_TAG + "-" + i)))
                        .build(),
                        HttpResponse.BodyHandlers.ofString());
            }
            HttpResponse<String> resp = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/audit/verify"))
                            .header("Authorization", bobBasic)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check("t15 step B: audit verify 200", resp.statusCode() == 200);
            Map<String, Object> json = Json.parseObject(resp.body());
            check("t15 step B: records > 0", ((Number) json.get("records")).longValue() > 0);
            check("t15 step B: records < " + N, ((Number) json.get("records")).longValue() < N);
            check("t15 step B: assurance == UNSIGNED", "UNSIGNED".equals(json.get("assurance")));
            check("t15 step B: lastSignedIndex == -1",
                    ((Number) json.get("lastSignedIndex")).longValue() == -1L);
            check("t15 step B: signatureConfigured == true",
                    Boolean.TRUE.equals(json.get("signatureConfigured")));
            check("t15 step B: reason present", json.containsKey("reason"));
            check("t15 step B: valid == true", Boolean.TRUE.equals(json.get("valid")));
            app.stop();
            app = null;

            // ---- Step C: cross a signing checkpoint -> SIGNED ----
            app = new App(0);
            app.auth().upsert("charlie", "charliePassword123".toCharArray(), List.of("analyst"));
            app.start();
            cli = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
            p = app.port();
            String charlieBasic = basic("charlie", "charliePassword123");
            // Add enough to cross at least one multiple of N, whatever the starting count was.
            while (true) {
                resp = cli.send(
                        HttpRequest.newBuilder(uri(p, "/api/audit/verify"))
                                .header("Authorization", charlieBasic)
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
                json = Json.parseObject(resp.body());
                if (((Number) json.get("lastSignedIndex")).longValue() >= 0) {
                    break;
                }
                cli.send(HttpRequest.newBuilder(uri(p, "/api/analyze"))
                        .header("Authorization", charlieBasic)
                        .header("Content-Type", "message/rfc822")
                        .POST(HttpRequest.BodyPublishers.ofString(eml("t15c-" + RUN_TAG)))
                        .build(),
                        HttpResponse.BodyHandlers.ofString());
            }
            check("t15 step C: audit verify 200", resp.statusCode() == 200);
            check("t15 step C: assurance == SIGNED", "SIGNED".equals(json.get("assurance")));
            long lastSigned = ((Number) json.get("lastSignedIndex")).longValue();
            check("t15 step C: lastSignedIndex >= 0", lastSigned >= 0);
            check("t15 step C: lastSignedIndex is a checkpoint", lastSigned % N == N - 1);
            check("t15 step C: lastSignatureValid == true",
                    Boolean.TRUE.equals(json.get("lastSignatureValid")));
            check("t15 step C: reason present", json.containsKey("reason"));
            check("t15 step C: valid == true", Boolean.TRUE.equals(json.get("valid")));
            String meaning = (String) json.get("assuranceMeaning");
            check("t15 step C: meaning not null", meaning != null);
            check("t15 step C: meaning contains index", meaning.contains("index " + lastSigned));
            app.stop();
            app = null;

            // ---- Step D: report and verify agree on a healthy chain ----
            app = new App(0);
            app.auth().upsert("echo", "echoPassword123".toCharArray(), List.of("analyst"));
            app.start();
            cli = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
            p = app.port();
            String echoBasic = basic("echo", "echoPassword123");
            HttpResponse<String> analResp = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/analyze?openCase=analyst"))
                            .header("Authorization", echoBasic)
                            .header("Content-Type", "message/rfc822")
                            .POST(HttpRequest.BodyPublishers.ofString(eml("t15e-" + RUN_TAG)))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check("t15 step D: analyze 200", analResp.statusCode() == 200);
            String caseId = (String) Json.parseObject(analResp.body()).get("caseId");
            check("t15 step D: caseId not null", caseId != null);
            HttpResponse<String> reportResp = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/report?case=" + caseId))
                            .header("Authorization", echoBasic)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check("t15 step D: report 200", reportResp.statusCode() == 200);
            Map<String, Object> reportAudit =
                    (Map<String, Object>) Json.parseObject(reportResp.body()).get("audit");
            HttpResponse<String> verifyResp = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/audit/verify"))
                            .header("Authorization", echoBasic)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check("t15 step D: verify 200", verifyResp.statusCode() == 200);
            Map<String, Object> verifyJson = Json.parseObject(verifyResp.body());
            check("t15 step D: report assurance matches verify",
                    reportAudit.get("assurance").equals(verifyJson.get("assurance")));
            check("t15 step D: report meaning matches verify",
                    reportAudit.get("assuranceMeaning").equals(verifyJson.get("assuranceMeaning")));
            check("t15 step D: report valid matches verify",
                    reportAudit.get("valid").equals(verifyJson.get("valid")));

            // ---- Step E: tamper a record -> TAMPERED, still reachable ----
            // Take the session token from the healthy request above. Verification has to stay
            // reachable on a broken chain, and Basic cannot do that: logging in appends a
            // login.success record, so on a corrupt chain the login itself throws and the caller
            // gets a 503 with no assurance field instead of the answer they asked for. A Bearer
            // token is validated without writing, which is why the endpoint can report the break.
            String token = header(analResp, "X-Session-Token");
            check("t15 step E: session token issued", !token.isEmpty());

            Path logPath = root.resolve("audit.ndjson");
            List<String> lines = Files.readAllLines(logPath);
            check("t15 step E: log non-empty", !lines.isEmpty());
            int idx = lines.size() / 2;
            Map<String, Object> rec = Json.parseObject(lines.get(idx));
            long tamperedIndex = ((Number) rec.get("index")).longValue();
            rec.put("outcome", "tampered");
            lines.set(idx, Json.write(rec));
            Files.write(logPath, lines);

            HttpResponse<String> tamperResp = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/audit/verify"))
                            .header("Authorization", bearer(token))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check("t15 step E: verify 200 on a tampered chain", tamperResp.statusCode() == 200);
            Map<String, Object> tamperJson = Json.parseObject(tamperResp.body());
            check("t15 step E: ok == false", Boolean.FALSE.equals(tamperJson.get("ok")));
            check("t15 step E: valid == false", Boolean.FALSE.equals(tamperJson.get("valid")));
            check("t15 step E: assurance == TAMPERED", "TAMPERED".equals(tamperJson.get("assurance")));
            check("t15 step E: firstDivergentIndex == " + tamperedIndex,
                    ((Number) tamperJson.get("firstDivergentIndex")).longValue() == tamperedIndex);
            check("t15 step E: reason present", tamperJson.containsKey("reason"));
            String tamperMeaning = (String) tamperJson.get("assuranceMeaning");
            check("t15 step E: meaning not null", tamperMeaning != null);
            check("t15 step E: meaning indicates tampering",
                    tamperMeaning.contains("altered") || tamperMeaning.contains("tampered"));

            // The break must also stop new records: appending to a corrupt chain would bury the
            // evidence, so a write path must refuse rather than extend it.
            HttpResponse<String> writeAfterTamper = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/analyze"))
                            .header("Authorization", bearer(token))
                            .header("Content-Type", "message/rfc822")
                            .POST(HttpRequest.BodyPublishers.ofString(eml("t15e-after-" + RUN_TAG)))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check("t15 step E: write to a tampered chain refused",
                    writeAfterTamper.statusCode() == 503);
            Map<String, Object> refused = Json.parseObject(writeAfterTamper.body());
            check("t15 step E: refusal names the break",
                    "audit_chain_broken".equals(refused.get("error")));

            // The chain must still be tampered, not repaired, and must still report the same break.
            HttpResponse<String> stillTampered = cli.send(
                    HttpRequest.newBuilder(uri(p, "/api/audit/verify"))
                            .header("Authorization", bearer(token))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            Map<String, Object> afterJson = Json.parseObject(stillTampered.body());
            check("t15 step E: still TAMPERED after the refused write",
                    "TAMPERED".equals(afterJson.get("assurance")));
            check("t15 step E: break point unchanged",
                    ((Number) afterJson.get("firstDivergentIndex")).longValue() == tamperedIndex);
            app.stop();
            app = null;
        } finally {
            if (app != null) app.stop();
            if (saved == null) {
                System.clearProperty("cipher.squad.dataDir");
            } else {
                System.setProperty("cipher.squad.dataDir", saved);
            }
            deleteTree(root);
        }
    }


    private static Set<String> expected_set() {
        return new java.util.LinkedHashSet<>(Arrays.asList(
                "AUTH", "ROUTE", "IDENT", "NLP", "PAYLOAD", "INFRA"));
    }

    /** Absolute-or-relative comparison, so a sum assembled in a different order still matches. */
    private static boolean close(double a, double b, double tol) {
        return Math.abs(a - b) <= tol * Math.max(1.0, Math.max(Math.abs(a), Math.abs(b)));
    }

    /** Whether the element at {@code i} is a maximum of {@code xs}. */
    private static boolean isMax(List<Object> xs, int i) {
        double v = ((Number) xs.get(i)).doubleValue();
        for (Object o : xs) if (((Number) o).doubleValue() > v + 1e-12) return false;
        return true;
    }

    public static void main(String[] args) throws Exception {
        long t0 = System.nanoTime();
        System.out.println("Phase 3 tests - CIPHER SQUAD");
        t01_binding();
        t02_routing();
        t03_traversal();
        t04_oversized();
        t05_badPercent();
        t06_authSession();
        t07_lockout();
        t08_ssrf();
        t09_audit();
        t10_cases();
        t11_stix();
        t12_console();
        t13_report();
        t14_breakdown();
        t15_auditAssurance();
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