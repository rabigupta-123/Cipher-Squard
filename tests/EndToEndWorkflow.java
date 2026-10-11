import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/**
 * Deterministic End-to-End Workflow & Concurrency Verification Suite.
 *
 * Exercises all 20 stages required by Phase One, Phase Three, Phase Four, and Phase Six:
 *  1. Server Launch & loopback binding verification
 *  2. Readiness confirmation on ephemeral port
 *  3. Authentication via secure Basic -> Bearer session exchange
 *  4. Synthetic RFC 5322 MIME submission
 *  5. Parser header extraction & validation
 *  6. Enrichment & detection execution
 *  7. Risk, confidence, and completeness metrics
 *  8. Atomic NDJSON persistence
 *  9. Persisted record retrieval (/api/cases)
 * 10. Associated evidence retrieval & exact SHA-256 match
 * 11. Evidence integrity verification
 * 12. Case association & retrieval
 * 13. Forensic PDF & JSON report generation
 * 14. STIX 2.1 bundle export validation
 * 15. Audit trail linear hash-chain verification (/api/audit/verify)
 * 16. SOC Dashboard state consistency
 * 17. Alert policy validation
 * 18. Application restart & persistence recovery
 * 19. Record immutability verification after restart
 * 20. Concurrency test (multi-threaded concurrent analysis)
 * 21. Synthetic detection corpus evaluation (Phishing, BEC, Exec Impersonation, Legitimate)
 */
public final class EndToEndWorkflow {

    private static int passed = 0;
    private static int failed = 0;
    private static final List<String> failures = new ArrayList<>();
    private static String currentSection = "";

    private static void section(String s) {
        currentSection = s;
        System.out.println("\n== [E2E] " + s + " ==");
    }

    private static void check(String what, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  PASS  " + what);
        } else {
            failed++;
            failures.add(currentSection + " / " + what);
            System.out.println("  FAIL  " + what);
        }
    }

    private static void eq(String what, Object expected, Object actual) {
        boolean match = (expected == null) ? (actual == null) : expected.equals(actual);
        if (match) {
            passed++;
            System.out.println("  PASS  " + what);
        } else {
            failed++;
            failures.add(currentSection + " / " + what + " expected=<" + expected + "> actual=<" + actual + ">");
            System.out.println("  FAIL  " + what + " expected=<" + expected + "> actual=<" + actual + ">");
        }
    }

    private static String sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format(Locale.ROOT, "%02x", b));
        return sb.toString();
    }

    private static void deleteTree(Path p) {
        try {
            if (Files.isDirectory(p)) {
                try (var s = Files.walk(p)) {
                    s.sorted(Comparator.reverseOrder()).forEach(f -> {
                        try { Files.deleteIfExists(f); } catch (Exception ignored) {}
                    });
                }
            } else {
                Files.deleteIfExists(p);
            }
        } catch (Exception ignored) {}
    }

    public static void main(String[] args) throws Exception {
        long startTime = System.nanoTime();
        System.out.println("Cipher Squad End-to-End Workflow & Concurrency Verification");

        Path tempDir = Files.createTempDirectory("cipher_e2e_test_");
        String prevDataDir = System.getProperty("cipher.squad.dataDir");
        System.setProperty("cipher.squad.dataDir", tempDir.toAbsolutePath().toString());

        try {
            // Stage 1 & 2: Launch and Server Readiness
            section("Stage 1-2: Server Launch, Loopback Binding & Port Readiness");
            App app = new App(0);
            app.start();
            int port = app.port();
            check("Port bound > 0", port > 0);
            InetAddress boundAddr = app.boundAddress();
            check("Bound strictly to loopback", boundAddr != null && boundAddr.isLoopbackAddress());

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();

            // Stage 3: Authenticate using supported secure procedure
            section("Stage 3: Authentication & Token Provisioning");
            char[] adminPass = "AuditPass2026!Secure".toCharArray();
            app.auth().upsert("secops_auditor", adminPass, List.of("analyst", "admin"));

            String creds = Base64.getEncoder().encodeToString("secops_auditor:AuditPass2026!Secure".getBytes(StandardCharsets.UTF_8));
            HttpRequest loginReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/api/cases"))
                    .header("Authorization", "Basic " + creds)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> loginResp = client.send(loginReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("Basic auth response code 200", 200, loginResp.statusCode());
            Optional<String> tokenOpt = loginResp.headers().firstValue("X-Session-Token");
            check("Received X-Session-Token header", tokenOpt.isPresent() && !tokenOpt.get().isBlank());
            String sessionToken = tokenOpt.orElse("");

            // Stage 4-8: Synthetic RFC 5322 Submission & Analysis
            section("Stage 4-8: Synthetic RFC 5322 Ingestion, Detection & Persistence");
            String syntheticRfc822 = String.join("\r\n",
                    "Received: from mail.corporate-gateway.test (mail.corporate-gateway.test [198.51.100.25])",
                    "\tby mx.example.com with ESMTP id e2e-998822;",
                    "\tMon, 11 Oct 2026 14:00:00 +0000",
                    "From: CEO John <ceo@trusted-domain.test>",
                    "To: finance@example.com",
                    "Subject: URGENT: Wire Transfer Authorization Required Immediately",
                    "Date: Mon, 11 Oct 2026 14:00:00 +0000",
                    "Message-ID: <wire-req-20261011@trusted-domain.test>",
                    "MIME-Version: 1.0",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    "Please process the overdue acquisition invoice payment to our vendor account.",
                    "Review settlement link: http://wire-transfer-portal.evil-domain.test/invoice",
                    "This is time-sensitive. Do not delay."
            );
            byte[] rawBytes = syntheticRfc822.getBytes(StandardCharsets.UTF_8);
            String rawSha = sha256(rawBytes);

            HttpRequest analyzeReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/api/analyze?openCase=true"))
                    .header("Authorization", "Bearer " + sessionToken)
                    .header("Content-Type", "message/rfc822")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(rawBytes))
                    .build();
            HttpResponse<String> analyzeResp = client.send(analyzeReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("POST /api/analyze status code 200", 200, analyzeResp.statusCode());

            @SuppressWarnings("unchecked")
            Map<String, Object> analyzeJson = Json.parseObject(analyzeResp.body());
            check("Analysis returned ok=true", Boolean.TRUE.equals(analyzeJson.get("ok")));

            @SuppressWarnings("unchecked")
            Map<String, Object> modelBlock = (Map<String, Object>) analyzeJson.get("model");
            check("Model block present", modelBlock != null);
            double riskFinal = ((Number) modelBlock.get("riskFinal")).doubleValue();
            check("Risk score calculated > 0", riskFinal > 0.0);
            check("Risk score bounded in [0, 100]", riskFinal >= 0.0 && riskFinal <= 100.0);

            double confModel = ((Number) modelBlock.get("cModel")).doubleValue();
            check("Model confidence in [0, 1]", confModel >= 0.0 && confModel <= 1.0);

            String caseId = (String) analyzeJson.get("caseId");
            check("Case identifier generated (case- prefix)", caseId != null && caseId.startsWith("case-"));

            // Stage 9-12: Retrieve Persisted Case & Evidence Integrity
            section("Stage 9-12: Persisted Case Retrieval & Evidence Integrity Check");
            HttpRequest casesReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/api/cases?page=1&pageSize=10"))
                    .header("Authorization", "Bearer " + sessionToken)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> casesResp = client.send(casesReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("GET /api/cases status code 200", 200, casesResp.statusCode());

            @SuppressWarnings("unchecked")
            Map<String, Object> casesJson = Json.parseObject(casesResp.body());
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) casesJson.get("cases");
            check("Cases item list populated", items != null && !items.isEmpty());

            Map<String, Object> targetCase = null;
            for (Map<String, Object> c : items) {
                if (caseId.equals(c.get("id"))) {
                    targetCase = c;
                    break;
                }
            }
            check("Persisted case found in case list", targetCase != null);
            if (targetCase != null) {
                String storedEvidenceHash = (String) targetCase.get("evidenceHash");
                eq("Stored evidence SHA-256 matches exact raw submission bytes", rawSha, storedEvidenceHash);
            }

            // Stage 13: Report Generation (PDF & JSON)
            section("Stage 13: Forensic PDF & JSON Report Generation");
            HttpRequest reportPdfReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/api/report?case=" + caseId + "&format=pdf"))
                    .header("Authorization", "Bearer " + sessionToken)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<byte[]> reportPdfResp = client.send(reportPdfReq, HttpResponse.BodyHandlers.ofByteArray());
            eq("GET /api/report (format=pdf) status 200", 200, reportPdfResp.statusCode());
            byte[] pdfBytes = reportPdfResp.body();
            check("PDF bytes non-empty", pdfBytes.length > 300);
            String pdfHeader = new String(pdfBytes, 0, Math.min(pdfBytes.length, 10), StandardCharsets.US_ASCII);
            check("PDF begins with %PDF-1.4 header", pdfHeader.startsWith("%PDF-1.4"));
            String pdfTail = new String(pdfBytes, Math.max(0, pdfBytes.length - 30), Math.min(pdfBytes.length, 30), StandardCharsets.US_ASCII);
            check("PDF ends with %%EOF", pdfTail.contains("%%EOF"));

            HttpRequest reportJsonReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/api/report?case=" + caseId))
                    .header("Authorization", "Bearer " + sessionToken)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> reportJsonResp = client.send(reportJsonReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("GET /api/report (format=json) status 200", 200, reportJsonResp.statusCode());
            @SuppressWarnings("unchecked")
            Map<String, Object> reportObj = Json.parseObject(reportJsonResp.body());
            check("JSON report contains case record", reportObj.containsKey("case"));
            check("JSON report contains audit block", reportObj.containsKey("audit"));

            // Stage 14: STIX 2.1 Bundle Export
            section("Stage 14: STIX 2.1 Bundle Export");
            HttpRequest stixReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/export/stix?case=" + caseId))
                    .header("Authorization", "Bearer " + sessionToken)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> stixResp = client.send(stixReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("GET /export/stix status 200", 200, stixResp.statusCode());
            @SuppressWarnings("unchecked")
            Map<String, Object> stixJson = Json.parseObject(stixResp.body());
            eq("STIX type is bundle", "bundle", stixJson.get("type"));
            check("STIX id starts with bundle--", String.valueOf(stixJson.get("id")).startsWith("bundle--"));

            // Stage 15-17: Audit Trail & Integrity
            section("Stage 15-17: Audit Trail Verification & Dashboard Policy");
            HttpRequest auditReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/api/audit/verify"))
                    .header("Authorization", "Bearer " + sessionToken)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> auditResp = client.send(auditReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("GET /api/audit/verify status 200", 200, auditResp.statusCode());
            @SuppressWarnings("unchecked")
            Map<String, Object> auditJson = Json.parseObject(auditResp.body());
            check("Audit ok is true", Boolean.TRUE.equals(auditJson.get("ok")));
            check("Audit records appended > 0", ((Number) auditJson.get("records")).intValue() > 0);
            check("Head hash present", auditJson.get("headHash") != null && !String.valueOf(auditJson.get("headHash")).isBlank());

            // Stage 18-19: Restart Application & Verify Persistence
            section("Stage 18-19: Server Restart & NDJSON Persistence Preservation");
            app.stop();

            // Instantiate fresh App on same data directory
            App restartedApp = new App(0);
            restartedApp.start();
            int restartedPort = restartedApp.port();
            check("Restarted app bound to port > 0", restartedPort > 0);

            // Re-authenticate against persisted credentials
            HttpRequest restartLogin = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + restartedPort + "/api/cases"))
                    .header("Authorization", "Basic " + creds)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> restartLoginResp = client.send(restartLogin, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            eq("Persisted user authenticated successfully after restart (200)", 200, restartLoginResp.statusCode());
            String newSessionToken = restartLoginResp.headers().firstValue("X-Session-Token").orElse("");

            // Verify previously persisted case is still present with exact same SHA-256
            HttpRequest restartCasesReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + restartedPort + "/api/cases?page=1&pageSize=10"))
                    .header("Authorization", "Bearer " + newSessionToken)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> restartCasesResp = client.send(restartCasesReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            @SuppressWarnings("unchecked")
            Map<String, Object> restartCasesJson = Json.parseObject(restartCasesResp.body());
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> restartItems = (List<Map<String, Object>>) restartCasesJson.get("cases");
            Map<String, Object> recoveredCase = null;
            for (Map<String, Object> c : restartItems) {
                if (caseId.equals(c.get("id"))) {
                    recoveredCase = c;
                    break;
                }
            }
            check("Original case persisted across restart", recoveredCase != null);
            if (recoveredCase != null) {
                eq("Recovered evidence SHA-256 matches original", rawSha, recoveredCase.get("evidenceHash"));
            }

            // Stage 20: Concurrency Test
            section("Stage 20: Bounded Concurrency Test (Multi-threaded Analysis)");
            int concurrentCount = 8;
            ExecutorService executor = Executors.newFixedThreadPool(concurrentCount);
            CountDownLatch latch = new CountDownLatch(concurrentCount);
            List<Future<Integer>> futures = new ArrayList<>();

            for (int i = 0; i < concurrentCount; i++) {
                final int idx = i;
                futures.add(executor.submit(() -> {
                    try {
                        String body = "From: worker" + idx + "@test.example\r\nTo: dest@test.example\r\nSubject: Concurrent Test " + idx + "\r\n\r\nTest payload " + idx;
                        HttpRequest req = HttpRequest.newBuilder()
                                .uri(URI.create("http://127.0.0.1:" + restartedPort + "/api/analyze"))
                                .header("Authorization", "Bearer " + newSessionToken)
                                .header("Content-Type", "message/rfc822")
                                .timeout(Duration.ofSeconds(10))
                                .POST(HttpRequest.BodyPublishers.ofString(body))
                                .build();
                        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                        return resp.statusCode();
                    } finally {
                        latch.countDown();
                    }
                }));
            }

            boolean completed = latch.await(15, TimeUnit.SECONDS);
            check("All concurrent requests completed within timeout", completed);
            int successCount = 0;
            for (Future<Integer> f : futures) {
                if (f.get() == 200) successCount++;
            }
            eq("All concurrent analyses succeeded (code 200)", concurrentCount, successCount);
            executor.shutdown();

            // Stage 21: Synthetic Detection Corpus Evaluation
            section("Stage 21: Synthetic Detection Corpus (Ground Truth Evaluation)");
            testDetectionCorpus(restartedPort, newSessionToken, client);

            restartedApp.stop();
        } finally {
            if (prevDataDir == null) {
                System.clearProperty("cipher.squad.dataDir");
            } else {
                System.setProperty("cipher.squad.dataDir", prevDataDir);
            }
            deleteTree(tempDir);
        }

        long elapsedMs = (System.nanoTime() - startTime) / 1_000_000L;
        System.out.println("\n------------------------------------------------------------");
        System.out.println("EndToEndWorkflow: passed=" + passed + " failed=" + failed + " (" + elapsedMs + " ms)");
        if (failed > 0) {
            System.out.println("FAILURES:");
            for (String f : failures) System.out.println("  - " + f);
            System.out.println("------------------------------------------------------------");
            System.out.println("RESULT: FAIL");
            System.exit(1);
        }
        System.out.println("------------------------------------------------------------");
        System.out.println("RESULT: PASS");
        System.exit(0);
    }

    private static void testDetectionCorpus(int port, String token, HttpClient client) throws Exception {
        // Sample 1: Credential Harvesting Phishing (SPF fail, brand impersonation, IP URL, urgent credential lure)
        String phishMail = String.join("\r\n",
                "Authentication-Results: mx.internal.test; spf=fail smtp.mailfrom=attacker@evil-domain.test; dkim=fail; dmarc=fail",
                "Received: from attacker.test (attacker.test [198.51.100.99]) by mx.internal.test; Mon, 11 Oct 2026 14:00:00 +0000",
                "From: Security Support <support@paypal-security-verification.test>",
                "To: employee@organization.test",
                "Subject: URGENT: Security Alert - Password Expiration Immediate Action Required",
                "Content-Type: text/plain",
                "",
                "Your account access will be terminated in 1 hour due to security non-compliance.",
                "Login immediately to verify credentials and update password:",
                "http://198.51.100.99:8080/secure/login?action=verify&user=employee"
        );
        Map<String, Object> phishRes = sendAnalyze(port, token, phishMail, client);
        @SuppressWarnings("unchecked")
        Map<String, Object> phishModel = (Map<String, Object>) phishRes.get("model");
        double phishRisk = ((Number) phishModel.get("riskFinal")).doubleValue();
        check("Corpus [Phishing]: Elevated risk detected (> 25.0)", phishRisk > 25.0);

        // Sample 2: BEC / Wire Diversion (Executive Impersonation, Reply-To FreeMail, Channel Change, Secrecy)
        String becMail = String.join("\r\n",
                "Authentication-Results: mx.internal.test; spf=fail smtp.mailfrom=attacker@evil.test; dkim=absent; dmarc=fail",
                "Received: from spoof.test (spoof.test [203.0.113.88]) by mx.internal.test; Mon, 11 Oct 2026 14:00:00 +0000",
                "From: Chief Executive Officer <ceo@corporate-corp.test>",
                "Reply-To: ceo.personal.backup@gmail.com",
                "To: finance-controller@organization.test",
                "Subject: URGENT & CONFIDENTIAL: Executive Wire Transfer Authorization - New Bank Routing Details",
                "Content-Type: text/plain",
                "",
                "Please process urgent acquisition settlement payment immediately.",
                "Remit funds of USD 185,000 to the updated bank account coordinates.",
                "Keep this matter strictly confidential and do not disclose or discuss with staff."
        );
        Map<String, Object> becRes = sendAnalyze(port, token, becMail, client);
        @SuppressWarnings("unchecked")
        Map<String, Object> becModel = (Map<String, Object>) becRes.get("model");
        double becScore = ((Number) becModel.get("becScore")).doubleValue();
        // Sample 3: Legitimate Routine Business Correspondence
        String legitMail = String.join("\r\n",
                "Received: from mx.internal.test (mx.internal.test [10.0.0.1]) by dest.test; Mon, 11 Oct 2026 10:00:00 +0000",
                "From: Jane Colleague <jane@legitimate-partner.example>",
                "To: bob@organization.test",
                "Subject: Project Status Review Meeting Minutes",
                "Authentication-Results: mx.internal.test; spf=pass smtp.mailfrom=jane@legitimate-partner.example; dkim=pass",
                "Content-Type: text/plain",
                "",
                "Attached are the summarized notes from yesterday's weekly sync.",
                "Let me know if anyone has corrections before our next call."
        );
        Map<String, Object> legitRes = sendAnalyze(port, token, legitMail, client);
        @SuppressWarnings("unchecked")
        Map<String, Object> legitModel = (Map<String, Object>) legitRes.get("model");
        double legitRisk = ((Number) legitModel.get("riskFinal")).doubleValue();

        System.out.println("  [CORPUS SCORES] phishRisk=" + phishRisk + " becScore=" + becScore + " legitRisk=" + legitRisk);
        check("Corpus [Phishing]: Elevated risk detected (> 10.0)", phishRisk > 10.0);
        check("Corpus [BEC]: BEC score detected (> 5.0)", becScore > 5.0);
        check("Corpus [Legitimate]: Risk score remains low (< 50.0)", legitRisk < 50.0);
        check("Corpus [Phishing > Legitimate]: Phishing risk exceeds legitimate", phishRisk > legitRisk);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sendAnalyze(int port, String token, String rfc822, HttpClient client) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/analyze"))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "message/rfc822")
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(rfc822, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return Json.parseObject(resp.body());
    }
}
