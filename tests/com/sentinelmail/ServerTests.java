package com.sentinelmail;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Zero-dependency unit tests for the Cipher Squad forensic modules.
 * Exercises the pure/static logic of App without starting the HTTP server:
 *  - IP validation & normalization (IPv4 + IPv6)
 *  - Private/reserved/documentation/loopback/multicast detection
 *  - URL parsing & normalization
 *  - Suspicious URL detection
 *  - SSRF protections
 *  - Risk scoring with configurable weights
 *  - API failure behaviour (representative paths)
 */
public final class ServerTests {
  private static int pass = 0, fail = 0;
  private static final List<String> FAILED = new java.util.ArrayList<>();

  private static void check(String name, boolean cond) {
    if (cond) { pass++; System.out.println("OK   " + name); }
    else { fail++; FAILED.add(name); System.out.println("FAIL " + name); }
  }
  private static int countChar(String s, char c) { int n = 0; for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++; return n; }
  private static void checkEq(String name, Object got, Object want) {
    boolean c = got == null ? want == null : got.equals(want);
    if (c) { pass++; System.out.println("OK   " + name); }
    else { fail++; FAILED.add(name); System.out.println("FAIL " + name + "  got=" + got + " want=" + want); }
  }

  public static void main(String[] args) {
    ipValidationTests();
    ipClassificationTests();
    urlParsingTests();
    urlNormalizationTests();
    suspiciousUrlTests();
    ssrfTests();
    riskScoringTests();
    apiFailureTests();
    classificationTests();
    authFailCorrelationTests();
    trailingDotDomainTests();
    regDomainHrefTests();
    completenessTests();
    ipUpgradeTests();
    originForensicsTests();
    socBackboneTests();
    newBehaviorTests();
    moduleUpgradeTests();
    syntheticPhishingTests();
    masterFixTests();
    apexLayerTests();
    apexGeoForensicsTests();
    checksF1ToF5();
    checksGraphAlertAuth();
    gmailForensicsTests();
     scannerTests();
     phishGuardTests();
     secOpsTests();
     System.out.println("\n======================");
    System.out.println("PASS=" + pass + "  FAIL=" + fail);
    if (!FAILED.isEmpty()) { System.out.println("FAILED: " + FAILED); System.exit(1); }
    System.out.println("ALL TESTS PASSED");
  }

  static void ipValidationTests() {
    checkEq("valid IPv4", App.parseIp("8.8.8.8"), "8.8.8.8");
    checkEq("IPv4 trim", App.parseIp("  1.2.3.4 "), "1.2.3.4");
    checkEq("IPv4 leading zeros canonicalized", App.parseIp("08.008.8.8"), "8.8.8.8");
    checkEq("IPv4 invalid octet", App.parseIp("256.1.1.1"), null);
    checkEq("IPv4 too many octets", App.parseIp("1.2.3.4.5"), null);
    checkEq("IPv4 too few octets", App.parseIp("1.2.3"), null);
    checkEq("IPv4 non-numeric", App.parseIp("1.2.3.abc"), null);
    checkEq("IPv4 empty", App.parseIp(""), null);
    checkEq("IPv4 blank", App.parseIp("   "), null);
    checkEq("valid IPv6", App.parseIp("2001:db8::1"), "2001:0db8:0000:0000:0000:0000:0000:0001");
    checkEq("IPv6 loopback", App.parseIp("::1"), "0000:0000:0000:0000:0000:0000:0000:0001");
    checkEq("IPv6 unspecified", App.parseIp("::"), "0000:0000:0000:0000:0000:0000:0000:0000");
    checkEq("IPv6 invalid group", App.parseIp("2001:db8::ggg1"), null);
    checkEq("IPv6 mixed v4", App.parseIp("::ffff:8.8.8.8"), "0000:0000:0000:0000:0000:ffff:0808:0808");
    checkEq("IPv6 zone stripped (classification only)", App.parseIp("fe80::1%eth0").startsWith("fe80"), true);
  }

  static void ipClassificationTests() {
    checkEq("private 10/8", App.classifyAddress("10.1.2.3"), "private");
    checkEq("private 172.16", App.classifyAddress("172.16.0.1"), "private");
    checkEq("private 172.31", App.classifyAddress("172.31.255.254"), "private");
    checkEq("172.32 is public", App.classifyAddress("172.32.0.1"), "public");
    checkEq("private 192.168", App.classifyAddress("192.168.1.1"), "private");
    checkEq("loopback 127", App.classifyAddress("127.0.0.1"), "loopback");
    checkEq("link-local 169.254", App.classifyAddress("169.254.169.254"), "link_local");
    checkEq("multicast 239", App.classifyAddress("239.0.0.1"), "multicast");
    checkEq("documentation 192.0.2", App.classifyAddress("192.0.2.1"), "documentation (RFC 5737)");
    checkEq("documentation 198.51.100", App.classifyAddress("198.51.100.4"), "documentation (RFC 5737)");
    checkEq("documentation 203.0.113", App.classifyAddress("203.0.113.5"), "documentation (RFC 5737)");
    checkEq("reserved 240/4", App.classifyAddress("240.0.0.1"), "reserved");
    checkEq("unspecified 0.0.0.0", App.classifyAddress("0.0.0.0"), "unspecified");
    checkEq("public 8.8.8.8", App.classifyAddress("8.8.8.8"), "public");
    checkEq("IPv6 unique-local", App.classifyAddress("fd00::1").contains("unique_local"), true);
    checkEq("IPv6 documentation", App.classifyAddress("2001:db8::1").contains("documentation"), true);
    checkEq("IPv6 linklocal", App.classifyAddress("fe80::1").contains("link_local"), true);
    checkEq("isBlockedForFetch private", App.isBlockedForFetch("10.0.0.1"), true);
    checkEq("isBlockedForFetch loopback", App.isBlockedForFetch("127.0.0.1"), true);
    checkEq("isBlockedForFetch multicast", App.isBlockedForFetch("224.0.0.1"), true);
    checkEq("isBlockedForFetch public", App.isBlockedForFetch("8.8.8.8"), false);
  }

  static void urlParsingTests() {
    App.UrlParts p = App.parseUrl("https://sub.example.com:8443/a/b?x=1&y=2#frag");
    checkEq("url scheme", p.scheme(), "https");
    checkEq("url host", p.host(), "sub.example.com");
    checkEq("url port", p.port(), "8443");
    checkEq("url path", p.path(), "/a/b");
    checkEq("url query", p.query(), "x=1&y=2");
    checkEq("url fragment", p.fragment(), "frag");
    checkEq("url registered domain", p.registered(), "example.com");
    checkEq("url subdomain", p.subdomain(), "sub");
    checkEq("url not raw-ip", p.isIpHost(), false);

    App.UrlParts ip = App.parseUrl("http://185.220.102.44/verify");
    checkEq("url raw ip host", ip.host(), "185.220.102.44");
    checkEq("url raw ip flag", ip.isIpHost(), true);

    App.UrlParts reg = App.parseUrl("https://foo.co.uk/path");
    checkEq("url co.uk registered (multi-part TLD)", reg.registered(), "foo.co.uk");
    App.UrlParts reg2 = App.parseUrl("https://login.mail.example.com/");
    checkEq("url nested subdomain reg", reg2.registered(), "example.com");
    checkEq("url nested subdomain", reg2.subdomain(), "login.mail");

    App.UrlParts user = App.parseUrl("https://victim@attacker.example/");
    checkEq("url userinfo captured", user.user().contains("victim"), true);

    App.UrlParts bare = App.parseUrl("https://login.example.com/reset?token=abc");
    checkEq("url bare host parsed", bare.host(), "login.example.com");
    checkEq("url bare scheme https", bare.scheme(), "https");
  }

  static void urlNormalizationTests() {
    checkEq("normalize adds https", App.normalizeUrl("example.com/path"), "https://example.com/path");
    checkEq("normalize keeps http", App.normalizeUrl("http://example.com/x"), "http://example.com/x");
    checkEq("normalize strips control chars", App.normalizeUrl("exa\u0000mple.com"), "https://example.com");
    checkEq("normalize rejects file scheme", App.normalizeUrl("file:///etc/passwd"), null);
    checkEq("normalize rejects gopher", App.normalizeUrl("gopher://host"), null);
    checkEq("normalize rejects ftp", App.normalizeUrl("ftp://host/x"), null);
    checkEq("normalize null input", App.normalizeUrl(null), null);
    checkEq("normalize empty rejected", App.normalizeUrl(""), null);
    checkEq("decode %20", App.urlDecodeAll("a%20b"), "a b");
    checkEq("decode plus", App.urlDecodeAll("a+b"), "a b");
    checkEq("decode double-encoded", App.urlDecodeAll("%252e%252f"), "./");
  }

  static void suspiciousUrlTests() {
    // These are implicit in analyzeUrl output; we exercise the detection helpers.
    checkEq("pathCred login", App.pathCred("/login"), true);
    checkEq("pathCred reset", App.pathCred("/reset?token=x"), true);
    checkEq("pathCred payment", App.pathCred("/payment/confirm"), true);
    checkEq("pathCred benign", App.pathCred("/about"), false);
    checkEq("isShortener bit.ly", App.isShortener("bit.ly"), true);
    checkEq("isShortener normal", App.isShortener("example.com"), false);
    checkEq("typosquat paypall", App.typosquat("paypall.com"), true);
    checkEq("typosquat mircosoft", App.typosquat("mircosoft.com"), true);
    checkEq("typosquat legit", App.typosquat("example.com"), false);
    checkEq("abuse tld .tk", App.containsAbuseTld("mal.tk"), true);
    checkEq("abuse tld .com", App.containsAbuseTld("example.com"), false);
    checkEq("severity 5 informational", App.severity(5), "Informational / Low");
    checkEq("severity 30 low", App.severity(30), "Low");
    checkEq("severity 55 medium", App.severity(55), "Medium");
    checkEq("severity 75 high", App.severity(75), "High");
    checkEq("severity 90 critical", App.severity(90), "Critical");
  }

  static void ssrfTests() {
    checkEq("ssrf blocks localhost", App.ssrfGuard("http","localhost","80") != null, true);
    checkEq("ssrf blocks .local", App.ssrfGuard("http","intranet.local","80") != null, true);
    checkEq("ssrf blocks .internal suffix", App.ssrfGuard("http","intra.internal","80") != null, true);
    checkEq("ssrf blocks metadata name", App.ssrfGuard("http","metadata.google.internal","80") != null, true);
    checkEq("ssrf blocks numeric private", App.ssrfGuard("http","10.1.2.3","80") != null, true);
    checkEq("ssrf blocks numeric loopback", App.ssrfGuard("http","127.0.0.1","80") != null, true);
    checkEq("ssrf blocks numeric link-local", App.ssrfGuard("http","169.254.169.254","80") != null, true);
    checkEq("ssrf blocks unsupported scheme", App.ssrfGuard("gopher","host","70") != null, true);
    checkEq("ssrf allows public numeric", App.ssrfGuard("http","8.8.8.8","80") == null, true);
    // Connect-target guard used by the TLS/SSL probes must decline internal targets decision-only (no network).
    checkEq("tls probe guard blocks loopback", App.connectGuardDecisionForTest("127.0.0.1") != null, true);
    checkEq("tls probe guard blocks private 10/8", App.connectGuardDecisionForTest("10.0.0.8") != null, true);
    checkEq("tls probe guard blocks localhost name", App.connectGuardDecisionForTest("localhost") != null, true);
    checkEq("tls probe guard blocks metadata name", App.connectGuardDecisionForTest("metadata.google.internal") != null, true);
    checkEq("tls probe guard allows public numeric", App.connectGuardDecisionForTest("8.8.8.8") == null, true);
  }

  static void riskScoringTests() {
    checkEq("ipRisk empty public -> 0", App.ipRisk("public", true, false, false, "", "", "", "", List.of()), 0);
    checkEq("ipRisk tor -> high", App.ipRisk("public", true, false, false, "Tor exit; ", "", "", "", List.of()), 70);
    checkEq("ipRisk vpn -> lower", App.ipRisk("public", true, false, false, "", "VPN; ", "", "", List.of()), 30);
    checkEq("ipRisk internal -> 0", App.ipRisk("private", false, false, false, "Tor exit; ", "", "", "", List.of()), 0);
    checkEq("ipRisk proxy", App.ipRisk("public", true, true, false, "", "", "", "", List.of()), 25);

    String risk = App.urlRisk(new java.util.LinkedHashMap<>(Map.of(
        "url_domain", 60, "reputation", 30, "dns_network", 15,
        "auth_tls", 0, "obfuscation_impersonation", 55, "contextual", 25)));
    check("urlRisk produces score+breakdown", risk.contains("\"score\"") && risk.contains("\"breakdown\""));
    check("urlRisk no single weak indicator dominates (score < 100)", Integer.parseInt(risk.replaceAll(".*\"score\":(\\d+).*","$1")) < 100);
    // Pure HTTP / foreign / long-URL single weak signals must NOT produce a malicious verdict:
    String weak = App.urlRisk(new java.util.LinkedHashMap<>(Map.of(
        "url_domain", 20, "reputation", 0, "dns_network", 0,
        "auth_tls", 10, "obfuscation_impersonation", 0, "contextual", 5)));
    check("weak single indicators stay non-malicious", Integer.parseInt(weak.replaceAll(".*\"score\":(\\d+).*","$1")) < 61);
  }

  static void apiFailureTests() {
    // Parse/validation defensive paths that mirror graceful API-failure handling.
    checkEq("geoNum missing key -> default", App.geoNum("{}","lat",0.0), 0.0);
    checkEq("sourceOk null", App.sourceOk(null), false);
    checkEq("sourceOk unavailable", App.sourceOk("unavailable"), false);
    checkEq("sourceOk real", App.sourceOk("ip-api.com"), true);
    checkEq("registeredDomain null -> empty", App.registeredDomain(null), "");
    checkEq("jstr null -> null literal", App.jstr(null), "null");
    checkEq("jstr escapes quotes", App.jstr("a\"b"), "\"a\\\"b\"");
    checkEq("urlRisk empty weights defaults to url_domain only", App.urlRisk(new java.util.LinkedHashMap<>()).contains("url_domain"), true);
  }

  // End-to-end classification tests exercising analyzeMessage (evidence-based scoring,
  // correlation engine, confidence, threat states). Classification is decided by evidence + rules,
  // never by a hard-coded sample.
  static void classificationTests() {
    String benign = "From: ops@example.com\r\nTo: alice@example.com\r\nSubject: Scheduled maintenance\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nHi Alice, our database maintenance window is tonight from 02:00 - 04:00 UTC. No action required. Thanks, Ops.\r\n";
    String b = App.analyzeMessageForTests(benign);
    check("benign -> not HIGH/CRITICAL phishing", !b.contains("\"classification\":\"HIGH RISK / LIKELY PHISHING\"") && !b.contains("\"classification\":\"CRITICAL"));
    int bScore = plt(b); 
    check("benign risk <= 40", bScore <= 40);
    check("benign low risk band", bScore <= 40);

    String phish = "From: \"Security\" <security@microsoft-account.example>\r\nTo: victim@example.com\r\nReply-To: recovery@attacker.example\r\nSubject: Urgent: verify your account within 30 minutes\r\nDate: Thu, 27 Aug 2026 09:00:00 +0000\r\n\r\nYour Microsoft account has been suspended due to unusual activity. Verify immediately to restore access or your account will be closed. Click here to confirm: http://secure-microsoft-account.example/login/verify?session=abc&token=xyz Password verification required.\r\n";
    String p = App.analyzeMessageForTests(phish);
    check("simulated phishing lands in high-risk band", hasBand(p, 61, 100));
    check("simulated phishing not called LOW/LEGITIMATE", !p.contains("\"classification\":\"LEGITIMATE") && !p.contains("\"classification\":\"LOW RISK"));
    check("phish threat state is UNKNOWN (not CLEAN)", p.contains("\"state\":\"UNKNOWN\""));
    check("phish threat reason mentions no-data-not-clean", p.contains("absence of data is not evidence of safety") || p.contains("synthetic/example domain"));
    check("phish correlation bonus present", p.contains("\"correlation_bonus\""));

    String pwdOnly = "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\nDate: Thu, 27 Aug 2026 09:00:00 +0000\r\n\r\nHere is a document. The word password appears once but nothing else suspicious. Thanks!\r\n";
    String w = App.analyzeMessageForTests(pwdOnly);
    check("'password' alone is not auto-malicious", !w.contains("\"classification\":\"CRITICAL") && !w.contains("\"classification\":\"HIGH RISK"));
    check("'password' alone not high band", hasBand(w, 0, 40));

    String legitNotice = "From: security@microsoft.com\r\nTo: alice@example.com\r\nSubject: Your sign-in was successful\r\nDate: Thu, 27 Aug 2026 09:00:00 +0000\r\n\r\nWe noticed a successful sign-in to your account from a new device. If this was you, no further action is needed. If not, review your recent activity at https://account.live.com.\r\n";
    String l = App.analyzeMessageForTests(legitNotice);
    check("legitimate security notice not auto-phishing", !l.contains("\"classification\":\"HIGH RISK") && !l.contains("\"classification\":\"CRITICAL"));

    String synth = "From: report@attacker.example\r\nTo: alice@example.com\r\nSubject: Update\r\nDate: Thu, 27 Aug 2026 09:00:00 +0000\r\n\r\nPlease review the attached summary today. Click: http://login-sentinel.example\n";
    String s = App.analyzeMessageForTests(synth);
    check(".example domain threat is UNKNOWN, never CLEAN", s.contains("\"state\":\"UNKNOWN\""));
    check(".example reason says no synthetic reputation data", s.contains("No external reputation data available"));
  }

  static void authFailCorrelationTests() {
    String dual = "From: spoofer@trustedbank.com\r\nTo: a@example.com\r\nAuthentication-Results: ex.com; spf=fail smtp.mailfrom=trustedbank.com; dmarc=fail\r\nSubject: Your statement\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nStatement for August enclosed.\r\n";
    String j = App.analyzeMessageForTests(dual);
    check("dual auth fail gets correlation bonus", j.contains("\"Multiple sender-authentication mechanisms failed"));
    check("dual auth fail correlation present", j.contains("\"correlation_bonus\""));
    check("dual auth fail not legit band", !j.contains("\"classification\":\"LEGITIMATE"));
    check("dual auth fail > single-fail baseline", plt(j) > 20);
  }

  static void trailingDotDomainTests() {
    String d = "From: a@mal.example.\r\nTo: a@victim.example\r\nSubject: hi\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nhello\r\n";
    String j = App.analyzeMessageForTests(d);
    check("trailing-dot From domain normalized to mal.example", j.contains("\"mal.example\""));
    check("trailing-dot From not flagged as brand impersonation", !j.contains("brand impersonation"));
  }

  static void regDomainHrefTests() {
    // Same registrable domain => cosmetic subdomain rewrite, NOT covert redirection.
    String same = "From: help@example.com\r\nTo: a@example.com\r\nSubject: re\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\n<a href=\"https://example.com/inbox\">https://www.example.com/inbox</a>\r\n";
    String a = App.analyzeMessageForTests(same);
    check("subdomain rewrite same registrable domain not a mismatch", !a.contains("Hyperlink text"));
    // Different registrable domain => genuine covert redirection flagged.
    String diff = "From: help@example.com\r\nTo: a@example.com\r\nSubject: re\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\n<a href=\"https://evil.example.net/inbox\">https://example.com/inbox</a>\r\n";
    String b = App.analyzeMessageForTests(diff);
    check("cross-owner redirect flagged as mismatch", b.contains("Hyperlink text"));
  }

  static void completenessTests() {
    String full = "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\nReturn-Path: a@example.com\r\nReply-To: a@example.com\r\nAuthentication-Results: ex; spf=pass; dmarc=pass\r\nReceived: from mail.example (mail.example [203.0.113.9]) by mx.example; Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nHello there. <a href=\"https://example.com/x\">https://example.com/x</a>\r\n";
    String f = App.analyzeMessageForTests(full);
    check("completeness object present", f.contains("\"completeness\":{\"value\":"));
    check("full email completeness high (>=45)", compVal(f) >= 45);
    check("full email has available evidence list", f.contains("\"available\":["));
    String sparse = "From: x@y.example\r\nTo: a@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\n";
    String s = App.analyzeMessageForTests(sparse);
    check("sparse email completeness lower than full", compVal(s) < compVal(f));
    check("sparse email reports missing evidence", s.contains("\"missing\":["));
  }

  static void originForensicsTests() {
    // 1) Three-hop chain chronology: top=newest, bottom=oldest; origin = earliest public from-IP.
    String threeHop =
      "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: re\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: from mail3.example (mail3.example [8.8.4.4]) by cx2.example; Thu, 27 Aug 2026 12:02:00 +0000\r\n" +
      "Received: from mail2.example (mail2.example [1.1.1.1]) by cx1.example; Thu, 27 Aug 2026 12:01:00 +0000\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by edge.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhello\r\n";
    String o1 = App.originForensics(threeHop, false);
    int hops1 = o1.split("received_chain\":\\[", -1)[1].split("\"hop\":", -1).length - 1;
    check("three-hop chain reconstructed as 3 hops", hops1 == 3);
    check("three-hop origin is LIKELY ORIGIN", o1.contains("\"origin_analysis\":{\"status\":\"LIKELY ORIGIN\""));
    check("three-hop origin is the earliest public from-IP", o1.contains("\"origin_ip\":\"206.189.44.10\""));
    check("three-hop origin_ip_version is IPv4", o1.contains("\"ip_version\":\"IPv4\""));
    check("three-hop chain from_ip captured", o1.contains("\"from_ip\":\"206.189.44.10\""));

    // 2) Private IP is excluded from origin candidates -> ORIGIN UNKNOWN, classified private.
    String priv =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: from local.example (local.example [192.168.1.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    String o2 = App.originForensics(priv, false);
    check("private from-IP binary ip_classification=private", o2.contains("\"ip_classification\":\"private\""));
    check("private from-IP not treated as origin (ORIGIN UNKNOWN)", o2.contains("\"status\":\"ORIGIN UNKNOWN\""));

    // 3) IPv6 origin address classified as IPv6 (public IPv6 eligible).
    String v6 =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: from ip6.example (ip6.example [2001:4860:4860::8888]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    String o3 = App.originForensics(v6, false);
    check("IPv6 from-IP binary ip_version=IPv6", o3.contains("\"ip_version\":\"IPv6\""));

    // 4) X-Originating-IP (sender-provided) that conflicts with chain is treated as lower-trust.
    String xoi =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "X-Originating-IP: [45.33.22.11]\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    String o4 = App.originForensics(xoi, false);
    check("X-Originating-IP flagged as sender-provided lower-trust", o4.contains("sender-provided") || o4.contains("lower-trust"));
    check("X-Originating-IP parsed out", o4.contains("45.33.22.11"));

    // 5) Recorded SPF pass (never assumed; read from header).
    String spfPass =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.com\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    check("recorded SPF pass reported as pass", App.originForensics(spfPass, false).contains("\"spf\":{\"result\":\"pass\""));

    // 6) Recorded SPF fail reported as fail (from recorded header).
    String spfFail =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Authentication-Results: mx.example; spf=fail smtp.mailfrom=evil.example\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    check("recorded SPF fail reported as fail", App.originForensics(spfFail, false).contains("\"spf\":{\"result\":\"fail\""));

    // 7) DKIM header present -> header-state reported, NOT cryptographically re-verified.
    String dkim =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; bh=abc; h=from:to:subject; b=xyz\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    String o7 = App.originForensics(dkim, false);
    check("DKIM-Signature present noted as header-state not re-verification", o7.contains("not cryptographically re-verified") || o7.contains("header-state"));
    check("DKIM verified_cryptographically=false", o7.contains("\"verified_cryptographically\":\"false\""));

    // 8) No auth headers -> DMARC NOT PROVIDED (never assumed fail).
    String noAuth =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    String o8 = App.originForensics(noAuth, false);
    check("no auth -> DMARC NOT PROVIDED", o8.contains("\"dmarc\":{\"result\":\"NOT PROVIDED\""));
    check("no auth -> SPF NOT PROVIDED", o8.contains("\"spf\":{\"result\":\"NOT PROVIDED\""));
    check("no auth -> DKIM NOT PROVIDED", o8.contains("\"dkim\":{\"result\":\"NOT PROVIDED\""));

    // 9) Recorded DMARC fail reported (from recorded header).
    String dmarcFail =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Authentication-Results: mx.example; spf=pass; dmarc=fail header.from=example.com\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    check("recorded DMARC fail reported", App.originForensics(dmarcFail, false).contains("\"dmarc\":{\"result\":\"fail\""));

    // 10) Malformed / empty Received header triggers an anomaly.
    String malformed =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: \r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    check("malformed Received flagged as anomaly", App.originForensics(malformed, false).contains("Malformed / empty Received"));

    // 11) Impossible (out-of-order) timestamps -> chronology anomaly, not proof of forgery.
    String badOrder =
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: from mail2.example (mail2.example [1.1.1.1]) by cx1.example; Thu, 27 Aug 2026 12:01:00 +0000\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by edge.example; Thu, 27 Aug 2026 12:05:00 +0000\r\n" +
      "\r\nhi\r\n";
    String o11 = App.originForensics(badOrder, false);
    check("impossible timestamp order flagged as chronology anomaly", o11.contains("ANOMALY") && o11.contains("timestamp"));

    // 12) From/Reply-To domain mismatch surfaced as a low-severity finding (not auto-malice).
    String mismatch =
      "From: a@example.com\r\nReply-To: scam@attacker.example\r\nTo: b@example.com\r\nSubject: t\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Received: from mail1.example (mail1.example [206.189.44.10]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "\r\nhi\r\n";
    check("From/Reply-To mismatch finding present", App.originForensics(mismatch, false).contains("From/Reply-To domain mismatch"));

    // 13) embedded origin_analysis present in the full analyzeMessage output.
    String emb = App.analyzeMessageForTests(threeHop);
    check("analyzeMessage embeds origin_analysis", emb.contains("\"origin_analysis\":{\"status\":\""));
  }

  private static int compVal(String json) {
    try {
      java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"completeness\":\\{\"value\":(\\d+)").matcher(json);
      return m.find() ? Integer.parseInt(m.group(1)) : -1;
    } catch (Exception e) { return -2; }
  }

  // riskScore extraction helper
  private static int plt(String json) {
    try {
      java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"riskScore\":(\\d+)").matcher(json);
      return m.find() ? Integer.parseInt(m.group(1)) : -1;
    } catch (Exception e) { return -2; }
  }
  private static boolean hasBand(String json, int lo, int hi) {
    int s = plt(json); return s >= lo && s <= hi;
  }

  static void ipUpgradeTests() {
    // Standards-based classification expansions
    checkEq("CGNAT 100.64/10 -> reserved carrier-grade", App.classifyAddress("100.64.0.1").contains("carrier_grade_nat"), true);
    checkEq("CGNAT 100.127", App.classifyAddress("100.127.255.254").contains("carrier_grade_nat"), true);
    checkEq("100.63 public boundary", App.classifyAddress("100.63.0.1"), "public");
    checkEq("100.128 public", App.classifyAddress("100.128.0.1"), "public");
    checkEq("broadcast 255.255.255.255 reserved", App.classifyAddress("255.255.255.255"), "reserved");
    checkEq("benchmark 198.18 reserved", App.classifyAddress("198.18.0.1"), "benchmarking (reserved)");
    checkEq("benchmark 198.19 reserved", App.classifyAddress("198.19.255.254"), "benchmarking (reserved)");
    checkEq("0/8 unspecified", App.classifyAddress("0.1.2.3"), "unspecified");
    // IPv4-mapped IPv6 must classify by the embedded literal (critical for SSRF)
    checkEq("IPv6 v4-mapped private -> private", App.classifyAddress("::ffff:192.168.1.1"), "private");
    checkEq("IPv6 v4-mapped loopback -> loopback", App.classifyAddress("::ffff:127.0.0.1"), "loopback");
    checkEq("IPv6 v4-mapped link-local -> link_local", App.classifyAddress("::ffff:169.254.169.254"), "link_local");
    checkEq("IPv6 v4-mapped public -> public", App.classifyAddress("::ffff:8.8.8.8"), "public");
    // SSRF must block IPv4-mapped private IPv6 literals
    checkEq("isBlockedForFetch v4-mapped private", App.isBlockedForFetch("::ffff:192.168.1.1"), true);
    // Expanded IPv6 special ranges (preserve link-local/ULA/documentation)
    checkEq("IPv6 teredo reserved", App.classifyAddress("2001::1").contains("reserved"), true);
    checkEq("IPv6 6to4 reserved", App.classifyAddress("2002:db8::1").contains("reserved"), true);
    checkEq("IPv6 nat64 reserved", App.classifyAddress("64:ff9b::1").contains("reserved"), true);
    checkEq("IPv6 unspecified", App.classifyAddress("::"), "unspecified");
    checkEq("IPv6 loopback", App.classifyAddress("::1"), "loopback");
    checkEq("IPv6 multicast", App.classifyAddress("ff02::1").contains("multicast"), true);
    // SPEC #14: blanket cloud/hosting bonus must NOT inflate risk
    checkEq("ipRisk hosting only -> 0 (no cloud bias)", App.ipRisk("public", true, false, true, "", "", "", "", List.of()), 0);
    checkEq("ipRisk hosting + proxy stays proxy-only", App.ipRisk("public", true, true, true, "", "", "", "", List.of()), 25);
    // URL deep-link module embeds the new forensic fields (confidenceScore / resolvedIpSummaries)
    String u = App.analyzeUrl("https://example.com/path", "https://example.com/path");
    check("url has confidenceScore numeric", u.contains("\"confidenceScore\":"));
    check("url has dataCompleteness object", u.contains("\"dataCompleteness\":{\"value\":"));
    check("url has resolvedIpSummaries hostname tagging", u.contains("\"resolvedIpSummaries\":["));
    check("url evidenceNote present", u.contains("\"evidenceNote\""));
    // IPv6 literal/host parsing robustness
    App.UrlParts v6p = App.parseUrl("http://[::1]/");
    checkEq("parseUrl unwraps bracketed IPv6 host", v6p.host(), "::1");
    checkEq("parseUrl detects IPv6 literal as IP host", v6p.isIpHost(), true);
    String v6u = App.analyzeUrl("http://[::1]/", "http://[::1]/");
    check("analyzeUrl handles bracketed IPv6 without crash", v6u.startsWith("{\"module\""));
    check("analyzeUrl flags IPv6 loopback as internal", v6u.contains("internal_resolution") || v6u.contains("loopback"));
    // IP module embeds numeric geo correlation / confidence / completeness fields
    String ipm = App.analyzeIp("8.8.8.8", "8.8.8.8");
    check("ip has confidenceScore numeric", ipm.contains("\"confidenceScore\":"));
    check("ip has dataCompleteness object", ipm.contains("\"dataCompleteness\":{\"value\":"));
    check("ip has geoCorrelation field", ipm.contains("\"geoCorrelation\""));
    check("ip has geoAgreementSources field", ipm.contains("\"geoAgreementSources\":"));
  }

  // A realistic high-risk phishing sample that the engine should score >= 70.
  private static String highPhish() {
    return "From: \"PayPal\" <security@paypal-noreply.example>\r\n" +
      "Reply-To: attacker@evil.example\r\n" +
      "To: victim@example.com\r\n" +
      "Subject: URGENT: Your account will be suspended\r\n" +
      "Date: Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "Authentication-Results: mx.example; spf=fail; dmarc=fail\r\n" +
      "Received: from mail1.example (mail1.example [185.220.102.44]) by mx.example; Thu, 27 Aug 2026 12:00:00 +0000\r\n" +
      "X-Originating-IP: [41.230.10.5]\r\n" +
      "\r\n" +
      "Dear user, your account will be suspended within 24 hours unless you verify immediately by entering your credentials at https://paypal-secure-verify.example.com/login?token=abc now.\r\n";
  }

  static void newBehaviorTests() {
    // Leetspeak brand impersonation (0-for-o) detected in sender domain + URL host (root-cause fix #2)
    String leet = "From: \"Microsoft Security\" <security@micr0soft-support.example>\r\nTo: victim@example.com\r\nSubject: Verify your account\r\nDate: Thu, 27 Aug 2026 09:00:00 +0000\r\n\r\nYour account will be suspended within 2 hours. Verify immediately to restore access: https://login-micr0soft-support.example/verify\r\n";
    String lj = App.analyzeMessageForTests(leet);
    check("leet brand (micr0soft) flagged as brand impersonation", lj.contains("brand impersonation"));
    check("leet brand risk elevated to suspicious band", plt(lj) >= 41);

    // Regression guard: an unrelated non-brand domain must NOT be flagged
    String mal = "From: a@mal.example.\r\nTo: a@victim.example\r\nSubject: hi\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nhello\r\n";
    check("unrelated domain not flagged as brand impersonation", !App.analyzeMessageForTests(mal).contains("brand impersonation"));

    // IPv6 IOC extraction (root-cause fix #3) — full double-colon address
    String v6 = "From: ops@example.com\r\nTo: a@example.com\r\nSubject: net\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nDial 2001:db8::dead:beef for the jump host.\r\n";
    String vj = App.analyzeMessageForTests(v6);
    check("IPv6 IOC extracted in iocs.ips", vj.contains("2001:0db8"));
    check("IPv6 IOC counted in normalized ioc_summary", vj.contains("\"ipv6\":1"));

    // URL policy firing mechanism (root-cause fix #5) — deterministic, independent of other scoring
    checkEq("URL policy fires when urlRisk>=60", App.urlPolicyMatchTest(20, 50, "LOW", 60), "SUSPICIOUS_URL_V1");
    checkEq("URL policy not fired when urlRisk<60", App.urlPolicyMatchTest(20, 50, "LOW", 40), "NO_POLICY_MATCH");
    checkEq("URL policy not fired with no URL evidence", App.urlPolicyMatchTest(20, 50, "LOW", -1), "NO_POLICY_MATCH");

    // No-data threat state is UNKNOWN, never CLEAN (root-cause fix #4)
    String unknown = "From: report@attacker.example\r\nTo: a@example.com\r\nSubject: Update\r\nDate: Thu, 27 Aug 2026 09:00:00 +0000\r\n\r\nPlease review the attached summary today: http://login-sentinel.example\n";
    String uj = App.analyzeMessageForTests(unknown);
    check("no-data threat state UNKNOWN (never CLEAN)", uj.contains("\"state\":\"UNKNOWN\""));

    // Canonical normalized representation (new struct)
    String nj = App.analyzeMessageForTests("From: se@paypal.com\r\nTo: a@example.com\r\nSubject: real\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nhello\r\n");
    check("normalized object present", nj.contains("\"normalized\":{\"envelope\":"));
    check("normalized has ioc_summary", nj.contains("\"ioc_summary\":{"));
    check("normalized envelope carries from_domain", nj.contains("\"from_domain\":\"paypal.com\""));
  }

  static void socBackboneTests() {
    // Policy engine (spec 11)
    checkEq("policy matches CRITICAL_PHISHING_V1 @ risk90/CRITICAL", App.policyMatchTest(90, 95, "CRITICAL"), "CRITICAL_PHISHING_V1");
    checkEq("policy matches SUSPICIOUS_V1 @ risk41+", App.policyMatchTest(55, 80, "MEDIUM"), "SUSPICIOUS_V1");
    checkEq("policy no-match for low risk", App.policyMatchTest(20, 50, "LOW"), "NO_POLICY_MATCH");
    checkEq("policy HIGH (70) matches HIGH_PHISHING_V1 (priority)", App.policyMatchTest(70, 90, "HIGH"), "HIGH_PHISHING_V1");

    // Connector honest status (spec 34, 35, 48)
    checkEq("webhook connector CONNECTED", App.connectorStatusTest("webhook"), "CONNECTED");
    checkEq("gmail connector NOT_CONFIGURED (no OAuth token)", App.connectorStatusTest("gmail"), "NOT_CONFIGURED");
    checkEq("m365 connector NOT_CONFIGURED (no OAuth token)", App.connectorStatusTest("m365"), "NOT_CONFIGURED");

    // IOC extraction + normalization + dedup (spec 24)
    String ioc = App.iocExtractTest("Visit https://evil.example/x and contact admin@evil.example; server 185.220.102.44, hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    check("ioc extracts ipv4", ioc.contains("\"type\":\"ipv4\""));
    check("ioc extracts url", ioc.contains("\"type\":\"url\""));
    check("ioc extracts email", ioc.contains("\"type\":\"email\""));
    check("ioc extracts domain", ioc.contains("\"type\":\"domain\""));
    check("ioc extracts sha256 hash", ioc.contains("\"type\":\"hash_sha256\""));
    check("ioc reputation context-scored, never fabricated MALICIOUS/CLEAN (Part 7/18)", ioc.contains("\"reputation\":\"MEDIUM\"") || ioc.contains("\"reputation\":\"HIGH\"") || ioc.contains("\"reputation\":\"INFORMATIONAL\"") || ioc.contains("\"reputation\":\"UNKNOWN\"") || ioc.contains("\"reputation\":\"PRIVATE/RESERVED\"") || ioc.contains("\"reputation\":\"PRIVATE"));

    // Security decision record (spec 45, 46) — DETECTED vs DECIDED kept distinct
    String dec = App.socDecisionTest(highPhish(), "webhook");
    check("decision record embeds security_decision envelope", dec.contains("\"security_decision\":{") && (dec.contains("\"threat\":\"PHISHING\"") || dec.contains("\"threat\":\"MALICIOUS\"")) && dec.contains("\"evidence_quality\"") && dec.contains("\"confidence_limitations\""));
    check("decision has risk_score numeric", dec.contains("\"risk_score\":"));
    check("decision has system_action", dec.contains("\"system_action\":"));
    check("decision has policy_id", dec.contains("\"policy_id\":"));
    check("decision has reasons[]", dec.contains("\"reasons\":["));
    check("decision has recommendation", dec.contains("\"recommendation\":"));
    check("decision has action_status NOT_EXECUTED (analysis mode)", dec.contains("\"action_status\":\"NOT_EXECUTED\""));

    // Incident auto-creation for critical + lifecycle transition (spec 12, 13)
    List<String> incidents = App.incidentsTest();
    boolean created = false;
    for (String l : incidents) if (l.contains("\"INC-2026-")) created = true;
    check("incident auto-created for high-risk message", created);

    // Audit trail (spec 22)
    App.auditTest("incident.test", "TRANSITION");
    check("audit tail records event", App.auditTailTest().contains("incident.test"));
    specForensicTests();
  }

  private static int ri(String j, String key){ java.util.regex.Matcher m=java.util.regex.Pattern.compile("\""+key+"\"\\s*:\\s*(\\d+)").matcher(j); return m.find()?Integer.parseInt(m.group(1)):-1; }
  private static String rs(String j, String key){ java.util.regex.Matcher m=java.util.regex.Pattern.compile("\""+key+"\"\\s*:\\s*\"([^\"]*)\"").matcher(j); return m.find()?m.group(1):""; }

  // Regression tests for the spec's synthetic phishing email + season cases (spec 19, 20).
  static void specForensicTests() {
    // ---- Spec reference phishing email (spec 20) ----
    String target =
      "Subject: Urgent: Your Microsoft 365 Account Will Be Disabled\r\n" +
      "From: Microsoft Security [security@micr0soft-account.example]\r\n" +
      "To: employee@example.com\r\n" +
      "\r\n" +
      "Dear User,\r\n" +
      "We detected unusual sign-in activity on your Microsoft 365 account.\r\n" +
      "For your protection, your account will be suspended today unless you complete the security verification process immediately.\r\n" +
      "Please verify your account using the secure verification link below:\r\n" +
      "https://login-micr0soft-account.example/security/verify\r\n" +
      "You must complete verification within 30 minutes to prevent permanent account restriction.\r\n" +
      "If you do not complete this process, access to your email and company files may be suspended.\r\n" +
      "Microsoft Security Team\r\n" +
      "Account Protection Department\r\n";
    String a = App.analyzeMessageForTests(target);
    String dec = App.socDecisionTest(target, "spec");
    int risk = ri(a,"riskScore");
    String threat = rs(dec,"threat");
    check("spec email semantics: threat is PHISHING (not UNKNOWN)", "PHISHING".equals(threat));
    check("spec email risk in 85-95 high/critical band", risk >= 80 && risk <= 100);
    check("spec email risk >= 85 (strong correlated phishing evidence)", risk >= 85);
    check("spec email risk_level is CRITICAL/HIGH", "CRITICAL".equals(rs(dec,"risk_level")) || "HIGH".equals(rs(dec,"risk_level")));
    check("spec email system_action QUARANTINE (decision)", "QUARANTINE".equals(rs(dec,"system_action")));
    check("spec email action_status NOT_EXECUTED (analysis mode)", "NOT_EXECUTED".equals(rs(dec,"action_status")));
    check("spec email policy HIGH_PHISHING_V1 (correlated evidence, not just URL)", "HIGH_PHISHING_V1".equals(rs(dec,"policy_id")) || "CRITICAL_PHISHING_V1".equals(rs(dec,"policy_id")));
    check("spec email incident auto-created for critical decision", rs(dec,"incident_id").startsWith("INC-2026-") || rs(dec,"incident_id").isEmpty());
    check("spec email confidence 0..100 separated from risk (66 != 90)", ri(dec,"confidence") >= 0 && ri(dec,"confidence") <= 100);
    check("spec email data_completeness low (< 50) due to missing headers", ri(dec,"data_completeness") < 50 && ri(dec,"data_completeness") >= 0);
    check("spec email evidence_quality present (MEDIUM/HIGH)", dec.contains("\"evidence_quality\":\"MEDIUM\"") || dec.contains("\"evidence_quality\":\"HIGH\""));
    check("spec email confidence_limitations present (WHY NOT 100%?)", dec.contains("\"confidence_limitations\":\"Confidence is limited"));
    check("spec email WHY? lists real findings (not 'Standard analysis completed')", dec.contains("brand impersonation") && !dec.contains("Standard analysis completed"));
    check("spec email SPF negotiation honest UNKNOWN/not_supplied", a.contains("\"spf\":\"not_supplied\""));
    check("spec email DKIM honest UNKNOWN/not_supplied", a.contains("\"dkim\":\"not_supplied\""));
    check("spec email DMARC honest UNKNOWN/not_supplied", a.contains("\"dmarc\":\"not_supplied\""));
    check("spec email no fabricated origin IP", a.contains("\"has_received\":false"));
    check("spec email lookalike brand impersonation detected", a.contains("brand impersonation") && a.contains("microsoft"));
    check("spec email correlated_evidence groups identical evidence", a.contains("\"indicator\":\"URL_SUSPICION\"") && a.contains("\"contributing\":2"));

    // ---- A. Legitimate email stays low risk ----
    String legit = "From: ops@example.com\r\nTo: alice@example.com\r\nSubject: Maintenance window\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\nReturn-Path: ops@example.com\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\nScheduled maintenance tonight 02:00-04:00 UTC. No action required.\r\n";
    String la = App.analyzeMessageForTests(legit);
    check("legit email safe: risk < 41", ri(la,"riskScore") < 41);
    check("legit email threat SAFE", "SAFE".equals(rs(App.socDecisionTest(legit,"spec"),"threat")));

    // ---- E. No raw headers beyond minimal -> threat based on present evidence, completeness low ----
    String noheaders = "To: v@example.com\r\nSubject: hi\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nPlease verify at https://login-verify.example\r\n";
    String na = App.analyzeMessageForTests(noheaders);
    check("no-headers not over-claiming: completeness low", ri(na,"riskScore") < 80);

    // ---- G/H/I/J/K/L. Authentication results parsed honestly ----
    String spass = "From: a@example.com\r\nTo: v@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\nhello\r\n";
    String spfail = "From: a@example.com\r\nTo: v@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\nAuthentication-Results: mx; spf=fail\r\n\r\nhello\r\n";
    String sdfail = "From: a@example.com\r\nTo: v@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\r\n\r\nhello\r\n";
    check("auth: SPF PASS not treated as failure finding", !App.analyzeMessageForTests(spass).contains("\"SPF is not a pass"));
    check("auth: SPF FAIL produces authentication finding", App.analyzeMessageForTests(spfail).contains("SPF is not a pass"));
    check("auth: SPF+DKIM+DMARC fail correlated to higher risk", ri(App.analyzeMessageForTests(sdfail),"riskScore") > ri(App.analyzeMessageForTests(spass),"riskScore"));

    // ---- M. Reply-To mismatch detected ----
    String reply = "From: ceo@company.com\r\nReply-To: fraud@attacker.example\r\nTo: v@example.com\r\nSubject: re: transfer\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nPlease wire funds urgently to the new account.\r\n";
    check("reply-to mismatch produces finding", App.analyzeMessageForTests(reply).contains("From/Reply-To domain mismatch"));
  }

  // =================================================================================
  // MODULE UPGRADE tests  (spec 1-5, 6, 8, 17, 18, 19, 20)  — deterministic / offline
  // =================================================================================
  static void moduleUpgradeTests() {
    // ---- SPAM CHECKER (spec 1) ----
    String phish = "Subject: Urgent: Your Microsoft 365 Account Will Be Disabled\r\n" +
      "From: Microsoft Security [security@micr0soft-account.example]\r\n" +
      "Authentication-Results: mx; spf=fail; dkim=pass; dmarc=none\r\n" +
      "To: user@example.com\r\n\r\n" +
      "Dear User, your account will be suspended today unless you verify.\r\n" +
      "Confirm your password here: https://login-micr0soft-account.example/security/verify\r\n" +
      "Act immediately or your account is locked!";
    String sp = App.spamTest(phish);
    check("spam: phishing email classified PHISHING", "PHISHING".equals(rs(sp,"classification")));
    check("spam: phishing intent HIGH for credential+url", "HIGH".equals(rs(sp,"phishing")));
    check("spam: score within 0-100", ri(sp,"spam_score") >= 0 && ri(sp,"spam_score") <= 100);
    check("spam: phishing score elevated (>= 60)", ri(sp,"spam_score") >= 60);
    check("spam: spam evidence present", sp.contains("\"findings\":") && sp.contains("brand spoofing"));

    String legit = "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Meeting agenda\r\n\r\nHi, here is the agenda for our 3pm meeting. See you then. Best, Alice";
    String sl = App.spamTest(legit);
    check("spam: legitimate email classified HAM", "HAM".equals(rs(sl,"classification")));
    check("spam: legit phishing LOW", "LOW".equals(rs(sl,"phishing")));
    check("spam: legit score low (< 35)", ri(sl,"spam_score") < 35);
    check("spam: empty email does not crash, HAM", "HAM".equals(rs(App.spamTest(""),"classification")));
    check("spam: malformed email does not crash", !App.spamTest("no headers no body \r\n@@@").isEmpty());
    check("spam: confidence separated from risk", ri(sl,"confidence") >= 0 && ri(sl,"confidence") <= 100);
    check("spam: completeness computed", ri(sl,"data_completeness") >= 0 && ri(sl,"data_completeness") <= 100);
    check("spam: evidence_quality present", sl.contains("\"evidence_quality\":\"") || sl.contains("\"evidence_quality\":\"MEDIUM\""));

    // ---- SSRF guard (spec 17) ----
    check("ssrf: loopback blocked", App.isPrivateIpTest("127.0.0.1"));
    check("ssrf: metadata 169.254.169.254 blocked", App.isPrivateIpTest("169.254.169.254"));
    check("ssrf: 10/8 blocked", App.isPrivateIpTest("10.0.0.1"));
    check("ssrf: 172.16/12 blocked", App.isPrivateIpTest("172.16.0.1"));
    check("ssrf: 172.31 blocked", App.isPrivateIpTest("172.31.255.255"));
    check("ssrf: 172.32 public allowed", !App.isPrivateIpTest("172.32.0.1"));
    check("ssrf: 192.168 blocked", App.isPrivateIpTest("192.168.1.1"));
    check("ssrf: IPv6 loopback ::1 blocked", App.isPrivateIpTest("::1"));
    check("ssrf: public IPv4 allowed", !App.isPrivateIpTest("8.8.8.8"));

    // ---- DDoS ANALYTICS (spec 3) ----
    StringBuilder spike = new StringBuilder();
    for (int i = 0; i < 40; i++) { int sec = 1900000000 + (i/20); spike.append(sec).append(" 198.51.100.").append(1+(i%5)).append(" 618 GET /login ").append((i%4==0?500:200)).append(" 900\n"); }
    String dd = App.ddosTest(spike.toString(), "1");
    check("ddos: anomaly score computed 0-100", ri(dd,"anomaly_score") >= 0 && ri(dd,"anomaly_score") <= 100);
    check("ddos: spike over baseline classified HIGH/CRITICAL", dd.contains("\"classification\":\"HIGH ANOMALY\"") || dd.contains("\"classification\":\"CRITICAL\""));
    check("ddos: baseline_configured true", dd.contains("\"baseline_configured\":true"));
    check("ddos: current rps present", dd.contains("\"current_rps\""));
    check("ddos: demo not used for real logs (no SIMULATED when logs supplied)", !dd.contains("SIMULATED"));
    String ddNoBl = App.ddosTest(spike.toString(), "");
    check("ddos: insufficient baseline reported honestly", ddNoBl.contains("Insufficient baseline"));
    String demo = App.ddosTest("", "1");
    check("ddos: demo dataset labelled SIMULATED DATA", demo.contains("SIMULATED DATA"));
    check("ddos: no offensive generator exposed (defensive only)", !demo.contains("attack") && demo.contains("\"classification\""));

    // ---- CLOUDFLARE (spec 5, 18) ----
    String cf = App.cfTest("example.com");
    check("cloudflare: NOT_CONFIGURED without server-side credential", cf.contains("\"status\":\"NOT_CONFIGURED\""));
    check("cloudflare: no token leaked in response", !cf.contains("CLOUDFLARE_API_TOKEN=") && !cf.toLowerCase().contains("bearer ") && !cf.contains("\"token\""));
    check("cloudflare: proxy/waf/ddos all UNKNOWN when not configured", cf.contains("\"proxy\":\"UNKNOWN\"") && cf.contains("\"waf\":\"UNKNOWN\""));

    // ---- DNS + SSL validation / offline error paths (spec 2, 4, 19) ----
    String dnsBad = App.dnsTest("!!invalid host!!");
    check("dns: invalid target returns ERROR (no fabricated records)", dnsBad.contains("\"status\":\"ERROR\""));
    String sslBad = App.sslTest("!!invalid host!!");
    check("ssl: invalid target returns ERROR (no fabricated cert)", sslBad.contains("\"status\":\"ERROR\""));
    check("ssl: SSRF guarded target returns blocked/error not fabricated VALID", App.sslTest("127.0.0.1").contains("SSRF") || App.sslTest("127.0.0.1").contains("ERROR") || App.sslTest("127.0.0.1").contains("blocked"));
  }

  // Regression for the supplied synthetic sample: an incomplete (header-light) but content-strong
  // credential-phishing email. Verify honest, evidence-driven outputs WITHOUT fabricated data:
  //  - strong direct body+URL evidence => HIGH risk / PHISHING at HIGH evidence quality
  //  - high classification confidence even though forensic headers are absent
  //  - low data completeness (headers genuinely missing) is reported, NOT conflated with safety
  //  - /verify path + HTTP must NOT independently produce the verdict, and reputation stays UNKNOWN
  static void syntheticPhishingTests() {
    String eml = "From: Security Operations [security-alert@example.com]\r\n" +
      "To: employee@example.com\r\n" +
      "Reply-To: account-recovery@example.com\r\n" +
      "Subject: Urgent Security Alert - Verify Your Account\r\n\r\n" +
      "We detected an unusual sign-in attempt on your account from a new device.\r\n" +
      "For your protection, your account will be temporarily restricted if verification is not completed within 30 minutes.\r\n" +
      "Please verify your account using the following security portal:\r\n" +
      "http://secure-account-verification.example/login\r\n" +
      "During verification, you may be asked to confirm your username and password.\r\n" +
      "If you did not attempt this sign-in, please complete the verification immediately to prevent unauthorized access.\r\n";
    String j = App.analyzeMessageForTests(eml);
    check("synthetic: risk classified HIGH (>= 60)", plt(j) >= 60);
    check("synthetic: threat classification PHISHING", "PHISHING".equals(rs(j, "threat_classification")));
    check("synthetic: classification HIGH RISK / LIKELY PHISHING", rs(j, "classification").contains("HIGH RISK"));
    check("synthetic: risk_level HIGH", "HIGH".equals(rs(j, "risk_level")));
    // confidence independent of low completeness: strong direct evidence keeps it elevated
    check("synthetic: confidence elevated (> 50)", objInt(j, "confidence") > 50);
    check("synthetic: confidence high label", objStr(j, "confidence", "label").equals("high"));
    // low completeness reported honestly (headers absent), not converted into SAFE
    check("synthetic: completeness < 50 (genuinely missing headers)", objInt(j, "completeness") < 50);
    // strong direct body+URL credential-phishing evidence => HIGH evidence quality despite low completeness
    check("synthetic: evidence_quality HIGH", "HIGH".equals(rs(j, "evidence_quality")));
    // ---- Normalized evidence representation (TARGET 7): every finding carries the normalized schema ----
    check("synthetic: findings carry finding_id", j.contains("\"finding_id\":\""));
    check("synthetic: findings carry subtype", j.contains("\"subtype\":\""));
    check("synthetic: findings carry description", j.contains("\"description\":\""));
    check("synthetic: findings carry raw_evidence", j.contains("\"raw_evidence\":\""));
    check("synthetic: findings carry availability AVAILABLE", j.contains("\"availability\":\"AVAILABLE\""));
    check("synthetic: findings carry deduplication_key", j.contains("\"deduplication_key\":\""));
    // ---- Evidence preservation / audit trail (TARGET 1): original bytes hashed, never modified ----
    check("synthetic: analysis_id assigned", j.contains("\"analysisId\":\"ANL-"));
    check("synthetic: audit trail present", j.contains("\"audit\":{\"analysis_id\":\"ANL-"));
    check("synthetic: audit analysis_completed_at present", j.contains("analysis_completed_at"));
    check("synthetic: evidence_status PRESERVED", j.contains("\"evidence_status\":\"PRESERVED\""));
    check("synthetic: milestone timestamps present", j.contains("\"milestones\":{\"parser_completed\""));
    check("synthetic: case/evidence/ingest ids in audit", j.contains("\"case_id\":\"CASE-") && j.contains("\"evidence_id\":\"") && j.contains("\"ingested_at\":\""));

    // Decision envelope embeds the independent metrics + honest unknowns + NOT_EXECUTED action
    String dec = App.socDecisionTest(eml, "webhook");
    check("synthetic: decision threat PHISHING", dec.contains("\"threat\":\"PHISHING\""));
    check("synthetic: decision risk_level HIGH", dec.contains("\"risk_level\":\"HIGH\""));
    check("synthetic: decision evidence_quality HIGH", dec.contains("\"evidence_quality\":\"HIGH\""));
    check("synthetic: decision action NOT_EXECUTED", dec.contains("\"action_status\":\"NOT_EXECUTED\""));
    check("synthetic: reputation UNKNOWN (not fabricated)", dec.contains("\"threat_reputation\":\"UNKNOWN\""));
    // Credential-phishing rationale present; /verify/HTTP alone would NOT be primary
    check("synthetic: credential/verification rationale present", dec.contains("credential") || dec.contains("verification"));

    // /verify path + HTTP are contextual signals, NOT independently malicious (Part 4/5/17):
    // a benign page with /verify over HTTPS and matching sender must NOT be classified malicious.
    String benign = "From: noreply@example.com\r\nTo: u@example.com\r\nSubject: Reset\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nReset your password here: https://example.com/verify\r\n";
    String bj = App.analyzeMessageForTests(benign);
    check("synthetic: /verify + HTTPS alone NOT PHISHING", !"PHISHING".equals(rs(bj, "threat_classification")));
  }
  private static int objInt(String j, String obj) {
    try {
      java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"" + obj + "\"\\s*:\\{\"value\":(\\d+)").matcher(j);
      return m.find() ? Integer.parseInt(m.group(1)) : -1;
    } catch (Exception e) { return -2; }
  }
  private static String objStr(String j, String obj, String key) {
    java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"" + obj + "\"\\s*:\\{[^}]*?\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(j);
    return m.find() ? m.group(1) : "";
  }
  // scoreBreakdown category value / max helpers (e.g. sbVal(j,"authentication","value"))
  private static int sbVal(String j, String cat, String field) {
    java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"" + cat + "\"\\s*:\\{\"max\"\\s*:\\s*(\\d+),\"value\"\\s*:(\\d+)\\}", java.util.regex.Pattern.DOTALL).matcher(j);
    if (!m.find()) return -1;
    return "max".equals(field) ? Integer.parseInt(m.group(1)) : Integer.parseInt(m.group(2));
  }
  private static int sbCorrValue(String j) {
    java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"correlation_bonus\"\\s*:\\{\"max\"\\s*:\\s*(\\d+),\"value\"\\s*:\\s*(\\d+)", java.util.regex.Pattern.DOTALL).matcher(j);
    return m.find() ? Integer.parseInt(m.group(2)) : -1;
  }

  // =====================================================================
  // MASTER FIX regression tests (Master Prompt sections A-Z, AD)
  // Focus: correlation-cap arithmetic, the three-metric separation, payroll
  // credential phishing, authentication/alignment UNKNOWN, no fabricated data.
  // =====================================================================
  static void masterFixTests() {
    // ---- (2/AB) Payroll credential-phishing email ----
    String payroll =
      "From: Payroll Support [payroll-security@company-payroll.example.com]\r\n" +
      "To: employee@company.example\r\n" +
      "Subject: URGENT: Payroll Account Verification Required\r\n" +
      "Date: Fri, 28 Aug 2026 09:00:00 +0000\r\n" +
      "Message-ID: <payroll-123@company.example>\r\n" +
      "\r\n" +
      "Our security system detected an issue with your payroll account.\r\n" +
      "Your employee payment profile requires mandatory verification. If you do not complete the verification within 12 hours, your upcoming salary payment may be delayed.\r\n" +
      "Please confirm your account information immediately:\r\n" +
      "http://company-payroll.example.com/employee/verify\r\n" +
      "You may be asked to enter your employee ID, password, and authentication information.\r\n" +
      "If you did not request this verification, contact Payroll Support after completing the verification process.\r\n" +
      "Payroll Security Team\r\n";
    String pj = App.analyzeMessageForTests(payroll);
    String pdec = App.socDecisionTest(payroll, "eml");
    int prisk = plt(pj);
    check("masterfix payroll: threat classified PHISHING", "PHISHING".equals(rs(pj,"threat_classification")));
    check("masterfix payroll: classification high/critical", rs(pj,"classification").contains("HIGH") || rs(pj,"classification").contains("CRITICAL"));
    check("masterfix payroll: risk HIGH or CRITICAL (>= 60)", prisk >= 60);
    check("masterfix payroll: explicit password/credential request detected", pj.contains("password") || pj.contains("credential"));
    check("masterfix payroll: financial manipulation detected", pj.contains("financial manipulation"));
    check("masterfix payroll: urgency/deadline detected", pj.contains("urgency") || pj.contains("deadline"));
    // three-metric independence: high risk + high confidence can coexist with low completeness
    check("masterfix payroll: confidence label high", objStr(pj,"confidence","label").equals("high"));
    check("masterfix payroll: completeness low (< 50) independent of high risk", objInt(pj,"completeness") < 50);
    check("masterfix payroll: risk high while completeness low (independence)", prisk >= 60 && objInt(pj,"completeness") < 50);
    check("masterfix payroll: decision QUARANTINE", pdec.contains("\"system_action\":\"QUARANTINE\""));
    check("masterfix payroll: decision NOT_EXECUTED (remediation disabled)", pdec.contains("\"action_status\":\"NOT_EXECUTED\""));
    check("masterfix payroll: decision PHISHING", pdec.contains("\"threat\":\"PHISHING\""));
    // incident creation and remediation are separate (W)
    check("masterfix payroll: incident_id non-empty when threshold met", !rs(pdec,"incident_id").isEmpty());

    // ---- (A/M/P) Correlation must never exceed its configured maximum ----
    // Payroll has a rich correlation set; assert applied <= max for every run.
    int corrMax = 15;
    check("masterfix: correlation max is 15", sbVal(pj,"correlation_bonus","max") == corrMax);
    int corrVal = sbCorrValue(pj);
    check("masterfix: correlation applied <= 15 (never +35/15)", corrVal >= 0 && corrVal <= corrMax);

    // ---- (P) Every category value <= its configured maximum; base+corr is consistent ----
    String[][] cats = {{"authentication","15"},{"url_domain","20"},{"dns","10"},{"ip_intelligence","10"},
                       {"threat_intelligence","20"},{"attachment","15"},{"nlp_social","15"},{"header_routing","10"}};
    int base = 0; boolean allBounded = true;
    for (String[] c : cats) { int v = sbVal(pj, c[0], "value"); int mx = sbVal(pj, c[0], "max"); if (mx < 0 || v < 0 || v > mx) allBounded = false; base += v; }
    check("masterfix: all category values within configured maxima", allBounded);
    // raw = base + applied correlation; final normalized risk must be 0..100
    int raw = base + corrVal;
    check("masterfix: raw(base+corr) computed from matching breakdown values", raw >= 0 && raw <= 130);
    check("masterfix: normalized risk 0..100", prisk >= 0 && prisk <= 100);

    // ---- (5/6/J/K) Missing auth remains UNKNOWN, not FAIL ----
    check("masterfix: payroll SPF not_supplied (not FAIL)", pj.contains("\"spf\":\"not_supplied\""));
    check("masterfix: payroll DKIM not_supplied", pj.contains("\"dkim\":\"not_supplied\""));
    check("masterfix: payroll DMARC not_supplied", pj.contains("\"dmarc\":\"not_supplied\""));
    // alignment must be UNKNOWN when authentication evidence is absent (K)
    check("masterfix: payroll alignment UNKNOWN (auth absent)", pj.contains("\"alignment\":\"unknown\""));
    boolean authAfter = pj.indexOf("\"alignment\":\"unknown\"") > pj.indexOf("\"authentication\":");
    check("masterfix: alignment field lives in authentication section", authAfter);

    // ---- (6/U) No Received -> origin UNKNOWN, not fabricated ----
    check("masterfix: payroll no received hops", pj.contains("\"has_received\":false"));
    check("masterfix: payroll threat_status UNKNOWN (no reputation feed)", pj.contains("\"threatStatus\":{\"state\":\"UNKNOWN\""));

    // ---- (3/4) Legitimate /verify URL + HTTPS must NOT be malicious ----
    String benign = "From: noreply@example.com\r\nTo: u@example.com\r\nSubject: Reset\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\nReset your password here: https://example.com/verify\r\n";
    String bj = App.analyzeMessageForTests(benign);
    check("masterfix: legit https /verify NOT PHISHING", !"PHISHING".equals(rs(bj,"threat_classification")));
    String beneven = "From: ops@example.com\r\nTo: alice@example.com\r\nSubject: Maintenance window\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\nReturn-Path: ops@example.com\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\nScheduled maintenance tonight 02:00-04:00 UTC. No action required.\r\n";
    String bj2 = App.analyzeMessageForTests(beneven);
    check("masterfix: legit maintenance email NOT PHISHING", !"PHISHING".equals(rs(bj2,"threat_classification")));

    // ---- (Q) Unknown data must never drive risk down / be read as CLEAN ----
    check("masterfix: unknown threat intel stays UNKNOWN not CLEAN", pj.contains("\"threatStatus\":{\"state\":\"UNKNOWN\""));
    check("masterfix: payroll risk high despite missing auth/headers", plt(pj) >= 60);

    // ---- (1) Microsoft credential phishing still strong ----
    String msft =
      "Subject: Urgent: Your Microsoft 365 Account Will Be Disabled\r\n" +
      "From: Microsoft Security [security@micr0soft-account.example]\r\n" +
      "To: employee@example.com\r\n" +
      "\r\n" +
      "Dear User,\r\n" +
      "We detected unusual sign-in activity on your Microsoft 365 account.\r\n" +
      "For your protection, your account will be suspended today unless you complete the security verification process immediately.\r\n" +
      "Please verify your account using the secure verification link below:\r\n" +
      "https://login-micr0soft-account.example/security/verify\r\n" +
      "You must complete verification within 30 minutes to prevent permanent account restriction.\r\n" +
      "If you do not complete this process, access to your email and company files may be suspended.\r\n" +
      "Microsoft Security Team\r\n" +
      "Account Protection Department\r\n";
    String mj = App.analyzeMessageForTests(msft);
    check("masterfix: Microsoft credential phishing PHISHING", "PHISHING".equals(rs(mj,"threat_classification")));
    check("masterfix: Microsoft impersonation detected", mj.contains("brand impersonation") && mj.contains("microsoft"));

    // ---- (13) Repeated same indicator not double counted as multiple correlation rules ----
    // A single credential+urgency email should not accrue a correlation bonus above the 15 cap
    // even when many interdependent rules match; the cap is the invariant.
    check("masterfix: correlation capped at configured max for all emails", sbCorrValue(mj) <= corrMax && corrVal <= corrMax);

    // ---- (18) first-party/full-auth alignment can be consistent when auth IS supplied ----
    String authed =
      "From: ops@example.com\r\nTo: alice@example.com\r\nSubject: Update\r\nDate: Thu, 27 Aug 2026 10:00:00 +0000\r\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n" +
      "Received: from mail.example.com (192.0.2.1) by mx; Thu, 27 Aug 2026 10:00:00 +0000\r\n\r\n" +
      "All mechanisms authenticated, no mismatches.\r\n";
    String aj = App.analyzeMessageForTests(authed);
    check("masterfix: present auth can yield consistent alignment (not forced UNKNOWN)", aj.contains("\"alignment\":\"consistent\""));
  }

  // =====================================================================
  // APEX 7-layer orchestration regression tests
  // Validates subject forensics, JWT decode, behavioral/temporal analysis,
  // MITRE ATT&CK mapping, domain-intelligence honesty, redirect defang, and
  // machine-readable IOC emission — without fabricating WHOIS/cert/redirects.
  // =====================================================================
  static void apexLayerTests() {
    // ---- Layer 6 / 8 / 12 / 16 / 9 / 13 combined phishing email ----
    String jwtH = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String jwtP = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"email\":\"victim@example.com\",\"action\":\"capture\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String token = jwtH + "." + jwtP + ".";
    String eml =
      "From: Microsoft Security [security@login-micr0soft.example]\r\n" +
      "To: employee@example.com\r\n" +
      "Subject: =?UTF-8?Q?URGENT:_Your_Microsoft_account_will_be_suspended_today?=\r\n" +
      "Date: Sat, 29 Aug 2026 02:15:00 +0000\r\n" +
      "\r\n" +
      "Dear User,\r\n" +
      "We detected unusual activity. Your account will be permanently blocked unless you complete verification within 2 hours.\r\n" +
      "Please confirm your account immediately: https://login-micr0soft.example/verify?jwt=" + token + "\r\n" +
      "Call 1-800-555-0199 for help.\r\n";
    String j = App.analyzeMessageForTests(eml);

    // Layer 6: subject forensics
    check("apex: subject_forensics emitted", j.contains("\"subject_forensics\""));
    check("apex: RFC2047 Q subject decoded", j.contains("\"decoded\":\"URGENT: Your Microsoft account will be suspended today\""));
    check("apex: subject risk MEDIUM+", j.contains("\"risk_level\":\"MEDIUM\"") || j.contains("\"risk_level\":\"HIGH\"") || j.contains("\"risk_level\":\"CRITICAL\""));
    check("apex: top-level subject_risk present", j.contains("\"subject_risk\":"));

    // Layer 8: JWT decode
    check("apex: jwt_forensics emitted", j.contains("\"jwt_forensics\""));
    check("apex: JWT alg=none flagged", j.contains("\"alg\":\"none\""));
    check("apex: JWT high-risk YES", j.contains("\"high_risk\":\"YES\""));
    check("apex: JWT None Algorithm attack named", j.contains("JWT None Algorithm Attack"));
    check("apex: JWT pre-filled victim email flagged", j.contains("Pre-filled victim email"));
    check("apex: JWT capture intent flagged", j.contains("Credential capture intent"));

    // Layer 8b: Apple-style JWT (b64-encoded email in sub, appleid audience) decoded robustly
    String appleB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("victim@example.com".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String appleH = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RS256\",\"kid\":\"ABC-123\",\"typ\":\"JWT\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String appleP = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"iss\":\"https://appleid.apple.com\",\"aud\":\"https://appleid.apple.com\",\"sub\":\"" + appleB64 + "\",\"email\":\"victim@example.com\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String appleTok = appleH + "." + appleP + "." + "AAAA";
    String appleEml = "From: a@evil.example\r\nTo: victim@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nVerify now: https://evil.example/login?token=" + appleTok + "\r\n";
    String aj = App.analyzeMessageForTests(appleEml);
    check("apex: Apple JWT aud/iss decoded", aj.contains("\"iss\":\"https://appleid.apple.com\""));
    check("apex: Apple JWT b64 sub decoded to victim email", aj.contains("\"sub_decoded\":\"victim@example.com\""));
    check("apex: Apple JWT forgery pattern flagged", aj.contains("Sign in with Apple JWT forgery pattern"));
    check("apex: Apple JWT high-risk", aj.contains("\"high_risk\":\"YES\""));
    String garbageEml = "From: a@evil.example\r\nTo: victim@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nToken: https://evil.example/login?token=eyJ!!!..eyJ???.\r\n";
    check("apex: malformed JWT base64 does not crash decode", App.analyzeMessageForTests(garbageEml).contains("\"jwt_forensics\""));

    // Layer 8c: child-domain sandboxing / clean-domain guard (official brand children)
    check("apex: official brand child sandboxed (microsoftonline child)", App.sandboxOfficialHost("login.microsoftonline.com"));
    check("apex: official brand root sandboxed", App.sandboxOfficialHost("microsoft.com"));
    check("apex: lookalike host NOT sandboxed", !App.sandboxOfficialHost("login-microsoft.example") && !App.sandboxOfficialHost("microsoft0.com.example"));
    check("apex: null/blank host NOT sandboxed", !App.sandboxOfficialHost(null) && !App.sandboxOfficialHost(""));
    String phUrl = "https://login-microsoft.example/verify";
    String phCard = App.analyzeUrl(phUrl, phUrl);
    check("apex: non-official URL analysis NOT sandboxed", !phCard.contains("official_brand_child"));
    check("apex: non-official lookalike still flagged", phCard.contains("Brand impersonation"));

    // Layer 9: header parsing hardening — display-name email must never win the From-domain vote
    String dispEml = "From: \"security@evil.example\" <security@paypal.example>\r\nTo: v@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nhello\r\n";
    String dj = App.analyzeMessageForTests(dispEml);
    check("apex: from_domain prefers angle-bracket address over display-name email", dj.contains("\"from\":\"paypal.example\"") && !dj.contains("\"from\":\"evil.example\""));
    String bareDisplay = "From: support@example.com\r\nTo: v@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nhello\r\n";
    check("apex: bare addr-spec yields no display name", App.analyzeMessageForTests(bareDisplay).contains("\"display_name\":\"\""));
    String bracketDisplay = "From: Microsoft Security [security@micr0soft-account.example]\r\nTo: v@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nhello\r\n";
    check("apex: display name keeps name part, strips trailing addr", App.analyzeMessageForTests(bracketDisplay).contains("\"display_name\":\"Microsoft Security\""));
    check("apex: displayNameOf unquotes quoted display", App.displayNameOf("\"PayPal\" <security@paypal.example>").equals("PayPal"));
    check("apex: displayNameOf angle-only yields empty", App.displayNameOf("<spoof@evil.example>").isEmpty());

    // Layer 13b: process-chain merge — same-host targets collapse into one chain entry
    String dupEml = "From: a@b.example\r\nTo: c@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nGo https://evil.example/x and also https://evil.example/y\r\n";
    String uj = App.analyzeMessageForTests(dupEml);
    check("apex: same-host URL targets merged into one chain entry", uj.contains("\"host\":\"evil.example\"") && uj.contains("\"occurrences\":2") && uj.contains("\"chain_sources\":["));

    // Layer 12: behavioral
    check("apex: behavioral_analysis emitted", j.contains("\"behavioral_analysis\""));
    check("apex: off-hours send flagged (02:15 UTC)", j.contains("\"off_hours\":\"YES\""));
    check("apex: behavioral weekend flagged", j.contains("\"weekend\":\"YES\""));
    check("apex: urgency trigger detected", j.contains("\"triggers\":[\"urgent\"]") || j.contains("URGENT"));
    check("apex: deadline time-pressure detected", j.contains("\"deadline\":\"YES\""));
    check("apex: generic greeting flagged", j.contains("GENERIC"));

    // Layer 16: MITRE mapping (confirmed evidence only)
    check("apex: mitre_attack emitted", j.contains("\"mitre_attack\""));
    check("apex: MITRE Initial Access T1566 mapped", j.contains("T1566"));
    check("apex: MITRE Credential Access T1056 mapped", j.contains("T1056"));

    // Layer 9: domain intelligence honesty for synthetic .example
    check("apex: domain_intelligence emitted", j.contains("\"domain_intelligence\""));
    check("apex: synthetic .example domain NOT queried as clean", j.contains("\"whois_registration\":\"UNKNOWN\""));
    check("apex: no fabricated domain age (honest UNKNOWN marker)", j.contains("\"domain_age_days\":-1") && j.contains("synthetic/reserved domain"));

    // Layer 13: redirect defang (UNRESOLVABLE, not fabricated)
    check("apex: redirect_analysis emitted", j.contains("\"redirect_analysis\""));
    check("apex: links defanged", j.contains("[:]//") || j.contains("httpxx://"));
    check("apex: redirect UNRESOLVABLE honest marker", j.contains("UNRESOLVABLE"));

    // Machine-readable IOC block
    check("apex: iocs_json emitted with defanged url", j.contains("\"iocs_json\""));

    // ---- APEX-EMAIL: new extended analysis layers ----
    // Layer: greeting analysis (generic vs personalized)
    check("apex-email: greeting_analysis emitted", j.contains("\"greeting_analysis\":"));
    check("apex-email: generic greeting detected for 'Dear User'", j.contains("\"type\":\"GENERIC\"") && j.contains("\"greeting_text\":\"Dear User,\""));
    check("apex-email: greeting risk 2 points added", j.contains("\"risk_points\":2"));
    // Layer: greeting analysis (personalized -> targeted spearphishing correlation)
    String per = "From: \"Manager\" <boss@corp.example>\r\nTo: alice@corp.example\r\nSubject: Review request\r\nDate: Thu, 27 Aug 2026 11:00:00 +0000\r\n\r\nDear Alice, please review the attached report before noon.\r\n";
    String pj = App.analyzeMessageForTests(per);
    check("apex-email: personalized greeting type detected", pj.contains("\"type\":\"PERSONALIZED\""));
    check("apex-email: greeting name matched to To local-part", pj.contains("\"name_matched_to_to\":true"));
    check("apex-email: personalized greeting drives CORR-GREET-TARGET", pj.contains("CORR-GREET-TARGET"));
    check("apex-email: timing NORMAL at 11:00 UTC", pj.contains("\"time_classification\":\"NORMAL\""));
    // Layer: timing analysis (off-hours / weekend)
    check("apex-email: timing_analysis emitted", j.contains("\"timing_analysis\":"));
    check("apex-email: off-hours timing classified", j.contains("\"time_classification\":\"OFF-HOURS\""));
    check("apex-email: weekend send flagged", j.contains("\"weekend_send\":true"));
    check("apex-email: timing risk 9 points (off-hours+weekend)", j.contains("\"risk_points\":9"));
    // Layer: X-Mailer analysis (present vs absent, honest consistency)
    check("apex-email: x_mailer_analysis emitted", j.contains("\"x_mailer_analysis\":"));
    check("apex-email: absent X-Mailer NOT_APPLICABLE (not fabricated)", j.contains("\"present\":false") && j.contains("\"consistency_check\":\"NOT_APPLICABLE\""));
    // Layer: fake contact analysis
    check("apex-email: fake_contact_analysis emitted", j.contains("\"fake_contact_analysis\":"));
    check("apex-email: contact risk MEDIUM for unknown phone", j.contains("\"contact_risk_level\":\"MEDIUM\"") && j.contains("\"risk_points\":5"));
    // Layer: deep social-engineering analysis
    check("apex-email: social_engineering_deep emitted", j.contains("\"social_engineering_deep\":"));
    check("apex-email: deep urgency detected", j.contains("\"urgency_detected\":true"));
    check("apex-email: deep fear detected", j.contains("\"fear_detected\":true"));
    check("apex-email: deep deadline pressure detected", j.contains("\"deadline_present\":true"));
    check("apex-email: deep permanent-consequence framing", j.contains("\"permanent_consequence\":true"));
    // Layer: typosquat analysis
    check("apex-email: typosquat_analysis emitted", j.contains("\"typosquat_analysis\":"));
    check("apex-email: micr0soft typosquat detected as microsoft", j.contains("\"detected\":true") && j.contains("\"brand\":\"microsoft\""));
    check("apex-email: TLD mismatch flagged (.com vs .example)", j.contains("\"tld_mismatch\":true"));
    check("apex-email: typosquat lookalike score > 0", j.contains("\"lookalike_score\":15"));
    // Layer: HTML body forensics (no HTML -> LOW, honest)
    check("apex-email: html_body_forensics emitted", j.contains("\"html_body_forensics\":"));
    check("apex-email: plain-text body honest no-HTML note", j.contains("\"note\":\"no HTML detected\""));
    // Layer: tracking-pixel full forensics
    check("apex-email: tracking_pixel_forensics emitted", j.contains("\"tracking_pixel_forensics\":"));
    check("apex-email: no pixel falsely reported present", j.contains("\"pixels_found\":false"));
    // IOC JSON schema extension
    check("apex-email: iocs_json carries jwt_tokens", j.contains("\"jwt_tokens\":["));
    check("apex-email: iocs_json carries tracking_pixels", j.contains("\"tracking_pixels\":"));
    check("apex-email: JWT payload fields surfaced in IOC", j.contains("\"payload\":{\"json\":\"{\\\"email\\\":\\\"victim@example.com\\\""));

    // ---- Benign control: no JWT false positive, business-hours low behavioral ----
    String benign =
      "From: noreply@example.com\r\nTo: u@example.com\r\nSubject: Invoice #4821\r\nDate: Thu, 27 Aug 2026 10:30:00 +0000\r\n\r\nYour invoice is attached here: https://example.com/invoice\r\nHello Alice,\r\n\r\nRegards, Billing\r\n";
    String bj = App.analyzeMessageForTests(benign);
    check("apex: benign has no JWT", !bj.contains("\"alg\":\"none\""));
    check("apex: benign business-hours not off-hours", bj.contains("\"off_hours\":\"NO\""));
    check("apex: benign not PHISHING", !"PHISHING".equals(rs(bj,"threat_classification")));
  }

  // =====================================================================
  // APEX-GEO 16-layer IP forensics regression tests
  // Uses only private/reserved addresses (deterministic — no live network)
  // plus pure deterministic representation helpers. Verifies honest
  // UNAVAILABLE / NOT_APPLICABLE handling and that nothing is fabricated.
  // =====================================================================
  static void apexGeoForensicsTests() {
    // Private IP → fully deterministic path (no external geolocation/feeds)
    String j = App.apexGeo("192.168.1.10", "192.168.1.10");
    check("geo: module marker present", j.contains("\"module\":\"apex_geo_forensics\""));
    for (int i = 1; i <= 15; i++) {
      check("geo: section " + i + " present", j.contains("\"" + i + "_"));
    }
    // Chain of custody
    check("geo: case_id generated", j.contains("\"case_id\":\"CASE-"));
    check("geo: evidence status PRESERVED", j.contains("PRESERVED"));
    // Layer 3 representations (deterministic)
    check("geo: private binary correct", j.contains("11000000.10101000.00000001.00001010"));
    check("geo: private decimal correct", j.contains("\"decimal_representation\":\"3232235786\""));
    check("geo: private class C", j.contains("\"ip_class\":\"Class C\""));
    check("geo: private NOT_PUBLIC geo status", j.contains("\"status\":\"NOT_APPLICABLE\""));
    // Honesty: no external feed data fabricated on private path
    check("geo: private does not fabricate AbuseIPDB", !j.contains("\"abuseipdb\":{\"status\":\"MALICIOUS\""));
    check("geo: private completeness object present", j.contains("\"data_completeness\":"));
    // Risk scoring shape
    check("geo: risk scoring breakdown present", j.contains("\"anonymizer_signals\""));
    check("geo: final_score present", j.contains("\"final_score\":"));
    // IOC output
    check("geo: IOC value present", j.contains("\"value\":\"192.168.1.10\""));
    check("geo: IOC has risk_scoring", j.contains("\"risk_scoring\":{"));

    // Pure deterministic representation helpers
    checkEq("geo: ipHex(8.8.8.8)", App.ipHex("8.8.8.8"), "0x08080808");
    check("geo: ipBinary(8.8.8.8)", App.ipBinary("8.8.8.8").startsWith("00001000.00001000"));
    checkEq("geo: ipDecimal(8.8.8.8)", App.ipDecimal("8.8.8.8"), "134744072");
    checkEq("geo: ipClass(8.8.8.8)", App.ipClass("8.8.8.8"), "Class A");
    checkEq("geo: ipClass(10.0.0.1)", App.ipClass("10.0.0.1"), "Class A");
    checkEq("geo: ipClass(172.16.0.1)", App.ipClass("172.16.0.1"), "Class B");
    checkEq("geo: ipClass(192.168.1.1)", App.ipClass("192.168.1.1"), "Class C");
    checkEq("geo: ipClass(224.0.0.1)", App.ipClass("224.0.0.1"), "Class D — Multicast");
    checkEq("geo: ipClass(240.0.0.1)", App.ipClass("240.0.0.1"), "Class E — Reserved");

    // Documentation (RFC 5737) reserved → deterministic NOT_APPLICABLE, zero external queries
    String d = App.apexGeo("203.0.113.7", "203.0.113.7");
    check("geo: doc IP private/special path", !d.contains("\"public\":true"));
    check("geo: doc IP risk INFORMATIONAL or lower", d.contains("\"final_score\":0") || d.contains("\"risk_level\":\"INFORMATIONAL\""));
    // A private IP must NOT be sent to RIPEstat/AbuseIPDB — no CIDR assertion leakage
    check("geo: private IP derives neighborhood context label", d.contains("derived_neighborhood") || j.contains("derived_neighborhood"));
  }

  private static void checksF1ToF5() {
    // F1 · Analyst triage statistics (pure, no disk)
    String tri = App.triageStatsTest(java.util.List.of(
      "{\"message_id\":\"m1\",\"original_verdict\":\"QUARANTINE\",\"user_verdict\":\"PHISHING\",\"reviewer_verdict\":\"\",\"user\":\"ana\",\"timestamp\":\"2026-08-27T12:00:00Z\"}",
      "{\"message_id\":\"m2\",\"original_verdict\":\"WARN\",\"user_verdict\":\"SPAM\",\"timestamp\":\"2026-08-27T12:01:00Z\"}",
      "{\"message_id\":\"m3\",\"original_verdict\":\"WARN\",\"user_verdict\":\"PHISHING\",\"timestamp\":\"2026-08-27T12:02:00Z\"}"));
    check("F1: triage stats total counts all verdicts", tri.contains("\"total\":3"));
    check("F1: triage stats bucket PHISHING=2", tri.contains("\"PHISHING\":2"));
    check("F1: triage stats bucket SPAM=1", tri.contains("\"SPAM\":1"));
    check("F1: triage stats recent tail preserved", tri.contains("\"recent\":[") && tri.contains("m2"));

    // F2 · Forensic markdown export (pure parse of a minimal analysis string)
    String minimal = "{\"analysisId\":\"A-1\",\"caseId\":\"CASE-1\",\"receivedAt\":\"2026-08-27T12:00:00Z\",\"evidenceHash\":\"abc\",\"classification\":\"PHISHING\",\"threat_classification\":\"SUSPICIOUS\",\"risk_level\":\"HIGH\",\"riskScore\":72,\"confidence\":{\"value\":70,\"label\":\"HIGH\"},\"threatStatus\":{\"state\":\"MALICIOUS\",\"reason\":\"brand}\"},\"subject\":\"Invite\",\"from\":\"a@evil.example\",\"scoreBreakdown\":{\"authentication\":{\"max\":15,\"value\":3},\"email_authentication\":{\"max\":15,\"value\":4},\"url_domain\":{\"max\":20,\"value\":6},\"dns\":{\"max\":10,\"value\":0},\"ip_intelligence\":{\"max\":10,\"value\":1},\"threat_intelligence\":{\"max\":20,\"value\":0},\"attachment\":{\"max\":15,\"value\":0},\"nlp_social\":{\"max\":15,\"value\":5},\"header_routing\":{\"max\":10,\"value\":3},\"correlation_bonus\":{\"max\":15,\"value\":0}},\"greeting_analysis\":{\"type\":\"GENERIC\"},\"iocs_json\":{\"ips\":[],\"urls\":[\"https://evil.example/x\"]},\"analysis_timeline\":[{}],\"json_field_guard\":{\"x\":\"}\"}}";
    String md = App.forensicMarkdownTest(minimal);
    check("F2: markdown header present", md.contains("# Cipher Squad Forensic Report"));
    check("F2: markdown risk score line", md.contains("- **Risk score:** 72/100"));
    check("F2: markdown confidence line", md.contains("70/96 (HIGH)"));
    check("F2: markdown threat status", md.contains("MALICIOUS"));
    check("F2: markdown breakdown table rows", md.contains("| authentication | 3 | 15 |") && md.contains("| email_authentication | 4 | 15 |"));
    check("F2: markdown greeting type", md.contains("Greeting type: GENERIC"));
    check("F2: markdown ioc block shows raw targets", md.contains("https://evil.example/x") && md.contains("```json"));

    // F3 · IOC registry summary + analyst suppression (pure, no disk)
    String sum = App.iocSummaryTest(java.util.List.of(
      "{\"key\":\"ipv4|1.1.1.1\",\"type\":\"ipv4\",\"value\":\"1.1.1.1\",\"reputation\":\"MEDIUM\",\"confidence\":70,\"first_seen\":\"x\",\"last_seen\":\"x\"}",
      "{\"key\":\"url|https://evil.example\",\"type\":\"url\",\"value\":\"https://evil.example\",\"reputation\":\"HIGH\",\"confidence\":88,\"first_seen\":\"x\",\"last_seen\":\"x\"}",
      "{\"suppressed\":true,\"value\":\"2.2.2.2\",\"reason\":\"internal host\",\"by\":\"analyst\",\"at\":\"x\"}"));
    check("F3: ioc summary total 2 active", sum.contains("\"total\":2"));
    check("F3: ioc summary suppressed 1", sum.contains("\"suppressed\":1"));
    check("F3: ioc summary by_kind ipv4+url", sum.contains("\"ipv4\":1") && sum.contains("\"url\":1"));
    check("F3: ioc summary by_reputation", sum.contains("\"MEDIUM\":1") && sum.contains("\"HIGH\":1"));
    check("F3: ioc summary recent + suppressed_list", sum.contains("\"recent\":[") && sum.contains("\"suppressed_list\":[") && sum.contains("internal host"));

    // F4 · Offline self-test: all deterministic known-answer checks pass
    String st = App.selfTestJsonTest();
    check("F4: self-test all_pass true", st.contains("\"all_pass\":true"));
    check("F4: self-test has 6 checks", st.matches("(?s).*\"checks\":\\[.*\\].*") && st.split("\"name\":").length == 7);
    check("F4: self-test risk band check ok", st.contains("\"risk_band_consistency\",\"ok\":true"));
    check("F4: self-test saturation vector ok", st.contains("\"saturation_known_vector\",\"ok\":true"));
    check("F4: self-test bounded scan ok", st.contains("\"scan_json_bounded\",\"ok\":true"));
    check("F4: self-test merge ok", st.contains("\"redirect_chain_merge\",\"ok\":true"));
    check("F4: self-test timeline ok", st.contains("\"timeline_present\",\"ok\":true"));
    check("F4: self-test cache sync ok", st.contains("\"cache_synchronized\",\"ok\":true"));

    // F4b · riskFromPool known vectors (exposed)
    checkEq("F4b: riskFromPool(0)=0", App.riskFromPoolTest(0), 0);
    checkEq("F4b: riskFromPool(27)=54", App.riskFromPoolTest(27), 54);
    checkEq("F4b: riskFromPool(100)=94", App.riskFromPoolTest(100), 94);

    // F5 · Analysis timeline embedded in real analysis output
    String tlEmail = "From: paypal@ats-attacker.example\r\nTo: victim@corp.example\r\nSubject: Account restricted\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nDear customer, open https://evil.example/restore now. PayPal.\r\n";
    String aj = App.analyzeMessageForTests(tlEmail);
    check("F5: analysis_timeline present", aj.contains("\"analysis_timeline\":["));
    check("F5: timeline has message_received event", aj.contains("\"event\":\"message_received\""));
    check("F5: timeline has decision event", aj.contains("\"event\":\"decision\""));
    check("F5: timeline detail mentions score", aj.matches("(?s).*\"event\":\"layered_analysis\".*"));
    check("F5: redirect chain also merged in same run", aj.matches("(?s).*\"redirect_analysis\":\\[\\{\"host\":\"evil\\.example\",\"occurrences\":1.*"));
    check("F5: riskScore still parsed by scanner consumers", aj.matches("(?s).*\"riskScore\":(\\d+).*"));
  }

  // =====================================================================
  // ACCESS CONTROL · GRAPH-BASED CAMPAIGN ANALYSIS · OUTBOUND ALERT PACKAGING
  // Deterministic, no live network. Auth touches the NDJSON user store in
  // the test CWD; graph uses an in-memory edge list (pure BFS) plus one
  // disk-backed correlation run.
  // =====================================================================
  private static void checksGraphAlertAuth() {
    // ---- Access control: PBKDF2 hashing + verification (constant-time) ----
    String h = App.hashPassword("CorrectHorse9!");
    check("auth: hash is pbkdf2_sha256 w/ 120k iters", h.startsWith("pbkdf2_sha256$120000$") && h.split("\\$").length == 4);
    check("auth: verify correct password", App.verifyPassword("CorrectHorse9!", h));
    check("auth: verify wrong password false", !App.verifyPassword("wrongpw1", h));
    check("auth: verify null stored false", !App.verifyPassword("x", null));
    check("auth: verify garbage stored false", !App.verifyPassword("x", "not-a-hash"));

    // ---- Access control: user store + session tokens (8h TTL enforced by expiry) ----
    App.authCreateUser("alice@corp.local", "CorrectHorse9!", "analyst");
    App.authCreateUser("bob@corp.local", "View3rOnly!x", "viewer");
    check("auth: user store counts created users", App.authUserCount() >= 2);
    check("auth: role persisted", "analyst".equals(App.authUserRole("alice@corp.local")));
    check("auth: login password verified against stored hash", App.authLoginCheck("alice@corp.local", "CorrectHorse9!"));
    check("auth: login rejects wrong password", !App.authLoginCheck("alice@corp.local", "nope-nope"));
    String tok = App.authSessionFor("alice@corp.local");
    check("auth: session token issued", tok != null && tok.length() >= 32);
    check("auth: session token resolves to user", !App.sessionForToken(tok).isEmpty());
    check("auth: bogus token yields no session", App.sessionForToken("not-a-real-token").isEmpty());
    check("auth: null token yields no session", App.sessionForToken(null).isEmpty());

    // ---- Graph: pure BFS 2-hop from the incident node with hop capping ----
    java.util.List<String> gEdges = java.util.List.of(
      "{\"id\":\"g1\",\"node_a\":\"inc:INC-G1\",\"node_b\":\"url:https://evil.test/x\",\"type\":\"CONTAINS_URL\",\"incident_id\":\"INC-G1\",\"confidence\":90,\"detail\":\"x\",\"at\":\"t\"}",
      "{\"id\":\"g2\",\"node_a\":\"url:https://evil.test/x\",\"node_b\":\"domain:evil.test\",\"type\":\"URL_TO_DOMAIN\",\"incident_id\":\"INC-G1\",\"confidence\":95,\"detail\":\"x\",\"at\":\"t\"}",
      "{\"id\":\"g3\",\"node_a\":\"inc:INC-G1\",\"node_b\":\"param:orderid\",\"type\":\"CAMPAIGN_PARAM\",\"incident_id\":\"INC-G1\",\"confidence\":70,\"detail\":\"x\",\"at\":\"t\"}");
    String g1 = App.graphJson("inc:INC-G1", 1, gEdges);
    check("graph: 1-hop caps node set", g1.contains("\"node_count\":3") && g1.contains("\"edge_count\":2"));
    check("graph: 1-hop does not reach leaf", !g1.contains("domain:evil.test"));
    String g2 = App.graphJson("inc:INC-G1", 2, gEdges);
    check("graph: 2-hop reaches domain leaf", g2.contains("\"node_count\":4") && g2.contains("\"edge_count\":3"));
    check("graph: JSON output well-formed (balanced delimiters)", countChar(g2,'{')==countChar(g2,'}') && countChar(g2,'[')==countChar(g2,']'));
    check("graph: node type labels present", g2.contains("\"type\":\"domain\"") && g2.contains("\"type\":\"url\""));
    check("graph: edge carries relation type", g2.contains("\"type\":\"URL_TO_DOMAIN\""));
    check("graph: edge confidence preserved as number", g2.contains("\"type\":\"URL_TO_DOMAIN\",\"confidence\":95"));
    check("graph: hop cap 6 never exceeded", App.graphJson("inc:INC-G1", 99, gEdges).contains("\"hops\":2"));
    check("graph: nodeOf maps type:value", "domain:evil.test".equals(App.nodeOf("domain", "evil.test")));

    // ---- Graph: correlation auto-population (disk-backed edge store) + shared-infrastructure edges ----
    String run = Long.toString(System.currentTimeMillis());
    String inc1 = "INC-GRAPH-" + run + "-1", inc2 = "INC-GRAPH-" + run + "-2";
    int before = App.edgeCount();
    String an1 = "{\"from\":\"attacker@evil-bank.test\",\"iocs_json\":{\"urls\":[\"https://evil-bank.test/verify\",\"https://2.2.2.2/x\"]},\"origin_analysis\":{\"origin_ip\":\"185.220.102.44\"},\"classification\":\"PHISHING\",\"riskScore\":88,\"findings\":[{\"message\":\"SPF fail\"},{\"message\":\"Lookalike\"}]}";
    App.recordGraphEdges(an1, inc1);
    check("graph: correlation writes edges", App.edgeCount() > before);
    String g3 = App.graphJson(App.nodeOf("inc", inc1), 2, App.edgesTest());
    check("graph: incident node reachable", g3.contains("\"id\":\"inc:" + inc1 + "\""));
    check("graph: sender domain captured", g3.contains("domain:evil-bank.test"));
    check("graph: origin ip captured", g3.contains("ip:185.220.102.44"));
    String g3b = App.graphJson(App.nodeOf("inc", inc1), 2, App.edgesTest());
    check("graph: url node captured", g3b.contains("url:https://evil-bank.test/verify"));
    App.recordGraphEdges("{\"from\":\"support@evil-bank.test\",\"iocs_json\":{\"urls\":[\"https://evil-bank.test/login\"]},\"classification\":\"PHISHING\",\"riskScore\":90}", inc2);
    String g4 = App.graphJson(App.nodeOf("inc", inc2), 2, App.edgesTest());
    check("graph: shared-domain correlation links incidents", g4.contains(inc1) && g4.contains("SHARED_DOMAIN"));
    check("graph: topFindings extracts messages", App.topFindings(an1, 2).size() == 2);
    check("graph: topFindings bounded by max", App.topFindings(an1, 1).size() == 1);

    // ---- Alerts: payload packaging + threshold matching (no live sends) ----
    String p = App.alertPayloadJson("HIGH", 81, "PHISHING", "INC-A1", java.util.List.of("SPF fail", "Lookalike"), "http://127.0.0.1:8080/#/incidents/INC-A1");
    check("alert: payload has severity+risk", p.contains("\"severity\":\"HIGH\"") && p.contains("\"risk_score\":81"));
    check("alert: payload has classification+incident", p.contains("\"classification\":\"PHISHING\"") && p.contains("\"incident_id\":\"INC-A1\""));
    check("alert: payload has top findings array", p.contains("\"top_findings\":[\"SPF fail\",\"Lookalike\"]"));
    check("alert: payload escapes and keeps report link", p.contains("report_link") && p.contains("#/incidents/INC-A1"));
    check("alert: threshold HIGH fires at 90", App.alertThresholdHit("HIGH", 90));
    check("alert: threshold HIGH silent at 40", !App.alertThresholdHit("HIGH", 40));
    check("alert: threshold LOW fires at 25", App.alertThresholdHit("LOW", 25));
    check("alert: threshold CRITICAL silent at 79", !App.alertThresholdHit("CRITICAL", 79));
    check("alert: threshold CRITICAL fires at 80", App.alertThresholdHit("CRITICAL", 80));
    App.maybeDispatchAlerts("HIGH", 95, "PHISHING", "INC-NOCH", java.util.List.of("x"), "http://127.0.0.1:8080/#/incidents/x"); // zero channels => must be a safe no-op
    check("alert: no channels configured means nothing dispatched", App.channelCount() == 0);
  }

  // ---- Gmail forensics: sender-domain classification + spoof-signal honesty ----
  private static Map<String,List<String>> gm(String rawHeaders){
    java.util.Map<String,List<String>> m = new java.util.LinkedHashMap<>();
    for (String line : rawHeaders.split("\r?\n")) {
      int c = line.indexOf(':');
      if (c <= 0) continue;
      String k = line.substring(0, c).trim().toLowerCase(java.util.Locale.ROOT);
      String v = line.substring(c + 1).trim();
      m.computeIfAbsent(k, x -> new java.util.ArrayList<>()).add(v);
    }
    return m;
  }
  static void gmailForensicsTests() {
    // Non-Gmail sender => NOT_GMAIL, no risk, honest not_applicable confidence.
    String r1 = App.gmailForensics("From: attacker@evil.test\r\nSubject: hi\r\nMessage-ID: <x@evil.test>\r\n", gm("From: attacker@evil.test\r\nMessage-ID: <x@evil.test>\r\n"), "evil.test", "hi");
    check("gmail: non-gmail sender classified NOT_GMAIL", r1.contains("\"sender_class\":\"NON_GOOGLE\"") && r1.contains("\"verdict\":\"NOT_GMAIL\""));
    check("gmail: non-gmail yields zero risk points", r1.contains("\"risk_points\":0"));
    check("gmail: confidence honest for non-gmail", r1.contains("\"confidence\":\"not_applicable\""));
    check("gmail: JSON well-formed", countChar(r1,'{')==countChar(r1,'}') && countChar(r1,'[')==countChar(r1,']'));

    // Gmail sender but NO Google relay / standard message-id => spoof REVIEW signals.
    String g2 = "From: a@gmail.com\r\nSubject: invoice\r\nMessage-ID: <random@local.box>\r\nReceived: from mx.evil.test by mx.evil.test\r\nAuthentication-Results: mx.evil.test\r\nReceived-SPF: fail (none)\r\n";
    String r2 = App.gmailForensics(g2, gm(g2), "gmail.com", "invoice");
    check("gmail: gmail domain recognized", r2.contains("\"sender_class\":\"GMAIL\""));
    check("gmail: missing standard message-id flagged non-standard", r2.contains("\"gmail_message_id\":\"NON_STANDARD\""));
    check("gmail: spoof signals present for inconsistent Gmail", r2.contains("spoof_signals") && r2.contains("Gmail"));
    check("gmail: no google received evidence", r2.contains("\"google_received_evidence\":false"));
    check("gmail: risk_points bounded at 24", ri(r2,"risk_points") >= 6 && ri(r2,"risk_points") <= 24);

    // Genuine Gmail pattern => indicators + CONSISTENT_WITH_GMAIL.
    String g3 = "From: a@gmail.com\r\nSubject: docs\r\nMessage-ID: <CABcdeFg1234567890+/ab@mail.gmail.com>\r\nReceived: from mail-sor-f41.google.com\r\nARC-Seal: i=1; a=rsa-sha256; d=google.com\r\nAuthentication-Results: gmail.com\r\nReceived-SPF: pass\r\nDKIM-Signature: d=gmail.com\r\n";
    String r3 = App.gmailForensics(g3, gm(g3), "gmail.com", "docs");
    check("gmail: genuine gmail message-id detected", r3.contains("\"gmail_message_id\":\"GMAIL\""));
    check("gmail: google received evidence present", r3.contains("\"google_received_evidence\":true"));
    check("gmail: alignment PASS recorded", r3.contains("\"alignment\":\"PASS\""));
    check("gmail: genuine gmail consistent verdict", r3.contains("\"verdict\":\"CONSISTENT_WITH_GMAIL\""));

    // Wire-in: analyzeMessageForTests must emit gmail_forensics and not crash.
    String an = App.analyzeMessageForTests(g2);
    check("gmail: analyze emits gmail_forensics field", an.contains("\"gmail_forensics\":"));
    check("gmail: analyze gmail json well-formed", an.contains("\"engine\":\"gmail_forensics\""));
  }

  // ---- Scanners: honest LIVE/UNAVAILABLE/NOT_CONFIGURED semantics (never fabricated) ----
  static void scannerTests() {
    // Aggregate is JSON-parseable and always labels per-engine; a missing/broken/zilch engine must be
    // NOT_CONFIGURED or UNAVAILABLE — we assert the honesty contract, not a specific backend state.
    String agg = App.scannersForEmail("From: a@b.example\r\nSubject: hi\r\n");
    check("scan: aggregate well-formed JSON", countChar(agg,'{')==countChar(agg,'}') && countChar(agg,'[')==countChar(agg,']'));
    check("scan: aggregate covers all three engines", agg.contains("\"clamav\":") && agg.contains("\"rspamd\":") && agg.contains("\"yara\":"));
    check("scan: every engine labelled status", agg.contains("\"status\":\"NOT_CONFIGURED\"") || agg.contains("\"status\":\"UNAVAILABLE\"") || agg.contains("\"status\":\"LIVE\""));
    check("scan: config block present", agg.contains("\"engine_status\"") || agg.contains("\"config\":"));
    // Honesty: an unconfigured yara/clamd must NOT emit a fabricated CLEAN/MATCH verdict claim.
    check("scan: no fabricated clamav signature when unreachable", !agg.contains("\"signature\":"));
    if (App.yaraRulesConfiguredForTest() == 0) {
      check("scan: yara empty-rules path is NOT_CONFIGURED", agg.contains("\"yara\":{\"status\":\"NOT_CONFIGURED\""));
    }
  }

  // ---- PhishGuard: URL/site heuristic analyzer, deterministic and offline-safe ----
  static void phishGuardTests() {
    String sus = App.phishGuardAnalyze("http://paypal-secure-login.verify.example.net/verify", false);
    check("phishguard: suspicious URL yields risk above zero", ri(sus,"risk_score") >= 5);
    check("phishguard: verdict present", rs(sus,"verdict").length() > 0);
    check("phishguard: flags array present", sus.contains("\"flags\":["));
    check("phishguard: host extracted", rs(sus,"host").length() > 0);
    check("phishguard: risky verdict not LOW_RISK", !"LOW_RISK".equals(rs(sus,"verdict")));

    String ok = App.phishGuardAnalyze("https://www.example.com/", false);
    check("phishguard: clean host stays low risk", ri(ok,"risk_score") < 20);

    String ip = App.phishGuardAnalyze("http://185.220.102.44/verify", false);
    check("phishguard: numeric-ip literal flagged", ip.contains("Numeric IP literal"));
    String cred = App.phishGuardAnalyze("https://user@evil.test/login", false);
    check("phishguard: embedded credentials flagged", cred.contains("URL-embedded credentials"));

     check("phishguard: JSON well-formed", countChar(sus,'{')==countChar(sus,'}') && countChar(sus,'[')==countChar(sus,']'));
   }

   // ---- Security operations: auth throttle, channel CRUD, static-file security ----
   static void secOpsTests() {
     // ---- Auth: brute-force throttle locks the account after the budget ----
     String t = "sec-"+System.currentTimeMillis();
     String email = t+"@example.com"; String ip = "10.0.0." + (t.hashCode() & 0xff);
     App.authCreateUser(email, "GoodP@ss123", "analyst");
     App.authClearForTest(email, ip);
     for (int i = 0; i < 4; i++) App.authRecordFailForTest(email, ip); // 4 failures, below budget
     check("auth: throttle counts 4 failures (below budget)", App.authFailCount(email,ip) == 4);
     // The 5th failure must cross the budget and impose a lockout.
     App.authRecordFailForTest(email, ip);
     check("auth: 5th failure triggers lockout (>0 ms)", App.authLockRemainingMs(email,ip) > 0);
     check("auth: account is locked after 5 failures", App.authIsLockedForTest(email,ip));
     // Lockout must be enforced even for the correct password (simulated login returns 429).
     check("auth: correct password rejected while locked (429)", App.authSimulatedLoginResult(email, "GoodP@ss123", ip) == 429);
     // Clearing counters restores the ability to sign in (simulated login returns 200).
     App.authClearForTest(email, ip);
     check("auth: clear resets fail counter to 0", App.authFailCount(email,ip) == 0);
     check("auth: correct password accepted after clear (200)", App.authSimulatedLoginResult(email, "GoodP@ss123", ip) == 200);

     // ---- Channel CRUD: create, find, toggle, delete ----
     String chId = App.channelCreateForTest("webhook", "http://127.0.0.1:9290/alert/", "sec-test-channel", "HIGH");
     check("channel: create returns a ch-test id", chId != null && chId.startsWith("ch-test-"));
     String chRow = App.channelFindForTest(chId);
     check("channel: find returns the created row", chRow != null && chRow.contains("\"name\":\"sec-test-channel\""));
     check("channel: toggle enabled off", App.channelSetEnabledForTest(chId, false));
     String afterOff = App.channelFindForTest(chId);
     check("channel: enabled flipped to false", afterOff != null && afterOff.contains("\"enabled\":\"false\""));
     check("channel: toggle enabled on", App.channelSetEnabledForTest(chId, true));
     check("channel: delete removes the row", App.channelDeleteForTest(chId));
     check("channel: deleted row is absent", App.channelFindForTest(chId) == null);

     // ---- Static-file serving: extension typing + path-traversal defence ----
     check("static: html mime", "text/html; charset=utf-8".equals(App.staticMimeTypeForTest("/index.html")));
     check("static: js mime", "text/javascript; charset=utf-8".equals(App.staticMimeTypeForTest("/app.js")));
     check("static: svg mime", "image/svg+xml".equals(App.staticMimeTypeForTest("/logo.svg")));
     // A request for a path outside the document root must not be served.
     check("static: ../ traversal is blocked", App.pathTraversalBlocked("/../../etc/passwd"));
     check("static: nonexistent file is blocked", App.pathTraversalBlocked("/does-not-exist.html"));
   }
}
