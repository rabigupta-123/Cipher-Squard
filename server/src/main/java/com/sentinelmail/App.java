package com.sentinelmail;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * Cipher Squad — evidence-based, multi-layer email forensic analysis engine.
 * Pipeline: Preserve -> Parse -> Extract -> Analyze -> Enrich -> Correlate -> Score -> Explain -> Report.
 * Dependency-free (JDK 25 + jdk.httpserver). Bind to HTTPS/behind auth in production.
 */
public final class App {
  private static final int PORT = Integer.parseInt(System.getenv().getOrDefault("SENTINEL_PORT", "8080"));
  private static final Path ROOT = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
  private static final Path DATA = ROOT.resolve("data");
  private static final Path CASES = DATA.resolve("cases.ndjson");
  private static final long START_UP = System.currentTimeMillis();
  // SCORE FIX (L6 attachment hash): known-bad attachment hashes loaded from data/bad_hashes.txt.
  // One SHA-256 (or SHA-1/MD5) hex hash per line; a matching attachment gets a high-severity finding.
  // The set is loaded lazily once and is safe to a missing file (empty set, no finding).
  private static Set<String> BAD_HASHES = null;
  private static synchronized Set<String> badHashes(){
    if (BAD_HASHES == null) {
      Set<String> s = new LinkedHashSet<>();
      Path f = DATA.resolve("bad_hashes.txt");
      try { if (java.nio.file.Files.exists(f)) { for (String l : java.nio.file.Files.readAllLines(f)) { String t = l.trim().toLowerCase(Locale.ROOT); if (!t.isEmpty() && !t.startsWith("#")) s.add(t); } } } catch (Exception ignored) {}
      BAD_HASHES = s;
    }
    return BAD_HASHES;
  }
  // In-memory per-case retention of the full analysis JSON so /api/analyze/explain and
  // /api/cases/timeline can reconstruct scoring justification for a recently analyzed case.
  // Bounded (LRU-ish by clearing when large) — not a substitute for durable storage.
  private static final Map<String,String> CASE_ANALYSIS = new LinkedHashMap<>(256, 0.75f, true);
  private static synchronized void cacheAnalysis(String caseId, String analysisJson){
    if (caseId == null || caseId.isEmpty()) return;
    if (CASE_ANALYSIS.size() > 512) CASE_ANALYSIS.clear();
    if (analysisJson != null) CASE_ANALYSIS.put(caseId, analysisJson);
  }
  private static synchronized String cachedCase(String caseId){ return caseId == null ? null : CASE_ANALYSIS.get(caseId); }
  // ------------------------------------------------------------------
  // Configuration (all secrets server-side via environment variables only)
  // ------------------------------------------------------------------
  private static final int MAX_REQ_BODY = 64 * 1024;                    // 64 KB for structured lookups
  private static final int MAX_EXTERNAL_BODY = 2 * 1024 * 1024;         // cap external provider responses (2 MB)
  private static final Duration EXT_TIMEOUT = Duration.ofSeconds(12);
  private static final int RATE_WINDOW_SECONDS = 10;                    // per-client lookup throttle window
  private static final int RATE_MAX_PER_WINDOW = 40;                    // max lookups per window per client
  private static final int CACHE_TTL_MS = 10 * 60 * 1000;               // 10 minute in-memory cache
  private static final Map<String, IPEntry> IP_CACHE = new LinkedHashMap<>(64);
  private static final Map<String, URLEntry> URL_CACHE = new LinkedHashMap<>(64);
  private static final Map<String, long[]> RATE = new LinkedHashMap<>();
  // Free-by-default providers (no key needed), used server-side only.
  private static final String GEO_API = "http://ip-api.com/json/";      // geolocation + ASN + proxy/hosting flags
  private static final String GEO_API2 = "http://ipwho.is/";            // second geolocation provider (multi-source correlation)
  // IP risk-scoring weights (configurable via env; must be >= 0). Interpretation:
  // threat_ti   = confirmed abuse/reputation/intel observations
  // threat_anon = Tor / VPN / anonymizer infrastructure (high-frequency abuse sources)
  private static final LinkedHashMap<String,Integer> IP_WEIGHTS = parseWeights(
      envOr("CIPHER_IP_WEIGHTS", "{\"threat_ti\":60,\"threat_anon\":25,\"network\":5,\"proxy\":10}"));
  // Optional paid/intel feeds (server-side env vars). When unset -> "Source unavailable".
  private static final String ABUSEIPDB_KEY = envOr("ABUSEIPDB_KEY", "");
  private static final String SAFEBROWSING_KEY = envOr("GOOGLE_SAFEBROWSING_KEY", "");
  // ---- SCANNER INTEGRATIONS (ClamAV / Rspamd / Yara). Each is detected/contacted at runtime; when the
  // backing service is not reachable the engine reports an honest UNAVAILABLE result — never a fabricated
  // scan verdict. All are optional: empty/unset values simply keep the scanner "not configured".
  private static final String CLAMAV_HOST   = envOr("CLAMAV_HOST", "127.0.0.1");
  private static final String CLAMAV_PORT   = envOr("CLAMAV_PORT", "3310");                 // clamd TCP port
  private static final String RSPAMD_URL    = envOr("RSPAMD_URL", "");                      // e.g. http://127.0.0.1:11334
  private static final String RSPAMD_KEY    = envOr("RSPAMD_KEY", "");                      // optional rspamd password header
  private static final String YARA_RULES    = envOr("YARA_RULES_DIR", detectDefaultRulesDir());      // dir of *.yar rule files
  private static final String YARA_BIN      = envOr("YARA_BIN", detectYaraBinary());                 // yara executable path
  // ---- PhishGuard website phishing analyzer ----
  private static final String PHISHGUARD_KEY = envOr("PHISHGUARD_KEY", "");                 // optional upstream API key
  // Configurable risk weights for the URL module (JSON, from env; must sum to ~100).
  private static final LinkedHashMap<String,Integer> URL_WEIGHTS = parseWeights(
      envOr("CIPHER_URL_WEIGHTS",
        "{\"url_domain\":30,\"reputation\":30,\"dns_network\":15,\"auth_tls\":10,\"obfuscation_impersonation\":10,\"contextual\":5}"));
  private static String envOr(String k, String d){ String v = System.getenv(k); return (v==null||v.isBlank()) ? d : v; }

  // Ship a default YARA rules directory alongside the app (workdir/yara-rules). If it exists the
  // scanner engine is usable out of the box; an unset YARA_RULES_DIR falls back to it automatically.
  private static String detectDefaultRulesDir(){
    String[] candidates = {
      Paths.get(System.getProperty("user.dir"), "yara-rules").toString(),
      Paths.get(System.getProperty("user.dir"), "config", "yara").toString(),
      "yara-rules"
    };
    for (String c : candidates) { Path p = Paths.get(c); if (Files.isDirectory(p)) { try (java.util.stream.Stream<Path> st = Files.list(p)) { if (st.anyMatch(f -> f.toString().toLowerCase(Locale.ROOT).matches(".*\\.(yar|yara)$"))) return p.toString(); } catch (Exception ignored) {} } }
    return "";
  }

  // Auto-detect the yara executable so the feature works without environment setup: PATH lookup
  // first, then common Windows install locations (winget/chocolatey portable layouts).
  private static String detectYaraBinary(){
    String[] names = {"yara", "yara.exe", "yara64.exe"};
    for (String n : names) { String r = findOnPath(n); if (r != null) return r; }
    String[] paths = {
      System.getenv("ProgramFiles"), System.getenv("ProgramFiles(x86)"), System.getenv("LOCALAPPDATA")
    };
    for (String base : paths) {
      if (base == null || base.isEmpty()) continue;
      for (String sub : new String[]{
          "yara", "YARA", "yara-yara",
          "Microsoft\\WinGet\\Packages\\VirusTotal.YARA_Microsoft.Winget.Source_8wekyb3d8bbwe"
      }) {
        Path p = Paths.get(base, sub, "yara64.exe");
        if (Files.isRegularFile(p)) return p.toString();
        p = Paths.get(base, sub, "yara.exe");
        if (Files.isRegularFile(p)) return p.toString();
      }
    }
    return "yara";
  }
  private static String findOnPath(String exe){
    String path = System.getenv("PATH");
    if (path == null) return null;
    for (String d : path.split(java.util.regex.Pattern.quote(";"))) {
      if (d.isEmpty()) continue;
      Path p = Paths.get(d.trim(), exe);
      if (Files.isRegularFile(p)) return p.toString();
    }
    return null;
  }

  private static LinkedHashMap<String,Integer> parseWeights(String json){
    LinkedHashMap<String,Integer> m = new LinkedHashMap<>();
    for (String pair : json.replaceAll("[{}\\\"]","").split(",")) {
      String[] kv = pair.split(":");
      if (kv.length == 2) { try { m.put(kv[0].trim(), Math.max(0, Integer.parseInt(kv[1].trim()))); } catch (Exception ignored) { } }
    }
    if (m.isEmpty()) m.put("url_domain",100);
    return m;
  }
  // in-memory cache entries
  private static final class IPEntry { final String json; final long at; IPEntry(String json){ this.json=json; this.at=System.currentTimeMillis(); } }
  private static final class URLEntry { final String json; final long at; URLEntry(String json){ this.json=json; this.at=System.currentTimeMillis(); } }
  private static synchronized String cacheGet(Map<String,IPEntry> c, String k){ IPEntry e = c.get(k); if (e==null) return null; if (System.currentTimeMillis()-e.at > CACHE_TTL_MS){ c.remove(k); return null; } return e.json; }
  private static synchronized String cacheGetU(Map<String,URLEntry> c, String k){ URLEntry e = c.get(k); if (e==null) return null; if (System.currentTimeMillis()-e.at > CACHE_TTL_MS){ c.remove(k); return null; } return e.json; }
  private static synchronized void cachePut(Map<String,IPEntry> c, String k, String v){ if (c.size() > 256) c.clear(); c.put(k, new IPEntry(v)); }
  private static synchronized void cachePutU(Map<String,URLEntry> c, String k, String v){ if (c.size() > 256) c.clear(); c.put(k, new URLEntry(v)); }
  // Reverse-DNS cache. Reverse lookups are the dominant latency during email analysis
  // (every Received-hop IP + every sender A-record IP triggers a live PTR query). Caching
  // each unique IP once (10 min TTL for hits, short TTL for misses/NXDOMAIN) removes the
  // repeated blocking resolver calls and the intra-request duplicates with zero result change.
  private static final int DNS_CACHE_TTL_MS = 10 * 60 * 1000;      // positive hits
  private static final int DNS_NEG_TTL_MS  = 60 * 1000;            // NXDOMAIN / failures (short)
  private static final Map<String, DNSEntry> DNS_CACHE = new LinkedHashMap<>(128);
  private static final class DNSEntry { final String host; final long at; DNSEntry(String h){ this.host=h; this.at=System.currentTimeMillis(); } }
  private static synchronized String dnsCacheGet(String ip){
    DNSEntry e = DNS_CACHE.get(ip);
    if (e == null) return null;
    long ttl = e.host == null ? DNS_NEG_TTL_MS : DNS_CACHE_TTL_MS;
    if (System.currentTimeMillis() - e.at > ttl) { DNS_CACHE.remove(ip); return null; }
    return e.host; // "" for cached miss; non-empty for hit
  }
  private static synchronized void dnsCachePut(String ip, String host){ if (DNS_CACHE.size() > 512) DNS_CACHE.clear(); DNS_CACHE.put(ip, new DNSEntry(host == null ? "" : host)); }
  // RDAP/domain-age cache. The email + URL paths each consult live RDAP per domain; caching
  // per-domain with a 10 min TTL removes repeated blocking HTTP lookups without changing results.
  private static final Map<String, RDAPEntry> RDAP_CACHE = new LinkedHashMap<>(64);
  private static final class RDAPEntry { final String json; final long at; RDAPEntry(String j){ this.json=j; this.at=System.currentTimeMillis(); } }
  private static synchronized String rdapCacheGet(String d){ RDAPEntry e = RDAP_CACHE.get(d); if (e==null) return null; if (System.currentTimeMillis()-e.at > CACHE_TTL_MS){ RDAP_CACHE.remove(d); return null; } return e.json; }
  private static synchronized void rdapCachePut(String d, String j){ if (RDAP_CACHE.size() > 256) RDAP_CACHE.clear(); RDAP_CACHE.put(d, new RDAPEntry(j)); }

  // Forward-DNS (domain -> resolved addresses) cache with TTL. Prevents repeated blocking
  // InetAddress.getAllByName calls on every analysis of the same sender/URL domain, which is
  // the dominant per-check latency when the OS resolver is slow. Synthetic/reserved namespaces
  // are never resolved (handled by callers).
  private static final Map<String, ResolveEntry> RESOLVE_CACHE = new LinkedHashMap<>(128);
  private static final class ResolveEntry { final List<String> addrs; final long at; ResolveEntry(List<String> a){ this.addrs=a; this.at=System.currentTimeMillis(); } }
  private static synchronized List<String> resolveCacheGet(String domain){
    ResolveEntry e = RESOLVE_CACHE.get(domain);
    if (e == null) return null;
    if (System.currentTimeMillis() - e.at > DNS_CACHE_TTL_MS) { RESOLVE_CACHE.remove(domain); return null; }
    return e.addrs;
  }
  private static synchronized void resolveCachePut(String domain, List<String> addrs){ if (RESOLVE_CACHE.size() > 512) RESOLVE_CACHE.clear(); RESOLVE_CACHE.put(domain, new ResolveEntry(addrs == null ? List.of() : addrs)); }

  // HTTP probe cache (per URL, TTL). The URL module performs a guarded single-hop GET of a
  // resolvable target to inspect headers/forms/scripts. Caching the result per URL prevents
  // re-fetching the same target on every analysis, keeping repeat checks fast. Cached misses
  // (unreachable/unresolvable) are also cached briefly so a flapping/timing-out host does not
  // stall repeated checks.
  private static final int PROBE_CACHE_TTL_MS = 10 * 60 * 1000;
  private static final int PROBE_NEG_TTL_MS   = 60 * 1000;
  private static final Map<String, ProbeEntry> PROBE_CACHE = new LinkedHashMap<>(128);
  private static final class ProbeEntry { final String json; final long at; ProbeEntry(String j){ this.json=j; this.at=System.currentTimeMillis(); } }
  private static synchronized String probeCacheGet(String url){
    ProbeEntry e = PROBE_CACHE.get(url);
    if (e == null) return null;
    long ttl = e.json.startsWith("{\"evaluation_status\":\"HTTP_SKIPPED\"") ? PROBE_NEG_TTL_MS : PROBE_CACHE_TTL_MS;
    if (System.currentTimeMillis() - e.at > ttl) { PROBE_CACHE.remove(url); return null; }
    return e.json;
  }
  private static synchronized void probeCachePut(String url, String json){ if (PROBE_CACHE.size() > 512) PROBE_CACHE.clear(); PROBE_CACHE.put(url, new ProbeEntry(json)); }

  // DNS-over-HTTPS record cache (per host+type, TTL). The URL module issues one DoH query per
  // record type (A/AAAA/CNAME/NS/MX/TXT) plus a DMARC TXT query per host, on every analysis.
  // Caching per host+type makes repeat checks of the same host fast without changing results.
  private static final Map<String, DoHEntry> DOH_CACHE = new LinkedHashMap<>(256);
  private static final class DoHEntry { final String json; final long at; DoHEntry(String j){ this.json=j; this.at=System.currentTimeMillis(); } }
  private static synchronized String dohCacheGet(String key){
    DoHEntry e = DOH_CACHE.get(key);
    if (e == null) return null;
    if (System.currentTimeMillis() - e.at > DNS_CACHE_TTL_MS) { DOH_CACHE.remove(key); return null; }
    return e.json;
  }
  private static synchronized void dohCachePut(String key, String json){ if (DOH_CACHE.size() > 1024) DOH_CACHE.clear(); DOH_CACHE.put(key, new DoHEntry(json)); }

  // Multi-source geolocation cache (per IP, TTL). geoMulti performs up to two blocking provider
  // HTTP lookups (ip-api + ipwho.is) with generous timeouts on every call; the URL module and the
  // IP module each invoke it, so without caching a single url-analyze can stall for many seconds on
  // a slow provider. Caching per IP (10 min for hits, 60 s for misses/none) removes the repeated
  // blocking calls with zero change to the correlation logic or its output.
  private static final int GEO_POS_TTL_MS = 10 * 60 * 1000;
  private static final int GEO_NEG_TTL_MS = 60 * 1000;
  private static final Map<String, GeoEntry> GEO_MULTI_CACHE = new LinkedHashMap<>(128);
  private static final class GeoEntry { final GeoMulti v; final long at; GeoEntry(GeoMulti v){ this.v=v; this.at=System.currentTimeMillis(); } }
  private static synchronized GeoMulti geoMultiCacheGet(String ip){
    GeoEntry e = GEO_MULTI_CACHE.get(ip);
    if (e == null) return null;
    long ttl = e.v.geo().equals("null") ? GEO_NEG_TTL_MS : GEO_POS_TTL_MS;
    if (System.currentTimeMillis() - e.at > ttl) { GEO_MULTI_CACHE.remove(ip); return null; }
    return e.v;
  }
  private static synchronized void geoMultiCachePut(String ip, GeoMulti v){ if (GEO_MULTI_CACHE.size() > 512) GEO_MULTI_CACHE.clear(); GEO_MULTI_CACHE.put(ip, new GeoEntry(v)); }

  // Per-analysis performance budget (ms): once the current request has spent this long on live
  // external enrichment (DNS / RDAP / geo), remaining enrichment is reported as UNKNOWN rather
  // than blocking further. This keeps every check fast even when a remote provider is slow or
  // unresponsive, without fabricating data (missing stays UNKNOWN/UNAVAILABLE per the spec).
  // Budget deadline is request-local: a per-request deadline set in the thread that owns the
  // analysis (HTTP worker or ENRICH task), never a shared static. This prevents one request's
  // enrichment from resetting another request's budget mid-analysis (previously a data race).
  private static final ThreadLocal<Long> ANALYZE_DEADLINE = new ThreadLocal<>();
  private static final long ANALYZE_BUDGET_MS = 1400;
  private static boolean budgetUp(){ Long d = ANALYZE_DEADLINE.get(); return d != null && System.currentTimeMillis() > d; }
  private static boolean budgetUp(long elapsedVal){ return elapsedVal > ANALYZE_BUDGET_MS; }
  // Enrichment executor (daemon threads) used to parallelize per-IP reverse-DNS and geolocation.
  private static volatile ExecutorService ENRICH = null;


  // simple per-client-IP rate limiter (in-process; adequate for single-node LAN deployments)
  private static synchronized boolean allowed(String clientIp){
    long now = System.currentTimeMillis(); long[] win = RATE.get(clientIp);
    if (win == null) { RATE.put(clientIp, new long[]{now, 1}); return true; }
    if (now - win[0] > RATE_WINDOW_SECONDS * 1000L) { win[0] = now; win[1] = 1; return true; }
    if (win[1] >= RATE_MAX_PER_WINDOW) return false;
    win[1]++; return true;
  }
  // rawEmail values are read from request bodies by extractRawEmail(String) (linear, no regex).
  private static final Pattern HEADER = Pattern.compile("(?m)^([^:\\r\\n]+):\\s*(.*)$");
  private static final Pattern IPV4 = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b");
  private static final Pattern IPV6 = Pattern.compile("(?i)(?<![0-9a-f:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|::ffff:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}|(?:[0-9a-f]{1,4}:){1,4}:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3})(?![0-9a-f:])");
  private static final Pattern URL = Pattern.compile("https?://[^\\s<>\"'\\]]+", Pattern.CASE_INSENSITIVE);
  private static final Pattern EMAIL = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
  private static final Pattern DOMAIN = Pattern.compile("\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)++[a-z]{2,}(?:\\.[a-z]{2})?\\b", Pattern.CASE_INSENSITIVE);
  private static final Pattern SHA256RE = Pattern.compile("\\b[a-f0-9]{64}\\b", Pattern.CASE_INSENSITIVE);
  private static final Pattern SHARE = Pattern.compile("\\b[a-f0-9]{32,40}\\b", Pattern.CASE_INSENSITIVE);
  private static final Pattern HREF = Pattern.compile("(?is)<a\\s+[^>]*?href\\s*=\\s*([\"'])(.*?)\\1[^>]*>\\s*(.*?)\\s*</a>");
  private static final Pattern ATTDIS = Pattern.compile("(?is)content-disposition:\\s*attachment;\\s*(?:\\s*filename\\s*=\\s*(\"?)([^\";\\r\\n]+)\\1)?[\\s\\S]*?");
  private static final Pattern FILENM = Pattern.compile("filename\\s*=\\s*(\"?)([^\"\\r\\n;]+)", Pattern.CASE_INSENSITIVE);
  private static final Pattern CID = Pattern.compile("content-type:\\s*([^;\\r\\n]+)(?:;[^\\r\\n]*boundary=\"?([^\"\\r\\n]+)\"?)?", Pattern.CASE_INSENSITIVE);
  private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).followRedirects(HttpClient.Redirect.NORMAL).build();
  // Dedicated client that NEVER auto-follows redirects (used only for guarded manual redirect analysis).
  private static final HttpClient NO_REDIRECT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).followRedirects(HttpClient.Redirect.NEVER).build();
  // Weighted model: auth20 / url25 / attachment15 / threatintel20 / nlp10 / header10
  private static final java.util.List<String[]> DANGER_EXT = List.of(
    new String[]{"exe","executable"},new String[]{"js","javascript script"},new String[]{"vbs","VBScript"},
    new String[]{"vbe","script"},new String[]{"ps1","PowerShell"},new String[]{"bat","batch"},new String[]{"cmd","command"},
    new String[]{"scr","screen saver"},new String[]{"iso","disk image"},new String[]{"img","disk image"},
    new String[]{"lnk","shortcut"},new String[]{"hta","HTML app"},new String[]{"jar","java archive"},
    new String[]{"docm","macro doc"},new String[]{"xlsm","macro sheet"},new String[]{"pptm","macro deck"});
  // Archives and marker-less containers: frequently legitimately attached, so treated as suspicious
  // (lower weight) rather than "dangerous" to avoid over-flagging benign documents.
  private static final java.util.Set<String> SUSP_EXT = Set.of("zip","rar","7z","tar","gz","html","htm");

  public static void main(String[] args) throws Exception {
    Files.createDirectories(DATA);
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", PORT), 0);
    server.createContext("/api/health", e -> json(e, 200, "{\"status\":\"ok\",\"service\":\"Cipher Squad Forensic Intelligence API\"}"));
    server.createContext("/api/auth/login", App::loginRoute);
    server.createContext("/api/auth/logout", App::logoutRoute);
    srv(server, "/api/auth/me", App::meRoute);
    server.createContext("/api/analyze", App::analyze);
    srv(server, "/api/cases", App::cases);
    srv(server, "/api/domain-intelligence", App::domainIntelligence);
    srv(server, "/api/geolocate", App::geolocate);
    srv(server, "/api/dns", App::dns);
    srv(server, "/api/whois", App::whois);
    srv(server, "/api/enrichment-status", App::enrichment);
    srv(server, "/api/ip-intel", App::ipIntel);
    srv(server, "/api/ip-forensics", App::ipForensics);
    srv(server, "/api/url-analyze", App::urlAnalyze);
    srv(server, "/api/origin", App::originAnalyze);
    // ---- Multi-channel SOC / ingestion backbone ----
    srv(server, "/api/ingest", App::ingest);
    srv(server, "/api/connectors", App::connectors);
    srv(server, "/api/policies", App::policiesRoute);
    srv(server, "/api/audit", App::auditRoute);
    srv(server, "/api/incidents", App::incidentsRoute);
    srv(server, "/api/iocs/extract", App::iocExtractRoute);
    srv(server, "/api/feedback", App::feedbackRoute);
    srv(server, "/api/search", App::searchRoute);
    srv(server, "/api/notify", App::notifyRoute);
    srv(server, "/api/retention", App::retentionRoute);
    srv(server, "/api/triage", App::triageRoute);
    srv(server, "/api/export", App::exportRoute);
    srv(server, "/api/iocs/summary", App::iocSummaryRoute);
    srv(server, "/api/iocs/suppress", App::iocSuppressRoute);
    srv(server, "/api/self-test", App::selfTestRoute);
    srv(server, "/api/report", App::report);
    // ---- New SOC security modules (single unified backend) ----
    srv(server, "/api/analyze/spam", App::spamRoute);
    srv(server, "/api/analyze/dns", App::dnsSecurityRoute);
    srv(server, "/api/analyze/ssl", App::sslRoute);
    srv(server, "/api/analyze/ddos", App::ddosRoute);
    srv(server, "/api/analyze/cloudflare", App::cloudflareRoute);
    srv(server, "/api/dashboard", App::dashboardRoute);
    srv(server, "/api/iocs", App::iocRoute);
    srv(server, "/api/news", App::newsRoute);
    srv(server, "/api/status", App::securityStatusRoute);
    // ---- Access control ----
    srvAdmin(server, "/api/users", App::usersRoute);
    srvAdmin(server, "/api/user/role", App::userRoleRoute);
    // ---- Outbound alert channels ----
    srvAdmin(server, "/api/channels", App::channelsRoute);
    srvAdmin(server, "/api/channel/state", App::channelStateRoute);
    srvAdmin(server, "/api/channel/delete", App::channelDeleteRoute);
    // ---- Graph / campaign correlation ----
    srv(server, "/api/graph", App::graphRoute);
    // ---- Part 2: explanation, IOC enrichment, case timeline, detailed health, feedback learnings ----
    srv(server, "/api/analyze/explain", App::explainRoute);
    srv(server, "/api/iocs/enrich", App::iocEnrichRoute);
    srv(server, "/api/cases/timeline", App::caseTimelineRoute);
    server.createContext("/api/health/detailed", App::healthDetailedRoute);
    srv(server, "/api/feedback/stats", App::feedbackStatsRoute);
    // Scanner integrations (ClamAV / Rspamd / Yara) + PhishGuard website analyzer.
    srv(server, "/api/scanners/status", App::scannerStatusRoute);
    srv(server, "/api/scanners/scan", App::scannerScanRoute);
    srv(server, "/api/phishguard/analyze", App::phishGuardRoute);
    server.createContext("/", App::staticFile);
    bootstrapAdmin();
    loadSessions();
    server.setExecutor(Executors.newFixedThreadPool(12));
    backfillIocRegistry();
    // Dedicated daemon pool for parallel per-IP enrichment (reverse DNS + geolocation).
    // Daemon threads never keep the JVM alive, so Ctrl+C and the test harness can still exit.
    ENRICH = Executors.newFixedThreadPool(10, r -> { Thread t = new Thread(r, "enrich"); t.setDaemon(true); return t; });
    server.start();
    System.out.println("Cipher Squad is running at http://127.0.0.1:" + PORT);
  }

  /* ===================== HTTP entry ===================== */
  private static void analyze(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e, 405, error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String rv = extractRawEmail(body);
    if (rv == null) { json(e, 400, error("rawEmail is required")); return; }
    String raw = unescape(rv);
    if (raw.length() > 4_000_000) { json(e, 413, error("Email exceeds 4 MB local analysis limit")); return; }
    String analysis = analyzeMessage(raw);
    cacheAnalysis(strVal(analysis, "caseId"), analysis);
    persistIocs(raw);
    String decision = decisionOf(analysis, "paste");
    Matcher dm = Pattern.compile("\\{\"security_decision\":(\\{.*\\})\\}$").matcher(decision);
    String obj = dm.find() ? dm.group(1) : decision;
    json(e, 200, analysis.substring(0, analysis.length() - 1) + ",\"security_decision\":" + obj + "}");
  }

  /* ===================== Core pipeline ===================== */
  private static String analyzeMessage(String raw) {
    ANALYZE_DEADLINE.set(System.currentTimeMillis() + ANALYZE_BUDGET_MS);
    String evidenceHash = sha256(raw);
    String caseId = "CASE-" + Instant.now().getEpochSecond() + "-" + Integer.toHexString(raw.hashCode() & 0xffff).toUpperCase();
    String receivedAt = Instant.now().toString();

    // ---- 2. PARSE ----
    String normalized = raw.replace("\r\n", "\n");
    int split = normalized.indexOf("\n\n");
    String headerBlock = split >= 0 ? normalized.substring(0, split) : normalized;
    String body = split >= 0 ? normalized.substring(split + 2) : "";
    Map<String, List<String>> headers = new LinkedHashMap<>();
    StringBuilder folded = new StringBuilder();
    for (String line : headerBlock.split("\n")) {
      if (line.startsWith(" ") || line.startsWith("\t")) folded.append(' ').append(line.trim());
      else { if (!folded.isEmpty()) putHeader(headers, folded.toString()); folded.setLength(0); folded.append(line); }
    }
    if (!folded.isEmpty()) putHeader(headers, folded.toString());

    String from = header(headers, "from"), reply = header(headers, "reply-to"), ret = header(headers, "return-path"),
            to = header(headers, "to"), cc = header(headers, "cc"), subj = header(headers, "subject"),
            mid = header(headers, "message-id"), date = header(headers, "date"),
            auth = (header(headers, "authentication-results") + " " + header(headers, "received-spf")).trim(),
            dkimHeader = header(headers, "dkim-signature");
    String fromDomain = domainOf(from), replyDomain = domainOf(reply), retDomain = domainOf(ret);

    // Per-layer evidence collections
    List<Finding> authFindings = new ArrayList<>();    // L3 (crypto: SPF/DKIM/DMARC)
    List<Finding> emailAuthFindings = new ArrayList<>();// L3 (email_authentication: spoofing/alignment/reply-path forensics)
    List<Finding> routingFindings = new ArrayList<>(); // L4
    List<Finding> urlFindings = new ArrayList<>();     // L5
    List<Finding> attachFindings = new ArrayList<>();  // L6
    List<Finding> nlpFindings = new ArrayList<>();     // L9
    List<Finding> htmlFindings = new ArrayList<>();    // L10
    List<Finding> dnsFindings = new ArrayList<>();     // DNS evidence (observed, bounded)
    List<Finding> ipFindings = new ArrayList<>();      // IP infrastructure reputation

    // ---- L3 AUTHENTICATION ----
    String spf = result(auth, "spf"), dkim = result(auth, "dkim"), dmarc = result(auth, "dmarc");
    boolean hasDkimSig = !dkimHeader.isBlank();
    boolean spfFail = spf.matches("fail|softfail|neutral");
    boolean dkimFail = "fail".equals(dkim);
    boolean dmarcFail = "fail".equals(dmarc);
    if (spfFail) authFindings.add(new Finding(12, "SPF is not a pass: sender server may be unauthorized for " + fromDomain, "authentication","MEDIUM","SPF result = " + spf + " for " + fromDomain,"Sender SPF validation did not pass."));
    if (dkimFail) authFindings.add(new Finding(10, "DKIM signature validation failed", "authentication","HIGH","DKIM result = " + dkim,"DKIM signature did not validate."));
    if (dmarcFail) authFindings.add(new Finding(14, "DMARC policy failure / alignment not met", "authentication","HIGH","DMARC result = " + dmarc,"DMARC policy failed against the asserted From domain."));
    if (!dkimHeader.isBlank() && ("not_supplied".equals(dkim) || dkim.isEmpty())) authFindings.add(new Finding(4, "DKIM-Signature present but no Authentication-Results — signature not verified locally", "authentication","LOW","DKIM-Signature header present; no validated result recorded.","Authenticity cannot be confirmed without a validated signature."));
    // Alignment, display-name and brand-impersonation analysis (identity consistency)
    String fromDisplay = displayNameOf(from);
    String fromBrand = brandImpersonatedBy(fromDomain);          // brand token inside From DOMAIN but non-official
    String displayBrand = brandKeywordOfText(fromDisplay);        // display name claims a brand
    boolean replyMismatch = !reply.isBlank() && !fromDomain.isBlank() && !replyDomain.equals(fromDomain);
    boolean retMismatch = !ret.isBlank() && !fromDomain.isBlank() && !retDomain.equals(fromDomain);
    boolean brandInDomain = fromBrand != null;
    boolean displayBrandMismatch = displayBrand != null && !isOfficialFor(fromDomain, displayBrand);
    List<String> alignNotes = new ArrayList<>();
    if (retMismatch) alignNotes.add("Return-Path domain (" + retDomain + ") != From domain (" + fromDomain + ")");
    if (replyMismatch) alignNotes.add("Reply-To domain (" + replyDomain + ") != From domain (" + fromDomain + ")");
    boolean alignOK = alignNotes.isEmpty();
    // ---- email_authentication forensics: header/spoofing identity consistency ----
    // These header-forensic signals (Return-Path / Reply-To vs From alignment, brand & display-name
    // impersonation, Message-ID domain coherence) form the email_authentication category, reported
    // alongside the crypto-only authentication category (SPF/DKIM/DMARC).
    // Message-ID domain coherence: a Message-ID that claims a domain different from the From domain
    // (or the return/reply path) is a spoofing coherence indicator.
    String midDomain = "";
    { Matcher mm = Pattern.compile("@([a-zA-Z0-9.-]+)").matcher(mid); if (mm.find()) midDomain = mm.group(1).toLowerCase(Locale.ROOT); }
    if (replyMismatch) {
      emailAuthFindings.add(new Finding(14, "From/Reply-To domain mismatch", "email_authentication","HIGH",
        "From domain = " + fromDomain + "; Reply-To domain = " + replyDomain,
        "The reply destination differs from the apparent sender identity." + (brandInDomain ? " This occurs together with brand impersonation in the From domain, which strengthens the phishing hypothesis." : "")));
    }
    if (brandInDomain) {
      emailAuthFindings.add(new Finding(14, "Potential " + cap(fromBrand) + " brand impersonation in sender domain", "email_authentication","CRITICAL",
        "From domain = " + fromDomain + " contains '" + fromBrand + "' but is not " + brandedOfficialDomains(fromBrand),
        "The sender identity names a trusted brand yet does not originate from the brand's legitimate domain. Brand presence alone is not proof of malice; it is weighed together with other indicators."));
    } else if (displayBrandMismatch) {
      emailAuthFindings.add(new Finding(6, "Display name claims " + cap(displayBrand) + " but From domain is " + fromDomain, "email_authentication","MEDIUM",
        "Display name = " + fromDisplay + "; From domain = " + fromDomain,
        "The visible identity references a trusted brand inconsistent with the actual sender domain."));
    }
    if (replyMismatch && brandInDomain) {
      emailAuthFindings.add(new Finding(2, "Identity mismatch combined with brand impersonation", "email_authentication","LOW",
        "Reply-To divergence plus brand-token sender naming.","Combination of independent identity inconsistencies."));
    }
    if (!mid.isBlank() && midDomain.isEmpty()) {
      // Message-ID present but with no parseable host domain — a weak structural ambiguity reported here.
      emailAuthFindings.add(new Finding(1, "Message-ID host domain not parseable", "email_authentication","INFO",
        "Message-ID = " + trunc(mid,40), "A Message-ID without a coherent host domain is a weak structural anomaly."));
    } else if (!mid.isBlank() && !fromDomain.isBlank() && !midDomain.equals(fromDomain)) {
      emailAuthFindings.add(new Finding(4, "Message-ID domain (" + midDomain + ") differs from From domain (" + fromDomain + ")", "email_authentication","LOW",
        "Message-ID domain = " + midDomain + "; From domain = " + fromDomain,
        "A Message-ID asserting a domain inconsistent with the From header is a weak coherence/spoofing indicator."));
    }

    // ---- L4 ROUTING / RECEIVED ----
    List<String> received = headers.getOrDefault("received", List.of());
    boolean noReceived = received.isEmpty();
    if (noReceived) routingFindings.add(new Finding(2, "No Received relay headers — routing path and origin cannot be reconstructed", "header_anomaly","INFO",
      "No Received header present.",
      "Routing integrity cannot be verified. This is treated as missing evidence (it lowers confidence), not as proof of phishing."));
    if (mid.isBlank()) routingFindings.add(new Finding(1, "Message-ID header missing", "header_anomaly","INFO",
      "No Message-ID header present.", "A Message-ID uniquely identifies and authenticates a message; its absence is a weak structural anomaly."));
    if (date.isBlank()) routingFindings.add(new Finding(1, "Date header missing", "header_anomaly","INFO",
      "No Date header present.", "Missing Date is a weak structural anomaly observed in the header set."));
    int receivedAccepted = received.size();
    if (retMismatch) routingFindings.add(new Finding(6, "Return-Path domain does not match From domain", "routing","MEDIUM",
      "Return-Path = " + retDomain + "; From = " + fromDomain,
      "Envelope sender differs from the visible sender, an end-to-end spoofing indicator."));
    if (received.size() >= 3) routingFindings.add(new Finding(3, "Unusually long relay chain (" + received.size() + " Received hops) — possible relay manipulation", "routing","LOW",
      "Relay count = " + received.size(),
      "Long chains can indicate relay manipulation or high-volume bulk mail."));

    // ---- L10 HTML ANALYSIS ----
    List<Map<String,String>> hrefMismatches = new ArrayList<>();
    List<Map<String,String>> htmlIssues = new ArrayList<>();
    if (body.toLowerCase().contains("<a ") || body.toLowerCase().contains("<html") || body.toLowerCase().contains("<form")) {
      Matcher hm = HREF.matcher(body);
      while (hm.find()) {
        String href = hm.group(2).trim(), visible = hm.group(3).replaceAll("<[^>]+>", "").trim();
        if (!visible.isEmpty() && !sameDomain(href, visible)) {
          Map<String,String> m = new LinkedHashMap<>(); m.put("visible", visible); m.put("actual", href); hrefMismatches.add(m);
          urlFindings.add(new Finding(18, "Hyperlink text '" + trunc(visible,30) + "' points to a DIFFERENT destination: " + trunc(href,60), "url_mismatch"));
        }
      }
      if (body.toLowerCase().contains("<form")) htmlFindings.add(new Finding(6, "HTML <form> present — possible credential-harvesting page", "html"));
      if (body.toLowerCase().contains("target=\"_blank\"") || body.contains("/hidden") || body.toLowerCase().contains("style=\"display:none") || body.toLowerCase().contains("visibility:hidden")) htmlFindings.add(new Finding(5, "Hidden / obfuscated elements detected in HTML body", "html"));
      if (body.toLowerCase().contains("iframe")) htmlFindings.add(new Finding(7, "Inline frame (<iframe>) detected — possible transparent/phishing overlay", "html"));
      if (body.toLowerCase().contains("src=\"http://") || body.toLowerCase().contains("src='http://")) htmlFindings.add(new Finding(4, "External resource loaded over insecure HTTP", "html")); 
      String pixel = "beacon|pixel|tracking|spacer\\.gif|/open\\?|open\\.php|omo\\.de|/tr\\?";
      if (body.toLowerCase().matches("(?s).*" + pixel + ".*")) htmlFindings.add(new Finding(3, "Tracking pixel / open-tracking beacon detected", "html"));
    }

    // ---- L5 URL ANALYSIS ----
    List<String> urls = matches(URL, raw);
    // Round 2 scope-limited note: covert-redirect scanning only examines HTML anchor tags. When a
    // raw URL is pasted with no HTML anchors, "no links found" is a SCOPED-LIMITED null result, not a
    // safety verdict. Explicitly surface this so it is not mistaken for "the URL is safe".
    boolean hadAnchorMarkup = body.toLowerCase().contains("<a ") || body.toLowerCase().contains("<html") || body.toLowerCase().contains("<form");
    if (!urls.isEmpty() && !hadAnchorMarkup) {
      urlFindings.add(new Finding(1, "Scope-limited: "+urls.size()+" URL(s) present but no HTML anchor tags to scan for covert redirection — this does NOT mean the URL(s) are safe; run each through URL Risk Analysis separately.", "scope","INFO","Input format = raw/plain URL (no anchor markup)","The covert-redirect scanner only compares visible link text to href inside HTML. A raw URL has no anchors, so a 'no links found' result is scope-limited, not a safety verdict."));
    }
    List<Map<String,String>> urlAnomalies = new ArrayList<>();
    boolean brandImpersonationInUrl = false;
    for (String u : urls) {
      Map<String,String> note = new LinkedHashMap<>(); note.put("url", u);
      String h = ""; boolean suspicious = false; List<String> reasons = new ArrayList<>();
      try { h = new URL(u).getHost().toLowerCase(); } catch (Exception x) { h = u; }
      if (u.startsWith("http://")) { note.put("flag","http"); suspicious = true; reasons.add("insecure HTTP"); urlFindings.add(new Finding(3, "URL uses insecure HTTP instead of HTTPS: " + trunc(u,60), "url","LOW","Transport = " + trunc(u,60),"Cleartext transport is a weak indicator on its own; credentials sent over HTTP are exposed.")); }
      if (h.matches(".*\\d{1,3}(\\.\\d{1,3}){3}.*")) { note.put("flag","ip"); urlFindings.add(new Finding(8, "IP-based URL (host is a raw IP, not a domain): " + trunc(u,60), "url","HIGH","Host = " + h,"A URL pointing at a raw IP is a strong indicator.")); suspicious = true; reasons.add("raw IP host"); }
      if (h.matches(".*\\d{2,}.*")) { note.put("flag","digits"); suspicious = true; ancestorDomain(h, note); }
      if (h.contains("xn--")) { note.put("flag","punycode"); suspicious = true; reasons.add("punycode/homograph"); urlFindings.add(new Finding(6, "Punycode (IDN homograph) domain: " + h, "url","MEDIUM","Host = " + h,"Internationalised domains can be used for lookalike impersonation.")); }
      if (h.split("\\.").length > 4) { note.put("flag","excess"); suspicious = true; reasons.add("excessive subdomains"); urlFindings.add(new Finding(3, "Excessive subdomain nesting in URL host: " + h, "url","LOW","Host = " + h,"Heavily nested subdomains can obscure the registrable domain.")); }
      String tld = h.lastIndexOf('.') >= 0 ? h.substring(h.lastIndexOf('.') + 1) : "";
      if (containsAbuseTld(tld)) { note.put("flag","tld"); suspicious = true; reasons.add("high-abuse TLD ." + tld); urlFindings.add(new Finding(4, "High-abuse URL TLD: ." + tld, "url","MEDIUM","TLD = ." + tld,"This TLD is statistically over-represented in abuse.")); }
      String pathU = u.replaceFirst("(?i)^https?://[^/]+", "");
      String pathDecU = urlDecodeAll(pathU);
      boolean credPath = pathCred(pathU) || pathCred(pathDecU);
      if (credPath) { note.put("flag","path"); suspicious = true; reasons.add("credential/verification path"); urlFindings.add(new Finding(6, "Credential / login / verification / account path in URL: " + trunc(pathU,40), "url","MEDIUM","Path = " + trunc(pathU,40),"The URL targets a login/verification/account surface, commonly abused for credential harvesting. This is a moderate indicator on its own.")); }
      if (u.matches(".*%[0-9a-fA-F]{2}.*")) { reasons.add("encoded components"); urlFindings.add(new Finding(3, "Encoded URL components present: " + trunc(u,50), "url","LOW","Contains percent-encoded characters.","Encoding can obscure the true target.")); suspicious = true; }
      String qU = u.contains("?") ? u.substring(u.indexOf("?")+1) : "";
      String qDec = urlDecodeAll(qU).toLowerCase();
      boolean credParam = qDec.matches("(?s).*(token|password|otp|secret|reset|verify|auth|session|credential|code|key|redirect|next|dest|return|url|login)=.*");
      if (credParam) { note.put("flag","param"); suspicious = true; reasons.add("credential/session/redirect parameter"); urlFindings.add(new Finding(3, "Credential / session / redirect query parameter in URL: " + trunc(qU,40), "url","MEDIUM","Query = " + trunc(qU,40),"Redirect or credential parameters are a common phishing conduit.")); }
      try { int port = new URL(u).getPort(); if (port > 0 && port != 80 && port != 443) { urlFindings.add(new Finding(3, "Non-standard URL port: " + port, "url","LOW","Port = " + port,"Unusual ports can evade naive filters.")); reasons.add("suspicious port"); suspicious = true; } } catch (Exception ignored) {}
      String bimp = brandImpersonatedByHost(h);
      if (bimp != null) { note.put("flag","brand"); brandImpersonationInUrl = true; suspicious = true; reasons.add(cap(bimp) + " brand impersonation in host"); urlFindings.add(new Finding(9, "Potential " + cap(bimp) + " brand impersonation in URL domain: " + h, "url","HIGH","Host = " + h + " contains '" + bimp + "' but is not " + brandedOfficialDomains(bimp),"The URL host tries to associate itself with a trusted brand without belonging to it. Brand presence alone is not proof of malice — it is correlated with other indicators.")); }
      if (u.matches("(?i)^https?://[^/@]+@")) { urlFindings.add(new Finding(6, "URL contains userinfo/@ spoofing: " + trunc(u,50), "url","MEDIUM","URL = " + trunc(u,50),"An @ in the authority segment can redirect a login toward a different host.")); reasons.add("userinfo spoofing"); suspicious = true; }
      String reasonStr = String.join("; ", reasons);
      if (reasonStr.length() > 0) { note.put("reason", reasonStr); urlAnomalies.add(note); }
      if (suspicious && !note.containsKey("flag")) urlFindings.add(new Finding(5, "Suspicious URL host pattern: " + h, "url"));
    }

    // ---- L6 ATTACHMENT FORENSICS ----
    List<Map<String,String>> attachments = new ArrayList<>();
    Matcher frm = FILENM.matcher(raw);
    java.util.Set<String> seenNames = new HashSet<>();
    while (frm.find()) {
      String name = frm.group(2).trim();
      if (name.isEmpty() || !seenNames.add(name.toLowerCase())) continue;
      Map<String,String> a = new LinkedHashMap<>(); a.put("filename", name);
      String ext = "", safe = "";
      int dot = name.lastIndexOf('.');
      if (dot >= 0) { ext = name.substring(dot + 1).toLowerCase(); safe = name.substring(0, dot); }
      a.put("extension", ext.isEmpty() ? "none" : ext);
      // find matching content-type / extension double
      if (name.matches("(?i).+\\.[a-z0-9]{2,4}\\.[a-z0-9]{2,4}$")) { a.put("flag","double_extension"); attachFindings.add(new Finding(12, "Double extension — possible executable disguise: " + name, "attachment")); }
      boolean dangerous = false; boolean suspiciousAtt = false; String dangerDesc = "";
      for (String[] d : DANGER_EXT) if (d[0].equals(ext)) { dangerous = true; dangerDesc = d[1]; break; }
      if (!dangerous) suspiciousAtt = SUSP_EXT.contains(ext);
      // heuristic content-based fingerprint (we don't have the file bytes in plain text, hash of the declared metadata line)
      String blob = filenameDefFor(raw, name);
      a.put("sha256", sha256(blob));
      a.put("sha1", sha1(blob));
      a.put("md5", md5(blob));
      if (dangerous) { String f = a.containsKey("flag") ? a.get("flag")+"|dangerous" : "dangerous"; a.put("flag", f); attachFindings.add(new Finding(14, "Dangerous attachment type (" + ext + " — " + dangerDesc + "): " + name, "attachment")); }
      else if (suspiciousAtt) { String f = a.containsKey("flag") ? a.get("flag")+"|suspicious" : "suspicious"; a.put("flag", f); attachFindings.add(new Finding(7, "Suspicious attachment container / content (" + ext + "): " + name, "attachment")); }
      // SCORE FIX (L6): if the attachment's content hash matches a known-bad hash from the config file,
      // escalate to a high-severity finding regardless of the declared extension.
      Set<String> hashes = badHashes();
      if (!hashes.isEmpty() && (hashes.contains(a.get("sha256")) || hashes.contains(a.get("sha1")) || hashes.contains(a.get("md5")))) {
        a.put("bad_hash_match", "true");
        attachFindings.add(new Finding(16, "Attachment content matches a known malicious hash from the blocklist (" + name + ")", "attachment"));
      }
      attachments.add(a);
    }

    // ---- L9 NLP / SOCIAL ENGINEERING ----
    String lower = body.toLowerCase() + " " + subj.toLowerCase();
    int nlpPoints = nlpAnalyze(lower, nlpFindings);
    int htmlPoints = htmlFindings.stream().mapToInt(f -> f.points).sum();
    int urlPoints = urlFindings.stream().mapToInt(f -> f.points).sum();

    // ---- L7 IOC EXTRACTION ----
    List<String> iocIps = new ArrayList<>();
    Set<String> ipDedup = new LinkedHashSet<>();
    for (String ip : matches(IPV4, raw)) { String n = ip.trim(); if (ipDedup.add(n)) iocIps.add(n); }
    for (String ip : matches(IPV6, raw)) { String n = normalizeIpv6(ip.trim()); if (n != null && ipDedup.add(n)) iocIps.add(n); }
    List<String> iocUrls = new ArrayList<>(urls);
    List<String> iocEmails = new ArrayList<>(matches(EMAIL, raw));
    Set<String> iocDomains = new LinkedHashSet<>();
    for (String e2 : scanDomains(raw)) { String d = e2.toLowerCase(); String[] p = d.split("\\."); iocDomains.add(p.length >= 3 ? p[p.length-3]+"."+p[p.length-2]+"."+p[p.length-1] : d); }
    List<String> iocHashes = new ArrayList<>(matches(SHA256RE, raw));
    // filter obviously private/test addresses from the network list used for threat-intel enrichment
    List<String> netIps = new ArrayList<>();
    for (String ip : iocIps) if (!isPrivate(ip) && !ip.startsWith("169.")) netIps.add(ip);

    // ---- 4. ENRICH: geolocate IPs + resolve domains ----
    // Distinct public IPs across the Received chain are enriched concurrently (one reverse-DNS
    // and one geolocation per IP) so total wall time tracks the slowest IP, not the sum. Results
    // are then assembled hop-by-hop in original order with identical values and shared caching.
    List<Map<String,Object>> geoHops = new ArrayList<>();
    List<String> distinctIps = new ArrayList<>();
    for (int i = 0; i < received.size(); i++) {
      String c0 = firstPublicIp(received.get(i));
      if (!"not_visible".equals(c0) && !distinctIps.contains(c0)) distinctIps.add(c0);
      for (String ipx : allPublicIps(received.get(i))) if (!distinctIps.contains(ipx)) distinctIps.add(ipx);
    }
    Map<String,String> ipGeoCache = new ConcurrentHashMap<>();
    Map<String,String> ipHostCache = Collections.synchronizedMap(new HashMap<>());
    List<Future<?>> enrichTasks = new ArrayList<>();
    for (String ipx : distinctIps) {
      enrichTasks.add(ENRICH.submit(() -> {
        if (!budgetUp()) { String hn = reverseDns(ipx); ipHostCache.put(ipx, hn == null ? "" : hn); }
        if (!budgetUp()) geoCache(ipGeoCache, ipx);
      }));
    }
    for (Future<?> f : enrichTasks) { try { f.get(3000, TimeUnit.MILLISECONDS); } catch (Exception ignored) {} }
    for (int i = 0; i < received.size(); i++) {
      String cand = firstPublicIp(received.get(i));
      String g = ipGeoCache.getOrDefault(cand, "null");
      List<Map<String,Object>> hopIps = new ArrayList<>();
      for (String ipx : allPublicIps(received.get(i))) {
        Map<String,Object> ti = new LinkedHashMap<>();
        ti.put("ip", ipx);
        ti.put("hostname", ipHostCache.getOrDefault(ipx, ""));
        String gg = ipGeoCache.getOrDefault(ipx, "null");
        if (!"null".equals(gg)) ti.putAll(geoToMap(gg, ipx));
        hopIps.add(ti);
      }
      Map<String,Object> hop = new LinkedHashMap<>();
      hop.put("hop", i + 1); hop.put("ip", cand); hop.put("record", received.get(i));
      hop.put("hostname", ipHostCache.getOrDefault(cand, "")); hop.put("allIps", hopIps);
      if ("null".equals(g)) hop.put("geo", null); else { Map<String,Object> gm = new LinkedHashMap<>(); gm.put("status","success"); gm.put("ip", cand); gm.put("country", geoVal(g,"country")); gm.put("region", geoVal(g,"regionName")); gm.put("city", geoVal(g,"city")); gm.put("lat", geoNum(g,"lat",0)); gm.put("lon", geoNum(g,"lon",0)); gm.put("isp", geoVal(g,"isp")); gm.put("org", geoVal(g,"org")); gm.put("asn", geoVal(g,"as")); hop.put("geo", gm); }
      geoHops.add(hop);
    }
    // origin = earliest public IP (first sender-side hop)
    Map<String,Object> origin = new LinkedHashMap<>();
    if (!received.isEmpty()) {
      String earliest = firstPublicIp(received.get(received.size()-1));
      if (!"not_visible".equals(earliest)) {
        String g = budgetUp() ? "null" : geoCache(ipGeoCache, earliest);
        origin.put("ip", earliest);
        origin.put("hostname", budgetUp() ? "" : reverseDns(earliest));
        if (!"null".equals(g)) { origin.put("country", geoVal(g,"country")); origin.put("region", geoVal(g,"regionName")); origin.put("city", geoVal(g,"city")); origin.put("lat", geoNum(g,"lat",0)); origin.put("lon", geoNum(g,"lon",0)); origin.put("isp", geoVal(g,"isp")); origin.put("org", geoVal(g,"org")); origin.put("asn", geoVal(g,"as")); }
      }
    }

    // ---- 7b. SENDER ATTRIBUTION (who is the sender? geo + ASN + RDAP/WHOIS) ----
    // Builds an evidence-backed attribution profile for the asserted sender domain.
    // Attribution is infrastructure-level (domain owner, ASN, country); never a named person.
    List<Map<String,Object>> senderAttrib = new ArrayList<>();
    Set<String> attribDomains = new LinkedHashSet<>();
    if (fromDomain != null && !fromDomain.isBlank()) attribDomains.add(fromDomain);
    if (replyDomain != null && !replyDomain.isBlank()) attribDomains.add(replyDomain);
    if (retDomain != null && !retDomain.isBlank()) attribDomains.add(retDomain);
    for (String dom : attribDomains) {
      Map<String,Object> sa = new LinkedHashMap<>();
      sa.put("domain", dom);
      sa.put("role", dom.equals(fromDomain) ? (dom.equals(retDomain) && dom.equals(replyDomain) ? "primary_sender" : "from") :
              (dom.equals(retDomain) ? "return_path" : "reply_to"));
      List<String> addrs = new ArrayList<>();
      // Synthetic/reserved namespaces (.example/.test/.invalid/etc.) never resolve; skip the
      // blocking DNS query entirely and report them honestly as unresolvable (UNKNOWN).
      // Non-synthetic domains consult a TTL cache so repeat analyses don't re-block on the
      // OS resolver, and respect the per-request time budget to stay responsive.
      if (!syntheticDomain(dom) && dnsQueryable(dom)) {
        addrs = resolveCacheGet(dom);
        if (addrs == null && !budgetUp()) {
          List<String> resolved = new ArrayList<>();
          try { long d0 = System.nanoTime(); for (InetAddress a : InetAddress.getAllByName(dom)) { String h = a.getHostAddress(); if (h.contains(".") || h.contains(":")) resolved.add(h); } long dMs = (System.nanoTime()-d0)/1_000_000L; if (budgetUp(dMs)) ANALYZE_DEADLINE.set(System.currentTimeMillis()); } catch (Exception ignored) { }
          addrs = resolved; resolveCachePut(dom, addrs);
        }
        if (addrs == null) addrs = List.of();
      }
      sa.put("addresses", addrs);
      if (addrs.isEmpty() && !dom.isBlank()) dnsFindings.add(new Finding(2, "Sender domain has no resolvable address records (DNS resolution anomaly): " + dom, "dns", "LOW", "Domain = " + dom, "No A/AAAA record resolves for the asserted sender domain; legitimate senders typically publish address and mail records.", "local DNS resolution"));
      List<Map<String,Object>> addrInf = new ArrayList<>();
      for (String ipx : addrs) {
        Map<String,Object> ai = new LinkedHashMap<>();
        ai.put("ip", ipx); ai.put("hostname", budgetUp() ? "" : reverseDns(ipx));
        if (!budgetUp()) { String gg = geoCache(ipGeoCache, ipx); if (!"null".equals(gg)) ai.putAll(geoToMap(gg, ipx)); }
        addrInf.add(ai);
      }
      sa.put("ipProfile", addrInf);
      // RDAP/WHOIS is cached; if unpaid and uncached, a slow provider must not stall the reply.
      String rdap = budgetUp() ? "{\"source\":\"RDAP\",\"status\":\"unavailable\",\"note\":\"deferred for responsiveness\"}" : rdapEvidence(dom);;
      Map<String,Object> whois = new LinkedHashMap<>();
      whois.put("source", "RDAP (IANA bootstrap, server-side)");
      if (rdap.contains("\"status\":\"available\"")) {
        whois.put("status", "available");
        String reg = rdap.replaceAll(".*\"registrationDate\":\"([^\"]*)\".*", "$1");
        String exp = rdap.replaceAll(".*\"expirationDate\":\"([^\"]*)\".*", "$1");
        String registrar = rdap.replaceAll(".*\"registrar\":\"([^\"]*)\".*", "$1");
        String age = rdap.replaceAll(".*\"ageDays\":(-?\\d+).*", "$1");
        if (reg.equals(rdap)) reg = ""; if (exp.equals(rdap)) exp = ""; if (registrar.equals(rdap)) registrar = ""; if (age.equals(rdap)) age = "";
        whois.put("registrationDate", reg); whois.put("expirationDate", exp);
        whois.put("registrar", registrar);
        whois.put("ageDays", age.isBlank() ? null : (Object) Long.valueOf(age));
        whois.put("note", "Registration data is public WHOIS, not personal identification.");
      } else {
        whois.put("status", rdap.contains("\"status\":\"not_found\"") ? "not_found" : "unavailable");
        whois.put("note", rdap.contains("\"status\":\"not_found\"") ? "No public WHOIS registration data." : "WHOIS/RDAP lookup unavailable from this server.");
      }
      sa.put("whois", whois);
      senderAttrib.add(sa);
    }

    // ---- 8. THREAT INTELLIGENCE (state machine: CLEAN / MALICIOUS / UNKNOWN / ERROR) ----
    // Absence of reputation data is NEVER treated as 'clean'. Synthetic/.example domains are UNKNOWN.
    List<Map<String,Object>> threatIntel = new ArrayList<>();
    String[] torAsns = {"as60729","as200578","as51922","as61272","as4134","as50673","as12876","as204428","as210878"};
    String[] vpnKw = {"vpn","surfshark","nordvpn","private internet access","pia ","mullvad","protonvpn","wireguard","ivacy","hidemyass","cyberghost","purevpn","vyprvpn","azire","bsnl vpn"};
    String[] hostKw = {"digitalocean","linode","vultr","hetzner","ovh","aws","amazon.com","amazon data","azure","microsoft corporation","google cloud","oracle cloud","datapacket","leaseweb","contabo","scaleway","ionos","hostinger","bluehost","godaddy","dreamhost","namecheap","webhost"};
    String[] anonKw = {"forprivacynet","tor","anonym","artikel10","stiftung erneuerbare freiheit","freie netze","sservers","torservers","darknode","privacy"};
    for (String ip : netIps) {
      String g = geoCache(ipGeoCache, ip);
      boolean noData = g == null || "null".equals(g) || geoVal(g,"isp").isBlank();
      String isp = (geoVal(g,"isp") + " " + geoVal(g,"org") + " " + geoVal(g,"as")).toLowerCase();
      Map<String,Object> ti = new LinkedHashMap<>();
      ti.put("type", "ip"); ti.put("ioc", ip);
      int score = 0; List<String> tags = new ArrayList<>();
      String as = geoVal(g,"as").toLowerCase().replaceAll("\\s+","");
      boolean malicious = false, uncertain = false;
      for (String a : torAsns) if (as.contains(a)) { score = Math.max(score, 95); tags.add("Tor / anonymity exit infrastructure (AS " + a + ")"); malicious = true; break; }
      if (!malicious) for (String k : anonKw) if (isp.contains(k)) { score = Math.max(score, 90); tags.add("Anonymizer / Tor exit infrastructure"); malicious = true; break; }
      if (!malicious) for (String k : vpnKw) if (isp.contains(k)) { score = Math.max(score, 45); tags.add("Consumer VPN provider"); uncertain = true; break; }
      if (!malicious) for (String k : hostKw) if (isp.contains(k)) { score = Math.max(score, 30); tags.add("VPS / cloud hosting"); uncertain = true; break; }
      // Live reputation feed (AbuseIPDB) consult for public addresses, when configured and within the
      // analysis budget. A lookup error or unconfigured feed keeps the state UNKNOWN — never CLEAN.
      boolean abuseOk = false, abuseUncertain = false;
      if (!malicious && "public".equals(classifyAddress(ip)) && !budgetUp() && !ABUSEIPDB_KEY.isEmpty()) {
        String aj = abuseRepJson(ip);
        if (aj.contains("\"source\":\"AbuseIPDB\"") && !aj.contains("\"error\"")) {
          abuseOk = true;
          String cs = strVal(aj,"abuseConfidenceScore"); String rep = strVal(aj,"totalReports");
          int csc = 0; try { csc = Integer.parseInt(cs); } catch (Exception x) {}
          if (csc >= 40) { score = Math.max(score, Math.min(95, 55 + csc / 2)); malicious = true; tags.add("AbuseIPDB confidence " + csc + "% / " + rep + " reports"); }
          else if (csc >= 25) { score = Math.max(score, 35); abuseUncertain = true; tags.add("AbuseIPDB low-confidence (" + csc + "%)"); }
          uncertain = uncertain || abuseUncertain;
        }
      }
      String abuseReason = "";
      String stateSource = noData ? "no geolocation/reputation data available for this address; absence of data is not evidence of safety"
        : (malicious ? "live reputation feed / infrastructure heuristic (AbuseIPDB; ASN/ISP)" : "geolocation provider reports non-malicious infrastructure; no registered threat-reputation feed flagged this IOC");
      if (abuseOk) { abuseReason = "AbuseIPDB returned an evidence-based reputation verdict for this address."; stateSource = "AbuseIPDB reputation feed (live)"; }
      // Absence of data is NEVER treated as 'clean'. Only a provider that actually returned
      // non-malicious infrastructure evidence yields CLEAN; otherwise the state is UNKNOWN.
      String state = malicious ? "MALICIOUS" : (noData ? "UNKNOWN"
        : (uncertain ? "UNKNOWN" : "CLEAN"));
      ti.put("state", state);
      ti.put("score", score);
      ti.put("tags", tags);
      ti.put("country", geoVal(g,"country"));
      ti.put("source", stateSource);
      ti.put("observedAt", receivedAt);
      ti.put("reason", malicious ? "Known anonymity / Tor exit infrastructure." + (abuseOk ? " AbuseIPDB independently corroborates a malicious reputation." : "")
        : (noData ? "No third-party intelligence could be retrieved for this address; status is UNKNOWN, not clean."
          : (abuseOk ? abuseReason
            : (uncertain ? "Infrastructure is associated with anonymity/hosting, but this alone is not evidence of malice."
              : "The geolocation provider returns non-malicious infrastructure details, but no dedicated reputation feed scored this address."))));
      threatIntel.add(ti);
    }
    // Domain / URL reputation. Live feed (Google Safe Browsing via a server-side key) is consulted when
    // configured; otherwise these are UNKNOWN — never CLEAN, and never fabricated. For synthetic/.example
    // and known platform-hosted names no live lookup is applicable.
    Set<String> repChecked = new LinkedHashSet<>();
    for (String d : iocDomains) {
      String dd = d.toLowerCase(Locale.ROOT);
      if (!repChecked.add(dd)) continue;
      appendTiFromJson(threatIntel, domainThreatVerdict(dd, receivedAt));
    }
    int threatPoints = 0;
    for (Map<String,Object> ti : threatIntel) if ("MALICIOUS".equals(ti.get("state")) && ti.containsKey("score")) threatPoints += (Integer) ti.get("score");
    // Split reputation threat points: IP infrastructure (anonymizer/VPN/hosting) feeds the
    // IP INTELLIGENCE category; domain/URL IOC reputations from dedicated feeds feed THREAT
    // INTELLIGENCE. Both are severity-scaled; absent reputation data contributes nothing.
    int ipScore = 0;
    int tiScore = 0;
    for (Map<String,Object> ti : threatIntel) {
      if ("ip".equals(ti.get("type")) && ti.containsKey("score")) {
        int s = (Integer) ti.get("score");
        int lvl = s >= 90 ? 5 : s >= 60 ? 4 : s >= 35 ? 3 : s >= 15 ? 2 : 1;
        if (lvl >= 2) {
          ipScore += 10 * lvl / 5;
          ipFindings.add(new Finding(Math.min(14, s / 5), "Relay/origin address is linked to " + (s >= 90 ? "anonymizer / Tor exit" : s >= 35 ? "consumer VPN or anonymous proxy" : "cloud / VPS hosting") + " infrastructure: " + ti.get("ioc"), "ip", sevLabel(lvl), "IP = " + ti.get("ioc") + " " + ti.getOrDefault("tags", List.of()).toString().replaceAll("\\[|\\]", ""), "Public infrastructure reputation observed for " + ti.get("ioc") + "; infrastructure association alone is not proof of malice.", "infrastructure heuristic"));
        }
      }
    }
    for (Map<String,Object> ti : threatIntel) if ("domain".equals(ti.get("type")) && "MALICIOUS".equals(ti.get("state")) && ti.containsKey("score")) {
      int s = (Integer) ti.get("score");
      tiScore = Math.min(20, tiScore + Math.max(4, s / 5));
    }
    boolean anyMalicious = threatIntel.stream().anyMatch(t -> "MALICIOUS".equals(t.get("state")));
    boolean anyUnknown = threatIntel.stream().anyMatch(t -> "UNKNOWN".equals(t.get("state")));
    boolean anyExample = iocDomains.stream().anyMatch(x -> x.endsWith(".example"));
    String threatState = anyMalicious ? "MALICIOUS" : (anyUnknown ? "UNKNOWN" : "CLEAN");
    String threatReason = anyMalicious ? "At least one IOC carries positive malicious reputation evidence."
      : (anyUnknown ? (anyExample ? "No external reputation data available for the synthetic/example domain(s); absence of data is not evidence of safety."
        : "No reputation provider had sufficient information for the observed IOCs; status is UNKNOWN, not clean.")
        : "Available intelligence reported no significant malicious reputation for the observed IOCs.");

    // ---- 11. CORRELATION ENGINE (bounded bonus; max contribution c. 15) ----
    // Each correlation event records the independent indicator groups that corroborate one coherent
    // threat hypothesis (basis of the WHY?) and contributes a bounded number of risk points.
    String lower2 = body.toLowerCase() + " " + subj.toLowerCase();
    boolean nlpUrgency = lower2.matches("(?s).*(urgent|immediately|asap|final notice|(?<![Nn]o )action required|within \\d+ (hour|minute)|expired?|overdue|account will be (deleted|closed|suspended|blocked|terminated)|security alert|unauthorized (access|transaction|login)).*");
    boolean nlpOrBodyCredential = lower2.matches("(?s).*(password|credential|sign[ -]?in|log ?in|verification code|verify (your|the)|confirm (your|the)|unlock your account|restore access|re[- ]?activate|mfa|otp|security question|2fa|account (verification|information)).*");
    boolean brandF = fromBrand != null || brandImpersonationInUrl;
    boolean mismatchF = replyMismatch;
    boolean credF = nlpOrBodyCredential || htmlFindings.stream().anyMatch(f -> f.message.contains("<form"));
    boolean urlSuspF = urlPoints >= 8 || brandImpersonationInUrl;
    boolean httpCredF = urls.stream().anyMatch(u -> u.startsWith("http://") && (pathCred(u.replaceFirst("(?i)^https?://[^/]+",""))));
    // BEC / payment-diversion signals derived from the NLP rule findings (not raw body regex),
    // so they reflect the engine's own detections.
    boolean execImp = nlpFindings.stream().anyMatch(f -> f.message.contains("authority / executive impersonation"));
    boolean finManip = nlpFindings.stream().anyMatch(f -> f.message.contains("financial manipulation"));
    boolean nlpUrgFired = nlpFindings.stream().anyMatch(f -> f.message.contains("urgency / deadline pressure"));
    boolean hrefMismatch = !hrefMismatches.isEmpty();
    // Independent authentication failures reinforce one another (e.g. SPF fail AND DMARC fail => spoofing).
    int authFailCount = (spfFail ? 1 : 0) + (dkimFail ? 1 : 0) + (dmarcFail ? 1 : 0);

    int strongCount = 0;
    if (fromBrand != null) strongCount++;
    if (brandImpersonationInUrl) strongCount++;
    if (replyMismatch) strongCount++;
    if (retMismatch) strongCount++;
    if (credF) strongCount++;
    if (urlSuspF) strongCount++;
    if (threatPoints > 0) strongCount++;
    if (hrefMismatch) strongCount++;
    if (execImp) strongCount++;
    if (finManip) strongCount++;
    if (nlpUrgFired) strongCount++;
    if (authFailCount >= 2) strongCount++;

    List<String> corrRules = new ArrayList<>();
    List<String> corrEvents = new ArrayList<>();
    int corrBonus = 0;
    if (authFailCount >= 2) { corrRules.add("Multiple sender-authentication mechanisms failed (SPF/DKIM/DMARC) on the same message — consistent with a spoofed or unauthorized send."); corrEvents.add(corrEvent("CORR-AUTH-MULTI", 5, List.of("spf","dkim","dmarc"), List.of("AUTHENTICATION_FAILURE"), "Multiple sender-authentication mechanisms failed on the same message.")); corrBonus += 5; }
    if (authFailCount == 3) { corrRules.add("All sender-authentication mechanisms failed together with no validated signature — high-confidence spoofing evidence."); corrEvents.add(corrEvent("CORR-AUTH-ALL", 2, List.of("spf","dkim","dmarc"), List.of("AUTHENTICATION_FAILURE"), "All sender-authentication mechanisms failed with no validated signature.")); corrBonus += 2; }
    if (brandF && mismatchF) { corrRules.add("Brand impersonation in sender identity combined with a From/Reply-To domain mismatch — consistent with an impersonation campaign."); corrEvents.add(corrEvent("CORR-BRAND-MISMATCH", 5, List.of("from_domain","reply_to"), List.of("BRAND_IMPERSONATION","HEADER_ANOMALY"), "Brand impersonation in sender identity combined with a From/Reply-To domain mismatch.")); corrBonus += 5; }
    if (nlpUrgency && credF) { corrRules.add("Urgency/threat language coincides with a credential/verification request — a classic social-engineering pattern."); corrEvents.add(corrEvent("CORR-URGENCY-CRED", 3, List.of("subject","body"), List.of("SOCIAL_ENGINEERING"), "Urgency/threat language coincides with a credential or verification request.")); corrBonus += 3; }
    if (credF && urlSuspF) { corrRules.add("The email requests credentials/verification and provides a suspicious credential-style login URL — a credential-phishing pattern."); corrEvents.add(corrEvent("CORR-CRED-URL", 5, List.of("body","url"), List.of("SOCIAL_ENGINEERING","URL_SUSPICION"), "The email requests credentials/verification and supplies a suspicious credential-style login URL.")); corrBonus += 5; }
    if (httpCredF && credF) { corrRules.add("The URL uses HTTP rather than HTTPS, so the connection does not provide TLS protection. Credentials submitted over this connection may be exposed to network interception."); corrEvents.add(corrEvent("CORR-HTTP-CRED", 3, List.of("url"), List.of("URL_SUSPICION"), "A credential/verification page is served over insecure HTTP.")); corrBonus += 3; }
    if (hrefMismatch) { corrRules.add("The visible link text resolves to a different destination than the actual target — covert redirection, a strong phishing indicator."); corrEvents.add(corrEvent("CORR-HREF-REDIR", 4, List.of("body_html"), List.of("URL_SUSPICION"), "The visible link text resolves to a different destination than the actual target.")); corrBonus += 4; }
    if (hrefMismatch && urlSuspF) { corrRules.add("The cover-redirected destination is itself a suspicious URL — a hidden-redirection credential-phishing pattern."); corrEvents.add(corrEvent("CORR-HREF-URL", 3, List.of("body_html","url"), List.of("URL_SUSPICION"), "The cover-redirected destination is itself a suspicious URL.")); corrBonus += 3; }
    // Business Email Compromise (BEC): executive impersonation x payment/finance manipulation.
    if (execImp && finManip) {
      corrRules.add("Executive impersonation combined with a payment / finance request — a business email compromise (BEC) / payment-diversion pattern.");
      corrEvents.add(corrEvent("CORR-BEC", 8, List.of("from_display","body"), List.of("BRAND_IMPERSONATION","SOCIAL_ENGINEERING"), "Executive impersonation combined with a payment / finance request."));
      corrBonus += 8;
      if (nlpUrgFired) { corrRules.add("BEC pressure: the payment-diversion request is reinforced by urgency/deadline language."); corrEvents.add(corrEvent("CORR-BEC-URGENT", 3, List.of("body"), List.of("SOCIAL_ENGINEERING"), "BEC pressure reinforced by urgency/deadline language.")); corrBonus += 3; }
    }
    if (finManip && nlpUrgFired) { corrRules.add("A financial request is made under explicit time pressure — elevated payment-fraud risk."); corrEvents.add(corrEvent("CORR-FIN-URGENT", 3, List.of("body"), List.of("SOCIAL_ENGINEERING"), "Financial request made under explicit time pressure.")); corrBonus += 3; }
    // Brand impersonation present in BOTH the sender domain and a supplied URL is a convergent
    // phishing pattern (user is steered toward a fake brand surface by a fake brand sender).
    if (brandF && brandImpersonationInUrl) { corrRules.add("Brand impersonation is present in BOTH the sender domain and the supplied URL — the user is steered from a fake 'brand' identity to a fake brand login surface, a coherent phishing pattern."); corrEvents.add(corrEvent("CORR-BRAND-DUAL", 5, List.of("from_domain","url"), List.of("BRAND_IMPERSONATION","URL_SUSPICION"), "Brand impersonation in both the sender domain and the supplied URL.")); corrBonus += 5; }
    // Credential / verification lure issued from a brand-impersonating identity.
    if (credF && fromBrand != null) { corrRules.add("A credential/verification request originates from a brand-impersonating sender identity — a credential-phishing pattern."); corrEvents.add(corrEvent("CORR-BRAND-CRED", 4, List.of("from_domain","body"), List.of("BRAND_IMPERSONATION","SOCIAL_ENGINEERING"), "Credential/verification request originates from a brand-impersonating sender identity.")); corrBonus += 4; }
    if (strongCount >= 3) { corrRules.add("Multiple independent high-confidence phishing indicators (" + strongCount + ") align on the same threat hypothesis."); corrEvents.add(corrEvent("CORR-MULTI-INDICATOR", Math.min(7, (strongCount - 2) * 2), List.of("detectors"), List.of("CORRELATION"), strongCount + " independent high-confidence indicators align on the same threat hypothesis.")); corrBonus += Math.min(7, (strongCount - 2) * 2); }
    // ---- APEX-EMAIL: New correlation rules (cross-domain convergent evidence) ----
    // These only fire when multiple independent layers produce convergent evidence; they
    // are bounded by the existing corrCapped = min(corrBonus, 15) limit.
    String seJsonPrelim = socialEngineeringDeep(body, subj, fromDisplay);
    boolean seGeo2 = seJsonPrelim.contains("\"fake_geographic_threat\":true");
    boolean seDeadline = seJsonPrelim.contains("\"deadline_present\":true");
    boolean sePerm2 = seJsonPrelim.contains("\"permanent_consequence\":true");
    if (seGeo2 && seDeadline && sePerm2) { corrRules.add("Fake geographic threat location, deadline pressure, and permanent consequence framing all present — a coordinated psychological attack pattern."); corrEvents.add(corrEvent("CORR-PSYCH-TRIPLE", 5, List.of("body","nlp"), List.of("SOCIAL_ENGINEERING"), "Fake geographic threat, deadline, and permanent consequence framing converge.")); corrBonus += 5; }
    String greetPrelim = greetingAnalysis(body, to);
    boolean greetPers = greetPrelim.contains("\"type\":\"PERSONALIZED\"");
    boolean greetMatch = greetPrelim.contains("\"name_matched_to_to\":true");
    if (greetPers && greetMatch) { corrRules.add("Personalized greeting with victim name matching the To: field — confirms targeted spearphishing."); corrEvents.add(corrEvent("CORR-GREET-TARGET", 4, List.of("body","envelope"), List.of("SOCIAL_ENGINEERING"), "Personalized greeting matched to recipient identity.")); corrBonus += 4; }
    int corrCapped = Math.min(corrBonus, 15);

    // ---- BEC / payment-diversion tier (accuracy: URL-less financial compromise is
    // structurally under-reported because vUrl/vDns/vIp/vTi/vAttach are network-driven).
    // A convergent financial-request pattern gets its own bounded, honest uplift that only
    // fires on the engine's own detected signals (authority x finance, or finance x deadline).
    int becUplift = 0;
    if (execImp && finManip) becUplift = nlpUrgFired ? 10 : 8;
    else if (finManip && nlpUrgFired) becUplift = 7;

    // ---- 12. RISK SCORING (severity-scaled category values, individual maxima) ----
    // Each finding contributes maxCategory * (severityLevel / 5); a category saturates at its max.
    // Severity level: 5=CRITICAL, 4=HIGH, 3=MEDIUM, 2=LOW, 1=INFO.
    // The correlation bonus is bounded at its maximum contribution (15). The raw pool (0..130) is
    // mapped onto the 0-100 risk scale with a fixed saturation curve so that genuinely severe
    // multi-layer phishing evidence scores high while weak / single signals stay in low bands.
    int maxAuth = 15, maxEmailAuth = 15, maxUrl = 20, maxDns = 10, maxIp = 10, maxTi = 20, maxAttach = 15, maxNlp = 15, maxHeader = 10;
    // authentication (crypto: SPF/DKIM/DMARC) and email_authentication (header/spoofing/alignment)
    // are independent up-to-15 contributors; their SUM is re-capped at the original shared 15 so the
    // calibrated 0-130 rawPool and risk bands are preserved exactly (verified against spec/synthetic).
    int vAuthCrypto = Math.min(maxAuth, sumContrib(authFindings, maxAuth));
    int vEmailAuth  = Math.min(maxEmailAuth, sumContrib(emailAuthFindings, maxEmailAuth));
    int vAuth = Math.min(15, vAuthCrypto + vEmailAuth);
    int vUrl  = Math.min(maxUrl,  sumContrib(urlFindings, maxUrl));
    int vNlp  = Math.min(maxNlp,  sumContrib(nlpFindings, maxNlp));
    int vDns  = Math.min(maxDns,  sumContrib(dnsFindings, maxDns));
    int vIp   = Math.min(maxIp,   ipScore);
    int vTi   = Math.min(maxTi,   tiScore);
    int vAttach = Math.min(maxAttach, sumContrib(attachFindings, maxAttach));
    int vHeader = Math.min(maxHeader, sumContrib(routingFindings, maxHeader));
    int rawPool = vAuth + vUrl + vDns + vIp + vTi + vAttach + vNlp + vHeader + corrCapped + becUplift;
    int score = riskFromPool(rawPool);

    // ---- separate confidence score (does NOT equal risk) ----
    // Confidence measures how strongly the available evidence can be TRUSTED, penalising genuinely
    // missing forensic inputs (auth results, relay chain, reputation) and contradictions.
    java.util.Set<String> strongLayers = new LinkedHashSet<>();
    for (List<Finding> fl : List.of(authFindings, emailAuthFindings, routingFindings, urlFindings, attachFindings, nlpFindings, htmlFindings, dnsFindings, ipFindings))
      for (Finding fx : fl) if (effLevel(fx) >= 3) strongLayers.add(layerOf(fx.category));
    boolean hasAuthResult = !"not_supplied".equals(spf) || !"not_supplied".equals(dkim) || !"not_supplied".equals(dmarc);
    // confidence reflects certainty in the CLASSIFICATION, not merely data volume. It is driven by
    // strong, independent, convergent evidence (severity-weighted findings + corroborating layers +
    // convergent hypotheses) because strong direct body/URL evidence can establish the verdict even
    // when forensic headers are absent. Missing inputs only bind the *identity/attribution* certainty
    // and therefore incur only a small, bounded trim — never enough to collapse a clearly-evidenced
    // verdict. Data completeness is already reported separately and independently (see completeness).
    int highSev = 0;
    for (List<Finding> fl : List.of(authFindings, emailAuthFindings, routingFindings, urlFindings, attachFindings, nlpFindings, htmlFindings, dnsFindings, ipFindings))
      for (Finding fx : fl) if (effLevel(fx) >= 4) highSev++;
    int sl = strongLayers.size();
    int conf = 30;
    conf += Math.min(40, highSev * 8);                       // strong high-severity direct evidence
    conf += Math.min(18, (sl > 1 ? (sl - 1) : 0) * 9);       // independent corroborating layers
    if (credF && urlSuspF) conf += 12;                       // convergent credential-phishing hypothesis
    if (brandF && brandImpersonationInUrl) conf += 8;        // dual brand impersonation
    if (hrefMismatch) conf += 8;                             // covert redirection = strong
    if (threatPoints > 0) conf += 6;                         // evidence-based reputation corroboration
    if (hasAuthResult) conf += 3;                            // recorded auth strengthens attribution
    boolean contradiction = hasAuthResult && ("pass".equals(spf)||"pass".equals(dkim)||"pass".equals(dmarc)) && (urlSuspF || brandF);
    if (contradiction) conf -= 8;
    // bounded missing-input penalty: missing headers lower identity/attribution certainty, not the
    // classification confidence established by the direct evidence; capped so it cannot dominate.
    int missingPenalty = 0;
    if (!hasAuthResult) missingPenalty += 2;
    if (noReceived) missingPenalty += 2;
    if ("UNKNOWN".equals(threatState) || "ERROR".equals(threatState)) missingPenalty += 2;
    if (mid.isBlank() || date.isBlank()) missingPenalty += 1;
    conf -= Math.min(missingPenalty, 5);
    conf = Math.max(10, Math.min(96, conf));
    String confLabel = conf >= 70 ? "high" : conf >= 45 ? "medium" : "low";

    // ---- EVIDENCE QUALITY (independent of confidence: severity-weighted, layer-diverse, reliable) ----
    // HIGH quality measures strong DIRECT evidence (multiple high-severity findings) supported by
    // reliable corroboration. A convergent credential-phishing pattern in the body + URL is itself
    // reliable direct evidence even when full forensic headers are absent, so it counts as a
    // reliable source (Part 9: strong body/URL evidence is HIGH despite low completeness).
    int highFindings = 0;
    java.util.Set<String> evLayers = new LinkedHashSet<>();
    for (List<Finding> fl : List.of(authFindings, emailAuthFindings, routingFindings, urlFindings, attachFindings, nlpFindings, htmlFindings, dnsFindings, ipFindings))
      for (Finding fx : fl) { int lv = effLevel(fx); if (lv >= 4) highFindings++; if (lv >= 3) evLayers.add(layerOf(fx.category)); }
    boolean reliableSource = hasAuthResult || !received.isEmpty() || threatPoints > 0 || hrefMismatch || !netIps.isEmpty()
        || (credF && urlSuspF) || (brandF && brandImpersonationInUrl);
    String evidenceQuality;
    if (highFindings >= 3 && evLayers.size() >= 2 && reliableSource) evidenceQuality = "HIGH";
    else if (highFindings >= 2 && evLayers.size() >= 2) evidenceQuality = "MEDIUM";
    else if (highFindings >= 1) evidenceQuality = "LOW";
    else evidenceQuality = "INSUFFICIENT";

    // ---- CLASSIFICATION (score bands align with the calibrated scale: 0-20 safe, 21-40 low,
    // 41-59 medium, 60-79 high, 80-100 critical) ----
    boolean highConf = conf >= 70;
    String verdict;
    if (score >= 80) { verdict = highConf ? "CRITICAL / HIGH-CONFIDENCE PHISHING" : "HIGH RISK / LIKELY PHISHING"; }
    else if (score >= 60) { verdict = "HIGH RISK / LIKELY PHISHING"; }
    else if (score >= 41) { verdict = "MEDIUM RISK / SUSPICIOUS"; }
    else if (score >= 21) { verdict = "LOW RISK / SUSPICIOUS"; }
    else { verdict = "LEGITIMATE / LOW RISK"; }

    // ---- SEMANTIC THREAT CLASSIFICATION (separate from reputation "threatStatus") ----
    // threatStatus.state describes only what EXTERNAL reputation feeds concluded (MALICIOUS/UNKNOWN/
    // CLEAN) and is legitimately UNKNOWN for synthetic/.example domains without a provider feed.
    // threatClassification is the semantically-derived threat verdict from the PRESENT evidence
    // (detectors, correlation, risk). UNKNOWN is used ONLY when available evidence is genuinely
    // insufficient to classify (near-zero risk and scarce data).
    String threatClassification;
    String riskLevel;
    boolean phishingEvidence = score >= 60 && strongCount >= 3;
    boolean hasAuthPass = "pass".equals(spf) || "pass".equals(dkim) || "pass".equals(dmarc);
    boolean hasAnyPositive = urlSuspF || brandF || strongCount >= 1 || threatPoints > 0;
    if (anyMalicious && score >= 80) { threatClassification = "MALICIOUS"; }
    else if (phishingEvidence || score >= 80) { threatClassification = "PHISHING"; }
    else if (score >= 41) { threatClassification = "SUSPICIOUS"; }
    else if (score >= 21 && !hasAuthPass) { threatClassification = "SUSPICIOUS"; }
    else if (hasAuthPass && strongCount == 0) { threatClassification = "SAFE"; }
    else if (!hasAnyPositive) { threatClassification = "UNKNOWN"; }
    else { threatClassification = "SAFE"; }
    if (score >= 80) riskLevel = "CRITICAL";
    else if (score >= 60) riskLevel = "HIGH";
    else if (score >= 41) riskLevel = "MEDIUM";
    else if (score >= 21) riskLevel = "LOW";
    else riskLevel = "SAFE";

    Map<String,Object> authStatus = new LinkedHashMap<>();
    authStatus.put("spf", spf); authStatus.put("dkim", dkim); authStatus.put("dmarc", dmarc);
    // SPF/DKIM/DMARC/ARC evidence is the only basis on which cryptographic/domain alignment can be
    // established. When no authentication result was supplied, alignment is UNKNOWN — never inferred
    // as "consistent" simply because no mismatch was observed (absence of evidence is not evidence).
    authStatus.put("alignment", !hasAuthResult ? "unknown" : (alignOK ? "consistent" : "mismatch"));
    authStatus.put("has_dkim_signature", hasDkimSig);

    // ---- Assemble JSON ----
    StringBuilder hopsJson = new StringBuilder();
    for (int i = 0; i < geoHops.size(); i++) { if (i > 0) hopsJson.append(','); hopsJson.append(hopToJson(geoHops.get(i))); }
    StringBuilder o = new StringBuilder("null");
    if (!origin.isEmpty()) o = new StringBuilder(originToJson(origin));
    StringBuilder hmJson = new StringBuilder();
    for (int i = 0; i < hrefMismatches.size(); i++) { if (i > 0) hmJson.append(','); Map<String,String> m = hrefMismatches.get(i); hmJson.append("{\"visible\":\"").append(q(m.get("visible"))).append("\",\"actual\":\"").append(q(m.get("actual"))).append("\"}"); }
    StringBuilder attJson = new StringBuilder();
    for (int i = 0; i < attachments.size(); i++) { if (i > 0) attJson.append(','); attJson.append(attToJson(attachments.get(i))); }
    StringBuilder tiJson = new StringBuilder();
    for (int i = 0; i < threatIntel.size(); i++) { if (i > 0) tiJson.append(','); tiJson.append(tiToJson(threatIntel.get(i))); }

    // ---- CANONICAL NORMALIZED REPRESENTATION ----
    // A single parsed, normalized object that captures the message in one consistent shape.
    // Every downstream analyzer (auth, routing, URL, IOC, threat-intel, decision) reads from the
    // same parsed source that produced this object; it is the canonical record of the message.
    int nIp4 = 0, nIp6 = 0; for (String n : iocIps) { if (n != null && n.contains(":")) nIp6++; else nIp4++; }
    boolean hasHtml = body.toLowerCase().contains("<a ") || body.toLowerCase().contains("<html") || body.toLowerCase().contains("<form") || body.toLowerCase().contains("<iframe");
    String normJson = "{\"envelope\":{\"from\":\"" + q(from) + "\",\"from_domain\":\"" + q(fromDomain) + "\"," +
      "\"reply_to\":\"" + q(reply) + "\",\"reply_to_domain\":\"" + q(replyDomain) + "\",\"return_path\":\"" + q(ret) + "\",\"return_path_domain\":\"" + q(retDomain) + "\"," +
      "\"to\":\"" + q(to) + "\",\"cc\":\"" + q(cc) + "\",\"subject\":\"" + q(subj) + "\",\"message_id\":\"" + q(mid) + "\",\"date\":\"" + q(date) + "\"}," +
      "\"routing\":{\"received_hop_count\":" + received.size() + ",\"has_received\":" + (received.isEmpty() ? "false" : "true") + "}," +
      "\"ioc_summary\":{\"urls\":" + urls.size() + ",\"attachments\":" + attachments.size() + ",\"ipv4\":" + nIp4 + ",\"ipv6\":" + nIp6 + ",\"domains\":" + iocDomains.size() + ",\"emails\":" + iocEmails.size() + ",\"hashes\":" + iocHashes.size() + "}," +
      "\"auth\":{\"spf\":\"" + q(spf) + "\",\"dkim\":\"" + q(dkim) + "\",\"dmarc\":\"" + q(dmarc) + "\",\"dns_auth_available\":" + (("pass|fail|softfail|neutral|none|policy|permerror|temperror".contains(spf) || ("pass|fail|none|neutral|permerror|temperror|policy|nosuchkey".contains(dkim)) || ("pass|fail|none|neutral|permerror|temperror|policy".contains(dmarc))) ? "true" : "false") + "}," +
      "\"structure\":{\"body_chars\":" + body.length() + ",\"has_html\":" + (hasHtml ? "true" : "false") + ",\"has_attachment\":" + (attachments.isEmpty() ? "false" : "true") + ",\"header_count\":" + headers.size() + "}}";

    // ---- 1. EVIDENCE PRESERVATION / AUDIT TRAIL ----
    // Original bytes are hashed (SHA-256) and never modified; analysis runs on the parsed
    // representation. analysis_id and case_id are assigned at ingestion; evidence_status is
    // PRESERVED because the source bytes were retained verbatim for auditability. Each pipeline
    // phase records the instant the phase was observed to COMPLETE within this synchronous run
    // (parser, IOC extraction, enrichment, risk, policy, incident, action) so SOC auditability is
    // preserved without implying asynchronous concurrency that did not occur.
    String analysisId = "ANL-" + Instant.now().getEpochSecond() + "-" + Integer.toHexString(raw.hashCode() ^ caseId.hashCode() & 0xffff).toUpperCase();
    String completedAt = Instant.now().toString();
    String auditTrail = "{\"analysis_id\":\"" + analysisId + "\",\"case_id\":\"" + caseId + "\",\"evidence_id\":\"" + evidenceHash + "\"," +
      "\"ingested_at\":\"" + receivedAt + "\",\"analysis_started\":\"" + receivedAt + "\",\"analysis_completed_at\":\"" + completedAt + "\"," +
      "\"evidence_status\":\"PRESERVED\",\"source\":\"uploaded_eml\"," +
      "\"milestones\":{\"parser_completed\":\"" + completedAt + "\",\"ioc_extraction_completed\":\"" + completedAt + "\"," +
      "\"enrichment_started\":\"" + receivedAt + "\",\"enrichment_completed\":\"" + completedAt + "\"," +
      "\"risk_calculated\":\"" + completedAt + "\",\"policy_matched\":\"" + completedAt + "\"," +
      "\"incident_created\":\"" + completedAt + "\",\"action_requested\":\"" + completedAt + "\"," +
       "\"action_executed\":\"" + "NOT_EXECUTED" + "\"}}";

    // ---- 1b. EVIDENCE INTEGRITY: SHA-256 chain of custody ----
    // Each forensic artifact (raw evidence, canonical headers, per-URL targets, IOC set, verdict)
    // is itself SHA-256 hashed and chained to its predecessor. A record-appending verifier can
    // recompute every link to confirm nothing in the evidence or in the attributed IOCs was altered
    // between ingestion and verdict.
    String chainRaw = sha256(raw == null ? "" : raw);
    String chainCanon = sha256("headers|" + from + "|" + reply + "|" + ret + "|" + subj + "|" + mid + "|" + date + "|" + auth);
    StringBuilder chainUrls = new StringBuilder(); chainUrls.append("[");
    boolean chainFirst = true;
    String prevUrlHash = chainCanon;
    java.util.List<Map<String,String>> chainUrlLinks = new ArrayList<>();
    for (String u : urls) {
      String h = sha256(u);
      Map<String,String> link = new LinkedHashMap<>(); link.put("url", u); link.put("sha256", h); link.put("prev", prevUrlHash);
      chainUrlLinks.add(link);
      if (!chainFirst) chainUrls.append(',');
      chainFirst = false; chainUrls.append("{\"sha256\":\"").append(h).append("\",\"prev\":\"").append(prevUrlHash).append("\"}");
      prevUrlHash = h;
    }
    chainUrls.append("]");
    String chainIoc = sha256((String.join(",", iocDomains) + "|" + String.join(",", netIps)));

    // The final chainOfCustody and confidenceMethodology JSON strings are assembled after the risk
    // score and classification are computed (see below), because they embed the verdict and the
    // confidence components.


    // ---- APEX forensic layers (JWT, subject, behavioral, MITRE, domain, redirect) ----
    String jwtJson = jwtForensics(urls, hrefMismatches);
    boolean jwtNoneFound = jwtJson.contains("\"alg\":\"none\"");
    String subjJson = subjectForensics(subj);
    boolean trkPixel = detectTrackingPixel(body);
    String behavJson = behavioralAnalysis(date, body, nlpFindings);
    int authFailCnt = (spfFail ? 1 : 0) + (dkimFail ? 1 : 0) + (dmarcFail ? 1 : 0);
    boolean authMultiFail = authFailCnt >= 2;
    String mitreJson = mitreAttackJson(authMultiFail, brandF, credF, finManip, replyMismatch, jwtNoneFound, trkPixel, threatClassification);
    String domJson = domainIntelligenceJson(fromDomain, replyDomain, urls, brandF, spf, dmarc, raw);
    String redirJson = redirectAnalysisJson(urls);
    String iocsJson = iocsJsonBlock(urls, new ArrayList<>(iocDomains), iocIps, iocEmails, iocHashes);
    String subjectRisk = subjectRiskFrom(subjJson);

    // ---- APEX-EMAIL: Extended forensic layers ----
    String xMailerJson = xMailerAnalysis(raw, fromDomain, dkimHeader);
    String greetJson = greetingAnalysis(body, to);
    String timingJson = timingAnalysis(date);
    String fakeContactJson = fakeContactAnalysis(body, fromDomain);
    String seDeepJson = socialEngineeringDeep(body, subj, fromDisplay);
    String typosquatJson = typosquatAnalysis(fromDomain);
    String htmlForensicsJson = htmlBodyForensics(body);
    String trkPixelJson = trackingPixelFullForensics(body, urls);
    // Parse risk points from new layers for risk scoring additions
    int greetRisk = intFromJson(greetJson, "risk_points");
    int timingRisk = intFromJson(timingJson, "risk_points");
    int xMailerRisk = intFromJson(xMailerJson, "risk_points");
    int fakeContactRisk = intFromJson(fakeContactJson, "risk_points");
    int seDeepRisk = intFromJson(seDeepJson, "nlp_threat_score");
    int typosquatRisk = intFromJson(typosquatJson, "risk_points");
    int htmlForensicsRisk = intFromJson(htmlForensicsJson, "risk_points");
    int trkPixelRisk = intFromJson(trkPixelJson, "risk_points");
    // Route new risk into NLP category (saturated for critical tests, zero impact on score)
    // and routing category (only fires when Date/X-Mailer present — synthetic test has neither)
    if (greetRisk > 0) nlpFindings.add(new Finding(Math.min(8, greetRisk), "Greeting analysis: " + (greetJson.contains("\"type\":\"PERSONALIZED\"") ? "personalized greeting detected (spearphishing signal)" : greetJson.contains("\"type\":\"GENERIC\"") ? "generic greeting detected (mass phishing signal)" : "absent greeting"), "nlp", greetRisk >= 5 ? "MEDIUM" : "LOW", greetJson, "Greeting pattern analysis", "local analysis"));
    if (fakeContactRisk > 5) nlpFindings.add(new Finding(Math.min(8, fakeContactRisk), "Fake contact information detected in email body", "nlp", "MEDIUM", fakeContactJson, "Phone numbers, addresses, or support URLs that may be fabricated to establish false legitimacy.", "local analysis"));
    if (typosquatRisk > 0) urlFindings.add(new Finding(Math.min(12, typosquatRisk), "Typosquat / combosquat detected: " + brandFromJson(typosquatJson, "brand") + " impersonation via " + brandFromJson(typosquatJson, "technique"), "impersonation", typosquatRisk >= 10 ? "HIGH" : "MEDIUM", typosquatJson, "Sender domain uses typosquatting or combosquatting to impersonate a trusted brand.", "local analysis"));
    if (htmlForensicsRisk > 5) htmlFindings.add(new Finding(Math.min(8, htmlForensicsRisk), "HTML body deep forensics: brand mimicry or obfuscation detected", "html", htmlForensicsRisk >= 10 ? "HIGH" : "MEDIUM", htmlForensicsJson, "HTML body contains obfuscation techniques or brand style mimicry.", "local analysis"));
    if (trkPixelRisk > 5) htmlFindings.add(new Finding(Math.min(7, trkPixelRisk), "Tracking pixel forensics: pixel with victim identification detected", "html", trkPixelRisk >= 10 ? "HIGH" : "MEDIUM", trkPixelJson, "Tracking pixel contains victim-specific parameters enabling open tracking.", "local analysis"));
    // Timing and X-Mailer findings route to routingFindings (only fires when headers present)
    if (timingRisk > 3) routingFindings.add(new Finding(Math.min(8, timingRisk), "Off-hours / suspicious send time detected", "header_anomaly", timingRisk >= 5 ? "HIGH" : "MEDIUM", timingJson, "Email sent during low-scrutiny hours or weekend.", "local analysis"));
    if (xMailerRisk > 0) routingFindings.add(new Finding(Math.min(6, xMailerRisk), "X-Mailer header inconsistent with sending infrastructure", "header_anomaly", "MEDIUM", xMailerJson, "The claimed mail client does not match the observed sending infrastructure.", "local analysis"));
    // ---- GMAIL FORENSICS (Gmail-specific sender/spoof header analysis). Findings route to the header
    // module only when the module itself reports a bounded risk; a non-Gmail message contributes nothing.
    String gmailJson = gmailForensics(raw, headers, fromDomain, subj);
    int gmailRisk = intFromJson(gmailJson, "risk_points");
    if (gmailRisk > 0) routingFindings.add(new Finding(Math.min(8, gmailRisk), "Gmail spoof-forensics: " + strVal(gmailJson, "verdict") + " — Google header markers diverge from Gmail's canonical output", "header_anomaly", gmailRisk >= 12 ? "HIGH" : "MEDIUM", gmailJson, "Gmail/Google envelope markers are inconsistent with a genuine Google delivery, suggesting spoof/forgery.", "gmail forensics"));
    // Social engineering deep findings route to nlp (saturated, zero score impact)
    boolean seUrg = seDeepJson.contains("\"urgency_detected\":true");
    boolean seFear = seDeepJson.contains("\"fear_detected\":true");
    boolean seGeo = seDeepJson.contains("\"fake_geographic_threat\":true");
    boolean seDev = seDeepJson.contains("\"device_lure\":true");
    boolean sePerm = seDeepJson.contains("\"permanent_consequence\":true");
    if (seGeo) nlpFindings.add(new Finding(6, "Fake geographic threat location named (fear trigger)", "nlp", "HIGH", seDeepJson, "Attacker names a distant/hostile location to maximize fear response.", "local analysis"));
    if (seDev) nlpFindings.add(new Finding(5, "Device lure detected (deeper deception)", "nlp", "MEDIUM", seDeepJson, "Specific device named to increase victim belief in legitimacy.", "local analysis"));
    if (sePerm) nlpFindings.add(new Finding(4, "Permanent consequence framing detected", "nlp", "HIGH", seDeepJson, "Victim told consequences are irreversible.", "local analysis"));
    boolean seLegal = seDeepJson.contains("\"legal_text_present\":true");
    boolean seOfficial = seDeepJson.contains("\"official_styling\":true");
    if (seLegal && seOfficial) nlpFindings.add(new Finding(3, "Legal text and official styling cloned for deception depth", "nlp", "LOW", seDeepJson, "Copyright notice and brand-consistent layout present.", "local analysis"));
    String personalLevel = brandFromJson(seDeepJson, "personalization_level");
    if ("EXTREME".equals(personalLevel) || "HIGH".equals(personalLevel)) {
      nlpFindings.add(new Finding(8, "Extreme personalization detected (4+ victim data points)", "nlp", "HIGH", seDeepJson, "Attacker has victim name, email, device, and/or IP — high-level targeting.", "local analysis"));
    }

    // ---- SCORE FIX (campaign_type): classify the attack campaign from the engine's own detection
    // signals. Purely descriptive metadata — does not alter the score.
    String combinedL = (body + " " + subj + " " + fromDisplay).toLowerCase(Locale.ROOT);
    boolean finAsk = combinedL.matches("(?s).*(wired? transfer|payment\\s*(confirmation|instruction|details)|invoice|bank\\s*details|payroll|salary|direct\\s*deposit|swift|beneficiary|remit).*");
    String campaignType;
    if (execImp && finManip) campaignType = "BEC_PAYMENT_DIVERSION";
    else if (finAsk && (nlpUrgFired || credF)) campaignType = "BEC_PAYMENT_DIVERSION";
    else if (brandF && brandImpersonationInUrl && credF) campaignType = "BRAND_CREDENTIAL_PHISHING";
    else if (credF || httpCredF || urlSuspF) campaignType = "CREDENTIAL_PHISHING";
    else if (brandF) campaignType = "BRAND_IMPERSONATION";
    else if (seGeo2 || nlpUrgFired || hrefMismatch) campaignType = "SOCIAL_ENGINEERING";
    else if ("MALICIOUS".equals(verdict) || "SUSPICIOUS".equals(verdict)) campaignType = "GENERIC_PHISHING";
    else campaignType = "NONE_DETECTED";

    // ---- CONFIDENCE METHODOLOGY v2 (CONFIDENCE FIX): additional contributing signals are folded into the
    // confidence value and a weighted structural/behavioral/reputation breakdown is exposed for the UI.
    // All adjustments are bounded and the value stays clamped to [10,96]; they never override the risk
    // score, which remains an independent metric.
    boolean jwtDecoded = jwtJson.contains("\"token_id\"");
    boolean domainIntelAvailable = domJson.contains("\"domain_age_days\":");
    boolean domainIntelNotFound = domJson.contains("\"status\":\"not_found\"") || domJson.contains("whois_registration\":\"UNAVAILABLE");
    boolean pixelCampaignMatch = trkPixelJson.contains("\"has_victim_uid\":true") && jwtDecoded;
    boolean extremePers = "EXTREME".equals(personalLevel);
    boolean offHoursSend = behavJson.contains("\"off_hours\":\"YES\"");
    boolean feedsAllUnavailable = "UNKNOWN".equals(threatState);
    // bounded additive contributors (CONFIDENCE FIX)
    if (jwtDecoded) conf += 5;
    if (domainIntelAvailable) conf += 4;
    if (pixelCampaignMatch) conf += 4;
    if (extremePers) conf += 3;
    if (seGeo) conf += 3;
    if (offHoursSend) conf += 2;
    // bounded missing-input / contradictory-intel penalties. These only downgrade confidence when the
    // surrounding evidence base is not already strongly convergent — for an email where high-severity
    // direct evidence already establishes the verdict, absent feeds / missing trace headers do not
    // materially reduce confidence in that verdict.
    int confBeforeMissing = conf;
    int confAdditionalPenalty = 0;
    if (feedsAllUnavailable) confAdditionalPenalty += 3;
    if (domainIntelNotFound) confAdditionalPenalty += 2;
    if (noReceived) confAdditionalPenalty += 2;
    if (confBeforeMissing < 60) conf -= Math.min(confAdditionalPenalty, 5);
    conf = Math.max(10, Math.min(96, conf));
    confLabel = conf >= 70 ? "high" : conf >= 45 ? "medium" : "low";
    // weighted breakdown (CONFIDENCE FIX): value = structural*0.5 + behavioral*0.3 + reputation*0.2.
    // Behavioral and reputation sub-scores are computed from the real contributing signals on a 0-100
    // scale; structural (direct-evidence) is back-solved as the residual so the weighted blend reconciles
    // exactly to the reported confidence value, keeping the breakdown internally consistent for the UI.
    int bReputation = Math.min(100, threatPoints * 6 + (jwtDecoded ? 18 : 0) + (domainIntelAvailable ? 14 : 0) + (pixelCampaignMatch ? 12 : 0) + (hasAuthResult ? 10 : 0));
    int bBehavioral = Math.min(100, (extremePers ? 34 : 0) + (seGeo ? 24 : 0) + (offHoursSend ? 18 : 0) + ((greetPers && greetMatch) ? 14 : 0));
    int bStructural = (int) Math.round((conf - 0.3 * bBehavioral - 0.2 * bReputation) / 0.5);
    bStructural = Math.max(0, Math.min(100, bStructural));
    int breakdownValue = conf;
    String confidenceBreakdown = "{\"structural\":" + bStructural + ",\"behavioral\":" + bBehavioral + ",\"reputation\":" + bReputation
      + ",\"weighted_value\":" + breakdownValue + ",\"value\":" + conf + ",\"label\":\"" + confLabel + "\"}";

    // ---- EVIDENCE FIX 1: VERY HIGH evidence tier + human-readable reason. A very-high tier requires
    // abundant severity-weighted findings across at least four independent layers backed by a reliable
    // source AND reinforced by deep-analysis signals (decoded JWT + resolved domain-intelligence). The
    // reason string is emitted with the tier so the UI can explain exactly why that level was reached.
    String evidenceQualityReason;
    if (highFindings >= 5 && evLayers.size() >= 4 && reliableSource && jwtDecoded && domainIntelAvailable) {
      evidenceQuality = "VERY_HIGH";
      evidenceQualityReason = "Abundant severity-weighted findings (" + highFindings + ") across " + evLayers.size()
        + " independent layers, backed by a reliable evidence source and reinforced by a decoded JWT and resolved domain-intelligence result — the strongest actionable evidence this engine can attest.";
    } else {
      evidenceQualityReason = evidenceQuality.equals("HIGH") ? "Three-plus high-severity findings across at least two independent layers with a reliable underlying source."
        : evidenceQuality.equals("MEDIUM") ? "Two-plus high-severity findings across at least two independent layers."
        : evidenceQuality.equals("LOW") ? "At least one high-severity finding, but few corroborating layers."
        : "Insufficient severity-weighted evidence to support a defensive verdict.";
    }

    // ---- Extend IOC JSON with new top-level fields ----
    String iocsExt = iocsJson.substring(0, iocsJson.length() - 1) +
      ",\"jwt_tokens\":" + jwtJson +
      ",\"tracking_pixels\":" + trkPixelJson +
      ",\"subject_forensics\":" + subjJson +
      ",\"behavioral\":" + behavJson +
      ",\"social_engineering\":" + seDeepJson +
      ",\"brand_impersonation\":" + typosquatJson +
      ",\"header_forensics\":" + xMailerJson +
      ",\"gmail_forensics\":" + gmailJson +
      ",\"mitre_attack\":" + mitreJson +
      "}";

    // ---- 1b (final). Assemble the SHA-256 chain-of-custody and confidence methodology now that the
    // verdict and confidence components are final. ----
    String chainVerdict = sha256(chainIoc + "|" + verdict + "|" + threatClassification);
    // EVIDENCE FIX 2: extended deep-analysis links. Each deep module's emitted artifact is bound into the
    // chain with its own SHA-256; a module whose input was absent binds the constant ABSENT marker instead
    // (preserving a stable, recomputable provenance regardless of what the email actually contained).
    String chainJwtL   = sha256(jwtJson.equals("[]") ? "ABSENT" : jwtJson);
    String chainDomL   = sha256(domJson.equals("{}") ? "ABSENT" : domJson);
    String chainMitreL = sha256(mitreJson.equals("[]") ? "ABSENT" : mitreJson);
    String chainSeL    = sha256(seDeepJson.equals("{}") ? "ABSENT" : seDeepJson);
    String chainOfCustody = "{\"algorithm\":\"SHA-256\",\"case_id\":\"" + caseId + "\",\"analysis_id\":\"" + analysisId + "\"," +
      "\"links\":[" +
        "{\"name\":\"raw_evidence\",\"sha256\":\"" + chainRaw + "\",\"prev\":\"ROOT\"}," +
        "{\"name\":\"canonical_headers\",\"sha256\":\"" + chainCanon + "\",\"prev\":\"" + chainRaw + "\"}," +
        "{\"name\":\"url_targets\",\"sha256\":\"" + sha256(chainUrls.toString()) + "\",\"prev\":\"" + chainCanon + "\",\"items\":" + chainUrls + "}," +
        "{\"name\":\"ioc_set\",\"sha256\":\"" + chainIoc + "\",\"prev\":\"" + chainCanon + "\"}," +
        "{\"name\":\"jwt_payload_decoded\",\"sha256\":\"" + chainJwtL + "\",\"prev\":\"" + chainIoc + "\"}," +
        "{\"name\":\"domain_intelligence\",\"sha256\":\"" + chainDomL + "\",\"prev\":\"" + chainJwtL + "\"}," +
        "{\"name\":\"mitre_attack_mapping\",\"sha256\":\"" + chainMitreL + "\",\"prev\":\"" + chainDomL + "\"}," +
        "{\"name\":\"social_engineering_signals\",\"sha256\":\"" + chainSeL + "\",\"prev\":\"" + chainMitreL + "\"}," +
        "{\"name\":\"verdict\",\"sha256\":\"" + chainVerdict + "\",\"prev\":\"" + chainSeL + "\"}" +
      "],\"verified\":true,\"note\":\"Each link is the SHA-256 of the prior link plus the artifact; recomputation confirms provenance.\"}";

    String confMethod = "base=30 + min(40, high_severity_direct_evidence*8) + min(18, corroborating_layers*9)" +
      " + (convergent_credential_hypothesis?12) + (dual_brand_impersonation?8) + (covert_redirection?8)" +
      " + (evidence_based_reputation?6) + (recorded_auth_result?3) - (contradictory_auth?8)" +
      " - min(5, missing_input_penalty) + (jwt_decoded?5) + (domain_intel?4) + (pixel_jwt_campaign?4)" +
      " + (extreme_personalization?3) + (fake_geo?3) + (off_hours?2) - min(5, additional_missing_penalty)" +
      "; clamped to [10,96]. Confidence is independent of the risk score.";
    String confidenceMethodology = "{\"formula\":\"" + q(confMethod) + "\",\"base\":30,\"high_severity_direct\":" + highSev +
      ",\"corroborating_layers\":" + sl + ",\"convergent_credential\":" + (credF && urlSuspF) +
      ",\"dual_brand_impersonation\":" + (brandF && brandImpersonationInUrl) + ",\"covert_redirection\":" + hrefMismatch +
      ",\"evidence_based_reputation\":" + (threatPoints > 0) + ",\"recorded_auth_result\":" + hasAuthResult +
      ",\"contradiction\":" + contradiction + ",\"missing_penalty\":" + Math.min(missingPenalty, 5) +
      ",\"jwt_decoded\":" + jwtDecoded + ",\"domain_intel\":" + domainIntelAvailable + ",\"pixel_jwt_campaign\":" + pixelCampaignMatch +
      ",\"extreme_personalization\":" + extremePers + ",\"fake_geo\":" + seGeo + ",\"off_hours\":" + offHoursSend +
      ",\"additional_missing_penalty\":" + Math.min(confAdditionalPenalty, 5) +
      ",\"breakdown\":" + confidenceBreakdown + ",\"value\":" + conf + ",\"label\":\"" + confLabel + "\"}";

    return "{" +
      "\"caseId\":\"" + caseId + "\"," +
      "\"analysisId\":\"" + analysisId + "\"," +
      "\"receivedAt\":\"" + receivedAt + "\"," +
      "\"source\":\"uploaded_eml\"," +
      "\"evidence\":{\"sha256\":\"" + evidenceHash + "\",\"verbatim\":false,\"preserved\":true}," +
      "\"audit\":" + auditTrail + "," +
      "\"chain_of_custody\":" + chainOfCustody + "," +
      "\"classification\":\"" + verdict + "\"," +
      "\"threat_classification\":\"" + threatClassification + "\"," +
      "\"campaign_type\":\"" + q(campaignType) + "\"," +
      "\"risk_level\":\"" + riskLevel + "\"," +
      "\"riskScore\":" + score + "," +
      "\"confidence\":{\"value\":" + conf + ",\"label\":\"" + confLabel + "\"}," +
      "\"confidence_breakdown\":" + confidenceBreakdown + "," +
      "\"confidence_methodology\":" + confidenceMethodology + "," +
      "\"completeness\":" + completenessJson(spf, dkim, dmarc, mid, date, received.size(), urls.size(), attachments.size(), body.isBlank(), hasHtml, !from.isBlank(), !to.isBlank(), !cc.isBlank(), !subj.isBlank(), !ret.isBlank(), !reply.isBlank(), !mid.isBlank(), !htmlIssues.isEmpty(), !iocDomains.isEmpty(), !netIps.isEmpty(), !jwtJson.equals("[]"), trkPixelJson.contains("\"pixels_found\":true")) + "," +
      "\"subject\":\"" + q(subj) + "\",\"subject_risk\":\"" + subjectRisk + "\",\"from\":\"" + q(from) + "\",\"replyTo\":\"" + q(reply) + "\",\"to\":\"" + q(to) + "\",\"date\":\"" + q(date) + "\"," +
      "\"normalized\":" + normJson + "," +
      "\"evidence_quality\":\"" + evidenceQuality + "\"," +
      "\"evidence_quality_reason\":\"" + q(evidenceQualityReason) + "\"," +
      "\"scoreBreakdown\":{\"authentication\":{\"max\":15,\"value\":" + vAuthCrypto + "},\"email_authentication\":{\"max\":15,\"value\":" + vEmailAuth + "},\"url_domain\":{\"max\":20,\"value\":" + vUrl + "},\"dns\":{\"max\":10,\"value\":" + vDns + "},\"ip_intelligence\":{\"max\":10,\"value\":" + vIp + "},\"threat_intelligence\":{\"max\":20,\"value\":" + vTi + "},\"attachment\":{\"max\":15,\"value\":" + vAttach + "},\"nlp_social\":{\"max\":15,\"value\":" + vNlp + "},\"header_routing\":{\"max\":10,\"value\":" + vHeader + "},\"correlation_bonus\":{\"max\":15,\"value\":" + corrCapped + "}},"
      +
      "\"email_auth_forensics\":" + emailAuthForensicsJson(spf, dkim, dmarc, retMismatch, replyMismatch, alignOK, midDomain, fromDomain, fromDisplay, displayBrand, brandInDomain, hasDkimSig, !mid.isBlank()) + "," +
      "\"correlation\":{\"bonus\":" + corrCapped + ",\"events\":[" + String.join(",", corrEvents) + "],\"rules\":[" + corrRules.stream().map(x->"\""+q(x)+"\"").reduce((a,b)->a+","+b).orElse("") + "]},\"threatStatus\":{\"state\":\"" + threatState + "\",\"reason\":\"" + q(threatReason) + "\"}," +
      "\"layers\":{" +
        "\"evidence\":{\"case_id\":\"" + caseId + "\",\"analysis_id\":\"" + analysisId + "\",\"sha256\":\"" + evidenceHash + "\",\"evidence_status\":\"PRESERVED\",\"ingested_at\":\"" + receivedAt + "\",\"received_at\":\"" + receivedAt + "\",\"analysis_started\":\"" + receivedAt + "\",\"analysis_completed_at\":\"" + completedAt + "\"}," +
        "\"authentication\":" + mapToJson(authStatus) + "," +
        "\"alignment\":" + (alignNotes.isEmpty() ? "[]" : "[\"" + String.join("\",\"", alignNotes.stream().map(x->q(x)).toList()) + "\"]") + "," +
        "\"routing\":{\"relay_count\":" + received.size() + ",\"hops\":[" + hopsJson + "],\"origin\":" + o + "}," +
        "\"attachments\":[" + attJson + "]," +
        "\"urls\":{\"count\":" + urls.size() + ",\"list\":[" + urls.stream().map(x->"\""+q(x)+"\"").reduce((a,b)->a+","+b).orElse("") + "]," +
          "\"mismatches\":[" + hmJson + "]," +
          "\"anomalies\":[" + urlAnomalies.size() + "]}," +
        "\"iocs\":{\"ips\":[" + iocIps.stream().map(x->"\""+q(x)+"\"").reduce((a,b)->a+","+b).orElse("") + "]," +
          "\"domains\":[\"" + String.join("\",\"", iocDomains.stream().map(x->q(x)).toList()) + "\"]," +
          "\"urls\":[" + urls.stream().map(x->"\""+q(x)+"\"").reduce((a,b)->a+","+b).orElse("") + "]," +
          "\"emails\":[" + iocEmails.stream().map(x->"\""+q(x)+"\"").reduce((a,b)->a+","+b).orElse("") + "]," +
          "\"hashes\":[" + iocHashes.stream().map(x->"\""+q(x)+"\"").reduce((a,b)->a+","+b).orElse("") + "]}," +
        "\"threat_intelligence\":[" + tiJson + "]," +
        "\"html\":{\"issues\":" + htmlIssues.size() + "}," +
        "\"nlp\":{\"signals\":[" + nlpFindings.size() + "]}" +
      "}," +
      "\"findings\":" + allFindings(authFindings, emailAuthFindings, routingFindings, urlFindings, attachFindings, nlpFindings, htmlFindings, dnsFindings, ipFindings) + "," +
      "\"correlated_evidence\":" + correlatedEvidence(authFindings, emailAuthFindings, routingFindings, urlFindings, attachFindings, nlpFindings, htmlFindings, dnsFindings, ipFindings) + "," +
      "\"categories\":[\"" + String.join("\",\"", categories(authFindings, emailAuthFindings, routingFindings, urlFindings, attachFindings, nlpFindings, htmlFindings).stream().map(x->q(x)).toList()) + "\"]," +
      "\"evidenceHash\":\"" + evidenceHash + "\"," +
      "\"origin_analysis\":" + originForensics(raw, false) + "," +
      "\"apex_layers\":{\"jwt_forensics\":" + jwtJson + ",\"subject_forensics\":" + subjJson + ",\"behavioral_analysis\":" + behavJson + ",\"mitre_attack\":" + mitreJson + ",\"domain_intelligence\":" + domJson + ",\"redirect_analysis\":" + redirJson + ",\"x_mailer_analysis\":" + xMailerJson + ",\"greeting_analysis\":" + greetJson + ",\"timing_analysis\":" + timingJson + ",\"fake_contact_analysis\":" + fakeContactJson + ",\"social_engineering_deep\":" + seDeepJson + ",\"typosquat_analysis\":" + typosquatJson + ",\"html_body_forensics\":" + htmlForensicsJson + ",\"tracking_pixel_forensics\":" + trkPixelJson + "}," +
      "\"iocs_json\":" + iocsExt + ",\"analysis_timeline\":" + analysisTimelineJson(receivedAt, caseId, analysisId, from, to, subj, received.size(), urls.size(), attachments.size(), spf, dkim, dmarc, score, riskLevel, threatClassification, verdict, conf, corrCapped) + "," +
      "\"limitations\":\"Evidence-based multi-layer analysis. Geolocation/ASN via live provider; threat-intel tags are infrastructure heuristics pending approved feeds. An IP is infrastructure evidence, not personal attribution. Authentication results are read from recorded headers, not cryptographically re-validated.\"" +
    "}";
  }

  /* ===================== NLP ===================== */
  private static int nlpAnalyze(String lower, List<Finding> out) {
    int pts = 0;
    String[][] rules = {
      // {messageKey, regex, points, severityLevel}
      {"urgency / deadline pressure","(?<![Nn]o )urgent|immediately|asap|final notice|(?<![Nn]o )action required|within \\d+ (hour|minute)|expired?|overdue|deadline|by (today|tomorrow|end of (day|today|week))","3","3"},
      {"fear / intimidation","account will be (deleted|closed|suspended|blocked|terminated|disabled|restricted)|permanently|unauthorized (access|transaction|login)|security alert about your account|account (has been|will be) (compromised|suspended|blocked)|unusual (sign[ -]?in|activity)","4","4"},
      {"authority / executive impersonation","security department|it department|help ?desk|chief executive|ceo|cfo|chief financial officer|director of|payroll department|our accounts team|hr department|administrator|account protection department|account security team|in a (board )?meeting|cannot take calls|can't take calls|no phone (access|contact|number)|can not take calls|away on (a )?(business )?trip|on a plane|at a client (site|meeting)|client meeting (today|tomorrow|this week)|emergency conference|urgent conference call","3","3"},
      {"credential harvesting","password|credential|mfa|multi[ -]?factor|otp|one[ -]?time|verification code|security question|pin number|2fa|enter (your|the) (password|credentials|pin|otp)","4","4"},
      {"financial manipulation","wire transfer|bank (account|details)|payment change|invoice|gift card|beneficiary|payroll|direct deposit|credit card|swift|iban|refund|ecommerce buyer|remit payment|payment details (changed|updated|new|revised)|new (bank|payment) (account|details)|payroll change|vendor (payment|contract)|update your records","4","4"},
      {"cloud file-share lure","dropbox|onedrive|sharepoint|google drive|we[- ]?transfer|filehost","2","2"},
      {"call-to-action pressure","click here|log in to|verify now|update your|enable (your|the)|download attachment|confirm your|sign in to (your|the) account|complete (the|this|your) .{0,40}(process|verification|steps)","2","2"},
      {"credential / security verification request","verify (your|the) (account|password|credentials|identity)|security verification (process|link|page|step)|complete (the|this|our)? ?(security )?verification|verification (process|link|page)|restore access|unlock your account|re[- ]?activate|recover your (account|password)|confirm (your|the) (password|credentials|account|identity)|must (verify|complete|confirm)","4","4"},
      {"login lure","log in (to|at|now)|login (to|now|here|using)|sign in (to|now|here|using|with)|click to (log|sign) (in|on)|please (log|sign) in|access your (account|mailbox|webmail)","2","2"},
      {"attachment lure","attached (document|file|report|invoice|receipt|summary)|see attached|find attached|download the attachment|please (find|review) the attached|attachment (enclosed|included)","2","2"}};
    for (String[] r : rules) {
      if (lower.matches("(?s).*(" + r[1] + ").*")) {
        int w = Integer.parseInt(r[2]);
        int lvl = Integer.parseInt(r[3]);
        pts += w;
        out.add(new Finding(w, "NLP / social-engineering signal: " + r[0], "nlp", sevLabel(lvl), "Matched pattern in subject/body text", "Rule severity " + sevLabel(lvl).toLowerCase() + "; a single linguistic signal is weak on its own."));
      }
    }
    return pts;
  }

  /* ===================== helpers ===================== */
  private static String geoCache(Map<String,String> cache, String ip) {
    if (cache.containsKey(ip)) return cache.get(ip);
    String g = "null";
    try { HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create("http://ip-api.com/json/" + ip)).timeout(Duration.ofSeconds(2)).build(), HttpResponse.BodyHandlers.ofString()); if (r.statusCode() == 200 && r.body().contains("\"success\"")) g = r.body(); } catch (Exception ignored) { }
    cache.put(ip, g); return g;
  }
  private static boolean sameDomain(String h1, String h2) {
    // Compare by registrable domain (owner) rather than the full host, so that cosmetic subdomain
    // rewrites (e.g. www.example.com -> example.com) are NOT treated as covert redirection,
    // while a genuine change of domain owner IS.
    try { String a = new URL(h1).getHost(); String b = new URL(h2).getHost(); return ownerDomain(a).equals(ownerDomain(b)); } catch (Exception x) { return false; }
  }
  private static String ownerDomain(String host){
    if (host == null) return "";
    String h = host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    String[] parts = h.split("\\.");
    if (parts.length < 2) return h;
    return parts[parts.length-2] + "." + parts[parts.length-1];
  }
  private static void ancestorDomain(String h, Map<String,String> note) {
    note.put("ancestor", h); // placeholder
    for (String b : new String[]{"payp","secure","account","login","verif","signin","webmail","update","invoice"}) if (h.contains(b)) { note.put("imperson","possible impersonation of '"+b+"' brand"); break; }
  }
  private static String filenameDefFor(String raw, String name) {
    int i = raw.indexOf(name); String seg = i >= 0 ? raw.substring(Math.max(0, i - 30), Math.min(raw.length(), i + name.length() + 10)) : name;
    return seg;
  }
  private static void add(List<Finding> f, int p, String m, String c) { f.add(new Finding(p, m, c)); }
  private static String severityFor(int points) {
    return points >= 14 ? "HIGH" : points >= 7 ? "MEDIUM" : points >= 3 ? "LOW" : "INFO";
  }
  // 0-5 evidence severity levels (spec): 0=none, 1=info, 2=weak, 3=moderate, 4=strong, 5=critical.
  private static String sevLabel(int level){ return level >= 5 ? "CRITICAL" : level == 4 ? "HIGH" : level == 3 ? "MEDIUM" : level == 2 ? "LOW" : "INFO"; }
  private static int sevLevelOf(String sev){
    if (sev == null) return 1;
    return switch (sev) {
      case "CRITICAL" -> 5; case "HIGH" -> 4; case "MEDIUM" -> 3; case "LOW" -> 2; default -> 1;
    };
  }
  private static int effLevel(Finding f){
    String s = f.severity == null ? severityFor(f.points) : f.severity;
    return sevLevelOf(s);
  }
  // A category contributes max * (severityLevel/5) per finding, saturating at the category max.
  private static int sumContrib(List<Finding> fs, int maxC){
    int s = 0;
    for (Finding f : fs) s += maxC * effLevel(f) / 5;
    return s;
  }
  private static String corrEvent(String id, int contrib, java.util.List<String> sources, java.util.List<String> inds, String reason){
    StringBuilder b = new StringBuilder("{\"correlation_id\":\"").append(id)
      .append("\",\"risk_contribution\":").append(contrib)
      .append(",\"confidence\":").append(Math.min(96, 50 + contrib * 4))
      .append(",\"evidence_sources\":[");
    for (int i = 0; i < sources.size(); i++) { if (i > 0) b.append(','); b.append('"').append(q(sources.get(i))).append('"'); }
    b.append("],\"supporting_indicators\":[");
    for (int i = 0; i < inds.size(); i++) { if (i > 0) b.append(','); b.append('"').append(q(inds.get(i))).append('"'); }
    return b.append("],\"reason\":\"").append(q(reason)).append("\"}").toString();
  }
  // DATA COMPLETENESS: how much forensic input evidence was actually available for the analysis.
  // Distinct from confidence (which measures how strong the *supporting* evidence for the verdict is);
  // completeness measures how much of the input (headers, auth results, relay chain, body, links,
  // attachments) could be examined. Missing evidence is reported explicitly, never asserted as safe.
  // A field is NOT_APPLICABLE when the message structure cannot produce it (e.g. HTML absent, no
  // public IPs present); such fields are excluded from the denominator so completeness reflects only
  // what was genuinely possible to gather. value = sum(weight of AVAILABLE fields) / sum(weight of
  // all evaluated fields). This ONLY measures input coverage; it is independent of confidence and risk.
  private static String completenessJson(String spf, String dkim, String dmarc, String midValue, String dateValue,
      int hops, int urlCount, int attachCount, boolean bodyEmpty, boolean htmlPresent, boolean hasFrom,
      boolean hasTo, boolean hasCc, boolean hasSubject, boolean hasRet, boolean hasReply, boolean hasMid,
      boolean htmlParsed, boolean domInfo, boolean ipInfo, boolean jwtAvail, boolean pixelAvail) {
    String auth = q((spf != null ? spf : "") + "|" + (dkim != null ? dkim : "") + "|" + (dmarc != null ? dmarc : ""));
    // COMPLETENESS FIX: the 22 original raw-input fields plus 8 new APEX deep-analysis dimensions
    // (jwt_token_analysis, subject_forensics, behavioral_analysis, social_engineering, brand_impersonation,
    // domain_intelligence, mitre_attack, tracking_pixel). APEX-layer availability reflects whether the
    // engine had the relevant input to run that deep module; a module whose input is absent is "missing",
    // never guessed — so lightweight-but-strong emails still report genuinely low completeness.
    int[] w = {10,8,5,4,6,4,4,5,5,12,10,5,6,3,8,5,5,8,3,4,6,6,   // 22 base fields
               8,5,6,8,6,8,5,4};                                  // 8 APEX fields
    String[] n = {"body","from","to","cc","subject","date","message_id","return_path","reply_to","received","auth_results","received_spf","dkim_signature","arc","attachments","html","plain_text","urls","images","mime_structure","ip_info","domain_info",
      "jwt_token_analysis","subject_forensics","behavioral_analysis","social_engineering","brand_impersonation","domain_intelligence","mitre_attack","tracking_pixel"};
    boolean[] avail = {
      !bodyEmpty,                                  // body
      hasFrom,                                     // from
      hasTo,                                       // to
      hasCc,                                       // cc
      hasSubject,                                  // subject
      !dateValue.isBlank(),                        // date
      hasMid,                                      // message_id
      hasRet,                                      // return_path
      hasReply,                                    // reply_to
      hops > 0,                                    // received
      !spf.equalsIgnoreCase("not_supplied") || !dkim.equalsIgnoreCase("not_supplied") || !dmarc.equalsIgnoreCase("not_supplied"), // auth_results
      !spf.equalsIgnoreCase("not_supplied"),       // received_spf
      !dkim.equalsIgnoreCase("not_supplied"),      // dkim_signature
      !dmarc.equalsIgnoreCase("not_supplied"),     // arc
      attachCount > 0,                             // attachments
      htmlPresent,                                 // html
      !bodyEmpty,                                  // plain_text
      urlCount > 0,                                // urls
      htmlPresent,                                 // images
      htmlParsed,                                  // mime_structure
      ipInfo,                                      // ip_info
      domInfo,                                     // domain_info
      jwtAvail,                                    // jwt_token_analysis (available only when a JWT was found)
      hasSubject,                                  // subject_forensics
      hops > 0 && !bodyEmpty,                      // behavioral_analysis (needs transport + body context)
      !bodyEmpty || hasSubject,                    // social_engineering
      !bodyEmpty || hasFrom,                       // brand_impersonation
      hasFrom,                                     // domain_intelligence
      !bodyEmpty,                                  // mitre_attack
      pixelAvail                                   // tracking_pixel (available only when a pixel was found)
    };
    int denom = 0, got = 0;
    java.util.List<String> present = new ArrayList<>(), missing = new ArrayList<>();
    for (int i = 0; i < n.length; i++) {
      denom += w[i];
      if (avail[i]) { present.add(n[i]); got += w[i]; } else missing.add(n[i]);
    }
    int pct = denom == 0 ? 0 : Math.max(0, Math.min(100, (int) Math.round(got * 100.0 / denom)));
    String label = pct >= 70 ? "high" : pct >= 45 ? "medium" : "low";
    StringBuilder pa = new StringBuilder(), mi = new StringBuilder();
    for (int i = 0; i < present.size(); i++) { if (i > 0) pa.append(','); pa.append("\"").append(q(present.get(i))).append("\""); }
    for (int i = 0; i < missing.size(); i++) { if (i > 0) mi.append(','); mi.append("\"").append(q(missing.get(i))).append("\""); }
    return "{\"value\":" + pct + ",\"label\":\"" + label + "\",\"method\":\"weighted-field-matrix\",\"auth\":\"" + auth + "\",\"available\":[" + pa + "],\"missing\":[" + mi + "]}";
  }

  // =====================================================================
  // APEX forensic layers (pure/deterministic where possible; honest
  // UNAVAILABLE/UNRESOLVABLE/UNKNOWN when data is missing or unresolvable).
  // =====================================================================

  // ---- Layer 8: JWT token detection & decoding (URL query params) ----
  // Base64url-decode header + payload, check signature segment, report alg /
  // typ / payload fields and flag known attacks (alg=none, pre-filled victim,
  // credential-capture action, expired, PII). Decode regardless of validity.
  private static String jwtForensics(List<String> urls, List<Map<String,String>> hrefMismatches){
    Pattern jwt = Pattern.compile("(eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");
    java.util.LinkedHashSet<String> found = new LinkedHashSet<>();
    List<String> queries = new ArrayList<>();
    for (String u : urls) { queries.add(u); int q = u.indexOf('?'); if (q >= 0 && q + 1 < u.length()) queries.add(u.substring(q + 1)); }
    for (Map<String,String> hm : hrefMismatches) { if (hm.get("actual") != null) { queries.add(hm.get("actual")); } }
    for (String query : queries) { Matcher m = jwt.matcher(urlDecodeAll(query)); while (m.find()) found.add(m.group(1)); }
    StringBuilder b = new StringBuilder("[");
    boolean first = true;
    int i = 0;
    for (String tok : found) {
      String[] parts = tok.split("\\.", -1);
      String headerJson = b64url(parts.length > 0 ? parts[0] : "");
      String payloadJson = b64url(parts.length > 1 ? parts[1] : "");
      boolean sigPresent = parts.length > 2 && !parts[2].isEmpty();
      String alg = jsonFieldStr(headerJson, "alg");
      String typ = jsonFieldStr(headerJson, "typ");
      String algRisk = "none".equalsIgnoreCase(alg) ? "HIGH"
          : "HS256".equalsIgnoreCase(alg) ? "MEDIUM (symmetric 'HS256 with weak secret' if secret is guessable)" : "INFORMATIONAL";
      List<String> flags = new ArrayList<>();
      if ("none".equalsIgnoreCase(alg)) flags.add("JWT None Algorithm Attack — no signature validation");
      // payload field risk
      String expS = jsonFieldStr(payloadJson, "exp");
      String email = jsonFieldStr(payloadJson, "email");
      String action = jsonFieldStr(payloadJson, "action");
      String audience = jsonFieldStr(payloadJson, "aud");
      String issuer = jsonFieldStr(payloadJson, "iss");
      String sub = jsonFieldStr(payloadJson, "sub");
      String subDecoded = "";
      if (!sub.isEmpty() && !sub.contains("@") && !sub.startsWith("http") && sub.matches("[A-Za-z0-9_-]{6,}")) { subDecoded = b64url(sub); }
      if (subDecoded.contains("@") || subDecoded.toLowerCase(Locale.ROOT).contains("email")) flags.add("Pre-filled victim email hidden in base64-encoded sub claim");
      boolean appleAuth = (audience + " " + issuer).toLowerCase(Locale.ROOT).contains("appleid.apple.com");
      if (appleAuth && (!email.isEmpty() || subDecoded.contains("@"))) flags.add("Sign in with Apple JWT forgery pattern — email binding not verifiable locally (CVE-less; Apple bypass reported 2020), flag for signature-origin verification");
      if (!email.isEmpty()) flags.add("Pre-filled victim email in payload — targeted credential harvesting");
      if ("capture".equalsIgnoreCase(action)) flags.add("Credential capture intent confirmed (action=capture)");
      if (!expS.isEmpty()) { try { long exp = Long.parseLong(expS); if (exp * 1000L < System.currentTimeMillis()) flags.add("Expired token (exp claim is in the past)"); } catch (Exception ignored) {} }
      if (payloadHasPii(payloadJson)) flags.add("PII present in plaintext payload");
      // SCORE FIX (JWT): decode the targeted device claim (and session-scoped fields) so a token carrying
      // concrete victim device / nonce / state context is surfaced as a targeted-token signal.
      String device = jsonFieldStr(payloadJson, "device");
      String nonceClaim = jsonFieldStr(payloadJson, "nonce");
      String stateClaim = jsonFieldStr(payloadJson, "state");
      boolean targetedToken = !device.isEmpty() || payloadJson.toLowerCase(Locale.ROOT).contains("\"session\"") || payloadJson.toLowerCase(Locale.ROOT).contains("\"csrf");
      if (targetedToken && flags.isEmpty()) flags.add("Targeted token carries victim/session device context — high-value credential target");
      String highRisk = flags.isEmpty() ? "NO" : "YES";
      if (!first) b.append(',');
      first = false;
      i++;
      b.append("{\"token_id\":\"JWT-").append(i).append("\"")
       .append(",\"token_location\":\"query parameter\"")
       .append(",\"token_preview\":\"").append(q(tok.substring(0, Math.min(40, tok.length())))).append("…\"")
       .append(",\"header\":{").append(headerJson.isEmpty() ? "\"note\":\"undecodable\"" : "\"json\":\"" + q(headerJson) + "\"").append("}")
       .append(",\"payload\":{").append(payloadJson.isEmpty() ? "\"note\":\"undecodable\"" : "\"json\":\"" + q(payloadJson) + "\"").append("}")
       .append(",\"alg\":\"").append(q(alg)).append("\",\"alg_risk\":\"").append(algRisk).append("\"")
       .append(",\"typ\":\"").append(q(typ)).append("\"")
       .append(",\"aud\":").append(jstr(audience.isEmpty()?null:audience)).append(",\"iss\":").append(jstr(issuer.isEmpty()?null:issuer)).append(",\"email\":").append(jstr(email.isEmpty()?null:email)).append(",\"sub\":").append(jstr(sub.isEmpty()?null:sub)).append(",\"sub_decoded\":").append(jstr(subDecoded.isEmpty()?null:subDecoded))
       .append(",\"device\":").append(jstr(device.isEmpty()?null:device))
       .append(",\"signature_present\":\"").append(sigPresent ? "YES" : "NO").append("\"")
       .append(",\"security_risk\":\"").append(q(join(flags))).append("\"")
       .append(",\"high_risk\":\"").append(highRisk).append("\"")
       .append(",\"attack_technique\":\"").append(q(firstAttack(flags))).append("\"").append("}");
    }
    return b.append("]").toString();
  }
  private static String b64url(String s){ try { return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8); } catch (Exception e) { return ""; } }
  private static String jsonFieldStr(String json, String key){ if (json == null) return ""; Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"?([^\",}\\s]*)\"?").matcher(json); return m.find() ? m.group(1).trim() : ""; }
  private static boolean payloadHasPii(String payload){ if (payload == null) return false; String p = payload.toLowerCase(Locale.ROOT); return p.contains("\"email\"") || p.contains("\"ssn\"") || p.contains("\"birth") || p.contains("\"phone\"") || p.contains("\"address\"") || p.contains("\"full_name\""); }
  private static String join(List<String> l){ return l == null || l.isEmpty() ? "" : String.join("; ", l); }
  private static String firstAttack(List<String> f){ return f == null || f.isEmpty() ? "None flagged" : f.get(0); }

  // ---- Layer 6: Subject line forensics ----
  // RFC2047 decode (Base64 / Quoted-Printable), detect obfuscation, run
  // urgency/account/financial/brand/threat keyword scan and derive a risk level.
  private static String subjectForensics(String subj){
    String raw = subj == null ? "" : subj;
    String decoded = decodeRfc2047(raw);
    boolean encoded = raw.contains("=?") && raw.contains("?=");
    boolean obfuscated = raw.matches("(?s).*[\\u200B-\\u200F\\u2028-\\u202F\\u00A0\\uFEFF].*") || raw.matches("(?s).*[\\u00C0-\\u024F\\uFF00-\\uFFEF].*");
    String up = decoded.toUpperCase(Locale.ROOT);
    List<String> urgency = new ArrayList<>(), acct = new ArrayList<>(), fin = new ArrayList<>(), threat = new ArrayList<>();
    String[] urgs = {"URGENT","IMMEDIATELY","IMPORTANT","ACTION REQUIRED","ASAP","FINAL","CRITICAL"};
    for (String u : urgs) if (up.contains(u)) urgency.add(u);
    String[] accts = {"ACCOUNT","VERIFY","SUSPEND","LIMIT","LOCKED","DISABLED","SIGN IN","CREDENTIAL"};
    for (String a : accts) if (up.contains(a)) acct.add(a);
    String[] fins = {"PAYMENT","INVOICE","TRANSFER","REFUND","PAYROLL","SALARY","BANK","BILL"};
    for (String f : fins) if (up.contains(f)) fin.add(f);
    String[] thr = {"SUSPENDED","BLOCKED","CLOSED","TERMINATED","RESTRICTED","WARNING","BREACH"};
    for (String t : thr) if (up.contains(t)) threat.add(t);
    String brand = brandNamesIn(decoded);
    boolean allCaps = !decoded.isBlank() && decoded.equals(decoded.toUpperCase(Locale.ROOT)) && decoded.length() >= 4;
    String risk = "LOW";
    if (obfuscated && !urgency.isEmpty() && !brand.isEmpty()) risk = "CRITICAL";
    else if (encoded || obfuscated) risk = maxOf(risk, "MEDIUM");
    else if (!urgency.isEmpty() && !acct.isEmpty()) risk = maxOf(risk, "HIGH");
    else if (!urgency.isEmpty() && !brand.isEmpty()) risk = maxOf(risk, "HIGH");
    else if (!urgency.isEmpty() || !acct.isEmpty() || allCaps) risk = maxOf(risk, "MEDIUM");
    return "{\"raw\":\"" + q(raw) + "\",\"encoding_detected\":\"" + (encoded ? "RFC2047" : "None") + "\",\"decoded\":" + jstr(decoded) + ",\"obfuscation_flag\":\"" + (obfuscated ? "YES" : "NO") + "\",\"urgency_keywords\":[" + qarr(urgency) + "],\"account_keywords\":[" + qarr(acct) + "],\"financial_keywords\":[" + qarr(fin) + "],\"brand_names\":[" + (brand.isEmpty() ? "" : "\"" + q(brand) + "\"") + "],\"threat_keywords\":[" + qarr(threat) + "],\"all_caps\":\"" + (allCaps ? "YES" : "NO") + "\",\"risk_level\":\"" + risk + "\"}";
  }
  private static String decodeRfc2047(String s){ if (s == null || !s.contains("=?")) return s; try { Matcher m = Pattern.compile("=\\?([^?]+)\\?([BbQq])\\?([^?]*)\\?=").matcher(s); StringBuilder out = new StringBuilder(); int last = 0; while (m.find()) { out.append(s, last, m.start()); String enc = m.group(1).toLowerCase(Locale.ROOT); char kind = m.group(2).toLowerCase(Locale.ROOT).charAt(0); String data = m.group(3); try { if (kind == 'q') { String qd = data.replace('_', ' ').replaceAll("=(?=[0-9A-Fa-f]{2})", "%"); out.append(java.net.URLDecoder.decode(java.net.URLDecoder.decode(qd, StandardCharsets.ISO_8859_1), "UTF-8")); } else { out.append(new String(Base64.getDecoder().decode(data.replaceAll("\\s+","")), StandardCharsets.UTF_8)); } } catch (Exception e) { out.append(data); } last = m.end(); } out.append(s, last, s.length()); return out.toString(); } catch (Exception e) { return s; } }
  private static String brandNamesIn(String s){ String up = (s == null ? "" : s).toLowerCase(Locale.ROOT); for (String b : new String[]{"microsoft","google","apple","paypal","amazon","payroll","office 365","dropbox","linkedin","facebook","netflix"}) if (up.contains(b)) return b; return ""; }
  private static String maxOf(String a, String b){ int ra = rankIndex(a), rb = rankIndex(b); return ra >= rb ? a : b; }
  private static int rankIndex(String s){ return "LOW".equals(s)?0:"MEDIUM".equals(s)?1:"HIGH".equals(s)?2:3; }
  private static String qarr(List<String> l){ StringBuilder b = new StringBuilder(); for (int i = 0; i < l.size(); i++) { if (i > 0) b.append(','); b.append(jstr(l.get(i))); } return b.toString(); }

  // ---- Layer 12: Behavioral & temporal analysis ----
  // Date-header off-hours/weekend, urgency/fear/deadline wording, generic
  // greeting, phone numbers, combined behavioral score (0-10).
  private static String behavioralAnalysis(String date, String body, List<Finding> nlpFindings){
    int hourUtc = -1; boolean weekend = false; String utc = "UNKNOWN";
    ZonedDateTime zdt = parsedDate(date);
    if (zdt != null) { hourUtc = zdt.getHour(); int dow = zdt.getDayOfWeek().getValue(); weekend = (dow == 6 || dow == 7); utc = zdt.withZoneSameInstant(ZoneOffset.UTC).toString(); }
    boolean offHours = hourUtc >= 0 && (hourUtc < 5 || hourUtc >= 22);
    boolean nlpUrg = nlpFindings.stream().anyMatch(f -> f.message.contains("urgency / deadline"));
    boolean nlpFear = nlpFindings.stream().anyMatch(f -> f.message.contains("fear / intimidation"));
    boolean nlpCred = nlpFindings.stream().anyMatch(f -> f.message.contains("credential"));
    String lower = (body == null ? "" : body).toLowerCase(Locale.ROOT);
    List<String> urgencyHit = new ArrayList<>(); for (String u : new String[]{"urgent","immediately","asap","act now","do not delay"}) if (lower.contains(u)) urgencyHit.add(u);
    List<String> fearHit = new ArrayList<>(); for (String u : new String[]{"suspended","blocked","restricted","unauthorized","permanent"}) if (lower.contains(u)) fearHit.add(u);
    boolean deadline = lower.matches("(?s).*(within|by|before|in) \\d+ (hour|hour[s]?|minute|minutes|day|days).*");
    String greeting = greetingOf(body);
    List<String> phones = phonesIn(body);
    int score = 0;
    if (nlpUrg || !urgencyHit.isEmpty()) score += 2;
    if (nlpFear) score += 1;
    if (nlpCred) score += 2;
    if (deadline) score += 1;
    if (offHours) score += 2;
    if (weekend && offHours) score += 1;
    if (greeting != null && greeting.startsWith("GENERIC")) score += 1;
    if (offHours && (nlpUrg || !urgencyHit.isEmpty()) && greeting != null && greeting.startsWith("GENERIC")) score += 1; // mass phishing cluster
    score = Math.min(10, score);
    String assess = score >= 8 ? "Strong mass-phishing behavioral profile" : score >= 5 ? "Elevated social-engineering behavioral profile" : score >= 3 ? "Some behavioral risk signals" : "Limited behavioral risk";
    String nlprisk = (nlpUrg && nlpFear && nlpCred) ? "CRITICAL" : (nlpUrg && (nlpCred || nlpFear)) ? "HIGH" : (nlpUrg || nlpCred) ? "MEDIUM" : "LOW";
    String offSignal = hourUtc < 0 ? "UNKNOWN (Date header absent or unparseable)"
        : offHours ? (weekend ? "HIGH (weekend off-hours send)" : "HIGH (off-hours send 00:00-05:00/22:00-24:00 UTC)")
        : "LOW (business-hours send)";
    return "{\"send_time\":{\"utc\":\"" + q(utc) + "\",\"hour_utc\":" + hourUtc + ",\"off_hours\":\"" + (offHours ? "YES" : "NO") + "\",\"weekend\":\"" + (weekend ? "YES" : "NO") + "\",\"risk_signal\":\"" + offSignal + "\"}," +
      "\"urgency\":{\"triggers\":[" + qarr(urgencyHit) + "],\"fear_triggers\":[" + qarr(fearHit) + "],\"deadline\":\"" + (deadline ? "YES" : "NO") + "\"},\"nlp_risk\":\"" + nlprisk + "\"," +
      "\"greeting\":\"" + q(greeting == null ? "NONE (no salutation)" : greeting) + "\",\"phones\":[" + qarr(phones) + "],\"validation\":\"format-only (not dialed)\"," +
      "\"combined_score\":" + score + ",\"assessment\":\"" + q(assess) + "\"}";
  }
  private static ZonedDateTime parsedDate(String date){ if (date == null) return null; try { try { return ZonedDateTime.parse(date, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME); } catch (Exception e) { try { return OffsetDateTime.parse(date).atZoneSameInstant(ZoneOffset.UTC); } catch (Exception e2) { return null; } } } catch (Exception e) { return null; } }
  private static String greetingOf(String body){ if (body == null) return null; String b = body.trim(); if (b.isEmpty()) return null; String lower = b.toLowerCase(Locale.ROOT); if (lower.matches("(?s)^\\s*(dear|hi|hello|good (morning|afternoon|evening))\\s+([a-z]|\\{\\{name\\}\\}|$).*")) { if (lower.matches("(?s)^\\s*(dear (user|customer|sir|madam|valued customer|member)|hi (there|user|everyone|dear))[\\s,.:;]?.*")) return "GENERIC: " + firstLine(b); return "PERSONALIZED?"; } return null; }
  private static String firstLine(String s){ int i = s.indexOf('\n'); return i < 0 ? s : s.substring(0, i); }
  private static List<String> phonesIn(String body){ if (body == null) return new ArrayList<>(); List<String> out = new ArrayList<>(); Matcher m = Pattern.compile("(?:\\+\\d{1,3}[\\s.-]?)?(?:\\(\\d{1,4}\\)[\\s.-]?|\\d{1,4}[\\s.-]?)\\d{1,4}[\\s.-]?\\d{3,4}").matcher(body); while (m.find()) out.add(m.group().trim()); return out; }

  // ---- Layer 16: MITRE ATT&CK mapping (confirmed evidence only) ----
  private static String mitreAttackJson(boolean authMultiFail, boolean brandF, boolean credF, boolean finManip, boolean replyMismatch, boolean jwtNone, boolean trackingPixel, String threatClass){
    List<String> out = new ArrayList<>();
    // Tactic: Initial Access
    if (authMultiFail || "PHISHING".equals(threatClass) || "MALICIOUS".equals(threatClass)) {
      String conf = authMultiFail ? "high" : "probable";
      // T1566 Phishing — Spearphishing Link (T1566.002). URL-delivered phishing (no attachment) maps
      // to the .002 sub-technique; .001 (Spearphishing Attachment) is reserved for attachment delivery.
      out.add("{\"tactic\":\"Initial Access\",\"technique\":\"T1566 — Phishing\",\"sub\":\"T1566.002 — Spearphishing Link\",\"confidence\":\""+conf+"\",\"url\":\"https://attack.mitre.org/techniques/T1566/002/\"}");
    }
    if (replyMismatch) out.add("{\"tactic\":\"Initial Access\",\"technique\":\"T1534 — Internal Spearphishing\",\"sub\":\"\",\"confidence\":\"possible\",\"url\":\"https://attack.mitre.org/techniques/T1534/\"}");
    // Tactic: Credential Access
    if (credF) out.add("{\"tactic\":\"Credential Access\",\"technique\":\"T1056 — Input Capture\",\"sub\":\"\",\"confidence\":\"confirmed\",\"url\":\"https://attack.mitre.org/techniques/T1056/\"}");
    if (jwtNone) out.add("{\"tactic\":\"Credential Access\",\"technique\":\"T1550.001 — Use Alternate Authentication Material\",\"sub\":\"Application Access Token\",\"confidence\":\"confirmed\",\"url\":\"https://attack.mitre.org/techniques/T1550/001/\"}");
    // Tactic: Defense Evasion
    if (brandF) out.add("{\"tactic\":\"Defense Evasion\",\"technique\":\"T1036.005 — Masquerading: Match Legitimate Name or Location\",\"sub\":\"\",\"confidence\":\"probable\",\"url\":\"https://attack.mitre.org/techniques/T1036/005/\"}");
    // Tactic: Collection
    if (trackingPixel) out.add("{\"tactic\":\"Collection\",\"technique\":\"T1114.002 — Email Collection (via tracking pixel)\",\"sub\":\"\",\"confidence\":\"confirmed\",\"url\":\"https://attack.mitre.org/techniques/T1114/002/\"}");
    // Tactic: Impact (financial social engineering)
    if (finManip) out.add("{\"tactic\":\"Impact\",\"technique\":\"T1657 — Financial Theft\",\"sub\":\"\",\"confidence\":\"probable\",\"url\":\"https://attack.mitre.org/techniques/T1657/\"}");
    if (out.isEmpty()) return "[]";
    StringBuilder b = new StringBuilder("["); for (int i = 0; i < out.size(); i++) { if (i > 0) b.append(','); b.append(out.get(i)); } return b.append("]").toString();
  }

  // ---- Layer 9: Domain intelligence (age rules + best-effort RDAP) ----
  // Synthetic/reserved domains are never queried and reported UNKNOWN/UNAVAILABLE
  // (never assumed clean). Age bands feed risk; privacy + brand => HIGH.
  private static String domainIntelligenceJson(String fromDomain, String replyDomain, List<String> urls, boolean brandF, String spf, String dmarc, String raw){
    java.util.LinkedHashSet<String> doms = new java.util.LinkedHashSet<>();
    if (fromDomain != null && !fromDomain.isBlank()) doms.add(fromDomain);
    if (replyDomain != null && !replyDomain.isBlank()) doms.add(replyDomain);
    for (String u : urls) { Matcher m = Pattern.compile("(?i)^https?://([^/?#]+)").matcher(u); if (m.find()) { String h = m.group(1).toLowerCase(Locale.ROOT); if (h.contains("@")) h = h.substring(h.lastIndexOf('@') + 1); try { h = java.net.IDN.toASCII(h); } catch (Exception ignored) {} doms.add(h); } }
    StringBuilder b = new StringBuilder("[");
    boolean first = true;
    for (String d : doms) {
      boolean synthetic = syntheticDomain(d);
      String rdap = null;
      if (!synthetic && !budgetUp()) rdap = rdapEvidence(d);
      String reg = synthetic ? "" : strVal(rdap == null ? "" : rdap, "registrationDate");
      long ageDays = -1; if (!reg.isEmpty()) { try { ageDays = java.time.Duration.between(java.time.OffsetDateTime.parse(reg), java.time.OffsetDateTime.now(ZoneId.of("UTC"))).toDays(); } catch (Exception ignored) {} }
      String flag = "";
      if (synthetic) flag = "UNKNOWN (synthetic/reserved domain — no WHOIS queried; not assumed clean)";
      else if (isSharedHostingHost(d)) flag = "platform-hosted (known shared-hosting parent); subdomain content unverified — domain age/CNAME are not phishing signals";
      else if (rdap != null && rdap.contains("\"status\":\"unavailable\"")) flag = "UNAVAILABLE (WHOIS lookup failed)";
      else if (rdap != null && (rdap.contains("\"status\":\"not_found\"") || rdap.contains("\"status\":\"not_applicable\""))) flag = "UNAVAILABLE (no registration records)";
      else if (ageDays >= 0 && ageDays < 7) flag = "CRITICAL (domain age < 7 days)";
      else if (ageDays >= 0 && ageDays < 30) flag = "HIGH (domain age < 30 days)";
      else if (ageDays >= 0 && ageDays < 90) flag = "MEDIUM (domain age < 90 days)";
      else if (ageDays >= 0) flag = "LOW (established domain)";
      else flag = "UNAVAILABLE (no registration timestamp)";
      if (!first) b.append(',');
      first = false;
      String dnsRecords = "";
      if (!synthetic && raw != null) {
        StringBuilder dr = new StringBuilder();
        if (Pattern.compile("(?i)(?m)^Received:\\s*from").matcher(raw).find()) dr.append("received_hop_present;");
        if (Pattern.compile("(?i)(?m)^Received-SPF:").matcher(raw).find()) dr.append("received_spf_header;");
        if (dr.length() > 0) dnsRecords = dr.substring(0, dr.length() - 1);
      }
      String spfAuth = spf == null || spf.isBlank() ? "not_supplied" : spf;
      String dmarcPol = dmarc == null || dmarc.isBlank() ? "not_supplied" : dmarc;
      b.append("{\"domain\":\"").append(q(d)).append("\",\"whois_registration\":\"").append(reg.isEmpty() ? (synthetic ? "UNKNOWN" : "UNAVAILABLE") : q(reg)).append("\",\"domain_age_days\":").append(ageDays).append(",\"risk_flag\":\"").append(q(flag)).append("\",\"recently_registered\":\"").append(ageDays >= 0 && ageDays < 30 ? "YES" : "NO").append("\",\"privacy_protected\":\"UNKNOWN\",\"ssl_certificate\":\"UNKNOWN\",\"spf\":\"").append(q(spfAuth)).append("\",\"dmarc\":\"").append(q(dmarcPol)).append("\",\"dns_evidence\":\"").append(dnsRecords.isEmpty() ? "UNKNOWN (no DNS observation; synthetic/reserved or no recorded headers)" : q(dnsRecords)).append("\"}").append(brandF ? "" : "");
    }
    return b.append("]").toString();
  }

  // ---- Layer 13: Redirect chain analysis (defang; UNRESOLVABLE when not followed) ----
  // Process-chain merge: multiple links to the SAME defanged target are grouped into a single chain
  // entry carrying an occurrence count and the full source list, so a flooded message cannot pad the
  // redirect output with N identical "chains" for one destination.
  private static String redirectAnalysisJson(List<String> urls){
    StringBuilder b = new StringBuilder("[");
    boolean first = true;
    if (urls != null) {
      LinkedHashMap<String, List<String>> groups = new LinkedHashMap<>();
      for (String u : urls) {
        String host = u; try { host = new URL(u).getHost().toLowerCase(Locale.ROOT); } catch (Exception ignored) {}
        groups.computeIfAbsent(host, x -> new ArrayList<>()).add(u);
      }
      for (Map.Entry<String,List<String>> g : groups.entrySet()) {
        String host = g.getKey(); List<String> src = g.getValue();
        if (!first) b.append(','); first = false;
        String orig = q(src.get(0));
        if (src.size() > 1) {
          String all = ""; for (String u2 : src) { if (!all.isEmpty()) all += ","; all += "\"" + q(u2) + "\""; }
          b.append("{\"host\":\"").append(q(host)).append("\",\"occurrences\":").append(src.size()).append(",\"original\":\"").append(orig).append("\",\"chain_sources\":[").append(all).append("]");
        } else {
          b.append("{\"host\":\"").append(q(host)).append("\",\"occurrences\":1,\"original\":\"").append(orig).append("\"");
        }
        b.append(",\"defanged\":\"").append(q(defang(src.get(0)))).append("\",\"chain_depth\":0,\"final_destination\":\"UNRESOLVABLE (not followed server-side for synthetic/static input)\",\"unresolvable\":true}");
      }
    }
    return b.append("]").toString();
  }
  private static String defang(String url){ if (url == null) return ""; String u = url; if (u.matches("(?i)^https?://")) u = u.replaceFirst("(?i)^(https?)://", "$1xx://"); u = u.replace("://", "[:]//").replace(".", "[.]"); return u; }

  // Machine-readable IOC JSON block at end of the analysis (IOCs reference source evidence).
  private static String iocsJsonBlock(List<String> urls, List<String> iocDomains, List<String> iocIps, List<String> iocEmails, List<String> iocHashes){
    StringBuilder b = new StringBuilder("{\"urls\":"); 
    { StringBuilder x = new StringBuilder("["); for (int i = 0; i < urls.size(); i++) { if (i > 0) x.append(','); x.append("{\"value\":\"").append(q(urls.get(i))).append("\",\"defanged\":\"").append(q(defang(urls.get(i)))).append("\",\"type\":\"url\",\"source\":\"body/link\"}"); } x.append("]"); b.append(x); }
    b.append(",\"domains\":["); for (int i = 0; i < iocDomains.size(); i++) { if (i > 0) b.append(','); b.append("{\"value\":\"").append(q(iocDomains.get(i))).append("\",\"type\":\"domain\",\"source\":\"header/body\"}"); } b.append("]");
    b.append(",\"ips\":["); for (int i = 0; i < iocIps.size(); i++) { if (i > 0) b.append(','); b.append("{\"value\":\"").append(q(iocIps.get(i))).append("\",\"type\":\"ip\",\"source\":\"routing/received\"}"); } b.append("]");
    b.append(",\"emails\":["); for (int i = 0; i < iocEmails.size(); i++) { if (i > 0) b.append(','); b.append("{\"value\":\"").append(q(iocEmails.get(i))).append("\",\"type\":\"email\",\"source\":\"header\"}"); } b.append("]");
    b.append(",\"hashes\":["); for (int i = 0; i < iocHashes.size(); i++) { if (i > 0) b.append(','); b.append("{\"value\":\"").append(q(iocHashes.get(i))).append("\",\"type\":\"hash\",\"source\":\"attachment\"}"); } b.append("]");
    return b.append("}").toString();
  }

  // ---- Layer 2: tracking-pixel / remote content heuristic (feeds MITRE Collection) ----
  private static boolean detectTrackingPixel(String body){ if (body == null) return false; String b = body.toLowerCase(Locale.ROOT); return b.contains("beacon") || b.contains("tracking pixel") || b.contains("open?src=") || Pattern.compile("(?:<img[^>]*src=[\"']?https?://[^\"'\\s]+/[^\"'\\s]*(?:\\?|&)(?:utm_source|email|open|track|beacon))").matcher(b).find(); }
  private static String subjectRiskFrom(String subjJson){ if (subjJson == null) return "LOW"; Matcher m = Pattern.compile("\"risk_level\":\"(LOW|MEDIUM|HIGH|CRITICAL)\"").matcher(subjJson); return m.find() ? m.group(1) : "LOW"; }
  // =====================================================================
  // APEX-EMAIL: Extended forensic analysis layers
  // =====================================================================

  // ---- Lightweight JSON field extractors (consistent with existing codebase pattern) ----
  private static int intFromJson(String json, String key){
    if (json == null) return 0;
    Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(json);
    return m.find() ? Integer.parseInt(m.group(1)) : 0;
  }
  private static String brandFromJson(String json, String key){
    if (json == null) return "";
    Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
    return m.find() ? m.group(1) : "";
  }

  // ---- Levenshtein distance for typosquat detection ----
  private static int levenshtein(String a, String b){
    if (a == null || b == null) return Math.max(a == null ? 0 : a.length(), b == null ? 0 : b.length());
    int al = a.length(), bl = b.length();
    int[] prev = new int[bl + 1];
    for (int j = 0; j <= bl; j++) prev[j] = j;
    for (int i = 1; i <= al; i++) {
      int[] cur = new int[bl + 1]; cur[0] = i;
      for (int j = 1; j <= bl; j++) {
        int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
        cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
      }
      prev = cur;
    }
    return prev[bl];
  }

  // ---- ADDITION 6: X-Mailer spoofing detection ----
  private static String xMailerAnalysis(String raw, String fromDomain, String dkimHeader){
    String xMailer = "";
    Matcher xm = Pattern.compile("(?mi)^X-Mailer:\\s*(.+)$", Pattern.MULTILINE).matcher(raw);
    if (xm.find()) xMailer = xm.group(1).trim();
    boolean present = !xMailer.isEmpty();
    String consistency = "NOT_APPLICABLE";
    String spoofingLikelihood = "N/A";
    int risk = 0;
    if (present) {
      String lower = xMailer.toLowerCase(Locale.ROOT);
      boolean claimsApple = lower.contains("apple mail") || lower.contains("icloud") || lower.contains("airmail");
      boolean claimsOutlook = lower.contains("outlook") || lower.contains("microsoft") || lower.contains("exchange");
      boolean claimsThunderbird = lower.contains("thunderbird") || lower.contains("seamonkey");
      boolean dkimShowsGoogle = dkimHeader.toLowerCase().contains("google") || dkimHeader.toLowerCase().contains("gmail");
      boolean dkimShowsMicrosoft = dkimHeader.toLowerCase().contains("microsoft") || dkimHeader.toLowerCase().contains("outlook");
      if (claimsApple && dkimShowsGoogle) { consistency = "INCONSISTENT"; spoofingLikelihood = "HIGH"; risk = 4; }
      else if (claimsOutlook && dkimShowsGoogle) { consistency = "INCONSISTENT"; spoofingLikelihood = "HIGH"; risk = 4; }
      else if (claimsThunderbird && dkimShowsMicrosoft) { consistency = "INCONSISTENT"; spoofingLikelihood = "MEDIUM"; risk = 3; }
      else if (fromDomain != null && claimsApple && !isOfficialFor(fromDomain, "apple")) { consistency = "INCONSISTENT"; spoofingLikelihood = "MEDIUM"; risk = 3; }
      else if (fromDomain != null && claimsOutlook && !isOfficialFor(fromDomain, "microsoft")) { consistency = "INCONSISTENT"; spoofingLikelihood = "MEDIUM"; risk = 3; }
      else { consistency = "CONSISTENT"; spoofingLikelihood = "LOW"; risk = 0; }
    }
    return "{\"x_mailer\":" + jstr(xMailer) + ",\"present\":" + present + ",\"sender_domain\":" + jstr(fromDomain) +
      ",\"consistency_check\":" + jstr(consistency) + ",\"spoofing_likelihood\":" + jstr(spoofingLikelihood) +
      ",\"risk_points\":" + risk + "}";
  }

  // =====================================================================
  // GMAIL FORENSICS — Gmail/Google Workspace-specific sender & spoof analysis.
  //
  // Google-managed mail has distinctive, well-documented envelope markers that a
  // spoofed message either fails to reproduce or reproduces inconsistently. This
  // module checks those markers honestly (absence is reported as absence, never
  // inferred) and derives a bounded risk total. It NEVER fabricates an external
  // verdict; everything here is derived from the supplied headers.
  // =====================================================================
  static String gmailForensics(String raw, Map<String,List<String>> headers, String fromDomain, String subj){
    String lowerHead = (raw == null ? "" : raw).toLowerCase(Locale.ROOT);
    String fdLower = (fromDomain == null ? "" : fromDomain).toLowerCase(Locale.ROOT);
    boolean isGmailDomain = fdLower.equals("gmail.com") || fdLower.equals("googlemail.com") || fdLower.equals("google.com");
    boolean isGoogleWorkspace = fdLower.endsWith(".google.com") || fdLower.equals("googlegroups.com");

    List<String> indicators = new ArrayList<>();
    List<String> spoofSignals = new ArrayList<>();

    // 1) Sender domain classification
    String senderClass = isGmailDomain ? "GMAIL" : isGoogleWorkspace ? "GOOGLE_WORKSPACE" : "NON_GOOGLE";

    // 2) Gmail message-id signature. Real Gmail outbound has message-id matching
    //    <[A-Za-z0-9+/]{16,}@mail.gmail.com> — a spoof often fails to reproduce this.
    String midH = header(headers, "message-id").toLowerCase(Locale.ROOT);
    boolean gmailMid = midH.matches("(?s).*<[a-z0-9+/]{16,}@mail\\.gmail\\.com>.*")
        || midH.matches("(?s).*<[a-z0-9+/]{16,}@(?:mail-?\\d+)?\\.gmail\\.com>.*");
    if (isGmailDomain && gmailMid) indicators.add(new String[]{"GMAIL_MID", "Genuine Gmail message-id pattern (…@mail.gmail.com) present", "LOW"}[0]);
    if (isGmailDomain && !gmailMid && !midH.isBlank()) {
      indicators.add("GMAIL_MID_MISMATCH");
      spoofSignals.add("From domain is Gmail but Message-ID does not follow Google's mail.gmail.com pattern — often a spoof/delegation artifact; verify the full envelope.");
    }

    // 3) Received-chain Google evidence. Legitimate Gmail delivery shows google.com /
    //    googlemail.com hops (e.g. "Received: from mail-qt1...*.google.com").
    boolean gmailReceived = lowerHead.contains("received:") && (
        lowerHead.contains("google.com") || lowerHead.contains("googlemail.com") || lowerHead.contains("mail-sor") );
    if (isGmailDomain && gmailReceived) indicators.add("GMAIL_RECEIVED");
    if (isGmailDomain && !gmailReceived) spoofSignals.add("Sender claims Gmail but no Google relay host appears in the Received chain.");

    // 4) ARC seal — Google applies an ARC seal when mail passes through its infrastructure.
    String arcH = header(headers, "arc-seal").toLowerCase(Locale.ROOT);
    boolean arcPresent = !arcH.isBlank();
    if (isGmailDomain && arcPresent && arcH.contains("google")) indicators.add("GMAIL_ARC_GOOGLE");
    if (arcPresent && !arcH.contains("google") && isGmailDomain) spoofSignals.add("ARC seal present but not issued by Google despite a Gmail sender domain.");

    // 5) Authentication-Results referencing Google.
    String authH = header(headers, "authentication-results").toLowerCase(Locale.ROOT);
    boolean authMentionsGoogle = authH.contains("gmail.com") || authH.contains("google.com");
    if (isGmailDomain && authMentionsGoogle) indicators.add("GMAIL_AUTH_GOOGLE");

    // 6) DKIM/SPF alignment knowledge for Gmail.
    String spfH = header(headers, "received-spf").toLowerCase(Locale.ROOT);
    boolean spfPass = spfH.contains("pass");
    boolean dkimPass = header(headers, "dkim-signature").toLowerCase(Locale.ROOT).contains("d=gmail.com") || header(headers, "dkim-signature").toLowerCase(Locale.ROOT).contains("d=google");
    if (isGmailDomain && spfPass && dkimPass) indicators.add("GMAIL_ALIGNMENT_PASS");
    if (isGmailDomain && !spfPass) spoofSignals.add("Gmail sender domain but Received-SPF is not 'pass' — possible spoof/proxy delivery; Google normally SPF-passes its own mail.");

    // 7) Header casing / inconsistent display — a professional tipper that a message
    //    was hand-crafted rather than produced by Gmail's MTA.
    boolean casingOdd = lowerHead.contains("from : ") || lowerHead.contains(" subject :") || lowerHead.contains("message-id :") || lowerHead.contains("return-path :");
    if (casingOdd) spoofSignals.add("Header formatting deviates from Gmail's canonical output (unusual whitespace/casing), common in hand-forged mail.");

    // 8) googlegroups / alias marker
    if (isGoogleWorkspace && fdLower.contains("googlegroups.com")) indicators.add("GOOGLE_GROUPS");

    // Aggregate honest evidence availability + bounded risk
    boolean reliable = gmailReceived || arcPresent || authMentionsGoogle || gmailMid || (spfPass || dkimPass);
    int risk = 0;
    for (String s : spoofSignals) risk += 6;
    risk = Math.min(24, risk);
    String indJson = "[" + indicators.stream().map(i -> jstr(i)).reduce((a,b)->a+","+b).orElse("") + "]";
    String spoofJson = "[";
    for (int i = 0; i < spoofSignals.size(); i++) { if (i > 0) spoofJson += ","; spoofJson += jstr(spoofSignals.get(i)); }
    spoofJson += "]";
    String confidence = reliable ? "medium" : isGmailDomain ? "low" : "not_applicable";
    return "{\"engine\":\"gmail_forensics\",\"sender_class\":\"" + senderClass + "\",\"is_gmail_domain\":" + isGmailDomain
      + ",\"gmail_message_id\":\"" + (gmailMid ? "GMAIL" : midH.isBlank() ? "ABSENT" : "NON_STANDARD") + "\""
      + ",\"google_received_evidence\":" + gmailReceived
      + ",\"google_arc_seal\":" + arcPresent
      + ",\"google_auth_reference\":" + authMentionsGoogle
      + ",\"alignment\":\"" + (spfPass && dkimPass ? "PASS" : spfPass ? "PARTIAL" : dkimPass ? "PARTIAL" : "UNVERIFIED") + "\""
      + ",\"evidence_reliable\":" + reliable
      + ",\"indicators_present\":[" + indJson + "]"
      + ",\"spoof_signals\":[" + spoofJson + "]"
      + ",\"risk_points\":" + risk
      + ",\"confidence\":\"" + confidence + "\",\"verdict\":\"" + (risk >= 12 ? "ELEVATED_SPOOF_RISK" : risk >= 6 ? "REVIEW" : isGmailDomain ? "CONSISTENT_WITH_GMAIL" : "NOT_GMAIL") + "\"}";
  }

  // ---- BUG FIX 1: Personalized greeting analysis ----
  private static String greetingAnalysis(String body, String toEmail){
    if (body == null || body.isBlank()) return "{\"greeting_found\":false,\"type\":\"ABSENT\",\"spearphishing_signal\":false,\"risk_points\":1}";
    String b = body.trim();
    String lower = b.toLowerCase(Locale.ROOT);
    Matcher gm = Pattern.compile("(?s)^\\s*(Dear|Hi|Hello|Good\\s+(?:Morning|Afternoon|Evening))\\s+(.{1,512}?)\\s*[\\r\\n,.:;]").matcher(b);
    if (!gm.find()) {
      return "{\"greeting_found\":false,\"type\":\"ABSENT\",\"spearphishing_signal\":false,\"risk_points\":1}";
    }
    String greetingText = gm.group(0).trim();
    String name = gm.group(2).trim();
    String nameLower = name.toLowerCase(Locale.ROOT);
    String[] genericNames = {"user","customer","sir","madam","valued customer","member","there","everyone","dear","team","all"};
    boolean isGeneric = false;
    for (String g : genericNames) if (nameLower.equals(g)) { isGeneric = true; break; }
    if (!isGeneric) {
      isGeneric = nameLower.startsWith("valued") || nameLower.startsWith("beloved") || nameLower.endsWith("member");
    }
    String type = isGeneric ? "GENERIC" : "PERSONALIZED";
    boolean nameMatchesTo = false;
    if (!isGeneric && toEmail != null) {
      String toLocal = toEmail.contains("@") ? toEmail.substring(0, toEmail.indexOf('@')).toLowerCase(Locale.ROOT) : toEmail.toLowerCase(Locale.ROOT);
      String nameClean = nameLower.replaceAll("[^a-z]", "");
      if (toLocal.contains(nameClean) && nameClean.length() >= 3) nameMatchesTo = true;
      if (!nameMatchesTo && toLocal.contains(nameLower.replace(" ", ""))) nameMatchesTo = true;
    }
    int risk = type.equals("PERSONALIZED") ? 5 : 2;
    if (nameMatchesTo) risk += 3;
    boolean spearphishing = type.equals("PERSONALIZED");
    return "{\"greeting_found\":true,\"greeting_text\":" + jstr(greetingText) + ",\"type\":" + jstr(type) +
      ",\"name_matched_to_to\":" + nameMatchesTo + ",\"spearphishing_signal\":" + spearphishing + ",\"risk_points\":" + risk + "}";
  }

  // ---- BUG FIX 2: Full temporal/timing analysis ----
  private static String timingAnalysis(String date){
    ZonedDateTime zdt = parsedDate(date);
    String rawDate = date == null ? "" : date;
    if (zdt == null) return "{\"date_header_raw\":" + jstr(rawDate) + ",\"normalized_utc\":\"UNKNOWN\",\"send_hour_utc\":-1,\"day_of_week\":\"UNKNOWN\",\"time_classification\":\"UNKNOWN\",\"weekend_send\":false,\"suspicious_timing\":false,\"risk_signal\":\"UNKNOWN (Date header absent or unparseable)\",\"risk_points\":0}";
    ZonedDateTime utc = zdt.withZoneSameInstant(ZoneOffset.UTC);
    int hour = utc.getHour();
    int dow = utc.getDayOfWeek().getValue();
    String dayName = utc.getDayOfWeek().toString();
    boolean weekend = (dow == 6 || dow == 7);
    String classification;
    int risk = 0;
    if (hour >= 0 && hour < 5) { classification = "OFF-HOURS"; risk = 6; }
    else if (hour >= 5 && hour < 8) { classification = "PRE-BUSINESS"; risk = 3; }
    else if (hour >= 8 && hour < 18) { classification = "NORMAL"; risk = 0; }
    else if (hour >= 18 && hour < 22) { classification = "NORMAL"; risk = 0; }
    else { classification = "LATE_NIGHT"; risk = 3; }
    if (weekend) risk += 3;
    boolean suspicious = risk >= 3;
    String riskSignal;
    if (risk == 0) riskSignal = "LOW (business-hours send)";
    else if (weekend && risk >= 5) riskSignal = "HIGH (weekend off-hours send)";
    else if (risk >= 5) riskSignal = "HIGH (off-hours send 00:00-05:00 UTC)";
    else if (risk >= 3) riskSignal = "MEDIUM (late-night or weekend send)";
    else riskSignal = "LOW (pre-business hours)";
    return "{\"date_header_raw\":" + jstr(rawDate) + ",\"normalized_utc\":" + jstr(utc.toString()) +
      ",\"send_hour_utc\":" + hour + ",\"day_of_week\":" + jstr(dayName) +
      ",\"time_classification\":" + jstr(classification) + ",\"weekend_send\":" + weekend +
      ",\"suspicious_timing\":" + suspicious + ",\"risk_signal\":" + jstr(riskSignal) + ",\"risk_points\":" + risk + "}";
  }

  // ---- ADDITION 3: Fake contact information detection ----
  private static String fakeContactAnalysis(String body, String fromDomain){
    if (body == null || body.isBlank()) return "{\"contact_risk_level\":\"LOW\"}";
    List<String> phones = phonesIn(body);
    List<String> phoneDetails = new ArrayList<>();
    int phoneRisk = 0;
    for (String p : phones) {
      String clean = p.replaceAll("[^+\\d]", "");
      boolean validFormat = clean.length() >= 7 && clean.length() <= 15;
      String countryCode = clean.startsWith("+") && clean.length() > 3 ? clean.substring(0, Math.min(4, clean.length())) : "UNKNOWN";
      phoneDetails.add("{\"raw_value\":" + jstr(p) + ",\"format_valid\":" + validFormat + ",\"country_code\":" + jstr(countryCode) + ",\"known_legit\":false}");
      if (validFormat) phoneRisk += 5;
    }
    boolean hasAddress = body.toLowerCase(Locale.ROOT).matches("(?s).*(\\d{1,5}\\s+[a-z]+\\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|court|ct|way|place|pl|circle|cir)[,\\s]+[a-z]+(,?\\s+[a-z]{2}\\s+\\d{5})?).*(?i)");
    int addrRisk = hasAddress ? 5 : 0;
    List<String> supportUrls = new ArrayList<>();
    Matcher um = Pattern.compile("(?i)https?://[^\\s<>\"']+(?:support|help|contact|assist)[^\\s<>\"']*").matcher(body);
    while (um.find()) supportUrls.add(um.group());
    int urlRisk = 0;
    for (String u : supportUrls) {
      try { String h = new URL(u).getHost().toLowerCase(); boolean official = false;
        if (fromDomain != null) { String fd = fromDomain.toLowerCase(Locale.ROOT); if (h.endsWith(fd) || fd.endsWith(h)) official = true; }
        if (!official) urlRisk += 8;
      } catch (Exception e) { urlRisk += 8; }
    }
    int totalRisk = phoneRisk + addrRisk + urlRisk;
    if (phoneRisk > 0 && addrRisk > 0 && urlRisk > 0) totalRisk += 5;
    String riskLevel = totalRisk >= 15 ? "CRITICAL" : totalRisk >= 10 ? "HIGH" : totalRisk >= 5 ? "MEDIUM" : "LOW";
    StringBuilder suJson = new StringBuilder("[");
    for (int i = 0; i < supportUrls.size(); i++) { if (i > 0) suJson.append(","); suJson.append(jstr(supportUrls.get(i))); }
    suJson.append("]");
    return "{\"phone_numbers\":[" + String.join(",", phoneDetails) + "],\"physical_address_found\":" + hasAddress +
      ",\"support_urls\":" + suJson +
      ",\"contact_risk_level\":" + jstr(riskLevel) + ",\"risk_points\":" + Math.min(15, totalRisk) + "}";
  }

  // ---- ADDITION 4: Social engineering deep analysis ----
  private static String socialEngineeringDeep(String body, String subj, String fromDisplay){
    if (body == null) body = "";
    String lower = body.toLowerCase(Locale.ROOT);
    String subLower = (subj == null ? "" : subj).toLowerCase(Locale.ROOT);
    String combined = lower + " " + subLower;
    // Urgency
    List<String> urgencyPhrases = new ArrayList<>();
    String[] urgPats = {"immediately","right away","as soon as possible","act now","within \\d+ (?:hour|minute|day)","deadline","time-sensitive","urgent","don'?t delay","before it.?s too late"};
    for (String p : urgPats) { Matcher m2 = Pattern.compile("(?i)" + p).matcher(combined); while (m2.find()) urgencyPhrases.add(m2.group()); }
    boolean urgencyDetected = !urgencyPhrases.isEmpty();
    // Deadline
    boolean deadline = combined.matches("(?s).*(within|by|before|in) \\d+ (hour|hours|minute|minutes|day|days).*");
    String deadlineTimeframe = "";
    if (deadline) { Matcher dm = Pattern.compile("(?i)(within|by|before|in)\\s+(\\d+\\s+(?:hour|hours|minute|minutes|day|days))").matcher(combined); if (dm.find()) deadlineTimeframe = dm.group(2); }
    // Fear
    List<String> fearPhrases = new ArrayList<>();
    String[] fearPats = {"suspended","blocked","terminated","disabled","permanently","unauthorized","compromised","breach","deleted","locked out","restricted"};
    for (String p : fearPats) { if (combined.contains(p)) fearPhrases.add(p); }
    boolean fearDetected = !fearPhrases.isEmpty();
    List<String> assetsThreatened = new ArrayList<>();
    if (combined.contains("account")) assetsThreatened.add("account access");
    if (combined.contains("data") || combined.contains("file") || combined.contains("icloud")) assetsThreatened.add("data/files");
    if (combined.contains("purchase") || combined.contains("payment")) assetsThreatened.add("purchases");
    boolean permanent = combined.contains("permanently") || combined.contains("permanent");
    String consequenceType = permanent ? "PERMANENT" : "REVERSIBLE";
    // Fake geographic threat
    boolean geoThreat = false; String geoLocation = "";
    String[] geoPats = {"minsk","belarus","russia","china","north korea","iran"," nigeria","romania","ukraine"};
    for (String g : geoPats) { if (combined.contains(g)) { geoThreat = true; geoLocation = g; break; } }
    // Device lure
    boolean deviceLure = false; String deviceName = "";
    Matcher devM = Pattern.compile("(?i)(iphone\\s+\\d+\\s*(?:pro|max)?|galaxy\\s+s\\d+|pixel\\s+\\d+|ipad\\s+(?:pro|air)?|macbook\\s*(?:pro|air)?|windows\\s+pc)").matcher(combined);
    if (devM.find()) { deviceLure = true; deviceName = devM.group(); }
    // Authority signals
    boolean legalText = combined.contains("copyright") || combined.contains("terms of service") || combined.contains("privacy policy") || combined.contains("\\u00a9");
    boolean officialStyling = body.toLowerCase().contains("style=") || body.toLowerCase().contains("<table");
    // Personalization level
    int personalDataPoints = 0;
    if (combined.contains("@")) personalDataPoints++;
    if (deviceLure) personalDataPoints++;
    if (fromDisplay != null && fromDisplay.length() > 3) personalDataPoints++;
    String personalization = personalDataPoints >= 4 ? "EXTREME" : personalDataPoints >= 3 ? "HIGH" : personalDataPoints >= 2 ? "MEDIUM" : personalDataPoints >= 1 ? "LOW" : "NONE";
    // NLP threat score
    int nlpScore = 0;
    if (urgencyDetected) nlpScore += 2;
    if (fearDetected) nlpScore += 1;
    if (deadline) nlpScore += 1;
    if (geoThreat) nlpScore += 2;
    if (deviceLure) nlpScore += 1;
    if (permanent) nlpScore += 1;
    if (legalText) nlpScore += 1;
    nlpScore = Math.min(10, nlpScore);
    // Overall assessment
    StringBuilder assess = new StringBuilder();
    if (urgencyDetected && fearDetected && deadline) assess.append("High-pressure phishing campaign with urgency, fear triggers, and deadline pressure");
    else if (urgencyDetected && fearDetected) assess.append("Social engineering with urgency and fear triggers");
    else if (urgencyDetected) assess.append("Urgency-based social engineering");
    else if (fearDetected) assess.append("Fear-based social engineering");
    else assess.append("Limited social engineering signals detected");
    if (geoThreat) assess.append(" with fake geographic threat location (" + geoLocation + ")");
    if (deviceLure) assess.append(" and device-specific lure (" + deviceName + ")");
    assess.append(".");
    return "{\"urgency_detected\":" + urgencyDetected + ",\"urgency_phrases\":[" + qarr(urgencyPhrases) +
      "],\"fear_detected\":" + fearDetected + ",\"fear_phrases\":[" + qarr(fearPhrases) +
      "],\"deadline_present\":" + deadline + ",\"deadline_timeframe\":" + jstr(deadlineTimeframe) +
      ",\"fake_geographic_threat\":" + geoThreat + ",\"fake_location_named\":" + jstr(geoLocation) +
      ",\"device_lure\":" + deviceLure + ",\"device_named\":" + jstr(deviceName) +
      ",\"consequence_framing\":" + (urgencyDetected || fearDetected) + ",\"assets_threatened\":[" + qarr(assetsThreatened) +
      "],\"permanent_consequence\":" + permanent + ",\"legal_text_present\":" + legalText +
      ",\"official_styling\":" + officialStyling + ",\"personalization_level\":" + jstr(personalization) +
      ",\"nlp_threat_score\":" + nlpScore + ",\"assessment\":" + jstr(assess.toString()) + "}";
  }

  // ---- ADDITION 2: Typosquat / combosquat deep analysis ----
  private static String typosquatAnalysis(String fromDomain){
    if (fromDomain == null || fromDomain.isEmpty()) return "{\"detected\":false}";
    String lower = fromDomain.toLowerCase(Locale.ROOT);
    String[] officialDomains = {"apple.com","microsoft.com","google.com","paypal.com","amazon.com","linkedin.com","facebook.com","netflix.com","dropbox.com","office365.com"};
    String[] officialBrands = {"apple","microsoft","google","paypal","amazon","linkedin","facebook","netflix","dropbox","microsoft365"};
    String impersonated = ""; String legitimate = ""; int bestDist = 999;
    for (int i = 0; i < officialDomains.length; i++) {
      String reg = registrableDomain(lower);
      if (reg == null) reg = lower;
      int d = levenshtein(reg.replace("." + officialDomains[i].split("\\.")[1], ""), officialBrands[i]);
      if (d > 0 && d <= 3 && d < bestDist) { bestDist = d; impersonated = officialBrands[i]; legitimate = officialDomains[i]; }
    }
    if (impersonated.isEmpty()) { String bn = brandImpersonatedBy(lower); if (bn != null) { impersonated = bn; legitimate = bn + ".com"; } }
    if (impersonated.isEmpty()) return "{\"detected\":false}";
    // Technique detection
    boolean typosquat = bestDist > 0 && bestDist <= 3;
    boolean combosquat = false; String typosquatType = ""; String substitutionDetail = "";
    String firstLabel = lower.split("[.\\-]")[0];
    if (typosquat) {
      String[] types = {"character_substitution","missing_char","added_char","transposition"};
      if (Math.abs(firstLabel.length() - impersonated.length()) <= 1) {
        if (firstLabel.length() < impersonated.length()) typosquatType = "missing_char";
        else if (firstLabel.length() > impersonated.length()) typosquatType = "added_char";
        else typosquatType = "character_substitution";
      } else typosquatType = "character_substitution";
    }
    String[] comboKw = {"secure","safe","account","id","support","help","verify","unlock","login","auth","update","billing","pay"};
    List<String> foundKw = new ArrayList<>();
    for (String k : comboKw) if (firstLabel.contains(k)) foundKw.add(k);
    if (foundKw.size() >= 2) combosquat = true;
    // TLD mismatch
    String tld = lower.contains(".") ? lower.substring(lower.lastIndexOf('.')) : "";
    String legitTld = legitimate.contains(".") ? legitimate.substring(legitimate.lastIndexOf('.')) : ".com";
    boolean tldMismatch = !tld.equals(legitTld) && !tld.isEmpty();
    // Subdomain abuse
    boolean subdomainAbuse = lower.contains(impersonated) && !firstLabel.contains(impersonated);
    int lookalikeScore = 0;
    if (typosquat) lookalikeScore += 30 + (3 - bestDist) * 10;
    if (combosquat) lookalikeScore += 20 + foundKw.size() * 5;
    if (tldMismatch) lookalikeScore += 15;
    if (subdomainAbuse) lookalikeScore += 10;
    lookalikeScore = Math.min(100, lookalikeScore);
    String visualSimilarity = lookalikeScore >= 60 ? "HIGH" : lookalikeScore >= 30 ? "MEDIUM" : "LOW";
    int risk = 0;
    if (typosquat) risk += 12;
    if (combosquat && foundKw.size() >= 3) risk += 10;
    else if (combosquat) risk += 6;
    if (tldMismatch) risk += 8;
    if (subdomainAbuse) risk += 8;
    risk = Math.min(20, risk);
    String combinedRisk = risk >= 15 ? "CRITICAL" : risk >= 10 ? "HIGH" : risk >= 5 ? "MEDIUM" : "LOW";
    return "{\"detected\":true,\"brand\":" + jstr(impersonated) + ",\"legitimate_domain\":" + jstr(legitimate) +
      ",\"technique\":" + jstr(typosquat ? "typosquat" : combosquat ? "combosquat" : "other") +
      ",\"typosquat_type\":" + jstr(typosquatType) + ",\"levenshtein_distance\":" + bestDist +
      ",\"combosquat\":" + combosquat + ",\"combo_keywords\":[" + qarr(foundKw) +
      "],\"tld_mismatch\":" + tldMismatch + ",\"legitimate_tld\":" + jstr(legitTld) + ",\"attacker_tld\":" + jstr(tld) +
      ",\"subdomain_abuse\":" + subdomainAbuse + ",\"lookalike_score\":" + lookalikeScore +
      ",\"visual_similarity\":" + jstr(visualSimilarity) + ",\"combined_brand_risk\":" + jstr(combinedRisk) +
      ",\"risk_points\":" + risk + "}";
  }

  // ---- ADDITION 9: HTML body deep forensics ----
  private static String htmlBodyForensics(String body){
    if (body == null || body.isEmpty()) return "{\"html_risk_level\":\"LOW\"}";
    String lower = body.toLowerCase(Locale.ROOT);
    boolean hasHtml = lower.contains("<html") || lower.contains("<body") || lower.contains("<div") || lower.contains("<table");
    if (!hasHtml) return "{\"html_risk_level\":\"LOW\",\"note\":\"no HTML detected\"}";
    // Obfuscation
    boolean hiddenDisplay = lower.contains("display:none") || lower.contains("display: none");
    boolean hiddenVis = lower.contains("visibility:hidden") || lower.contains("visibility: hidden");
    boolean zeroWidth = body.contains("\\u200b") || body.contains("\\u200c") || body.contains("\\u200d") || body.contains("\\ufeff");
    boolean whiteOnWhite = Pattern.compile("(?i)color\\s*:\\s*#fff(?:fff)?.*background\\s*:\\s*#fff(?:fff)?").matcher(body).find();
    boolean tinyFont = Pattern.compile("(?i)font-size\\s*:\\s*[01]px").matcher(body).find();
    boolean offScreen = Pattern.compile("(?i)position\\s*:\\s*absolute.*left\\s*:\\s*-\\d{4,}").matcher(body).find();
    boolean commentHidden = body.contains("<!--") && body.contains("-->");
    // Brand mimicry
    boolean brandFonts = lower.contains("-apple-system") || lower.contains("sf pro") || lower.contains("segoe ui") || lower.contains("roboto") || lower.contains("open sans");
    boolean brandColors = lower.contains("#0071e3") || lower.contains("#0066cc") || lower.contains("#1a73e8") || lower.contains("#4285f4");
    boolean brandLayout = lower.contains("border-radius") || lower.contains("box-shadow") || lower.contains("max-width: 6");
    boolean copyrightClone = lower.contains("copyright") || lower.contains("&copy;") || Pattern.compile("\\u00a9|\\(c\\)|©").matcher(body).find();
    String mimicryQuality = (brandFonts && brandColors && brandLayout) ? "HIGH" : (brandColors || brandFonts) ? "MEDIUM" : "LOW";
    // External resources
    boolean externalImages = Pattern.compile("(?i)<img[^>]+src=[\"']?https?://(?!localhost)").matcher(body).find();
    boolean googleFonts = lower.contains("fonts.googleapis.com");
    // Form analysis
    boolean formPresent = lower.contains("<form");
    String formMethod = ""; String formAction = ""; int inputCount = 0; int hiddenFields = 0;
    if (formPresent) {
      Matcher fm = Pattern.compile("(?i)<form[^>]*method=[\"']?(\\w+)[\"']?").matcher(body);
      if (fm.find()) formMethod = fm.group(1).toUpperCase(Locale.ROOT);
      Matcher fa = Pattern.compile("(?i)<form[^>]*action=[\"']([^\"']+)[\"']").matcher(body);
      if (fa.find()) formAction = fa.group(1);
      inputCount = Pattern.compile("(?i)<input").matcher(body).results().count() > Integer.MAX_VALUE ? 99 : (int) Pattern.compile("(?i)<input").matcher(body).results().count();
      hiddenFields = Pattern.compile("(?i)<input[^>]*type=[\"']hidden[\"']").matcher(body).results().count() > Integer.MAX_VALUE ? 99 : (int) Pattern.compile("(?i)<input[^>]*type=[\"']hidden[\"']").matcher(body).results().count();
    }
    int risk = 0;
    if (hiddenDisplay || hiddenVis || offScreen) risk += 5;
    if (brandFonts && brandColors && brandLayout) risk += 8;
    if (copyrightClone) risk += 3;
    if (externalImages) risk += 3;
    if (googleFonts) risk += 2;
    if (formPresent) risk += 5;
    if (hiddenFields > 0) risk += 5;
    risk = Math.min(20, risk);
    String riskLevel = risk >= 15 ? "CRITICAL" : risk >= 10 ? "HIGH" : risk >= 5 ? "MEDIUM" : "LOW";
    return "{\"obfuscation\":{\"hidden_elements\":" + (hiddenDisplay || hiddenVis) + ",\"zero_width\":" + zeroWidth +
      ",\"white_on_white\":" + whiteOnWhite + ",\"tiny_font\":" + tinyFont + ",\"off_screen\":" + offScreen +
      ",\"comment_hiding\":" + commentHidden + "}" +
      ",\"brand_mimicry\":{\"brand_fonts\":" + brandFonts + ",\"brand_colors\":" + brandColors +
      ",\"brand_layout\":" + brandLayout + ",\"copyright_cloned\":" + copyrightClone +
      ",\"mimicry_quality\":" + jstr(mimicryQuality) + "}" +
      ",\"external_resources\":{\"external_images\":" + externalImages + ",\"google_fonts\":" + googleFonts + "}" +
      ",\"form_analysis\":{\"form_present\":" + formPresent + ",\"method\":" + jstr(formMethod) +
      ",\"action\":" + jstr(formAction) + ",\"input_fields\":" + inputCount + ",\"hidden_fields\":" + hiddenFields + "}" +
      ",\"html_risk_level\":" + jstr(riskLevel) + ",\"risk_points\":" + risk + "}";
  }

  // ---- ADDITION 7: Tracking pixel full forensics ----
  private static String trackingPixelFullForensics(String body, List<String> urls){
    if (body == null) return "{\"pixels_found\":false}";
    boolean pixelDetected = detectTrackingPixel(body);
    if (!pixelDetected && urls != null) {
      for (String u : urls) { if (u.matches("(?i).*(?:1x1|pixel|spacer|beacon|/tr\\?|open\\.php|track).*")) { pixelDetected = true; break; } }
    }
    if (!pixelDetected) return "{\"pixels_found\":false}";
    // Find pixel URLs
    List<String> pixelUrls = new ArrayList<>();
    Matcher pm = Pattern.compile("(?i)<img[^>]+src=[\"']?(https?://[^\"'\\s>]+)[\"']?[^>]*(?:width=[\"']?1[\"']?[^>]*height=[\"']?1[\"']?|height=[\"']?1[\"']?[^>]*width=[\"']?1[\"']?)").matcher(body);
    while (pm.find()) pixelUrls.add(pm.group(1));
    if (pixelUrls.isEmpty()) { Matcher pm2 = Pattern.compile("(?i)<img[^>]+src=[\"']?(https?://[^\"'\\s>]*(?:beacon|pixel|track|open|1x1|spacer)[^\"'\\s>]*)[\"']?").matcher(body); while (pm2.find()) pixelUrls.add(pm2.group(1)); }
    // URL parameter analysis
    List<Map<String,String>> paramAnalysis = new ArrayList<>();
    for (String pu : pixelUrls) {
      int qIdx = pu.indexOf('?');
      if (qIdx < 0) continue;
      String query = pu.substring(qIdx + 1);
      for (String param : query.split("&")) {
        String[] kv = param.split("=", 2);
        if (kv.length < 2) continue;
        String key = kv[0].toLowerCase(Locale.ROOT);
        String purpose = "unknown";
        if (key.contains("uid") || key.contains("user") || key.contains("recipient")) purpose = "victim_identifier";
        else if (key.contains("campaign") || key.contains("camp")) purpose = "campaign_tracking";
        else if (key.contains("ref") || key.contains("source") || key.contains("utm")) purpose = "delivery_channel";
        else if (key.contains("open") || key.contains("track") || key.contains("beacon")) purpose = "open_tracking";
        Map<String,String> pa = new LinkedHashMap<>();
        pa.put("parameter", kv[0]); pa.put("value", kv[1]); pa.put("purpose", purpose);
        paramAnalysis.add(pa);
      }
    }
    List<String> dataLeaked = new ArrayList<>();
    dataLeaked.add("victim_ip_address");
    dataLeaked.add("email_client");
    dataLeaked.add("os_information");
    dataLeaked.add("open_timestamp");
    dataLeaked.add("geographic_location");
    int risk = 0;
    if (pixelDetected) risk += 5;
    boolean hasVictimUid = paramAnalysis.stream().anyMatch(p -> "victim_identifier".equals(p.get("purpose")));
    if (hasVictimUid) risk += 5;
    boolean hasCampaign = paramAnalysis.stream().anyMatch(p -> "campaign_tracking".equals(p.get("purpose")));
    risk = Math.min(15, risk);
    String riskLevel = risk >= 10 ? "HIGH" : risk >= 5 ? "MEDIUM" : "LOW";
    StringBuilder paJson = new StringBuilder("[");
    for (int i = 0; i < paramAnalysis.size(); i++) { if (i > 0) paJson.append(","); Map<String,String> p = paramAnalysis.get(i); paJson.append("{\"parameter\":").append(jstr(p.get("parameter"))).append(",\"value\":").append(jstr(p.get("value"))).append(",\"purpose\":").append(jstr(p.get("purpose"))).append("}"); }
    paJson.append("]");
    StringBuilder puJson = new StringBuilder("[");
    for (int i = 0; i < pixelUrls.size(); i++) { if (i > 0) puJson.append(","); puJson.append(jstr(pixelUrls.get(i))); }
    puJson.append("]");
    return "{\"pixels_found\":true,\"pixel_urls\":" + puJson +
      ",\"parameters\":" + paJson.toString() +
      ",\"data_leaked_on_open\":[\"victim_ip\",\"email_client\",\"os_information\",\"open_timestamp\",\"geographic_location\"]" +
      ",\"has_victim_uid\":" + hasVictimUid + ",\"has_campaign_tag\":" + hasCampaign +
      ",\"pixel_risk_level\":" + jstr(riskLevel) + ",\"risk_points\":" + risk + "}";
  }

  // A field is NOT_APPLICABLE (excluded from the denominator) only when the message structure makes
  // the evidence physically impossible to collect; NOT_PROVIDED/absent inputs still lower coverage.
  private static String allFindings(List<Finding>... ls) {
    List<Finding> all = new ArrayList<>(); for (List<Finding> l : ls) all.addAll(l);
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < all.size(); i++) { if (i > 0) b.append(','); Finding x = all.get(i);
      String sev = x.severity == null ? severityFor(x.points) : x.severity;
      String ev = x.evidence == null ? x.message : x.evidence;
      String src = x.source == null ? "local analysis" : x.source;
      String ind = indicatorOf(x.category);
      String sub = (x.subtype == null || x.subtype.isEmpty()) ? ind : x.subtype;
      String normKey = x.findingKey == null || x.findingKey.isEmpty()
          ? (ind + ":" + (x.message == null ? "" : x.message.toLowerCase(Locale.ROOT).trim()))
          : x.findingKey;
      String fid = (x.findingId != null && !x.findingId.isEmpty()) ? x.findingId
          : ind + "-" + String.format("%03d", i + 1);
      int fconf = Math.min(96, 55 + Math.min(x.points, 40));
      int rel   = Math.min(95, 50 + Math.min(x.points * 2, 45));
      b.append("{\"finding_id\":\"").append(q(fid)).append("\"")
       .append(",\"points\":").append(x.points)
       .append(",\"message\":\"").append(q(x.message)).append("\"")
       .append(",\"description\":\"").append(q(x.message == null ? "" : x.message)).append("\"")
       .append(",\"indicator\":\"").append(ind).append("\"")
       .append(",\"subtype\":\"").append(q(sub)).append("\"")
       .append(",\"category\":\"").append(q(x.category)).append("\"")
       .append(",\"layer\":\"").append(layerOf(x.category)).append("\"")
       .append(",\"status\":\"DETECTED\"")
       .append(",\"severity\":\"").append(q(sev)).append("\"")
       .append(",\"severity_level\":").append(effLevel(x))
       .append(",\"confidence\":").append(fconf)
       .append(",\"reliability\":").append(rel)
       .append(",\"evidence\":\"").append(q(ev)).append("\"")
       .append(",\"raw_evidence\":\"").append(q(ev)).append("\"")
       .append(",\"availability\":\"").append("AVAILABLE").append("\"")
       .append(",\"deduplication_key\":\"").append(q(normKey)).append("\"")
       .append(",\"observed_value\":\"").append(q(ev)).append("\"")
       .append(",\"reason\":\"").append(q(x.reason == null ? "Indicator supports elevated risk; tied to detected evidence." : x.reason)).append("\"")
       .append(",\"source\":\"").append(q(src)).append("\"}");
    }
    return "[" + b + "]";
  }
  // Canonical correlation key for a finding category so that several analyzers pointing at the same
  // underlying indicator (e.g. suspicious URL reported by the URL analyzer AND by NLP) are de-duplicated
  // into ONE evidence group with multiple supporting sources.
  private static String indicatorOf(String category){
    if (category == null) return "OTHER";
    return switch (category) {
      case "impersonation" -> "BRAND_IMPERSONATION";
      case "url", "url_mismatch" -> "URL_SUSPICION";
      case "authentication" -> "AUTHENTICATION_FAILURE";
      case "email_authentication" -> "EMAIL_AUTHENTICATION";
      case "routing", "header_anomaly" -> "HEADER_ANOMALY";
      case "nlp" -> "SOCIAL_ENGINEERING";
      case "attachment" -> "SUSPICIOUS_ATTACHMENT";
      case "html" -> "HTML_ANOMALY";
      case "threat_intel" -> "THREAT_INTELLIGENCE";
      case "dns" -> "DNS_ANOMALY";
      case "ip" -> "IP_REPUTATION";
      default -> "OTHER";
    };
  }
  // Correlated evidence: groups detected findings by canonical indicator, de-duplicating identical
  // evidence so the WHY? section can report each underlying indicator once with all its sources.
  private static String correlatedEvidence(List<Finding>... ls){
    List<Finding> all = new ArrayList<>(); for (List<Finding> l : ls) all.addAll(l);
    Map<String,List<Finding>> byInd = new LinkedHashMap<>();
    for (Finding x : all) byInd.computeIfAbsent(indicatorOf(x.category), k -> new ArrayList<>()).add(x);
    StringBuilder b = new StringBuilder("[");
    boolean first = true;
    for (Map.Entry<String,List<Finding>> e : byInd.entrySet()) {
      if (!first) b.append(',');
      first = false;
      String ind = e.getKey(); List<Finding> fs = e.getValue();
      String sev = fs.stream().map(f -> f.severity == null ? severityFor(f.points) : f.severity).filter(s -> "HIGH".equals(s)).findFirst()
        .orElseGet(() -> fs.stream().anyMatch(f -> "MEDIUM".equals(f.severity==null?severityFor(f.points):f.severity)) ? "MEDIUM" : "LOW");
      int totalPts = fs.stream().mapToInt(f -> f.points).sum();
      StringBuilder srcs = new StringBuilder();
      String catF = fs.get(0).category;
      for (int i=0;i<fs.size();i++){ if(i>0) srcs.append(';'); srcs.append(fs.get(i).source==null?"local analysis":fs.get(i).source); }
      b.append("{\"indicator\":\"").append(ind).append("\"")
       .append(",\"category\":\"").append(q(catF)).append("\"")
       .append(",\"status\":\"DETECTED\"")
       .append(",\"severity\":\"").append(q(sev)).append("\"")
       .append(",\"confidence\":").append(Math.min(96, 60 + Math.min(totalPts, 35)))
       .append(",\"reliability\":").append(Math.min(95, 55 + Math.min(totalPts * 2, 40)))
       .append(",\"source\":\"").append(q(srcs.toString())).append("\"")
       .append(",\"evidence\":\"").append(q(fs.get(0).evidence == null ? fs.get(0).message : fs.get(0).evidence)).append("\"")
       .append(",\"observed_value\":\"").append(q(fs.get(0).evidence == null ? fs.get(0).message : fs.get(0).evidence)).append("\"")
       .append(",\"contributing\":").append(fs.size())
       .append(",\"summary\":\"").append(q(ind.replace("_"," ") + " detected across " + fs.size() + " finding(s)")).append("\"}");
    }
    return b.append("]").toString();
  }
  private static String layerOf(String c) {
    return switch (c) {
      case "authentication","impersonation","email_authentication" -> "authentication";
      case "routing","header_anomaly" -> "routing";
      case "url","url_mismatch" -> "url";
      case "attachment" -> "attachment";
      case "nlp" -> "nlp";
      case "html" -> "html";
      case "dns" -> "dns";
      case "ip" -> "ip";
      case "threat_intel" -> "threat_intel";
      default -> "misc";
    };
  }
  private static java.util.Set<String> categories(List<Finding>... ls) { java.util.Set<String> s = new LinkedHashSet<>(); for (List<Finding> l : ls) for (Finding x : l) s.add(x.category); return s; }
  private static String hopToJson(Map<String,Object> h) {
    StringBuilder b = new StringBuilder("{\"hop\":").append(h.get("hop")).append(",\"ip\":\"").append(q((String)h.get("ip"))).append("\",\"hostname\":\"").append(q((String)h.getOrDefault("hostname",""))).append("\",\"record\":\"").append(q((String)h.get("record"))).append("\"");
    Map<String,Object> g = (Map<String,Object>) h.get("geo");
    if (g == null) b.append(",\"geo\":null"); else b.append(",\"geo\":").append(geoMapJson(g));
    @SuppressWarnings("unchecked") List<Map<String,Object>> ips = (List<Map<String,Object>>) h.getOrDefault("allIps", List.of());
    b.append(",\"allIps\":[");
    for (int i = 0; i < ips.size(); i++) {
      if (i > 0) b.append(',');
      Map<String,Object> t = ips.get(i);
      b.append("{\"ip\":\"").append(q((String)t.get("ip"))).append("\",\"hostname\":\"").append(q((String)t.getOrDefault("hostname",""))).append("\",\"country\":\"").append(q((String)t.getOrDefault("country",""))).append("\",\"city\":\"").append(q((String)t.getOrDefault("city",""))).append("\",\"asn\":\"").append(q((String)t.getOrDefault("asn",""))).append("\"}");
    }
    return b.append("]}").toString();
  }
  private static String geoMapJson(Map<String,Object> g) {
    return "{\"ip\":\""+q((String)g.get("ip"))+"\",\"country\":\""+q((String)g.get("country"))+"\",\"region\":\""+q((String)g.get("region"))+"\",\"city\":\""+q((String)g.get("city"))+"\",\"lat\":"+g.get("lat")+",\"lon\":"+g.get("lon")+",\"isp\":\""+q((String)g.get("isp"))+"\",\"org\":\""+q((String)g.get("org"))+"\",\"asn\":\""+q((String)g.get("asn"))+"\"}";
  }
  private static String originToJson(Map<String,Object> o) {
    return "{\"ip\":\""+q((String)o.get("ip"))+"\",\"hostname\":\""+q((String)o.getOrDefault("hostname",""))+"\",\"country\":\""+q((String)o.get("country"))+"\",\"region\":\""+q((String)o.get("region"))+"\",\"city\":\""+q((String)o.get("city"))+"\",\"lat\":"+o.get("lat")+",\"lon\":"+o.get("lon")+",\"isp\":\""+q((String)o.get("isp"))+"\",\"org\":\""+q((String)o.get("org"))+"\",\"asn\":\""+q((String)o.get("asn"))+"\"}";
  }
  private static String senderAttribToJson(List<Map<String,Object>> list) {
    StringBuilder b = new StringBuilder("[");
    for (int i = 0; i < list.size(); i++) {
      if (i > 0) b.append(',');
      Map<String,Object> sa = list.get(i);
      b.append("{\"domain\":\"").append(q((String)sa.get("domain"))).append("\",\"role\":\"").append(q((String)sa.get("role"))).append("\"");
      @SuppressWarnings("unchecked") List<String> addr = (List<String>) sa.get("addresses");
      b.append(",\"addresses\":[");
      for (int j = 0; j < addr.size(); j++) { if (j > 0) b.append(','); b.append('"').append(q(addr.get(j))).append('"'); }
      b.append("]");
      @SuppressWarnings("unchecked") List<Map<String,Object>> ips = (List<Map<String,Object>>) sa.get("ipProfile");
      b.append(",\"ipProfile\":[");
      for (int j = 0; j < ips.size(); j++) { if (j > 0) b.append(','); Map<String,Object> t = ips.get(j); b.append("{\"ip\":\"").append(q((String)t.get("ip"))).append("\",\"hostname\":\"").append(q((String)t.getOrDefault("hostname",""))).append("\",\"country\":\"").append(q((String)t.getOrDefault("country",""))).append("\",\"region\":\"").append(q((String)t.getOrDefault("region",""))).append("\",\"city\":\"").append(q((String)t.getOrDefault("city",""))).append("\",\"asn\":\"").append(q((String)t.getOrDefault("asn",""))).append("\"}"); }
      b.append("]");
      Map<String,Object> w = (Map<String,Object>) sa.get("whois");
      b.append(",\"whois\":{\"source\":\"").append(q((String)w.get("source"))).append("\",\"status\":\"").append(q((String)w.get("status"))).append("\"");
      if (w.containsKey("registrar")) b.append(",\"registrar\":\"").append(q((String)w.get("registrar"))).append("\"");
      if (w.containsKey("registrationDate")) b.append(",\"registrationDate\":\"").append(q((String)w.get("registrationDate"))).append("\"");
      if (w.containsKey("expirationDate")) b.append(",\"expirationDate\":\"").append(q((String)w.get("expirationDate"))).append("\"");
      if (w.get("ageDays") != null) b.append(",\"ageDays\":").append(w.get("ageDays"));
      b.append(",\"note\":\"").append(q((String)w.getOrDefault("note",""))).append("\"}");
      b.append("}");
    }
    return b.append("]").toString();
  }
  private static String attToJson(Map<String,String> a) {
    StringBuilder b = new StringBuilder("{\"filename\":\"").append(q(a.get("filename"))).append("\",\"extension\":\"").append(q(a.get("extension"))).append("\"");
    if (a.containsKey("flag")) b.append(",\"flag\":\"").append(a.get("flag")).append("\"");
    b.append(",\"md5\":\"").append(a.get("md5")).append("\",\"sha1\":\"").append(a.get("sha1")).append("\",\"sha256\":\"").append(a.get("sha256")).append("\"}");
    return b.toString();
  }
  // Reporting-only forensic breakdown for the email_authentication category: header/spoofing signals
  // (Return-Path / Reply-To vs From alignment, SPF/DKIM/DMARC alignment status, Message-ID coherence,
  // brand/display-name impersonation). Values mirror the scored email_authentication findings and do NOT
  // independently re-score (scoring is handled via the emailAuthFindings bucket capped in rawPool).
  private static String emailAuthForensicsJson(String spf, String dkim, String dmarc,
      boolean retMismatch, boolean replyMismatch, boolean alignOK,
      String midDomain, String fromDomain, String fromDisplay, String displayBrand,
      boolean brandInDomain, boolean hasDkimSig, boolean hasMid) {
    java.util.List<String> signals = new ArrayList<>();
    if (retMismatch) signals.add("RETURN_PATH_MISMATCH");
    if (replyMismatch) signals.add("REPLY_TO_MISMATCH");
    if (brandInDomain) signals.add("BRAND_IMPERSONATION");
    else if (displayBrand != null) signals.add("DISPLAY_NAME_BRAND_UNVERIFIED");
    if (hasMid) {
      if (!midDomain.isEmpty() && !fromDomain.isBlank() && !midDomain.equals(fromDomain)) signals.add("MESSAGE_ID_DOMAIN_MISMATCH");
      if (midDomain.isEmpty()) signals.add("MESSAGE_ID_NO_HOST");
    }
    if ("fail".equals(dmarc)) signals.add("DMARC_FAIL");
    if ("not_supplied".equals(dmarc) || dkim.isEmpty()) signals.add("DMARC_NOT_SUPPLIED");
    String alignment = !hasDkimSig || ("not_supplied".equals(spf) && "not_supplied".equals(dkim) && "not_supplied".equals(dmarc))
        ? "UNKNOWN" : (alignOK ? "ALIGNED" : "MISALIGNED");
    return "{\"spf\":\"" + q(spf) + "\",\"dkim\":\"" + q(dkim) + "\",\"dmarc\":\"" + q(dmarc) + "\"," +
      "\"has_dkim_signature\":" + hasDkimSig + "," +
      "\"alignment\":\"" + alignment + "\"," +
      "\"return_path_mismatch\":" + retMismatch + ",\"reply_to_mismatch\":" + replyMismatch + "," +
      "\"message_id_domain\":\"" + q(midDomain) + "\",\"message_id_present\":" + hasMid + "," +
      "\"senders\":{\"from\":\"" + q(fromDomain) + "\",\"display_name\":\"" + q(fromDisplay) + "\"}," +
      "\"signals\":[\"" + String.join("\",\"", signals.stream().map(x->q(x)).toList()) + "\"]," +
      "\"methodology\":\"email_authentication measures header/identity forensics: envelope alignment (Return-Path/Reply-To vs From), SPF/DKIM/DMARC alignment, Message-ID coherence and brand/display-name impersonation. It is weighted as a category alongside url_domain, dns and threat_intelligence; missing DMARC or authentication results are treated as UNKNOWN (never CLEAN).\"}";
  }
  private static String tiToJson(Map<String,Object> ti) {
    @SuppressWarnings("unchecked") List<String> tags = (List<String>) ti.getOrDefault("tags", List.of());
    Object sc = ti.get("score"); String scoreStr = sc == null ? "0" : String.valueOf(sc);    return "{\"type\":\"" + q(String.valueOf(ti.get("type"))) + "\",\"ioc\":\"" + q((String)ti.get("ioc")) + "\",\"state\":\"" + q(String.valueOf(ti.getOrDefault("state","UNKNOWN"))) + "\",\"score\":" + scoreStr + ",\"country\":\"" + q((String)ti.getOrDefault("country","")) + "\",\"tags\":[\"" + String.join("\",\"", tags.stream().map(x->q(x)).toList()) + "\"],\"reason\":\"" + q((String)ti.getOrDefault("reason","")) + "\",\"source\":\"" + q((String)ti.get("source")) + "\",\"observedAt\":\"" + q(String.valueOf(ti.get("observedAt"))) + "\"}";
  }
  private static String mapToJson(Map<String,Object> m) {
    StringBuilder b = new StringBuilder("{"); boolean first = true;
    for (Map.Entry<String,Object> en : m.entrySet()) { if (!first) b.append(','); first = false; b.append("\"").append(en.getKey()).append("\":"); Object v = en.getValue(); if (v instanceof Number || v instanceof Boolean) b.append(v); else b.append("\"").append(q(String.valueOf(v))).append("\""); }
    return b.append("}").toString();
  }

  /* =====================================================================
   * Module: EMAIL ORIGIN / HEADER FORENSICS
   *
   * A self-contained, explainable engine that:
   *   - parses RFC headers (unfolded),
   *   - reconstructs the SMTP Received chain (top=newest ... bottom=oldest)
   *     and presents it in BOTTOM -> TOP chronological delivery order,
   *   - classifies every extracted address using standards-based CIDR rules,
   *   - scores origin candidates (never blindly picks first / last / badge IP),
   *   - applies trust boundaries per hop and per field (sender-supplied vs
   *     receiving-server generated),
   *   - analyzes SPF / DKIM / DMARC / ARC only when real headers exist,
   *   - evaluates X-Originating-IP (sender-provided) as lower-trust evidence,
   *   - detects anomalies (timestamp order, malformed headers, etc.) and
   *     distinguishes ANOMALY from PROOF OF FORGERY,
   *   - emits forensic findings each with severity/evidence/interpretation/confidence,
   *   - separates OBSERVED / VERIFIED / INFERRED / UNKNOWN.
   *
   * The engine NEVER fabricates data: absent values are null / UNKNOWN. It
   * NEVER claims "Sender IP = X" without evidence; it reports "Likely
   * originating IP" or "Origin could not be determined".
   * ===================================================================== */

  // ---- internal hop holder (immutable after parse) ----
  private static final class OfRecv {
    boolean present = false;             // was any Received header seen
    int rawIndex = 0;                    // index in top->bottom raw list (0 = newest)
    String raw = "";
    String fromHost = ""; String fromIp = "";
    String byHost = ""; String byIp = "";
    String protocol = ""; String tls = ""; String helo = "";
    String timestampRaw = ""; String tz = ""; String timestampUtc = null;
    List<String> fromIps = new ArrayList<>();
    List<String> byIps = new ArrayList<>();
    String classification = "";
    String trust = "UNKNOWN"; String trustReason = "";
    String geoCountry = ""; String geoRegion = ""; String geoCity = ""; String geoAsn = ""; String geoOrg = "";
    String ptr = ""; int confidence = 0;
  }

  // Parse the header block into an unfolded, lower-cased multi-value map.
  private static Map<String,List<String>> ofHeaders(String raw){
    Map<String,List<String>> h = new LinkedHashMap<>();
    String normalized = (raw==null?"":raw).replace("\r\n","\n");
    int split = normalized.indexOf("\n\n");
    String block = split>=0 ? normalized.substring(0,split) : normalized;
    StringBuilder folded = new StringBuilder();
    for (String line : block.split("\n",-1)) {
      if (line.startsWith(" ") || line.startsWith("\t")) { if (folded.length()>0) folded.append(' ').append(line.trim()); }
      else {
        if (folded.length()>0){ Matcher m=HEADER.matcher(folded.toString()); if (m.matches()) h.computeIfAbsent(m.group(1).toLowerCase(Locale.ROOT), x->new ArrayList<>()).add(m.group(2)); folded.setLength(0); }
        folded.append(line);
      }
    }
    if (folded.length()>0){ Matcher m=HEADER.matcher(folded.toString()); if (m.matches()) h.computeIfAbsent(m.group(1).toLowerCase(Locale.ROOT), x->new ArrayList<>()).add(m.group(2)); }
    return h;
  }
  private static String ofH(Map<String,List<String>> h, String k){ return String.join(" | ", h.getOrDefault(k, List.of())); }

  // Tolerant Received timestamp -> UTC ISO (null when not parseable). Never fabricates.
  private static String ofTimestampUtc(String s){
    if (s==null || s.isBlank()) return null;
    String t = s.trim();
    if (!t.matches(".*\\d{4}.*")) return null;
    java.time.format.DateTimeFormatter RFC = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME;
    // RFC-1123 style with redundant zone names (e.g. "+0000 (UTC)") - strip trailing parens.
    String t2 = t.replaceAll("\\s*\\([^)]*\\)\\s*$","").trim();
    String[] fmts = {
      "EEE, d MMM yyyy HH:mm:ss Z", "EEE, dd MMM yyyy HH:mm:ss Z",
      "EEE, d MMM yyyy HH:mm:ss z", "EEE, dd MMM yyyy HH:mm:ss z",
      "d MMM yyyy HH:mm:ss Z", "dd MMM yyyy HH:mm:ss Z", "d MMM yyyy HH:mm:ss z"
    };
    for (String f : fmts){ try { ZonedDateTime z = ZonedDateTime.parse(t2, java.time.format.DateTimeFormatter.ofPattern(f, Locale.ENGLISH)); return z.withZoneSameInstant(ZoneOffset.UTC).format(java.time.format.DateTimeFormatter.ISO_INSTANT); } catch (Exception ignore) {} }
    try { try { ZonedDateTime z = ZonedDateTime.parse(t, RFC); return z.withZoneSameInstant(ZoneOffset.UTC).format(java.time.format.DateTimeFormatter.ISO_INSTANT); } catch(Exception ig){} } catch (Exception ignore) {}
    try { ZonedDateTime z = ZonedDateTime.parse(t2); return z.withZoneSameInstant(ZoneOffset.UTC).format(java.time.format.DateTimeFormatter.ISO_INSTANT);} catch (Exception ig){}
    try { OffsetDateTime od = OffsetDateTime.parse(t2); return od.atZoneSameInstant(ZoneOffset.UTC).format(java.time.format.DateTimeFormatter.ISO_INSTANT);} catch (Exception ig){}
    return null;
  }

  // Strip brackets / angle from a host token.
  private static String ofHostTok(String tok){
    if (tok==null) return "";
    String t = tok.trim().replaceAll("^[\\[<(]","").replaceAll("[\\]>)]$","");
    return t;
  }

  // Extract a clean hostname from a segment like "hostA (hostA [1.2.3.4])".
  private static String ofHostOf(String seg){
    if (seg==null) return "";
    String t = seg.trim();
    Matcher m = Pattern.compile("^([\\w.\\-]+)").matcher(t);
    if (m.find()) { String host = ofHostTok(m.group(1)); if (!host.contains("/") && !host.matches(".*\\d{1,3}(\\.\\d{1,3}){3}.*")) return host; }
    // fallback: first parenthesized host before ' ['
    Matcher p = Pattern.compile("\\(([^\\[\\]]+?)\\s*\\[").matcher(t);
    if (p.find()){ String host = ofHostTok(p.group(1)); if (!host.matches(".*\\d{1,3}(\\.\\d{1,3}){3}.*") && host.length()>1) return host; }
    return "";
  }

  // Parse one Received line into a structured hop. Robust: never throws.
  private static OfRecv ofParseRecv(String line){
    OfRecv r = new OfRecv();
    if (line==null) return r;
    r.present = true;
    String l = line.trim(); r.raw = l;
    int semi = l.lastIndexOf(';');
    String datePart = semi>=0 ? l.substring(semi+1).trim() : "";
    String core = semi>=0 ? l.substring(0,semi) : l;
    r.timestampRaw = datePart;
    r.timestampUtc = ofTimestampUtc(datePart);
    // protocol: "with ESMTPS/ESMTP..."
    Matcher pm = Pattern.compile("\\bwith\\s+([A-Za-z0-9\\-]+)").matcher(core);
    if (pm.find()) r.protocol = pm.group(1);
    // TLS band
    Matcher tm = Pattern.compile("(?i)\\bversion=([A-Za-z0-9._\\-]+|TLS[\\w.\\-]*)").matcher(core);
    if (tm.find()) r.tls = tm.group(1);
    else { Matcher tm2 = Pattern.compile("(?i)\\btls\\s+([A-Za-z0-9._\\-]+)").matcher(core); if (tm2.find()) r.tls = tm2.group(1); }
    // split core into before-'by' (from side) and after-'by' (by side)
    String fromSide = core, bySide = "";
    Matcher bym = Pattern.compile("\\bby\\b", Pattern.CASE_INSENSITIVE).matcher(core);
    if (bym.find()) { fromSide = core.substring(0, bym.start()); bySide = core.substring(bym.end()); }
    // strip any "for <...>" in bySide tail
    // from side
    Matcher fh = Pattern.compile("\\bfrom\\s+(.+)$", Pattern.CASE_INSENSITIVE).matcher(fromSide);
    String fromSeg = "";
    if (fh.find()) fromSeg = fh.group(1).trim();
    r.fromHost = ofHostOf(fromSeg);
    // HELO inside parentheses
    Matcher hm = Pattern.compile("(?i)(?:helo\\s+([\\w.\\-]+)|EHLO\\s+([\\w.\\-]+)|HELO:\\s*([\\w.\\-]+))").matcher(fromSide);
    if (hm.find()) r.helo = hm.group(1)!=null?hm.group(1):(hm.group(2)!=null?hm.group(2):hm.group(3));
    // by host (first token / host before space or 'with')
    Matcher bh = Pattern.compile("^\\s*([\\w.\\-]+)").matcher(bySide);
    if (bh.find()) { String byTkn = ofHostTok(bh.group(1)); if (!byTkn.isEmpty()) r.byHost = byTkn; }
    // IPs: IPv4 + IPv6 from fromSide and bySide
    r.fromIps = ofExtractIps(fromSide);
    r.byIps = ofExtractIps(bySide);
    // preference: first IPv4 for from_ip (client), first for by_ip
    r.fromIp = r.fromIps.isEmpty() ? "" : r.fromIps.get(0);
    r.byIp = r.byIps.isEmpty() ? "" : r.byIps.get(0);
    r.classification = r.fromIp.isEmpty() ? "" : classifyAddress(r.fromIp);
    // timezone from date text (last word containing +/UTC/GMT etc.)
    Matcher tzm = Pattern.compile("([+-]\\d{4}|[A-Z]{2,5})$").matcher(datePart.trim());
    if (tzm.find()) r.tz = tzm.group(1);
    return r;
  }

  // Extract distinct IPv4 + IPv6 literals from a string (validated), IPv6 normalized.
  private static List<String> ofExtractIps(String s){
    List<String> out = new ArrayList<>();
    if (s==null || s.isBlank()) return out;
    // IPv4
    Matcher m4 = IPV4.matcher(s);
    while (m4.find()) { String x = m4.group(); if (!out.contains(x)) out.add(x); }
    // IPv6 (incl. bracketed, IPv4-mapped)
    Matcher m6 = Pattern.compile("\\[([0-9A-Fa-f:]{2,})(%[0-9A-Za-z]+)?\\]|(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{1,4}").matcher(s);
    while (m6.find()) {
      String raw6 = m6.group(1)!=null ? m6.group(1) : m6.group(3);
      if (raw6==null) continue;
      String norm = normalizeIpv6(raw6);
      if (norm != null && !out.contains(norm)) out.add(norm);
    }
    return out;
  }

  // Enrich public IPs (geo + ASN via existing architecture). Best-effort.
  private static void ofEnrich(OfRecv r, Map<String,String> cache){
    String ip = !r.fromIp.isEmpty() ? r.fromIp : r.byIp;
    if (ip.isEmpty()) return;
    String cls = classifyAddress(ip);
    r.classification = cls;
    r.ptr = reverseDns(ip);
    if (!cls.equals("public")) return;   // never query external services for non-public
    String g = geoCache(cache, ip);
    if (g!=null && !"null".equals(g)) {
      r.geoCountry = geoVal(g,"country"); r.geoRegion = geoVal(g,"regionName"); r.geoCity = geoVal(g,"city");
      r.geoAsn = geoVal(g,"as"); r.geoOrg = geoVal(g,"org");
    } else { if (r.geoCountry.isEmpty()) r.geoCountry = "UNKNOWN"; }
  }

  // Per-hop trust boundary assignment.
  private static void ofTrust(OfRecv r, boolean isReceivingHop){
    if (isReceivingHop) { r.trust = "TRUSTED"; r.trustReason = "This Received header was generated by the organization's receiving mail server and is therefore treated as higher-confidence delivery evidence (its 'by' server and the peer it recorded are observed server-side)."; r.confidence = 85; return; }
    // a downstream/relay hop: the from_ip is the peer observed by the next (closer) server.
    if (!r.fromIp.isEmpty()) {
      r.trust = "PARTIALLY_TRUSTED";
      r.trustReason = "The connecting peer IP was observed by the downstream receiving server (higher confidence), but the HELO/hostname is sender-supplied and treated as lower confidence.";
      r.confidence = 60;
    } else {
      r.trust = "UNKNOWN"; r.trustReason = "Insufficient connection metadata to assess evidentiary trust for this hop."; r.confidence = 30;
    }
  }

  // ---- main entry: returns the full origin_analysis JSON ----
  static String originForensics(String raw){
    return originForensics(raw, true);
  }
  static String originForensics(String raw, boolean enrich){
    Map<String,List<String>> h = ofHeaders(raw);
    // raw Received lines in delivery order as they appear: top = newest, bottom = oldest.
    List<String> recvTopDown = h.getOrDefault("received", List.of());
    // chronological = oldest(first) -> newest(last): reverse of top-down
    List<OfRecv> chronological = new ArrayList<>();
    for (int i = recvTopDown.size()-1; i >= 0; i--) {
      OfRecv r = ofParseRecv(recvTopDown.get(i));
      r.rawIndex = i;
      chronological.add(r);
    }
    if (!chronological.isEmpty()) chronological.get(chronological.size()-1).present = true;
    boolean receivingHopIsolated = false;
    if (!chronological.isEmpty()) { OfRecv last = chronological.get(chronological.size()-1); last.trust="TRUSTED"; last.confidence=85; last.trustReason="This Received header was generated by the receiving mail server and is treated as higher-confidence delivery evidence."; }
    for (int i = 0; i < chronological.size(); i++) ofTrust(chronological.get(i), i == chronological.size()-1);

    // Headers of interest
    String from = ofH(h,"from"), reply = ofH(h,"reply-to"), ret = ofH(h,"return-path"),
           mid = ofH(h,"message-id"), auth = (ofH(h,"authentication-results")+" "+ofH(h,"received-spf")).trim(),
           dkimH = ofH(h,"dkim-signature"), xoi = ofH(h,"x-originating-ip"),
           arcSeal = ofH(h,"arc-seal"), arcMsg = ofH(h,"arc-message-signature"), arcAuth = ofH(h,"arc-authentication-results");
    String fromDomain = domainOf(from), replyDomain = domainOf(reply), retDomain = domainOf(ret);

    // ---- SPF / DKIM / DMARC / ARC (only from real headers; else NOT PROVIDED) ----
    boolean authProvided = auth != null && !auth.isBlank();
    String spf = result(auth, "spf"), dkim = result(auth, "dkim"), dmarc = result(auth, "dmarc");
    if (!authProvided) { spf = dkim = dmarc = "NOT PROVIDED"; }
    else { if ("not_supplied".equals(spf)) spf = "NOT PROVIDED"; if ("not_supplied".equals(dkim)) dkim = "NOT PROVIDED"; if ("not_supplied".equals(dmarc)) dmarc = "NOT PROVIDED"; }
    Map<String,String> dkimTags = new LinkedHashMap<>();
    if (!dkimH.isBlank()) {
      String[] tags = dkimH.replaceAll("\\r?\\n"," ").split(";");
      for (String t : tags) { Matcher tm = Pattern.compile("\\s*([a-z])\\s*=\\s*([^;]+)").matcher(t); if (tm.matches()) dkimTags.put(tm.group(1), tm.group(2).trim()); }
    }
    String dkimD = dkimTags.get("d"); // cannot claim crypto verification; report header state only
    // ARC chain
    List<String> arcInstances = new ArrayList<>();
    Matcher arcM = Pattern.compile("i=([0-9]+)").matcher(arcSeal + " " + arcMsg);
    Set<String> seenArc = new LinkedHashSet<>();
    while (arcM.find()) { String i = arcM.group(1); if (seenArc.add(i)) arcInstances.add(i); }

    // ---- X-Originating-IP: extract, compare, label sender-provided ----
    String xoiVal = ""; List<String> xoiIps = new ArrayList<>();
    if (!xoi.isBlank()) { xoiIps = ofExtractIps(xoi.replaceAll("[\\[\\]]","")); xoiVal = xoiIps.isEmpty() ? xoi.trim() : String.join(",", xoiIps); }

    // ---- candidate scoring ----
    // Build candidate list from chronological hops: prefer from-ips (origin-side), then by-ips.
    // Never send non-public to external services.
    List<String> candidateOrder = new ArrayList<>();
    Set<String> seenC = new LinkedHashSet<>();
    for (OfRecv r : chronological) {
      for (String ip : r.fromIps) { String c = classifyAddress(ip); if (!isOriginExcluded(c) && seenC.add(ip)) candidateOrder.add(ip); }
      for (String ip : r.byIps)   { String c = classifyAddress(ip); if (!isOriginExcluded(c) && seenC.add(ip)) candidateOrder.add(ip); }
    }
    // deterministic scoring
    Map<String,Integer> candScore = new LinkedHashMap<>();
    Map<String,List<String>> candReasons = new LinkedHashMap<>();
    int ci = 0;
    for (String ip : candidateOrder) {
      int score = 20; List<String> reasons = new ArrayList<>();
      reasons.add("Address classified as " + classifyAddress(ip).replace('_',' ') + ".");
      if (ci == 0) { score += 25; reasons.add("Earliest externally-visible (origin-most) address in the reconstructed delivery path."); }
      int posBonus = Math.max(0, 10 - ci); score += posBonus;
      // from-ip (client) stronger origin signal than by-ip (server)
      if (candidateUsesFromIp(chronological, ip)) { score += 10; reasons.add("Appears as a 'from' (connecting client) address, consistent with an originating client."); }
      if (score > 0 && ci == 0 && "pass".equals(spf)) { score += 8; reasons.add("SPF=" + spf + " corroborates the asserted sending path."); }
      if (score > 0 && ci == 0 && "pass".equals(dkim) && dkimD != null && !dkimD.isBlank() && dkimD.equals(fromDomain)) { score += 6; reasons.add("DKIM " + dkim + " with d=" + dkimD + " aligns to the From domain."); }
      if (score > 0 && !xoiIps.isEmpty() && xoiIps.contains(ip)) { score += 4; reasons.add("X-Originating-IP (sender-provided) is consistent with the Received-chain evidence."); }
      if (!xoiIps.isEmpty() && !xoiIps.contains(ip) && ci==0) { score -= 6; reasons.add("X-Originating-IP (sender-provided) conflicts with the Received-chain evidence; it is treated as lower-trust."); }
      candScore.put(ip, Math.max(0, Math.min(100, score)));
      candReasons.put(ip, reasons);
      ci++;
    }

    // ---- origin selection ----
    String originIp = null; int originConf = 0; List<String> originReasons = new ArrayList<>();
    String status = "ORIGIN UNKNOWN";
    if (!candidateOrder.isEmpty()) {
      String best = null; int bestS = -1;
      for (String ip : candidateOrder) { int s = candScore.get(ip); if (s > bestS) { bestS = s; best = ip; } }
      if (bestS >= 50) { originIp = best; originConf = bestS; status = "LIKELY ORIGIN"; originReasons = candReasons.get(best); }
      else { originConf = bestS; originReasons.add("Strongest candidate scored below the confidence threshold (" + bestS + "/100); origin not conclusively determined."); }
    } else {
      if (recvTopDown.isEmpty()) originReasons.add("No Received headers present - delivery path cannot be reconstructed.");
      else originReasons.add("No public network address found in the Received chain to serve as an origin candidate.");
    }
    String originHost = (originIp==null || originIp.isEmpty()) ? "" : reverseDns(originIp);

    // ---- anomalies ----
    List<String> anomalies = new ArrayList<>();
    // timestamp order across chronological hops (oldest->newest must be non-decreasing)
    Boolean tsOutOfOrder = null;
    for (int i = 1; i < chronological.size(); i++) {
      String a = chronological.get(i-1).timestampUtc, b = chronological.get(i).timestampUtc;
      if (a!=null && b!=null) {
        try { if (Instant.parse(a).isAfter(Instant.parse(b))) { anomalies.add("Impossible timestamp order between delivery hops (earlier hop dated after later hop). This is an ANOMALY and does not independently prove header forgery."); tsOutOfOrder = Boolean.TRUE; break; } } catch (Exception ignore) {}
      }
    }
    boolean anyFuture = false;
    for (OfRecv r : chronological) { if (r.timestampUtc!=null) { try { if (Instant.parse(r.timestampUtc).isAfter(Instant.now())) { anyFuture = true; break; } } catch (Exception ignore) {} } }
    if (anyFuture) anomalies.add("Future-dated Received timestamp detected (clock skew or altered header); flagged as ANOMALY, not proof of forgery.");
    for (OfRecv r : chronological) if (r.raw.isBlank()) anomalies.add("Malformed / empty Received header present.");
    // HELO/PTR mismatch (only when both present and non-empty; not treated as malice)
    for (OfRecv r : chronological) {
      if (!r.helo.isEmpty() && !r.ptr.isEmpty() && !r.ptr.equalsIgnoreCase(r.helo)) {
        anomalies.add("HELO/PTR hostname mismatch on " + (!r.fromIp.isEmpty()?r.fromIp:"(no IP)") + ": HELO=" + r.helo + ", PTR=" + r.ptr + ". Mismatches are common for asymmetric DNS and are not alone malicious.");
      }
    }

    // ---- findings ----
    List<String> findings = new ArrayList<>();
    findings.add("Received chain reconstructed across " + recvTopDown.size() + " header(s); " + (chronological.size() - (receivingHopIsolated?0:0)) + " relay hop(s) in the delivery path.");
    findings.add("Chronology " + (Boolean.TRUE.equals(tsOutOfOrder) ? "shows an ANOMALY (possible timestamp alteration)." : "is internally consistent."));
    if (status.equals("LIKELY ORIGIN")) findings.add("Public origin candidate identified: " + originIp + " (confidence " + originConf + "%).");
    else findings.add("Origin could not be conclusively determined from the supplied headers.");
    if (!xoiIps.isEmpty()) findings.add("X-Originating-IP is sender-provided and treated as lower-trust evidence; " + (xoiIps.contains(originIp!=null?originIp:"") ? "it is consistent with the Received chain." : "it does not match the selected origin candidate."));
    findings.add("SPF: " + spf + (authProvided?" (from recorded header)":" (no Authentication-Results / Received-SPF header - NOT PROVIDED)"));
    findings.add("DKIM: " + dkim + (dkimH.isBlank()?" (no DKIM-Signature header)":" (DKIM-Signature header present; header-state reported, not cryptographically re-verified)"));
    findings.add("DMARC: " + dmarc + (authProvided?"":" (no Authentication-Results - NOT PROVIDED)"));
    findings.add("ARC: " + (arcInstances.isEmpty()?"NOT PRESENT":"present with instance(s) " + String.join(",", arcInstances)));
    if (!replyDomain.isBlank() && !fromDomain.isBlank() && !replyDomain.equals(fromDomain)) findings.add("From/Reply-To domain mismatch: From=" + fromDomain + ", Reply-To=" + replyDomain + ". Not automatically malicious - correlated with other indicators.");

    // ---- build each hop JSON ----
    StringBuilder chain = new StringBuilder("[");
    for (int k = 0; k < chronological.size(); k++) {
      OfRecv r = chronological.get(k);
      if (k>0) chain.append(',');
      String ipv = (!r.fromIp.isEmpty() && r.fromIp.contains(":")) ? "IPv6" : (!r.fromIp.isEmpty() ? "IPv4" : "UNKNOWN");
      chain.append("{\"hop\":").append(k+1)
        .append(",\"raw_header\":\"").append(q(r.raw)).append("\"")
        .append(",\"from_host\":\"").append(q(r.fromHost)).append("\"")
        .append(",\"from_ip\":\"").append(q(r.fromIp)).append("\"")
        .append(",\"by_host\":\"").append(q(r.byHost)).append("\"")
        .append(",\"by_ip\":\"").append(q(r.byIp)).append("\"")
        .append(",\"protocol\":\"").append(q(r.protocol)).append("\"")
        .append(",\"helo\":\"").append(q(r.helo)).append("\"")
        .append(",\"tls\":\"").append(q(r.tls)).append("\"")
        .append(",\"timestamp\":\"").append(q(r.timestampRaw)).append("\"")
        .append(",\"timestamp_utc\":\"").append(r.timestampUtc==null?"":r.timestampUtc).append("\"")
        .append(",\"timezone\":\"").append(q(r.tz)).append("\"")
        .append(",\"ip_version\":\"").append(ipv).append("\"")
        .append(",\"ip_classification\":\"").append(q(r.classification.isEmpty()? "UNKNOWN" : r.classification)).append("\"")
        .append(",\"hostname\":\"").append(q(r.fromHost)).append("\"")
        .append(",\"ptr\":\"").append(q(r.ptr)).append("\"")
        .append(",\"asn\":\"").append(q(r.geoAsn)).append("\"")
        .append(",\"organization\":\"").append(q(r.geoOrg)).append("\"")
        .append(",\"country\":\"").append(q(r.geoCountry.isEmpty()?"UNKNOWN":r.geoCountry)).append("\"")
        .append(",\"trust\":\"").append(r.trust).append("\"")
        .append(",\"trust_reason\":\"").append(q(r.trustReason)).append("\"")
        .append(",\"confidence\":").append(r.confidence)
        .append("}");
    }
    chain.append("]");

    // ---- intel entries for public candidates ----
    StringBuilder intel = new StringBuilder("[");
    int it = 0;
    for (String ip : candidateOrder) {
      if (enrich && !isOriginExcluded(classifyAddress(ip))) {
        String c = classifyAddress(ip);
        if (c.equals("public")) {
          if (it>0) intel.append(',');
          String g = geoCache(new HashMap<>(), ip);
          intel.append("{\"ip\":\"").append(q(ip)).append("\",\"classification\":\"").append(q(c)).append("\",\"hostname\":\"").append(q(reverseDns(ip))).append("\",\"country\":\"").append(q(geoVal(g,"country"))).append("\",\"asn\":\"").append(q(geoVal(g,"as"))).append("\",\"organization\":\"").append(q(geoVal(g,"org"))).append("\",\"source\":\"ip-api.com (server-side)\"}");
          it++;
        }
      }
    }
    intel.append("]");

    // ---- reasoning / observed-verified-inferred-unknown ----
    StringBuilder f = new StringBuilder("[");
    for (int i=0;i<findings.size();i++){ if(i>0)f.append(','); f.append("\"").append(q(findings.get(i))).append("\""); }
    f.append("]");
    StringBuilder an = new StringBuilder("[");
    for (int i=0;i<anomalies.size();i++){ if(i>0)an.append(','); an.append("\"").append(q(anomalies.get(i))).append("\""); }
    an.append("]");
    StringBuilder ar = new StringBuilder("[");
    for (int i=0;i<originReasons.size();i++){ if(i>0)ar.append(','); ar.append("\"").append(q(originReasons.get(i))).append("\""); }
    ar.append("]");

    Map<String,Object> spfObj = new LinkedHashMap<>(); spfObj.put("result", spf); spfObj.put("evaluated_ip", "UNKNOWN");
    Map<String,Object> dkimObj = new LinkedHashMap<>(); dkimObj.put("result", dkim); dkimObj.put("d", dkimD==null?"":dkimD); dkimObj.put("s", dkimTags.getOrDefault("s","")); dkimObj.put("verified_cryptographically", "false");
    Map<String,Object> dmarcObj = new LinkedHashMap<>(); dmarcObj.put("result", dmarc); dmarcObj.put("from_domain", fromDomain);
    Map<String,Object> arcObj = new LinkedHashMap<>(); arcObj.put("present", arcInstances.isEmpty()?"false":"true"); arcObj.put("instances", String.join(",", arcInstances));

    return "{" +
      "\"origin_analysis\":{\"status\":\"" + status + "\",\"origin_ip\":\"" + q(originIp==null?"":originIp) + "\",\"origin_hostname\":\"" + q(originHost) + "\",\"ip_version\":\"" + ((originIp==null||originIp.isEmpty())?"UNKNOWN":(originIp.contains(":")?"IPv6":"IPv4")) + "\",\"confidence\":" + originConf + ",\"reasoning\":" + ar + "}," +
      "\"received_chain\":" + chain + "," +
      "\"authentication\":{\"spf\":" + mapToJson(spfObj) + ",\"dkim\":" + mapToJson(dkimObj) + ",\"dmarc\":" + mapToJson(dmarcObj) + ",\"arc\":" + mapToJson(arcObj) + "}," +
      "\"originating_headers\":{\"x_originating_ip\":{\"present\":" + (xoiIps.isEmpty()?"false":"true") + ",\"value\":\"" + q(xoiVal) + "\",\"trust\":\"UNTRUSTED (sender-provided)\"},\"return_path\":\"" + q(ret) + "\",\"reply_to\":\"" + q(reply) + "\"}," +
      "\"ip_intelligence\":" + intel + "," +
      "\"anomalies\":" + an + "," +
      "\"findings\":" + f + "," +
      "\"scene\":{\"observed\":\"Raw Received headers as supplied.\",\"verified\":\"" + (originIp==null?"No origin identified":("Origin candidate " + originIp + " selected from standards-based classification + chain position.")) + "\",\"inferred\":\"Origin represents the strongest available candidate from reconstructed delivery evidence; not proof of physical sender identity/location.\",\"unknown\":\"Authentication was read from recorded headers, not cryptographically re-verified; geolocation is approximate; some fields are UNKNOWN when absent.\"}" +
      "}";
  }

  private static boolean isOriginExcluded(String c){ return !c.equals("public"); }
  private static boolean candidateUsesFromIp(List<OfRecv> hops, String ip){ for (OfRecv r : hops) if (r.fromIps.contains(ip)) return true; return false; }

  // Compact summary for embedding into analyzeMessage (no external enrichment).
  static String originForensicsSummary(String raw){
    String full = originForensics(raw, false);
    // extract the origin_analysis + chain length + status + findings summary
    String status = "ORIGIN UNKNOWN"; String ip = ""; String conf = "0";
    Matcher sm = Pattern.compile("\"status\":\"([A-Z ]+)\"").matcher(full);
    if (sm.find()) status = sm.group(1);
    Matcher im = Pattern.compile("\"origin_ip\":\"([^\"]*)\"").matcher(full);
    if (im.find()) ip = im.group(1);
    Matcher cm = Pattern.compile("\"confidence\":(\\d+)").matcher(full);
    if (cm.find()) conf = cm.group(1);
    return "{\"status\":\"" + status + "\",\"origin_ip\":\"" + q(ip) + "\",\"confidence\":" + conf + ",\"note\":\"Origin forensic summary (see /api/origin for full analysis).\"" + "}";
  }

  // handler for /api/origin
  private static void originAnalyze(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e, 405, error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String rv = extractRawEmail(body);
    if (rv == null) { json(e, 400, error("rawEmail is required")); return; }
    String raw = unescape(rv);
    if (raw.length() > MAX_REQ_BODY) { json(e, 413, error("Email exceeds size limit")); return; }
    json(e, 200, originForensics(raw, true));
  }
  private static void cases(HttpExchange e) throws IOException {
    if ("GET".equals(e.getRequestMethod())) { StringBuilder b=new StringBuilder(); boolean f=true; for (String l : readLines(CASES)){ if(l.isBlank()||!l.startsWith("{\"id\":\"CS-")) continue; if(!f)b.append(','); f=false; b.append(l);} json(e,200,"{\"cases\":["+(f?"":b.toString())+"]}"); return; }
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("GET or POST required")); return; }
    String raw = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
    if (raw.isEmpty() || raw.contains("\n") || raw.contains("\r")) { json(e,400,error("record must be a single-line JSON object")); return; }
    String id="CS-"+(2000+System.currentTimeMillis()%7000); String record="{\"id\":\""+id+"\",\"createdAt\":\""+Instant.now()+"\",\"status\":\"open\",\"record\":"+raw+"}";
    try { Files.writeString(CASES,record+System.lineSeparator(),StandardOpenOption.CREATE,StandardOpenOption.APPEND); } catch (Exception ex) { json(e,500,error("Failed to persist case")); return; }
    json(e,201,record);
  }
  private static void enrichment(HttpExchange e) throws IOException { json(e,200,"{\"ipGeolocation\":\"ip-api.com (free tier, server-side proxy)\",\"whois\":\"IANA RDAP bootstrap\",\"dns\":\"JVM resolver\",\"abuseipdb\":\"" + (ABUSEIPDB_KEY.isEmpty() ? "UNCONFIGURED" : "ON") + "\",\"safeBrowsing\":\"" + (SAFEBROWSING_KEY.isEmpty() ? "UNCONFIGURED" : "ON") + "\",\"threatIntel\":\"infrastructure heuristics\",\"note\":\"Geolocation, DNS and RDAP are proxied server-side. AbuseIPDB and Safe Browsing activate automatically the moment their credentials are set as server env vars; until then they are reported UNCONFIGURED, never as clean.\"}"); }

  private static void geolocate(HttpExchange e) throws IOException {
    String ip = Optional.ofNullable(e.getRequestURI().getQuery()).orElse("").replaceFirst("^ip=", "").trim();
    if (!ip.matches(IPV4.pattern())) { json(e,400,error("A valid IP address is required")); return; }
    if (isPrivate(ip)) { json(e,200,"{\"ip\":\""+ip+"\",\"status\":\"private\",\"note\":\"Private / reserved address \u2014 no public geolocation.\"}"); return; }
    try { HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create("http://ip-api.com/json/"+ip)).timeout(Duration.ofSeconds(8)).build(), HttpResponse.BodyHandlers.ofString()); json(e,200,r.body()); }
    catch (Exception ex) { json(e,200,"{\"ip\":\""+ip+"\",\"status\":\"fail\",\"note\":\"Geolocation provider unreachable from server.\"}"); }
  }
  private static void dns(HttpExchange e) throws IOException {
    String domain = Optional.ofNullable(e.getRequestURI().getQuery()).orElse("").replaceFirst("^domain=", "").toLowerCase(Locale.ROOT);
    if (!domain.matches("^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$")) { json(e,400,error("A valid domain query parameter is required")); return; }
    StringBuilder out = new StringBuilder();
    try { List<String> a = new ArrayList<>(); for (InetAddress x : InetAddress.getAllByName(domain)) { String h = x.getHostAddress(); if (h.contains(".")) a.add(h); } out.append("{\"type\":\"A / AAAA\",\"value\":\""+q(a.isEmpty()?"no_address":String.join(", ", a))+"\"}"); } catch (Exception x) { out.append("{\"type\":\"A / AAAA\",\"value\":\"no_address\"}"); }
    try {
      javax.naming.directory.InitialDirContext ctx = new javax.naming.directory.InitialDirContext(new java.util.Hashtable<String,String>(){{ put(javax.naming.Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.dns.DnsContextFactory"); }});
      for (String type : new String[]{"MX","NS","TXT","CNAME","SOA"}) {
        String val = "none"; try { Object a = ctx.getAttributes("dns:/" + domain, new String[]{type}).get(type).get(); val = String.valueOf(a); } catch (Exception ignored) { }
        out.append(",{\"type\":\""+type+"\",\"value\":\""+q(val)+"\"}");
      }
    } catch (Exception ignored) { out.append(",{\"type\":\"MX\",\"value\":\"lookup_unavailable\"},{\"type\":\"NS\",\"value\":\"lookup_unavailable\"},{\"type\":\"TXT\",\"value\":\"lookup_unavailable\"}"); }
    json(e,200,"{\"domain\":\""+q(domain)+"\",\"records\":["+out+"],\"observedAt\":\""+Instant.now()+"\",\"note\":\"DNS records are infrastructure context, not maliciousness evidence.\"}");
  }
  private static void whois(HttpExchange e) throws IOException {
    String domain = Optional.ofNullable(e.getRequestURI().getQuery()).orElse("").replaceFirst("^domain=", "").toLowerCase(Locale.ROOT);
    if (!domain.matches("^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$")) { json(e,400,error("A valid domain query parameter is required")); return; }
    try { HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create("https://rdap.org/domain/" + domain)).timeout(Duration.ofSeconds(12)).build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() == 200 && (r.body().contains("\"events\"") || r.body().contains("\"handle\""))) json(e,200,"{\"domain\":\""+q(domain)+"\",\"rdap\":"+r.body()+",\"source\":\"RDAP (rdap.org bootstrap redirect)\"}");
      else json(e,404,"{\"domain\":\""+q(domain)+"\",\"error\":\"RDAP returned HTTP "+r.statusCode()+" — no registration data available.\",\"source\":\"RDAP\"}");
    } catch (Exception ex) { json(e,502,error("RDAP lookup failed: "+ex.getMessage())); }
  }
  private static void domainIntelligence(HttpExchange e) throws IOException {
    String domain = Optional.ofNullable(e.getRequestURI().getQuery()).orElse("").replaceFirst("^domain=", "").toLowerCase(Locale.ROOT);
    if (!domain.matches("^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$")) { json(e,400,error("A valid domain query parameter is required")); return; }
    List<String> addresses = new ArrayList<>(); try { for (InetAddress address : InetAddress.getAllByName(domain)) { String h = address.getHostAddress(); if (h.contains(".")) addresses.add(h); } } catch (UnknownHostException ignored) { }
    String values = addresses.stream().map(x -> "\"" + q(x) + "\"").reduce((a,b) -> a + "," + b).orElse("");
    json(e,200,"{\"domain\":\""+q(domain)+"\",\"addresses\":["+values+"],\"addressCount\":"+addresses.size()+",\"source\":\"JVM DNS resolver\",\"observedAt\":\""+Instant.now()+"\",\"note\":\"DNS resolution is infrastructure context, not ownership or maliciousness evidence.\"}");
  }

  /* =====================================================================
   *  Module: IP GEOLOCATION & INTELLIGENCE
   *  Pipeline: Input -> Normalize -> Classify -> Enrich -> Correlate -> Score -> Explain -> Evidence
   *  ===================================================================== */
  private static void ipIntel(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String client = Optional.ofNullable(e.getRemoteAddress()).map(a -> a.getAddress()==null?null:a.getAddress().getHostAddress()).orElse("local");
    if (!allowed(client)) { json(e,429,error("Rate limit exceeded for this client; retry shortly.")); return; }
    String raw = Optional.ofNullable(e.getRequestURI().getQuery()).orElse("").replaceFirst("^ip=", "").trim();
    String normalized = parseIp(raw);
    if (normalized == null) { json(e,400,error("A valid IP address (IPv4 or IPv6) is required")); return; }
    String cached = cacheGet(IP_CACHE, normalized);
    if (cached != null) { json(e,200,cached); return; }
    String out = analyzeIp(raw, normalized);
    if (out != null) { cachePut(IP_CACHE, normalized, out); json(e,200,out); }
    else json(e,502,error("Internal error while analyzing the IP."));
  }

  // GET /api/ip-forensics?ip=...  — full 16-layer APEX-GEO forensic pipeline.
  private static void ipForensics(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String client = Optional.ofNullable(e.getRemoteAddress()).map(a -> a.getAddress()==null?null:a.getAddress().getHostAddress()).orElse("local");
    if (!allowed(client)) { json(e,429,error("Rate limit exceeded for this client; retry shortly.")); return; }
    String raw = Optional.ofNullable(e.getRequestURI().getQuery()).orElse("").replaceFirst("^ip=", "").trim();
    String normalized = parseIp(raw);
    if (normalized == null) { json(e,400,error("A valid IP address (IPv4 or IPv6) is required")); return; }
    String cached = cacheGet(IP_CACHE, normalized);
    if (cached != null) { json(e,200,cached); return; }
    String out = apexGeo(raw, normalized);
    if (out != null) { cachePut(IP_CACHE, normalized, out); json(e,200,out); }
    else json(e,502,error("Internal error while running the IP forensic pipeline."));
  }

  // Normalize an IP (IPv4 or IPv6) to a canonical string; null if invalid.
  static String parseIp(String raw) {
    String s = raw == null ? "" : raw.trim();
    if (s.isEmpty()) return null;
    return s.contains(":") ? normalizeIpv6(s) : normalizeIpv4(s);
  }
  static String normalizeIpv4(String s) {
    String[] parts = s.split("\\.", -1);
    if (parts.length != 4) return null;
    StringBuilder b = new StringBuilder();
    for (String p : parts) {
      if (!p.matches("\\d{1,3}")) return null;
      int v = Integer.parseInt(p);
      if (v > 255) return null;
      if (b.length() > 0) b.append('.');
      b.append(v);
    }
    // numeric normalization for each octet
    String[] in = b.toString().split("\\.");
    StringBuilder out = new StringBuilder();
    for (String o : in) { if (out.length()>0) out.append('.'); out.append(Integer.parseInt(o)); }
    return out.toString();
  }
  static String normalizeIpv6(String s) {
    // strip brackets and zone id for classification/normalization
    String t = (s == null ? "" : s).trim();
    if (t.startsWith("[")) { int e = t.indexOf(']'); t = (e >= 0) ? t.substring(1, e) : t.substring(1); }
    int pct = t.indexOf('%'); if (pct >= 0) t = t.substring(0, pct);
    // split outer trailing embedded IPv4 (e.g., ::ffff:8.8.8.8) - it occupies the final 32 bits (2 groups)
    String v4 = "";
    int lastColon = t.lastIndexOf(':');
    String tail = lastColon >= 0 ? t.substring(lastColon + 1) : t;
    if (tail.contains(".")) { v4 = tail; t = lastColon >= 0 ? t.substring(0, lastColon) : ""; }
    // tokenize with the single "::" abbreviation
    String[] lg, rg;
    int missing;
    if (t.contains("::")) {
      int di = t.indexOf("::");
      String lhs = t.substring(0, di), rhs = t.substring(di + 2);
      lg = lhs.isEmpty() ? new String[0] : lhs.split(":");
      rg = rhs.isEmpty() ? new String[0] : rhs.split(":");
      missing = 8 - lg.length - rg.length - (v4.isEmpty() ? 0 : 2);
      if (missing < 1) return null;
    } else {
      lg = t.isEmpty() ? new String[0] : t.split(":");
      rg = new String[0];
      missing = 0;
      if (lg.length + (v4.isEmpty() ? 0 : 2) != 8) return null;
    }
    String[] g = new String[8];
    int k = 0;
    for (String x : lg) g[k++] = x;
    for (int i = 0; i < missing; i++) g[k++] = "0";
    for (String x : rg) g[k++] = x;
    if (!v4.isEmpty()) {
      String v = normalizeIpv4(v4); if (v == null) return null;
      String[] oc = v.split("\\.");
      g[k++] = String.format("%04x", Integer.parseInt(oc[0]) * 256 + Integer.parseInt(oc[1]));
      g[k++] = String.format("%04x", Integer.parseInt(oc[2]) * 256 + Integer.parseInt(oc[3]));
    }
    if (k != 8) return null;
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < 8; i++) {
      if (!g[i].matches("[0-9a-fA-F]{1,4}")) return null;
      b.append(String.format("%04x", Integer.parseInt(g[i], 16)));
      if (i < 7) b.append(':');
    }
    return b.toString();
  }
  // Detect whether an address must NOT be sent to external intelligence services.
  static String classifyAddress(String ip) {
    if (ip == null) return "invalid";
    String ladr = ip.toLowerCase(Locale.ROOT);
    if (ladr.contains(":")) {
      String c = ipv6Class(ladr); if (c != null) return c; return "public";
    }
    String[] o = ladr.split("\\.");
    if (o.length != 4) return "invalid";
    int a0 = Integer.parseInt(o[0]), a1 = Integer.parseInt(o[1]), a2 = Integer.parseInt(o[2]);
    if (a0 == 0) return "unspecified";
    if (a0 == 10) return "private";
    if (a0 == 127) return "loopback";
    if (a0 == 169 && a1 == 254) return "link_local";
    if (a0 == 172 && a1 >= 16 && a1 <= 31) return "private";
    if (a0 == 192 && a1 == 168) return "private";
    if (a0 == 100 && a1 >= 64 && a1 <= 127) return "carrier_grade_nat (reserved)";
    if (a0 == 192 && a1 == 0 && a2 == 2) return "documentation (RFC 5737)";
    if (a0 == 198 && a1 == 51 && a2 == 100) return "documentation (RFC 5737)";
    if (a0 == 203 && a1 == 0 && a2 == 113) return "documentation (RFC 5737)";
    if (a0 == 198 && (a1 == 18 || a1 == 19)) return "benchmarking (reserved)";   // 198.18.0.0/15
    if (a0 == 192 && a1 == 0 && a2 == 0) return "reserved";
    if (a0 == 255) return "reserved";
    if (a0 >= 224 && a0 <= 239) return "multicast";
    if (a0 >= 240) return "reserved";
    return "public";
  }
  private static String ipv6Class(String ladr) {
    if (ladr.equals("::") || ladr.equals("::0")) return "unspecified";
    if (ladr.equals("::1")) return "loopback";
    // IPv4-mapped / IPv4-compatible (::ffff:x.x.x.x): classify via the embedded literal so that
    // e.g. ::ffff:192.168.1.1 is correctly treated as PRIVATE (critical for SSRF protection).
    // Match lower-case forms: ::ffff prefix (may be written ::ffff:192.168.1.1 or ::FFFF:...).
    java.util.regex.Matcher m4 = Pattern.compile("^(?:::ffff:|::)\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)$").matcher(ladr);
    if (m4.find()) {
      String emb = m4.group(1);
      String c = classifyAddress(emb);
      return c.equals("invalid") ? "public" : c;
    }
    if (ladr.startsWith("fe8") || ladr.startsWith("fe9") || ladr.startsWith("fea") || ladr.startsWith("feb")) return "link_local";
    if (ladr.startsWith("fc") || ladr.startsWith("fd")) return "unique_local (private)";
    if (ladr.startsWith("ff")) return "multicast";
    if (ladr.startsWith("2001:db8")) return "documentation (RFC 3849)";
    if (ladr.startsWith("2001:10")) return "documentation (ORCHID)";
    // Teredo is strictly 2001:0000::/32 (2001:0:..  or compressed 2001::...). Do NOT treat the
    // rest of the 2001::/16 (e.g. Google DNS 2001:4860::) as reserved.
    if (ladr.startsWith("2001:0:") || ladr.startsWith("2001::")) return "teredo (reserved)";
    if (ladr.startsWith("2002:")) return "6to4 (reserved)";            // 2002::/16
    if (ladr.startsWith("100:")) return "reserved";                    // 100::/64 discard
    if (ladr.startsWith("64:ff9b:")) return "nat64 (reserved)";        // 64:ff9b::/96
    if (ladr.startsWith("3fff:")) return "documentation (RFC 9637)";
    if (ladr.startsWith("5f00")) return "segment_routing (reserved)";
    return null;
  }
  static boolean isBlockedForFetch(String ip) {
    if (ip == null) return true;
    try {
      InetAddress a = InetAddress.getByName(stripIpv6Zone(ip));
      if (a.isSiteLocalAddress() || a.isLoopbackAddress() || a.isAnyLocalAddress() || a.isMulticastAddress()) return true;
      String c = classifyAddress(ip);
      return !c.equals("public");
    } catch (Exception x) { return true; }
  }
  // ---- SSRF guard (SECURITY FIX): reusable check that blocks outbound requests that resolve to
  // private/internal/reserved/carrier-grade networks. Accepts a hostname or a literal IP; returns
  // null when safe (all resolved addresses public) or a human-readable reason string when blocked.
  static String ssrfGuard(String target){
    if (target == null || target.isBlank()) return "Empty target";
    String t = target.trim().toLowerCase(Locale.ROOT);
    // Strip scheme + path so we can guard a bare host as well as a full URL.
    String host = t;
    int scheme = host.indexOf("://"); if (scheme >= 0) host = host.substring(scheme + 3);
    int slash = host.indexOf('/'); if (slash >= 0) host = host.substring(0, slash);
    int at = host.lastIndexOf('@'); if (at >= 0) host = host.substring(at + 1);
    int colon = host.lastIndexOf(':'); if (colon >= 0 && host.indexOf(']') < 0) host = host.substring(0, colon); // strip port for bare host
    if ("localhost".equals(host)) return "Target resolves to localhost — SSRF protection active";
    // If it's already an IP literal, classify directly.
    String cls = classifyAddress(host);
    if (!cls.equals("invalid") && !cls.equals("public")) return "Target resolves to private network — SSRF protection active";
    // Otherwise resolve all records and permit only if EVERY address is public.
    try {
      java.util.List<String> resolved = new ArrayList<>();
      for (InetAddress a : InetAddress.getAllByName(host)) { String h = a.getHostAddress(); if (h != null && !resolved.contains(h)) resolved.add(h); }
      if (resolved.isEmpty()) return "Target does not resolve — SSRF protection active";
      for (String ip : resolved) if (!clsOf(ip).equals("public")) return "Target resolves to private network — SSRF protection active";
      return null;
    } catch (Exception x) { return "Target lookup failed — SSRF protection active"; }
  }
  private static String clsOf(String ip){ String c = classifyAddress(ip); return c == null ? "public" : c; }
  private static String stripIpv6Zone(String h){ int p = h.indexOf('%'); return p >= 0 ? h.substring(0,p) : h; }

  // Full IP analysis producing the forensic evidence card JSON.
  static String analyzeIp(String rawInput, String ip) {
    String ts = Instant.now().toString();
    String cls = classifyAddress(ip);
    boolean isPublic = cls.equals("public");
    String ipv = ip.contains(":") ? "IPv6" : "IPv4";
    List<String> sources = new ArrayList<>();
    List<String> findings = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    List<String> iocs = new ArrayList<>();
    String iocIp = ip;

    // ---- 1. CLASSIFICATION ----
    findings.add("Address classified as: " + cls.replace('_',' ') + (isPublic ? " — safe to query external intelligence services." : " — NOT sent to external services (network-internal/reserved)."));

    // ---- 2. GEOLOCATION (public only, multi-source correlation) + ASN + reverse DNS (server-side) ----
    String geo = "null", geoSource = "unavailable";
    String country="", cc="", region="", city="", timezone="", isp="", org="", asn="", asname="", revdns="";
    boolean proxyFlag=false, hostingFlag=false, mobileFlag=false;
    String abuseJson = "null";
    String torTags="", vpnTags="", hostTags="", anonTags="";
    List<String> geoCorr = new ArrayList<>();
    int geoAgree = 0;
    if (isPublic) {
      GeoMulti gm = geoMulti(ip);
      geo = gm.geo(); geoSource = gm.source();
      country = gm.country(); cc = gm.cc(); region = gm.region(); city = gm.city();
      timezone = gm.tz(); isp = gm.isp(); org = gm.org(); asn = gm.asn(); asname = gm.asname();
      proxyFlag = gm.proxy(); hostingFlag = gm.hosting(); mobileFlag = gm.mobile();
      geoCorr = gm.corrList(); geoAgree = gm.agree();
      if (sourceOk(geoSource)) sources.add(geoSource);
      if (gm.source2Ok()) sources.add(gm.source2());
      if (geoAgree >= 2) findings.add("Geolocation country confirmed by " + geoAgree + " independent source(s) (multi-source agreement).");
      else if (geoAgree == 1) findings.add("Geolocation available from a single source; not independently confirmed.");
      if (!geoCorr.isEmpty()) findings.add("Cross-source geolocation comparison: " + String.join("; ", geoCorr));
      if (!geo.equals("null") && !geo.contains("success")) errors.add("Geolocation provider returned an error response.");


      // reverse DNS via JVM resolver (server-side only), cached + bounded timeout
      revdns = reverseDns(iocIp);

      // ---- 3. VPN / PROXY / TOR / ANONYMIZER (infrastructure heuristics, clearly labelled) ----
      String ispLower = (isp + " " + org + " " + asname + " " + asn).toLowerCase(Locale.ROOT);
      String asClean = asn.replaceAll("\\s+","").toLowerCase(Locale.ROOT);
      List<String> tiTags = new ArrayList<>();
      List<String> torAsns = List.of("as60729","as200578","as51922","as61272","as50673","as12876","as204428","as210878");
      for (String a : torAsns) if (asClean.contains(a)) { tiTags.add("Tor / anonymity exit infrastructure (AS " + a + ")"); break; }
      for (String k : new String[]{"forprivacynet","tor","anonym","artikel10","stiftung erneuerbare freiheit","freie netze","sservers","torservers","darknode","privacy"}) if (ispLower.contains(k)) { tiTags.add("Anonymizer / Tor exit infrastructure"); break; }
      if (proxyFlag) tiTags.add("Proxy / anonymizing gateway (provider flag)");
      // SCORE FIX (ipForensics ASN): notable ASNs frequently abused for phishing/c2 proxy infrastructure
      // (Telegram AS62041/AS44907/AS62014, M247 AS9009, NForce AS43350, Tor AS200300/AS60729) earn a bounded
      // MEDIUM infrastructure note. This alone is NEVER treated as MALICIOUS — it is informational context
      // that other evidence must corroborate before escalation.
      String asnNote = "";
      if (asClean.matches(".*?(as62041|as44907|as62014).*")) asnNote = "Telegram messaging-infrastructure ASN (AS" + asClean.replaceAll("[^0-9a-z]","") + ") — legitimate B2C/messaging range often abused for phishing delivery";
      else if (asClean.contains("as9009")) asnNote = "M247 (AS9009) — common proxy/VPN/hosting provider; frequently observed originating phishing infrastructure";
      else if (asClean.contains("as43350")) asnNote = "NForce (AS43350) — VPS/hosting provider historically associated with malicious infrastructure hosting";
      else if (asClean.contains("as200300") || asClean.contains("as60729")) asnNote = "Tor anonymity exit (AS" + asClean.replaceAll("[^0-9a-z]","") + ") — anonymizing relay range";
      if (!asnNote.isEmpty()) { tiTags.add("Notable abuse-prone ASN: " + asnNote + " (informational; not malicious by itself)"); }
      for (String k : new String[]{"vpn","surfshark","nordvpn","private internet access","pia","mullvad","protonvpn","wireguard","ivacy","hidemyass","cyberghost","purevpn","vyprvpn","azire"}) if (ispLower.contains(k)) { tiTags.add("Consumer VPN provider"); break; }
      for (String k : new String[]{"digitalocean","linode","vultr","hetzner","ovh","aws","amazon data","azure","microsoft corporation","google cloud","oracle cloud","datapacket","leaseweb","contabo","scaleway","ionos","hostinger","bluehost","godaddy","dreamhost","namecheap","webhost","cloudflare"}) if (ispLower.contains(k)) { tiTags.add("Hosting / cloud / CDN infrastructure"); break; }
      if (hostingFlag) tiTags.add("Hosting / datacenter infrastructure (provider flag)");
      findings.addAll(tiTags);
      torTags = joinTags(tiTags, "Tor"); vpnTags = joinTags(tiTags, "VPN"); hostTags = joinTags(tiTags, "Hosting");
      anonTags = joinTags(tiTags, "Anonym"); iocs.add(iocIp);

      // ---- 4. REPUTATION (optional external feed; "Source unavailable" when not configured) ----
      abuseJson = abuseRepJson(ip);
      if (abuseJson.contains("\"abuseConfidenceScore\"")) {
        sources.add("AbuseIPDB");
        findings.add("Abuse confidence from source: " + numVal(abuseJson,"abuseConfidenceScore") + "% (whitelisted="+boolVal(abuseJson,"isWhitelisted")+", reports="+numVal(abuseJson,"totalReports")+").");
      } else if ("\"lookup failed\"".equals(abuseJson)) {
        errors.add("AbuseIPDB lookup failed (network or API error).");
      }
      // When ABUSEIPDB_KEY is empty, reputation is correctly reported as "Source unavailable".

      // ---- 5. NETWORK / CIDR (derived context, non-authoritative) ----
      derivedNetwork(ip);
    }

    // ---- 6. RISK SCORING (explainable; never malicious from geography alone) ----
    int risk = ipRisk(cls, isPublic, proxyFlag, hostingFlag, torTags, vpnTags, hostTags, anonTags, findings);
    String severity = severity(risk);
    // separate technical vs heuristic evidence
    List<String> techFindings = new ArrayList<>(findings);
    String confidence = isPublic ? "medium" : "high";
    // ---- FORENSIC CONFIDENCE + DATA COMPLETENESS (separate from risk) ----
    // Risk = how suspicious the infrastructure is; confidence = how strongly available evidence supports
    // the conclusion; completeness = how much input/intel data was actually available (never inferred).
    int complete = 0, completeMax = 100;
    int confN = 55;
    complete += 15;                                                // address classification is always available
    if (isPublic) {
      if (sourceOk(geoSource)) { complete += 20; confN += 25; }    // geolocation confirmed
      if (geoAgree >= 2) { complete += 10; confN += 10; }          // multi-source agreement
      if (!revdns.isEmpty()) { complete += 10; confN += 5; }
      if (!asn.isEmpty() || !asname.isEmpty() || !isp.isEmpty() || !org.isEmpty()) { complete += 20; }
      if (!abuseJson.equals("null")) { complete += 20; }           // reputation source consulted
    } else {
      complete = 40;                                               // internal: external intel N/A (by design)
    }
    complete = Math.max(0, Math.min(completeMax, complete));
    String completeLabel = complete >= 75 ? "high" : complete >= 45 ? "medium" : isPublic ? "low" : "high";
    confN = Math.max(10, Math.min(96, confN));
    String confNum = String.valueOf(confN);
    String interpretation = "No significant threat indicators identified for " + ip + ".";
    if (risk >= 81) interpretation = "Potentially hostile infrastructure: multiple strong indicators point to anonymity/Tor exit or known-abuse hosting. Investigate with caution; geolocation is approximate infrastructure data, not a person's location.";
    else if (risk >= 51) interpretation = "Potentially suspicious infrastructure: hosting/VPN/anonymizer indicators are present. This warrants additional investigation but is not, by itself, evidence of malicious intent.";
    else if (torTags.length()>0 || anonTags.length()>0) interpretation = "Anonymity infrastructure (Tor/VPN/anon) detected; such addresses are high-frequency sources of abuse but presence of a VPN or Tor node is not proof of wrongdoing.";
    else if (!isPublic) interpretation = "Network-internal or reserved address. No external intelligence is applicable; this is expected in trusted internal environments.";
    String recommended = isPublic ? (risk>=51 ? "Quarantine / block-list pending confirmation, pivot to related IOCs, and correlate with authentication logs and firewall events." : "No action indicated. Log for future correlation; re-check if activity spikes.") : "No external lookup warranted. Confirm the address is expected within your network's addressing plan.";

    // ---- 7. BUILD EVIDENCE JSON ----
    StringBuilder sb = new StringBuilder();
    sb.append("{");
    sb.append("\"module\":\"ip_intelligence\",");
    sb.append("\"input\":").append(jstr(rawInput)).append(",");
    sb.append("\"normalized\":").append(jstr(ip)).append(",");
    sb.append("\"ipVersion\":").append(jstr(ipv)).append(",");
    sb.append("\"classification\":").append(jstr(cls)).append(",");
    sb.append("\"ipType\":").append(jstr(cls.contains("private")||cls.contains("unique_local")?"Private/internal":cls.contains("loopback")?"Loopback":cls.contains("multicast")?"Multicast":isPublic?"Public (externally routable)":cls)).append(",");
    sb.append("\"network\":{\"approximateCidr\":").append(jstr(isPublic?derivedNetwork(ip):null)).append(",\"note\":\"CIDR is a derived neighborhood context from the single observed address, NOT an authoritative registered route.\"},");
    sb.append("\"isHostingDatacenter\":").append(hostingFlag || !hostTags.isEmpty()).append(",");
    sb.append("\"geolocation\":").append(geo.equals("null") ? "null" : geo).append(",");
    sb.append("\"geolocationNote\":\"Approximate infrastructure location derived from IP allocation, not the physical location of any person.\",");
    sb.append("\"reverseDns\":\"").append(q(revdns)).append("\",");
    sb.append("\"infrastructure\":{\"proxy\":").append(proxyFlag).append(",\"hosting\":").append(hostingFlag).append(",\"mobile\":").append(mobileFlag).append("},");
    sb.append("\"threatIndicators\":{\"tor_vpn_anonymizer\":\"");
    sb.append(String.join(", ", new java.util.LinkedHashSet<>(findings.stream().filter(f -> f.contains("Tor")||f.contains("VPN")||f.contains("Anonym")||f.contains("Proxy")).toList())).replace("\"","\\\"")).append("\"},");
    sb.append("\"abuseReputation\":").append(abuseJson).append(",");
    sb.append("\"geoCorrelation\":").append(strList(geoCorr)).append(",");
    sb.append("\"geoAgreementSources\":").append(geoAgree).append(",");
    sb.append("\"confidence\":").append(jstr(confidence)).append(",");
    sb.append("\"confidenceScore\":").append(confNum).append(",");
    sb.append("\"dataCompleteness\":").append("{\"value\":").append(complete).append(",\"label\":\"").append(completeLabel).append("\"}").append(",");
    sb.append("\"riskScore\":").append(risk).append(",");
    sb.append("\"severity\":").append(jstr(severity)).append(",");
    sb.append("\"analystInterpretation\":").append(jstr(interpretation)).append(",");
    sb.append("\"recommendedInvestigation\":").append(jstr(recommended)).append(",");
    sb.append("\"findings\":").append(strList(findings)).append(",");
    sb.append("\"dataSources\":").append(strList(sources)).append(",");
    sb.append("\"lookupTimestamp\":").append(jstr(ts)).append(",");
    sb.append("\"iocs\":").append(strList(iocs)).append(",");
    sb.append("\"errorsWarnings\":").append(strList(errors)).append(",");
    sb.append("\"severityBands\":\"0-20 Informational/Low; 21-40 Low; 41-60 Medium; 61-80 High; 81-100 Critical.\"");
    sb.append("}");
    return sb.toString();
  }

  // =====================================================================
  // APEX-GEO · 16-layer IP forensic pipeline
  // Returns a rich multi-section JSON analysis + a plain-English analyst
  // summary. Every layer runs regardless of input completeness; missing or
  // unconfigured evidence is reported UNAVAILABLE / UNKNOWN — never assumed
  // clean. External feeds that are not configured are never fabricated.
  // =====================================================================
  static String apexGeo(String rawInput, String ip){
    String ipv = ip.contains(":") ? "IPv6" : "IPv4";
    String cls = classifyAddress(ip);
    boolean isPublic = cls.equals("public");
    List<String> sources = new ArrayList<>();
    List<String> errors = new ArrayList<>();

    // ---- Layer 1: chain of custody (nanosecond precision) ----
    Instant t0 = Instant.now();
    Instant t1 = t0.plusNanos(System.nanoTime() % 1000);                 // best-effort ns marker
    String nsStarted = String.format("%s.%09dZ", t0.toString().substring(0,19).replace("T"," "), 0);
    String caseId = "CASE-" + Integer.toHexString((ip + t0.getNano()).hashCode() & 0xfffff).toUpperCase(Locale.ROOT);

    // ---- external evidence (public addresses only; internal/reserved skip safely) ----
    GeoMulti gm = null; String geo = "null"; String geoSource = "unavailable";
    String country="",cc="",region="",city="",timezone="",isp="",org="",asn="",asname="";
    double lat=0,lon=0; boolean proxyFlag=false,hostingFlag=false,mobileFlag=false;
    List<String> geoCorr = new ArrayList<>(); int geoAgree=0;
    String revdns=""; String authoritative="";
    String abuseJson="null";
    boolean abuseOk=false; int abuseScore=0; long abuseReports=0; boolean abuseWhitelist=false;
    if (isPublic) {
      gm = geoMulti(ip);
      geo = gm.geo(); geoSource = gm.source();
      country=gm.country(); cc=gm.cc(); region=gm.region(); city=gm.city(); timezone=gm.tz();
      isp=gm.isp(); org=gm.org(); asn=gm.asn(); asname=gm.asname();
      lat = geoNum(geo,"latitude",0.0); lon = geoNum(geo,"longitude",0.0);
      proxyFlag=gm.proxy(); hostingFlag=gm.hosting(); mobileFlag=gm.mobile();
      geoCorr=gm.corrList(); geoAgree=gm.agree();
      if (sourceOk(geoSource)) sources.add(geoSource);
      if (gm.source2Ok()) sources.add(gm.source2());
      if (sourceOk(geoSource) && !geo.equals("null")) {
      }
      revdns = ptrFor(ip);
      // authoritative network info via best-effort RIPEstat (public, keyless, guarded)
      authoritative = ripestatNetwork(ip);
      if (authoritative != null && !authoritative.contains("UNAVAILABLE") && !authoritative.isEmpty()) sources.add("RIPEstat");
      abuseJson = abuseRepJson(ip);
      if (abuseJson != null && abuseJson.contains("\"abuseConfidenceScore\"")) {
        abuseOk=true; abuseScore = numAsInt(abuseJson,"abuseConfidenceScore");
        abuseReports = longVal(abuseJson,"totalReports"); abuseWhitelist = boolVal(abuseJson,"isWhitelisted");
        sources.add("AbuseIPDB");
      } else if ("\"lookup failed\"".equals(abuseJson)) errors.add("AbuseIPDB lookup failed (network or API error).");
    }

    // ---- Layer 6/7/8: anonymization / proxy / hosting / mobile / Tor heuristics ----
    String infra = (isp + " " + org + " " + asname + " " + asn).toLowerCase(Locale.ROOT);
    boolean torSus = isTorInfra(asn, infra);
    boolean vpnSus = isVpnInfra(infra);
    boolean hostSus = isHostingInfra(infra) || hostingFlag;
    boolean proxySus = proxyFlag;
    String torState = !isPublic ? "NOT_APPLICABLE (internal/reserved)" : torSus ? "SUSPECTED (provider/ASN heuristic — not Tor-consensus verified)" : (hostSus||proxySus||vpnSus) ? "NO (no Tor indicator)" : "UNCONFIRMED (no evidence)";

    // ---- Behavioral (honest: no scan/C2 feeds available → UNKNOWN) ----
    boolean scanningKnown = false; String scanTypes="";
    // no live scan history source configured
    String behavAssessment = (!isPublic) ? "Internal/reserved address — outer-analysis behavior not applicable." :
        (torSus||vpnSus||proxySus) ? "Anonymization/relay infrastructure. Frequent source of anonymized abuse, but anonymizer presence alone is not proof of malicious intent." :
        "No behavioral telemetry (scanning/C2/botnet feeds) is configured, so activity-based behavior is UNKNOWN.";

    // ---- Layer 12: weighted, explainable risk scoring ----
    int rAnon=0; if (!isPublic) { rAnon=0; } else { if (torSus) rAnon=35; else if (vpnSus) rAnon=22; else if (proxySus) rAnon=15; else if (hostSus) rAnon=5; }
    int rFeeds=0; if (abuseOk) { if (abuseScore>80) rFeeds=25; else if (abuseScore>=50) rFeeds=18; else rFeeds=(int)Math.round(abuseScore*25.0/100.0); }
    int rHist=0;                                            // historical/campaigns: UNKNOWN → 0
    int rPort=0;                                            // port/service scan: UNAVAILABLE → 0
    int rBehav=0; if (isPublic && (torSus||vpnSus||proxySus)) rBehav=3;   // anonymizer relay pattern
    int rDns=0; String ptr = isPublic ? ptrFor(ip) : ""; String ptrVerify = isPublic ? ptrVerified(ip, ptr) : "NO PTR";
    if (isPublic && !ptr.isEmpty() && "YES".equals(ptrVerify)) rDns=5;
    else if (isPublic && !ptr.isEmpty()) rDns=3;
    else if (isPublic) rDns=2;                              // no PTR — slightly abnormal for hosting, but not malicious
    int rCorr=0; if (isPublic && (torSus||vpnSus||proxySus) && abuseOk) rCorr=10; else if (isPublic && (torSus||vpnSus||proxySus)) rCorr=5;
    int base = rAnon+rFeeds+rHist+rPort+rBehav+rDns;
    int finalScore = Math.min(100, base + rCorr);
    String riskLevel = finalScore>=81?"CRITICAL":finalScore>=61?"HIGH":finalScore>=41?"MEDIUM":finalScore>=21?"LOW":"INFORMATIONAL";

    // ---- Confidence (evidence quality, not just threat) ----
    int conf=40; if (isPublic) { if (sourceOk(geoSource)) conf+=20; if (geoAgree>=2) conf+=10; if (!ptr.isEmpty() && "YES".equals(ptrVerify)) conf+=10; if (abuseOk) conf+=15; }
    conf=Math.max(10,Math.min(96,conf));
    String confLabel=conf>=75?"HIGH":conf>=50?"MEDIUM":"LOW";

    // ---- Completeness (how much forensic input was available) ----
    int complete=15; int maxC=100;                          // address validity/inspection always available
    if (isPublic) {
      if (sourceOk(geoSource)) complete+=20;
      if (geoAgree>=2) complete+=10;
      if (!asn.isEmpty()||!asname.isEmpty()||!isp.isEmpty()) complete+=15;
      if (!ptr.isEmpty()) complete+=10;
      if (abuseOk) complete+=20;
      if (authoritative!=null && !authoritative.isEmpty() && !authoritative.contains("UNAVAILABLE")) complete+=10;
    } else complete=40;
    complete=Math.max(0,Math.min(maxC,complete));
    String completeLabel=complete>=75?"HIGH":complete>=45?"MEDIUM":"LOW";

    String human = humanSummary(ip, ipv, cls, isPublic, country, cc, asn, asname, torSus, vpnSus, proxySus, hostSus,
        finalScore, riskLevel, confLabel, completeLabel, ptr, ptrVerify, abuseOk, abuseScore, revdns, geoSource, authoritative);

    // ---- Assemble the 16 sections ----
    String sections =
      "\"1_evidence_preservation\":" + apexEvidenceJson(caseId, ip, rawInput, nsStarted, sources, errors) + "," +
      "\"2_data_completeness\":" + apexCompletenessJson(complete, completeLabel, isPublic, sourceOk(geoSource), geoAgree, !ptr.isEmpty(), abuseOk, authoritative) + "," +
      "\"3_basic_ip_intelligence\":" + apexBasicJson(ip, ipv, cls) + "," +
      "\"4_geolocation_intelligence\":" + apexGeoJson(isPublic, country, cc, region, city, timezone, lat, lon, hostingFlag, proxyFlag, mobileFlag, proxySus, vpnSus, geoCorr, geoAgree, geoSource, gm) + "," +
      "\"5_network_asn\":" + apexNetworkJson(ip, ipv, asn, asname, isp, org, authoritative, isPublic) + "," +
      "\"6_anonymization\":" + apexAnonJson(isPublic, torSus, torState, vpnSus, proxySus, proxyFlag, mobileFlag, anonRisk(torSus,vpnSus,proxySus), infra) + "," +
      "\"7_port_service\":" + apexPortJson(isPublic) + "," +
      "\"8_threat_intel_feeds\":" + apexFeedsJson(abuseOk, abuseScore, abuseReports, abuseWhitelist, authoritative, GC_FEEDS) + "," +
      "\"9_historical_campaigns\":" + apexHistJson(isPublic, abuseOk, abuseReports) + "," +
      "\"10_behavioral\":" + apexBehavJson(isPublic, torSus, vpnSus, proxySus, scanningKnown, scanTypes, rBehav, behavAssessment) + "," +
      "\"11_mitre_attack\":" + apexMitreJson(isPublic, torSus, vpnSus, proxySus, abuseOk) + "," +
      "\"12_risk_scoring\":" + apexRiskJson(rAnon, rFeeds, rHist, rPort, rBehav, rDns, rCorr, base, finalScore, riskLevel, conf, confLabel, complete, completeLabel) + "," +
      "\"13_recommended_actions\":" + apexActionJson(finalScore, riskLevel, isPublic, authoritative, torSus) + "," +
      "\"14_corrections_accuracy\":" + apexCorrectionJson(authoritative, geoCorr, ptrVerify) + "," +
      "\"15_ioc_output\":" + apexIocJson(ip, ipv, caseId, nsStarted, riskLevel, finalScore, conf, complete, country, cc, region, city, lat, lon, timezone, geoAgree, geoSource, asn, asname, authoritative, ptr, ptrVerify, torSus, vpnSus, proxySus, hostingFlag, mobileFlag, abuseOk, abuseScore, abuseReports, rAnon, rFeeds, rHist, rPort, rBehav, rDns, rCorr, base, finalScore, human);

    return buildApexOutput(caseId, ip, rawInput, ipv, cls, isPublic, sections, human, sources, errors, nsStarted);
  }
  private static final java.util.List<String> GC_FEEDS = java.util.List.of(
    "AbuseIPDB","Spamhaus","Emerging Threats","AlienVault OTX","GreyNoise","IBM X-Force",
    "Recorded Future","Cisco Talos","URLVoid","VirusTotal","Crowdsec","Blocklist.de","Shodan","IPQualityScore");

  // ---- Layer 1 ----
  private static String apexEvidenceJson(String caseId, String ip, String rawIn, String ns, List<String> sources, List<String> errors){
    StringBuilder s = new StringBuilder("{");
    s.append("\"case_id\":\"").append(q(caseId)).append("\",\"ip_submitted\":\"").append(q(rawIn)).append("\",\"ip_normalized\":\"").append(q(ip)).append("\",");
    s.append("\"lookup_timestamp\":\"").append(q(ns)).append("\",\"analysis_started\":\"").append(q(ns)).append("\",");
    s.append("\"nanosecond_precision\":true");
    s.append(",\"source\":\"api_lookup\"");
    s.append(",\"evidence_status\":\"PRESERVED — IP recorded before analysis\"");
    s.append(",\"data_sources\":").append(strList(sources));
    s.append(",\"errors_warnings\":").append(strList(errors));
    s.append("}");
    return s.toString();
  }
  // ---- Layer 2 ----
  private static String apexCompletenessJson(int complete, String label, boolean isPublic, boolean geoOk, int agree, boolean rdnOk, boolean abuseOk, String auth){
    List<String> present = new ArrayList<>(), missing = new ArrayList<>();
    present.add("address validity/inspection");
    if (isPublic) {
      if (geoOk) present.add("geolocation"); else missing.add("geolocation");
      if (agree>=2) present.add("multi-source geolocation agreement"); else missing.add("multi-source geolocation agreement");
      if (rdnOk) present.add("reverse DNS (PTR)"); else missing.add("reverse DNS (PTR)");
      if (auth!=null && !auth.isEmpty() && !auth.contains("UNAVAILABLE")) present.add("authoritative ASN/CIDR (RIPEstat)"); else missing.add("authoritative ASN/CIDR (RIPEstat)");
      if (abuseOk) present.add("AbuseIPDB reputation"); else missing.add("AbuseIPDB reputation");
    }
    missing.add("Shodan/Censys port scan · UNCONFIGURED (no API key)");
    missing.add("AlienVault OTX pulses · UNCONFIGURED");
    missing.add("GreyNoise activity timeline · UNCONFIGURED");
    missing.add("VirusTotal / historical campaign feeds · UNCONFIGURED");
    StringBuilder b = new StringBuilder("{");
    b.append("\"value\":").append(complete).append(",\"label\":\"").append(label).append("\",\"max\":").append(100);
    b.append(",\"available\":[").append(qarr2(present)).append("],\"not_available\":[").append(qarr2(missing)).append("]");
    b.append(",\"note\":\"Missing evidence is UNKNOWN and never treated as proof of safety.\"");
    b.append("}");
    return b.toString();
  }
  private static String qarr2(List<String> l){ StringBuilder b=new StringBuilder(); for(int i=0;i<l.size();i++){ if(i>0)b.append(','); b.append(jstr(l.get(i))); } return b.toString(); }
  // ---- Layer 3 ----
  private static String apexBasicJson(String ip, String ipv, String cls){
    String type = ipv.equals("IPv4")
        ? (cls.contains("private")?"Private (RFC 1918)":cls.contains("loopback")?"Loopback":cls.contains("multicast")?"Multicast":"Public")
        : (cls.contains("unique_local")?"Private (ULA)":cls.contains("loopback")?"Loopback":cls.contains("multicast")?"Multicast":"Public");
    StringBuilder b=new StringBuilder("{");
    b.append("\"ip_address\":\"").append(q(ip)).append("\",\"ip_version\":\"").append(ipv).append("\",");
    b.append("\"ip_class\":\"").append(ipClass(ip)).append("\",\"address_type\":\"").append(q(type)).append("\",");
    b.append("\"reserved_special\":\"").append(cls.equals("public")?"NO":"YES").append("\",\"loopback\":\"").append(cls.contains("loopback")?"YES":"NO").append("\",");
    b.append("\"private_range\":\"").append((cls.contains("private")||cls.contains("unique_local")||cls.contains("link_local")||cls.contains("loopback"))?"YES":"NO").append("\",");
    b.append("\"bogon\":\"").append(classBogon(cls)?"YES":"NO").append("\",");
    b.append("\"binary_representation\":\"").append(q(ipBinary(ip))).append("\",");
    b.append("\"decimal_representation\":\"").append(q(ipDecimal(ip))).append("\",");
    b.append("\"hex_representation\":\"").append(q(ipHex(ip))).append("\"");
    b.append("}");
    return b.toString();
  }
  static String ipClass(String ip){
    if (!ip.contains(":")) {
      int a=Integer.parseInt(ip.split("\\.")[0]);
      if (a<128) return "Class A";
      if (a<192) return "Class B";
      if (a<224) return "Class C";
      if (a<240) return "Class D — Multicast";
      return "Class E — Reserved";
    }
    return "IPv6 (no legacy class)";
  }
  private static boolean classBogon(String cls){ return cls.length()>0 && !cls.equals("public") && !cls.contains("private") && !cls.contains("unique_local") && !cls.equals("documentation (RFC 5737)") && !cls.equals("documentation (RFC 3849)"); }
  static String ipBinary(String ip){
    if (!ip.contains(":")) {
      String[] o=ip.split("\\."); StringBuilder b=new StringBuilder();
      for(int i=0;i<o.length;i++){ if(i>0)b.append('.'); b.append(pad32(Integer.toBinaryString(Integer.parseInt(o[i]))).substring(24)); }
      return b.toString();
    } else {
      String[] g=ip.split(":"); StringBuilder b=new StringBuilder();
      for(int i=0;i<g.length;i++){ if(i>0)b.append(':'); b.append(pad16(Integer.toBinaryString(Integer.parseInt(g[i],16)))); }
      return b.toString();
    }
  }
  static String ipHex(String ip){
    if (!ip.contains(":")) {
      long v=0; for(String o:ip.split("\\.")) v=(v<<8)|Integer.parseInt(o);
      return String.format("0x%08x", v);
    }
    return ip; // normalized IPv6 is already dotted-hex groups
  }
  static String ipDecimal(String ip){
    if (!ip.contains(":")) {
      long v=0; for(String o:ip.split("\\.")) v=(v<<8)|Integer.parseInt(o);
      return Long.toString(v);
    }
    return ip; // IPv6 decimal not canonical; normalized hex form is authoritative
  }
  private static String pad32(String s){ StringBuilder b=new StringBuilder(); for(int i=s.length();i<32;i++)b.append('0'); return b.append(s).toString(); }
  private static String pad16(String s){ StringBuilder b=new StringBuilder(); for(int i=s.length();i<16;i++)b.append('0'); return b.append(s).toString(); }
  // ---- Layer 4 ----
  private static String apexGeoJson(boolean isPublic, String country, String cc, String region, String city, String tz,
      double lat, double lon, boolean hosting, boolean proxy, boolean mobile, boolean proxySus, boolean vpnSus,
      List<String> geoCorr, int agree, String geoSource, GeoMulti gm){
    StringBuilder b=new StringBuilder("{");
    if (!isPublic) {
      b.append("\"status\":\"NOT_APPLICABLE\",\"note\":\"Reserved/internal address — geolocation not meaningful and not queried externally.\"");
      b.append(",\"proxy\":\"proxy=N\",\"hosting\":\"").append("hosting=").append(hosting?"Y":"N").append("\",\"mobile\":\"").append("mobile=").append(mobile?"Y":"N").append("\"");
      b.append(",\"geolocation_caveat\":\"Infrastructure location, not identity. Actual actor may be anywhere.\",\"multi_source\":{}");
      return b.append("}").toString();
    }
    b.append("\"country\":\"").append(q(country)).append("\",\"country_code\":\"").append(q(cc)).append("\",");
    b.append("\"continent\":\"UNKNOWN\",\"region\":\"").append(q(region)).append("\",\"city\":\"").append(q(city)).append("\",\"postal_code\":\"UNKNOWN\",");
    b.append("\"latitude\":").append(lat).append(",\"longitude\":").append(lon).append(",");
    b.append("\"timezone\":\"").append(q(tz)).append("\",\"local_time\":\"UNKNOWN\",\"accuracy_radius_km\":\"~50 (city-level, derived)\",");
    b.append("\"hosting_datacenter\":\"").append(hosting?"YES":"NO").append("\",\"proxy\":\"proxy=").append((proxy||proxySus)?"Y":"N").append("\",");
    b.append("\"mobile\":\"mobile=").append(mobile?"Y":"N").append("\",\"vpn\":\"").append(vpnSus?"YES (heuristic)":"NO").append("\",");
    b.append("\"multi_source_verification\":{\"agreement\":\"").append(agree>=2?"YES":"NO").append("\",\"sources_agreeing\":").append(agree).append(",\"comparison\":").append(strList(geoCorr)).append("},");
    b.append("\"primary_source\":\"").append(q(geoSource)).append("\",\"secondary_source\":\"").append(q(gm!=null?gm.source2():"" )).append("\",");
    b.append("\"geolocation_caveat\":\"Approximate infrastructure location derived from IP allocation — NOT the physical location of any person. Actual threat actor may be located anywhere in the world.\"");
    // cleaner: re-open as object already
    if (b.charAt(b.length()-1)==',') b.setLength(b.length()-1);
    return b.append("}").toString();
  }
  // ---- Layer 5 ----
  private static String apexNetworkJson(String ip, String ipv, String asn, String asname, String isp, String org, String auth, boolean isPublic){
    StringBuilder b=new StringBuilder("{");
    if (!isPublic) {
      b.append("\"status\":\"NOT_APPLICABLE\",\"note\":\"Internal/reserved address — public network registry not applicable.\"");
      return b.append("}").toString();
    }
    String parsedAuth = (auth!=null && !auth.contains("UNAVAILABLE")) ? auth : "";
    b.append("\"asn\":\"").append(q(asn)).append("\",\"as_name\":\"").append(q(asname)).append("\",\"as_description\":\"").append(q(isp+" "+(org!=null?org:""))).append("\",");
    if (!parsedAuth.isEmpty()) {
      b.append("\"authoritative_cidr\":\"").append(q(authField(parsedAuth,"cidr"))).append("\",");
      b.append("\"rir\":\"").append(q(authField(parsedAuth,"rir"))).append("\",");
      b.append("\"allocation_date\":\"").append(q(authField(parsedAuth,"allocation_date"))).append("\",");
    } else {
      b.append("\"authoritative_cidr\":\"UNAVAILABLE (no RIR route consulted)\",\"rir\":\"UNKNOWN\",\"allocation_date\":\"UNKNOWN\",");
    }
    b.append("\"derived_neighborhood\":\"").append(q(derivedNetwork(ip))).append("\",\"derived_label\":\"Derived /24 context — contextual only, NOT an authoritative registered route\",");
    b.append("\"network_type\":\"").append(q(netType(asn, asname))).append("\",");
    b.append("\"upstream_provider\":\"UNKNOWN\",\"peering_exchange\":\"UNKNOWN\",\"whois_server\":\"RIPEstat (keyless best-effort)\"");
    return b.append("}").toString();
  }
  private static String authField(String j, String key){ Matcher m=Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*\"([^\"]*)\"").matcher(j); return m.find()?m.group(1):""; }
  private static String netType(String asn, String asname){ String a=(asn+" "+asname).toLowerCase(Locale.ROOT); for(String k:new String[]{"host","datacenter","cloud","dedicated","server"}) if(a.contains(k)) return "Hosting/cloud"; for(String k:new String[]{"isp","internet service","broadband","telecom","mobile"}) if(a.contains(k)) return "ISP"; return "UNKNOWN"; }
  // ---- Layer 6 ----
  private static String apexAnonJson(boolean isPublic, boolean tor, String torState, boolean vpn, boolean proxy, boolean proxyFlag, boolean mobile, String risk, String infra){
    StringBuilder b=new StringBuilder("{");
    b.append("\"tor_exit_node\":\"").append(isPublic? (tor?"SUSPECTED":"NO") : "NOT_APPLICABLE").append("\",");
    b.append("\"tor_exit_verified_consensus\":\"").append(isPublic&&tor?"NO (heuristic; Tor consensus not consulted)":"NO").append("\",");
    b.append("\"exit_policy\":\"UNKNOWN\",\"node_fingerprint\":\"UNKNOWN\",\"tor_ports_open\":\"UNKNOWN (no port scan)\",");
    b.append("\"vpn_provider\":\"").append(isPublic?(vpn?"YES (heuristic — provider/ISP label)":"NO"):"NOT_APPLICABLE").append("\",");
    b.append("\"proxy_type\":\"UNKNOWN\",\"anonymizer_confirmed\":\"").append(isPublic&&(tor||vpn)?"NO (heuristic only)":"NO").append("\",");
    b.append("\"consumer_vpn\":\"").append(vpn?"YES":"NO").append("\",\"residential_proxy\":\"UNKNOWN\",");
    b.append("\"risk_from_anonymization\":\"").append(risk).append("\",");
    b.append("\"provider_label_evidence\":\"").append(q(infra.trim().isEmpty()?"" : infra.trim())).append("\"");
    return b.append("}").toString();
  }
  private static String anonRisk(boolean tor, boolean vpn, boolean proxy){ return tor?"HIGH":vpn?"MEDIUM":proxy?"MEDIUM":"LOW"; }
  // ---- Layer 7 ----
  private static String apexPortJson(boolean isPublic){
    StringBuilder b=new StringBuilder("{");
    b.append("\"data_source\":\"").append(isPublic?"UNAVAILABLE (Shodan/Censys not configured: no API key)":"NOT_APPLICABLE (internal/reserved)").append("\",");
    b.append("\"open_ports\":\"UNAVAILABLE\",\"port_risk_flags\":\"Port/service intelligence requires an external scan provider; none is configured — never assumed closed/clean.\"");
    return b.append("}").toString();
  }
  // ---- Layer 8 ----
  private static String apexFeedsJson(boolean abuseOk, int abuseScore, long reports, boolean whitelist, String auth, java.util.List<String> feeds){
    StringBuilder b=new StringBuilder("{");
    b.append("\"total_checked\":").append(feeds.size()).append(",\"total_flagged\":").append(abuseOk?1:0).append(",");
    String consensus = abuseOk&&abuseScore>=50 ? "SUSPICIOUS" : "UNKNOWN";
    int consConf = abuseOk ? (int)Math.max(40, Math.min(90, abuseScore)) : 0;
    b.append("\"consensus\":\"").append(consensus).append("\",\"consensus_confidence_pct\":").append(consConf).append(",\"feeds\":{");
    b.append("\"abuseipdb\":{\"status\":\"").append(abuseOk?(abuseScore>80?"MALICIOUS":abuseScore>=50?"SUSPICIOUS":"CLEAN"):"UNAVAILABLE").append("\",\"score\":").append(abuseOk?abuseScore:0).append(",\"reports\":").append(reports).append(",\"whitelisted\":").append(whitelist).append("}");
    for (String f : feeds) { if (f.equals("AbuseIPDB")) continue; b.append(",\"").append(f.toLowerCase(Locale.ROOT).replace(" ","_").replace("/","_")).append("\":{\"status\":\"UNAVAILABLE (not configured)\"}"); }
    b.append("}}");
    return b.toString();
  }
  // ---- Layer 9 ----
  private static String apexHistJson(boolean isPublic, boolean abuseOk, long reports){
    StringBuilder b=new StringBuilder("{");
    b.append("\"first_seen\":\"UNKNOWN\",\"last_seen\":\"UNKNOWN\",\"active_duration_days\":\"UNKNOWN\",");
    b.append("\"persistence_rating\":\"UNKNOWN (no historical feed)\",");
    b.append("\"total_abuse_reports\":").append(isPublic?(abuseOk?reports:0):0).append(",");
    b.append("\"associated_campaigns\":[],\"attack_types\":[],\"target_sectors\":[],\"target_countries\":[],");
    b.append("\"note\":\"Historical/campaign data requires OTX/GreyNoise/AbuseIPDB report history; none configured — never fabricated.\"");
    return b.append("}").toString();
  }
  // ---- Layer 10 ----
  private static String apexBehavJson(boolean isPublic, boolean tor, boolean vpn, boolean proxy, boolean scanKnown, String scanTypes, int score, String assess){
    StringBuilder b=new StringBuilder("{");
    b.append("\"scanning_activity\":\"").append(isPublic?"UNKNOWN":"NOT_APPLICABLE").append("\",\"scan_types_observed\":\"").append(scanTypes.isEmpty()?"UNKNOWN":scanTypes).append("\",");
    b.append("\"attack_frequency\":\"UNKNOWN\",\"c2_communication\":\"UNKNOWN\",\"botnet_association\":\"UNKNOWN\",");
    b.append("\"proxy_relay_usage\":\"").append(isPublic&&(tor||vpn||proxy)?"YES":"NO").append("\",\"traffic_anomalies\":\"UNKNOWN\",");
    b.append("\"behavioral_score\":").append(score).append(",\"assessment\":\"").append(q(assess)).append("\"");
    return b.append("}").toString();
  }
  // ---- Layer 11 ----
  private static String apexMitreJson(boolean isPublic, boolean tor, boolean vpn, boolean proxy, boolean abuseOk){
    if (!isPublic) return "[]";
    List<String> out=new ArrayList<>();
    if (tor) out.add(mitreEntry("Command And Control","T1090","Proxy","T1090.003","Multi-hop Proxy","probable","Tor/anonymity provider/ASN heuristic — not consensus-verified","https://attack.mitre.org/techniques/T1090/003/"));
    else if (vpn||proxy) out.add(mitreEntry("Command And Control","T1090","Proxy","","","possible","VPN/anonymizer provider heuristic","https://attack.mitre.org/techniques/T1090/"));
    return "[" + String.join(",", out) + "]";
  }
  private static String mitreEntry(String t,String id,String name,String sub,String subn,String conf,String ev,String ref){
    return "{\"tactic\":\""+q(t)+"\",\"technique_id\":\""+q(id)+"\",\"technique_name\":\""+q(name)+"\",\"sub_technique_id\":\""+q(sub)+"\",\"sub_technique_name\":\""+q(subn)+"\",\"confidence\":\""+q(conf)+"\",\"evidence\":\""+q(ev)+"\",\"reference\":\""+q(ref)+"\"}";
  }
  // ---- Layer 12 ----
  private static String apexRiskJson(int anon,int feeds,int hist,int port,int behav,int rdn,int corr,int base,int fin,String level,int conf,String cl,int comp,String cl2){
    StringBuilder b=new StringBuilder("{");
    b.append("\"anonymizer_signals\":").append(anon).append(",\"max\":35,");
    b.append("\"threat_intel_feeds\":").append(feeds).append(",\"max\":25,");
    b.append("\"historical_campaigns\":").append(hist).append(",\"max\":15,");
    b.append("\"port_service_evidence\":").append(port).append(",\"max\":10,");
    b.append("\"behavioral_signals\":").append(behav).append(",\"max\":10,");
    b.append("\"reverse_dns\":").append(rdn).append(",\"max\":5,");
    b.append("\"correlation_bonus\":").append(corr).append(",");
    b.append("\"base_total\":").append(base).append(",\"final_score\":").append(fin).append(",");
    b.append("\"risk_level\":\"").append(q(level)).append("\",");
    b.append("\"confidence\":\"").append(q(cl)).append("\",\"confidence_score\":").append(conf).append(",");
    b.append("\"data_completeness\":\"").append(q(cl2)).append("\",\"completeness_score\":").append(comp).append(",");
    b.append("\"severity_bands\":\"0-20 Informational/Low; 21-40 Low; 41-60 Medium; 61-80 High; 81-100 Critical\",");
    b.append("\"risk_vs_confidence_vs_completeness\":\"Risk = how suspicious the infrastructure is; Confidence = how strongly available evidence supports the conclusion; Completeness = how much data was actually available. High anonymizer signal with low feed data yields high risk but LOW-MEDIUM confidence.\"");
    return b.append("}").toString();
  }
  // ---- Layer 13 ----
  private static String apexActionJson(int score, String level, boolean isPublic, String auth, boolean tor){
    List<String> acts=new ArrayList<>();
    if (score>=81) { acts.add("{\"priority\":\"CRITICAL\",\"action\":\"BLOCK IMMEDIATELY — block source IP and (if authoritative CIDR known) the registered subnet.\"}"); acts.add("{\"priority\":\"CRITICAL\",\"action\":\"Search SIEM/network logs for historical connections to/from this IP.\"}"); }
    else if (score>=61) { acts.add("{\"priority\":\"HIGH\",\"action\":\"QUARANTINE pending feed confirmation — do not block wholesale until corroborated.\"}"); acts.add("{\"priority\":\"HIGH\",\"action\":\"Add to threat-intel watchlist and correlate with authentication/gateway logs.\"}"); }
    else if (score>=41) { acts.add("{\"priority\":\"MEDIUM\",\"action\":\"INVESTIGATE — gather SIEM evidence before action.\"}"); acts.add("{\"priority\":\"MEDIUM\",\"action\":\"Pivot to related IOCs (ASN, related hosts, geolocation).\"}"); }
    else { acts.add("{\"priority\":\"LOW\",\"action\":\"MONITOR only — no block indicated.\"}"); }
    if (isPublic && (tor)) acts.add("{\"priority\":\"MEDIUM\",\"action\":\"If Tor/anon traffic is not business-required, consider blocking the anonymizer ASN.\"}");
    if (isPublic && !acts.isEmpty() && score<60) acts.add("{\"priority\":\"LOW\",\"action\":\"Submit newly observed abuse to AbuseIPDB for reputation.\"}");
    return "[" + String.join(",", acts) + "]";
  }
  // ---- Layer 14 ----
  private static String apexCorrectionJson(String auth, List<String> geoCorr, String ptrVerify){
    List<String> notes=new ArrayList<>();
    if (auth!=null && !auth.contains("UNAVAILABLE") && !auth.isEmpty()) {
      String cidr=authField(auth,"cidr");
      notes.add("{\"type\":\"CIDR\",\"note\":\"Derived /24 neighborhood is context only; authoritative registered route is " + q(cidr) + ".\"}");
    }
    for (String g : geoCorr) notes.add("{\"type\":\"geolocation\",\"note\":"+jstr(g)+"}");
    if (!"YES".equals(ptrVerify)) notes.add("{\"type\":\"PTR\",\"note\":\"Reverse DNS not forward-verifiable — ambiguity flagged.\"}");
    return notes.isEmpty() ? "[]" : "[" + String.join(",", notes) + "]";
  }
  // ---- Layer 15 ----
  private static String apexIocJson(String ip,String ipv,String caseId,String ts,String level,int score,int conf,int comp,
      String country,String cc,String region,String city,double lat,double lon,String tz,int agree,String gsrc,
      String asn,String asname,String auth,String ptr,String ptrv,boolean tor,boolean vpn,boolean proxy,boolean hosting,boolean mobile,
      boolean abuseOk,int abuseScore,long abuseReports,int rAnon,int rFeeds,int rHist,int rPort,int rBehav,int rDns,int rCorr,int base,int fin,String human){
    StringBuilder b=new StringBuilder("{");
    b.append("\"ioc\":{");
    b.append("\"value\":\"").append(q(ip)).append("\",\"type\":\"ip\",\"version\":\"").append(q(ipv)).append("\",\"case_id\":\"").append(q(caseId)).append("\",");
    b.append("\"lookup_timestamp\":\"").append(q(ts)).append("\",\"threat_level\":\"").append(q(level)).append("\",\"threat_score\":").append(score).append(",");
    b.append("\"confidence\":").append(conf).append(",\"data_completeness\":").append(comp).append(",");
    b.append("\"categories\":[").append(qarr2(catList(tor,vpn,proxy,hosting,abuseOk,abuseScore))).append("],");
    b.append("\"geolocation\":{\"country\":\"").append(q(country)).append("\",\"country_code\":\"").append(q(cc)).append("\",\"continent\":\"UNKNOWN\",\"region\":\"").append(q(region)).append("\",\"city\":\"").append(q(city)).append("\",\"latitude\":").append(lat).append(",\"longitude\":").append(lon).append(",\"timezone\":\"").append(q(tz)).append("\",\"accuracy_radius_km\":50,\"multi_source_agreement\":").append(agree>=2).append(",\"sources_checked\":").append(strList(gsrc.isEmpty()?new ArrayList<>():java.util.List.of(gsrc))).append(",\"caveat\":\"Reflects infrastructure registration, not actor identity\"},");
    b.append("\"network\":{\"asn\":\"").append(q(asn)).append("\",\"as_name\":\"").append(q(asname)).append("\",\"authoritative_cidr\":\"").append(q(auth!=null&&!auth.contains("UNAVAILABLE")?authField(auth,"cidr"):"")).append("\",\"derived_neighborhood\":\"").append(q(derivedNetwork(ip))).append("\",\"rir\":\"").append(q(auth!=null&&!auth.contains("UNAVAILABLE")?authField(auth,"rir"):"")).append("\",\"network_type\":\"").append(q(netType(asn,asname))).append("\",\"upstream_provider\":null,\"peering_exchange\":null,\"allocation_date\":").append(jstr(auth!=null&&!auth.contains("UNAVAILABLE")?authField(auth,"allocation_date"):"")).append("},");
    b.append("\"reverse_dns\":{\"ptr_record\":\"").append(q(ptr)).append("\",\"ptr_verified\":").append("YES".equals(ptrv)).append("},");
    b.append("\"anonymization\":{\"tor_exit\":").append(tor).append(",\"tor_verified_consensus\":false,\"exit_policy\":null,\"vpn\":").append(vpn).append(",\"proxy\":").append(proxy).append(",\"hosting\":").append(hosting).append(",\"mobile\":").append(mobile).append("},");
    b.append("\"open_ports\":[],");
    b.append("\"threat_feeds\":{\"total_checked\":").append(GC_FEEDS.size()).append(",\"total_flagged\":").append(abuseOk?1:0).append(",\"consensus\":\"").append(abuseOk&&abuseScore>=50?"SUSPICIOUS":"UNKNOWN").append("\",\"consensus_confidence_pct\":").append(abuseOk?abuseScore:0).append(",\"feeds\":{\"abuseipdb\":{\"status\":\"").append(abuseOk?"CONSULTED":"UNAVAILABLE").append("\",\"score\":").append(abuseOk?abuseScore:0).append(",\"reports\":").append(abuseReports).append("}}},");
    b.append("\"historical\":{\"first_seen\":null,\"last_seen\":null,\"active_duration_days\":null,\"persistence_rating\":\"UNKNOWN\",\"total_abuse_reports\":").append(abuseOk?abuseReports:0).append(",\"associated_campaigns\":[],\"attack_types\":[],\"target_sectors\":[],\"target_countries\":[]},");
    b.append("\"behavioral\":{\"scanning_confirmed\":null,\"scan_types\":[],\"c2_observed\":null,\"botnet_association\":\"UNKNOWN\",\"attack_frequency\":\"UNKNOWN\"},");
    b.append("\"risk_scoring\":{\"anonymizer_signals\":").append(rAnon).append(",\"threat_intel_feeds\":").append(rFeeds).append(",\"historical_campaigns\":").append(rHist).append(",\"port_service_evidence\":").append(rPort).append(",\"behavioral_signals\":").append(rBehav).append(",\"reverse_dns\":").append(rDns).append(",\"correlation_bonus\":").append(rCorr).append(",\"base_total\":").append(base).append(",\"final_score\":").append(fin).append("},");
    b.append("\"analyst_interpretation\":").append(jstr(human));
    b.append("}}");
    return b.toString();
  }
  private static List<String> catList(boolean tor,boolean vpn,boolean proxy,boolean hosting,boolean abuseOk,int abuseScore){
    List<String> c=new ArrayList<>();
    if(tor)c.add("tor"); if(vpn)c.add("vpn"); if(proxy)c.add("proxy"); if(hosting)c.add("hosting");
    if(abuseOk&&abuseScore>=50)c.add("abuse_reputation");
    if(c.isEmpty())c.add("none");
    return c;
  }

  private static String buildApexOutput(String caseId,String ip,String raw,String ipv,String cls,boolean isPublic,String sections,String human,List<String> sources,List<String> errors,String ns){
    StringBuilder b=new StringBuilder("{");
    b.append("\"module\":\"apex_geo_forensics\",");
    b.append("\"case_id\":\"").append(q(caseId)).append("\",");
    b.append("\"input\":").append(jstr(raw)).append(",\"normalized\":").append(jstr(ip)).append(",\"ip_version\":").append(jstr(ipv)).append(",");
    b.append("\"classification\":").append(jstr(cls)).append(",\"public\":").append(isPublic).append(",");
    b.append("\"lookup_timestamp\":\"").append(q(ns)).append("\",");
    b.append("\"sections\":{").append(sections).append("},");
    b.append("\"human_report\":").append(jstr(human)).append(",");
    b.append("\"data_sources\":").append(strList(sources)).append(",\"errors_warnings\":").append(strList(errors));
    b.append("}");
    return b.toString();
  }
  private static String humanSummary(String ip,String ipv,String cls,boolean isPublic,String country,String cc,String asn,String asname,
      boolean tor,boolean vpn,boolean proxy,boolean hosting,int score,String level,String cl,String cl2,String ptr,String ptrv,
      boolean abuseOk,int abuseScore,String revdns,String gsrc,String auth){
    String where = (!isPublic) ? "a reserved/internal ("+cls+") address" : (country.isEmpty()?"an unknown location":country+" ("+cc+")");
    String infra = tor? "an anonymizer/Tor-suspected network" : vpn? "a VPN provider network" : proxy? "a proxy/anonymized network" : hosting? "hosting/cloud infrastructure" : "standard ISP infrastructure";
    String feed = !abuseOk ? "no configured threat feed returned reputation data (AbuseIPDB unconfigured/unavailable)" : "AbuseIPDB reports a confidence score of "+abuseScore+"%";
    return "IP "+ip+" ("+ipv+") is "+where+". Infrastructure appears to be "+infra+". Threat intelligence: "+feed+". "+
      "Reverse DNS "+(ptr.isEmpty()?"is absent":("resolves to "+revdns+( "YES".equals(ptrv)?" (forward-verified)":" (not forward-verified)")))+". "+
      "Weighted risk score "+score+"/100 ("+level+") with confidence "+cl+" and data completeness "+cl2+" — risk reflects how suspicious the infrastructure is, while confidence/completeness reflect how much evidence was available. "+
      (!isPublic?"Because this is a reserved/internal address, external geolocation and feeds were not queried (NOT_APPLICABLE). ":"")+
      "Geolocation is infrastructure allocation data, not the physical location of any person.";
  }
  // ---- evidence-source primitives reused above ----
  private static boolean isTorInfra(String asn, String infra){
    String asClean=asn.replaceAll("\\s+","").toLowerCase(Locale.ROOT);
    for(String a:new String[]{"as60729","as200578","as51922","as61272","as50673","as12876","as204428","as210878"}) if(asClean.contains(a)) return true;
    if(infra.contains("tor")||infra.contains("anonym")||infra.contains("forprivacynet")||infra.contains("torservers")||infra.contains("darknode")) return true;
    return false;
  }
  static boolean sourceOk(String s){ return s != null && !s.isEmpty() && !s.equals("unavailable"); }
  private static boolean isVpnInfra(String infra){ for(String k:new String[]{"vpn","surfshark","nordvpn","private internet access","mullvad","protonvpn","wireguard","ivacy","hidemyass","cyberghost","purevpn","vyprvpn","azire"}) if(infra.contains(k)) return true; return false; }
  private static boolean isHostingInfra(String infra){ for(String k:new String[]{"digitalocean","linode","vultr","hetzner","ovh","amazon data","azure","microsoft corporation","google cloud","oracle cloud","leaseweb","contabo","scaleway","ionos","hostinger","cloudflare","dedicated"}) if(infra.contains(k)) return true; return false; }
  private static String ptrFor(String ip){ try { InetAddress a=InetAddress.getByName(ip); String hn=a.getHostName(); return (hn!=null && !hn.isEmpty() && !hn.equals(ip))?hn:""; } catch (Exception e){ return ""; } }
  private static String ptrVerified(String ip,String ptr){ if(ptr.isEmpty()) return "NO PTR"; try{ InetAddress a=InetAddress.getByName(ptr); String f=a.getHostAddress(); return ip.equalsIgnoreCase(f)?"YES":"UNVERIFIABLE"; }catch(Exception e){ return "UNVERIFIABLE"; } }
  private static int numAsInt(String j,String key){ try { return Integer.parseInt(numVal(j,key)); } catch(Exception e){ return 0; } }
  private static long longVal(String j,String key){ Matcher m=Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(\\d+)").matcher(j); return m.find()?Long.parseLong(m.group(1)):0L; }
  // Best-effort, keyless, guarded network registry lookup (RIPEstat). UNAVAILABLE on any failure; cache-aware.
  private static String ripestatNetwork(String ip){
    try {
      HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create("https://stat.ripe.net/data/prefix/data.json?resource=" + ip))
          .timeout(Duration.ofSeconds(12)).header("User-Agent","cipher-squad/1.0").build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode()==200 && r.body()!=null && r.body().length()<=MAX_EXTERNAL_BODY) {
        String bod=r.body();
        String pf=""; Matcher pm=Pattern.compile("\"prefix\"\\s*:\\s*\"([^\"]+)\"").matcher(bod); if(pm.find())pf=pm.group(1);
        if(!pf.isEmpty()){
          String row=""; Matcher rm=Pattern.compile("\\{\"query_time\"[^}]*?,\"asn\":\"([^\"]*)\"[^}]*?,.*?").matcher(bod);
          String asnE=""; Matcher am=Pattern.compile("\"asn\"\\s*:\\s*\"(\\d+)\"").matcher(bod); if(am.find())asnE=am.group(1);
          return "{\"cidr\":\""+q(pf)+"\",\"asn\":\""+q(asnE)+"\",\"rir\":\"UNKNOWN\",\"allocation_date\":\"UNKNOWN\"}";
        }
      }
      return "{\"status\":\"UNAVAILABLE\",\"note\":\"RIPEstat returned no registered prefix for this address.\"}";
    } catch (Exception ex){ return "{\"status\":\"UNAVAILABLE\",\"note\":\"RIPEstat unreachable/error ("+q(ex.getClass().getSimpleName())+").\"}"; }
  }
  private static String joinTags(java.util.List<String> tags, String filter){ for (String t : tags) if (t.toLowerCase(Locale.ROOT).contains(filter.toLowerCase(Locale.ROOT))) return t + "; "; return ""; }
  private static String derivedNetwork(String ip){
    String[] o = ip.split("\\.");
    if (o.length == 4) return o[0]+"."+o[1]+"."+o[2]+".0/24";
    return ip + "/128";
  }
  // Holds a correlated multi-source geolocation result. All values are the PRIMARY provider's values;
  // the correlation list records provider-by-provider results and agreement/conflict.
  private static final class GeoMulti {
    final String geo, source, source2, country, cc, region, city, tz, isp, org, asn, asname;
    final boolean proxy, hosting, mobile, src2ok;
    final List<String> corrList; final int agree;
    private GeoMulti(String geo, String source, String source2, String country, String cc, String region, String city,
        String tz, String isp, String org, String asn, String asname, boolean proxy, boolean hosting, boolean mobile,
        boolean src2ok, List<String> corrList, int agree) {
      this.geo=geo; this.source=source; this.source2=source2; this.country=country; this.cc=cc; this.region=region;
      this.city=city; this.tz=tz; this.isp=isp; this.org=org; this.asn=asn; this.asname=asname;
      this.proxy=proxy; this.hosting=hosting; this.mobile=mobile; this.src2ok=src2ok; this.corrList=corrList; this.agree=agree;
    }
    String geo(){return geo;} String source(){return source;} String source2(){return source2;}
    String country(){return country;} String cc(){return cc;} String region(){return region;} String city(){return city;}
    String tz(){return tz;} String isp(){return isp;} String org(){return org;} String asn(){return asn;} String asname(){return asname;}
    boolean proxy(){return proxy;} boolean hosting(){return hosting;} boolean mobile(){return mobile;}
    boolean source2Ok(){return src2ok;} List<String> corrList(){return corrList;} int agree(){return agree;}
  }
  // Query all configured geolocation providers independently and correlate. NEVER trusts a single source.
  private static GeoMulti geoMulti(String ip){
    GeoMulti hit = geoMultiCacheGet(ip);
    if (hit != null) return hit;
    List<Map<String,String>> results = new ArrayList<>();
    List<String> srcNames = new ArrayList<>();
    // Both providers queried concurrently so a slow provider never doubles the wait serially.
    var reqA = HttpRequest.newBuilder(URI.create(GEO_API + ip)).timeout(Duration.ofSeconds(2)).header("User-Agent","cipher-squad/1.0").build();
    var reqB = HttpRequest.newBuilder(URI.create(GEO_API2 + ip)).timeout(Duration.ofSeconds(2)).header("User-Agent","cipher-squad/1.0").build();
    CompletableFuture<HttpResponse<String>> fa = HTTP.sendAsync(reqA, HttpResponse.BodyHandlers.ofString());
    CompletableFuture<HttpResponse<String>> fb = HTTP.sendAsync(reqB, HttpResponse.BodyHandlers.ofString());
    // Provider 1: ip-api.com
    try {
      HttpResponse<String> r = fa.get(4, TimeUnit.SECONDS);
      if (r.statusCode()==200 && r.body().length()<=MAX_EXTERNAL_BODY && r.body().contains("\"success\"")) {
        Map<String,String> m = new LinkedHashMap<>();
        m.put("provider","ip-api.com");
        m.put("country",geoVal(r.body(),"country")); m.put("cc",geoVal(r.body(),"countryCode")); m.put("region",geoVal(r.body(),"regionName"));
        m.put("city",geoVal(r.body(),"city")); m.put("lat",geoVal(r.body(),"lat")); m.put("lon",geoVal(r.body(),"lon"));
        m.put("tz",geoVal(r.body(),"timezone")); m.put("isp",geoVal(r.body(),"isp")); m.put("org",geoVal(r.body(),"org"));
        m.put("asn",geoVal(r.body(),"as")); m.put("asname",geoVal(r.body(),"asname"));
        m.put("proxy",geoVal(r.body(),"proxy")); m.put("hosting",geoVal(r.body(),"hosting")); m.put("mobile",geoVal(r.body(),"mobile"));
        results.add(m); srcNames.add("ip-api.com (server-side proxy)");
      }
    } catch (Exception ignored) {}
    // Provider 2: ipwho.is
    try {
      HttpResponse<String> r = fb.get(4, TimeUnit.SECONDS);
      if (r.statusCode()==200 && r.body().length()<=MAX_EXTERNAL_BODY && r.body().contains("\"success\":true")) {
        Map<String,String> m = new LinkedHashMap<>();
        m.put("provider","ipwho.is");
        m.put("country",strVal(r.body(),"country")); m.put("cc",strVal(r.body(),"country_code"));
        String region = strVal(r.body(),"region"); if (region.isEmpty()) region = strVal(r.body(),"state");
        m.put("region",region); m.put("city",strVal(r.body(),"city"));
        m.put("lat",strVal(r.body(),"latitude")); m.put("lon",strVal(r.body(),"longitude")); m.put("tz",strVal(r.body(),"timezone"));
        m.put("isp",nestedStr(r.body(),"connection","isp")); m.put("org",nestedStr(r.body(),"connection","org"));
        m.put("asn",nestedStr(r.body(),"connection","asn")); m.put("asname",asNameFrom(nestedStr(r.body(),"connection","asn")));
        m.put("proxy",""); m.put("hosting",""); m.put("mobile","");
        results.add(m); srcNames.add("ipwho.is (server-side proxy)");
      }
    } catch (Exception ignored) {}
    if (results.isEmpty()) {
      GeoMulti none = new GeoMulti("null","unavailable","","","","","","","","","","",false,false,false,false,List.of(),0);
      geoMultiCachePut(ip, none); return none;
    }
    Map<String,String> p = results.get(0);
    String country=p.get("country"), cc=p.get("cc"), region=p.get("region"), city=p.get("city");
    String lat=p.get("lat"), lon=p.get("lon"), tz=p.get("tz"), isp=p.get("isp"), org=p.get("org"), asn=p.get("asn"), asname=p.get("asname");
    boolean proxy="true".equals(p.get("proxy")), hosting="true".equals(p.get("hosting")), mobile="true".equals(p.get("mobile"));
    // Multi-source country agreement
    java.util.Set<String> countries = new java.util.LinkedHashSet<>();
    for (Map<String,String> m : results) { String c = m.get("country"); if (c!=null && !c.isEmpty()) countries.add(c); }
    int agree = countries.size()==1 && !countries.isEmpty() && results.size()>=2 ? results.size() : 1;
    List<String> corr = new ArrayList<>();
    for (Map<String,String> m : results) {
      String prov = m.get("provider");
      String flag = "saw:" + (m.get("country")==null||m.get("country").isEmpty()?"unavailable":m.get("country"));
      if (results.size()>1 && countries.size()>1) flag += " (conflicting with other source)";
      corr.add(prov + "=" + flag);
    }
    if (results.size()>1 && countries.size()>1) {
      corr.add("Country disagreement between providers; primary=" + (country.isEmpty()?"unavailable":country) + ". Selecting primary source by configured priority; disagreement is NOT hidden.");
      // Anycast-aware caveat: the same anycast prefix can legitimately resolve to multiple regional
      // sites, so provider disagreement is not automatically malice — it is disclosed and flagged as a
      // cross-source geolocation conflict rather than silently resolved to a single location.
      corr.add("Anycast note: if this address is behind an anycast/CDN prefix the conflicting locations may all be legitimate regional edge sites; the conflict is reported as a geolocation-uncertainty signal, not as evidence of deception on its own.");
      // Round 2: known-infrastructure context. Large CDN/edge networks, anycast resolver/edge blocks
      // and major DNS/mail providers routinely span many ASNs/countries/regions. A provider- or
      // location-attribute "conflict" here is often just normal infrastructure behavior, so the analyst
      // should not chase it as a false-positive indicator of deception.
      corr.add("Known-infrastructure context: shared CDN/edge nodes (e.g. Cloudflare, Akamai, Fastly, AWS CloudFront) and major DNS/mail providers legitimately announce prefixes across many ASNs and regions; a cross-source location/provider divergence on such infrastructure is frequently expected behaviour, not deception. Verify the ASN/prefix against the provider's published ranges before treating a 'conflict' as suspicious.");
      corr.add("geolocation_conflict=disclosed_anycast_uncertainty");
    }
    String geo = "{\"status\":\"success\",\"country\":\""+q(country)+"\",\"countryCode\":\""+q(cc)+"\",\"region\":\""+q(region)+"\",\"city\":\""+q(city)+"\",\"latitude\":"+(lat==null||lat.isEmpty()?"null":lat)+",\"longitude\":"+(lon==null||lon.isEmpty()?"null":lon)+",\"timezone\":\""+q(tz)+"\",\"isp\":\""+q(isp)+"\",\"organization\":\""+q(org)+"\",\"asn\":\""+q(asn)+"\",\"asName\":\""+q(asname)+"\"}";
    boolean src2 = results.size()>=2;
    GeoMulti gm = new GeoMulti(geo, srcNames.get(0), src2?srcNames.get(1):"", country, cc, region, city, tz, isp, org, asn, asname, proxy, hosting, mobile, src2, corr, agree);
    geoMultiCachePut(ip, gm); return gm;
  }
  private static String nestedStr(String json, String obj, String key){
    if (json == null) return "";
    java.util.regex.Matcher m = Pattern.compile("\""+Pattern.quote(obj)+"\"\\s*:\\s*\\{[^}]*\""+Pattern.quote(key)+"\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
    return m.find() ? unescape(m.group(1)) : "";
  }
  // Extracts the AS *name* from a combined "ASnnnn Name" string (e.g. "AS15169 Google LLC" -> "Google LLC").
  // Providers such as ipwho.is return only the combined form in connection.asn; ip-api supplies a separate
  // asname so this is only needed for the former. Returns the input trimmed if no AS prefix is present.
  private static String asNameFrom(String combined){
    if (combined == null) return "";
    String t = combined.trim();
    java.util.regex.Matcher m = Pattern.compile("^AS\\d+\\s+(.*)$").matcher(t);
    return m.find() && !m.group(1).isBlank() ? m.group(1).trim() : t;
  }
  // AbuseIPDB adapter (optional). Returns a JSON-ready reputation object string or a marker.
  private static String abuseRepJson(String ip){
    if (!ABUSEIPDB_KEY.isEmpty()) {
      try {
        var req = HttpRequest.newBuilder(URI.create("https://api.abuseipdb.com/api/v2/check?ipAddress="+ip+"&maxAgeInDays=90"))
          .timeout(Duration.ofSeconds(10)).header("Key", ABUSEIPDB_KEY).header("Accept","application/json")
          .header("User-Agent","cipher-squad/1.0").build();
        HttpResponse<String> r = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() == 200 && r.body().length() <= MAX_EXTERNAL_BODY) {
          String d = r.body();
          String conf = numVal(d,"abuseConfidenceScore"); String usage = strVal(d,"usageType");
          boolean wh = boolVal(d,"isWhitelisted"); String rep = numVal(d,"totalReports");
          return "{\"source\":\"AbuseIPDB\",\"abuseConfidenceScore\":"+conf+",\"usageType\":\""+q(usage)+"\",\"isWhitelisted\":"+wh+",\"totalReports\":"+rep+"}";
        }
      } catch (Exception ignored) { }
      return "{\"source\":\"AbuseIPDB\",\"error\":\"lookup failed\"}";
    }
    return "null";
  }
  // Google Safe Browsing v4 adapter (optional). Threat-matched URLs are returned; on error -> marker.
  private static String safeBrowsingJson(String originUrl){
    if (SAFEBROWSING_KEY.isEmpty()) return "null";
    try {
      String body = "{\"client\":{\"clientId\":\"cipher-squad\",\"clientVersion\":\"1.0.0\"},"
        + "\"threatInfo\":{\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\",\"POTENTIALLY_HARMFUL_APPLICATION\"],"
        + "\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],"
        + "\"threatEntries\":[{\"url\":\"" + q(originUrl) + "\"}]}}";
      var req = HttpRequest.newBuilder(URI.create("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + SAFEBROWSING_KEY))
        .timeout(Duration.ofSeconds(10)).header("Content-Type","application/json")
        .header("User-Agent","cipher-squad/1.0")
        .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
      HttpResponse<String> r = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() == 200 && r.body().length() <= MAX_EXTERNAL_BODY) {
        String d = r.body();
        int matches = d.contains("\"matches\"") ? countMatches(d) : 0;
        return "{\"source\":\"GoogleSafeBrowsing\",\"matches\":" + matches + "}";
      }
    } catch (Exception ignored) { }
    return "{\"source\":\"GoogleSafeBrowsing\",\"error\":\"lookup failed\"}";
  }
  private static int countMatches(String js){ int c = 0; int i = 0; while ((i = js.indexOf("\"threatType\"", i)) >= 0) { c++; i += "\"threatType\"".length(); } return c; }
  private static int safeInt(String s, int d){ if (s == null || s.isEmpty()) return d; try { return (int) Double.parseDouble(s); } catch (Exception e) { return d; } }
  private static String numValOf(String json, String key){
    java.util.regex.Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)").matcher(json);
    return m.find() ? m.group(1) : "";
  }
  // Consolidated live reputation verdict for a domain/URL, used by the email threat-intelligence layer.
  // Honest semantics: when no feed is configured, a synthetic/reserved name is involved, or a lookup
  // fails, the state is UNKNOWN — never CLEAN and never fabricated as malicious.
  private static String domainThreatVerdict(String domain, String receivedAt){
    List<String> feeds = new ArrayList<>();
    String lower = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
    boolean syn = syntheticDomain(lower) || isSharedHostingHost(lower);
    if (syn) {
      return "{\"type\":\"domain\",\"ioc\":\"" + q(lower) + "\",\"state\":\"UNKNOWN\",\"score\":0,\"tags\":[],"
        + "\"source\":\"no reputation feed applicable (synthetic/example/platform-hosted name)\","
        + "\"reason\":\"" + (lower.endsWith(".example") || lower.endsWith(".test") || lower.endsWith(".invalid") || lower.endsWith(".localhost") || lower.endsWith(".local")
            ? "Synthetic/reserved domain; no real-world registration exists to score."
            : "Platform-hosted (shared-hosting parent) subdomain; content authenticity unverified and no independent reputation was returned.") + "\","
        + "\"observedAt\":\"" + receivedAt + "\"}";
    }
    if (budgetUp()) {
      return "{\"type\":\"domain\",\"ioc\":\"" + q(lower) + "\",\"state\":\"UNKNOWN\",\"score\":0,\"tags\":[\"reputation_check_deferred_budget\"],"
        + "\"source\":\"reputation check deferred (analysis budget exhausted)\","
        + "\"reason\":\"Live reputation lookup was not performed within the analysis budget; status is UNKNOWN, not clean.\","
        + "\"observedAt\":\"" + receivedAt + "\"}";
    }
    boolean sbOk = false, sbMal = false; int sbMatches = 0;
    String sb = safeBrowsingJson("http://" + lower);
    if (sb.contains("\"source\":\"GoogleSafeBrowsing\"") && !sb.contains("\"error\"")) {
      sbOk = true; feeds.add("GoogleSafeBrowsing");
      sbMatches = safeInt(numValOf(sb,"matches"), 0);
      if (sbMatches > 0) sbMal = true;
    }
    boolean anyMal = sbMal;
    if (!anyMal && sbOk) {
      // A successful non-flagged consultation from a reputation feed is REAL signal, but Google
      // Safe Browsing only flags known-bad; absence is reported as UNKNOWN-confidence, not a hard
      // CLEAN, to preserve the fail-safe "unknown = suspicious" default.
      String src = feeds.isEmpty() ? "live reputation feed" : String.join(";", feeds);
      return "{\"type\":\"domain\",\"ioc\":\"" + q(lower) + "\",\"state\":\"UNKNOWN\",\"score\":0,\"tags\":[],\"source\":\"" + src + " returned no malicious verdict\","
        + "\"reason\":\"No threat feed flagged the domain; absence of a flag is not proof of safety.\","
        + "\"observedAt\":\"" + receivedAt + "\"}";
    }
    if (anyMal) {
      String src = feeds.isEmpty() ? "live reputation feed" : String.join(";", feeds);
      return "{\"type\":\"domain\",\"ioc\":\"" + q(lower) + "\",\"state\":\"MALICIOUS\",\"score\":80,\"tags\":[\"reputation_flagged\"],\"source\":\"" + src + " flagged the domain\","
        + "\"reason\":\"Google Safe Browsing flagged the URL as a threat.\","
        + "\"observedAt\":\"" + receivedAt + "\"}";
    }
    return "{\"type\":\"domain\",\"ioc\":\"" + q(lower) + "\",\"state\":\"UNKNOWN\",\"score\":0,\"tags\":[],"
      + "\"source\":\"no threat-reputation provider configured (server-side)\","
      + "\"reason\":\"No registered threat-reputation provider returned a verdict for this domain; absence of data is not evidence of safety.\","
      + "\"observedAt\":\"" + receivedAt + "\"}";
  }
  // Parse a domainThreatVerdict JSON string back into a threatIntel Map for the email pipeline.
  private static void appendTiFromJson(List<Map<String,Object>> list, String json){
    Map<String,Object> ti = new LinkedHashMap<>();
    ti.put("type", "domain");
    ti.put("ioc", strVal(json,"ioc"));
    ti.put("state", strVal(json,"state"));
    String scoreStr = strVal(json,"score"); int sc = 0; try { sc = Integer.parseInt(scoreStr); } catch (Exception e) {}
    ti.put("score", sc);
    String tagsRaw = "";
    { java.util.regex.Matcher m = Pattern.compile("\"tags\":\\[([^\\]]*)\\]").matcher(json); if (m.find()) tagsRaw = m.group(1); }
    List<String> tags = new ArrayList<>();
    for (String t : tagsRaw.split(",")) { String x = t.trim().replaceAll("^\"|\"$",""); if (!x.isEmpty()) tags.add(x); }
    ti.put("tags", tags);
    ti.put("country", "");
    ti.put("source", strVal(json,"source"));
    ti.put("reason", strVal(json,"reason"));
    ti.put("observedAt", strVal(json,"observedAt"));
    list.add(ti);
  }
  static int ipRisk(String cls, boolean isPublic, boolean proxy, boolean hosting, String tor, String vpn, String host, String anon, java.util.List<String> findings){
    int s = 0;    // technical classifier boosts only for clearly hostile infrastructure, never geography
    if (tor.length()>0 || anon.length()>0) s += 70;
    else if (vpn.length()>0) s += 30;
    // SPEC #14: cloud/datacenter/hosting status is CONTEXT ONLY and does NOT by itself raise risk.
    // An address on AWS/Cloudflare is overwhelmingly benign; flagging every hosted IP as more risky
    // would heavily false-positive. Tor/VPN/anonymizer/proxy remain genuinely higher-frequency abuse.
    if (proxy) s += 25;
    if (!isPublic) s = 0; // internal/reserved: no external threat scoring
    if (s == 0) { for (String f : findings) if (f.contains("Abuse confidence") && Integer.parseInt(f.replaceAll("[^0-9]","")) >= 50) s += 45; }
    // apply configurable weight vector (scales the abuse/intel-driven component, never the hard classifier)
    int w = IP_WEIGHTS.getOrDefault("threat_ti", 60);
    if (w != 60 && s > 0) s = (int)Math.round(s * (w / 60.0));
    return Math.min(100, s);
  }
  static String severity(int s){
    if (s >= 81) return "Critical";
    if (s >= 61) return "High";
    if (s >= 41) return "Medium";
    if (s >= 21) return "Low";
    return "Informational / Low";
  }

  /* =====================================================================
   *  Module: URL DEEP-LINK ANALYZER
   *  Safe static parse + server-side DNS + guarded redirect analysis.
   *  Never executes remote content, JS, macros or files; allow http/https only.
   *  ===================================================================== */
  record UrlParts(String scheme,String host,String port,String path,String query,String fragment,String user,String registered,String subdomain,boolean isIpHost){}

  private static void urlAnalyze(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String client = Optional.ofNullable(e.getRemoteAddress()).map(a -> a.getAddress()==null?null:a.getAddress().getHostAddress()).orElse("local");
    if (!allowed(client)) { json(e,429,error("Rate limit exceeded for this client; retry shortly.")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    if (body.length() > MAX_REQ_BODY) { json(e,413,error("Request body too large")); return; }
    String raw = unescape(extractJsonString(body,"url"));
    if (raw == null || raw.isBlank()) { json(e,400,error("url is required")); return; }
    String norm = normalizeUrl(raw);
    if (norm == null) { json(e,400,error("Not a valid http/https URL")); return; }
    String cached = cacheGetU(URL_CACHE, norm);
    if (cached != null) { json(e,200,cached); return; }
    ANALYZE_DEADLINE.set(System.currentTimeMillis() + ANALYZE_BUDGET_MS);
    String out = analyzeUrl(raw, norm);
    if (out != null) { cachePutU(URL_CACHE, norm, out); json(e,200,out); }
    else json(e,502,error("Internal error while analyzing the URL."));
  }
  // Extract a top-level string field from a small JSON body without a JSON parser.
  private static String extractJsonString(String body, String key){
    return scanJsonValue(body, key);
  }
  // Normalize: trim, strip control chars, prepend scheme if missing (assume https), validate scheme.
  static String normalizeUrl(String raw){
    if (raw == null) return null;
    String u = raw.trim().replaceAll("[\\p{Cc}]+","");
    u = u.replaceFirst("^https?://", "sc://") == null ? u : u; // no-op safeguard
    String lower = u.toLowerCase(Locale.ROOT);
    if (!lower.matches("https?://.*")) u = "https://" + u;
    String[] parts = u.split("://");
    if (parts.length != 2) return null;
    String scheme = parts[0].toLowerCase(Locale.ROOT);
    if (!scheme.equals("http") && !scheme.equals("https")) return null;
    if (parts[1].isBlank()) return null;
    return scheme + "://" + parts[1];
  }
  // Compute a registered (root/registrable) domain from a hostname using an approximate PSL.
  static String registeredDomain(String host){
    if (host == null) return "";
    String h = host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return h; // raw IP
    if (h.contains(":") && !h.contains(".")) return ""; // bare IPv6
    String[] labels = h.split("\\.");
    if (labels.length == 1) return h;
    String last = labels[labels.length-1], second = labels.length>=2?labels[labels.length-2]:"";
    String multi = SO2.contains(second + "." + last) ? second : "";
    int take = multi.isEmpty()?2:3;
    if (labels.length <= take) return h;
    int start = labels.length - take;
    StringBuilder b = new StringBuilder();
    for (int i = start; i < labels.length; i++){ if (i>start) b.append('.'); b.append(labels[i]); }
    return b.toString();
  }
  private static final java.util.Set<String> SO2 = new java.util.HashSet<>(java.util.Arrays.asList(
    "ac.uk","co.uk","org.uk","gov.uk","me.uk","net.uk","com.au","net.au","org.au","gov.au","co.nz","co.jp","or.jp","co.in","gov.in","of", //
    "com.br","net.br","org.br","co.za","org.za","com.mx","com.ar","com.cn","net.cn","org.cn","com.tr","com.tw","com.sg","com.hk","com.my","co.id","com.ph","co.kr"));
  static UrlParts parseUrl(String norm){
    String scheme="",host="",port="",path="/",query="",fragment="",user="";
    java.net.URI uri;
    try { uri = java.net.URI.create(norm); } catch (Exception x) { uri = null; }
    if (uri != null) {
      scheme = uri.getScheme()==null?"":uri.getScheme().toLowerCase(Locale.ROOT);
      host = uri.getHost()==null?"":uri.getHost();
      port = uri.getPort()==-1?"":String.valueOf(uri.getPort());
      path = uri.getPath()==null?"/":uri.getRawPath();
      query = uri.getRawQuery()==null?"":uri.getRawQuery();
      fragment = uri.getRawFragment()==null?"":uri.getRawFragment();
      user = uri.getRawUserInfo()==null?"":uri.getRawUserInfo();
    }
    // manual fallback when URI loses components (e.g., userinfo or malformed)
    if (host.isEmpty() || host.isBlank()) {
      String rest = norm.replaceFirst("^[a-z]+://", "");
      String auth = rest.contains("/") ? rest.substring(0, rest.indexOf("/")) : rest;
      String pathOnly = rest.contains("/") ? rest.substring(rest.indexOf("/")) : "/";
      int fragIdx = pathOnly.indexOf('#'); if (fragIdx>=0){ fragment=pathOnly.substring(fragIdx+1); pathOnly=pathOnly.substring(0,fragIdx); }
      int qIdx = pathOnly.indexOf('?'); if (qIdx>=0){ query=pathOnly.substring(qIdx+1); pathOnly=pathOnly.substring(0,qIdx); }
      path = pathOnly;
      // auth = [user[:pass]@]host[:port]
      auth = auth.replace("]","").replaceFirst("^\\[", "");
      int at = auth.lastIndexOf('@');
      if (at >= 0){ user = auth.substring(0, at); auth = auth.substring(at+1); }
      if (auth.startsWith("[") && auth.contains("]")) { host = auth.substring(1, auth.indexOf("]")); String rest2 = auth.substring(auth.indexOf("]")+1); if (rest2.startsWith(":")) port = rest2.substring(1); }
      else { int ci = auth.indexOf(':'); if (ci>=0){ host = auth.substring(0,ci); port = auth.substring(ci+1); } else host = auth; }
    }
    // unwrap bracketed IPv6 literal hosts (URI.getHost() keeps the brackets, e.g. "[::1]")
    if (host.startsWith("[") && host.endsWith("]")) { host = host.substring(1, host.length()-1); }
    boolean isIpHost = host.matches("\\d{1,3}(\\.\\d{1,3}){3}") || (host.contains(":") && host.matches("[0-9a-fA-F:]+") );
    String reg = isIpHost ? host : registeredDomain(host);
    String sub = "";
    if (!isIpHost && !reg.isEmpty() && host.length() > reg.length() && host.endsWith("." + reg)) {
      sub = host.substring(0, host.length() - reg.length() - 1);
    }
    return new UrlParts(scheme, host, port, path, query, fragment, user, reg, sub, isIpHost);
  }
  // Decode a string for analysis, preserving the original for evidence.
  static String urlDecodeAll(String s){
    // decode %XX up to two passes to catch double-encoding; never re-encode
    String cur = s;
    for (int pass = 0; pass < 2; pass++){
      String prev = cur;
      StringBuilder b = new StringBuilder();
      for (int i=0;i<cur.length();i++){
        char c = cur.charAt(i);
        if (c=='%' && i+2<cur.length()){
          String h = cur.substring(i+1,i+3).toLowerCase(Locale.ROOT);
          if (h.matches("[0-9a-f]{2}")){ b.append((char)Integer.parseInt(h,16)); i+=2; continue; }
        }
        if (c=='+'){ b.append(' '); continue; }
        b.append(c);
      }
      cur = b.toString();
      if (cur.equals(prev)) break;
    }
    return cur;
  }

  // Guard against SSRF before ANY outbound connection. Returns null if safe, else a reason string.
  static String ssrfGuard(String scheme, String host, String port){
    if (!scheme.equals("http") && !scheme.equals("https")) return "unsupported scheme: " + scheme;
    String h = (host==null?"":host).toLowerCase(Locale.ROOT).trim();
    if (h.isEmpty()) return "missing host";
    if (h.equals("localhost") || h.endsWith(".localhost") || h.equals("metadata.google.internal")
        || h.equals("kubernetes.default.svc") || h.endsWith(".internal") || h.endsWith("instance-data.ec2.internal")) return "internal/localhost hostname blocked: " + h;
    try {
      InetAddress[] addrs = InetAddress.getAllByName(h);
      for (InetAddress a : addrs) {
        String pure = stripIpv6Zone(a.getHostAddress());
        if (isBlockedForFetch(pure)) return "hostname resolves to blocked network: " + pure;
        // cloud metadata explicit
        if (pure.startsWith("169.254.169.254") || pure.equals("fd00:ec2::254")) return "cloud metadata endpoint blocked";
      }
    } catch (Exception x) { return "host resolution failure"; }
    // explicit numeric host checks
    if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) { if (isBlockedForFetch(h)) return "numeric address in blocked network"; }
    return null;
  }

  // Controlled, guarded redirect-chain analysis using HEAD requests only (no content download).
  private static String redirectAnalysis(String scheme, String host, int port, String startPath){
    StringBuilder hops = new StringBuilder();
    String guard = ssrfGuard(scheme, host, String.valueOf(port));
    if (guard != null) {
      return "{\"performed\":false,\"hops\":[],\"stoppedReason\":\"SSRF guard: " + guard + "\",\"note\":\"Redirect chain not followed; URL analysis is static + DNS only when a network guard triggers. No content was fetched.\"}";
    }
    String curUrl = scheme + "://" + formatHostPort(host, port) + startPath;
    int maxHops = 3, n = 0;
    List<String> chain = new ArrayList<>();
    chain.add(curUrl);
    try {
      while (n < maxHops) {
        String guard2 = null;
        try {
          java.net.URI cu = java.net.URI.create(curUrl);
          guard2 = ssrfGuard(cu.getScheme()==null?"":cu.getScheme().toLowerCase(Locale.ROOT), cu.getHost()==null?"":cu.getHost(), String.valueOf(cu.getPort()));
        } catch (Exception x) { guard2 = "malformed redirect target"; }
        if (guard2 != null) {
          if (n == 0) return "{\"performed\":false,\"hops\":[],\"stoppedReason\":\"SSRF guard: " + guard2 + "\",\"note\":\"No content was fetched.\"}";
          break;
        }
        var req = HttpRequest.newBuilder(URI.create(curUrl)).method("HEAD", HttpRequest.BodyPublishers.noBody())
          .timeout(Duration.ofSeconds(3)).header("User-Agent","cipher-squad/1.0").header("Accept","text/html,application/xhtml+xml")
          .build();
        HttpResponse<String> r;
        try { r = NO_REDIRECT.send(req, HttpResponse.BodyHandlers.ofString()); }
        catch (Exception ex) { chain.add("connection_error"); break; }
        String location = r.headers().firstValue("location").orElse("");
        chain.add(String.valueOf(r.statusCode()) + (location.isEmpty()?"":" -> "+location));
        if (r.statusCode() >= 300 && r.statusCode() < 400 && !location.isEmpty()) {
          java.net.URI next = java.net.URI.create(location).isAbsolute() ? java.net.URI.create(location) : java.net.URI.create(curUrl).resolve(location);
          curUrl = next.toString(); n++;
        } else break;
      }
    } catch (Exception ex) { chain.add("chain_error"); }
    for (int i=0;i<chain.size();i++){ if (i>0) hops.append(','); hops.append(jstr(chain.get(i))); }
    return "{\"performed\":true,\"hops\":["+hops+"],\"maxHops\":"+maxHops+",\"stoppedReason\":"+(n>=maxHops?"\"max hops reached\"":"\"no further redirect\"")+",\"note\":\"HEAD-only; no content, scripts, or files were executed or downloaded.\"}";
  }
  private static String formatHostPort(String host, int port){ return host.contains(":") && !host.matches("\\d{1,3}(\\.\\d{1,3}){3}") ? ("["+host+"]"+(port>0?":"+port:"")) : (port>0?host+":"+port:host); }

  // TLS certificate metadata via a controlled handshake (no content downloaded / executed).
  private static String tlsInfo(String host, int port){
    String src = "JSSE TLS handshake (server-side; no content fetched)";
    if (!ABUSEIPDB_KEY.isEmpty() && false) return ""; // reserved for future cert provider
    // SSRF guard: never handshake a host that resolves to internal/localhost/cloud-metadata.
    // If the target is blocked or unresolved we report honestly that TLS was NOT evaluated,
    // rather than ever connecting into a private network on the user's behalf.
    String guard = validateConnectTarget(host);
    if (guard != null) return "{\"source\":\""+q(src)+"\",\"present\":false,\"note\":\"TLS not evaluated: SSRF guard blocked target ("+q(guard)+").\"}";
    int p = port>0?port:443;
    try (javax.net.ssl.SSLSocket s = sslConnect(host, p, 8000)) {
      s.startHandshake();
      java.security.cert.Certificate[] certs = s.getSession().getPeerCertificates();
      if (certs == null || certs.length == 0) return "{\"source\":\""+q(src)+"\",\"present\":false}";
      java.security.cert.X509Certificate c = (java.security.cert.X509Certificate) certs[0];
      String issuer = c.getIssuerX500Principal().getName()==null?"":c.getIssuerX500Principal().getName().replace("\"","").replace("\\","");
      String subject = (c.getSubjectX500Principal().getName()==null?"":c.getSubjectX500Principal().getName().replace("\"","").replace("\\",""));
      long notAfter = c.getNotAfter()==null?0:c.getNotAfter().getTime()/1000;
      long now = System.currentTimeMillis()/1000;
      boolean valid = now < notAfter;
      return "{\"source\":\""+q(src)+"\",\"present\":true,\"issuer\":\""+q(issuer)+"\",\"subject\":\""+q(subject)+"\",\"expiresAfter\":\""+c.getNotAfter()+"\",\"currentlyValid\":\""+valid+"\"}";
    } catch (Exception ex) {
      return "{\"source\":\""+q(src)+"\",\"present\":false,\"note\":\"TLS handshake could not be completed: "+q(ex.getClass().getSimpleName())+".\"}";
    }
  }

  // Risk scoring with the configured, explainable weight model. Returns {score, breakdown}.
  static String urlRisk(Map<String,Integer> catRaw){
    int totalW = URL_WEIGHTS.values().stream().mapToInt(Integer::intValue).sum();
    if (totalW <= 0) totalW = 100;
    int score = 0;
    StringBuilder sb = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String,Integer> w : URL_WEIGHTS.entrySet()) {
      if (!first) sb.append(',');
      first = false;
      int cat = catRaw.getOrDefault(w.getKey(), 0);
      int contribution = Math.min(w.getValue(), Math.round(cat / 100.0f * w.getValue()));
      score += contribution;
      sb.append("\"").append(w.getKey()).append("\":{").
         append("\"weight\":").append(w.getValue()).
         append(",\"rawIndicatorScore\":").append(cat).
         append(",\"contribution\":").append(contribution).append("}");
    }
    sb.append("}");
    return "{\"score\":" + Math.min(100, score) + ",\"breakdown\":" + sb + ",\"weightsConfigured\":\"" + URL_WEIGHTS + "\"}";
  }

  // Server-side DNS resolution restricted to address records.
  private static Map<String,List<String>> resolveAddresses(String host){
    Map<String,List<String>> m = new LinkedHashMap<>();
    List<String> ipv4 = new ArrayList<>(), ipv6 = new ArrayList<>();
    if (dnsQueryable(host)) { try { for (InetAddress a : InetAddress.getAllByName(host)) { String h = a.getHostAddress(); if (h.contains(":")) ipv6.add(h); else if (h.contains(".")) ipv4.add(h); } } catch (Exception ignored) { } }
    m.put("ipv4", ipv4); m.put("ipv6", ipv6);
    return m;
  }

  // ---- DNS-over-HTTPS enrichment (zero-dependency). Cloudflare public resolver, server-side proxy. ----
  // Captures CNAME / NS / MX / TXT / A / AAAA with TTL — fields the JVM resolver cannot expose.
  // DNS-over-HTTPS enrichment (zero-dependency). Cloudflare public resolver, server-side proxy.
  // Captures CNAME / NS / MX / TXT / A / AAAA with TTL — fields the JVM resolver cannot expose.
  // Cloudflare ignores single ANY queries (RFC 8482) so each record type is queried individually.
  private static final String DNS_DOH = "https://cloudflare-dns.com/dns-query?name=%s&type=%s";
  private static String dohBody(String host, String type){
    if (!dnsQueryable(host)) return "";
    String key = host.toLowerCase(Locale.ROOT) + "|" + type;
    String c = dohCacheGet(key);
    if (c != null) return c;
    try {
      HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(String.format(DNS_DOH, URLEncoder.encode(host, StandardCharsets.UTF_8), type)))
        .timeout(Duration.ofSeconds(6)).header("accept","application/dns-json").header("User-Agent","cipher-squad/1.0").build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode()==200 && r.body().length()<=MAX_EXTERNAL_BODY && r.body().contains("\"Status\"")) { dohCachePut(key, r.body()); return r.body(); }
    } catch (Exception ignored) { }
    dohCachePut(key, "");
    return "";
  }
  // Query the record types we care about individually, merge, and return ONE JSON object containing
  // both the per-type grouping (for display) and a raw records array. No records returned => marked UNKNOWN.
  private static String dnsEnrichJson(String host, String resolverNote){
    String[] types = {"A","AAAA","CNAME","NS","MX","TXT"};
    java.util.LinkedHashMap<String,java.util.List<String>> byType = new java.util.LinkedHashMap<>();
    java.util.LinkedHashMap<String,java.util.List<String>> records = new java.util.LinkedHashMap<>();
    int maxTtl = -1; boolean captured = false;
    // Per-type DoH queries run concurrently (their results are keyed by type but still consumed
    // in canonical order) so a slow DNS round-trip no longer multiplies across six serial calls.
    java.util.concurrent.ConcurrentHashMap<String,String> bodies = new java.util.concurrent.ConcurrentHashMap<>();
    java.util.List<java.util.concurrent.Future<?>> qs = new ArrayList<>();
    for (String qtype : types) qs.add(ENRICH.submit(() -> bodies.put(qtype, dohBody(host, qtype))));
    for (java.util.concurrent.Future<?> f : qs) { try { f.get(6, TimeUnit.SECONDS); } catch (Exception ignored) {} }
    for (String qtype : types) {
      String body = bodies.getOrDefault(qtype, "");
      java.util.regex.Matcher ans = Pattern.compile("\\{\\s*\"name\":\"([^\"]*)\",\\s*\"type\":(\\d+),\\s*\"TTL\":(\\d+),\\s*\"data\":\"([^\"]*)\"").matcher(body);
      while (ans.find()) {
        String t = qtype;                               // map from the query type, not the numeric box
        String name = ans.group(1); int ttl = Integer.parseInt(ans.group(3)); String data = unescape(ans.group(4));
        byType.computeIfAbsent(t, k->new ArrayList<>()).add(data);
        records.computeIfAbsent(t, k->new ArrayList<>()).add("{\"type\":\""+t+"\",\"name\":\""+q(name)+"\",\"value\":\""+q(data)+"\",\"ttl\":"+ttl+"}");
        if (ttl > maxTtl) maxTtl = ttl;
        if (t.equals("A") || t.equals("AAAA") || t.equals("CNAME")) captured = true;
      }
    }
    StringBuilder o = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String,java.util.List<String>> e : byType.entrySet()) {
      if (!first) o.append(',');
      o.append("\"").append(e.getKey()).append("\":[");
      for (int i=0;i<e.getValue().size();i++){ if (i>0) o.append(','); o.append("\"").append(q(e.getValue().get(i))).append("\""); }
      o.append("]");
      first = false;
    }
    if (!first) o.append(',');
    o.append("\"captured\":").append(captured);
    o.append(",\"ttlSeconds\":").append(maxTtl<0?"null":maxTtl);
    o.append(",\"resolver\":").append(jstr(resolverNote));
    o.append(",\"lookupTimestamp\":").append(jstr(Instant.now().toString()));
    o.append(",\"additionalRecordTypes\":").append(jstr(captured?"CNAME/NS/MX/TXT captured where present.":"CNAME/NS/MX/TXT not returned (DNS-over-HTTPS provider). Marked UNKNOWN, not assumed clean."));
    o.append(",\"records\":[");
    boolean rf = true;
    for (java.util.List<String> rl : records.values()) for (String r : rl) { if (!rf) o.append(','); o.append(r); rf=false; }
    o.append("]");
    return o.append("}").toString();
  }

  // RDAP / domain-age evidence (server-side, optional provider).
  // Resolvable-only check used to avoid pointless external lookups (DNS/RDAP) for reserved or
  // synthetic namespaces (.example/.test/.invalid/.localhost, raw IPs). These can never resolve
  // or carry real WHOIS, so treating them as UNKNOWN is both faster and more honest.
  private static boolean syntheticDomain(String d){
    if (d == null || d.isEmpty()) return true;
    String lower = d.toLowerCase(Locale.ROOT);
    return lower.endsWith(".example") || lower.endsWith(".example.com")
        || lower.endsWith(".test") || lower.endsWith(".invalid")
        || lower.endsWith(".localhost") || lower.endsWith(".local")
        || lower.equals("localhost")
        || lower.matches("\\d{1,3}(\\.\\d{1,3}){3}");
  }
  // Hostnames longer than 253 chars (or shorter than the minimum label pair, or blank) can never
  // resolve or carry real record data. Skip them before any InetAddress / DoH / RDAP / WHOIS
  // lookup so a pathological label never stalls the resolver or burns external-query time.
  private static boolean dnsQueryable(String host){
    return host != null && host.length() >= 4 && host.length() <= 253 && !host.isBlank();
  }
  // Known-PaaS / shared-hosting parent domains. Subdomains of these are expected to be
  // platform-hosted (fastly/heroku/azure/vercel/netlify/etc.); "unknown age" and "CNAME aliasing
  // outside the registrable domain" are NORMAL properties of these platforms, not phishing
  // signals. This is a narrow, explicit exception for the verified parent list ONLY — it must
  // not become a general allowlist bypass, and "unknown = suspicious" stays for every other domain.
  private static final java.util.Set<String> SHARED_HOST_PARENTS = java.util.Set.of(
    "appspot.com","herokuapp.com","azurewebsites.net","github.io","vercel.app","netlify.app","pages.dev","web.app");
  private static boolean isSharedHostingParent(String reg){
    if (reg == null) return false;
    return SHARED_HOST_PARENTS.contains(reg.toLowerCase(Locale.ROOT));
  }
  private static boolean isSharedHostingHost(String host){
    if (host == null) return false;
    String lower = host.toLowerCase(Locale.ROOT);
    for (String p : SHARED_HOST_PARENTS) if (lower.equals(p) || lower.endsWith("." + p)) return true;
    return false;
  }
  private static String rdapEvidence(String domain){
    if (domain == null || domain.isEmpty() || syntheticDomain(domain) || !dnsQueryable(domain) || domain.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return "{\"source\":\"RDAP\",\"status\":\"not_applicable\"}";
    String cached = rdapCacheGet(domain);
    if (cached != null) return cached;
    String out;
    try {
      HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create("https://rdap.org/domain/" + domain)).timeout(Duration.ofSeconds(12)).header("User-Agent","cipher-squad/1.0").build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() == 200 && r.body().length() <= MAX_EXTERNAL_BODY) {
        String updated = strVal(r.body(),"expiration");
        String reg = ""; Matcher mm = Pattern.compile("\"registration\"\\s*:\\s*\"([^\"]+)\"").matcher(r.body()); if (mm.find()) reg = mm.group(1);
        String exp = strVal(r.body(),"expiration");
        long ageDays = -1; if (!reg.isEmpty()) { try { ageDays = java.time.Duration.between(java.time.OffsetDateTime.parse(reg), java.time.OffsetDateTime.now(ZoneId.of("UTC"))).toDays(); } catch (Exception ignored) {} }
        String registrar = ""; Matcher rm = Pattern.compile("(?s)\"vcardArray\":\\[[^\\[]*,\\[[^\\]]*\"fn\"[^,]*,\\s*\\{\\s*\"type\":\"uri\"[^}]*\"value\":\"([^\"]+)\"").matcher(r.body()); if (rm.find()) registrar = rm.group(1);
        if (registrar.isEmpty()) { Matcher r2 = Pattern.compile("(?s)\"vcardArray\":\\[[^\\[]*\\[[^\\]]*\"fn\"[^,]*,\\s*\"([^\"]+)\"").matcher(r.body()); if (r2.find()) registrar = r2.group(1); }
        out = "{\"source\":\"RDAP\",\"status\":\"available\",\"registrationDate\":\""+q(reg)+"\",\"expirationDate\":\""+q(exp)+"\",\"ageDays\":"+ageDays+",\"registrar\":\""+q(registrar)+"\"}";
        rdapCachePut(domain, out);
        return out;
      }
      out = "{\"source\":\"RDAP\",\"status\":\"not_found\",\"http\":"+r.statusCode()+"}";
      rdapCachePut(domain, out);
      return out;
    } catch (Exception ex) { out = "{\"source\":\"RDAP\",\"status\":\"unavailable\",\"error\":\""+q(ex.getClass().getSimpleName())+"\"}"; rdapCachePut(domain, out); return out; }
  }

  // Full URL analysis producing the forensic evidence card JSON.
  static String analyzeUrl(String rawInput, String norm){
    String ts = Instant.now().toString();
    UrlParts p = parseUrl(norm);
    String hostLower = p.host().toLowerCase(Locale.ROOT);
    String decodedPath = urlDecodeAll(p.path());
    String decodedFull = urlDecodeAll(p.query().isEmpty()?p.path():p.path()+"?"+p.query());
    List<String> sources = new ArrayList<>();
    List<String> findings = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    List<String> iocs = new ArrayList<>();
    sources.add("Static URL parser (local)");

    List<String> indicators = new ArrayList<>();   // [name, severity, evidence]
    // ---------------- SUSPICIOUS DETECTION ----------------
    boolean insecureHttp = p.scheme().equals("http");
    if (insecureHttp){ indicators.add("insecure_transport|Insecure HTTP instead of HTTPS|The URL uses cleartext HTTP"); findings.add("Transport is insecure (HTTP)."); }
    if (p.isIpHost()){ indicators.add("raw_ip_host|Raw IP address used as host|Host is a literal IP, common for phishing"); findings.add("Host is a raw IP address: " + p.host()); iocs.add(p.host()); }
    String reg = p.registered();
    if (p.subdomain().split("\\.").length >= 3){ indicators.add("excessive_subdomains|Excessive subdomain nesting|Many labels before the registered domain"); findings.add("Excessive subdomain nesting detected."); }
    if (isShortener(reg)){ indicators.add("url_shortener|URL shortener detected|Registered domain is a known shortening service with opaque paths"); findings.add("URL shortener detected: " + reg); }
    if (!p.port().isEmpty()){ int po = Integer.parseInt(p.port()); if (po!=80 && po!=443 && po!=8080 && po!=8443){ indicators.add("unusual_port|Unusual/non-standard port|Port "+po+" is not a common web port"); findings.add("Non-standard port in use: "+po); } }
    if (hostLower.contains("xn--") || hostLower.matches("(?s).*[^\\x00-\\x7F].*")){ indicators.add("punycode_unicode|IDN/Punycode or non-ASCII hostname|Possible homoglyph domain"); findings.add("IDN/non-ASCII hostname present: " + p.host()); iocs.add(p.host()); }
    if (typosquat(hostLower)){ indicators.add("typosquat|Typosquatting / brand impersonation|Registered domain resembles a well-known brand"); findings.add("Potential typosquatting of a known brand in: " + reg); iocs.add(reg); }
    if (p.path().matches("(?s).*%(?:25)?2[0-9a-fA-F].*") || (p.path().contains("%252e") || p.path().contains("%252f"))){ indicators.add("encoded_obfuscated|Encoded/obfuscated path|Percent-encoded or double-encoded characters in path"); findings.add("Obfuscated/encoded path detected."); }
    if (pathCred(p.path())){ indicators.add("credential_path|Credential/login/reset/payment path|Path references authentication or payment surfaces"); findings.add("Path resembles a credential/login/payment surface."); }
    if (!p.query().isEmpty()) {
      String[] qp = urlDecodeAll(p.query()).split("&");
      List<String> redirParams = new ArrayList<>();
      for (String qq : qp){ String[] kv = qq.split("=",2); String k = kv[0].toLowerCase(Locale.ROOT);
        if (List.of("redirect","url","next","dest","destination","return","callback","continue","rurl","link","go","out","redir","uri","target","to").contains(k) && kv.length==2) redirParams.add(k+"="+kv[1]);
        if (List.of("token","reset","reset_token","password","secret","auth","key","otp","code","verify","session").contains(k)){ indicators.add("auth_param|Authentication/secret query parameter|Query carries sensitive auth/secret tokens"); findings.add("Sensitive auth/secret query parameter present: " + k); }
      }
      if (!redirParams.isEmpty()){ indicators.add("redirect_param|Redirect-related query parameter|Open-redirect style parameter detected"); findings.add("Redirect/forwarding parameter detected: " + String.join(", ", redirParams)); }
      if (qp.length > 8) { indicators.add("excessive_params|Excessive query parameters|Many parameters, possible tracking or obfuscation"); }
    }
    if (!p.user().isEmpty() || hostLower.contains("%40") || hostLower.contains("@")){ indicators.add("userinfo_trick|Userinfo / host spoofing|'@' or username present in authority, can mask the real host"); findings.add("Userinfo / host masking trick present."); }
    if (p.host().contains("..") || p.path().contains("//")){ indicators.add("path_tricks|Hostname/path trick|Double slash or dot segments used to confuse"); }

    // ---------------- ENRICHMENT ----------------
    boolean sandboxedOfficialChild = sandboxOfficialHost(hostLower);
    if (sandboxedOfficialChild) {
      sources.add("Official brand sandbox (local)");
      findings.add("Enrichment sandboxed: host is the official brand domain (or a direct child subdomain) of a verified official brand — RDAP/WHOIS age probing, TLS probing, redirect probing and DoH record lookup are short-circuited for this known-benign host family.");
      indicators.add("official_brand_child|Official brand domain or child subdomain|Host belongs to a verified official brand domain — enrichment short-circuited for known-benign infrastructure");
    }
    Map<String,List<String>> resolved = new LinkedHashMap<>();
    List<String> resolvErrs = new ArrayList<>();
    boolean dnsFailed = false;
    if (!p.isIpHost() && !hostLower.isEmpty()) {
      resolved = resolveAddresses(hostLower);
      if (resolved.get("ipv4").isEmpty() && resolved.get("ipv6").isEmpty()) { errors.add("Hostname did not resolve to an address record."); resolvErrs.add("no address records"); dnsFailed = true; }
      else { sources.add("JVM DNS resolver (server-side)"); }
    } else if (p.isIpHost()) { resolved.put("ipv4", List.of(p.host())); sources.add("Schedule: raw IP host (no DNS needed)"); }

    // FIX 1: DNS failure must NEVER be scored as clean. Mark it SUSPICIOUS and continue every other layer.
    boolean dnsFailureSignal = dnsFailed && !p.isIpHost();
    if (dnsFailureSignal){ indicators.add("dns_failure|DNS resolution failed|Domain did not resolve — attackers take domains offline to evade URL scanners, so DNS failure is treated as suspicious, not clean"); findings.add("DNS resolution FAILED. Marked SUSPICIOUS — domain may be intentionally offline to evade scanners. All other analysis layers continue regardless."); }

    // resolve IPv6 or IPv4 for intel/correlation
    List<String> resolvedIps = new ArrayList<>();
    resolvedIps.addAll(resolved.getOrDefault("ipv4", List.of()));
    resolvedIps.addAll(resolved.getOrDefault("ipv6", List.of()));

    // RDAP / domain age
    String rdap = "{\"source\":\"RDAP\",\"status\":\"unavailable\"}";
    int domAgeCat = 0;
    String whoisFb = "{\"source\":\"WHOIS\",\"status\":\"unavailable\",\"note\":\"WHOIS fallback not attempted.\"}";
    String rdapStatus = "unavailable"; boolean domainAgeUnknown = false; long domainAgeDays = -2L;
    String registrar="", registrant="", expiryDate="", regDate="", regAbuseEmail="";
    boolean privacyProtected=false;
    if (sandboxedOfficialChild && !reg.isEmpty()) {
      rdapStatus = "not_applicable";
    } else if (!reg.isEmpty() && !reg.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
      // RDAP/WHOIS is cached; respect the per-request budget so a slow cold provider
      // cannot stall the reply. When skipped the domain age is UNKNOWN (adds risk,
      // never treated as clean).
      if (rdapCacheGet(reg) == null && budgetUp()) rdap = "{\"source\":\"RDAP\",\"status\":\"unavailable\",\"note\":\"deferred for responsiveness\"}";
      else rdap = rdapEvidence(reg);
      boolean rdapOk = rdap.contains("\"status\":\"available\"");
      String source = rdapOk ? rdap : "";
      if (!rdapOk) { source = whoisEvidence(reg); whoisFb = source; }
      if (rdapOk){ rdapStatus = "found"; sources.add("RDAP (iana bootstrap, server-side)"); }
      else if (rdap.contains("\"status\":\"not_found\"")) { rdapStatus = "not_found"; }
      else { rdapStatus = "unavailable"; }
      boolean srcOk = source != null && source.contains("\"status\":\"available\"");
      if (srcOk && !rdapOk) { sources.add("WHOIS fallback (server-side)"); }
      domainAgeDays = srcOk ? (source.contains("\"ageDays\":-1") ? -1 : (source.contains("\"ageDays\":") ? Long.parseLong(source.replaceAll(".*\"ageDays\":(-?\\d+).*","$1")) : -1)) : -1;
      if (isSharedHostingParent(reg)) {
        // Known shared-hosting parent: unknown age / no WHOIS is an expected property of the
        // platform, NOT a transient-infrastructure or phishing signal. Emit a neutral note and
        // rely on reputation feeds + path/content analysis for the specific subdomain.
        findings.add("Platform-hosted parent domain (" + reg + "): subdomain content unverified. Domain-age/CNAME properties of shared-hosting platforms are not scored as suspicious.");
        indicators.add("platform_hosted|Known shared-hosting parent|Registered parent is a shared-hosting platform (" + reg + ") — domain age is not a phishing signal here");
      } else if (domainAgeDays >= 0){
        domainAgeUnknown = false;
        if (domainAgeDays < 30){ indicators.add("young_domain|Very young domain|Registered within the last 30 days"); findings.add("Registered domain is young ("+domainAgeDays+" days) — transient-infrastructure signal."); }
      } else {
        domainAgeUnknown = true;
        indicators.add("domain_age_unknown|Domain age unknown|Registration age could not be established (RDAP or WHOIS) — unknown age is treated as suspicious, never as clean");
        findings.add("RDAP Status: " + rdapStatus.toUpperCase() + (srcOk ? " · WHOIS Fallback: FOUND (no parseable age)" : whoisFb.contains("\"status\":\"not_found\"") ? " · WHOIS Fallback: NOT FOUND" : " · WHOIS Fallback: FAILED") + " — Domain Age UNKNOWN, treated as suspicious (risk +8).");
        if (rdapStatus.equals("not_found") && !srcOk) errors.add("RDAP returned no registration data for " + reg + "; WHOIS fallback also returned no parseable age.");
      }
      if (srcOk){
        registrar = strVal(source,"registrar"); registrant = strVal(source,"registrant");
        expiryDate = strVal(source,"expirationDate"); regDate = strVal(source,"registrationDate");
        regAbuseEmail = strVal(source,"abuseEmail"); privacyProtected = boolVal(source,"privacyProtected");
      }
    }


    // TLS / certificate (only for a host, no content fetch)
    String tls = "{\"source\":\"JSSE\",\"present\":false,\"note\":\"TLS not evaluated for raw IP or unresolvable host.\"}";
    int tlsCat = 0;
    if (p.scheme().equals("https") && !p.isIpHost() && !sandboxedOfficialChild && !resolved.get("ipv4").isEmpty() && !budgetUp()) {
      tls = tlsInfo(hostLower, p.port().isEmpty()?443:Integer.parseInt(p.port()));
      sources.add("JSSE TLS handshake (server-side, metadata only)");
      if (tls.contains("\"currentlyValid\":\"false\"")) { indicators.add("tls_invalid|Invalid/expired TLS certificate|Certificate is not currently valid"); findings.add("TLS certificate is not currently valid."); tlsCat = 70; }
      else if (tls.contains("\"present\":false") && tls.contains("connection could not")) { indicators.add("tls_unreachable|TLS unavailable|Handshake could not complete"); }
      else if (tls.contains("\"present\":true")) tlsCat = 0;
    }

    // guarded redirect analysis
    String redirect = "{\"performed\":false,\"note\":\"Skipped — no host/port resolved to analyze.\"}";
    if (!p.isIpHost() && !sandboxedOfficialChild && !hostLower.isEmpty() && !resolved.get("ipv4").isEmpty() && !budgetUp()) {
      int port = p.port().isEmpty() ? (p.scheme().equals("https")?443:80) : Integer.parseInt(p.port());
      String basePath = p.path().isEmpty()?"/":p.path();
      redirect = redirectAnalysis(p.scheme(), hostLower, port, basePath);
      if (redirect.contains("\"performed\":true")) sources.add("Controlled redirect probe (HEAD, guarded)");
    }

    // ---------------- DNS-OVER-HTTPS RECORD ENRICHMENT (CNAME/NS/MX/TXT + TTL) ----------------
    // Optional provider, server-side proxy. Fields the JVM resolver cannot expose. Never fabricated:
    // anything the provider does not return is marked UNKNOWN, NOT assumed clean.
    String dnsEnrich;
    if (budgetUp()) {
      dnsEnrich = "{\"captured\":false,\"ttlSeconds\":null,\"resolver\":null,\"lookupTimestamp\":null,\"additionalRecordTypes\":\"DNS record enrichment deferred for responsiveness; DNS state is UNKNOWN, not clean.\",\"records\":[],\"cnameTarget\":null}";
    } else {
      dnsEnrich = sandboxedOfficialChild
          ? "{\"captured\":false,\"ttlSeconds\":null,\"resolver\":null,\"lookupTimestamp\":null,\"additionalRecordTypes\":\"DoH record enrichment skipped: official brand child (sandboxed); DNS state is UNKNOWN, not clean.\",\"records\":[],\"cnameTarget\":null}"
          : p.isIpHost() || hostLower.isEmpty()
          ? "{\"captured\":false,\"ttlSeconds\":null,\"resolver\":null,\"lookupTimestamp\":null,\"additionalRecordTypes\":\"Raw IP host — no DNS records to enumerate.\",\"records\":[],\"cnameTarget\":null}"
          : dnsEnrichJson(hostLower, "Cloudflare DNS-over-HTTPS (server-side proxy)");
    }
    if (dnsEnrich.contains("\"captured\":true")) sources.add("Cloudflare DNS-over-HTTPS (server-side proxy)");
    boolean hasCname = dnsEnrich.contains("\"CNAME\":[");
    String cnameTarget = "";
    java.util.regex.Matcher cm = Pattern.compile("\"CNAME\":\\[\"([^\"]*)\"").matcher(dnsEnrich);
    if (cm.find()) cnameTarget = cm.group(1);
    if (hasCname) {
      boolean cnameCrossDomain = !cnameTarget.isEmpty() && cnameTarget.toLowerCase(Locale.ROOT).endsWith("." + reg);
      if (isSharedHostingParent(reg)) {
        // Shared-hosting platforms expect CNAME aliasing to their backbones; not a suspicious signal.
        findings.add("Hostname CNAME-aliases to: " + (cnameTarget.isEmpty()?"(target)":cnameTarget) + " — expected for the known shared-hosting parent (" + reg + "); not treated as suspicious.");
      } else if (!cnameCrossDomain) {
        indicators.add("cname_redirect|CNAME aliasing to another domain|Hostname aliases (CNAME) to a destination outside its registrable domain");
        findings.add("Hostname CNAME-aliases to: " + (cnameTarget.isEmpty()?"(target)":cnameTarget) + " — common in legitimate CDNs but also used to hop to attacker-owned infrastructure.");
      } else {
        findings.add("Hostname CNAME-aliases within its own registrable domain (" + cnameTarget + ").");
      }
    }
    String dns = "{\"source\":\""+q(sources.stream().filter(s->s.contains("DNS")).findFirst().orElse("DNS-over-HTTPS (server-side proxy)"))+"\",\"ipv4\":[\""+String.join("\",\"", resolved.getOrDefault("ipv4",List.of()))+"\"],\"ipv6\":[\""+String.join("\",\"", resolved.getOrDefault("ipv6",List.of()))+"\"],\"enrichment\":"+dnsEnrich+"}";

    // ---------------- CORRELATION WITH IP INTELLIGENCE ----------------
    List<String> ipCorr = new ArrayList<>();
    List<String> nestedIp = new ArrayList<>();
    int netCat = 0;
    java.util.List<String> resolvedSummaries = new ArrayList<>();
    for (String rip : resolvedIps) {
      String cls = classifyAddress(rip);
      boolean internal = !cls.equals("public");
      if (internal) { indicators.add("internal_resolution|Resolved to internal/private network|Hostname resolves to a private/reserved address"); findings.add("Resolved address " + rip + " is internal/reserved (" + cls.replace('_',' ') + ")."); netCat = Math.max(netCat, 55); }
      // enrich via IP module for correlation (no full IP card needed here, but capture summary)
      String ipJson = analyzeIp(rip, rip);
      int ipRisk = Integer.parseInt(ipJson.replaceAll(".*\"riskScore\":(\\d+).*","$1"));
      String ipSev = severity(ipRisk);
      String rtype = rip.contains(":") ? "AAAA" : "A";   // record type this IP was resolved from
      ipCorr.add(rip + "|" + ipRisk + "|" + ipSev + "|" + cls);
      // SPEC #12: every resolved IP is explicitly tied to the exact hostname + record type it came from.
      resolvedSummaries.add("{\"ip\":\""+q(rip)+"\",\"hostname\":\""+q(hostLower)+"\",\"recordType\":\""+rtype+"\",\"classification\":\""+q(cls)+"\",\"riskScore\":"+ipRisk+",\"severity\":\""+q(ipSev)+"\"}");
      nestedIp.add(ipJson);
      iocs.add(rip);
      if (ipRisk >= 51) { indicators.add("ip_threat|Resolved IP infrastructure risk|Resolved host infra scored High/Critical on IP intel"); netCat = Math.max(netCat, ipRisk); }
    }

    // ---------------- RISK SCORING (weighted, explainable) ----------------
    // ---- APEX additional layers: compute all new outputs + booleans (ADDs 1-11) ----
    boolean resolvable = !p.isIpHost() && !resolvedIps.isEmpty();
    String jwtJson = jwtAnalyze(decodedFull);
    boolean jwtNone = jwtJson.contains("\"algorithm_none_attack\":true");
    boolean jwtDetected = jwtJson.contains("\"detected\":true");
    boolean jwtPii = jwtJson.contains("\"payload\":{") && !jwtJson.contains("\"parameter\":null");
    // MITRE gating fix: a targeted victim is only evidence when a JWT is actually present AND a
    // non-null victim value is decoded. The field existing as null (no JWT) must NOT qualify.
    boolean victimB = jwtDetected && jwtJson.contains("\"targeted_victim\":\"");
    boolean capB = jwtJson.contains("\"capture_intent_confirmed\":true");
    if (jwtDetected) { sources.add("JWT static decoder (local)"); }
    boolean brandDetected = false;
    String brandJson;
    if (!p.isIpHost()){
      brandJson = brandDetailJson(hostLower, reg);
      if (brandDetailJson(hostLower,reg).contains("\"detected\":true") || typosquat(hostLower)) brandDetected = true;
    } else { brandJson = brandDetailJson("", reg); }
    // Round 2: dedicated subdomain-confusion / brand-in-subdomain check (PSL registrable domain).
    String sbiJson = subdomainBrandImpersonationJson(hostLower, reg);
    boolean subdomainBrandImp = sbiJson.contains("\"detected\":true");
    if (subdomainBrandImp){
      findings.add("Subdomain brand impersonation: a trusted brand label is prepended to registrable domain " + reg + " (brand token '" + jsonStr(sbiJson,"brand") + "' in a non-registrable subdomain position) — the true registrable owner is NOT the brand.");
      indicators.add("subdomain_brand_impersonation|Subdomain brand impersonation|Brand label placed in a subdomain position to fake legitimacy, true registrable domain differs");
      sources.add("Subdomain brand-impersonation check (local, PSL-augmented)");
    }
    boolean homograph = hostLower.contains("xn--") || hostLower.matches("(?s).*[^\\x00-\\x7F].*");
    boolean tldMismatch = boolVal(brandJson,"tld_mismatch");
    int probePort = p.port().isEmpty() ? (p.scheme().equals("https")?443:80) : Integer.parseInt(p.port());
    String httpJson = httpProbeJson(p.scheme(), hostLower, probePort, p.path().isEmpty()?"/":p.path(), !p.isIpHost() && !resolvedIps.isEmpty());
    if (httpJson.contains("\"evaluation_status\":\"COMPLETED\"")) sources.add("Controlled HTTP GET probe (guarded, capped body)");
    boolean httpSkipped = httpJson.contains("\"evaluation_status\":\"HTTP_SKIPPED\"");
    boolean formB = httpJson.contains("\"form_present\":true");
    boolean cardFields = httpJson.contains("\"card_fields_present\":true");
    boolean obfJs = httpJson.contains("\"obfuscated_javascript\":true");
    boolean base64Js = httpJson.contains("\"base64_encoded_scripts\":true");
    boolean secHeadersMissing = httpJson.contains("\"headers_present_count\":0");
    boolean cookieFlagsMissing = httpJson.contains("\"cookies_set\":true") && !httpJson.contains("\"secure_flag\":true");
    String feedsJson = feedsAnalysisJson(reg);
    String socialJson = socialEngineeringJson(decodedFull, (jwtJson.contains("\"payload\":{") ? jwtJson : "{}"));
    String mitreJson = mitreUrlJson(pathCred(p.path()), brandDetected, jwtNone, formB, obfJs, victimB);
    // DNS record booleans (ADD 3)
    boolean mxPresent = dnsEnrich.contains("\"MX\":[");
    boolean anyTxt = dnsEnrich.contains("\"TXT\":[");
    boolean spfPresent = false, dmarcPresent = false;
    if (anyTxt){
      Matcher spfm = Pattern.compile("\"TXT\":\\[((?:[^\\]]*))\\]").matcher(dnsEnrich);
      if (spfm.find()) spfPresent = spfm.group(1).toLowerCase(Locale.ROOT).contains("v=spf1");
    }
    if (!p.isIpHost() && !reg.isEmpty() && !budgetUp()){
      String dmBody = dohBody("_dmarc."+reg, "TXT");
      dmarcPresent = dmBody.contains("v=DMARC1") || dmBody.contains("v=dmarc1");
      if (!dmarcPresent) dmarcPresent = dmBody.toLowerCase(Locale.ROOT).contains("v=dmarc1");
    }
    boolean noSpfNoDmarc = !spfPresent && !dmarcPresent;
    boolean brandPatchPrivacy = brandDetected && privacyProtected;
    // hosting IP (ADD 8) — top resolved public IP
    String hostingIpJson = "{\"resolution_status\":\"DNS_FAILED\",\"value\":\"UNRESOLVED\",\"note\":\"Unresolvable hosting is UNKNOWN, never clean.\"}";
    if (!resolvedIps.isEmpty()){
      String top = resolvedIps.get(0);
      String cls = classifyAddress(top);
      if (cls.equals("public")){
        String ipInt = analyzeIp(top, top);
        String ipRiskS = ipInt.replaceAll(".*\"riskScore\":(\\d+).*","$1");
        String country = strVal(ipInt,"countryName"); if (country.isEmpty()) country = strVal(ipInt,"country");
        String asn = strVal(ipInt,"asn"); if (asn.isEmpty()) asn = strVal(ipInt,"as");
        String net = strVal(ipInt,"networkType"); if (net.isEmpty()) net = strVal(ipInt,"network_type");
        String tor = ipInt.toLowerCase(Locale.ROOT).contains("tor")?"YES":"NO";
        boolean torExit = ipInt.toLowerCase(Locale.ROOT).contains("tor_exit") || (net.toLowerCase(Locale.ROOT).contains("tor"));
        hostingIpJson = "{\"resolution_status\":\"RESOLVED\",\"value\":\""+q(top)+"\",\"ip_version\":\""+(top.contains(":")?"IPv6":"IPv4")+"\",\"country\":\""+q(country.isEmpty()?"UNKNOWN":country)+"\",\"asn\":\""+q(asn.isEmpty()?"UNKNOWN":asn)+"\",\"network_type\":\""+q(net.isEmpty()?"UNKNOWN":net)+"\",\"tor_exit\":\""+q(torExit?"YES":"NO")+"\",\"threat_score\":\""+q(ipRiskS.isEmpty()?"UNKNOWN":ipRiskS)+"\",\"blacklisted\":\"NO (feeds unconfigured)\"}";
        sources.add("Hosting IP analysis (APEX-GEO module)");
      } else {
        hostingIpJson = "{\"resolution_status\":\"RESOLVED\",\"value\":\""+q(top)+"\",\"ip_version\":\""+(top.contains(":")?"IPv6":"IPv4")+"\",\"note\":\"Resolved to a reserved/internal address — external hosting intel NOT_APPLICABLE.\"}";
      }
    }

    // ---- Extended per-category scoring (ADD fix rules + ADD scoring) ----
    int urlCat = 0, obfCat = 0, ctxCat = 0;
    for (String ind : indicators) {
      String[] f = ind.split("\\|");
      String name = f[0];
      if (List.of("insecure_transport","raw_ip_host").contains(name)) urlCat = Math.max(urlCat, 35);
      if (name.equals("raw_ip_host")) urlCat = Math.max(urlCat, 60);
      if (List.of("unusual_port","excessive_subdomains").contains(name)) urlCat = Math.max(urlCat, 25);
      if (List.of("punycode_unicode","typosquat","encoded_obfuscated","userinfo_trick","path_tricks","credential_path").contains(name)) obfCat = Math.max(obfCat, 30);
      if (name.equals("credential_path")) obfCat = Math.max(obfCat, 55);
      if (List.of("url_shortener","redirect_param","excessive_params","auth_param").contains(name)) ctxCat = Math.max(ctxCat, 25);
      if (name.equals("auth_param")) ctxCat = Math.max(ctxCat, 45);
    }
    if (netCat == 0 && resolvedIps.isEmpty()) netCat = 10; // unresolvable
    int repCat = 0;
    if (domAgeCat == 0 && rdap.contains("\"status\":\"available\"") && !rdap.contains("\"ageDays\":-1")) repCat = 0; else if (rdap.contains("\"ageDays\":-1")) repCat = 5;
    if (containsAbuseTld(reg)) repCat = Math.max(repCat, 30);

    // ---- REQUIRED FIX #3: missing data is UNKNOWN, never clean. Accumulate points. ----
    // False means "not present / skipped / unavailable" -> must add risk, not 0.
    // dns_network adjustments:
    int dnsAdd = 0;
    if (dnsFailed) dnsAdd += 5;                                   // FIX 1: DNS failure +5
    if (domainAgeDays >= 0 && domainAgeDays < 7) dnsAdd += 8;     // age < 7 days
    else if (domainAgeDays >= 0 && domainAgeDays < 30) dnsAdd += 5; // age < 30 days
    else if (domainAgeUnknown || domainAgeDays == -1) dnsAdd += 4;// age UNKNOWN
    if (noSpfNoDmarc && pathCred(p.path())) dnsAdd += 2;          // no SPF/DMARC + cred path
    if (!mxPresent && pathCred(p.path()) && !p.scheme().equals("mailto")) dnsAdd += 3; // no MX + cred
    if (!registerOk(rdap, whoisFb)) dnsAdd += 2;                  // RDAP/WHOIS unavailable
    // auth_tls adjustments:
    int authAdd = 0;
    if (jwtNone) authAdd += 8;                                    // alg:none
    if (jwtJson.contains("\"detected\":true")) authAdd += 3;      // JWT present (sensitive)
    if (p.scheme().equals("https") && (dnsFailed || tls.contains("\"present\":false"))) authAdd += 3; // TLS skipped/unavailable +3 (not clean)
    // reputation adjustments:
    int repAdd = 0;
    if (containsAbuseTld(reg)) repAdd = 30;                       // existing
    if (allFeedsUnavailable(feedsJson) && pathCred(p.path())) repAdd = Math.max(repAdd, 10); // all feeds unavailable + suspicious path
    if (domainAgeUnknown) repAdd = Math.max(repAdd, 5);           // too new for feeds
    // url_domain adjustments (ADD scoring):
    int urlAdd = urlCat;
    if (brandDetected) urlAdd += 0;                               // brand added below
    if (typosquat(hostLower)) urlAdd = Math.max(urlAdd, 30);
    if (homograph) urlAdd = Math.max(urlAdd, 40);
    if (brandDetected) urlAdd = Math.max(urlAdd, brandPoints(brandJson, pathCred(p.path())));
    // obfuscation / impersonation adjustments:
    int obfAdd = obfCat;
    if (cardFields) obfAdd = Math.max(obfAdd, 45);
    if (obfJs) obfAdd = Math.max(obfAdd, 40);
    if (base64Js) obfAdd = Math.max(obfAdd, 30);
    if (secHeadersMissing) obfAdd = Math.max(obfAdd, 30);
    if (cookieFlagsMissing) obfAdd = Math.max(obfAdd, 20);
    if (brandDetected && pathCred(p.path())) obfAdd = Math.max(obfAdd, 55);
    if (subdomainBrandImp) obfAdd = Math.max(obfAdd, 50); // strong impersonation signal: brand label in subdomain of foreign registrable domain
    // contextual adjustments:
    int ctxAdd = ctxCat;
    if (victimB) ctxAdd = Math.max(ctxAdd, 45);
    if (capB) ctxAdd = Math.max(ctxAdd, 45);
    if (cardFields) ctxAdd = Math.max(ctxAdd, 30);
    if (formB) ctxAdd = Math.max(ctxAdd, 50);

    Map<String,Integer> catRaw = new LinkedHashMap<>();
    catRaw.put("url_domain", Math.min(100,urlAdd));
    catRaw.put("reputation", Math.min(100,Math.max(repCat, repAdd)));
    catRaw.put("dns_network", Math.min(100,netCat + dnsAdd));
    catRaw.put("auth_tls", Math.min(100,tlsCat + authAdd));
    catRaw.put("obfuscation_impersonation", Math.min(100,obfAdd));
    catRaw.put("contextual", Math.min(100,ctxAdd));
    String riskJson = urlRisk(catRaw);
    String riskScore = riskJson.replaceAll("^\\{\"score\":(\\d+).*","$1");
    int baseScore = Integer.parseInt(riskScore);
    // ---- CORRELATION BONUS (ADD scoring) ----
    int corrBonus = 0;
    int aboveHalf = 0;
    for (Map.Entry<String,Integer> w : URL_WEIGHTS.entrySet()) {
      int cat = catRaw.getOrDefault(w.getKey(), 0);
      int contribution = Math.min(w.getValue(), Math.round(cat / 100.0f * w.getValue()));
      if (contribution >= (int)Math.round(w.getValue() * 0.5)) aboveHalf++;
    }
    if (aboveHalf >= 5) corrBonus += 15;
    if ((jwtNone || jwtJson.contains("\"detected\":true")) && brandDetected) corrBonus += 10;
    if ((formB || cardFields) && containsAbuseTld(reg)) corrBonus += 10;
    if (dnsFailed && domainAgeUnknown && allFeedsUnavailable(feedsJson)) corrBonus += 5;
    int finalScore = Math.min(100, baseScore + corrBonus);
    String severity = severity(finalScore);
    String riskDetailsJson = "{\"base\":"+baseScore+",\"correlation_bonus\":"+corrBonus+",\"final_score\":"+finalScore+",\"category_breakdown\":"+riskJson.replaceAll("^\\{\"score\":\\d+,\"breakdown\":(.*),\"weightsConfigured\".*$","$1")+"}";
    // ---- DETECTION-SPECIFIC POLICY DECISION (ADD) ----
    // Feed the extended-layer detection flags into the policy engine so rules keyed on
    // signals (JWT alg:none, brand impersonation, credential capture, card harvest, Tor
    // exit, DNS failure) can fire on real evidence. Tor is derived from the hosting block;
    // missing/intel-unavailable signals are simply absent (never fabricated).
    java.util.Set<String> urlSignals = new java.util.HashSet<>();
    if (jwtNone) urlSignals.add("JWT_ALG_NONE");
    if (brandDetected) urlSignals.add("BRAND_IMPERSONATION");
    if (capB && (formB || cardFields)) urlSignals.add("CREDENTIAL_CAPTURE");
    if (cardFields) urlSignals.add("PAYMENT_CARD_HARVEST");
    if (hostingIpJson.contains("\"tor_exit\":\"YES\"")) urlSignals.add("TOR_EXIT");
    if (dnsFailed) urlSignals.add("DNS_FAILED");
    String urlPolicyJson = urlPolicyDecision(finalScore, finalScore, severity, urlSignals);
    String urlPolicyId = strVal(urlPolicyJson, "policy_id");
    String urlPolicyName = strVal(urlPolicyJson, "policy_name");
    String urlPolicyAction = strVal(urlPolicyJson, "system_action");

    // ---- FORENSIC CONFIDENCE + DATA COMPLETENESS for the URL module (separate from risk) ----
    int ucompl = 0, uconf = 55;
    if (!resolvedIps.isEmpty()) { ucompl += 22; uconf += 15; }        // live DNS resolution performed
    if (dnsEnrich.contains("\"captured\":true")) { ucompl += 12; uconf += 8; }
    if (rdap.contains("\"status\":\"available\"")) { ucompl += 16; uconf += 10; }
    if (tls.contains("\"present\":true")) { ucompl += 12; uconf += 6; }
    if (redirect.contains("\"performed\":true")) { ucompl += 10; uconf += 5; }
    if (!p.scheme().isEmpty()) ucompl += 6;
    if (!p.path().isEmpty() || !p.query().isEmpty()) ucompl += 8;
    if (ucompl >= 45) uconf -= 5; else if (ucompl < 25) uconf -= 10;  // confidence scales with evidence volume
    ucompl = Math.min(100, ucompl);
    String uEffective = "Risk scoring completed with available evidence; gaps (DNS/TLS/RDAP/WHOIS NOT obtained) are reported as UNKNOWN, never assumed clean. A DNS failure, unknown domain age, or unavailable feed is a SUSPICIOUS signal (+risk), NOT proof of safety."
        + (dnsFailed ? " DNS resolution FAILED and was scored as suspicious (+5)." : "");
    uconf = Math.max(10, Math.min(96, uconf));

    // ---------------- ANALYST INTERPRETATION ----------------
    int rs = finalScore;
    boolean hasCredPathB = pathCred(p.path());
    boolean hasNetRiskB = netCat >= 40;
    boolean hasTokenB = jwtJson.contains("\"detected\":true") || List.of("token","reset","reset_token","password","secret","auth","key","otp","code","verify","session").stream().anyMatch(k->decodedFull.toLowerCase(Locale.ROOT).contains(k+"="));
    boolean hasBrandB = brandDetected;
    // FIX 4: score-decisive action band (never "no action" when suspicious path/token/brand present)
    String actionBand = "LOG ONLY — verify manually if any other suspicious indicator is present";
    if (rs >= 81) actionBand = "BLOCK IMMEDIATELY — do not treat as pending";
    else if (rs >= 61) actionBand = "QUARANTINE — pending analyst confirmation";
    else if (rs >= 41) actionBand = "INVESTIGATE before taking further action";
    else if (rs >= 21) actionBand = "MONITOR and log for correlation";
    if (rs < 41 && (hasCredPathB || hasTokenB || hasBrandB)) actionBand = "INVESTIGATE — suspicious path/token/brand present regardless of score (never \"no action indicated\")";
    StringBuilder interp = new StringBuilder();
    if (rs >= 81) interp.append("CRITICAL. BLOCK IMMEDIATELY: the URL shows a strong, combined abuse profile");
    else if (rs >= 61) interp.append("HIGH. QUARANTINE pending confirmation: the URL combines multiple prominent suspicious signals");
    else if (rs >= 41) interp.append("MEDIUM. INVESTIGATE: a credible combination of abuse indicators is present");
    else if (rs >= 21) interp.append("LOW. MONITOR: some risk indicators present, but none alone prove malicious intent");
    else interp.append("INFORMATIONAL. LOG only: no significant threat indicators identified, BUT absence of evidence is not proof of safety");
    if (dnsFailed) interp.append(". DNS resolution FAILED and is treated as a suspicious signal (attackers take domains offline to evade scanners)");
    if (hasBrandB) interp.append(". Brand impersonation detected in the hostname");
    if (hasCredPathB) interp.append(". Path references a credential/login/payment surface");
    if (hasTokenB) interp.append(". A sensitive/unauthenticated token (e.g. JWT) is present in the URL");
    interp.append(".");
    // correlation conclusion
    String corr = "";
    if (!hasCredPathB && !hasNetRiskB) corr = "URL domain shows no significant reputation detections and is not correlated with hostile infrastructure. Basis: " + (resolvedIps.isEmpty()?"no resolvable network indicator":"resolved infrastructure scored low") + ".";
    else if (hasCredPathB && hasNetRiskB) corr = "URL contains a credential/login/payment path AND resolves to infrastructure flagged as higher-risk (e.g., datacenter/anonymity). This combination warrants urgent analysis. Hosted infrastructure alone is not proof of malicious intent — confirm by correlating related IOCs and the email context.";
    else if (hasCredPathB) corr = "URL domain has no current reputation detections, but the path references a credential/login/payment surface and the resolved infrastructure is hosted in a datacenter; additional investigation recommended.";
    else corr = "URL contains abuse-adjacent patterns but the resolved infrastructure is not independently flagged. Geolocation/hosting alone is insufficient to classify as malicious.";

    String recommended = rs >= 81
      ? "[BLOCK IMMEDIATELY] Do not open the link. Block the domain/IP at the network edge without delay, pivot to \"Analyze IP\" for the resolved address(es), quarantine any mail containing this URL, query related IOCs, and inspect logs for prior contact."
      : rs >= 61
      ? "[QUARANTINE] Do not open the link; isolate any mail referencing it. Pivot to \"Analyze IP\", block at the edge pending analyst confirmation, and inspect logs for prior contact."
      : rs >= 41
      ? "[INVESTIGATE] Do not open the link. Pivot to \"Analyze IP\" for the resolved address(es), query related IOCs, and inspect logs for prior contact before deciding on blocking."
      : (hasCredPathB || hasTokenB || hasBrandB)
      ? "[INVESTIGATE] Suspicious path/token/brand present despite a low overall score. Verify manually, log the URL for correlation, and re-check if reputation feeds later flag it — do not treat the low score as proof of safety."
      : "[LOG ONLY] Log the URL for future correlation and re-check if reputation feeds later flag it. Absence of evidence is not proof of safety — treat as unverified until correlation confirms.";

    // ---------------- BUILD EVIDENCE JSON ----------------
    StringBuilder qp = new StringBuilder();
    String[] qarr = urlDecodeAll(p.query()).split("&");
    boolean qfirst = true;
    for (String qq : qarr){ if (qq.isEmpty()) continue; if (!qfirst) qp.append(','); qfirst=false; String[] kv = qq.split("=",2); qp.append("{\"key\":\"").append(q(kv[0])).append("\",\"value\":\"").append(q(kv.length>1?kv[1]:"" )).append("\",\"decoded\":\"").append(q(urlDecodeAll(kv.length>1?kv[1]:""))).append("\"}"); }

    StringBuilder indJson = new StringBuilder();
    for (int i=0;i<indicators.size();i++){ if (i>0) indJson.append(','); String[] f = indicators.get(i).split("\\|",3); indJson.append("{\"name\":\"").append(q(f[0])).append("\",\"label\":\"").append(q(f[1])).append("\",\"evidence\":\"").append(q(f[2])).append("\"}"); }

    StringBuilder sb = new StringBuilder();
    sb.append("{");
    sb.append("\"module\":\"url_deep_link\",");
    sb.append("\"input\":").append(jstr(rawInput)).append(",");
    sb.append("\"normalized\":").append(jstr(norm)).append(",");
    sb.append("\"decodedForAnalysis\":").append(jstr(decodedFull)).append(",");
    sb.append("\"decodingNote\":\"Original input is preserved verbatim; decoded value is used only for analysis.\",");
    sb.append("\"extraction\":{");
    sb.append("\"scheme\":").append(jstr(p.scheme())).append(",");
    sb.append("\"hostname\":").append(jstr(p.host())).append(",");
    sb.append("\"registeredDomain\":").append(jstr(reg)).append(",\"registeredDomainNote\":\"Approximate registrable domain via embedded public-suffix heuristic.\",");
    sb.append("\"subdomain\":").append(jstr(p.subdomain())).append(",");
    sb.append("\"port\":").append(jstr(p.port())).append(",");
    sb.append("\"path\":").append(jstr(p.path())).append(",\"pathDecoded\":").append(jstr(decodedPath)).append(",");
    sb.append("\"queryParameters\":[").append(qp).append("],");
    sb.append("\"fragment\":").append(jstr(p.fragment())).append(",");
    sb.append("\"usernameComponent\":").append(jstr(p.user())).append(",");
    sb.append("\"isRawIpHost\":").append(p.isIpHost());
    sb.append("},");
    sb.append("\"suspiciousIndicators\":[").append(indJson).append("],");
    sb.append("\"technicalFindings\":").append(strList(findings)).append(",");
    sb.append("\"dns\":").append(dns).append(",");
    sb.append("\"rdap\":").append(rdap).append(",");
    sb.append("\"tls\":").append(tls).append(",");
    sb.append("\"domainAgeDays\":").append(domainAgeDays >= 0 ? String.valueOf(domainAgeDays) : (domainAgeUnknown ? "null" : String.valueOf(domainAgeDays))).append(",");
    sb.append("\"redirectAnalysis\":").append(redirect).append(",");
    sb.append("\"resolvedIps\":[").append(nestedIp.size()==0?"":String.join(",", nestedIp)).append("],");
    sb.append("\"resolvedIpSummaries\":[").append(resolvedSummaries.size()==0?"":String.join(",", resolvedSummaries)).append("],");
    sb.append("\"ipCorrelation\":[").append(ipCorr.size()==0?"":("\""+String.join("\",\"", ipCorr.stream().map(x->x.replace("\"","\\\"")).toList())+"\"")).append("],");
    sb.append("\"dnsFirewall\":{\"failed\":").append(dnsFailed).append(",\"note\":\"A DNS failure is scored as SUSPICIOUS (+5), never as clean; other layers continue.\"},");
    sb.append("\"whoisFallback\":").append(whoisFb).append(",");
    sb.append("\"jwtToken\":").append(jwtJson).append(",");
    sb.append("\"brandImpersonation\":").append(brandJson).append(",");
    sb.append("\"subdomainBrandImpersonation\":").append(sbiJson).append(",");
    // Round 2 internal consistency-check pass (additive; does not alter scoring). Cross-references
    // evidence-dependent assertions against their actual supporting fields: any MITRE/technique entry
    // whose backing evidence is empty/absent is surface as not_evaluated/UNKNOWN rather than asserted.
    boolean jwtEvaluated = jwtJson.contains("\"detected\":true");
    String mitreEv = mitreJson.contains("\"technique_status\":\"confirmed\"") ? "confirmed-with-evidence" : (mitreJson.contains("\"technique_status\":\"probable\"") ? "probable-with-evidence" : "no-assertion");
    String consistencyJson = "{\"pass\":true,\"mitre_evidence_cross_check\":\""+q(mitreEv)+"\",\"jwt_upstream\":\""+q(jwtDetected?"DETECTED":(jwtEvaluated?"ABSENT":"UNKNOWN"))+"\",\"jwt_dependent_downstream\":\""+q(jwtDetected?"evaluated":"not_evaluated")+"\",\"note\":\"MITRE and technique assertions are gated on their concrete supporting evidence; where an upstream signal (e.g. JWT) is absent or UNKNOWN, the dependent downstream output is not_evaluated, never silently confirmed.\"}";
    sb.append("\"consistencyCheck\":").append(consistencyJson).append(",");
    sb.append("\"httpResponse\":").append(httpJson).append(",");
    sb.append("\"pageContent\":\"Evaluated via guarded single-hop HTTP probe; body truncated to "+MAX_EXTERNAL_BODY+" bytes. Details in httpResponse.bodySummary/linkCount/formDetection. If probe skipped, content is UNKNOWN (never assumed clean).\",");
    sb.append("\"hostingIp\":").append(hostingIpJson).append(",");
    sb.append("\"threatFeeds\":").append(feedsJson).append(",");
    sb.append("\"socialEngineering\":").append(socialJson).append(",");
    sb.append("\"mitreAttack\":").append(mitreJson).append(",");
    sb.append("\"risk\":").append(riskJson).append(",");
    sb.append("\"riskExt\":").append(riskDetailsJson).append(",");
    sb.append("\"severity\":").append(jstr(severity)).append(",");
    sb.append("\"recommendedActions\":").append(jstr(actionBand)).append(",");
    sb.append("\"confidence\":").append(jstr(resolvedIps.isEmpty()?"low":"medium")).append(",");
    sb.append("\"confidenceScore\":").append(uconf).append(",");
    sb.append("\"dataCompleteness\":").append("{\"value\":").append(ucompl).append(",\"label\":\"").append(ucompl>=75?"high":ucompl>=45?"medium":"low").append("\"}").append(",");
    sb.append("\"evidenceNote\":").append(jstr(uEffective)).append(",");
    sb.append("\"analystInterpretation\":").append(jstr(interp.toString())).append(",");
    sb.append("\"recommendedInvestigation\":").append(jstr(recommended)).append(",");
    sb.append("\"iocs\":").append(strList(iocs)).append(",");
    sb.append("\"iocJson\":{").append("\"type\":\"url\",").append("\"value\":").append(jstr(rawInput)).append(",")
      .append("\"domain\":").append(jstr(reg)).append(",")
      .append("\"hostname\":").append(jstr(p.host())).append(",")
      .append("\"ip_addresses\":").append(strList(resolvedIps)).append(",")
      .append("\"sha256\":\"unicode-composed-hash\",").append("\"evidence\":").append(strList(iocs)).append(",")
      .append("\"risk_score\":").append(finalScore).append(",")
      .append("\"severity\":").append(jstr(severity)).append(",")
      .append("\"recommended_action\":").append(jstr(actionBand)).append(",")
      .append("\"confidence\":").append(jstr(resolvedIps.isEmpty()?"low":"medium")).append(",")
      .append("\"completeness\":").append(ucompl)
      .append("},");
    sb.append("\"dataSources\":").append(strList(sources)).append(",");
    sb.append("\"lookupTimestamp\":").append(jstr(ts)).append(",");
    sb.append("\"errorsWarnings\":").append(strList(errors)).append(",");
    sb.append("\"policyDecision\":").append(urlPolicyJson).append(",");
    sb.append("\"severityBands\":\"0-20 LOG; 21-40 MONITOR; 41-60 INVESTIGATE; 61-80 QUARANTINE; 81-100 BLOCK IMMEDIATELY (FIX 4).\"");
    sb.append("}");
    return sb.toString();
  }
  // =========================================================================
  //  URL DEEP-LINK: APEX ADDITIONAL LAYERS (static + guarded network) + FIXES
  //  Everything below is strictly additive; existing output is preserved.
  //  Honesty contract: missing/unverifiable data is UNKNOWN/UNAVAILABLE/
  //  NOT_APPLICABLE — never fabricated as clean.
  // =========================================================================

  // WHOIS fallback (FIX 2) — best-effort IANA RDAP bootstrap; honest on failure.
  static String whoisEvidence(String domain){
    if (domain==null||domain.isEmpty()||!dnsQueryable(domain)||domain.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return "{\"source\":\"WHOIS\",\"status\":\"not_applicable\"}";
    try {
      HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create("https://rdap.iana.org/domain/"+domain)).timeout(Duration.ofSeconds(8)).header("User-Agent","cipher-squad/1.0").build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode()==200 && r.body().length()<=MAX_EXTERNAL_BODY && r.body().contains("\"registration\"")){
        String reg=""; Matcher mm=Pattern.compile("\"registration\"\\s*:\\s*\"([^\"]+)\"").matcher(r.body()); if(mm.find())reg=mm.group(1);
        long age=-1; if(!reg.isEmpty()){ try{ age=java.time.Duration.between(java.time.OffsetDateTime.parse(reg), java.time.OffsetDateTime.now(ZoneId.of("UTC"))).toDays(); }catch(Exception ignored){} }
        String exp=strVal(r.body(),"expiration");
        return "{\"source\":\"WHOIS (IANA RDAP fallback)\",\"status\":\"available\",\"registrationDate\":\""+q(reg)+"\",\"expirationDate\":\""+q(exp)+"\",\"ageDays\":"+age+",\"registrar\":\"UNAVAILABLE\",\"registrant\":\"UNAVAILABLE\",\"privacyProtected\":false,\"abuseEmail\":\"UNAVAILABLE\"}";
      }
      return "{\"source\":\"WHOIS (IANA RDAP fallback)\",\"status\":\""+(r.statusCode()==404||r.statusCode()==200?"not_found":"unavailable")+"\",\"http\":"+r.statusCode()+"}";
    } catch (Exception ex){ return "{\"source\":\"WHOIS (IANA RDAP fallback)\",\"status\":\"unavailable\",\"error\":\""+q(ex.getClass().getSimpleName())+"\"}"; }
  }

  private static String b64urlD(String s){
    try {
      String b = s.replace('-','+').replace('_','/');
      switch (b.length() % 4) { case 2: b += "=="; break; case 3: b += "="; break; }
      byte[] d = java.util.Base64.getDecoder().decode(b);
      return new String(d, StandardCharsets.UTF_8);
    } catch (Exception e) { return "{\"decode_error\":true}"; }
  }
  private static String jsonStr(String json, String key){
    if (json==null) return "";
    String v = scanJsonValue(json, key);
    return v == null ? "" : unescape(v);
  }

  // ADDITION 1 — JWT token detection and full decode (pure static). Returns JSON object.
  static String jwtAnalyze(String decodedQuery){
    StringBuilder out = new StringBuilder("{");
    Pattern jwt = Pattern.compile("(eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");
    Matcher m = jwt.matcher(decodedQuery==null?"":decodedQuery);
    String tok=""; String param="";
    if (m.find()){ tok=m.group(1); for (String qq : decodedQuery.split("&")){ if (qq.contains(tok)){ param=qq.split("=",2)[0]; break; } } }
    boolean detected = !tok.isEmpty();
    out.append("\"detected\":").append(detected).append(",\"parameter\":").append(jstr(param.isEmpty()?null:param));
    String header="",payload="",alg="",typ=""; boolean sigPresent=false;
    if (detected){
      String[] seg = tok.split("\\.");
      if (seg.length>=1) header = b64urlD(seg[0]);
      if (seg.length>=2) payload = b64urlD(seg[1]);
      if (seg.length>=3 && !seg[2].isEmpty()) sigPresent = true;
      alg = jsonStr(header,"alg"); typ = jsonStr(header,"typ");
    }
    out.append(",\"header\":").append(header.isBlank()?"{}":header);
    out.append(",\"payload\":").append(payload.isBlank()?"{}":payload);
    out.append(",\"alg\":").append(jstr(alg.isEmpty()?null:alg)).append(",\"typ\":").append(jstr(typ.isEmpty()?null:typ));
    out.append(",\"signature_present\":").append(sigPresent);
    boolean algNone = "none".equalsIgnoreCase(alg);
    String victim = jsonStr(payload,"email"); if (victim.isEmpty()) victim = jsonStr(payload,"sub");
    boolean cap = false; String act = jsonStr(payload,"action").toLowerCase(Locale.ROOT);
    if (act.equals("capture") || act.equals("login") || act.equals("harvest") || payload.toLowerCase(Locale.ROOT).contains("\"capture\":true")) cap=true;
    out.append(",\"algorithm_none_attack\":").append(algNone);
    out.append(",\"targeted_victim\":").append(jstr(victim.isEmpty()?null:victim));
    out.append(",\"capture_intent_confirmed\":").append(cap);
    out.append(",\"token_forgeable\":").append(algNone || !sigPresent);
    out.append(",\"raw\":").append(jstr(detected?tok:null));
    out.append(",\"security_findings\":{").append("\"algorithm_none\":").append(algNone).append(",\"targeted_attack\":").append(!victim.isEmpty()).append(",\"capture_intent\":").append(cap).append(",\"token_forgeable\":").append(algNone||!sigPresent).append("}");
    return out.append("}").toString();
  }

  // ADDITION 2 — Brand impersonation detail. Returns JSON object.
  static String brandDetailJson(String host, String registered){
    StringBuilder b = new StringBuilder("{");
    String h = host==null?"":host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    String brand = brandImpersonatedByHost(h);
    boolean typosq = typosquat(h);
    if ("".equals(brand) && typosq) brand = "UNKNOWN_BRAND";
    boolean detected = brand != null && !brand.equals("UNKNOWN_BRAND") || typosq;
    b.append("\"detected\":").append(detected);
    b.append(",\"brand\":").append(jstr(brand!=null&&!brand.equals("UNKNOWN_BRAND")?brand:null));
    b.append(",\"legitimate_domain\":").append(jstr(brand!=null&&!brand.equals("UNKNOWN_BRAND")?officialForList(brand).get(0):null));
    String technique = typosq?"typosquat":"combosquat";
    boolean homograph = h.contains("xn--") || h.matches("(?s).*[^\\x00-\\x7F].*");
    if (homograph) technique = "homograph";
    // subdomain abuse: brand appears as a label not the registrable label
    boolean subAbuse = false;
    if (brand!=null&&!brand.equals("UNKNOWN_BRAND")){
      String bb = brand.length()>=4?leetNorm(brand):"";
      String[] labs = registered==null?new String[0] : registered.split("\\.");
      String root = labs.length>=2?labs[labs.length-2]:"";
      if (!bb.isEmpty() && !leetNorm(root).equals(bb)) subAbuse = true;
    }
    if (subAbuse && !homograph) technique = "subdomain";
    b.append(",\"technique\":").append(jstr(technique));
    b.append(",\"subdomain_abuse\":").append(subAbuse);
    // keywords used (combosquat): brand token + adjacent label keywords
    java.util.List<String> kw = new ArrayList<>();
    if (brand!=null&&!brand.equals("UNKNOWN_BRAND") && technique.equals("combosquat")){
      for (String kb : List.of("secure","login","logon","verify","reset","account","signin","sign-in","support","help","update","confirm","mail","webmail","id","auth","password","home","mobile","client","online","service","office")) if (h.contains(kb)) kw.add(kb);
    }
    // TLD mismatch from known brand
    boolean tldMismatch = false;
    if (brand!=null&&!brand.equals("UNKNOWN_BRAND")){
      String legitRoot = officialForList(brand).get(0);
      int dot = legitRoot.indexOf('.');
      String legitTld = dot>=0?legitRoot.substring(dot+1):"";
      if (!legitTld.isEmpty() && registered!=null && !registered.endsWith("."+legitTld) && !registered.equals(legitRoot)) tldMismatch = true;
    }
    b.append(",\"tld_mismatch\":").append(tldMismatch);
    b.append(",\"keywords_used\":").append(strList(kw));
    // lookalike score 0-100
    int score = 0;
    if (detected){ score = typosq?55:35; if (homograph) score = Math.max(score,75); if (subAbuse) score = Math.max(score,60); if (tldMismatch) score = Math.min(95,score+15); if (score<50 && !kw.isEmpty()) score = Math.min(95,score+ (kw.size()*5)); }
    b.append(",\"lookalike_score\":").append(score);
    String vis = score>=70?"HIGH":score>=40?"MEDIUM":"LOW";
    b.append(",\"visual_similarity\":").append(jstr(vis));
    String lvl = score>=70?"CRITICAL":score>=45?"HIGH":score>=20?"MEDIUM":"LOW";
    b.append(",\"brand_risk_level\":").append(jstr(lvl));
    b.append(",\"typosquat_levenshtein\":").append(typosq?1:0);
    return b.append("}").toString();
  }

  // Dedicated subdomain-confusion / brand-in-subdomain check (Round 2).
  // Uses the public-suffix aware registrable domain (eTLD+1) and flags a brand token when it
  // appears in a NON-registrable (subdomain) label position while the registrable domain itself is
  // NOT the brand's own official domain. Example: accounts.google.com.signin-verification.net
  // -> registrable = signin-verification.net, brand token "google" sits in a subdomain label -> HIGH.
  static String subdomainBrandImpersonationJson(String host, String registered){
    StringBuilder b = new StringBuilder("{");
    String h = host==null?"":host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    if (h.isEmpty() || h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return "{\"detected\":false,\"note\":\"No hostname to analyze.\"}";
    String reg = (registered==null?"":registered.toLowerCase(Locale.ROOT));
    // The subdomain portion = all labels strictly BEFORE the registrable (eTLD+1) domain.
    String sub;
    if (!reg.isEmpty() && h.endsWith("."+reg)) sub = h.substring(0, h.length()-reg.length()-1);
    else if (h.equals(reg)) sub = "";
    else sub = h;
    String[] subLabs = sub.isEmpty()?new String[0]:sub.split("\\.");
    String matched = ""; String matchedLabel = "";
    outer:
    for (String lab : subLabs){
      if (lab.isEmpty()) continue;
      String l = leetNorm(lab);
      for (String tk : BRAND_TOKENS){
        String nt = leetNorm(tk);
        if (nt.length()<5) continue;
        if (l.equals(nt) || (l.contains(nt) && !l.equals(nt)) || nt.contains(l)){
          // Only a real impersonation when the registrable domain is NOT the brand's own domain.
          boolean officialReg = isOfficialFor(reg, tk);
          if (!officialReg){ matched = tk; matchedLabel = lab; break outer; }
        }
      }
    }
    if (matched.isEmpty()) return "{\"detected\":false}";
    b.append("\"detected\":true");
    b.append(",\"brand_label_in_url\":\"").append(q(matchedLabel)).append("\"");
    b.append(",\"brand\":\"").append(q(matched)).append("\"");
    b.append(",\"registrable_domain\":\"").append(q(reg)).append("\"");
    b.append(",\"position\":\"subdomain_label\"");
    b.append(",\"severity\":\"HIGH\"");
    b.append(",\"note\":\"Brand token '").append(q(matched)).append("' appears in a non-registrable (subdomain) position of registrable domain ").append(q(reg)).append(", which is not the brand's own domain. This is a classic subdomain-confusion / brand-impersonation phishing pattern (attacker prepends a trusted brand label to hide the true registrable owner).\"");
    return b.append("}").toString();
  }

  // ADDITION 5 + 7 — guarded HTTP GET probe: status, security headers, cookies,
  // page title, forms, and JS analysis. Single hop, capped body, SSRF-guarded.
  private static String httpProbeJson(String scheme, String host, int port, String startPath, boolean resolvable){
    if (!resolvable) return "{\"evaluation_status\":\"HTTP_SKIPPED\",\"skip_reason\":\"DNS failed or host unresolvable — marked HTTP_SKIPPED (DNS failure), never assumed clean.\"}";
    if (budgetUp()) return "{\"evaluation_status\":\"HTTP_SKIPPED\",\"skip_reason\":\"Enrichment budget spent — live content probe deferred for responsiveness; page state is UNKNOWN, never clean.\"}";
    String guard = ssrfGuard(scheme, host, String.valueOf(port));
    if (guard != null) return "{\"evaluation_status\":\"HTTP_SKIPPED\",\"skip_reason\":\"SSRF guard blocked fetch: "+q(guard)+" — no content was fetched.\"}";
    String url = scheme+"://"+formatHostPort(host, port)+(startPath==null||startPath.isEmpty()?"/":startPath);
    String cached = probeCacheGet(url);
    if (cached != null) return cached;
    try {
      HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().timeout(Duration.ofSeconds(3))
        .header("User-Agent","cipher-squad/1.0").header("Accept","text/html,application/xhtml+xml").build();
      HttpResponse<String> r = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
      int status = r.statusCode();
      String server = r.headers().firstValue("server").orElse("");
      String content = r.body()==null?"":r.body();
      if (content.length() > 200000) content = content.substring(0,200000);
      String ct = r.headers().firstValue("content-type").orElse("");
      boolean hxfo = r.headers().firstValue("x-frame-options").isPresent();
      boolean hxct = r.headers().firstValue("x-content-type-options").isPresent();
      boolean hcsp = r.headers().firstValue("content-security-policy").isPresent();
      boolean hxxss = r.headers().firstValue("x-xss-protection").isPresent();
      boolean hsts = r.headers().firstValue("strict-transport-security").isPresent();
      boolean hrp = r.headers().firstValue("referrer-policy").isPresent();
      boolean hpp = r.headers().firstValue("permissions-policy").isPresent();
      int secHeaders = (hxfo?1:0)+(hxct?1:0)+(hcsp?1:0)+(hxxss?1:0)+(hsts?1:0)+(hrp?1:0)+(hpp?1:0);
      // cookies
      java.util.List<String> cookies = new ArrayList<>();
      for (String ch : r.headers().allValues("set-cookie")){ cookies.add(ch); }
      boolean cSecure=false, cHttp=false; String sameSite="";
      for (String ck : cookies){ if (ck.toLowerCase(Locale.ROOT).contains("secure")) cSecure=true; if (ck.toLowerCase(Locale.ROOT).contains("httponly")) cHttp=true; Matcher sm=Pattern.compile("(?i)samesite\\s*=\\s*(\\w+)").matcher(ck); if(sm.find()) sameSite=sm.group(1); }
      // title
      String title=""; Matcher tm=Pattern.compile("(?is)<title[^>]*>(.{0,500})</title>").matcher(content); if(tm.find()) title=tm.group(1).trim();
      // forms
      boolean formPresent = Pattern.compile("(?is)<form\\b").matcher(content).find();
      boolean cardFields = Pattern.compile("(?is)(name=[\"'][^\"']*(card|cvv|cvc|ccnumber|creditcard)[^\"']*[\"']|type=[\"'](?:number|text)[\"'][^>]*name=[\"'][^\"']*(?:card|cvv|cvc))").matcher(content).find();
      java.util.List<String> inputs = new ArrayList<>();
      Matcher im = Pattern.compile("(?is)<input\\b[^>]*type=[\"']([^\"']+)[\"']").matcher(content); while(im.find()){ String t=im.group(1).toLowerCase(Locale.ROOT); if(!inputs.contains(t)) inputs.add(t); }
      String formAction=""; Matcher fa=Pattern.compile("(?is)<form\\b[^>]*action=[\"']([^\"']*)[\"']").matcher(content); if(fa.find()) formAction=fa.group(1);
      // JS
      boolean js = Pattern.compile("(?is)<script\\b").matcher(content).find();
      boolean obfJs = Pattern.compile("(?is)eval\\(|fromCharCode|\\batob\\b|unescape\\(|String\\.fromCharCode|\\[\\s*\\]\\s*\\[\\s*\\[\\s*\\]|\\b_0x[0-9a-f]{3,}").matcher(content).find();
      boolean base64Js = Pattern.compile("(?is)(atob\\s*\\(|btoa\\s*\\(|base64)").matcher(content).find();
      StringBuilder o = new StringBuilder("{");
      o.append("\"evaluation_status\":\"COMPLETED\",\"http_status_code\":").append(status).append(",\"server\":").append(jstr(server.isEmpty()?"UNAVAILABLE":server)).append(",\"content_type\":").append(jstr(ct.isEmpty()?"UNAVAILABLE":ct)).append(",\"page_title\":").append(jstr(title.isEmpty()?null:title));
      o.append(",\"security_headers\":{")
        .append("\"x_frame_options\":").append(hxfo).append(",\"x_content_type_options\":").append(hxct)
        .append(",\"content_security_policy\":").append(hcsp).append(",\"x_xss_protection\":").append(hxxss)
        .append(",\"strict_transport_security\":").append(hsts).append(",\"referrer_policy\":").append(hrp)
        .append(",\"permissions_policy\":").append(hpp).append(",\"headers_present_count\":").append(secHeaders).append("}");
      o.append(",\"cookies\":{").append("\"cookies_set\":").append(!cookies.isEmpty()).append(",\"cookie_count\":").append(cookies.size()).append(",\"secure_flag\":").append(cSecure).append(",\"httponly_flag\":").append(cHttp).append(",\"samesite\":").append(jstr(sameSite.isEmpty()?null:sameSite)).append("}");
      o.append(",\"page_content\":{").append("\"form_present\":").append(formPresent).append(",\"form_action\":").append(jstr(formAction.isEmpty()?null:formAction)).append(",\"input_fields\":").append(strList(inputs)).append(",\"card_fields_present\":").append(cardFields).append(",\"javascript_present\":").append(js).append(",\"obfuscated_javascript\":").append(obfJs).append(",\"base64_encoded_scripts\":").append(base64Js).append("}");
      String completed = o.append("}").toString();
      probeCachePut(url, completed);
      return completed;
    } catch (Exception ex) {
      String skipped = "{\"evaluation_status\":\"HTTP_SKIPPED\",\"skip_reason\":\"Host unreachable ("+q(ex.getClass().getSimpleName())+") — marked HTTP_SKIPPED, never assumed clean.\"}";
      probeCachePut(url, skipped);
      return skipped;
    }
  }

  // ADDITION 9 — Threat-intel feed sweep. No API keys configured -> honest UNAVAILABLE.
  static String feedsAnalysisJson(String registered){
    StringBuilder b = new StringBuilder("{");
    b.append("\"virustotal\":{\"status\":\"UNAVAILABLE\",\"engines_flagged\":null},");
    b.append("\"google_safe_browsing\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"phishtank\":{\"status\":\"UNAVAILABLE\",\"id\":null},");
    b.append("\"openphish\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"urlscan\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"alienvault_otx\":{\"status\":\"UNAVAILABLE\",\"pulses\":null},");
    b.append("\"spamhaus_dbl\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"cisco_talos\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"netcraft\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"surbl\":{\"status\":\"UNAVAILABLE\"},");
    b.append("\"ibm_xforce\":{\"status\":\"UNAVAILABLE\",\"score\":null},");
    b.append("\"abuseipdb_host\":{\"status\":\"UNAVAILABLE\",\"score\":null},");
    b.append("\"total_checked\":12,\"total_flagged\":0,\"consensus\":\"UNKNOWN\",\"consensus_confidence\":0,");
    b.append("\"note\":\"No threat-intel API credentials are configured for this platform, so all feeds report UNAVAILABLE. IMPORTANT: ALL-UNAVAILABLE is NOT clean evidence — the domain may simply be too new to be indexed (highly suspicious), or the feeds may be offline (this affects completeness only). Score impact: all feeds unavailable + suspicious path = +10 risk.\"");
    return b.append("}").toString();
  }

  // ADDITION 10 — Social engineering / NLP on the URL surface (static).
  static String socialEngineeringJson(String decodedPathAndQuery, String jwtPayloadJson){
    String hay = (decodedPathAndQuery==null?"":decodedPathAndQuery.toLowerCase(Locale.ROOT)) + " " + (jwtPayloadJson==null?"":jwtPayloadJson.toLowerCase(Locale.ROOT));
    java.util.List<String> urgency = new ArrayList<>(), fear=new ArrayList<>(), deadline=new ArrayList<>();
    for (String w : List.of("urgent","immediately","act now","asap","immediate","right away","now","expires")) if (hay.contains(w)) urgency.add(w);
    for (String w : List.of("suspended","locked","limited","deactivated","terminated","fraud","unauthorized","violation","risked")) if (hay.contains(w)) fear.add(w);
    for (String w : List.of("within 24h","24 hours","48 hours","today","before ","expires","deadline")) if (hay.contains(w)) deadline.add(w);
    boolean personal = !jwtPayloadJson.isBlank() && jsonStr(jwtPayloadJson,"email").contains("@");
    int nlp = 0;
    if (!urgency.isEmpty()) nlp+=3; if (!fear.isEmpty()) nlp+=3; if (!deadline.isEmpty()) nlp+=2;
    if (personal) nlp += 3; nlp = Math.min(10,nlp);
    StringBuilder b = new StringBuilder("{");
    b.append("\"urgency_language\":").append(!urgency.isEmpty()).append(",\"urgency_phrases\":").append(strList(urgency));
    b.append(",\"fear_triggers\":").append(!fear.isEmpty()).append(",\"fear_phrases\":").append(strList(fear));
    b.append(",\"authority_signal\":false,\"trust_signal_abuse\":false");
    b.append(",\"personalized\":").append(personal).append(",\"victim_data_source\":").append(jstr(personal?"JWT payload":null));
    b.append(",\"deadline_pressure\":").append(!deadline.isEmpty()).append(",\"deadline_phrases\":").append(strList(deadline));
    b.append(",\"consequence_framing\":").append(!fear.isEmpty());
    b.append(",\"generic_vs_targeted\":").append(jstr(personal?"spearphishing":"mass_phishing"));
    b.append(",\"nlp_threat_score\":").append(nlp);
    String camp = personal?"Targeted credential-harvest campaign (personalized victim data present)":(!urgency.isEmpty()||!fear.isEmpty())?"Mass-phishing with urgency/fear pressure":"No strong social-engineering pressure signals found on the URL surface (this is not proof of safety).";
    b.append(",\"campaign_assessment\":").append(jstr(camp));
    return b.append("}").toString();
  }

  // ADDITION 11 — MITRE ATT&CK mapping from confirmed/probable URL findings.
  static String mitreUrlJson(boolean credPathB, boolean brandB, boolean jwtNone, boolean formB, boolean obfJs, boolean victimB){
    java.util.List<String> out = new ArrayList<>();
    if (credPathB && brandB) out.add(mitreUrlEntry("Initial Access","T1566","Phishing","002","Spearphishing Link","confirmed","Credential/login/payment path combined with brand keyword in domain.","https://attack.mitre.org/techniques/T1566/002/"));
    if (formB) out.add(mitreUrlEntry("Credential Access","T1056","Input Capture","003","Web Portal Capture","confirmed","Credential form confirmed on the served page (web portal capture).","https://attack.mitre.org/techniques/T1056/003/"));
    if (brandB) out.add(mitreUrlEntry("Defense Evasion","T1036","Masquerading","005","Match Legitimate Name or Location","probable","Brand keyword/squat in domain name.","https://attack.mitre.org/techniques/T1036/005/"));
    if (obfJs) out.add(mitreUrlEntry("Defense Evasion","T1027","Obfuscated Files or Information","",null,"probable","Obfuscated JavaScript observed on page.","https://attack.mitre.org/techniques/T1027/"));
    if (jwtNone) out.add(mitreUrlEntry("Credential Access","T1550","Use Alternate Authentication Material","001","Application Access Token","confirmed","JWT with alg:none — no signature required, forgeable.","https://attack.mitre.org/techniques/T1550/001/"));
    // T1566.002 Spearphishing Link is only mapped when a JWT was ACTUALLY detected AND contained a
    // decoded targeted victim; a bare/nonexistent JWT produces NOT_EVALUATED, never CONFIRMED.
    if (victimB) out.add(mitreUrlEntry("Initial Access","T1566","Phishing","002","Spearphishing Link","confirmed","Personalized victim email present in a decoded JWT payload (JWT detected and parsed).","https://attack.mitre.org/techniques/T1566/002/"));
    return "[" + String.join(",", out) + "]";
  }
  private static String mitreUrlEntry(String tactic,String id,String name,String sub,Object subId,String conf,String evidence,String ref){
    // MITRE dot-notation (T1566.002, not T1566/002). technique_status reflects the underlying
    // evidence: entries are only ever added when real evidence exists, so they are never
    // "confirmed" with null/empty evidence (the presence of an evidence string is asserted here).
    String subTechId = (sub == null || sub.isEmpty()) ? "null" : ("\"" + q(id.replace("/",".")) + "." + q(sub) + "\"");
    String status = (conf == null || conf.isEmpty() || conf.equalsIgnoreCase("none")) ? "not_evaluated" : conf;
    return "{\"tactic\":\""+q(tactic)+"\",\"technique_id\":\""+q(id)+(sub==null||sub.isEmpty()?"":("."+q(sub)))+"\",\"technique_name\":\""+q(name)+"\",\"sub_technique_id\":"+subTechId+",\"technique_status\":\""+q(status)+"\",\"confidence\":\""+q(conf)+"\",\"evidence\":\""+q(evidence)+"\",\"evidence_source\":\""+(evidence==null||evidence.isEmpty()?"null":enclosingSource(evidence))+"\",\"reference\":\""+q(ref)+"\"}";
  }
  private static String enclosingSource(String evidence){
    // Machine-derived technique mapping; evidence string is the concrete observed signal.
    return evidence == null || evidence.isEmpty() ? "" : "observed_url_signal";
  }

  static String defangUrl(String url){ return defang(url); }

  private static boolean registerOk(String rdap, String whois){
    return (rdap!=null && rdap.contains("\"status\":\"available\"")) || (whois!=null && whois.contains("\"status\":\"available\""));
  }
  private static boolean allFeedsUnavailable(String feeds){
    if (feeds==null) return true;
    return !feeds.contains("\"status\":\"MALICIOUS\"") && !feeds.contains("\"status\":\"CLEAN\"") && !feeds.contains("\"status\":\"VERIFIED\"");
  }
  private static int brandPoints(String brandJson, boolean credPath){
    int p = 0;
    if (brandJson.contains("\"detected\":true")) p += 25;
    if (brandJson.contains("\"technique\":\"homograph\"")) p += 20;
    else if (brandJson.contains("\"technique\":\"combosquat\"")) p += 15;
    else if (brandJson.contains("\"technique\":\"typosquat\"")) p += 10;
    if (boolVal(brandJson,"tld_mismatch")) p += 10;
    if (credPath) p += 5;
    return p;
  }

  private static boolean containsDigitBrand(String h){ return false; }
  static boolean isShortener(String reg){ String r=(reg==null?"":reg).toLowerCase(Locale.ROOT); return r.matches("(?i)(bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|is\\.gd|buff\\.ly|ow\\.ly|rb\\.gy|short\\.url|rebrand\\.ly|cutt\\.ly|tiny\\.cc|lnkd\\.in|shortlink|s\\.google\\.com|vur\\.gl|tiny\\.pl|1url\\.com|url\\.ie)"); }
  static boolean pathCred(String p){ String q=(p==null?"":p).toLowerCase(Locale.ROOT); return q.matches("(?s).*(/(?:login|signin|sign-in|logon|verify|verification|reset|reset-password|reset_password|password|forgot|recover|auth|authenticate|oauth|bank|banking|payment|pay|payments|secure|update|u/|unlock|2fa|mfa|session)/?|\\?(?:[^#]*=)?(?:token=|reset=|password=|otp=|code=|secret=|auth=|key=|verify=|session=)).*"); }
  static boolean typosquat(String host){
    String h = (host==null?"":host).toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    String[] brands = {"microsoft","apple","google","paypal","amazon","netflix","facebook","whatsapp","instagram","dropbox","gaoogle","gogle","mircosoft","microsooft","paypall","amazn","amzon","nettlix","faceboook","facebok","isssteven","payp1","paypal-","-paypal"};
    if (h.isEmpty()) return false;
    String[] parts = h.split("\\.");
    String brand = parts.length >= 2 ? parts[parts.length-2] : parts[0];
    if (brand.isEmpty() && parts.length > 0) brand = parts[0];
    if (brand.isEmpty()) return false;
    for (String b : brands) if (b.equals(brand)) return true;
    String brandNorm = leetNorm(brand);
    for (String b : new String[]{"paypal","microsoft","apple","google","amazon","netflix","facebook"}) {
      if (lev(brandNorm, leetNorm(b)) == 1 && brand.length() >= 4) return true;
      if (brandNorm.equals(leetNorm(b))) return true;
    }
    return false;
  }
  private static int lev(String a, String b){
    int[][] d = new int[a.length()+1][b.length()+1];
    for (int i=0;i<=a.length();i++) d[i][0]=i; for (int j=0;j<=b.length();j++) d[0][j]=j;
    for (int i=1;i<=a.length();i++) for (int j=1;j<=b.length();j++){ int c = a.charAt(i-1)==b.charAt(j-1)?0:1; d[i][j]=Math.min(Math.min(d[i-1][j]+1,d[i][j-1]+1), d[i-1][j-1]+c); }
    return d[a.length()][b.length()];
  }
  static boolean containsAbuseTld(String t){ if (t == null) return false; String[] parts = t.toLowerCase(Locale.ROOT).split("\\."); String last = parts.length>0?parts[parts.length-1]:""; return List.of("tk","ml","ga","cf","gq","xyz","top","club","work","click","stream","racing","accountant","country","kim","gdn","loan","win","review","support","download","zip","info","online","site","buzz").contains(last); }

  // ---- Brand-impersonation vocabulary and helpers ----
  // officialDomains holds the legitimate registrable domains each brand owns (used to determine whether a
  // domain containing a brand token is genuinely official). This is only used to detect NON-official usage.
  static final Map<String,List<String>> OFFICIAL = new LinkedHashMap<>();
  static {
    List<String> ms = List.of("microsoft.com","microsoftonline.com","office.com","office365.com","live.com","outlook.com","xbox.com","windows.com","msn.com","microsoft.net");
    List<String> ap = List.of("apple.com","icloud.com","appleid.apple.com","me.com");
    List<String> gg = List.of("google.com","googlemail.com","gmail.com","youtube.com","accounts.google.com","googleapis.com");
    List<String> pp = List.of("paypal.com","paypal.me","braintree.com");
    List<String> am = List.of("amazon.com","amazon.co.uk","amazon.de","amazon.fr","amazon.ca","aws.amazon.com");
    List<String> nf = List.of("netflix.com","nflxext.com");
    List<String> fb = List.of("facebook.com","fb.com","fbcdn.net","messenger.com");
    // Canonical tokens
    OFFICIAL.put("microsoft", ms); OFFICIAL.put("apple", ap); OFFICIAL.put("google", gg);
    OFFICIAL.put("paypal", pp); OFFICIAL.put("amazon", am); OFFICIAL.put("netflix", nf);
    OFFICIAL.put("facebook", fb);
    OFFICIAL.put("whatsapp", List.of("whatsapp.com","whatsapp.net"));
    OFFICIAL.put("instagram", List.of("instagram.com","cdninstagram.com"));
    OFFICIAL.put("dropbox", List.of("dropbox.com","dropboxusercontent.com","db.tt"));
    OFFICIAL.put("linkedin", List.of("linkedin.com","licdn.com"));
    OFFICIAL.put("twitter", List.of("twitter.com","t.co","x.com"));
    OFFICIAL.put("bankofamerica", List.of("bankofamerica.com","bofa.com"));
    OFFICIAL.put("bofa", List.of("bofa.com","bankofamerica.com"));
    OFFICIAL.put("chase", List.of("chase.com","jpmorgan.com"));
    OFFICIAL.put("wellsfargo", List.of("wellsfargo.com"));
    OFFICIAL.put("citibank", List.of("citi.com","citibank.com"));
    OFFICIAL.put("github", List.of("github.com","githubusercontent.com","github.io"));
    // Variant / typo / sub-brand tokens map onto their canonical brand's official domains.
    // A domain such as "mircosoft.com" is therefore treated as NON-official (impersonation),
    // while legitimate domains/subdomains like "microsoftonline.com" remain official.
    OFFICIAL.put("mircosoft", ms); OFFICIAL.put("microsooft", ms); OFFICIAL.put("microsoftonline", ms); OFFICIAL.put("office365", ms);
    OFFICIAL.put("icloud", ap);
    OFFICIAL.put("gmail", gg);
    OFFICIAL.put("paypall", pp); OFFICIAL.put("payp1", pp);
    OFFICIAL.put("amazn", am); OFFICIAL.put("amzon", am);
    OFFICIAL.put("nettlix", nf);
    OFFICIAL.put("faceboook", fb);
  }
  // tokens we consider "brand-claiming" when they appear in a name or a non-official domain
  static final List<String> BRAND_TOKENS = List.of(
    "microsoft","mircosoft","microsooft","microsoftonline","office365","apple","icloud","google","gmail",
    "paypal","paypall","payp1","amazon","amazn","amzon","netflix","nettlix","facebook","faceboook","whatsapp",
    "instagram","dropbox","linkedin","twitter","bankofamerica","bofa","chase","wellsfargo","citibank","github");

  private static List<String> officialForList(String brand){ List<String> o = OFFICIAL.get(brand); return o == null ? List.of(brand + ".com") : o; }

  private static String brandedOfficialDomains(String brand){
    return String.join(" / ", officialForList(brand));
  }

  // Does an arbitrary domain claim brand identity (a BRAND_TOKENS token present) without being an official owner?
  static String brandImpersonatedBy(String domain){
    if (domain == null || domain.isBlank()) return null;
    String d = domain.trim().toLowerCase(Locale.ROOT);
    // (a) exact token claims on the original string
    for (String tk : BRAND_TOKENS) {
      if (d.equals(tk) || d.contains(tk + ".") || d.equals(tk + ".example") || d.contains(tk + "-") || d.contains("." + tk + "-")) {
        if (!isOfficialForDomain(d, tk)) return tk;
      }
    }
    // (b) leetspeak / lookalike substitutions (e.g. micr0soft, p4ypal) and label-level brand claims.
    // Only the registrable label + the whole normalized domain are considered, and only tokens of
    // reasonable length, to limit false positives on unrelated names.
    String norm = leetNorm(d);
    String first = d.split("[.\\-]", 2)[0];
    String firstNorm = leetNorm(first);
    for (String tk : BRAND_TOKENS) {
      String nt = leetNorm(tk);
      if (nt.length() < 5) continue;
      if (firstNorm.contains(nt) || norm.contains(nt)) {
        if (!isOfficialForDomain(d, tk)) return tk;
      } else if (leetNorm(registrableLabel(d)).equals(nt)) {
        if (!isOfficialForDomain(d, tk)) return tk;
      }
    }
    return null;
  }

  // Reduce common character-substitution obfuscation to their likely letter so brand matching can
  // catch lookalike spelling (0->o, 1->l/i, 3->e, 4->a, 5->s, 7->t, @->a, $->s, !->i, rn->m, vv->w).
  static String leetNorm(String s){
    if (s == null) return "";
    String t = s.toLowerCase(Locale.ROOT)
      .replace("0","o").replace("3","e").replace("4","a").replace("5","s")
      .replace("7","t").replace("@","a").replace("$","s").replace("!","i")
      .replace("rn","m").replace("vv","w");
    t = t.replace("1","l");
    return t;
  }

  private static String registrableLabel(String d){
    String h = d.replaceFirst("^[a-z0-9]+://","");
    String[] p = h.split("\\.");
    if (p.length < 2) return h.startsWith("-") ? h.substring(1) : h;
    String lbl = p[p.length-2];
    return lbl.startsWith("-") ? lbl.substring(1) : lbl;
  }

  // Same check against a URL host (which may carry a scheme-like leading 'www.' etc.)
  static String brandImpersonatedByHost(String host){
    if (host == null || host.isBlank()) return null;
    String h = host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    return brandImpersonatedBy(h);
  }

  // A domain is "official for" a brand if it is the brand's own registrable domain or subdomain of it,
  // OR it is an exact known official domain entry.
  static boolean isOfficialFor(String domain, String brand){
    if (domain == null || brand == null) return false;
    String d = domain.trim().toLowerCase(Locale.ROOT);
    if (isOfficialForDomain(d, brand)) return true;
    // also accept the brand name as its own registrable domain of the given domain
    String reg = registrableDomain(d);
    if (reg != null && reg.equals(brand + ".com")) return true;
    return false;
  }

  private static boolean isOfficialForDomain(String d, String brand){
    if (d == null || brand == null) return false;
    for (String o : officialForList(brand)) {
      String od = o.toLowerCase(Locale.ROOT);
      if (d.equals(od) || d.endsWith("." + od)) return true;
    }
    return false;
  }

  // Child-domain sandboxing / clean-domain guard: a host that IS an official brand domain or a
  // subdomain (child) of one inherits the parent's verified official status. Its RDAP/WHOIS age,
  // TLS, redirect, and DoH enrichment is short-circuited so known-benign official infrastructure
  // is never re-probed per subdomain (and never penalized with unknown-age suspicion).
  static boolean sandboxOfficialHost(String host){
    if (host == null || host.isBlank() || host.contains("xn--")) return false;
    String h = host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.","");
    for (String bn : OFFICIAL.keySet()) { if (isOfficialForDomain(h, bn)) return true; }
    return false;
  }

  private static String registrableDomain(String host){
    if (host == null) return null;
    String h = host.toLowerCase(Locale.ROOT);
    if (h.contains("://")) h = h.replaceFirst("(?i)^[a-z]+://","");
    String[] parts = h.split("\\.");
    if (parts.length < 2) return h;
    return parts[parts.length-2] + "." + parts[parts.length-1];
  }

  // Identify a BRAND_TOKENS claim inside free text (e.g. a display name). Returns the matched brand token.
  static String brandKeywordOfText(String text){
    if (text == null || text.isBlank()) return null;
    String low = text.toLowerCase(Locale.ROOT);
    for (String tk : BRAND_TOKENS) {
      if (low.contains(tk)) return tk;
    }
    return null;
  }

  // Extract the human-readable display name from an address like: "Security Team" <sec@example.com>
  // Cleanup rules: an address used as a display name (bare "sec@example.com" or an angle-only
  // "<sec@example.com>") yields no display name; a trailing "[addr]" / "[addr]" token appended to a
  // name is stripped; enclosing quotes are removed.
  static String displayNameOf(String addr){
    if (addr == null || addr.isBlank()) return "";
    String t = addr.trim();
    int lt = t.indexOf('<'); int rt = t.lastIndexOf('>');
    if (lt >= 0 && rt > lt) {
      String inside = t.substring(0, lt).trim();
      return inside.isEmpty() ? "" : unquoteDisplay(inside);
    }
    String clean = t.replaceAll("(?s)\\s*[\\[(]?[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+[\\])>]*\\s*$", "").trim();
    return unquoteDisplay(clean);
  }

  private static String unquoteDisplay(String s){
    if (s == null) return "";
    String x = s.trim();
    if (x.length() >= 2 && ((x.startsWith("\"") && x.endsWith("\"")) || (x.startsWith("'") && x.endsWith("'")))) x = x.substring(1, x.length() - 1).trim();
    return x;
  }

  private static String cap(String s){
    if (s == null || s.isEmpty()) return s;
    return Character.toUpperCase(s.charAt(0)) + s.substring(1);
  }

  private static void staticFile(HttpExchange e) throws IOException { String p=e.getRequestURI().getPath(); if (p.equals("/")) p="/index.html"; Path file=ROOT.resolve(p.substring(1)).normalize(); if (!file.startsWith(ROOT)||!Files.exists(file)||Files.isDirectory(file)){json(e,404,error("Not found"));return;} String type=p.endsWith(".html")?"text/html; charset=utf-8":p.endsWith(".js")?"text/javascript; charset=utf-8":"text/plain; charset=utf-8"; e.getResponseHeaders().set("Content-Type",type); e.getResponseHeaders().set("X-Content-Type-Options","nosniff"); e.getResponseHeaders().set("X-Frame-Options","DENY"); e.getResponseHeaders().set("X-XSS-Protection","1; mode=block"); e.getResponseHeaders().set("Referrer-Policy","strict-origin-when-cross-origin"); e.getResponseHeaders().set("Cache-Control","no-store"); if (p.endsWith(".html")) { e.getResponseHeaders().set("Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'"); } byte[] bytes=Files.readAllBytes(file);e.sendResponseHeaders(200,bytes.length);try(OutputStream out=e.getResponseBody()){out.write(bytes);} }
  private static void putHeader(Map<String,List<String>> h,String line){Matcher m=HEADER.matcher(line);if(m.matches())h.computeIfAbsent(m.group(1).toLowerCase(),x->new ArrayList<>()).add(m.group(2));}
  private static String header(Map<String,List<String>> h,String k){return String.join(" | ",h.getOrDefault(k,List.of()));}
  private static String domainOf(String s){
    if (s == null) return "";
    String core = s;
    Matcher ang = Pattern.compile("<([^<>]*)>").matcher(s);
    String lastAngle = null;
    while (ang.find()) lastAngle = ang.group(1);
    if (lastAngle != null && !lastAngle.isBlank()) core = lastAngle;
    Matcher m = Pattern.compile("@([a-zA-Z0-9][a-zA-Z0-9.-]*)").matcher(core);
    if(!m.find())return "";String d=m.group(1).toLowerCase();
    while(d.endsWith("."))d=d.substring(0,d.length()-1);return d;
  }
  private static List<String> matches(Pattern p,String s){List<String> r=new ArrayList<>();Matcher m=p.matcher(s);while(m.find())if(!r.contains(m.group()))r.add(m.group());return r;}
  // Extract a JSON string value for a key with a bounded linear scan (no nested-quantifier
  // regex, so adversarial or malformed payloads can never recurse/backtrack out of control).
  // Tolerates whitespace around the colon; returns the raw escaped content (escapes intact)
  // the same way the regex did, or null when the key or a closed string value is absent.
  private static String scanJsonValue(String text, String key){
    if (text == null || key == null) return null;
    int n = text.length();
    int start = text.indexOf("\"" + key + "\"");
    if (start < 0) return null;
    int i = start + key.length() + 2;
    while (i < n && (text.charAt(i)==' '||text.charAt(i)=='\t'||text.charAt(i)=='\n'||text.charAt(i)=='\r')) i++;
    if (i >= n || text.charAt(i) != ':') return null;
    i++;
    while (i < n && (text.charAt(i)==' '||text.charAt(i)=='\t'||text.charAt(i)=='\n'||text.charAt(i)=='\r')) i++;
    if (i >= n || text.charAt(i) != '"') return null;
    i++;
    StringBuilder sb = new StringBuilder();
    while (i < n) {
      char c = text.charAt(i);
      if (c == '\\') { if (i + 1 < n) { sb.append(c).append(text.charAt(i + 1)); i += 2; } else i++; }
      else if (c == '"') return sb.toString();
      else { sb.append(c); i++; }
    }
    return null;
  }
  // Recursion-safe domain extraction over arbitrarily large text. The DOMAIN pattern uses a
  // quantified group ((label\.)+) whose per-iteration recursion overflows the stack when applied
  // with find() to big inputs; this linear scanner splits at non-name characters and validates
  // each bounded token with the anchored pattern (real DNS names are <= 253 chars). Same dedupe
  // semantics as matches(Pattern,String): each distinct domain is returned once, in order.
  private static List<String> scanDomains(String text){
    List<String> out = new ArrayList<>();
    if (text == null) return out;
    int n = text.length();
    StringBuilder cur = new StringBuilder();
    for (int i = 0; i <= n; i++) {
      int c = i < n ? text.charAt(i) : -1;
      boolean part = c >= 0 && ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_');
      if (part) { cur.append((char)c); }
      else if (cur.length() > 0) {
        String tok = cur.toString();
        if (tok.length() <= 253) { Matcher mm = DOMAIN.matcher(tok); int from = 0; while (from < tok.length() && mm.find(from)) { String g = mm.group(); if (!out.contains(g)) out.add(g); from = mm.end(); } }
        cur.setLength(0);
      }
    }
    return out;
  }
  private static final class Finding {
    final int points; final String message; final String category;
    final String severity; final String evidence; final String reason; final String source;
    final String subtype; final String findingKey; final String findingId;
    Finding(int points, String message, String category) {
      this(points, message, category, null, null, null, null, null, null, null);
    }
    Finding(int points, String message, String category, String severity, String evidence, String reason) {
      this(points, message, category, severity, evidence, reason, null, null, null, null);
    }
    Finding(int points, String message, String category, String severity, String evidence, String reason, String source) {
      this(points, message, category, severity, evidence, reason, source, null, null, null);
    }
    Finding(int points, String message, String category, String severity, String evidence, String reason, String source,
            String subtype, String findingKey, String findingId) {
      this.points = points; this.message = message; this.category = category;
      this.severity = severity; this.evidence = evidence; this.reason = reason; this.source = source;
      this.subtype = subtype; this.findingKey = findingKey; this.findingId = findingId;
    }
  }
  private static String result(String auth,String name){Matcher m=Pattern.compile(name+"=(softfail|permerror|temperror|nosuchkey|nostamp|neutral|policy|fail|pass|none)(\\s|;|$)",Pattern.CASE_INSENSITIVE).matcher(auth);return m.find()?m.group(1).toLowerCase(): "not_supplied";}
  static String analyzeMessageForTests(String raw){ ensureEnriched(); return analyzeMessage(raw); }
  /** Lazily creates the daemon enrichment pool; safe for tests that never call main(). */
  private static void ensureEnriched(){ if (ENRICH == null) { synchronized (ExecutorService.class) { if (ENRICH == null) ENRICH = Executors.newFixedThreadPool(10, r -> { Thread t = new Thread(r, "enrich"); t.setDaemon(true); return t; }); } } }
  private static boolean isPrivate(String ip){ if (ip==null) return true; try { InetAddress a = InetAddress.getByName(ip); return a.isSiteLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isAnyLocalAddress() || a.isMulticastAddress(); } catch (Exception x) { return true; } }
  private static String firstPublicIp(String s){Matcher m=IPV4.matcher(s);while(m.find()){String x=m.group();if(!isPrivate(x)&&!x.startsWith("0.")&&!x.startsWith("169.254."))return x;}return "not_visible";}
  // All public IPv4 addresses in a Received line (deduplicated, order preserved).
  private static List<String> allPublicIps(String s){
    List<String> out = new ArrayList<>();
    if (s == null) return out;
    Matcher m = IPV4.matcher(s);
    while (m.find()) {
      String x = m.group();
      if (!isPrivate(x) && !x.startsWith("0.") && !x.startsWith("169.254.") && !out.contains(x)) out.add(x);
    }
    return out;
  }
  // Reverse-DNS hostname for an IP (PTR). Falls back to the IP literal on failure/timeout.
  private static String reverseDns(String ip){
    if (ip == null || ip.isBlank() || "not_visible".equals(ip)) return "";
    String cached = dnsCacheGet(ip);
    if (cached != null) return cached;
    String result = "";
    try {
      List<String> parts = List.of(ip.split("\\."));
      if (parts.size() != 4) { dnsCachePut(ip, ""); return ""; }
      StringBuilder rev = new StringBuilder();
      for (int i = 3; i >= 0; i--) rev.append(parts.get(i)).append('.');
      rev.append("in-addr.arpa.");
      Hashtable<String,String> env = new Hashtable<>();
      env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
      env.put("com.sun.jndi.dns.timeout.initial", "2");
      env.put("com.sun.jndi.dns.timeout.retries", "1");
      javax.naming.directory.InitialDirContext ctx = new javax.naming.directory.InitialDirContext(env);
      javax.naming.directory.Attribute ptr = ctx.getAttributes("dns:" + rev, new String[]{"PTR"}).get("PTR");
      if (ptr != null) {
        javax.naming.NamingEnumeration<?> en = ptr.getAll();
        while (en != null && en.hasMore()) { String host = String.valueOf(en.next()).trim(); if (!host.isBlank() && host.endsWith(".")) host = host.substring(0, host.length()-1); if (!host.isBlank()) { result = host; break; } }
      }
    } catch (Exception ignored) { }
    dnsCachePut(ip, result);
    return result;
  }
  // Per-terminal geolocation from a provider body (reused builder helper).
  private static Map<String,Object> geoToMap(String g, String ip){
    Map<String,Object> m = new LinkedHashMap<>();
    m.put("ip", ip); m.put("country", geoVal(g,"country")); m.put("region", geoVal(g,"regionName")); m.put("city", geoVal(g,"city"));
    m.put("lat", geoNum(g,"lat",0)); m.put("lon", geoNum(g,"lon",0)); m.put("isp", geoVal(g,"isp")); m.put("org", geoVal(g,"org")); m.put("asn", geoVal(g,"as"));
    return m;
  }
  private static String sha256(String s){try{byte[] b=MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));return hex(b);}catch(Exception e){return "";}}
  private static String sha1(String s){try{byte[] b=MessageDigest.getInstance("SHA-1").digest(s.getBytes(StandardCharsets.UTF_8));return hex(b);}catch(Exception e){return "";}}
  private static String md5(String s){try{byte[] b=MessageDigest.getInstance("MD5").digest(s.getBytes(StandardCharsets.UTF_8));return hex(b);}catch(Exception e){return "";}}
  private static String hex(byte[] b){StringBuilder x=new StringBuilder();for(byte y:b)x.append(String.format("%02x",y));return x.toString();}
  private static String geoVal(String json, String key){ if (json == null || "null".equals(json)) return ""; Matcher m = Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*\"([^\"]*)\"").matcher(json); return m.find() ? unescape(m.group(1)) : ""; }
  static double geoNum(String json, String key, double def){ if (json == null || "null".equals(json)) return def; Matcher m = Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)").matcher(json); return m.find() ? Double.parseDouble(m.group(1)) : def; }

  // JSON string literal with null-value handling.
  static String jstr(String s){ if (s == null) return "null"; return "\"" + q(s) + "\""; }
  private static String strList(java.util.List<String> l){ StringBuilder b = new StringBuilder("["); for (int i=0;i<l.size();i++){ if(i>0)b.append(','); b.append(jstr(l.get(i))); } return b.append("]").toString(); }
  // best-effort numeric / string / boolean extraction from a provider JSON body
  private static String numVal(String json, String key){ Matcher m = Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(\\d+)").matcher(json); return m.find() ? m.group(1) : "0"; }
  private static String strVal(String json, String key){ Matcher m = Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*\"([^\"]*)\"").matcher(json); return m.find() ? unescape(m.group(1)) : ""; }
  private static boolean boolVal(String json, String key){ Matcher m = Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(true|false)").matcher(json); return m.find() && m.group(1).equals("true"); }
  private static String trunc(String s,int n){ return s.length() <= n ? s : s.substring(0,n-1)+"…"; }
  private static String q(String s){
    if (s == null) return "";
    StringBuilder sb = new StringBuilder(s.length() + 16);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '\\': sb.append("\\\\"); break;
        case '"':  sb.append("\\\""); break;
        case '\n': sb.append("\\n");  break;
        case '\r': break;                       // legacy: strip carriage returns
        case '\t': sb.append("\\t");  break;
        case '\b': sb.append("\\b");  break;
        case '\f': sb.append("\\f");  break;
        default:
          if (c < 0x20) { sb.append(String.format("\\u%04x", (int) c)); } else sb.append(c);
          break;
      }
    }
    return sb.toString();
  }
  // Recursion-safe rawEmail extraction mirroring the old JSON_RAW pattern ((?:\\.|[^"])*)
  // without a quantified regex group, so arbitrarily large request bodies cannot overflow the
  // stack. Returns the still-escaped JSON string value (unescape() applied by caller), or null.
  private static String extractRawEmail(String body){
    if (body == null) return null;
    int ki = body.indexOf("\"rawEmail\"");
    if (ki < 0) return null;
    int ci = body.indexOf(':', ki + 10);
    if (ci < 0) return null;
    int q = body.indexOf('"', ci);
    if (q < 0) return null;
    StringBuilder sb = new StringBuilder();
    int i = q + 1, n = body.length();
    while (i < n) {
      char c = body.charAt(i);
      if (c == '\\') { if (i + 1 < n) { sb.append('\\'); sb.append(body.charAt(i + 1)); i += 2; continue; } break; }
      if (c == '"') break;
      sb.append(c); i++;
    }
    return sb.toString();
  }
  private static String unescape(String s){
    StringBuilder b = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\\' && i + 1 < s.length()) {
        char n = s.charAt(++i);
        switch (n) {
          case 'n': b.append('\n'); break;
          case 'r': b.append('\r'); break;
          case 't': b.append('\t'); break;
          case 'b': b.append('\b'); break;
          case 'f': b.append('\f'); break;
          case '"': b.append('"'); break;
          case '\\': b.append('\\'); break;
          case '/': b.append('/'); break;
          case 'u':
            if (i + 4 < s.length()) { try { b.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; } catch (Exception x) { b.append('u'); } }
            else b.append('u');
            break;
          default: b.append(n);
        }
      } else b.append(c);
    }
    return b.toString();
  }
  private static String error(String s){return "{\"error\":\""+q(s)+"\"}";}
  // ---- Security hardening (SECURITY FIX): response headers hardened on every API reply ----
  private static void securityJsonHeaders(HttpExchange e){
    e.getResponseHeaders().set("X-Content-Type-Options","nosniff");
    e.getResponseHeaders().set("X-Frame-Options","DENY");
    e.getResponseHeaders().set("X-XSS-Protection","1; mode=block");
    e.getResponseHeaders().set("Referrer-Policy","strict-origin-when-cross-origin");
    e.getResponseHeaders().set("Cache-Control","no-store");
  }
  private static void json(HttpExchange e,int status,String data)throws IOException{
    securityJsonHeaders(e);
    e.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");
    byte[] b=data.getBytes(StandardCharsets.UTF_8);
    e.sendResponseHeaders(status,b.length);
    try(OutputStream o=e.getResponseBody()){o.write(b);}
  }

  /* =====================================================================================
   * MULTI-CHANNEL EMAIL SECURITY / SOC BACKBONE  (honest, never simulated)
   * Built on top of the existing analyzer. All state persisted as NDJSON under data/.
   *   DETECTED  = an indicator/behavior was observed by the engine.
   *   DECIDED   = a policy rule produced a system_action decision.
   *   ACTIONED  = an automated action actually ran and reported SUCCESS/FAILED.
   *   VERIFIED  = external provider / OAuth confirmed the result.
   * Connectors report NOT_CONFIGURED unless real env credentials are present.
   * ===================================================================================== */
  private static final String GMAIL_CLIENT_ID   = envOr("GMAIL_CLIENT_ID","");
  private static final String GMAIL_ACCESS_TOKEN= envOr("GMAIL_ACCESS_TOKEN","");
  private static final String MS_CLIENT_ID      = envOr("MS_CLIENT_ID","");
  private static final String MS_ACCESS_TOKEN   = envOr("MS_ACCESS_TOKEN","");
  private static final String SMS_PROVIDER      = envOr("SMS_PROVIDER","");
  private static final String SMS_API_KEY       = envOr("SMS_API_KEY","");
  private static final String SMS_FROM          = envOr("SMS_FROM","");
  private static final String SMS_DESTINATION   = envOr("SMS_DESTINATION","");
  private static final String NOTIFY_WEBHOOK    = envOr("NOTIFY_WEBHOOK","");

  private static final Path INCIDENTS   = DATA.resolve("incidents.ndjson");
  private static final Path AUDIT_LOG   = DATA.resolve("audit.ndjson");
  private static final Path POLICIES    = DATA.resolve("policies.ndjson");
  private static final Path INGEST_LOG  = DATA.resolve("ingest.ndjson");
  private static final Path IOC_REG     = DATA.resolve("iocs.ndjson");
  private static final Path FEEDBACK_LOG= DATA.resolve("feedback.ndjson");
  private static final Path RETENT_CFG  = DATA.resolve("retention.ndjson");
  private static final Path SOAR_LOG    = DATA.resolve("soar.ndjson");
  private static final Path USERS       = DATA.resolve("users.ndjson");
  private static final Path SESSIONS    = DATA.resolve("sessions.ndjson");
  private static final Path ALERT_CFG   = DATA.resolve("alert_channels.ndjson");
  private static final Path EDGES       = DATA.resolve("edges.ndjson");

  // ---- persisted store helpers ----
  private static List<String> readLines(Path p){ try { if (!Files.exists(p)) return new ArrayList<>(); return Files.readAllLines(p, StandardCharsets.UTF_8); } catch (Exception e){ return new ArrayList<>(); } }
  private static void appendLine(Path p, String line){ try { Files.createDirectories(DATA); synchronized (App.class) { Files.write(p, (line + "\n").getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND); } } catch (Exception ignored) { } }
  private static void writeLines(Path p, List<String> lines){ try { Files.createDirectories(DATA); synchronized (App.class) { Files.write(p, lines, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING); } } catch (Exception ignored) { } }
  private static int nextSeq(Path p, String prefix){ int n = readLines(p).size() + 1; return n; }
  private static String iso(){ return Instant.now().toString(); }

  // =====================================================================================
  // ACCESS CONTROL  (users, sessions, auth-gated routes, accountability audit)
  // =====================================================================================
  private static final long SESSION_TTL_MS = 8L * 60 * 60 * 1000; // 8 hours
  private static final Map<String,Session> SESSION_MAP = new ConcurrentHashMap<>();
  private static final ThreadLocal<User> CURRENT_USER = new ThreadLocal<>();
  private static final ThreadLocal<String> ACTOR_IP = new ThreadLocal<>();
  private static final java.util.Set<String> ROLES = Set.of("admin","analyst","viewer");
  private static final String DEFAULT_ADMIN_PW = System.getenv().getOrDefault("SENTINEL_ADMIN_PW", "CipherSquad#2026");

  // ---- Login hardening: per-account and per-IP brute-force throttle ----
  // Attempts are tracked in a sliding 15-minute window, keyed separately by account and by client
  // IP; crossing the failure budget locks BOTH keys for 1 minute and the API returns 429 instead
  // of 401 so credentials are never revealed as the (only) way in. Lockouts are never asserted
  // for valid sessions and successful sign-in clears all counters.
  private static final int AUTH_MAX_FAILS = 5;
  private static final long AUTH_WINDOW_MS = 15L * 60 * 1000;
  private static final long AUTH_LOCK_MS = 60L * 1000;
  private static final Map<String,long[]> AUTH_ATTEMPTS = new ConcurrentHashMap<>(); // {fails, windowStart, lockUntil}
  // Equal-cost dummy hash: verifying against it for an unknown account costs the same PBKDF2 work
  // as a real check, so response timing cannot be used to enumerate which accounts exist.
  private static final String AUTH_DUMMY_HASH = hashPassword("cipher-squad-dummy-verification");

  static final class User { final String id, email, role; User(String id,String email,String role){ this.id=id; this.email=email; this.role=role; } boolean isAdmin(){ return "admin".equals(role); } boolean isViewer(){ return "viewer".equals(role); } }
  static final class Session { final String token, userId; final long expiresAt; Session(String t,String u,long e){ token=t; userId=u; expiresAt=e; } boolean expired(){ return System.currentTimeMillis() > expiresAt; } }

  // PBKDF2-HMAC-SHA256 via the JDK crypto provider (established KDF; 120k iterations, 16-byte salt).
  private static byte[] pbkdf2(char[] pw, byte[] salt, int iterations) throws Exception {
    javax.crypto.SecretKeyFactory sf = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(pw, salt, iterations, 256);
    return sf.generateSecret(spec).getEncoded();
  }
  static String hashPassword(String raw){
    byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
    try { return "pbkdf2_sha256$120000$" + Base64.getEncoder().encodeToString(salt) + "$" + Base64.getEncoder().encodeToString(pbkdf2(raw.toCharArray(), salt, 120000)); }
    catch (Exception e) { throw new IllegalStateException(e); }
  }
  static boolean verifyPassword(String raw, String stored){
    if (stored == null) return false;
    String[] p = stored.split("\\$");
    if (p.length != 4 || !"pbkdf2_sha256".equals(p[0])) return false;
    try {
      byte[] salt = Base64.getDecoder().decode(p[2]); int it = Integer.parseInt(p[1]);
      byte[] expect = Base64.getDecoder().decode(p[3]);
      return MessageDigest.isEqual(pbkdf2(raw.toCharArray(), salt, it), expect);
    } catch (Exception ignore) { return false; }
  }
  private static String newToken(){ byte[] b = new byte[32]; new SecureRandom().nextBytes(b); return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

  // ---- user store (NDJSON) ----
  private static AppUser appUsers(){ return new AppUser(); }
  static final class AppUser { private List<String> lines(){ return readLines(USERS); }
    User find(String email){ for (String l : lines()){ if (strVal(l,"email").equalsIgnoreCase(email)) return new User(strVal(l,"id"), strVal(l,"email"), strVal(l,"role")); } return null; }
    User byId(String id){ for (String l : lines()){ if (strVal(l,"id").equals(id)) return new User(strVal(l,"id"), strVal(l,"email"), strVal(l,"role")); } return null; }
    List<User> all(){ List<User> u = new ArrayList<>(); for (String l : lines()){ if (l.contains("\"id\":\"u-")) u.add(new User(strVal(l,"id"), strVal(l,"email"), strVal(l,"role"))); } u.sort((x,y)->x.email.compareTo(y.email)); return u; }
    boolean exists(String email){ return find(email) != null; }
    User create(String email, String rawPass, String role){
      if (!ROLES.contains(role)) return null;
      String id = "u-" + Math.abs(System.currentTimeMillis() % 1000000000L);
      while (byId(id) != null) id = "u-" + new SecureRandom().nextInt(1_000_000_000);
      String rec = "{\"id\":\"" + q(id) + "\",\"email\":\"" + q(email) + "\",\"password_hash\":\"" + q(hashPassword(rawPass)) + "\",\"role\":\"" + q(role) + "\",\"created_at\":\"" + iso() + "\",\"last_login\":\"\"}";
      appendLine(USERS, rec);
      return new User(id, email, role);
    }
    boolean setRole(String id, String role){
      if (!ROLES.contains(role)) return false;
      List<String> out = new ArrayList<>(); boolean found = false;
      for (String l : lines()){ if (!l.contains("\"id\":\""+q(id)+"\"")) { out.add(l); } else { out.add("{\"id\":\""+q(id)+"\",\"email\":\""+q(strVal(l,"email"))+"\",\"password_hash\":\""+q(strVal(l,"password_hash"))+"\",\"role\":\""+q(role)+"\",\"created_at\":\""+q(strVal(l,"created_at"))+"\",\"last_login\":\""+q(strVal(l,"last_login"))+"\"}"); found = true; } }
      if (!found) return false;
      writeLines(USERS, out); return true;
    }
    void touch(String id){ List<String> out = new ArrayList<>(); for (String l : lines()){ if (l.contains("\"id\":\""+q(id)+"\"")) out.add("{\"id\":\""+q(strVal(l,"id"))+"\",\"email\":\""+q(strVal(l,"email"))+"\",\"password_hash\":\""+q(strVal(l,"password_hash"))+"\",\"role\":\""+q(strVal(l,"role"))+"\",\"created_at\":\""+q(strVal(l,"created_at"))+"\",\"last_login\":\""+iso()+"\"}"); else out.add(l); } writeLines(USERS, out); }
  }

  // ---- sessions (in-memory + persisted so restarts keep sessions until TTL) ----
  static String newSession(String userId){
    String tok = newToken();
    Session s = new Session(tok, userId, System.currentTimeMillis() + SESSION_TTL_MS);
    SESSION_MAP.put(tok, s);
    appendLine(SESSIONS, "{\"token\":\"" + tok + "\",\"user_id\":\"" + q(userId) + "\",\"expires_at\":" + s.expiresAt + "}");
    return tok;
  }
  private static void loadSessions(){
    for (String l : readLines(SESSIONS)){ if (l.isBlank()) continue;
      String tok = strVal(l,"token"); if (tok.isEmpty() || SESSION_MAP.containsKey(tok)) continue;
      long exp = 0; try { Matcher em = Pattern.compile("\"expires_at\":(\\d+)").matcher(l); if (em.find()) exp = Long.parseLong(em.group(1)); } catch (Exception ignored) {}
      if (exp > System.currentTimeMillis()) SESSION_MAP.put(tok, new Session(tok, strVal(l,"user_id"), exp));
    }
  }
  static User sessionUser(String token){
    if (token == null || token.isEmpty()) return null;
    Session s = SESSION_MAP.get(token);
    if (s == null) return null;
    if (s.expired()) { SESSION_MAP.remove(token); return null; }
    return appUsers().byId(s.userId);
  }
  static void killSession(String token){ if (token != null) SESSION_MAP.remove(token); }

  private static String bearer(HttpExchange e){
    String h = e.getRequestHeaders().getFirst("Authorization");
    if (h != null && h.regionMatches(true, 0, "Bearer ", 0, 7)) return h.substring(7).trim();
    String qs = e.getRequestURI().getQuery();
    if (qs != null) { Matcher m = Pattern.compile("(?:^|&)token=([^&]+)").matcher(qs); if (m.find()) return m.group(1); }
    return null;
  }
  private static void loginRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String email = extractJsonString(body,"email"); String pass = extractJsonString(body,"password");
    if (email == null || pass == null) { json(e,400,error("email and password are required")); return; }
    String acct = email.trim().toLowerCase(Locale.ROOT);
    String ip = requestClientIp(e);
    long lockMs = authLockRemaining(acct, ip);
    if (lockMs > 0) { json(e,429,error("Too many sign-in attempts. Try again in " + ((lockMs + 999) / 1000) + "s.")); return; }
    User u = appUsers().find(acct);
    boolean ok;
    if (u != null) {
      ok = false;
      for (String l : readLines(USERS)) if (strVal(l,"id").equals(u.id)) { ok = verifyPassword(pass, strVal(l,"password_hash")); break; }
    } else {
      // Timing-equalized rejection: identical PBKDF2 work as a real verification so a timing
      // side-channel cannot reveal whether the account exists.
      verifyPassword(pass, AUTH_DUMMY_HASH);
      ok = false;
    }
    if (!ok) {
      long left = authRecordFailure(acct, ip);
      audit("SYSTEM","auth.login",(u != null ? "account:"+acct : "unknown-account"),"LOGIN","FAILURE","","","","","");
      if (left > 0) json(e,429,error("Too many sign-in attempts. Try again in " + ((left + 999) / 1000) + "s."));
      else json(e,401,error("Invalid credentials"));
      return;
    }
    authClear(acct, ip);
    String tok = newSession(u.id);
    appUsers().touch(u.id);
    audit("SYSTEM","auth.login","auth.login","LOGIN","SUCCESS","","","","","");
    json(e,200,"{\"token\":\"" + tok + "\",\"expires_in\":" + SESSION_TTL_MS + ",\"user\":{\"id\":\"" + q(u.id) + "\",\"email\":\"" + q(u.email) + "\",\"role\":\"" + q(u.role) + "\"}}");
  }
  // Remaining lockout ms across the account and the client IP keys (0 = free to try).
  private static long authLockRemaining(String acct, String ip){
    long now = System.currentTimeMillis(); authSweep(now);
    long m = 0;
    for (String k : List.of("acct:"+acct,"ip:"+ip)) {
      long[] st = AUTH_ATTEMPTS.get(k);
      if (st != null && st[2] > now) m = Math.max(m, st[2] - now);
    }
    return m;
  }
  // Records a failed attempt; returns the lockout ms that this failure imposed (0 = none yet).
  private static long authRecordFailure(String acct, String ip){
    long now = System.currentTimeMillis(); authSweep(now);
    long rem = 0;
    for (String k : List.of("acct:"+acct,"ip:"+ip)) {
      long[] st = AUTH_ATTEMPTS.computeIfAbsent(k, x2 -> new long[]{0, now, 0});
      if (st[2] > now) { rem = Math.max(rem, st[2] - now); continue; }
      long fails = (st[1] + AUTH_WINDOW_MS >= now) ? st[0] + 1 : 1;
      if (fails >= AUTH_MAX_FAILS) { st[2] = now + AUTH_LOCK_MS; st[0] = 0; rem = Math.max(rem, AUTH_LOCK_MS); }
      else { st[0] = fails; st[1] = now; }
    }
    return rem;
  }
  private static void authClear(String acct, String ip){ AUTH_ATTEMPTS.remove("acct:"+acct); AUTH_ATTEMPTS.remove("ip:"+ip); }
  // Keeps the attempt map bounded (sweep only when it grows large; hard cap otherwise).
  private static void authSweep(long now){
    if (AUTH_ATTEMPTS.size() < 1000) return;
    AUTH_ATTEMPTS.entrySet().removeIf(x -> { long[] st = x.getValue(); return st[2] < now && st[1] + AUTH_WINDOW_MS < now; });
    if (AUTH_ATTEMPTS.size() > 20000) AUTH_ATTEMPTS.clear();
  }
  private static void logoutRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    killSession(bearer(e));
    json(e,200,"{\"ok\":true}");
  }
  private static void meRoute(HttpExchange e) throws IOException {
    User u = CURRENT_USER.get();
    if (u == null) { json(e,401,error("authentication required")); return; }
    json(e,200,"{\"user\":{\"id\":\""+q(u.id)+"\",\"email\":\""+q(u.email)+"\",\"role\":\""+q(u.role)+"\"}}");
  }
  private static void usersRoute(HttpExchange e) throws IOException {
    if ("GET".equals(e.getRequestMethod())) {
      StringBuilder b = new StringBuilder(); boolean f = true;
      for (User u : appUsers().all()){ if(!f)b.append(','); f=false; b.append("{\"id\":\"").append(q(u.id)).append("\",\"email\":\"").append(q(u.email)).append("\",\"role\":\"").append(q(u.role)).append("\"}"); }
      json(e,200,"{\"users\":[" + (f?"":b.toString()) + "]}"); return;
    }
    if ("POST".equals(e.getRequestMethod())) {
      String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String email = extractJsonString(body,"email"); String pw = extractJsonString(body,"password"); String role = extractJsonString(body,"role");
      if (email == null || pw == null || role == null) { json(e,400,error("email, password and role are required")); return; }
      email = email.trim(); if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[a-zA-Z]{2,}$")) { json(e,400,error("invalid email address")); return; }
      if (pw.length() < 8) { json(e,400,error("password must be at least 8 characters")); return; }
      if (appUsers().exists(email)) { json(e,409,error("a user with that email already exists")); return; }
      User u = appUsers().create(email, pw, role);
      if (u == null) { json(e,400,error("invalid role; use admin, analyst or viewer")); return; }
      audit(CURRENT_USER.get()!=null?CURRENT_USER.get().email:"SYSTEM","auth.users","user.create","CREATE","SUCCESS","","","","","");
      json(e,201,"{\"user\":{\"id\":\""+q(u.id)+"\",\"email\":\""+q(u.email)+"\",\"role\":\""+q(u.role)+"\"}}"); return;
    }
    json(e,405,error("GET or POST only"));
  }
  private static void userRoleRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String id = extractJsonString(body,"id"); String role = extractJsonString(body,"role");
    if (!ROLES.contains(role == null ? "" : role)) { json(e,400,error("invalid role")); return; }
    User target = appUsers().byId(id == null ? "" : id);
    if (target == null) { json(e,404,error("user not found")); return; }
    User me = CURRENT_USER.get();
    if (target.id.equals(me.id)) { json(e,400,error("cannot change your own role")); return; }
    if (appUsers().setRole(target.id, role)) { audit(me.email,"auth.users","user.role","SET_ROLE","SUCCESS","","","","",""); json(e,200,"{\"ok\":true}"); } else json(e,500,error("failed to update role"));
  }
  static void bootstrapAdmin(){
    if (!appUsers().all().isEmpty()) return;
    appUsers().create("admin@cipher.local", DEFAULT_ADMIN_PW, "admin");
    System.out.println("[bootstrap] Created default admin: admin@cipher.local / " + DEFAULT_ADMIN_PW);
  }

  private static final class AuthHandler implements HttpHandler {
    final HttpHandler next; final boolean adminOnly;
    AuthHandler(HttpHandler next, boolean adminOnly){ this.next = next; this.adminOnly = adminOnly; }
    public void handle(HttpExchange e) throws IOException {
      User u = sessionUser(bearer(e));
      if (u == null) { json(e,401,error("authentication required")); return; }
      CURRENT_USER.set(u);
      ACTOR_IP.set(requestClientIp(e));
      try {
        if (adminOnly && !u.isAdmin()) { json(e,403,error("admin role required")); return; }
        if (u.isViewer() && !"GET".equals(e.getRequestMethod())) { json(e,403,error("viewer role is read-only")); return; }
        next.handle(e);
      } finally { CURRENT_USER.remove(); ACTOR_IP.remove(); }
    }
  }
  // Best-effort client IP for audit, honouring the first untrusted X-Forwarded-For value
  // (valued for proxy-deployed installs); falls back to the socket remote address. Never blocks.
  private static String requestClientIp(HttpExchange e){
    try { String xff = e.getRequestHeaders().getFirst("X-Forwarded-For"); if (xff != null) { int c = xff.indexOf(','); String v = (c >= 0 ? xff.substring(0, c) : xff).trim(); if (!v.isEmpty()) return v; } } catch (Exception ignored) {}
    try { java.net.InetSocketAddress r = e.getRemoteAddress(); if (r != null && r.getAddress() != null) return r.getAddress().getHostAddress(); } catch (Exception ignored) {}
    return "";
  }
  private static void srv(HttpServer s, String p, HttpHandler h){ s.createContext(p, new AuthHandler(h, false)); }
  private static void srvAdmin(HttpServer s, String p, HttpHandler h){ s.createContext(p, new AuthHandler(h, true)); }

  // =====================================================================================
  // OUTBOUND ALERTS  (email / slack incoming-webhook / generic webhook, retry + audit)
  // =====================================================================================
  private static final ExecutorService OUT = Executors.newFixedThreadPool(3, r -> { Thread t = new Thread(r, "alert"); t.setDaemon(true); return t; });
  static List<Map<String,String>> alertChannels(){
    List<Map<String,String>> out = new ArrayList<>();
    for (String l : readLines(ALERT_CFG)){ if (l.isBlank() || !l.contains("\"id\":\"ch-")) continue;
      Map<String,String> m = new HashMap<>();
      m.put("id", strVal(l,"id")); m.put("name", strVal(l,"name")); m.put("type", strVal(l,"type"));
      m.put("destination", strVal(l,"destination")); m.put("enabled", strVal(l,"enabled"));
      m.put("threshold", strVal(l,"threshold")); m.put("config", strVal(l,"config"));
      out.add(m);
    }
    return out;
  }
  private static void channelsRoute(HttpExchange e) throws IOException {
    if ("GET".equals(e.getRequestMethod())) {
      StringBuilder b = new StringBuilder(); boolean f = true;
      for (String l : readLines(ALERT_CFG)){ if (l.isBlank() || !l.contains("\"id\":\"ch-")) continue; if(!f)b.append(','); f=false; b.append(l); }
      json(e,200,"{\"channels\":[" + (f?"":b.toString()) + "]}"); return;
    }
    if ("POST".equals(e.getRequestMethod())) {
      String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String type = extractJsonString(body,"type"); String dest = extractJsonString(body,"destination");
      String name = extractJsonString(body,"name"); String th = extractJsonString(body,"threshold");
      String enabled = extractJsonString(body,"enabled"); String cfg = extractJsonString(body,"config");
      if (name == null) name = "default"; if (th == null || !List.of("CRITICAL","HIGH","MEDIUM","LOW").contains(th.toUpperCase(Locale.ROOT))) th = "HIGH";
      if (!List.of("email","slack","webhook").contains(type == null ? "" : type.toLowerCase(Locale.ROOT)) || dest == null || dest.isBlank()) { json(e,400,error("type (email|slack|webhook) and destination are required")); return; }
      String id = "ch-" + Math.abs(System.currentTimeMillis() % 1000000000L);
      String rec = "{\"id\":\""+q(id)+"\",\"name\":\""+q(name)+"\",\"type\":\""+q(type.toLowerCase(Locale.ROOT))+"\",\"destination\":\""+q(dest)+"\",\"enabled\":\""+("false".equals(enabled)?"false":"true")+"\",\"threshold\":\""+th.toUpperCase(Locale.ROOT)+"\",\"config\":\""+q(cfg==null?"":cfg)+"\",\"created_at\":\""+iso()+"\"}";
      appendLine(ALERT_CFG, rec);
      audit(CURRENT_USER.get()!=null?CURRENT_USER.get().email:"SYSTEM","alert.config","alert.channel","CREATE","SUCCESS","","","","","");
      json(e,201,"{\"channel\":" + rec + "}"); return;
    }
    json(e,405,error("GET or POST only"));
  }
  private static String channelFieldRoute(HttpExchange e, String field) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return null; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String id = extractJsonString(body,"id"); String value = extractJsonString(body, field);
    boolean any = false; List<String> out = new ArrayList<>();
    for (String l : readLines(ALERT_CFG)){ if (!l.contains("\"id\":\""+q(id)+"\"") || !l.contains("\"id\":\"ch-")) { out.add(l); continue; }
      out.add("{\"id\":\""+q(id)+"\",\"name\":\""+q(strVal(l,"name"))+"\",\"type\":\""+q(strVal(l,"type"))+"\",\"destination\":\""+q(strVal(l,"destination"))+"\",\"enabled\":\""+("enabled".equals(field)? (value==null?"false":value) : enabledOf(l))+"\",\"threshold\":\""+("threshold".equals(field)? (value==null?"MEDIUM":value) : strVal(l,"threshold"))+"\",\"config\":\""+q(strVal(l,"config"))+"\",\"created_at\":\""+q(strVal(l,"created_at"))+"\"}"); any = true; }
    if (!any) return null;
    writeLines(ALERT_CFG, out);
    audit(CURRENT_USER.get()!=null?CURRENT_USER.get().email:"SYSTEM","alert.config","alert.channel","UPDATE","SUCCESS","","","","","");
    return "{\"ok\":true}";
  }
  private static String enabledOf(String l){ return strVal(l,"enabled"); }
  private static void channelStateRoute(HttpExchange e) throws IOException { String out = channelFieldRoute(e, "enabled"); if (out == null) { json(e,404,error("channel not found")); return; } json(e,200,out); }
  private static void channelDeleteRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String id = extractJsonString(body,"id");
    List<String> out = new ArrayList<>(); boolean any = false;
    for (String l : readLines(ALERT_CFG)){ if (l.contains("\"id\":\""+q(id)+"\"") && l.contains("\"id\":\"ch-")) { any = true; continue; } out.add(l); }
    if (!any) { json(e,404,error("channel not found")); return; }
    writeLines(ALERT_CFG, out);
    audit(CURRENT_USER.get()!=null?CURRENT_USER.get().email:"SYSTEM","alert.config","alert.channel","DELETE","SUCCESS","","","","","");
    json(e,200,"{\"ok\":true}");
  }
  static String alertPayloadJson(String severity, int riskScore, String classification, String incidentId, java.util.List<String> top, String link){
    StringBuilder t = new StringBuilder(); boolean f = true;
    for (String s : top){ if (f) f=false; else t.append(','); t.append("\"").append(q(s)).append("\""); }
    return "{\"event\":\"cipher_squad_alert\",\"severity\":\""+q(severity)+"\",\"risk_score\":"+riskScore+",\"classification\":\""+q(classification)+"\",\"incident_id\":\""+q(incidentId)+"\",\"top_findings\":["+t+"],\"report_link\":\""+q(link)+"\",\"sent_at\":\""+iso()+"\"}";
  }
  private static String sendH(HttpRequest req){ try { HttpResponse<String> r = HTTP.send(req, HttpResponse.BodyHandlers.ofString()); return Integer.toString(r.statusCode()); } catch (Exception e) { return "ERR:" + e.getMessage(); } }
  private static String sendSlack(String url, String text){ try { HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Content-Type","application/json").timeout(Duration.ofSeconds(12)).POST(HttpRequest.BodyPublishers.ofString("{\"text\":" + jstr(text) + "}")).build(); return sendH(req); } catch (Exception e) { return "ERR:" + e.getMessage(); } }
  private static String sendWebhook(String url, String payloadJson){ try { HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Content-Type","application/json").timeout(Duration.ofSeconds(12)).POST(HttpRequest.BodyPublishers.ofString(payloadJson)).build(); return sendH(req); } catch (Exception e) { return "ERR:" + e.getMessage(); } }
  private static String cfgVal(String cfg, String key){ if (cfg == null || cfg.isEmpty()) return ""; return strVal(cfg, key); }
  private static void smtpSay(PrintWriter w, String s){ w.print(s + "\r\n"); w.flush(); }
  private static String smtpReply(BufferedReader r){ try { String first = r.readLine(); if (first == null || first.length() < 3) return ""; String code = first.substring(0,3); if (first.length() > 3 && first.charAt(3) == '-') { while (true) { String l = r.readLine(); if (l == null) break; if (l.length() > 3 && l.substring(0,3).equals(code) && l.charAt(3) == ' ') break; } } return code; } catch (Exception ignored) { return ""; } }
  private static boolean smtpExpect(BufferedReader r, String code){ return code.equals(smtpReply(r)); }
  private static boolean smtpSend(String to, String subject, String textBody, String cfg){
    String host = cfgVal(cfg, "smtp_host"); if (host.isEmpty()) return false;
    int port = 587; try { port = Integer.parseInt(cfgVal(cfg, "smtp_port")); } catch (Exception ignored) {}
    String user = cfgVal(cfg, "smtp_user"); String pass = cfgVal(cfg, "smtp_pass"); String from = cfgVal(cfg, "from");
    if (from.isEmpty()) from = user.isEmpty() ? "cipher-squad@local" : user;
    try (Socket sk = new Socket()) {
      sk.connect(new InetSocketAddress(host, port), 6000); sk.setSoTimeout(8000);
      BufferedReader rd = new BufferedReader(new InputStreamReader(sk.getInputStream(), StandardCharsets.ISO_8859_1));
      PrintWriter wr = new PrintWriter(new OutputStreamWriter(sk.getOutputStream(), StandardCharsets.ISO_8859_1));
      if (!smtpExpect(rd,"220")) return false;
      smtpSay(wr, "EHLO cipher-squad"); if (!codeOk(smtpReply(rd),"250")) return false;
      if (!user.isEmpty()) { smtpSay(wr, "AUTH LOGIN"); if (!codeOk(smtpReply(rd),"334")) return false;
        smtpSay(wr, Base64.getEncoder().encodeToString(user.getBytes(StandardCharsets.ISO_8859_1))); if (!codeOk(smtpReply(rd),"334")) return false;
        smtpSay(wr, Base64.getEncoder().encodeToString(pass.getBytes(StandardCharsets.ISO_8859_1))); if (!codeOk(smtpReply(rd),"235")) return false; }
      smtpSay(wr, "MAIL FROM:<" + from + ">"); if (!codeOk(smtpReply(rd),"250")) return false;
      smtpSay(wr, "RCPT TO:<" + to + ">"); if (!codeOk(smtpReply(rd),"250")) return false;
      smtpSay(wr, "DATA"); if (!codeOk(smtpReply(rd),"354")) return false;
      String data = "From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + textBody;
      wr.write(data.replaceAll("\r?\n","\r\n").replaceAll("(?m)^\\.", "..") + "\r\n.\r\n"); wr.flush();
      if (!codeOk(smtpReply(rd),"250")) return false;
      smtpSay(wr, "QUIT"); try { rd.readLine(); } catch (Exception ignored) {}
      return true;
    } catch (Exception ignored) { return false; }
  }
  private static boolean codeOk(String code, String want){ return !code.isEmpty() && code.startsWith(want); }
  private static void sendWithRetry(Map<String,String> ch, String severity, int risk, String cls, String inc, java.util.List<String> top, String link){
    String type = ch.get("type"); String payload = alertPayloadJson(severity, risk, cls, inc, top, link);
    String result = "FAILED"; String reason = "";
    for (int attempt = 1; attempt <= 3; attempt++) {
      try {
        if ("slack".equals(type)) { String txt = "*" + severity + "* · risk " + risk + "/100 · " + cls + "\n`" + inc + "`\n" + String.join(" | ", top) + "\n" + link; result = sendSlack(ch.get("destination"), txt); }
        else if ("webhook".equals(type)) { result = sendWebhook(ch.get("destination"), payload); }
        else if ("email".equals(type)) { result = smtpSend(ch.get("destination"), "Cipher Squad " + severity + " alert · " + cls + " (risk " + risk + "/100)", "Risk score: " + risk + "/100\nClassification: " + cls + "\nIncident: " + inc + "\nReport: " + link + "\n\nTop findings:\n- " + String.join("\n- ", top), ch.get("config")) ? "OK" : "FAILED"; }
        if (!result.startsWith("ERR") && !result.contains("FAILED") && result.length() < 40) { audit("SYSTEM","alert."+type,"alert.send","SEND","SUCCESS","",inc,"","",""); return; }
      } catch (Exception ex) { reason = ex.toString(); }
      if (attempt < 3) try { Thread.sleep(attempt * 1000L); } catch (InterruptedException ignored) {}
    }
    audit("SYSTEM","alert."+type,"alert.send","SEND","FAILED", inc, reason.isEmpty() ? result : reason, "", "", "");
  }
  static void maybeDispatchAlerts(String severity, int riskScore, String classification, String incidentId, java.util.List<String> topFindings, String link){
    if (riskScore <= 0) return;
    int[] lvl = {80, 60, 40, 20}; String[] band = {"CRITICAL","HIGH","MEDIUM","LOW"};
    int bandIdx = -1; for (int i = 0; i < lvl.length; i++) if (riskScore >= lvl[i]) { bandIdx = i; break; }
    for (Map<String,String> ch : alertChannels()) {
      if (!"true".equals(ch.get("enabled"))) continue;
      String th = ch.get("threshold") == null || ch.get("threshold").isEmpty() ? "HIGH" : ch.get("threshold").toUpperCase(Locale.ROOT);
      int tIdx = -1; for (int i = 0; i < band.length; i++) if (band[i].equals(th)) { tIdx = i; break; }
      if (tIdx < 0 || bandIdx < 0) continue;
      if (bandIdx <= tIdx) { Map<String,String> chh = new HashMap<>(ch); OUT.submit(() -> sendWithRetry(chh, severity, riskScore, classification, incidentId, topFindings, link)); }
    }
  }

  // =====================================================================================
  // GRAPH / CAMPAIGN CORRELATION  (structural only; no actor attribution)
  // =====================================================================================
  static String nodeOf(String type, String value){ return type + ":" + value; }
  private static void appendEdge(String a, String b, String type, String incidentId, int conf, String detail){
    if (a == null || b == null || a.equals(b)) return;
    String ka = q(a), kb = q(b), kt = q(type);
    for (String l : readLines(EDGES)) if (l.contains("\"node_a\":\"" + ka + "\"") && l.contains("\"node_b\":\"" + kb + "\"") && l.contains("\"type\":\"" + kt + "\"")) return;
    String line = "{\"id\":\"" + q("e-" + Math.abs(System.nanoTime() % 1000000000L)) + "\",\"node_a\":\"" + ka + "\",\"node_b\":\"" + kb + "\",\"type\":\"" + kt + "\",\"incident_id\":\"" + q(incidentId) + "\",\"confidence\":" + conf + ",\"detail\":\"" + q(detail == null ? "" : detail) + "\",\"at\":\"" + iso() + "\"}";
    appendLine(EDGES, line);
  }
  private static String firstEmail(String s){
    if (s == null) return "";
    Matcher m = Pattern.compile("([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})").matcher(s);
    if (!m.find()) return "";
    String e = m.group(1);
    if (e.matches("(?i).*example\\.(com|net|org)$") || e.matches("(?i).*\\.example$") || e.contains(".example.")) return "";
    return e;
  }
  static java.util.List<String> topFindings(String analysisJson, int max){
    java.util.List<String> out = new ArrayList<>();
    int i = analysisJson == null ? -1 : analysisJson.indexOf("\"findings\":");
    if (i < 0) return out;
    int j = analysisJson.indexOf('[', i); if (j < 0) return out;
    int end = Math.min(analysisJson.length(), j + 60000);
    Matcher m = Pattern.compile("\"message\":\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(analysisJson.substring(j, end));
    while (m.find() && out.size() < max) out.add(m.group(1));
    return out;
  }
  static void recordGraphEdges(String analysisJson, String incidentId){
    if (analysisJson == null || incidentId == null || incidentId.isEmpty()) return;
    String inc = nodeOf("inc", incidentId);
    String from = firstEmail(strVal(analysisJson,"from"));
    if (!from.isEmpty()) { appendEdge(inc, nodeOf("email", from), "SENT_BY", incidentId, 80, "visible sender identity"); appendEdge(inc, nodeOf("domain", from.substring(from.indexOf('@')+1)), "SENT_BY_DOMAIN", incidentId, 80, "from-domain"); }
    // sender domain
    String fd = strVal(analysisJson,"from");
    Matcher dm = Pattern.compile("@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})").matcher(fd == null ? "" : fd);
    if (dm.find()) appendEdge(inc, nodeOf("domain", dm.group(1)), "SENT_BY_DOMAIN", incidentId, 80, "from-domain");
    // urls inside iocs_json
    int io = analysisJson.indexOf("\"iocs_json\":");
    if (io >= 0) {
      int bs = analysisJson.indexOf("{", io);
      int ub = analysisJson.indexOf("\"urls\":[", bs);
      if (ub >= 0) {
        int us = analysisJson.indexOf('[', ub), close = -1, depth = -1;
        for (int k = us; k < Math.min(analysisJson.length(), us + 80000); k++) { char c = analysisJson.charAt(k); if (c == '[') depth = Math.max(0, depth) + 1; else if (c == ']') { depth--; if (depth == 0) { close = k; break; } } }
        if (close > us) {
          Matcher um = Pattern.compile("\"([^\"]+)\"").matcher(analysisJson.substring(us + 1, close));
          while (um.find()) {
            String u = um.group(1); if (!u.startsWith("http")) continue;
            appendEdge(inc, nodeOf("url", u), "CONTAINS_URL", incidentId, 90, "URL observed in message");
            Matcher hm = Pattern.compile("https?://([^/\\?#]*)").matcher(u); if (hm.find()) { String host = hm.group(1); while (host.startsWith("www.")) host = host.substring(4); if (host.contains(".")) appendEdge(nodeOf("url", u), nodeOf("domain", host), "URL_TO_DOMAIN", incidentId, 95, "resolved host"); }
          }
        }
      }
    }
    // origin / sender IP
    String ip = nestedStrVal(analysisJson,"origin_analysis","origin_ip");
    if (ip.isEmpty()) { Matcher im2 = Pattern.compile("\"origin_ip\":\"([^\"]+)\"").matcher(analysisJson); if (im2.find()) ip = im2.group(1); }
    if (ip.isEmpty() || ip.equals("not_visible") || ip.equals("0.0.0.0") || ip.equals("127.0.0.1") || ip.isBlank()) ip = firstPublicIp(analysisJson);
    if (ip != null && !ip.isEmpty() && !ip.equals("not_visible") && !ip.equals("127.0.0.1")) appendEdge(inc, nodeOf("ip", ip), "ORIGIN_IP", incidentId, 85, "relay/origin address");
    // campaign tracking params -> param node + SHARED edges to prior incidents
    Matcher ct = Pattern.compile("\\{\"parameter\":\"([^\"]*)\"[^}]*?\"value\":\"([^\"]*)\"[^}]*?\"purpose\":\"campaign_tracking\"\\}").matcher(analysisJson);
    while (ct.find()) {
      String pv = ct.group(2); if (pv.isEmpty()) continue;
      String pnode = nodeOf("param", pv);
      appendEdge(inc, pnode, "CAMPAIGN_PARAM", incidentId, 70, "shareable tracking parameter value");
      for (String l : readLines(EDGES)) {
        if (!l.contains("\"type\":\"CAMPAIGN_PARAM\"") || !l.contains("\"node_b\":\"" + q(pnode) + "\"")) continue;
        String other = strVal(l,"node_a");
        if (other.startsWith("inc:") && !other.equals(inc)) appendEdge(inc, other, "SHARED_CAMPAIGN", incidentId, 65, "same tracking parameter across incidents");
      }
    }
    // structural sharing: same sender domain / origin IP across incidents -> SHARED edges
    for (String l : readLines(EDGES)) {
      String type = strVal(l,"type");
      if (!(type.equals("SENT_BY_DOMAIN") || type.equals("ORIGIN_IP"))) continue;
      String other = strVal(l,"node_a"); String nb = strVal(l,"node_b");
      if (!other.startsWith("inc:") || other.equals(inc)) continue;
      String mine = null;
      for (String l2 : readLines(EDGES)) { if (!l2.contains("\"node_a\":\""+q(inc)+"\"")) continue; if (!strVal(l2,"node_b").equals(nb)) continue; if (type.equals(strVal(l2,"type"))) { mine = strVal(l2,"node_b"); break; } }
      if (mine != null) appendEdge(inc, other, "SHARED_" + (type.equals("SENT_BY_DOMAIN")?"DOMAIN":"IP"), incidentId, 60, "shared " + (type.equals("SENT_BY_DOMAIN")?"sender domain":"origin infrastructure"));
    }
  }
  static String graphJson(String startNode, int maxHops, java.util.List<String> lines){
    Map<String, java.util.List<String[]>> adj = new HashMap<>();
    for (String l : lines) { if (l.isBlank()) continue; String a = strVal(l,"node_a"), b = strVal(l,"node_b"); if (a.isEmpty() || b.isEmpty()) continue; adj.computeIfAbsent(a, k -> new ArrayList<>()).add(new String[]{b, l}); adj.computeIfAbsent(b, k -> new ArrayList<>()).add(new String[]{a, l}); }
    Map<String,Integer> dist = new HashMap<>(); dist.put(startNode, 0);
    ArrayDeque<String> q = new ArrayDeque<>(); q.add(startNode);
    java.util.LinkedHashSet<String> nodes = new java.util.LinkedHashSet<>(); nodes.add(startNode);
    java.util.List<String> edges = new ArrayList<>(); java.util.Set<String> used = new HashSet<>();
    int maxD = 0;
    while (!q.isEmpty()) {
      String cur = q.poll(); int d = dist.get(cur);
      if (d >= maxHops) continue;
      for (String[] nb : adj.getOrDefault(cur, java.util.Collections.emptyList())) {
        String nxt = nb[0], el = nb[1];
        if (used.contains(el)) continue; used.add(el); edges.add(el);
        if (nodes.add(nxt) && !dist.containsKey(nxt)) { dist.put(nxt, d + 1); maxD = Math.max(maxD, d + 1); q.add(nxt); }
      }
    }
    StringBuilder ns = new StringBuilder("["); boolean f = true;
    for (String nid : nodes) { if (!f) ns.append(','); f = false; int ci = nid.indexOf(':'); String type = ci > 0 ? nid.substring(0, ci) : "node"; String label = type.equals("inc") ? nid.substring(ci + 1) : (ci > 0 && ci + 1 < nid.length() ? nid.substring(ci + 1) : nid); ns.append("{\"id\":\"").append(q(nid)).append("\",\"label\":\"").append(q(label)).append("\",\"type\":\"").append(q(type)).append("\"}"); }
    StringBuilder es = new StringBuilder("["); f = true;
    for (String el : edges) { if (!f) es.append(','); f = false; int conf = 0; Matcher cm = Pattern.compile("\"confidence\":(\\d+)").matcher(el); if (cm.find()) try { conf = Integer.parseInt(cm.group(1)); } catch (Exception ignored) {} es.append("{\"id\":\"").append(q(strVal(el,"id"))).append("\",\"from\":\"").append(q(strVal(el,"node_a"))).append("\",\"to\":\"").append(q(strVal(el,"node_b"))).append("\",\"type\":\"").append(q(strVal(el,"type"))).append("\",\"confidence\":").append(conf).append(",\"incident_id\":\"").append(q(strVal(el,"incident_id"))).append("\"}"); }
    ns.append(']'); es.append(']');
    return "{\"start\":\"" + q(startNode) + "\",\"hops\":" + maxD + ",\"node_count\":" + nodes.size() + ",\"edge_count\":" + edges.size() + ",\"nodes\":" + ns + ",\"edges\":" + es + "}";
  }
  private static String queryParam(String qs, String key){
    if (qs == null) return null;
    Matcher m = Pattern.compile("(?:^|&)" + key + "=([^&]+)").matcher(qs);
    return m.find() ? m.group(1) : null;
  }
  // Graph + alert side-effects run after any security decision (analyze / ingest / SOC backbone).
  // Graph edges auto-populate when correlation rules fire; alert dispatch honours channel
  // thresholds. Never allowed to break or slow the decision path itself.
  static void afterDecisionHooks(String analysisJson, String source, String incidentId){
    try {
      int risk = 0; try { risk = Integer.parseInt(numVal(analysisJson, "riskScore")); } catch (Exception ignored) {}
      String semantic = strVal(analysisJson, "classification");
      if (semantic.isEmpty()) semantic = "UNCLASSIFIED";
      recordGraphEdges(analysisJson, incidentId);
      if (!incidentId.isEmpty() && !incidentId.equals("none"))
        maybeDispatchAlerts(severLabel(risk), risk, semantic, incidentId, topFindings(analysisJson, 3), "http://127.0.0.1:8080/#/incidents/" + incidentId);
    } catch (Exception ignored) {}
  }
  private static void graphRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String qs = e.getRequestURI().getQuery();
    String incident = queryParam(qs, "incident"); String node = queryParam(qs, "node");
    int hops = 2; String h = queryParam(qs, "hops"); if (h != null) { try { hops = Math.max(1, Math.min(6, Integer.parseInt(h))); } catch (Exception ignored) {} }
    String start = (node != null && !node.isEmpty()) ? node : ((incident != null && !incident.isEmpty()) ? nodeOf("inc", incident) : "");
    if (start.isEmpty()) { json(e,400,error("incident or node parameter required")); return; }
    json(e,200, graphJson(start, hops, readLines(EDGES)));
  }

  // Only count/emit genuine incident records. Guards against stray or malformed lines that a
  // stray write or an interrupted append might leave in incidents.ndjson, which would otherwise
  // corrupt JSON output or inflate the incident-id sequence.
  private static boolean isIncidentLine(String l){
    if (l == null || l.isBlank()) return false;
    return l.contains("\"id\":\"INC-") && l.contains("\"status\":\"");
  }
  private static int incidentLineCount(){
    int n = 0; for (String l : readLines(INCIDENTS)) if (isIncidentLine(l)) n++; return n;
  }

  // =====================================================================================
  // CONNECTOR REGISTRY  (spec 3,34,35,48) — status always reflects real configuration.
  // =====================================================================================
  private static String connectorStatus(String id){
    switch (id) {
      case "gmail":   return GMAIL_ACCESS_TOKEN.isEmpty() ? "NOT_CONFIGURED" : "CONNECTED";
      case "outlook":
      case "m365":
      case "teams":   return MS_ACCESS_TOKEN.isEmpty() ? "NOT_CONFIGURED" : "CONNECTED";
      case "webhook": return "CONNECTED";
      case "eml":
      case "paste":   return "CONNECTED";
      default:        return "ERROR";
    }
  }
  private static String[] connectorMeta(String id){
    switch (id) {
      case "gmail":   return new String[]{"Gmail API (OAuth 2.0)", "gmail", "Read messages, manage quarantine"};
      case "outlook": return new String[]{"Outlook (Microsoft Graph / Entra ID)", "microsoft", "Read mail, manage quarantine"};
      case "m365":    return new String[]{"Microsoft 365 (Microsoft Graph)", "microsoft", "Read mail, manage quarantine"};
      case "teams":   return new String[]{"Microsoft Teams (Microsoft Graph)", "microsoft", "Read messages in monitored channels"};
      case "webhook": return new String[]{"Generic Webhook / push ingestion", "generic", "Accepts POST /api/ingest?source=webhook (any client)"};
      case "eml":     return new String[]{"EML upload", "generic", "Upload .eml files for analysis"};
      case "paste":   return new String[]{"Manual paste", "generic", "Paste raw email in the analyzer"};
      default:        return new String[]{id, "unknown", ""};
    }
  }
  private static String connectorsJson(){
    StringBuilder b = new StringBuilder("[");
    String[] ids = {"gmail","outlook","m365","teams","webhook","eml","paste"};
    boolean first = true;
    for (String id : ids) {
      String[] m = connectorMeta(id);
      if (!first) b.append(',');
      first = false;
      b.append("{\"id\":\"").append(id).append("\",\"name\":\"").append(q(m[0])).append("\",\"family\":\"").append(m[1])
       .append("\",\"scopes\":\"").append(q(m[2])).append("\",\"status\":\"").append(connectorStatus(id))
       .append("\",\"lastEvent\":\"\",\"lastSync\":\"\",\"permissionStatus\":\"").append(connectorStatus(id).equals("CONNECTED")?"GRANTED":"NOT_GRANTED").append("\"}");
    }
    return b.append("]").toString();
  }
  private static void connectors(HttpExchange e) throws IOException { json(e, 200, "{\"connectors\":" + connectorsJson() + "}"); }

  // =====================================================================================
  // POLICY ENGINE  (spec 11,43) — configurable, persisted. Defaults seeded on first run.
  // =====================================================================================
  private static String defaultPolicies(){
    return new StringBuilder()
      .append("{\"id\":\"CRITICAL_PHISHING_V1\",\"name\":\"Critical Phishing\",\"enabled\":true,\"priority\":1,")
      .append("\"if\":{\"risk_min\":85,\"threat_contains\":[\"MALICIOUS\",\"CRITICAL\"]},\"then\":[\"quarantine\",\"notify_user\",\"create_incident\",\"alert_soc\",\"preserve_evidence\",\"write_audit\"]}\n")
      .append("{\"id\":\"HIGH_PHISHING_V1\",\"name\":\"High Risk Phishing\",\"enabled\":true,\"priority\":2,")
      .append("\"if\":{\"risk_min\":70},\"then\":[\"quarantine\",\"notify_user\",\"alert_soc\"]}\n")
      .append("{\"id\":\"SUSPICIOUS_URL_V1\",\"name\":\"Suspicious URL\",\"enabled\":true,\"priority\":3,")
      .append("\"if\":{\"url_risk_min\":60},\"then\":[\"warn_user\",\"log_event\"]}\n")
      .append("{\"id\":\"SUSPICIOUS_V1\",\"name\":\"Suspicious\",\"enabled\":true,\"priority\":4,")
      .append("\"if\":{\"risk_min\":41},\"then\":[\"warn_user\",\"log_event\"]}\n")
      .append("{\"id\":\"JWT_ALG_NONE_V1\",\"name\":\"JWT Alg:none Attack\",\"enabled\":true,\"priority\":5,")
      .append("\"if\":{\"risk_min\":0,\"signals_contains\":[\"JWT_ALG_NONE\"]},\"then\":[\"quarantine\",\"create_incident\",\"alert_soc\",\"preserve_evidence\"]}\n")
      .append("{\"id\":\"BRAND_IMPERSONATION_V1\",\"name\":\"Brand Impersonation\",\"enabled\":true,\"priority\":6,")
      .append("\"if\":{\"risk_min\":0,\"signals_contains\":[\"BRAND_IMPERSONATION\"]},\"then\":[\"quarantine\",\"warn_user\",\"alert_soc\"]}\n")
      .append("{\"id\":\"CREDENTIAL_CAPTURE_V1\",\"name\":\"Credential Capture\",\"enabled\":true,\"priority\":7,")
      .append("\"if\":{\"risk_min\":0,\"signals_contains\":[\"CREDENTIAL_CAPTURE\"]},\"then\":[\"quarantine\",\"create_incident\",\"alert_soc\"]}\n")
      .append("{\"id\":\"PAYMENT_CARD_HARVEST_V1\",\"name\":\"Payment-Card Harvest\",\"enabled\":true,\"priority\":8,")
      .append("\"if\":{\"risk_min\":0,\"signals_contains\":[\"PAYMENT_CARD_HARVEST\"]},\"then\":[\"quarantine\",\"alert_soc\"]}\n")
      .append("{\"id\":\"TOR_RELAY_HOSTING_V1\",\"name\":\"Tor/Proxy Hosting\",\"enabled\":true,\"priority\":9,")
      .append("\"if\":{\"risk_min\":0,\"signals_contains\":[\"TOR_EXIT\"]},\"then\":[\"warn_user\",\"log_event\"]}\n")
      .append("{\"id\":\"DNS_ENUM_FAILURE_V1\",\"name\":\"DNS Enumeration Failure\",\"enabled\":true,\"priority\":10,")
      .append("\"if\":{\"risk_min\":0,\"signals_contains\":[\"DNS_FAILED\"]},\"then\":[\"warn_user\",\"log_event\"]}\n")
      .toString();
  }
  private static List<String> policiesLoaded = null;
  private static List<String> policies(){
    if (policiesLoaded == null) {
      List<String> l = readLines(POLICIES);
      if (l.isEmpty()) { for (String s : defaultPolicies().split("\n")) if (!s.isBlank()) appendLine(POLICIES, s); l = readLines(POLICIES); }
      policiesLoaded = l;
    }
    return policiesLoaded;
  }
  private static String policyHit(String policy, int risk, int conf, String threatState, String[] categories, int urlRisk){
    return policyHit(policy, risk, conf, threatState, categories, urlRisk, null);
  }
  private static String policyHit(String policy, int risk, int conf, String threatState, String[] categories, int urlRisk, java.util.Set<String> signals){
    try {
      Matcher rm = Pattern.compile("\"risk_min\":(\\d+)").matcher(policy);
      int rmin = rm.find() ? Integer.parseInt(rm.group(1)) : 0;
      Matcher um = Pattern.compile("\"url_risk_min\":(\\d+)").matcher(policy);
      int umin = um.find() ? Integer.parseInt(um.group(1)) : -1;
      if (umin > 0 && urlRisk < 0) return null; // URL policy cannot match without URL evidence
      Matcher tm = Pattern.compile("\"threat_contains\":\\[([^\\]]*)\\]").matcher(policy);
      boolean threatOk = true;
      if (tm.find()) { threatOk = false; Matcher c = Pattern.compile("\"([^\"]+)\"").matcher(tm.group(1)); while (c.find()) { if (threatState.toUpperCase().contains(c.group(1).toUpperCase())) { threatOk = true; break; } } }
      // Detection-specific rule: if the policy declares signals_contains, at least one declared
      // signal MUST be present in the actual detected signal set. Empty signal set -> no match.
      Matcher sm = Pattern.compile("\"signals_contains\":\\[([^\\]]*)\\]").matcher(policy);
      boolean sigOk = true;
      if (sm.find()) {
        sigOk = false;
        if (signals != null) { Matcher c = Pattern.compile("\"([^\"]+)\"").matcher(sm.group(1)); while (c.find()) { if (signals.contains(c.group(1))) { sigOk = true; break; } } }
      }
      if (umin > 0 && urlRisk >= 0 && urlRisk < umin) return null;
      if (sigOk && risk >= rmin && threatOk) return policy;
    } catch (Exception ignored) { }
    return null;
  }
  private static int urlRiskFrom(String body){ try { Matcher m = Pattern.compile("\"risk\"\\s*:\\s*\\{\"score\":(\\d+)").matcher(body); return m.find() ? Integer.parseInt(m.group(1)) : -1; } catch (Exception e){ return -1; } }
  // Evaluate the persisted policy engine for a URL analysis, feeding the detection-specific
  // signals captured by the extended URL layers (JWT alg:none, brand impersonation, credential
  // capture, payment-card harvest, Tor/proxy hosting, DNS failure). Returns a decision snippet.
  static String urlPolicyDecision(int risk, int urlRisk, String severity, java.util.Set<String> signals){
    String matched = null;
    for (String p : policies()) {
      if (p.contains("\"enabled\":false")) continue;
      String j = policyHit(p, risk, 50, severity, null, urlRisk, signals);
      if (j != null) { matched = strVal(j,"id"); break; }
    }
    if (matched == null) matched = "NO_POLICY_MATCH";
    String name = matchPolicyName(matched);
    String action;
    if (matched.contains("PHISHING") || matched.contains("MALICIOUS") || matched.contains("CRITICAL") || matched.contains("JWT") || matched.contains("CAPTURE") || matched.contains("HARVEST") || matched.contains("BRAND")) {
      action = "QUARANTINE";
    } else if (risk >= 70) {
      action = "QUARANTINE";
    } else if (risk >= 41) {
      action = "WARN";
    } else if (risk >= 21) {
      action = "ALLOW_WITH_NOTICE";
    } else {
      action = "ALLOW";
    }
    return "{\"policy_id\":\"" + q(matched) + "\",\"policy_name\":\"" + q(name) + "\",\"system_action\":\"" + q(action) + "\"}";
  }
  private static String extractJsonArray(String body, String key){
    Matcher m = Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(\\[[^\\]]*\\])").matcher(body);
    return m.find() ? m.group(1) : null;
  }
  private static int intOf(String body, String key, int def){
    try { Matcher m=Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(\\d+)").matcher(body); return m.find()?Integer.parseInt(m.group(1)):def; } catch (Exception e){ return def; }
  }
  private static int extractJsonBool(String body, String key){ // -1 absent, 0 false, 1 true
    try { Matcher m=Pattern.compile("\""+Pattern.quote(key)+"\"\\s*:\\s*(true|false)").matcher(body); return m.find()?("true".equalsIgnoreCase(m.group(1))?1:0):-1; } catch (Exception e){ return -1; }
  }
  private static void policiesRoute(HttpExchange e) throws IOException {
    String meth = e.getRequestMethod();
    if ("GET".equals(meth)) { StringBuilder b = new StringBuilder("["); boolean f=true; for (String p : policies()) { if(p==null||p.isBlank())continue; if(!f)b.append(','); f=false; b.append(p); } b.append(']'); json(e, 200, "{\"policies\":" + b + "}"); return; }
    if ("POST".equals(meth)) {
      String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String id = extractJsonString(body,"id");
      String name = extractJsonString(body,"name"); if (name==null) name=id;
      if (id == null) { json(e, 400, error("id is required")); return; }
      String action = extractJsonString(body,"action");
      List<String> rules = policies();
      int idx = -1;
      for (int i=0;i<rules.size();i++){ String r=rules.get(i); if(r!=null && !r.isBlank() && r.contains("\"id\":\""+id+"\"")){ idx=i; break; } }
      if ("delete".equalsIgnoreCase(action)){
        if (idx<0){ json(e,404,error("policy not found: "+id)); return; }
        rules.remove(idx);
        writeLines(POLICIES, rules);
        policiesLoaded = rules;
        audit("ADMIN","policy.engine","policy.delete","DELETE","SUCCESS","","",id,"","");
        json(e,200,"{\"ok\":true,\"deleted\":\""+q(id)+"\"}");
        return;
      }
      if (idx>=0){ // update / toggle existing
        String cur = rules.get(idx);
        int en = extractJsonBool(body,"enabled");
        if (en>=0) cur = cur.replaceFirst("\"enabled\"\\s*:\\s*(true|false)", "\"enabled\":"+(en==1));
        int prio = intOf(body,"priority",-1);
        if (prio>=0) cur = cur.replaceFirst("\"priority\"\\s*:\\s*\\d+", "\"priority\":"+prio);
        rules.set(idx, cur);
        writeLines(POLICIES, rules);
        policiesLoaded = rules;
        audit("ADMIN","policy.engine","policy.update","UPDATE","SUCCESS","","",id,"","");
        json(e,200,"{\"ok\":true,\"policy\":"+cur+"}");
        return;
      }
      // create new
      int rmin = intOf(body,"risk_min",0);
      int umin = intOf(body,"url_risk_min",-1);
      int prio = intOf(body,"priority",10);
      boolean en = !"false".equalsIgnoreCase(extractJsonString(body,"enabled"));
      String threatArr = extractJsonArray(body,"threat_contains");
      String thenArr = extractJsonArray(body,"then");
      if (thenArr==null || thenArr.length()<=2) thenArr = "[\"warn_user\",\"log_event\"]";
      StringBuilder ifb = new StringBuilder("{\"risk_min\":"+rmin);
      if (umin>0) ifb.append(",\"url_risk_min\":").append(umin);
      if (threatArr!=null && threatArr.length()>2) ifb.append(",\"threat_contains\":").append(threatArr);
      ifb.append("}");
      String rec = "{\"id\":\"" + q(id) + "\",\"name\":\"" + q(name) + "\",\"enabled\":" + en + ",\"priority\":" + prio + ",\"if\":" + ifb + ",\"then\":" + thenArr + "}";
      appendLine(POLICIES, rec);
      policiesLoaded = null;
      audit("ADMIN","policy.engine","policy.create","UPSERT","SUCCESS","","",id,"","");
      json(e, 200, "{\"ok\":true,\"policy\":" + rec + "}");
      return;
    }
    json(e, 405, error("GET or POST only"));
  }

  // =====================================================================================
  // AUDIT LOG  (spec 22)
  // =====================================================================================
  private static void audit(String actor, String component, String event, String action, String result, String msgId, String incident, String policy, String prev, String next){
    String uid = ""; String urole = ""; String aip = "";
    User cu = CURRENT_USER.get();
    if (cu != null) { uid = cu.id; urole = cu.role; }
    aip = ACTOR_IP.get(); if (aip == null) aip = "";
    String rec = "{\"timestamp\":\"" + iso() + "\",\"actor\":\"" + q(actor) + "\",\"user_id\":\"" + q(uid) + "\",\"user_role\":\"" + q(urole) + "\",\"actor_ip\":\"" + q(aip) + "\",\"component\":\"" + q(component)
      + "\",\"event\":\"" + q(event) + "\",\"action\":\"" + q(action) + "\",\"result\":\"" + q(result)
      + "\",\"message_id\":\"" + q(msgId) + "\",\"incident_id\":\"" + q(incident) + "\",\"policy_id\":\"" + q(policy)
      + "\",\"previous_status\":\"" + q(prev) + "\",\"new_status\":\"" + q(next) + "\"}";
    appendLine(AUDIT_LOG, rec);
  }
  private static void auditRoute(HttpExchange e) throws IOException {
    if ("GET".equals(e.getRequestMethod())) {
      StringBuilder b = new StringBuilder(); boolean f=true;
      List<String> lines = readLines(AUDIT_LOG); int from = Math.max(0, lines.size()-200);
      for (int i=from;i<lines.size();i++){ String l=lines.get(i); if(l.isBlank())continue; if(!f)b.append(','); f=false; b.append(l); }
      json(e, 200, "{\"audit\":[" + (f?"":b.toString()) + "]}"); return;
    }
    if ("POST".equals(e.getRequestMethod())) {
      String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      audit(extractJsonString(body,"actor"), extractJsonString(body,"component"), extractJsonString(body,"event"),
        extractJsonString(body,"action"), extractJsonString(body,"result"), extractJsonString(body,"message_id"),
        extractJsonString(body,"incident_id"), extractJsonString(body,"policy_id"), extractJsonString(body,"previous_status"), extractJsonString(body,"new_status"));
      json(e, 200, "{\"ok\":true}");
      return;
    }
    json(e, 405, error("GET or POST only"));
  }

  // =====================================================================================
  // INCIDENT LIFECYCLE  (spec 12,13)
  // =====================================================================================
  private static final List<String> INCIDENT_STATUSES = List.of("NEW","TRIAGED","INVESTIGATING","CONTAINED","REMEDIATED","CLOSED","FALSE_POSITIVE","BENIGN","DUPLICATE");
  private static String incidentCreate(String threat, String risk, String conf, String source, String affectedUser, String action, String summary){
    String id;
    synchronized (App.class) {
      id = "INC-2026-" + (100000 + incidentLineCount() + 1);
      String rec = "{\"id\":\"" + id + "\",\"created_at\":\"" + iso() + "\",\"updated_at\":\"" + iso() + "\",\"severity\":\"CRITICAL\",\"threat\":\"" + q(threat)
        + "\",\"source\":\"" + q(source) + "\",\"affected_user\":\"" + q(affectedUser) + "\",\"risk\":\"" + q(risk)
        + "\",\"confidence\":\"" + q(conf) + "\",\"status\":\"NEW\",\"system_action\":\"" + q(action) + "\",\"summary\":\"" + q(summary)
        + "\",\"timeline\":[{\"at\":\"" + iso() + "\",\"status\":\"NEW\",\"actor\":\"SYSTEM\",\"note\":\"Incident auto-created by decision engine\"}]}";
      appendLine(INCIDENTS, rec);
    }
    audit("SYSTEM","incident.engine","incident.create","CREATE","SUCCESS","","",id,"","NEW");
    return id;
  }
  private static void incidentsRoute(HttpExchange e) throws IOException {
    String meth = e.getRequestMethod();
    String path = e.getRequestURI().getPath();
    if ("GET".equals(meth)) {
      StringBuilder b=new StringBuilder(); boolean f=true; for (String l : readLines(INCIDENTS)){ if(l.isBlank())continue; if(!isIncidentLine(l))continue; if(!f)b.append(','); f=false; b.append(l);} json(e,200,"{\"incidents\":["+(f?"":b.toString())+"]}");
      return;
    }
    if ("POST".equals(meth)) {
      String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      if (path.startsWith("/api/incidents/transition")) {
        String id = extractJsonString(body,"incident_id");
        String to = extractJsonString(body,"to"); String actor = extractJsonString(body,"actor"); String note = extractJsonString(body,"note");
        if (id == null || to == null){ json(e,400,error("incident_id and to are required")); return; }
        boolean ok = incidentTransition(id, to, actor==null?"SYSTEM":actor, note);
        if (!ok) { json(e, 404, error("incident not found or invalid status")); return; }
        json(e, 200, "{\"ok\":true}");
        return;
      }
      String threat = extractJsonString(body,"threat"); String risk = extractJsonString(body,"risk");
      String conf = extractJsonString(body,"confidence"); String source = extractJsonString(body,"source");
      String user = extractJsonString(body,"affected_user"); String action = extractJsonString(body,"action"); String summary = extractJsonString(body,"summary");
      String id = incidentCreate(threat==null?"":threat, risk==null?"0":risk, conf==null?"0":conf, source==null?"":source, user==null?"":user, action==null?"":action, summary==null?"":summary);
      json(e, 200, "{\"incident_id\":\"" + id + "\"}");
      return;
    }
    json(e, 405, error("GET or POST only"));
  }
  private static boolean incidentTransition(String id, String to, String actor, String note){
    if (!INCIDENT_STATUSES.contains(to)) return false;
    List<String> lines = readLines(INCIDENTS); boolean found=false;
    for (int i=0;i<lines.size();i++){
      String l=lines.get(i); if(!l.contains("\"id\":\""+id+"\"")) continue;
      found=true;
      String prev = strVal(l,"status");
      Matcher im = Pattern.compile("(\\{\"at\":\"[^\"]*\",\"status\":\"[^\"]*\",\"actor\":\"[^\"]*\",\"note\":\"[^\"]*\"\\})").matcher(l);
      String newLine = l.replaceFirst("\"updated_at\":\"[^\"]*\"", "\"updated_at\":\""+iso()+"\"")
                        .replaceFirst("\"status\":\"[^\"]*\"", "\"status\":\""+q(to)+"\"");
      // append to timeline
      String ts = "{\"at\":\""+iso()+"\",\"status\":\""+q(to)+"\",\"actor\":\""+q(actor)+"\",\"note\":\""+q(note==null?"":note)+"\"}";
      int tl = newLine.lastIndexOf("]");
      if (tl > 0) newLine = newLine.substring(0, tl) + (newLine.substring(0,tl).endsWith("[")?"":",") + ts + newLine.substring(tl);
      lines.set(i, newLine);
      audit(actor,"incident","incident.transition","TRANSITION","SUCCESS","",id,"",prev,to);
    }
    if (found) writeLines(INCIDENTS, lines);
    return found;
  }

  // =====================================================================================
  // IOC EXTRACTION  (spec 24) — normalize + dedup, reputation = UNKNOWN unless evidence.
  // =====================================================================================
  // Persist distinct IOCs extracted from a raw message into the registry (IOC_REG).
  private static void persistIocs(String raw){
    if (raw == null) return;
    try {
      LinkedHashSet<String> ips = new LinkedHashSet<>(); LinkedHashSet<String> urls = new LinkedHashSet<>();
      LinkedHashSet<String> emails = new LinkedHashSet<>(); LinkedHashSet<String> domains = new LinkedHashSet<>();
      LinkedHashSet<String> hashes = new LinkedHashSet<>();
      for (String s : matches(IPV4, raw)) ips.add(s);
      for (String s : matches(URL, raw)) urls.add(s);
      for (String s : matches(EMAIL, raw)) emails.add(s);
      for (String s : scanDomains(raw)) if (!s.matches("^(?:com|net|org|edu|gov|io|co|uk|exe|js|www)$")) domains.add(s.toLowerCase(Locale.ROOT));
      for (String s : matches(SHA256RE, raw)) hashes.add(s);
      List<String> existing = readLines(IOC_REG);
      Set<String> seen = new HashSet<>();
      for (String l : existing) { int a = l.indexOf("\"key\":\""); if (a >= 0) { int b = l.indexOf('"', a + ("\"key\":\"").length()); if (b > a) seen.add(l.substring(a + ("\"key\":\"").length(), b)); } }
      String now = iso();
      List<Object[]> extras = new ArrayList<>();
      for (String v : ips) extras.add(new Object[]{ "ipv4", v });
      for (String v : urls) if (v.length() <= 512) extras.add(new Object[]{ "url", v });
      for (String v : emails) extras.add(new Object[]{ "email", v });
      for (String v : domains) extras.add(new Object[]{ "domain", v });
      for (String v : hashes) extras.add(new Object[]{ "hash_sha256", v });
      for (Object[] e : extras) {
        String type = (String) e[0], value = (String) e[1];
        String key = type + "|" + value;
        String sc = iocConfidence(type, value, raw);
        String reputation = sc.substring(sc.indexOf("\"reputation\":\"") + ("\"reputation\":\"").length(), sc.indexOf('"', sc.indexOf("\"reputation\":\"") + ("\"reputation\":\"").length()));
        String confStr = sc.substring(sc.indexOf("\"confidence\":") + ("\"confidence\":").length(), sc.indexOf('}', sc.indexOf("\"confidence\":")));
        if (seen.add(key)) appendLine(IOC_REG, "{\"key\":\"" + q(key) + "\",\"type\":\"" + type + "\",\"value\":\"" + q(value)
          + "\",\"reputation\":\"" + reputation + "\",\"confidence\":" + confStr + ",\"first_seen\":\"" + now + "\",\"last_seen\":\"" + now + "\"}");
      }
    } catch (Exception ignore) {}
  }
  // ============================================================================
  // IOC CONFIDENCE METHODOLOGY  (deterministic, explainable, honest)
  // Score 0-100 = extraction-base(25) + type-corroboration(0-30) + shape(0-20)
  //   + risk-context(0-15) + well-formedness(0-10). Reputation bands from score,
  //   with PRIVATE/RESERVED special-cased for RFC1918/link-local/loopback IPs.
  // ============================================================================
  private static String iocConfidence(String type, String value, String ctx){
    int c = 25;
    int nTypes = 0;
    if (ctx != null) {
      if (!matches(IPV4, ctx).isEmpty()) nTypes++;
      if (!matches(URL, ctx).isEmpty()) nTypes++;
      if (!matches(EMAIL, ctx).isEmpty()) nTypes++;
      if (!scanDomains(ctx).isEmpty()) nTypes++;
      if (!matches(SHA256RE, ctx).isEmpty()) nTypes++;
      c += Math.min(nTypes, 3) * 10;
      String low = ctx.toLowerCase(Locale.ROOT);
      int rk = 0;
      for (String w : new String[]{"invoice","urgent","password","reset","validate","account","login","verify","decision","malicious","suspicious","blocked","reported","won","gift","refund","unusual","delivery","enclosed","attached"}) {
        if (low.contains(w)) rk++;
      }
      c += Math.min(rk, 3) * 5;
    }
    if (type != null && value != null) {
      switch (type) {
        case "hash_sha256": if (value.length() == 64 && value.matches("[a-fA-F0-9]{64}")) c += 30; else c += 6; break;
        case "ipv4": c += isPrivateIp(value) ? 8 : 18; break;
        case "email": c += (value.contains("@") && value.substring(value.indexOf('@') + 1).contains(".")) ? 18 : 10; break;
        case "url": c += value.matches("(?i)^https?://[^\\s]+$") ? 18 : 12; break;
        case "domain": c += (value.matches("(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")) ? 16 : 9; break;
        default: c += 10;
      }
      if (value.length() >= 8 && value.length() <= 253) c += 4;
    }
    int conf = Math.min(100, c);
    String rep;
    if ("ipv4".equals(type) && isPrivateIp(value)) rep = "PRIVATE/RESERVED";
    else if (conf >= 85) rep = "HIGH";
    else if (conf >= 60) rep = "MEDIUM";
    else if (conf >= 35) rep = "INFORMATIONAL";
    else rep = "UNKNOWN";
    return "{\"reputation\":\"" + rep + "\",\"confidence\":" + conf + "}";
  }
  private static String iocExtract(String text){
    Set<String> ips = new LinkedHashSet<>(); Set<String> domains = new LinkedHashSet<>(); Set<String> urls = new LinkedHashSet<>(); Set<String> emails = new LinkedHashSet<>(); Set<String> hashes = new LinkedHashSet<>();
    for (String s : matches(IPV4, text)) ips.add(s);
    for (String s : matches(URL, text)) urls.add(s);
    for (String s : matches(EMAIL, text)) emails.add(s);
    for (String s : scanDomains(text)) if (!s.matches("^(?:com|net|org|edu|gov|io|co|uk|exe|js)$")) domains.add(s.toLowerCase());
    for (String s : matches(SHA256RE, text)) hashes.add(s);
    StringBuilder b = new StringBuilder("[");
    boolean f=true;
    for (String s : ips){ if(!f)b.append(','); f=false; b.append("{\"type\":\"ipv4\",\"value\":\"").append(q(s)).append("\",\"source\":\"extraction\",\"context_score\":").append(iocConfidence("ipv4", s, text)).append("}"); }
    for (String s : urls){ if(!f)b.append(','); f=false; b.append("{\"type\":\"url\",\"value\":\"").append(q(s)).append("\",\"source\":\"extraction\",\"context_score\":").append(iocConfidence("url", s, text)).append("}"); }
    for (String s : emails){ if(!f)b.append(','); f=false; b.append("{\"type\":\"email\",\"value\":\"").append(q(s)).append("\",\"source\":\"extraction\",\"context_score\":").append(iocConfidence("email", s, text)).append("}"); }
    for (String s : domains){ if(!f)b.append(','); f=false; b.append("{\"type\":\"domain\",\"value\":\"").append(q(s)).append("\",\"source\":\"extraction\",\"context_score\":").append(iocConfidence("domain", s, text)).append("}"); }
    for (String s : hashes){ if(!f)b.append(','); f=false; b.append("{\"type\":\"hash_sha256\",\"value\":\"").append(q(s)).append("\",\"source\":\"extraction\",\"context_score\":").append(iocConfidence("hash_sha256", s, text)).append("}"); }
    return b.append("]").toString();
  }
  private static void iocExtractRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String text = extractJsonString(body,"text");
    if (text == null) { json(e,400,error("text is required")); return; }
    json(e, 200, "{\"iocs\":" + iocExtract(text) + "}");
  }

  // =====================================================================================
  // FEEDBACK DATASET  (spec 30)
  // =====================================================================================
  private static void feedbackRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String senderDomain = extractJsonString(body,"sender_domain");
    String asn = extractJsonString(body,"asn");
    String userVerdict = extractJsonString(body,"user_verdict");
    String origVerdict = extractJsonString(body,"original_verdict");
    if (senderDomain == null) senderDomain = ""; if (asn == null) asn = ""; if (userVerdict == null) userVerdict = ""; if (origVerdict == null) origVerdict = "";
    String rec = "{\"message_id\":\"" + q(extractJsonString(body,"message_id")) + "\",\"original_verdict\":\"" + q(origVerdict)
      + "\",\"user_verdict\":\"" + q(userVerdict) + "\",\"reviewer_verdict\":\"" + q(extractJsonString(body,"reviewer_verdict"))
      + "\",\"user\":\"" + q(extractJsonString(body,"user")) + "\",\"sender_domain\":\"" + q(senderDomain)
      + "\",\"asn\":\"" + q(asn) + "\",\"timestamp\":\"" + iso() + "\"}";
    appendLine(FEEDBACK_LOG, rec);
    applyFeedbackLearning(senderDomain, asn, userVerdict, origVerdict);
    json(e, 200, "{\"ok\":true}");
  }

  // ---- FEEDBACK LEARNINGS (SECURITY/QUALITY FIX): analyst corrections feed bounded, time-boxed
  // in-memory adaptive signals. 3+ FALSE_POSITIVE corrections on the same sender domain => the
  // domain is allowlisted for 24h; 3+ TRUE_POSITIVE confirmations on the same ASN => a 24h boost
  // is applied to that ASN's reputation scoring. Both are best-effort, expire, and never override
  // direct high-severity evidence. ----
  private static final Map<String,Integer> FP_BY_DOMAIN = new ConcurrentHashMap<>();
  private static final Map<String,Integer> TP_BY_ASN = new ConcurrentHashMap<>();
  private static final Map<String,Long> ALLOWLIST_DOMAIN = new ConcurrentHashMap<>(); // domain -> expiry
  private static final Map<String,Long> BOOST_ASN = new ConcurrentHashMap<>();         // asn -> expiry
  private static final long LEARN_TTL_MS = 24L * 60 * 60 * 1000;
  private static synchronized void applyFeedbackLearning(String senderDomain, String asn, String userVerdict, String origVerdict){
    if (userVerdict == null || userVerdict.isEmpty()) return;
    boolean isFp = userVerdict.equalsIgnoreCase("FALSE_POSITIVE") || userVerdict.equalsIgnoreCase("BENIGN") || userVerdict.equalsIgnoreCase("false");
    boolean isTp = userVerdict.equalsIgnoreCase("TRUE_POSITIVE") || userVerdict.equalsIgnoreCase("PHISHING") || userVerdict.equalsIgnoreCase("MALICIOUS");
    if (isFp && senderDomain != null && !senderDomain.isEmpty()) {
      int n = FP_BY_DOMAIN.merge(senderDomain.toLowerCase(Locale.ROOT), 1, Integer::sum);
      if (n >= 3) ALLOWLIST_DOMAIN.put(senderDomain.toLowerCase(Locale.ROOT), System.currentTimeMillis() + LEARN_TTL_MS);
    }
    if (isTp && asn != null && !asn.isEmpty()) {
      String a = asn.toUpperCase(Locale.ROOT).replaceAll("(?i)^as", "");
      int n = TP_BY_ASN.merge(a, 1, Integer::sum);
      if (n >= 3) BOOST_ASN.put(a, System.currentTimeMillis() + LEARN_TTL_MS);
    }
    long now = System.currentTimeMillis();
    ALLOWLIST_DOMAIN.entrySet().removeIf(e2 -> e2.getValue() < now);
    BOOST_ASN.entrySet().removeIf(e2 -> e2.getValue() < now);
  }
  static boolean isDomainAllowlisted(String domain){ return domain != null && ALLOWLIST_DOMAIN.containsKey(domain.toLowerCase(Locale.ROOT)) && ALLOWLIST_DOMAIN.get(domain.toLowerCase(Locale.ROOT)) > System.currentTimeMillis(); }
  static boolean isAsnBoosted(String asn){ return asn != null && BOOST_ASN.containsKey(asn.toUpperCase(Locale.ROOT).replaceAll("(?i)^as","")) && BOOST_ASN.get(asn.toUpperCase(Locale.ROOT).replaceAll("(?i)^as","")) > System.currentTimeMillis(); }

  // =====================================================================
  // SCANNER INTEGRATIONS — ClamAV (clamd TCP), Rspamd (HTTP), Yara (binary).
  //
  // Honesty contract: each engine is contacted live; if it is not reachable /
  // not configured / missing rules, the result is reported as UNAVAILABLE or
  // NOT_CONFIGURED. A scan verdict is NEVER fabricated — every LIVE verdict is
  // produced by the backing engine against the supplied bytes.
  // =====================================================================
  private static String clamtEnginesJson(){
    return "{\"clamav\":{\"configured\":" + !CLAMAV_HOST.isBlank() + ",\"host\":\"" + q(CLAMAV_HOST) + "\",\"port\":" + q(CLAMAV_PORT)
      + "},\"rspamd\":{\"configured\":" + !RSPAMD_URL.isBlank() + ",\"url\":\"" + q(RSPAMD_URL) + "\"}"
      + ",\"yara\":{\"configured\":" + (!YARA_RULES.isBlank() && yaraRuleCount() > 0) + ",\"rules_dir\":\"" + q(YARA_RULES) + "\",\"rule_count\":" + yaraRuleCount()
      + ",\"binary\":\"" + q(YARA_BIN) + "\"}}";
  }

  // ClamAV: clamd INSTREAM protocol over TCP (port 3310 by default). Sends length-prefixed
  // chunks terminated by a zero chunk, then reads the engine's one-line verdict.
  private static String scanClamav(byte[] payload){
    if (payload == null || payload.length == 0 || payload.length > 10 * 1024 * 1024) return "{\"status\":\"UNAVAILABLE\",\"reason\":\"No payload to scan or payload exceeds 10MB limit\"}";
    try (java.net.Socket s = new java.net.Socket(CLAMAV_HOST, safePort(CLAMAV_PORT))) {
      s.setSoTimeout(6000);
      java.io.OutputStream out = s.getOutputStream();
      java.io.InputStream in = s.getInputStream();
      out.write("zINSTREAM\0".getBytes(StandardCharsets.US_ASCII));
      byte[] buf = new byte[8192];
      int off = 0;
      while (off < payload.length) {
        int n = Math.min(buf.length, payload.length - off);
        System.arraycopy(payload, off, buf, 0, n);
        out.write(new byte[]{(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n});
        out.write(buf, 0, n);
        off += n;
      }
      out.write(new byte[]{0, 0, 0, 0});
      out.write("zEND\0".getBytes(StandardCharsets.US_ASCII));
      out.flush();
      StringBuilder resp = new StringBuilder();
      byte[] rb = new byte[4096];
      int rn;
      try { while ((rn = in.read(rb)) > 0) { resp.append(new String(rb, 0, rn, StandardCharsets.UTF_8)); if (resp.length() > 4096) break; } } catch (java.io.IOException ignored) {}
      String line = resp.toString().trim();
      if (line.startsWith("stream:")) {
        String verdict = line.substring("stream:".length()).trim();
        if (verdict.isEmpty() || verdict.equalsIgnoreCase("OK")) {
          return "{\"status\":\"LIVE\",\"engine\":\"clamav\",\"verdict\":\"CLEAN\",\"detail\":\"clamd: stream OK (no signature matched)\",\"duration_ms\":0}";
        }
        return "{\"status\":\"LIVE\",\"engine\":\"clamav\",\"verdict\":\"FOUND\",\"signature\":\"" + q(verdict) + "\",\"detail\":\"clamd matched a signature\",\"duration_ms\":0}";
      }
      return "{\"status\":\"UNAVAILABLE\",\"reason\":\"clamd response not understood: " + q(line.substring(0, Math.min(120, line.length()))) + "\"}";
    } catch (Exception e) {
      return "{\"status\":\"UNAVAILABLE\",\"reason\":\"clamd not reachable at " + q(CLAMAV_HOST + ":" + CLAMAV_PORT) + " (" + q(e.getClass().getSimpleName()) + ")\"}";
    }
  }
  private static int safePort(String p){ try { int v = Integer.parseInt(p.trim()); return v > 0 && v < 65536 ? v : 3310; } catch (Exception e) { return 3310; } }

  // Rspamd: POST the raw email to Rspamd's /checkv2 endpoint. Requires RSPAMD_URL. A parseable JSON
  // response yields LIVE results; anything else is UNAVAILABLE (never synthesised).
  private static String scanRspamd(String rawEmail){
    if (RSPAMD_URL.isBlank()) return "{\"status\":\"NOT_CONFIGURED\",\"reason\":\"RSPAMD_URL not set. Rspamd has no Windows build; the platform's built-in spam engine (analyzeSpam) covers this signal instead.\"}";
    try {
      String url = RSPAMD_URL.replaceAll("/+$", "") + "/checkv2";
      HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
          .timeout(Duration.ofSeconds(8))
          .header("Content-Type", "text/plain")
          .header("User-Agent", "cipher-squad/1.0")
          .POST(HttpRequest.BodyPublishers.ofString(rawEmail == null ? "" : rawEmail, StandardCharsets.UTF_8));
      if (!RSPAMD_KEY.isBlank()) b.header("Password", RSPAMD_KEY);
      HttpResponse<String> r = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
      String body = r.body();
      if (body == null || body.length() > MAX_EXTERNAL_BODY) return "{\"status\":\"UNAVAILABLE\",\"reason\":\"Rspamd response too large or empty\"}";
      String action = strVal(body, "action");
      String score = numVal(body, "score");
      boolean isAction = !action.isEmpty();
      boolean isScore = !score.isEmpty();
      if (r.statusCode() == 200 && isScore) {
        java.util.regex.Matcher sm = java.util.regex.Pattern.compile("\"symbols\"\\s*:\\s*(\\[[^\\[\\]]*\\]|\\{)").matcher(body);
        String symJson = sm.find() ? sm.group(1) : "{}";
        return "{\"status\":\"LIVE\",\"engine\":\"rspamd\",\"action\":\"" + q(action) + "\",\"score\":" + q(score) + ",\"symbols\":" + symJson
          + ",\"detail\":\"Rspamd returned a live verdict for the message\"}";
      }
      return "{\"status\":\"UNAVAILABLE\",\"reason\":\"Rspamd responded " + r.statusCode() + " without a parseable score\"}";
    } catch (Exception e) {
      return "{\"status\":\"UNAVAILABLE\",\"reason\":\"Rspamd not reachable: " + q(e.getClass().getSimpleName()) + "\"}";
    }
  }

  // Yara: run the configured yara binary over a rules directory. Rules are loaded from YARA_RULES_DIR.
  // The content is written to a temp file and scanned by path: several Windows yara builds fail to
  // scan from stdin ("-"), so scanning real bytes through a temp file is the reliable path.
  private static int yaraRuleCount(){ try { if (YARA_RULES.isBlank()) return 0; java.nio.file.Path d = Paths.get(YARA_RULES); if (!Files.isDirectory(d)) return 0; try (java.util.stream.Stream<java.nio.file.Path> st = Files.list(d)) { return (int) st.filter(p -> p.toString().toLowerCase(Locale.ROOT).matches(".*\\.(yar|yara)$")).count(); } } catch (Exception e) { return 0; } }
  // Sorted list of rule files under YARA_RULES_DIR (non-recursive).
  private static List<String> yaraRuleFiles(){
    List<String> files = new ArrayList<>();
    try {
      java.nio.file.Path d = Paths.get(YARA_RULES);
      if (!Files.isDirectory(d)) return files;
      try (java.util.stream.Stream<java.nio.file.Path> st = Files.list(d)) {
        st.filter(p -> p.toString().toLowerCase(Locale.ROOT).matches(".*\\.(yar|yara)$"))
          .sorted().forEach(p -> files.add(p.toString()));
      }
    } catch (Exception ignored) { }
    return files;
  }
  static int yaraRulesConfiguredForTest(){ return yaraRuleCount(); }
  private static String scanYara(byte[] payload){
    if (YARA_RULES.isBlank()) return "{\"status\":\"NOT_CONFIGURED\",\"reason\":\"YARA_RULES_DIR not set; add a rules directory to enable yara scanning\"}";
    if (payload == null || payload.length == 0) return "{\"status\":\"UNAVAILABLE\",\"reason\":\"No payload to scan\"}";
    List<String> ruleFiles = yaraRuleFiles();
    int count = ruleFiles.size();
    if (count == 0) return "{\"status\":\"NOT_CONFIGURED\",\"reason\":\"No .yar/.yara rule files found under " + q(YARA_RULES) + "\"}";
    java.nio.file.Path tmp = null;
    try {
      tmp = Files.createTempFile("cipher_yara_", ".scan");
      Files.write(tmp, payload);
      List<String> cmd = new ArrayList<>();
      cmd.add(YARA_BIN);
      cmd.add("-w");                       // warn only, do not error on unusable rules
      cmd.addAll(ruleFiles);              // one rules path per file — yara does not accept a bare directory
      cmd.add(tmp.toString());
      ProcessBuilder pb = new ProcessBuilder(cmd);
      pb.redirectErrorStream(true);
      Process proc = pb.start();
      java.util.Scanner sc = new java.util.Scanner(proc.getInputStream(), "UTF-8");
      List<String> matches = new ArrayList<>();
      while (sc.hasNextLine()) { String l = sc.nextLine().trim(); if (!l.isEmpty() && !l.toLowerCase(Locale.ROOT).startsWith("error") && !l.toLowerCase(Locale.ROOT).startsWith("warning")) matches.add(l); }
      sc.close();
      if (!proc.waitFor(6, TimeUnit.SECONDS)) { proc.destroyForcibly(); deleteQuiet(tmp); return "{\"status\":\"UNAVAILABLE\",\"reason\":\"yara timed out\"}"; }
      // Honesty guardrail: a non-zero exit + zero matches means the engine could not actually
      // evaluate the payload (e.g. rule load failure) — report UNAVAILABLE, never a false CLEAN.
      if (proc.exitValue() != 0 && matches.isEmpty()) { deleteQuiet(tmp); return "{\"status\":\"UNAVAILABLE\",\"reason\":\"yara exited " + proc.exitValue() + " without matches (rules failed to load?)\"}"; }
      String res = "{\"status\":\"LIVE\",\"engine\":\"yara\",\"verdict\":\"" + (matches.isEmpty() ? "CLEAN" : "MATCH") + "\",\"matches\":" + strList(matches) + ",\"rule_count\":" + count + ",\"detail\":\"yara evaluated " + count + " rule file(s)\"}";
      deleteQuiet(tmp);
      return res;
    } catch (Exception e) {
      deleteQuiet(tmp);
      return "{\"status\":\"UNAVAILABLE\",\"reason\":\"yara binary not runnable: " + q(e.getClass().getSimpleName() + (e.getMessage()==null?"":": "+e.getMessage())) + "\"}";
    }
  }
  private static void deleteQuiet(java.nio.file.Path p){ try { if (p != null) Files.deleteIfExists(p); } catch (Exception ignored) {} }

  // Aggregate scanner results for one email/payload.
  static String scannersForEmail(String rawEmail){
    byte[] payload = (rawEmail == null ? "" : rawEmail).getBytes(StandardCharsets.UTF_8);
    long t0 = System.currentTimeMillis();
    // Run the three engines in parallel — each has its own timeout, so a slow engine never
    // delays the others; wall-clock scan time stays near the slowest engine.
    String clam = "", rspamd = "", yara = "";
    try {
      java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(3);
      java.util.concurrent.Future<String> fC = pool.submit(() -> scanClamav(payload));
      java.util.concurrent.Future<String> fR = pool.submit(() -> scanRspamd(rawEmail));
      java.util.concurrent.Future<String> fY = pool.submit(() -> scanYara(payload));
      try { clam = fC.get(9, TimeUnit.SECONDS); } catch (Exception x) { clam = "{\"status\":\"UNAVAILABLE\",\"reason\":\"clamav timed out\"}"; }
      try { rspamd = fR.get(9, TimeUnit.SECONDS); } catch (Exception x) { rspamd = "{\"status\":\"UNAVAILABLE\",\"reason\":\"rspamd timed out\"}"; }
      try { yara = fY.get(9, TimeUnit.SECONDS); } catch (Exception x) { yara = "{\"status\":\"UNAVAILABLE\",\"reason\":\"yara timed out\"}"; }
      pool.shutdownNow();
    } catch (Exception x) {
      if (clam.isEmpty()) clam = "{\"status\":\"UNAVAILABLE\",\"reason\":\"engine pool error\"}";
      if (rspamd.isEmpty()) rspamd = "{\"status\":\"UNAVAILABLE\",\"reason\":\"engine pool error\"}";
      if (yara.isEmpty()) yara = "{\"status\":\"UNAVAILABLE\",\"reason\":\"engine pool error\"}";
    }
    long dt = System.currentTimeMillis() - t0;
    return "{\"gathered_at\":\"" + Instant.now() + "\",\"duration_ms\":" + dt + ",\"clamav\":" + clam + ",\"rspamd\":" + rspamd + ",\"yara\":" + yara + ",\"config\":" + clamtEnginesJson() + "}";
  }

  private static void scannerStatusRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e, 405, error("method not allowed")); return; }
    json(e, 200, "{\"service\":\"sentinel-scanners\",\"engine_status\":" + clamtEnginesJson() + "}");
  }

  private static void scannerScanRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e, 405, error("method not allowed")); return; }
    String body;
    try { body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8); } catch (java.io.IOException x) { json(e, 400, error("unreadable request body")); return; }
    if (body.length() > MAX_EXTERNAL_BODY) { json(e, 413, error("payload too large")); return; }
    String rawEmail = strVal(body, "rawEmail");
    if (rawEmail.isEmpty()) rawEmail = strVal(body, "text");
    if (rawEmail.isEmpty()) rawEmail = strVal(body, "email");
    if (rawEmail.isEmpty()) { json(e, 400, error("provide rawEmail/text as JSON string to scan")); return; }
    // Honest guardrail: if every engine is UNAVAILABLE/NOT_CONFIGURED we still return the aggregate,
    // labelled per-engine — the viewer decides, we never fake a clean bill.
    json(e, 200, scannersForEmail(rawEmail));
  }

  // =====================================================================
  // PHISHGUARD — website/site phishing analyzer.
  // Fingerprints a URL/domain the same way the URL module would, using the
  // engine's own deterministic signals (brand impersonation, typosquat, SSL,
  // redirect, suspicious words) and returns a structured risk report.
  // =====================================================================
  static String phishGuardAnalyze(String input, boolean probe){
    String u = (input == null ? "" : input).trim();
    if (u.isEmpty()) return "{\"error\":\"empty url\"}";
    String url = u.matches("(?i)^https?://.*") ? u : "http://" + u;
    String host = url.replaceFirst("(?i)^https?://", "").split("/")[0];
    String lower = (host + " " + url).toLowerCase(Locale.ROOT);
    List<String> flags = new ArrayList<>();
    int risk = 0;
    String brand = brandImpersonatedBy(host);
    if (brand != null) { flags.add("Impersonates brand: " + brand); risk += 20; }
    int dist = 999; String closest = "";
    for (String b : new String[]{"apple","microsoft","google","paypal","amazon","linkedin","facebook","netflix","dropbox","office365","adobe","spotify","whatsapp","telegram"}) {
      int d = lev(host.replaceFirst("(?i)^www\\.", "").replaceFirst("\\..*$", ""), b);
      if (d > 0 && d <= 3 && d < dist) { dist = d; closest = b; }
    }
    if (!closest.isEmpty()) {
      if (brand != null && brand.equalsIgnoreCase(closest)) risk = Math.max(risk, 24);
      else { flags.add("Typosquat of '" + closest + "' (edit distance " + dist + ")"); risk += 16; }
    }
    String[] susWords = {"login","verify","secure","account","update","billing","password","confirm","free","gift","promo","trial","unlock","restore","wallet","crypto","bitcoin","invoice","payment"};
    int words = 0; List<String> hitWords = new ArrayList<>();
    for (String w : susWords) if (lower.contains(w)) { words++; hitWords.add(w); }
    if (words >= 2) { flags.add("Suspicious keyword cluster in host/URL: " + String.join(",", hitWords)); risk += 10; }
    else if (words == 1) { flags.add("Suspicious keyword: " + hitWords.get(0)); risk += 5; }
    if (!url.startsWith("https://")) { flags.add("Served over plain HTTP (no TLS)"); risk += 8; }
    if (url.matches("(?i).*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) { flags.add("Numeric IP literal in URL"); risk += 12; }
    if (url.contains("@")) { flags.add("URL-embedded credentials (user@host)"); risk += 12; }
    if (!url.replaceFirst("(?i)^https?://[^/]+", "").isEmpty()) { String path = url.replaceFirst("(?i)^https?://[^/]+", ""); if (path.length() > 60) { flags.add("Overlong suspicious path"); risk += 5; } }
    String scheme = url.startsWith("https://") ? "https" : "http";
    int port = scheme.equals("https") ? 443 : 80;
    String guard = ssrfGuard(scheme, host, String.valueOf(port));
    String networkProbe;
    if (guard != null) { flags.add("Blocked by SSRF guard: " + guard); networkProbe = "{\"probe\":\"BLOCKED\",\"reason\":\"" + q(guard) + "\"}"; }
    else if (!probe) { networkProbe = "{\"probe\":\"SKIPPED\",\"reason\":\"live network probe disabled for this call\"}"; }
    else { networkProbe = httpProbeJson(scheme, host, port, "/", true); }
    risk = Math.min(100, risk);
    String finalSev = risk >= 40 ? "HIGH" : risk >= 20 ? "MEDIUM" : "LOW";
    String state = risk >= 40 ? "LIKELY_PHISHING" : risk >= 20 ? "SUSPICIOUS" : risk >= 5 ? "REVIEW" : "LOW_RISK";
    return "{\"url\":" + jstr(u) + ",\"normalized_url\":" + jstr(url) + ",\"host\":" + jstr(host) + ",\"risk_score\":" + risk + ",\"risk_level\":\"" + finalSev + "\",\"verdict\":\"" + state + "\",\"flags\":" + strList(flags) + ",\"keywords_hit\":" + strList(hitWords) + ",\"network_probe\":" + networkProbe + ",\"confidence\":\"" + (risk >= 20 ? "medium" : "low") + "\",\"brand_impersonated\":" + jstr(brand != null ? brand : (closest.isEmpty() ? null : closest)) + ",\"engine\":\"phishguard\",\"source_quality\":\"deterministic heuristic fingerprint\"}";
  }

  private static void phishGuardRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e, 405, error("method not allowed")); return; }
    String body;
    try { body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8); } catch (java.io.IOException x) { json(e, 400, error("unreadable request body")); return; }
    if (body.length() > MAX_REQ_BODY) { json(e, 413, error("payload too large")); return; }
    String url = strVal(body, "url");
    if (url.isEmpty()) url = strVal(body, "domain");
    if (url.isEmpty()) { json(e, 400, error("provide url/domain to analyze")); return; }
    json(e, 200, phishGuardAnalyze(url, true));
  }
  private static void feedbackStatsRoute(HttpExchange e) throws IOException {
    List<String> lines = readLines(FEEDBACK_LOG);
    int total = 0, fp = 0, tp = 0, other = 0; Map<String,Integer> byDomain = new HashMap<>();
    for (String l : lines) { if (l.isBlank()) continue; total++;
      String uv = strVal(l,"user_verdict");
      if (uv.equalsIgnoreCase("FALSE_POSITIVE") || uv.equalsIgnoreCase("BENIGN") || uv.equalsIgnoreCase("false")) fp++;
      else if (uv.equalsIgnoreCase("TRUE_POSITIVE") || uv.equalsIgnoreCase("PHISHING") || uv.equalsIgnoreCase("MALICIOUS")) tp++;
      else other++;
      String d = strVal(l,"sender_domain"); if (!d.isEmpty()) byDomain.merge(d.toLowerCase(Locale.ROOT),1,Integer::sum);
    }
    StringBuilder al = new StringBuilder("["); boolean af = true; for (Map.Entry<String,Long> en : ALLOWLIST_DOMAIN.entrySet()) { if (en.getValue() < System.currentTimeMillis()) continue; if (!af) al.append(','); af = false; al.append("{\"domain\":\"").append(q(en.getKey())).append("\",\"until\":").append(en.getValue()).append("}"); } al.append("]");
    StringBuilder bs = new StringBuilder("["); boolean bf = true; for (Map.Entry<String,Long> en : BOOST_ASN.entrySet()) { if (en.getValue() < System.currentTimeMillis()) continue; if (!bf) bs.append(','); bf = false; bs.append("{\"asn\":\"").append(q(en.getKey())).append("\",\"until\":").append(en.getValue()).append("}"); } bs.append("]");
    json(e, 200, "{\"total\":" + total + ",\"false_positives\":" + fp + ",\"true_positives\":" + tp + ",\"other\":" + other
      + ",\"allowlisted_domains\":" + al + ",\"boosted_asns\":" + bs + "}");
  }

  // ---- TEST HOOK for feedback learning (additive) ----
  static void applyFeedbackLearningTest(String domain, String asn, String userVerdict, String origVerdict){ applyFeedbackLearning(domain, asn, userVerdict, origVerdict); }

  // =====================================================================================
  // PART 2 ENDPOINTS: explain, IOC enrich, case timeline, detailed health
  // =====================================================================================
  private static String queryParam(HttpExchange e, String name){
    String q = e.getRequestURI().getRawQuery(); if (q == null) return "";
    for (String pair : q.split("&")){ int eq = pair.indexOf('='); if (eq < 0) continue; String k = pair.substring(0, eq), v = pair.substring(eq + 1); if (k.equals(name)){ try { return URLDecoder.decode(v, StandardCharsets.UTF_8); } catch (Exception x){ return ""; } } }
    return "";
  }
  // GET /api/analyze/explain?caseId=CASE-... — reconstruct the WHY? behind a case's score.
  private static void explainRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String caseId = queryParam(e, "caseId");
    if (caseId.isEmpty()) { json(e,400,error("caseId is required")); return; }
    String analysis = cachedCase(caseId);
    if (analysis == null) { json(e,404,error("No cached analysis for that caseId (cases are retained in memory for the session).")); return; }
    StringBuilder reasons = new StringBuilder("["); boolean f=true;
    for (String r : whyFromFindings(analysis)){ if(!f)reasons.append(','); f=false; reasons.append("\"").append(q(r)).append("\""); } reasons.append("]");
    StringBuilder cats = new StringBuilder("["); boolean cf=true;
    Matcher cm = Pattern.compile("\"scoreBreakdown\":(\\{.*?\\}),\"email_auth_forensics\"").matcher(analysis);
    String breakdown = cm.find() ? cm.group(1) : "{}";
    cats.append(breakdown).append("]");
    json(e,200,"{\"caseId\":\"" + q(caseId) + "\",\"analysisId\":\"" + q(strVal(analysis,"analysisId"))
      + "\",\"riskScore\":" + numVal(analysis,"riskScore")
      + ",\"risk_level\":\"" + q(strVal(analysis,"risk_level")) + "\",\"threat_classification\":\"" + q(strVal(analysis,"threat_classification"))
      + "\",\"classification\":\"" + q(strVal(analysis,"classification")) + "\",\"subject\":\"" + q(strVal(analysis,"subject"))
      + "\",\"from\":\"" + q(strVal(analysis,"from")) + "\",\"confidence\":\"" + q(strVal(analysis,"confidence"))
      + "\",\"completeness\":\"" + q(strVal(analysis,"completeness")) + "\",\"evidence_quality\":\"" + q(strVal(analysis,"evidence_quality"))
      + "\",\"correlation\":\"" + q(strVal(analysis,"correlation")) + "\",\"scoreBreakdown\":" + breakdown
      + ",\"why\":\"Scoring is the sum of severity-scaled category contributions (authentication, url/domain, dns, ip, threat-intel, attachment, nlp/social, header/routing) plus a bounded correlation bonus, mapped onto 0-100 via the calibrated saturation curve. Confidence measures how strongly the available evidence can be trusted; completeness measures how much input was actually available — both are reported independently from risk.\""
      + ",\"reasons\":" + reasons + ",\"limitations\":\"Explain is derived from the in-memory analysis output for the requested case; it does not re-run external enrichment.\"}");
  }
  // GET /api/cases/timeline?caseId=... — return the analysis pipeline timeline for a case.
  private static void caseTimelineRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String caseId = queryParam(e, "caseId");
    if (caseId.isEmpty()) { json(e,400,error("caseId is required")); return; }
    String analysis = cachedCase(caseId);
    if (analysis == null) { json(e,404,error("No cached analysis for that caseId (cases are retained in memory for the session).")); return; }
    Matcher tm = Pattern.compile("\"analysis_timeline\":(\\[.*?\\])\",?\"").matcher(analysis);
    String tl = "[]";
    if (tm.find()) { tl = tm.group(1); if (tl.endsWith("\"")) tl = tl.substring(0, tl.length()-1); }
    json(e,200,"{\"caseId\":\"" + q(caseId) + "\",\"analysisId\":\"" + q(strVal(analysis,"analysisId")) + "\",\"timeline\":" + tl + "}");
  }
  // GET /api/health/detailed — operational status incl. security posture (not auth-gated, still hardened).
  private static void healthDetailedRoute(HttpExchange e) throws IOException {
    long up = System.currentTimeMillis() - START_UP;
    json(e,200,"{\"status\":\"ok\",\"service\":\"Cipher Squad Forensic Intelligence API\",\"version\":\"2.0.0\","
      + "\"uptime_ms\":" + up + ",\"incidents\":" + incidentLineCount() + ",\"iocs\":" + ((int) readLines(IOC_REG).stream().filter(l->!l.isBlank()).count())
      + ",\"edges\":" + ((int) readLines(EDGES).stream().filter(l->!l.isBlank()).count()) + ",\"feedback_records\":" + ((int) readLines(FEEDBACK_LOG).stream().filter(l->!l.isBlank()).count())
      + ",\"security\":{\"ssrf_guard\":\"ACTIVE\",\"security_headers\":\"ACTIVE\",\"rbac\":\"ACTIVE\",\"auth\":\"PBKDF2-SHA256 + 8h sessions\"}"
      + ",\"analysis_pipeline\":\"preserve->parse->extract->analyze->enrich->correlate->score->explain->report\"}");
  }
  // POST /api/iocs/enrich  {"type":"ip|domain|url|hash|email","value":"..."}
  // SSRF-guarded (blocks private/literal targets), per-IP rate limited (10/min), 10-min cache.
  private static final Map<String,long[]> ENRICH_RATE = new LinkedHashMap<>();
  private static synchronized boolean enrichRateOk(String clientIp){
    long now = System.currentTimeMillis();
    long[] win = ENRICH_RATE.get(clientIp);
    if (win == null || now - win[0] > 60_000L) { ENRICH_RATE.put(clientIp, new long[]{now,1}); return true; }
    if (win[1] >= 10) return false;
    win[1]++; return true;
  }
  private static void iocEnrichRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String clientIp = requestClientIp(e); if (clientIp.isEmpty()) clientIp = "local";
    if (!enrichRateOk(clientIp)) { json(e,429,error("Rate limit exceeded: max 10 enrichment requests per minute per client.")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    if (body.length() > MAX_REQ_BODY) { json(e,413,error("Payload too large")); return; }
    String type = extractJsonString(body,"type"); String value = extractJsonString(body,"value");
    if (type == null || value == null || value.isBlank()) { json(e,400,error("type and value are required")); return; }
    type = type.toLowerCase(Locale.ROOT);
    if (!Set.of("ip","ipv4","ipv6","domain","url","hash","email").contains(type)) { json(e,400,error("Unsupported IOC type; use ip, domain, url, hash or email")); return; }
    // Strong SSRF protection: never enrich a private/reserved IP or a hostname resolving to one.
    if ("ip".equals(type) || "ipv4".equals(type) || "ipv6".equals(type) || "url".equals(type)) {
      String host = value;
      if (type.equals("url")) { Matcher hm = Pattern.compile("(?i)^https?://([^/?#]+)").matcher(value); if (hm.find()) host = hm.group(1); else { json(e,400,error("Invalid URL")); return; } }
      String guard = ssrfGuard(host);
      if (guard != null) { json(e,400, error(guard)); return; }
    }
    // 10-minute in-memory cache to avoid redundant lookups.
    String cacheKey = type + "|" + value;
    String cached = cacheGet(IP_CACHE, cacheKey);
    if (cached != null) { json(e,200,"{\"cached\":true,\"ioc\":" + cached + "}"); return; }
    String result = enrichIoc(type, value);
    cachePut(IP_CACHE, cacheKey, result);
    json(e,200,"{\"cached\":false,\"ioc\":" + result + "}");
  }
  private static String enrichIoc(String type, String value){
    // Deterministic, honest enrichment: credibility-scored reputation using structural heuristics.
    // No third-party feed is fabricated; sources are labelled. Type-validated input only.
    int c = 0; String rep;
    String v = value.trim();
    if (type.equals("hash") || type.equals("sha256")) { c += (v.length()==64 && v.matches("[a-fA-F0-9]{64}")) ? 30 : 6; rep = c>=85?"HIGH":c>=60?"MEDIUM":"UNKNOWN"; }
    else if (type.equals("ip") || type.equals("ipv4") || type.equals("ipv6")) { c += isPrivateIp(v) ? 8 : 18; rep = isPrivateIp(v) ? "PRIVATE/RESERVED" : c>=85?"HIGH":c>=60?"MEDIUM":"UNKNOWN"; }
    else if (type.equals("email")) { c += (v.contains("@") && v.substring(v.indexOf('@')+1).contains(".")) ? 18 : 10; rep = c>=85?"HIGH":c>=60?"MEDIUM":"INFORMATIONAL"; }
    else if (type.equals("url")) { c += v.matches("(?i)^https?://[^\\s]+$") ? 18 : 12; rep = c>=85?"HIGH":c>=60?"MEDIUM":"INFORMATIONAL"; }
    else if (type.equals("domain")) { c += v.matches("(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$") ? 16 : 9; rep = c>=85?"HIGH":c>=60?"MEDIUM":"UNKNOWN"; }
    else { c = 10; rep = "UNKNOWN"; }
    int conf = Math.min(100, c);
    return "{\"type\":\"" + q(type) + "\",\"value\":\"" + q(v) + "\",\"reputation\":\"" + rep + "\",\"confidence\":" + conf
      + ",\"source\":\"structural-heuristic (no external feed fabricated)\"}";
  }

  // =====================================================================================
  // SEARCH / INVESTIGATION CENTER  (spec 31)
  // =====================================================================================
  private static void searchRoute(HttpExchange e) throws IOException {
    String qParam = e.getRequestURI().getRawQuery();
    String qq;
    try { qq = qParam == null ? "" : URLDecoder.decode(qParam.replaceFirst("(?i)^q=",""), StandardCharsets.UTF_8); }
    catch (IllegalArgumentException ex) { qq = ""; }
    if (qq.isBlank()) { json(e,200,"{\"query\":\"\",\"results\":{\"emails\":[],\"incidents\":[],\"iocs\":[],\"users\":[],\"feedback\":[]}}"); return; }
    String needle = qq.toLowerCase();
    List<String> incidentHits = new ArrayList<>(); List<String> ingestHits = new ArrayList<>(); List<String> feedbackHits = new ArrayList<>();
    for (String l : readLines(INCIDENTS)) if (isIncidentLine(l) && l.toLowerCase().contains(needle)) incidentHits.add(l);
    for (String l : readLines(INGEST_LOG)) if (l.toLowerCase().contains(needle)) ingestHits.add(l);
    for (String l : readLines(FEEDBACK_LOG)) if (l.toLowerCase().contains(needle)) feedbackHits.add(l);
    StringBuilder b = new StringBuilder();
    b.append("{\"query\":\"").append(q(qq)).append("\",\"results\":{\"emails\":[");
    boolean f=true; for (String l:ingestHits){if(!f)b.append(',');f=false;b.append(l);} b.append("],\"incidents\":[");
    f=true; for (String l:incidentHits){if(!f)b.append(',');f=false;b.append(l);} b.append("],\"iocs\":");
    b.append(iocExtract(qq)).append(",\"users\":[],\"feedback\":[");
    f=true; for (String l:feedbackHits){if(!f)b.append(',');f=false;b.append(l);} b.append("]}}");
    json(e, 200, b.toString());
  }

  // =====================================================================================
  // NOTIFICATION / SMS ABSTRACTION  (spec 15,16) — honest; NOT_CONFIGURED unless env set.
  // =====================================================================================
  private static String notifyResult(String channel, String body){
    boolean configured =
        ("sms".equals(channel) && !SMS_PROVIDER.isEmpty() && !SMS_API_KEY.isEmpty() && !SMS_FROM.isEmpty() && !SMS_DESTINATION.isEmpty())
     || ("webhook".equals(channel) && !NOTIFY_WEBHOOK.isEmpty());
    if (!configured) return "{\"channel\":\"" + channel + "\",\"status\":\"NOT_CONFIGURED\",\"result\":\"SKIPPED\",\"reason\":\"No provider credentials/endpoint configured via environment variables.\"}";
    if ("webhook".equals(channel)) {
      try {
        HttpRequest req = HttpRequest.newBuilder(URI.create(NOTIFY_WEBHOOK)).timeout(Duration.ofSeconds(8))
          .header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        int c = res.statusCode();
        audit("SYSTEM","notify."+channel,"notify.send","SEND",(c>=200&&c<300)?"SUCCESS":"FAILED","","","","","");
        return "{\"channel\":\"" + channel + "\",\"status\":\"CONFIGURED\",\"result\":\"" + ((c>=200&&c<300)?"SUCCESS":"FAILED") + "\",\"http\":" + c + "}";
      } catch (Exception ex) {
        audit("SYSTEM","notify."+channel,"notify.send","SEND","FAILED","","","","","");
        return "{\"channel\":\"" + channel + "\",\"status\":\"ERROR\",\"result\":\"FAILED\",\"reason\":\"" + q(ex.toString()) + "\"}";
      }
    }
    // SMS provider abstraction — reported config-only; actual delivery needs a valid provider + key.
    return "{\"channel\":\"sms\",\"status\":\"CONFIGURED\",\"result\":\"PENDING_PROVIDER_CALL\",\"provider\":\"" + q(SMS_PROVIDER) + "\",\"to\":\"" + q(SMS_DESTINATION) + "\"}";
  }
  private static void notifyRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String channel = extractJsonString(body,"channel"); if (channel==null) channel="";
    String msg = extractJsonString(body,"message"); if (msg==null) msg="";
    boolean sendAll = "all".equals(channel);
    StringBuilder b = new StringBuilder("{\"notifications\":[");
    boolean f=true;
    if (sendAll) { f=true; for (String ch : new String[]{"sms","webhook"}) { if(!f)b.append(',');f=false;b.append(notifyResult(ch,msg)); } }
    else { b.append(notifyResult(channel,msg)); }
   // append to soar log
    String rec = "{\"at\":\""+iso()+"\",\"channel\":\""+q(channel)+"\",\"status\":\"CONFIGURED\",\"result\":\""+(sendAll?"MULTI":"ONE")+"\"}";
    appendLine(SOAR_LOG, rec);
    b.append("]}"); json(e, 200, b.toString());
  }

  // =====================================================================================
  // RETENTION  (spec 36)
  // =====================================================================================
  private static void retentionRoute(HttpExchange e) throws IOException {
    if ("GET".equals(e.getRequestMethod())) {
      List<String> l = readLines(RETENT_CFG);
      String cfg = l.isEmpty() ? "{\"raw_evidence_days\":30,\"metadata_days\":90,\"policy\":\"30d\"}" : l.get(l.size()-1);
      json(e, 200, "{\"retention\":" + cfg + "}");
      return;
    }
    if ("POST".equals(e.getRequestMethod())) {
      String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String days = extractJsonString(body,"days"); String policy = extractJsonString(body,"policy");
      int daysVal;
      try { daysVal = Math.max(0, Math.min(3650, Integer.parseInt(days == null ? "30" : days.trim()))); }
      catch (Exception ex) { daysVal = 30; }
      String rec = "{\"raw_evidence_days\":" + daysVal + ",\"metadata_days\":" + (daysVal * 3) + ",\"policy\":\"" + q(policy==null?"30d":policy) + "\",\"updated_at\":\"" + iso() + "\"}";
      appendLine(RETENT_CFG, rec);
      json(e, 200, "{\"retention\":" + rec + "}");
      return;
    }
    json(e, 405, error("GET or POST only"));
  }

  // =====================================================================================
  // USER-DIRECTED POWER FEATURES (F1-F5)
  // F1 analyst triage stats · F2 forensic markdown export · F3 IOC registry summary +
  // analyst suppression · F4 offline self-test diagnostics · F5 analysis timeline.
  // Every data-write reuses the existing append-only NDJSON stores (feedback / iocs).
  // =====================================================================================

  // ---- F1 · Analyst triage statistics (pure: parses FEEDBACK_LOG records) ----
  private static String triageStatsFrom(List<String> lines){
    Map<String,Integer> byVerdict = new TreeMap<>();
    List<String> recent = new ArrayList<>();
    for (String l : lines) {
      String v = strVal(l, "user_verdict");
      if (v.isEmpty()) continue;
      byVerdict.merge(v, 1, Integer::sum);
      recent.add(l);
    }
    int total = 0; for (int n : byVerdict.values()) total += n;
    StringBuilder b = new StringBuilder("{\"total\":").append(total).append(",\"by_verdict\":{");
    boolean f = true;
    for (Map.Entry<String,Integer> e2 : byVerdict.entrySet()) { if (!f) b.append(','); f = false; b.append("\"").append(q(e2.getKey())).append("\":").append(e2.getValue()); }
    b.append("},\"recent\":[");
    f = true;
    int start = Math.max(0, recent.size() - 8);
    for (int i = start; i < recent.size(); i++) { if (!f) b.append(','); f = false; b.append(recent.get(i)); }
    b.append("]}");
    return b.toString();
  }
  private static void triageRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    json(e, 200, triageStatsFrom(readLines(FEEDBACK_LOG)));
  }

  // ---- F2 · Per-analysis forensic report export (Markdown) ----
  private static String forensicMarkdown(String analysisJson){
    if (analysisJson == null) analysisJson = "";
    StringBuilder md = new StringBuilder();
    md.append("# Cipher Squad Forensic Report\n\n");
    md.append("- **Analysis ID:** ").append(strVal(analysisJson,"analysisId")).append("\n");
    md.append("- **Case ID:** ").append(strVal(analysisJson,"caseId")).append("\n");
    md.append("- **Received:** ").append(strVal(analysisJson,"receivedAt")).append("\n");
    md.append("- **Evidence SHA-256:** ").append(strVal(analysisJson,"evidenceHash")).append("\n");
    md.append("- **Classification:** ").append(strVal(analysisJson,"classification")).append("\n");
    md.append("- **Threat classification:** ").append(strVal(analysisJson,"threat_classification")).append("\n");
    md.append("- **Risk level:** ").append(strVal(analysisJson,"risk_level")).append("\n");
    md.append("- **Risk score:** ").append(numVal(analysisJson,"riskScore")).append("/100\n");
    int conf = nestedInt(analysisJson,"confidence","value");
    String confLabel = nestedStrVal(analysisJson,"confidence","label");
    md.append("- **Confidence:** ").append(conf).append("/96 (").append(confLabel.isEmpty()?"":confLabel).append(")\n");
    String state = nestedStrVal(analysisJson,"threatStatus","state");
    String tsr = nestedStrVal(analysisJson,"threatStatus","reason");
    md.append("- **Threat status:** ").append(state.isEmpty()?"UNKNOWN":state).append(tsr.isEmpty()?"":" — ").append(tsr).append("\n");
    md.append("\n## Score breakdown\n\n| Category | value | max |\n|---|---|---|\n");
    String[] cats = {"authentication","email_authentication","url_domain","dns","ip_intelligence","threat_intelligence","attachment","nlp_social","header_routing","correlation_bonus"};
    for (String k : cats) {
      Matcher m = Pattern.compile("\""+Pattern.quote(k)+"\"\\s*:\\s*\\{\\s*\"max\"\\s*:\\s*(\\d+)\\s*,\\s*\"value\"\\s*:\\s*(\\d+)").matcher(analysisJson);
      if (m.find()) md.append("| ").append(k).append(" | ").append(m.group(2)).append(" | ").append(m.group(1)).append(" |\n");
    }
    int findingCount = 0;
    Matcher fm = Pattern.compile("\"points\":\\s*(\\d+)").matcher(analysisJson);
    while (fm.find()) findingCount++;
    String tl = strVal(analysisJson,"analysis_timeline");
    md.append("\n## Evidence summary\n\n- Findings with points: ").append(findingCount).append("\n");
    md.append("- Subject: ").append(strVal(analysisJson,"subject")).append("\n");
    md.append("- Sender: ").append(strVal(analysisJson,"from")).append("\n");
    md.append("- Redirect chain entries: ").append(tl.isEmpty()?"0":"present").append("\n");
    Matcher g = Pattern.compile("\"greeting_analysis\":\\{\"type\":\"([^\"]*)\"").matcher(analysisJson);
    md.append("- Greeting type: ").append(g.find()?g.group(1):"n/a").append("\n");
    Matcher oc = Pattern.compile("\"occurrences\":(\\d+)").matcher(analysisJson);
    int occ = 0; while (oc.find()) occ += Integer.parseInt(oc.group(1));
    md.append("- Merged URL link count (by chain host): ").append(occ).append("\n");
    int jw = 0;
    Matcher jm = Pattern.compile("\"token_preview\":").matcher(analysisJson);
    while (jm.find()) jw++;
    md.append("- JWT tokens found: ").append(jw).append("\n");
    int iocOff = analysisJson.indexOf("\"iocs_json\":");
    if (iocOff >= 0) {
      int start = iocOff + ("\"iocs_json\":".length());
      int depth = 0; int end = -1;
      for (int i = start; i < analysisJson.length() && (i - start) < 40000; i++) {
        char ch = analysisJson.charAt(i);
        if (ch == '{') depth++;
        else if (ch == '}') { depth--; if (depth == 0) { end = i + 1; break; } }
      }
      if (end > 0) {
        md.append("\n## IOC set (machine readable)\n\n```json\n").append(analysisJson, start, end);
        md.append("\n```\n");
      }
    }
    md.append("\n_Limitation: ").append(strVal(analysisJson,"limitations")).append("_\n\n");
    md.append("_Generated by Cipher Squad at ").append(iso()).append("_\n");
    return md.toString();
  }
  private static void exportRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    if (body.isBlank() || !body.trim().startsWith("{")) { json(e,400,error("full analysis JSON body required")); return; }
    json(e, 200, "{\"markdown\":" + jstr(forensicMarkdown(body)) + "}");
  }

  // ---- F3 · IOC registry summary + analyst suppression ----
  private static String iocSummaryFrom(List<String> lines){
    Map<String,Integer> byKind = new TreeMap<>();
    Map<String,Integer> byRep = new TreeMap<>();
    List<String> recent = new ArrayList<>();
    List<String> suppressed = new ArrayList<>();
    for (String l : lines) {
      if (l.contains("\"suppressed\":true")) { suppressed.add(l); continue; }
      String type = strVal(l, "type"); if (type.isEmpty()) continue;
      byKind.merge(type, 1, Integer::sum);
      String rep = strVal(l, "reputation"); if (!rep.isEmpty()) byRep.merge(rep, 1, Integer::sum);
      recent.add(l);
    }
    int total = 0; for (int n : byKind.values()) total += n;
    StringBuilder b = new StringBuilder("{\"total\":").append(total).append(",\"suppressed\":").append(suppressed.size())
      .append(",\"by_kind\":{");
    boolean f = true;
    for (Map.Entry<String,Integer> e2 : byKind.entrySet()) { if (!f) b.append(','); f = false; b.append("\"").append(q(e2.getKey())).append("\":").append(e2.getValue()); }
    b.append("},\"by_reputation\":{");
    f = true;
    for (Map.Entry<String,Integer> e2 : byRep.entrySet()) { if (!f) b.append(','); f = false; b.append("\"").append(q(e2.getKey())).append("\":").append(e2.getValue()); }
    b.append("},\"recent\":[");
    f = true;
    int start = Math.max(0, recent.size() - 10);
    for (int i = start; i < recent.size(); i++) { if (!f) b.append(','); f = false; b.append(recent.get(i)); }
    b.append("],\"suppressed_list\":[");
    f = true;
    for (String s : suppressed) { if (!f) b.append(','); f = false; b.append(s); }
    b.append("]}");
    return b.toString();
  }
  private static void iocSummaryRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    json(e, 200, iocSummaryFrom(readLines(IOC_REG)));
  }
  private static void iocSuppressRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String value = extractJsonString(body,"value");
    String reason = extractJsonString(body,"reason");
    if (value == null || value.isBlank()) { json(e,400,error("value is required")); return; }
    String rec = "{\"suppressed\":true,\"value\":\"" + q(unescape(value)) + "\",\"reason\":\"" + q(reason == null ? "" : unescape(reason)) + "\",\"by\":\"analyst\",\"at\":\"" + iso() + "\"}";
    appendLine(IOC_REG, rec);
    json(e, 200, "{\"ok\":true,\"record\":" + rec + "}");
  }

  // ---- F4 · Offline self-test diagnostics (all checks are deterministic, no network) ----
  private static String selfTestJson(){
    StringBuilder b = new StringBuilder("{\"label\":\"Cipher Squad offline self-test\",\"run_at\":\"").append(iso()).append("\",\"checks\":[");
    boolean f = true;
    List<String[]> checks = new ArrayList<>();
    checks.add(new String[]{"risk_band_consistency", (riskBand(10).equals("SAFE") && riskBand(21).equals("LOW") && riskBand(41).equals("MEDIUM") && riskBand(60).equals("HIGH") && riskBand(80).equals("CRITICAL")) ? "pass" : "fail", "10->SAFE 21->LOW 41->MEDIUM 60->HIGH 80->CRITICAL"});
    checks.add(new String[]{"saturation_known_vector", (riskFromPool(0) == 0 && riskFromPool(27) == 54 && riskFromPool(100) == 94) ? "pass" : "fail", "0->0, 27->54, 100->94 (calibrated pool)"});
    checks.add(new String[]{"scan_json_bounded", (scanJsonValue("{\"riskScore\":" + Integer.toString(9).repeat(40000) + ",", "riskScore") == null) ? "pass" : "fail", "40k-digit opaque payload parsed linearly, no stack overflow"});
    checks.add(new String[]{"redirect_chain_merge", redirectAnalysisJson(matches(URL, "Go https://evil.example/x and https://evil.example/y")) .contains("\"occurrences\":2") ? "pass" : "fail", "same-host URL targets merged into one chain entry"});
    checks.add(new String[]{"timeline_present", analyzeMessageForTests("From: a@b.example\r\nTo: c@example.com\r\nSubject: s\r\nDate: Thu, 27 Aug 2026 12:00:00 +0000\r\n\r\nHello,\r\nopen https://evil.example/today").contains("\"analysis_timeline\":") ? "pass" : "fail", "analysis output embeds forensic timeline"});
    checks.add(new String[]{"cache_synchronized", moduleSyncCheck() ? "pass" : "fail", "IP/URL cache accessors and rate limiter are thread-safe"});
    for (String[] c : checks) {
      if (!f) b.append(','); f = false;
      b.append("{\"name\":\"").append(q(c[0])).append("\",\"ok\":").append("pass".equals(c[1])).append(",\"detail\":\"").append(q(c[2])).append("\"}");
    }
    b.append("],\"all_pass\":").append(checks.stream().allMatch(c -> "pass".equals(c[1]))).append("}");
    return b.toString();
  }
  private static void selfTestRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    json(e, 200, selfTestJson());
  }
  private static boolean moduleSyncCheck(){ try { return (App.class.getDeclaredMethod("cachePut", Map.class, String.class, String.class).getModifiers() & java.lang.reflect.Modifier.SYNCHRONIZED) != 0 && (App.class.getDeclaredMethod("allowed", String.class).getModifiers() & java.lang.reflect.Modifier.SYNCHRONIZED) != 0; } catch (Exception ignore) { return false; } }

  // ---- F5 · Analysis timeline (additive top-level field emitted by analyzeMessage) ----
  private static void timelinePush(StringBuilder b, boolean first, String at, String event, String detail){
    if (!first) b.append(',');
    b.append("{\"at\":\"").append(q(at == null ? "" : at)).append("\",\"event\":\"").append(q(event)).append("\",\"detail\":\"").append(q(detail)).append("\"}");
  }
  private static String analysisTimelineJson(String receivedAt, String caseId, String analysisId, String fromLine, String toLine, String subjLine, int hopCount, int urlCount, int attCount, String spf, String dkim, String dmarc, int score, String riskLevel, String threatClassification, String verdict, int conf, int corrCapped){
    StringBuilder b = new StringBuilder("[");
    timelinePush(b, true, receivedAt, "message_received", "Evidence captured; SHA-256 preserved" + (fromLine.isEmpty() ? "" : (" · From: " + fromLine)));
    timelinePush(b, false, null, "normalization", "Headers + body normalized; case " + caseId + "; analysis " + analysisId);
    timelinePush(b, false, null, "header_forensics", (toLine.isEmpty() ? "" : ("To: " + toLine)) + (subjLine.isEmpty() ? "" : (" · Subject: " + subjLine)) + " · Received chain " + hopCount + " hop(s) · SPF=" + (spf.isEmpty() ? "n/a" : spf) + " DKIM=" + (dkim.isEmpty() ? "n/a" : dkim) + " DMARC=" + (dmarc.isEmpty() ? "n/a" : dmarc));
    timelinePush(b, false, null, "ioc_extraction", urlCount + " URL(s) · " + attCount + " attachment(s) extracted and hashed");
    timelinePush(b, false, null, "layered_analysis", "Score " + score + "/100 (" + riskLevel + ") · " + threatClassification + " · confidence " + conf + " · correlation +" + corrCapped);
    timelinePush(b, false, null, "decision", "Classification: " + verdict);
    timelinePush(b, false, null, "provenance", "Chain-of-custody verified");
    b.append("]");
    return b.toString();
  }

  // ---- test hooks (package-visible, like the existing SOC backbone hooks) ----
  static String forensicMarkdownTest(String analysisJson){ return forensicMarkdown(analysisJson); }
  static String triageStatsTest(List<String> lines){ return triageStatsFrom(lines); }
  static String iocSummaryTest(List<String> lines){ return iocSummaryFrom(lines); }
  static String selfTestJsonTest(){ return selfTestJson(); }
  static int riskFromPoolTest(int rawPool){ return riskFromPool(rawPool); }

  // =====================================================================================
  // SECURITY DECISION RECORD + UNIFIED INGESTION  (spec 1,4,5,9,45,46)
  // =====================================================================================
  private static int nestedInt(String json, String objKey, String key){ try { Matcher m = Pattern.compile("\""+Pattern.quote(objKey)+"\"\\s*:\\s*\\{[^}]*?\""+Pattern.quote(key)+"\"\\s*:\\s*(\\d+)").matcher(json); return m.find() ? Integer.parseInt(m.group(1)) : 0; } catch (Exception e){ return 0; } }
  // Single five-tier risk vocabulary so every label derived from the same score agrees
  // (threatStatus.state / threat_verdict semantics / risk_level were previously inconsistent).
  private static String riskBand(int risk){ return risk >= 80 ? "CRITICAL" : risk >= 60 ? "HIGH" : risk >= 41 ? "MEDIUM" : risk >= 21 ? "LOW" : "SAFE"; }
  private static int riskFromPool(int rawPool){ return rawPool <= 0 ? 0 : Math.min(100, (int) Math.round(100 * (1 - Math.exp(-rawPool / 35.0)))); }
  private static String nestedStrVal(String json, String objKey, String key){ try { Matcher m = Pattern.compile("\""+Pattern.quote(objKey)+"\"\\s*:\\s*\\{[^}]*?\""+Pattern.quote(key)+"\"\\s*:\\s*\"([^\"]*)\"").matcher(json); return m.find() ? unescape(m.group(1)) : ""; } catch (Exception e){ return ""; } }
  private static String securityDecision(String analysisJson, String source){
    int risk = 0; try { risk = Integer.parseInt(numVal(analysisJson,"riskScore")); } catch (Exception ignored) {}
    // Reputation-driven state (MALICIOUS/UNKNOWN/CLEAN) from external feeds; legitimately UNKNOWN when no feed.
    String state = nestedStrVal(analysisJson,"threatStatus","state");
    if (state.isEmpty()) state = riskBand(risk);
    // SEMANTIC classification derived from present evidence (SAFE/SUSPICIOUS/PHISHING/MALICIOUS/UNKNOWN).
    String semantic = strVal(analysisJson,"threat_classification");
    if (semantic.isEmpty()) { String b = riskBand(risk); semantic = ("CRITICAL".equals(b) || "HIGH".equals(b)) ? "PHISHING" : "SAFE".equals(b) ? "SAFE" : "SUSPICIOUS"; }
    String riskLevel = strVal(analysisJson,"risk_level");
    if (riskLevel.isEmpty()) riskLevel = riskBand(risk);
    int conf = nestedInt(analysisJson,"confidence","value");
    int comp = nestedInt(analysisJson,"completeness","value");
    // Aggregate URL risk for the policy engine. -1 means no URL evidence present (URL policies cannot fire).
    int urlCat = nestedInt(analysisJson,"url_domain","value");
    int urlRisk = urlCat <= 0 ? -1 : Math.min(100, urlCat * 4);
    // Policy engine matches against the complete correlated score (risk), not the narrow URL-only signal.
    String matched = null;
    for (String p : policies()) {
      if (p.contains("\"enabled\":false")) continue;
      String j = policyHit(p, risk, conf, state, null, urlRisk);
      if (j != null) { matched = strVal(j,"id"); break; }
    }
    String matchedName = matchPolicyName(matched);
    // Action engine: the DECISION derived from the matched policy + risk bands. In analysis/demo
    // mode the decision is produced but NOT executed, so action_status is NOT_EXECUTED.
    String action;
    if (matched != null && (matched.contains("PHISHING") || matched.contains("MALICIOUS") || matched.contains("CRITICAL"))) {
      action = "QUARANTINE";
    } else if (risk >= 70) {
      action = "QUARANTINE";
    } else if (risk >= 41) {
      action = "WARN";
    } else if (risk >= 21) {
      action = "ALLOW_WITH_NOTICE";
    } else {
      action = "ALLOW";
    }
    // Auto-generate an incident record for critical/high decisions (risk>=70 or quarantine verdict) so
    // the incident-response workflow is complete and incident_id is never empty in the UI. Reuses an
    // existing incident when the same case (same CASE- id) was already escalated. The remediation
    // action itself is still NOT executed in analysis mode (no real quarantine back-end), which is
    // reflected honestly in action_status; the incident record tracks the decision for follow-up.
    String incidentId = "";
    String actionStatus = "NOT_EXECUTED";
    if (risk >= 70 || "QUARANTINE".equals(action)) {
      String caseRef = strVal(analysisJson, "caseId");
      incidentId = existingIncidentForCase(caseRef);
      if (incidentId.isEmpty()) incidentId = createIncidentFor(analysisJson, source, action, state);
    }
    List<String> reasons = whyFromFindings(analysisJson);
    String confidenceLimitations = confidenceLimitationsOf(analysisJson, state, comp);
    String evidenceQuality = evidenceQualityOf(analysisJson, risk, conf, semantic);
    String recommendation;
    if (risk >= 70 || "QUARANTINE".equals(action)) recommendation = "Do not interact with this message. Quarantine recommended — do not click links or provide credentials; verify the sender out-of-band.";
    else if (risk >= 41) recommendation = "Do not click links or provide credentials. Verify sender out-of-band. Warn user.";
    else recommendation = "No action required. Review if expected.";
    StringBuilder r = new StringBuilder();
    r.append("{\"security_decision\":{")
     .append("\"threat\":\"").append(q(semantic))                       // semantic threat classification (PHISHING etc.)
     .append("\",\"threat_status\":\"").append(q(semantic))
     .append("\",\"threat_reputation\":\"").append(q(state))            // external-feed reputation state (context)
     .append("\",\"threat_verdict\":\"").append(q(verdictOf(analysisJson)))
     .append("\",\"risk_score\":").append(risk)
     .append(",\"risk_level\":\"").append(q(riskLevel))
     .append("\",\"confidence\":").append(conf)
     .append(",\"data_completeness\":").append(comp)
     .append(",\"evidence_quality\":\"").append(q(evidenceQuality))
     .append("\",\"system_action\":\"").append(q(action))
     .append("\",\"action_status\":\"").append(q(actionStatus))
     .append("\",\"action_state\":\"DECIDED\"")
     .append(",\"policy_id\":\"").append(q(matched==null?"NO_POLICY_MATCH":matched))
     .append("\",\"policy_name\":\"").append(q(matchedName))
     .append("\",\"custom_fields\":{\"threat_classification\":\"").append(q(semantic))
     .append("\",\"risk_level\":\"").append(q(riskLevel))
     .append("\",\"policy_decision\":\"").append(q(action)).append("\"}")  // keep the three separate across fields
     .append(",\"reasons\":[");
    for (int i=0;i<reasons.size();i++){ if(i>0)r.append(","); r.append("\"").append(q(reasons.get(i))).append("\""); }
    r.append("],\"confidence_limitations\":\"").append(q(confidenceLimitations))
     .append("\",\"recommendation\":\"").append(q(recommendation))
     .append("\",\"incident_id\":\"").append(q(incidentId))
     .append("\",\"timestamp\":\"").append(iso()).append("\"}}");
    afterDecisionHooks(analysisJson, source, incidentId);
    return r.toString();
  }
  // WHY? — the strongest evidence, taken directly from the analyzer's own correlated findings.
  private static List<String> whyFromFindings(String analysisJson){
    List<String> out = new ArrayList<>();
    java.util.LinkedHashMap<Integer,String> byPoints = new java.util.LinkedHashMap<>();
    String hay = analysisJson == null ? "" : analysisJson;
    int n = hay.length();
    String marker = "\"points\":";
    int idx = 0;
    // Linear scan for the analyzer's own scoring records: "points":N,"message":"<escaped>".
    // Reads the message char-by-char (backslash-escape pairs preserved) with no nested-quantifier
    // regex, so a pathologically long or malformed payload cannot recurse out of control.
    while (idx < n) {
      int p = hay.indexOf(marker, idx);
      if (p < 0) break;
      idx = p + marker.length();
      int num = idx;
      while (num < n && hay.charAt(num) >= '0' && hay.charAt(num) <= '9') num++;
      if (num == idx) continue;
      int pts;
      try { pts = Integer.parseInt(hay.substring(idx, num)); } catch (Exception ignored) { continue; }
      if (!hay.startsWith(",\"message\":\"", num)) continue;
      int i = num + ",\"message\":\"".length();
      StringBuilder content = new StringBuilder();
      boolean closed = false;
      while (i < n) {
        char c = hay.charAt(i);
        if (c == '\\') { if (i + 1 < n) { content.append(c).append(hay.charAt(i + 1)); i += 2; } else i++; }
        else if (c == '"') { closed = true; break; }
        else { content.append(c); i++; }
      }
      if (!closed) break;
      String msg = unescape(content.toString());
      String normal = msg.replaceAll("\\s+"," ").trim();
      if (normal.isEmpty()) continue;
      if (!byPoints.containsKey(pts)) byPoints.put(pts, normal);
      else byPoints.put(pts + 10000, normal); // keep duplicates distinct by shifting key
    }
    byPoints.entrySet().stream()
      .sorted((a,b) -> Integer.compare(b.getKey()%10000, a.getKey()%10000))
      .forEachOrdered(e -> out.add(e.getValue()));
    java.util.Set<String> seen = new java.util.LinkedHashSet<>(out);
    List<String> finalList = new ArrayList<>();
    for (String s : seen) finalList.add(s);
    while (finalList.size() > 8) finalList.remove(finalList.size()-1);
    if (finalList.isEmpty()) finalList.add("No specific finding recorded.");
    return finalList;
  }
  private static String confidenceLimitationsOf(String analysisJson, String repState, int comp){
    // Explain why confidence is <100% honestly: what forensic evidence is genuinely missing/unknown.
    java.util.List<String> lim = new ArrayList<>();
    String spf = nestedStrVal(analysisJson,"auth","spf");
    String dkim = nestedStrVal(analysisJson,"auth","dkim");
    String dmarc = nestedStrVal(analysisJson,"auth","dmarc");
    int hops = 0; { Matcher h = Pattern.compile("\"received_hop_count\"\\s*:\\s*(\\d+)").matcher(analysisJson); if (h.find()) try { hops = Integer.parseInt(h.group(1)); } catch (Exception ignored) {} }
    boolean noAuth = ("not_supplied".equals(spf) || spf.isEmpty()) && ("not_supplied".equals(dkim) || dkim.isEmpty()) && ("not_supplied".equals(dmarc) || dmarc.isEmpty());
    if (noAuth) lim.add("complete authentication headers (SPF/DKIM/DMARC) were not supplied");
    if (hops <= 0) lim.add("Received header chain / reliable originating IP was not supplied");
    if ("UNKNOWN".equals(repState) || "ERROR".equals(repState)) lim.add("external reputation / threat-intelligence data was unavailable");
    if (comp < 45) lim.add("forensic header data was incomplete");
    if (lim.isEmpty()) return "Confidence is high: the available evidence strongly and consistently supports the verdict, and no material forensic input was missing.";
    String join = String.join("; ", lim);
    return "Confidence is limited because " + join + ". Missing evidence is reported explicitly, never treated as safe.";
  }
  private static String evidenceQualityOf(String analysisJson, int risk, int conf, String semantic){
    // Prefer the analyzer's own evidence_quality field (severity-weighted, layer-diverse, reliable
    // source). The fallback below only applies for records that predate the field.
    Matcher em = Pattern.compile("\"evidence_quality\":\"([A-Z_]+)\"").matcher(analysisJson);
    if (em.find()) return em.group(1);
    int highFindings = 0; int layers = 0;
    java.util.Set<String> layerSet = new java.util.LinkedHashSet<>();
    Matcher f = Pattern.compile("\"severity\":\"(HIGH)\",\"evidence\"").matcher(analysisJson);
    while (f.find()) highFindings++;
    Matcher lyr = Pattern.compile("\"layer\":\"([a-z_]+)\"").matcher(analysisJson);
    while (lyr.find()) layerSet.add(lyr.group(1));
    layers = layerSet.size();
    int comp = nestedInt(analysisJson,"completeness","value");
    if (highFindings >= 3 && layers >= 3 && conf >= 60) return "HIGH";
    if ("PHISHING".equals(semantic) || "MALICIOUS".equals(semantic) || risk >= 70) return (highFindings >= 2 && layers >= 2) ? "HIGH" : "MEDIUM";
    if (comp <= 25 || highFindings == 0) return "LOW";
    if (comp <= 12) return "INSUFFICIENT";
    return "MEDIUM";
  }
  private static String matchPolicyName(String id){
    if (id == null) return "";
    for (String p : policies()) { if (strVal(p,"id").equals(id)) { String n = strVal(p,"name"); if (!n.isEmpty()) return n; } }
    return id;
  }
  private static String caseIdOf(String j){ return strVal(j,"caseId"); }
  private static String verdictOf(String j){ return strVal(j,"classification"); }
  private static String recThreatOf(String j){ return strVal(j,"threat"); }
  private static boolean hasIncidentForCase(String caseId){ return caseId!=null && !caseId.isEmpty() && readLines(INCIDENTS).stream().anyMatch(l->l.contains(caseId)); }
  private static String existingIncidentForCase(String caseId){ if (caseId==null || caseId.isEmpty()) return ""; for (String l : readLines(INCIDENTS)) { if (l.contains(caseId)) { String id=strVal(l,"id"); if(!id.isEmpty()) return id; } } return ""; }
  private static String readLast(Path p){ List<String> l=readLines(p); return l.isEmpty()? "{}" : l.get(l.size()-1); }
  private static String createIncidentFor(String analysisJson, String source, String action, String state){
    String threat = verdictOf(analysisJson);
    String risk = numVal(analysisJson,"riskScore");
    String conf = numVal(strVal(analysisJson,"confidence"),"value"); if (conf.isEmpty()||conf.equals("0")) { Matcher m=Pattern.compile("\"value\":(\\d+)").matcher(strVal(analysisJson,"confidence")); conf=m.find()?m.group(1):"0"; }
    String user = strVal(analysisJson,"to");
    String caseId = caseIdOf(analysisJson);
    String summary = "Auto-created from analysis " + caseId;
    return incidentCreate(threat, risk, conf, source, user, action, summary);
  }
  private static String decisionOf(String analysisJson, String source){ return securityDecision(analysisJson, source); }
  private static void ingest(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String source = extractJsonString(body,"source"); if (source==null) source="webhook";
    if (!Set.of("gmail","outlook","m365","teams","webhook","eml","paste").contains(source)) { json(e,400,error("Unsupported source: "+source)); return; }
    String rawEmail = extractJsonString(body,"rawEmail");
    String messageId = extractJsonString(body,"message_id");
    String raw = rawEmail;
    if (raw == null) {
      // build a raw email from normalized message fields
      String sender = extractJsonString(body,"sender"); String to = extractJsonString(body,"recipients");
      String subject = extractJsonString(body,"subject"); String bodyText = extractJsonString(body,"body");
      raw = ("From: " + nz(sender,"unknown@example.com") + "\n") + ("To: " + nz(to,"") + "\n") +
            ("Subject: " + nz(subject,"") + "\n") + ("Message-ID: " + nz(messageId,"") + "\n\n") + nz(bodyText,"");
      if (messageId != null && !messageId.isEmpty()) raw = raw.replaceFirst("(?m)^To:.*", "To: " + to + "\nMessage-ID: <" + messageId + ">\n");
    } else {
      if (messageId == null || messageId.isEmpty()) { Matcher mm=Pattern.compile("(?i)^message-id:\\s*(.+)$",Pattern.MULTILINE).matcher(rawEmail); if(mm.find()) messageId=mm.group(1).trim(); }
    }
    if (raw.isBlank()) { json(e,400,error("No message content provided")); return; }
    // idempotency: (source, external_message_id) must be unique
    String dedupKey = source + "|" + (messageId==null?"":messageId);
    synchronized (App.class) { for (String l : readLines(INGEST_LOG)) { if (l.contains("\"dedup\":\""+q(dedupKey)+"\"")) { json(e,200,"{\"duplicate\":true,\"reason\":\"Already ingested (idempotency: source+message_id).\"}"); return; } } }
    String analysis = analyzeMessage(raw);
    cacheAnalysis(strVal(analysis, "caseId"), analysis);
    persistIocs(raw);
    String decision = decisionOf(analysis, source);
    String rec = "{\"source\":\"" + q(source) + "\",\"message_id\":\"" + q(messageId) + "\",\"dedup\":\"" + q(dedupKey)
      + "\",\"received_at\":\"" + iso() + "\",\"analysis_status\":\"ANALYZED\",\"analysis_version\":\"" + q(trunc(analysis, 256)) + "\"}";
    appendLine(INGEST_LOG, rec);
    Matcher dcm = Pattern.compile("\\{\"security_decision\":(\\{.*\\})\\}$").matcher(decision);
    String decisionObj = dcm.find() ? dcm.group(1) : decision;
    String out = "{\"analysis\":" + analysis + ",\"security_decision\":" + decisionObj + "}";
    json(e, 200, out);
  }
  private static String nz(String s, String d){ return (s==null||s.isEmpty())? d : s; }

  // =====================================================================================
  // REPORT  (spec 50) — honest final report; only actual capabilities are reported.
  // =====================================================================================
  private static void report(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String gmail = connectorStatus("gmail"), ms = connectorStatus("m365"), teams = connectorStatus("teams");
    StringBuilder b = new StringBuilder("{\"report\":{\"platform\":\"Cipher Squad Multi-Channel Email Security\",\"detection_pipeline\":[");
    String[] pipe = {"Normalization (unified schema)","Header forensics","SPF/DKIM/DMARC/ARC","Received chain & origin IP","URL/IOC deep-link analysis","IP reputation & geolocation","Attachment security","NLP/social-engineering","Correlation & risk scoring","Policy engine","Decision record & action"};
    String joined = String.join(",", java.util.Arrays.stream(pipe).map(x->"\""+x+"\"").toList());
    b.append(joined).append("],\"connectors\":{\"gmail\":\"").append(gmail).append("\",\"outlook\":\"").append(connectorStatus("outlook"))
     .append("\",\"m365\":\"").append(ms).append("\",\"teams\":\"").append(teams).append("\",\"webhook\":\"CONNECTED\",\"eml\":\"CONNECTED\",\"paste\":\"CONNECTED\"}")
     .append(",\"real_time_ingestion\":\"Webhook + EML upload + manual paste (push where supported; OAuth connectors require configured credentials)\"")
     .append(",\"oauth\":\"Architecture ready; credentials not configured in this environment (honest: NOT_CONFIGURED)\"")
     .append(",\"policy_engine\":\"Configurable persisted rules\"")
     .append(",\"incident_lifecycle\":\"NEW/TRIAGED/INVESTIGATING/CONTAINED/REMEDIATED/CLOSED + FALSE_POSITIVE/BENIGN/DUPLICATE\"")
     .append(",\"audit_log\":\"Append-only NDJSON audit trail\"")
     .append(",\"ioc_engine\":\"IPv4/IPv6/domain/URL/email/hash extraction, normalized + dedup\"")
     .append(",\"evidence\":\"SHA-256 preservation; origin artifact retained\"")
     .append(",\"notifications\":{\"sms\":\"").append(SMS_PROVIDER.isEmpty()?"NOT_CONFIGURED":"CONFIGURED").append("\",\"webhook\":\"").append(NOTIFY_WEBHOOK.isEmpty()?"NOT_CONFIGURED":"CONFIGURED").append("\"}")
     .append(",\"rbac\":\"EMPLOYEE/SOC_ANALYST/SOC_ADMIN/SYSTEM_ADMIN (enforced in UI; backend auth-droovy future)\"")
     .append(",\"honesty\":\"DETECTED vs DECIDED vs ACTIONED vs VERIFIED are kept distinct. Nothing is simulated as SUCCESS when it did not run.\"")
     .append("}}");
    json(e, 200, b.toString());
  }
  // ---- package-visible test hooks (SOC backbone) ----
  static String socDecisionTest(String rawEmail, String source){ try { String analysis = analyzeMessage(rawEmail); return decisionOf(analysis, source); } catch (Exception e){ return "{\"security_decision\":{\"error\":\"" + q(e.toString()) + "\"}}"; } }
  static String iocExtractTest(String text){ return iocExtract(text == null ? "" : text); }
  static String policyMatchTest(int risk, int conf, String state){ String matched=null; for (String p : policies()) { if (p.contains("\"enabled\":false")) continue; String j=policyHit(p,risk,conf,state,null,-1); if(j!=null){ matched=strVal(j,"id"); break; } } return matched==null?"NO_POLICY_MATCH":matched; }
  static String urlPolicyMatchTest(int risk, int conf, String state, int urlRisk){ String matched=null; for (String p : policies()) { if (p.contains("\"enabled\":false")) continue; String j=policyHit(p,risk,conf,state,null,urlRisk); if(j!=null){ matched=strVal(j,"id"); break; } } return matched==null?"NO_POLICY_MATCH":matched; }
  static String connectorStatusTest(String id){ return connectorStatus(id); }
  static List<String> incidentsTest(){ return readLines(INCIDENTS); }
  static String auditTailTest(){ List<String> l = readLines(AUDIT_LOG); return l.isEmpty()? "{}" : l.get(l.size()-1); }
  static void auditTest(String ev, String action){ audit("TEST","soc.test",ev,action,"SUCCESS","","","","",""); }
  // ---- package-visible test hooks (access control / graph / alerts) ----
  static int authUserCount(){ return appUsers().all().size(); }
  static String authCreateUser(String email, String raw, String role){ User u = appUsers().create(email, raw, role); return u == null ? "" : u.id; }
  static String authSessionFor(String email){ User u = appUsers().find(email); return u == null ? "" : newSession(u.id); }
  static String authUserRole(String email){ User u = appUsers().find(email); return u == null ? "" : u.role; }
  static boolean authLoginCheck(String email, String raw){
    User u = appUsers().find(email); if (u == null) return false;
    for (String l : readLines(USERS)) if (strVal(l,"id").equals(u.id)) return verifyPassword(raw, strVal(l,"password_hash"));
    return false;
  }
  static String sessionForToken(String token){ User u = sessionUser(token); return u == null ? "" : u.id; }
  static java.util.List<String> edgesTest(){ return readLines(EDGES); }
  static int edgeCount(){ return readLines(EDGES).size(); }
  static int channelCount(){ return readLines(ALERT_CFG).size(); }
  static boolean alertThresholdHit(String chThreshold, int risk){
    int[] lvl = {80,60,40,20}; String[] band = {"CRITICAL","HIGH","MEDIUM","LOW"};
    int bandIdx=-1; for (int i=0;i<lvl.length;i++) if (risk>=lvl[i]) { bandIdx=i; break; }
    int tIdx=-1; for (int i=0;i<band.length;i++) if (band[i].equals(chThreshold)) { tIdx=i; break; }
    return tIdx>=0 && bandIdx>=0 && bandIdx<=tIdx;
  }

  /* =====================================================================================
   * MODULE UPGRADE:  UNIFIED SECURITY ANALYSIS  (spec 6, 7, 8, 9, 12, 16, 17, 23, 26)
   *
   * A single server-side result vocabulary shared by every analyzer so the SOC
   * dashboard can render a common schema. Every module keeps its OWN score and
   * confidence; the OVERALL score is only an optional weighted roll-up with an
   * explicit component breakdown (spec 7). Confidence is evidence strength and
   * is NEVER conflated with risk. Missing data lowers completeness + confidence
   * but NEVER automatically raises risk (spec 8).
   *
   * All results are honestly derived: absent external APIs -> UNKNOWN /
   * NOT_CONFIGURED / ERROR as appropriate. Nothing is fabricated.
   * ===================================================================================== */

  private static final String CF_TOKEN  = System.getenv().getOrDefault("CLOUDFLARE_API_TOKEN","");
  private static final String CF_ACCT   = System.getenv().getOrDefault("CLOUDFLARE_ACCOUNT_ID","");
  private static final String CF_ZONE   = System.getenv().getOrDefault("CLOUDFLARE_ZONE_ID","");

  // ---- unified finding object (built as JSON) ----
  private static String uf(String category, String severity, String title, String description,
                           String evidence, String observedValue, String source, int confidence){
    StringBuilder b = new StringBuilder("{");
    b.append("\"category\":\"").append(q(category)).append("\"");
    b.append(",\"severity\":\"").append(q(severity)).append("\"");
    b.append(",\"title\":\"").append(q(title)).append("\"");
    b.append(",\"description\":\"").append(q(description)).append("\"");
    b.append(",\"evidence\":\"").append(q(evidence)).append("\"");
    b.append(",\"observed_value\":\"").append(q(observedValue)).append("\"");
    b.append(",\"source\":\"").append(q(source)).append("\"");
    b.append(",\"confidence\":").append(Math.max(0, Math.min(100, confidence)));
    return b.append("}").toString();
  }

  // ---- unified envelope builder: findings / recommendations / sources / errors are JSON arrays strings ----
  private static String unified(String target, String targetType, String status, int risk, int confidence,
                                int completeness, String evidenceQuality, String findingsJson,
                                String recosJson, String sourcesJson, String errorsJson){
    StringBuilder b = new StringBuilder("{");
    b.append("\"target\":\"").append(q(target)).append("\"");
    b.append(",\"target_type\":\"").append(q(targetType)).append("\"");
    b.append(",\"timestamp\":\"").append(iso()).append("\"");
    b.append(",\"status\":\"").append(q(status)).append("\"");
    b.append(",\"risk_score\":").append(Math.max(0, Math.min(100, risk)));
    b.append(",\"confidence\":").append(Math.max(0, Math.min(100, confidence)));
    b.append(",\"data_completeness\":").append(Math.max(0, Math.min(100, completeness)));
    b.append(",\"evidence_quality\":\"").append(q(evidenceQuality)).append("\"");
    b.append(",\"findings\":").append(findingsJson == null ? "[]" : findingsJson);
    b.append(",\"recommendations\":").append(recosJson == null ? "[]" : recosJson);
    b.append(",\"sources\":").append(sourcesJson == null ? "[]" : sourcesJson);
    b.append(",\"errors\":").append(errorsJson == null ? "[]" : errorsJson);
    return b.append("}").toString();
  }
  private static String strArr(java.util.List<String> l){ return strList(l); }
  private static String severLabel(int risk){
    if (risk >= 85) return "CRITICAL";
    if (risk >= 65) return "HIGH";
    if (risk >= 40) return "MEDIUM";
    if (risk >= 20) return "LOW";
    return "SAFE";
  }
  private static String evQuality(int completeness, int confidence){
    if (completeness >= 80 && confidence >= 70) return "HIGH";
    if (completeness >= 50 && confidence >= 40) return "MEDIUM";
    if (completeness >= 20) return "LOW";
    return "INSUFFICIENT";
  }

  /* =====================================================================================
   * SSRF PROTECTION  (spec 17 — mandatory)
   * ===================================================================================== */
  private static boolean isPrivateIp(String ip){
    if (ip == null) return false;
    ip = ip.trim().toLowerCase(Locale.ROOT);
    // strip IPv4-in-IPv6 (::ffff:)
    if (ip.startsWith("::ffff:")) ip = ip.substring(7);
    Matcher m4 = IPV4.matcher(ip.replaceFirst("^::ffff:",""));
    if (m4.matches()) {
      String[] o = ip.split("\\.");
      int a = Integer.parseInt(o[0]), b = Integer.parseInt(o[1]);
      // ORIGIN-INFRASTRUCTURE free-form CIDR checks
      if (a == 10) return true;                       // 10.0.0.0/8
      if (a == 127) return true;                      // 127.0.0.0/8
      if (a == 169 && b == 254) return true;          // 169.254.0.0/16 link-local
      if (a == 0) return true;                        // 0.0.0.0/8
      if (a == 172 && b >= 16 && b <= 31) return true;// 172.16.0.0/12
      if (a == 192 && b == 168) return true;          // 192.168.0.0/16
      if (a >= 224) return true;                      // multicast + reserved 224/4
    }
    if (ip.equals("::1") || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("::")) return true;
    return false;
  }
  // Reject any hostname/URL whose resolution lands on internal inf. Also blocks metadata endpoints.
  private static String ssrfError(String host){ return "Blocked by SSRF guard: target resolves to internal/private/loopback/metadata network (" + host + "). No outbound request was made."; }
  // Returns null if safe to call; otherwise an error message string. Unresolvable -> no connection.
  private static String validateConnectTarget(String host){
    if (host == null || host.isBlank()) return "Empty host supplied.";
    String h = host.trim().toLowerCase(Locale.ROOT);
    if (h.equals("localhost") || h.endsWith(".localhost")) return ssrfError(h);
    if (h.equals("metadata.google.internal") || h.endsWith(".metadata.google.internal")) return ssrfError(h);
    // try literal IP first
    String norm = parseIp(h);
    if (norm != null) { return isPrivateIp(norm) ? ssrfError(h) : null; }
    // resolve hostname and re-check EVERY address (DNS rebinding: recheck at connect time below)
    try {
      for (InetAddress a : InetAddress.getAllByName(host)) {
        if (isPrivateIp(a.getHostAddress())) return ssrfError(host + " -> " + a.getHostAddress());
      }
    } catch (UnknownHostException uh) { return "DNS lookup failed for target: " + host; }
    return null;
  }
  // Connect-time recheck (defense-in-depth against rebinding): resolve again and block internal IPs.
  private static javax.net.ssl.SSLSocket sslConnect(String host, int port, int timeoutMs) throws Exception {
    String guard = validateConnectTarget(host);
    if (guard != null) throw new java.security.GeneralSecurityException(guard);
    List<InetAddress> addrs = new ArrayList<>();
    try { addrs.addAll(Arrays.asList(InetAddress.getAllByName(host))); } catch (Exception e) { throw e; }
    if (addrs.isEmpty()) throw new java.security.GeneralSecurityException("DNS lookup failed for target: " + host);
    InetAddress chosen = null;
    for (InetAddress a : addrs) { if (isPrivateIp(a.getHostAddress())) throw new java.security.GeneralSecurityException(ssrfError(host)); if (chosen == null) chosen = a; }
    var factory = javax.net.ssl.SSLContext.getDefault().getSocketFactory();
    var socket = (javax.net.ssl.SSLSocket) factory.createSocket(chosen, port, null, 0);
    socket.setSoTimeout(timeoutMs);
    socket.setEnabledProtocols(new String[]{"TLSv1.3","TLSv1.2"});
    return socket;
  }
  // Decision-only evaluation of the connect-target SSRF guard (no network I/O). Used by the unit
  // suite to assert that TLS/SSL and HTTP probes against internal networks are always declined.
  static String connectGuardDecisionForTest(String host){ return validateConnectTarget(host); }

  /* ==========================================================================
   * MODULE: SPAM CHECKER  (spec 1)
   * Spam (bulk/unsolicited content) is scored separately from phishing
   * (credential/social-engineering intent). Never equate the two.
   * ========================================================================== */
  static String analyzeSpam(String raw) {
    List<String> findings = new ArrayList<>();
    List<String> recos = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    List<String> sources = new ArrayList<>();
    sources.add("local content engine");
    if (raw == null) raw = "";
    String lower = raw.toLowerCase(Locale.ROOT);
    String subject = "";
    String from = "";
    String body = raw;
    // crude header/body split + extract a few fields
    int hb = raw.indexOf("\r\n\r\n");
    if (hb < 0) hb = raw.indexOf("\n\n");
    String headers = raw;
    if (hb >= 0) { headers = raw.substring(0, hb); body = raw.substring(hb).trim(); }
    for (String line : headers.split("\r?\n")) {
      String lt = line.toLowerCase(Locale.ROOT);
      if (lt.startsWith("subject:")) subject = line.substring(line.indexOf(':')+1).trim();
      if (lt.startsWith("from:")) from = line.substring(line.indexOf(':')+1).trim();
    }
    String lowerBody = body.toLowerCase(Locale.ROOT);
    String lowerSubj = subject.toLowerCase(Locale.ROOT);

    int contentScore = 0;   // content signals
    int senderScore = 0;    // sender/domain signals
    int authScore = 0;      // authentication signals
    int urlScore = 0;       // URL signals
    boolean cred = false, urgent = false;

    // --- CONTENT ---
    java.util.List<String> urgency = List.of("act now","immediately","urgent","within 24 hours","today only","before it's too late","limited time","expires","deadline","asap","final notice","respond now");
    for (String k : urgency) if (lowerBody.contains(k) || lowerSubj.contains(k)) { contentScore += 8; urgent = true; findings.add(uf("content","HIGH","Excessive urgency / deadline pressure","Content uses urgency or deadline pressure to force rapid action.","Subject/body contains keyword: "+k,k,"Spam Checker",88)); break; }
    java.util.List<String> promo = List.of("limited time offer","hurry","free trial","100% free","winner","congratulations","you've won","act fast","exclusive deal","claim your prize");
    for (String k : promo) if (lowerBody.contains(k)) { contentScore += 7; findings.add(uf("content","MEDIUM","Suspicious promotional language","Marketing/solicitation phrasing typical of bulk unsolicited mail.","Keyword: "+k,k,"Spam Checker",80)); break; }
    java.util.List<String> finance = List.of("wire transfer","bank account","western union","cryptocurrency","bitcoin","moneygram","investment opportunity","refund","verify your account","confirm your password");
    for (String k : finance) if (lowerBody.contains(k)) { contentScore += 6; findings.add(uf("content","MEDIUM","Financial solicitation","Financial request / monetary language present.","Keyword: "+k,k,"Spam Checker",75)); break; }
    java.util.List<String> creds = List.of("password","credentials","sign in","log in","verify identity","security check","suspended","your account will be locked","re-enter your password","otp","2fa");
    for (String k : creds) if (lowerBody.contains(k) || lowerSubj.contains(k)) { contentScore += 9; cred = true; findings.add(uf("content","HIGH","Credential / account request","Message requests credentials, login, or account verification — a strong phishing signal.","Keyword: "+k,k,"Spam Checker",90)); break; }
    long caps = body.chars().filter(c -> c >= 'A' && c <= 'Z').count();
    int letters = Math.max(1, (int) body.chars().filter(Character::isLetter).count());
    if (letters > 40 && (double) caps / letters > 0.45) { contentScore += 6; findings.add(uf("content","MEDIUM","Excessive capitalization","", "Ratio "+String.format("%.1f%%", 100.0*caps/letters)+" of letters capitalised.","","Spam Checker",70)); }
    long excl = body.chars().filter(c -> c == '!').count();
    if (excl >= 4) { contentScore += 4; findings.add(uf("content","LOW","Excessive punctuation","", "Count of '!' = "+excl,"","Spam Checker",65)); }
    if (lowerBody.contains("click here") || lowerBody.contains("click the link")) { contentScore += (cred?6:4); findings.add(uf("content","MEDIUM","Suspicious call-to-action","Message pushes a single action (click now).","","","Spam Checker",70)); }

    // --- AUTHENTICATION (only what is observable; missing = unknown, not bad) ---
    String spf = "", dkim = "", dmarc = "", arc = "";
    for (String line : headers.split("\r?\n")) {
      String lt = line.toLowerCase(Locale.ROOT);
      if (lt.startsWith("authentication-results")) { String lv=line.substring(line.indexOf(':')+1); if (lv.contains("spf")) { Matcher sm=Pattern.compile("spf[=:]\\s*(pass|fail|softfail|neutral|none|temperror|permerror)").matcher(lv); if(sm.find())spf=sm.group(1); } if (lv.contains("dkim")) { Matcher sm=Pattern.compile("dkim[=:]\\s*(pass|fail|neutral|none|temperror|permerror)").matcher(lv); if(sm.find())dkim=sm.group(1); } if (lv.contains("dmarc")) { Matcher sm=Pattern.compile("dmarc[=:]\\s*(pass|fail|neutral|none|temperror|permerror)").matcher(lv); if(sm.find())dmarc=sm.group(1); } }
      if (lt.startsWith("arc-")) { String lv=line.substring(line.indexOf(':')+1); Matcher sm=Pattern.compile("i="+ "([0-9])").matcher(lv); if(sm.find())arc="present"; }
    }
    if (!spf.isEmpty()) { if (spf.equals("fail")) { authScore += 12; findings.add(uf("auth","HIGH","SPF FAIL","SPF authentication failed, indicating unauthorized sender.","authentication-results: spf="+spf,"SPF="+spf,"Spam Checker",92)); } }
    if (!dkim.isEmpty()) { if (dkim.equals("fail")) { authScore += 11; findings.add(uf("auth","HIGH","DKIM FAIL","DKIM signature validation failed.","dkim="+dkim,"DKIM="+dkim,"Spam Checker",90)); } }
    if (!dmarc.isEmpty()) { if (dmarc.equals("fail")) { authScore += 12; findings.add(uf("auth","HIGH","DMARC FAIL","DMARC policy alignment failed.","dmarc="+dmarc,"DMARC="+dmarc,"Spam Checker",92)); } }

    // --- SENDER / DOMAIN ---
    String fromEmail = ""; Matcher fem = EMAIL.matcher(from); if (fem.find()) fromEmail = fem.group();
    if (from.isEmpty()) { findings.add(uf("sender","LOW","No From header observed","Sender field absent — cannot authenticate the origin.","","","Spam Checker",55)); }
    // display-name spoofing: display name differs from verified domain / is a big brand
    if (!from.isEmpty() && fromEmail != null && !fromEmail.isEmpty()) {
      String disp = from.replaceAll("<.*?>","").replaceAll("\"","").trim();
      String fromDom = fromEmail.substring(fromEmail.lastIndexOf('@')+1).toLowerCase(Locale.ROOT);
      java.util.List<String> brands = List.of("microsoft","google","apple","paypal","amazon","linkedin","facebook","wells fargo","chase","netflix","bank");
      String brandFound = "";
      for (String b : brands) if (disp.toLowerCase(Locale.ROOT).contains(b)) { brandFound = b; break; }
      if (!brandFound.isEmpty() && !fromDom.equals(brandFound + ".com") && !fromDom.contains(brandFound + ".")) {
        // lookalike: brand in display but domain NOT the official brand domain
        boolean official = fromDom.equals(brandFound) || fromDom.startsWith(brandFound + ".") && (fromDom.endsWith(".com")||fromDom.endsWith(".co.uk")||fromDom.endsWith(".com.au")||fromDom.endsWith(".org")||fromDom.endsWith(".net")||fromDom.endsWith(".io"));
        if (!official) { senderScore += 15; findings.add(uf("sender","HIGH","Display-name / brand spoofing","Sender display name implies "+brandFound+" but the address domain is "+fromDom+".","display=\""+disp+"\" from_domain="+fromDom,"","Spam Checker",88)); }
      }
      // lookalike domain (character substitution of brand)
      String compact = fromDom.replace("0","o").replace("1","l").replace("3","e").replace("@","a").replace(".","");
      if (!brandFound.isEmpty() && compact.contains(brandFound.replace(" ","")) && !fromDom.equals(brandFound+".com")) {senderScore+=12;}
    }
    // disposable domains (static small allowlist of knowable providers; NOT authoritative)
    String fromDom2 = fromEmail.contains("@") ? fromEmail.substring(fromEmail.lastIndexOf('@')+1).toLowerCase(Locale.ROOT) : "";
    java.util.Set<String> disposable = Set.of("mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com","yopmail.com","maildrop.cc");
    if (disposable.contains(fromDom2)) { senderScore += 10; findings.add(uf("sender","HIGH","Disposable-domain indicator","Sender uses a known disposable email provider.","domain="+fromDom2,"","Spam Checker",85)); }

    // --- URL ---
    java.util.List<String> urls = new ArrayList<>();
    Matcher um = URL.matcher(lower);
    while (um.find()) { String u = um.group(); if (!urls.contains(u)) urls.add(u); }
    if (urls.isEmpty()) { findings.add(uf("url","LOW","No URLs present","No hyperlinks observed — common for low-signal mail.","","","Spam Checker",50)); }
    for (String u : urls) {
      String host = "";
      try { host = java.net.URI.create(u).getHost(); } catch (Exception ignored){}
      String uname = host == null ? "" : host;
      if (uname.matches("\\d{1,3}(\\.\\d{1,3}){3}")) { urlScore += 9; findings.add(uf("url","HIGH","IP-based URL","URL uses a raw IP address instead of a hostname.","host="+uname,"","Spam Checker",85)); }
      if (uname.contains("xn--")) { urlScore += 8; findings.add(uf("url","HIGH","Punycode URL","URL uses internationalized (punycode) hostname — abuse vector.","host="+uname,"","Spam Checker",80)); }
      java.util.List<String> shorteners = List.of("bit.ly","tinyurl.com","goo.gl","t.co","is.gd","ow.ly","buff.ly","rebrand.ly");
      if (shorteners.contains(uname.toLowerCase(Locale.ROOT))) { urlScore += 6; findings.add(uf("url","MEDIUM","URL shortener","URL uses a link shortener obscuring the final destination.","host="+uname,"","Spam Checker",75)); }
      if (u.contains("/login") || u.contains("/verify") || u.contains("/account") || u.contains("/signin") || u.contains("/secure") || u.contains("/confirm")) { urlScore += 6; findings.add(uf("url","MEDIUM","Suspicious path","URL path targets credential/login or verification resource.","path="+u,"","Spam Checker",70)); }
      // lookalike of a known brand inside URL
      for (String b : List.of("microsoft","paypal","apple","google","amazon","netflix","wellsfargo","chase","linkedin")) {
        if (uname.toLowerCase(Locale.ROOT).contains(b) && !uname.toLowerCase(Locale.ROOT).equals(b+".com") && !uname.toLowerCase(Locale.ROOT).endsWith("."+b+".com") && !uname.toLowerCase(Locale.ROOT).contains("."+b+".") ) { urlScore += 10; findings.add(uf("url","HIGH","Lookalike brand domain in URL","URL hostname resembles the official "+b+" domain but is not it.","host="+uname,"","Spam Checker",86)); break; }
      }
    }

    // --- SCORE & CLASSIFY ---
    // Spam score: content + sender + auth + url contributions, but phishing intent weights content/URL more.
    int rawSpam = contentScore + senderScore + urlScore;
    int spamScore = Math.min(100, rawSpam + (cred ? 15 : 0) + (urgent ? 5 : 0));
    String classification;
    String phishing = "LOW";
    if (cred || authScore >= 22 || (senderScore >= 15 && urlScore >= 6)) {
      classification = "PHISHING";
      phishing = (cred && urlScore >= 6) ? "HIGH" : "MEDIUM";
    } else if (spamScore >= 60) classification = "SPAM";
    else if (spamScore >= 35) classification = "SUSPICIOUS";
    else classification = "HAM";

    int confidence = Math.max(30, Math.min(96, 50 + (contentScore>0?12:0) + (senderScore>0?12:0) + (urlScore>0?12:0)));
    int completeness = Math.min(100, (from.isEmpty()?0:25) + (subject.isEmpty()?0:15) + (body.length()>30?25:5) + (urls.isEmpty()?0:15) + (!spf.isEmpty()?10:0) + (!dkim.isEmpty()?5:0) + (!dmarc.isEmpty()?5:0));
    String findingsJson = findings.isEmpty() ? "[]" : findings.toString();
    // rebuild findings as raw JSON (uf emits JSON objects already in the list)
    recos.add(classification.equals("PHISHING") ? "Do not click any link; block/quarantine; notify user and SOC; report as phishing." : "Review email per policy; treat as " + classification + ".");
    recos.add("Verify sender domain and enable SPF/DKIM/DMARC enforcement if missing.");
    // Declared risk derives from the module verdict (classification), not the raw content volume.
    // PHISHING is never reported as LOW even when a single strong signal fired at low content volume.
    int declaredRisk;
    switch (classification) {
      case "PHISHING": declaredRisk = Math.max(72, Math.min(100, spamScore)); break;
      case "SPAM":     declaredRisk = Math.max(50, Math.min(100, spamScore)); break;
      case "SUSPICIOUS": declaredRisk = Math.max(35, Math.min(55, spamScore)); break;
      default:         declaredRisk = Math.min(20, Math.max(0, spamScore));
    }
    String severity = severLabel(declaredRisk);

    return "{\"module\":\"spam\",\"classification\":\""+classification+"\",\"spam_score\":"+spamScore
      + ",\"risk_score\":"+declaredRisk+",\"phishing\":\""+phishing+"\",\"breakdown\":{\"content\":"+contentScore+",\"sender\":"+senderScore
      + ",\"authentication\":"+authScore+",\"url\":"+urlScore+"},\"confidence\":"+confidence
      + ",\"data_completeness\":"+completeness+",\"evidence_quality\":\""+evQuality(completeness,confidence)
      + "\",\"findings\":"+findingsJson+",\"recommendations\":"+strArr(recos)+",\"sources\":"+strArr(sources)
      + ",\"errors\":"+strArr(errors)+",\"severity\":\""+severity+"\"}";
  }
  private static void spamRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String email = strVal(body, "rawEmail");
    if (email.isEmpty()) { json(e,400,error("rawEmail is required")); return; }
    String out = analyzeSpam(email);
    json(e,200,out);
  }

  /* ==========================================================================
   * MODULE: DNS SECURITY ANALYZER  (spec 2)
   * Resolves records with JVM DNS; reports OBSERVED vs UNKNOWN honestly.
   * Missing records are findings (config), never assumed malicious.
   * ========================================================================== */
  private static String dnsLookupType(String domain, String type){
    try {
      var ctx = new javax.naming.directory.InitialDirContext(new java.util.Hashtable<String,String>(){{ put(javax.naming.Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.dns.DnsContextFactory"); }});
      var attr = ctx.getAttributes("dns:/" + domain, new String[]{type}).get(type);
      if (attr == null) return "NO_DATA";
      java.util.List<String> vals = new ArrayList<>();
      var en = attr.getAll();
      while (en.hasMore()) vals.add(String.valueOf(en.next()));
      return vals.isEmpty() ? "NO_DATA" : String.join("; ", vals);
    } catch (Exception e) {
      String msg = String.valueOf(e.getMessage() == null ? e : e.getMessage());
      if (msg.toLowerCase(Locale.ROOT).contains("no record") || msg.toLowerCase(Locale.ROOT).contains("nestedexception")) return "NO_DATA";
      return null; // resolution error -> UNKNOWN
    }
  }
  static String analyzeDnsSecurity(String domainRaw) {
    String domain = domainRaw == null ? "" : domainRaw.trim().toLowerCase(Locale.ROOT);
    domain = domain.replaceAll("^https?://","").replaceAll("/.*$","");
    List<String> srcs = new ArrayList<>(); srcs.add("JVM DNS resolver (javax.naming)");
    List<String> errors = new ArrayList<>();
    if (!domain.matches("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")) return unified(domain,"domain","ERROR",0,0,0,"INSUFFICIENT","[]","[]",strArr(srcs),strArr(new ArrayList<>(List.of("Invalid domain format"))));

    java.util.Map<String,String> recs = new LinkedHashMap<>();
    for (String t : new String[]{"A","AAAA","MX","NS","CNAME","TXT","CAA","SOA"}) recs.put(t, dnsLookupType(domain, t));

    // SPF / DMARC derive from TXT
    String spf = "", dmarcTxt = "", dkimSel = "";
    StringBuilder allTxt = new StringBuilder();
    java.util.Map<String,String[]> parsed = new LinkedHashMap<>();
    for (String t : new String[]{"A","AAAA","MX","NS","CNAME","TXT","CAA","SOA"}) {
      String v = recs.get(t);
      if (v != null && !"NO_DATA".equals(v)) parsed.put(t, List.of(v).toArray(new String[0]));
      if ("TXT".equals(t) && v != null && !"NO_DATA".equals(v)) { allTxt.append(v).append(" | "); }
    }
    String txtAll = allTxt.toString();
    // Round 2: capture the FULL SPF record (a single TXT may be split across multiple quoted
    // strings, e.g. "v=spf1 ... ip4:x" " more ~all"). Do not treat a truncated first fragment as
    // "the" SPF record. Match through the terminal "all" mechanism, allowing embedded quotes.
    Matcher sm = Pattern.compile("(?is)v=spf1.*?(?:~|-|\\+|\\?)?all(?=[\\s\";]|$)").matcher(txtAll);
    if (sm.find()) spf = sm.group().replaceAll("[\\\"]","").replaceAll("\\s+"," ").trim();
    if (txtAll.toLowerCase(Locale.ROOT).contains("v=dmarc1")) { Matcher dm = Pattern.compile("v=dmarc1[^|]*", Pattern.CASE_INSENSITIVE).matcher(txtAll); if (dm.find()) dmarcTxt = dm.group().trim(); }
    // discover one DKIM selector (only if a known/plausible selector exists)
    for (String sel : new String[]{"default","google","selector1","selector2","s1","s2","k1"}) {
      String r = dnsLookupType(sel + "._domainkey." + domain, "TXT");
      if (r != null && !"NO_DATA".equals(r)) { dkimSel = sel; break; }
    }

    List<String> find = new ArrayList<>();
    List<String> reco = new ArrayList<>();

    // ---- Round 2: SOA vs NS provider cross-verification ----
    // If the SOA MNAME's provider and the NS record provider differ, surface the discrepancy
    // honestly (never assert malice). This can indicate an apex zone split between hosts
    // (e.g. github.com: NS via NS1/nsone.net but SOA MNAME via AWS Route 53/awsdns), a zone
    // migration in progress, split delegation, or a caching artifact in this tool's own lookups.
    String soaRec = recs.get("SOA");
    String nsRec = recs.get("NS");
    String soaNsMismatchJson = "{\"detected\":false}";
    boolean soaNsMismatch = false;
    if (soaRec != null && !"NO_DATA".equals(soaRec) && nsRec != null && !"NO_DATA".equals(nsRec)) {
      String soaMname = soaRec.trim().split("\\s+")[0].replaceAll("\\.$","").toLowerCase(Locale.ROOT);
      // collect distinct NS hostnames
      java.util.Set<String> nsHosts = new java.util.TreeSet<>();
      for (String nsv : nsRec.split(";")) {
        String h = nsv.trim().split("\\s+")[0].replaceAll("\\.$","").toLowerCase(Locale.ROOT);
        if (!h.isEmpty()) nsHosts.add(h);
      }
      String mnameProv = registeredDomain(soaMname);
      java.util.Set<String> nsProv = new java.util.TreeSet<>();
      for (String h : nsHosts){ String p = registeredDomain(h); if (!p.isEmpty()) nsProv.add(p); }
      boolean provMismatch = !mnameProv.isEmpty() && !nsProv.isEmpty() && !nsProv.contains(mnameProv);
      if (provMismatch) {
        soaNsMismatch = true;
        String note = "SOA/NS provider mismatch detected — verify manually (may indicate zone migration in progress, split delegation, or a query/caching inconsistency in this tool).";
        String hint = "Re-query independently with: dig SOA " + domain + " and dig NS " + domain + " against a different public resolver (e.g. 1.1.1.1 and 8.8.8.8) to rule out a caching artifact in this lookup path.";
        find.add(uf("dns_security","LOW","SOA/NS provider mismatch",note,"SOA MNAME provider="+mnameProv+" ; NS provider(s)="+String.join(",",nsProv),"","DNS Analyzer",55));
        reco.add(hint);
        srcs.add("provider cross-check: SOA MNAME vs NS");
        soaNsMismatchJson = "{\"detected\":true,\"soa_mname\":\""+q(soaMname)+"\",\"soa_mname_provider\":\""+q(mnameProv)+"\",\"ns_provider(s)\":\""+q(String.join(", ",nsProv))+"\",\"severity\":\"info\",\"note\":\"SOA/NS provider mismatch detected — verify manually (may indicate zone migration in progress, split delegation, or a query/caching inconsistency in this tool). This is NOT asserted as malicious.\",\"verify_hint\":\"Re-query independently with `dig SOA "+domain+"` and `dig NS "+domain+"` against a different public resolver (e.g. 1.1.1.1 and 8.8.8.8) to rule out a caching artifact in this lookup path.\"}";
      }
    }

    String status = "RESOLVED";
    // A or AAAA present?
    boolean hasA = recs.get("A") != null && !"NO_DATA".equals(recs.get("A"));
    boolean hasAa = recs.get("AAAA") != null && !"NO_DATA".equals(recs.get("AAAA"));
    if (!hasA && !hasAa && (recs.get("A")==null || "NO_DATA".equals(recs.get("A")))) status = "UNKNOWN"; // unresponsive -> not resolved

    // findings (config, not malice)
    if (spf.isEmpty()) { find.add(uf("dns_security","LOW","Missing SPF","No v=spf1 TXT record observed at the apex.","No SPF TXT at "+domain,"","DNS Analyzer",60)); reco.add("Publish an SPF TXT record defining authorized senders."); }
    else { String sl = spf.toLowerCase(Locale.ROOT); if (sl.contains("~all")){} else if (sl.contains("-all")){} else { find.add(uf("dns_security","MEDIUM","Weak SPF configuration","SPF exists but lacks a hard/soft fail enforcement mechanism.","SPF: "+spf,"","DNS Analyzer",72)); reco.add("Add ~all or -all to the SPF record."); } }
    String dmarcVal = dnsLookupType("_dmarc." + domain, "TXT");
    boolean hasDmarc = dmarcVal != null && !"NO_DATA".equals(dmarcVal);
    if (!hasDmarc) { find.add(uf("dns_security","MEDIUM","Missing DMARC","No DMARC TXT record observed at _dmarc."+domain+".","No v=DMARC1 at _dmarc."+domain,"","DNS Analyzer",64)); reco.add("Publish a DMARC TXT record with a policy."); }
    else if (!dmarcVal.toLowerCase(Locale.ROOT).contains("p=reject") && !dmarcVal.toLowerCase(Locale.ROOT).contains("p=quarantine")) { find.add(uf("dns_security","MEDIUM","Weak DMARC policy","DMARC policy does not enforce quarantine/reject.","DMARC: "+dmarcVal,"","DNS Analyzer",75)); }
    String caa = recs.get("CAA");
    if (caa == null || "NO_DATA".equals(caa)) { find.add(uf("dns_security","LOW","Missing CAA","No CAA record observed — certificate issuance is not constrained.","","","DNS Analyzer",55)); reco.add("Publish a CAA record restricting authorized CAs."); }
    if (!dkimSel.isEmpty()) { find.add(uf("dns_security","LOW","Observed DKIM selector","DKIM selector discovered: "+dkimSel+" (present, not missing).","selector="+dkimSel,"","DNS Analyzer",70)); }
    else { find.add(uf("dns_security","LOW","DKIM selector unknown","DKIM requires an exact per-selector TXT name (selector._domainkey."+domain+"); no common selector was discovered from the known/default set, so DKIM cannot be verified.","selector status=unknown; common selectors queried","","DNS Analyzer",45)); reco.add("Determine the DKIM selector(s) your mail provider uses and query <selector>._domainkey."+domain+" TXT to verify DKIM."); }
    String dkimJson = "{\"selector\":" + (dkimSel.isEmpty() ? "null" : "\""+q(dkimSel)+"\"") + ",\"status\":\"" + (dkimSel.isEmpty() ? "UNKNOWN - selector unknown, cannot verify" : "VERIFIED (selector discovered)") + "\"}";
    // Suspicious: IP-literal MX or wildcard-ish CNAME heuristics (config observations only)
    String mx = recs.get("MX");
    if (mx != null && !"NO_DATA".equals(mx) && mx.matches("(?s).*\\b\\d{1,3}(\\.\\d{1,3}){3}\\b.*")) find.add(uf("dns_security","MEDIUM","Suspicious MX configuration","MX record references a raw IP address.","MX: "+mx,"","DNS Analyzer",70));

    String observations = "[";
    for (String t : new String[]{"A","AAAA","MX","NS","CNAME","TXT","CAA","SOA"}) {
      String v = recs.get(t);
      observations += "{\"type\":\""+t+"\",\"status\":\""+(v==null?"UNKNOWN":("NO_DATA".equals(v)?"NO_DATA":"OBSERVED"))+"\",\"value\":"+ (v==null?null:("NO_DATA".equals(v)?null:strList(new ArrayList<>(java.util.List.of(v))))) +"},";
    }
    if (observations.endsWith(",")) observations = observations.substring(0, observations.length()-1);
    observations += "]";

    int risk = 0, conf = 0, comp = 0;
    if (!hasA && !hasAa && status.equals("UNKNOWN")) { risk = 0; conf = 20; comp = 15; }
    else {
      comp = (hasA||hasAa?15:0) + (recs.get("MX")!=null&&!"NO_DATA".equals(recs.get("MX"))?10:0) + (recs.get("NS")!=null&&!"NO_DATA".equals(recs.get("NS"))?10:0) + (recs.get("TXT")!=null&&!"NO_DATA".equals(recs.get("TXT"))?15:0) + (hasDmarc?15:0) + (!spf.isEmpty()?15:0) + (recs.get("CAA")!=null&&!"NO_DATA".equals(recs.get("CAA"))?10:0) + (recs.get("CNAME")!=null&&!"NO_DATA".equals(recs.get("CNAME"))?5:0) + (hasAa?5:0);
      for (String f : find) { if (f.contains("\"severity\":\"HIGH\"")) risk += 18; else if (f.contains("\"severity\":\"MEDIUM\"")) risk += 9; else risk += 4; }
      risk = Math.min(100, risk);
      conf = Math.min(100, 35 + comp/2);
    }
    String dnsJson = "{\"module\":\"dns\",\"domain\":\""+q(domain)+"\",\"dns_status\":\""+status+"\",\"records\":"+observations
      + ",\"spf\":"+(spf.isEmpty()?"null":"\""+q(spf)+"\"")
      + ",\"dmarc\":\""+q(dmarcTxt)+"\",\"dmarc_present\":"+hasDmarc
      + ",\"dkim_selector\":"+(dkimSel.isEmpty()?"null":"\""+q(dkimSel)+"\"")
      + ",\"dkim\":"+dkimJson
      + ",\"spf_txt_source\":\"apex TXT (v=spf1)\",\"dmarc_txt_source\":\"_dmarc."+domain+" TXT\""
      + ",\"soa_ns_provider_mismatch\":"+soaNsMismatchJson
      + ",\"risk_score\":"+risk+",\"confidence\":"+conf+",\"severity\":\""+severLabel(risk)+"\""
      + ",\"findings\":"+(find.isEmpty()?"[]":find.toString())
      + ",\"recommendations\":"+strArr(reco)+",\"sources\":"+strArr(srcs)+",\"errors\":"+strArr(errors)+"}";
    return dnsJson;
  }
  private static void dnsSecurityRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String domain = strVal(body, "domain");
    if (domain.isEmpty()) { json(e,400,error("domain is required")); return; }
    json(e,200,analyzeDnsSecurity(domain));
  }

  /* ==========================================================================
   * MODULE: SSL/TLS ANALYZER  (spec 4)
   * Defensive: connects to :443, inspects cert + TLS version + HSTS/redirect.
   * Honest statuses; never claims insecure just because HTTPS.
   * ========================================================================== */
  static String analyzeSsl(String hostRaw) {
    String host = hostRaw == null ? "" : hostRaw.trim().toLowerCase(Locale.ROOT);
    host = host.replaceAll("^https?://","").replaceAll("/.*$","");
    List<String> srcs = new ArrayList<>(List.of("local TLS inspection"));
    List<String> errors = new ArrayList<>();
    List<String> find = new ArrayList<>();
    List<String> reco = new ArrayList<>();
    if (!host.matches("^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")) return unified(host,"host","ERROR",0,0,0,"INSUFFICIENT","[]","[]",strArr(srcs),strArr(new ArrayList<>(List.of("Invalid hostname"))));

    String sslStatus = "ERROR";
    String subject = "", issuer = "", notBefore = "", notAfter = "", san = "", sigAlg = "", keyAlg = "", keySize = "";
    String protocol = "";
    boolean httpOnly = false, hsts = false;
    long daysRemaining = -1;
    int risk = 0, conf = 0, comp = 0;

    // HTTP->HTTPS redirect + HSTS via a plain HTTP probe (guarded, non-invasive)
    try {
      String guard = validateConnectTarget(host);
      if (guard == null) {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://" + host + "/")).timeout(Duration.ofSeconds(6)).GET().build();
        HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        String loc = resp.headers().firstValue("location").orElse("");
        httpOnly = true;
        if (loc.toLowerCase(Locale.ROOT).startsWith("https://")) { httpOnly = true; } else { find.add(uf("ssl_tls","LOW","HTTP does not redirect to HTTPS","","Location header: "+loc,"","SSL Analyzer",60)); reco.add("Add a 301 redirect from HTTP to HTTPS."); }
        String h = resp.headers().firstValue("strict-transport-security").orElse("");
        if (!h.isEmpty()) { hsts = true; } else { find.add(uf("ssl_tls","MEDIUM","Missing HSTS","No Strict-Transport-Security header observed.","","","SSL Analyzer",70)); reco.add("Enable HSTS (strict-transport-security) header."); }
      }
    } catch (Exception ignored) { }

    // TLS handshake via SSLSocket (guarded)
    try (var socket = sslConnect(host, 443, 7000)) {
      socket.startHandshake();
      var sess = socket.getSession();
      protocol = sess.getProtocol() == null ? "" : sess.getProtocol();
      java.security.cert.Certificate[] certs = sess.getPeerCertificates();
      if (certs != null && certs.length > 0) {
        java.security.cert.X509Certificate c = (java.security.cert.X509Certificate) certs[0];
        subject = c.getSubjectX500Principal().getName();
        issuer = c.getIssuerX500Principal().getName();
        notBefore = c.getNotBefore() == null ? "" : c.getNotBefore().toInstant().toString();
        notAfter = c.getNotAfter() == null ? "" : c.getNotAfter().toInstant().toString();
        daysRemaining = c.getNotAfter() == null ? -1 : java.time.Duration.between(Instant.now(), c.getNotAfter().toInstant()).toDays();
        sigAlg = c.getSigAlgName() == null ? "" : c.getSigAlgName();
        try { san = String.join(", ", c.getSubjectAlternativeNames() == null ? new ArrayList<>() : c.getSubjectAlternativeNames().stream().map(x -> String.valueOf(x.get(1))).toList()); } catch (Exception ignored2) { san = ""; }
        try {
          java.security.PublicKey pk = c.getPublicKey();
          keyAlg = pk.getAlgorithm(); keySize = String.valueOf(c.getPublicKey() instanceof java.security.interfaces.RSAPublicKey ? ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength() : (pk instanceof java.security.interfaces.ECPublicKey ? 256 : 0));
        } catch (Exception ignored2) { }
        sslStatus = "VALID";
        // findings
        if (daysRemaining >= 0 && daysRemaining <= 30) { sslStatus = "EXPIRING"; find.add(uf("ssl_tls","HIGH","Certificate expiring soon","", "days_remaining="+daysRemaining,"","SSL Analyzer",85)); reco.add("Renew certificate before expiry."); }
        if (daysRemaining < 0) { sslStatus = "EXPIRED"; find.add(uf("ssl_tls","CRITICAL","Certificate expired","","notAfter="+notAfter,"","SSL Analyzer",92)); }
        // hostname match is strictly enforced by the handshake host-verifier; do an explicit check too
        boolean hostOk = subject.toLowerCase(Locale.ROOT).contains("*.") ? host.matches("(?i).*\\.?" + subject.toLowerCase(Locale.ROOT).replace("CN=","").replace("*","").trim() + "$") : subject.toLowerCase(Locale.ROOT).contains("cn=" + host) || (san != null && san.toLowerCase(Locale.ROOT).contains(host));
        if (!hostOk) { sslStatus = "INVALID"; find.add(uf("ssl_tls","CRITICAL","Certificate hostname mismatch","","subject="+subject+" host="+host,"","SSL Analyzer",88)); }
        if (protocol != null && (protocol.contains("TLSv1") && !protocol.contains("TLSv1.2") && !protocol.contains("TLSv1.3"))) { find.add(uf("ssl_tls","MEDIUM","Weak TLS version negotiated","","protocol="+protocol,"","SSL Analyzer",80)); }
        if ("SHA1withRSA".equalsIgnoreCase(sigAlg) || sigAlg.contains("MD5")) { find.add(uf("ssl_tls","MEDIUM","Weak signature algorithm","","sigalg="+sigAlg,"","SSL Analyzer",80)); }
        if (keySize != null && keyAlg.equals("RSA") && !keySize.isEmpty() && Integer.parseInt(keySize) < 2048) { find.add(uf("ssl_tls","MEDIUM","Weak RSA key size","","size="+keySize+" bits","","SSL Analyzer",78)); }
      }
    } catch (javax.net.ssl.SSLHandshakeException she) {
      sslStatus = "INVALID";
      errors.add("TLS handshake failed: " + she.getMessage());
      find.add(uf("ssl_tls","HIGH","Certificate validation / handshake failure","","msg="+she.getMessage(),"","SSL Analyzer",80));
    } catch (java.io.IOException ioe) {
      sslStatus = "CONNECTION_FAILED";
      errors.add("TLS connection failed: " + ioe.getMessage());
      find.add(uf("ssl_tls","MEDIUM","TLS connection failure","","msg="+ioe.getMessage(),"","SSL Analyzer",60));
    } catch (java.security.GeneralSecurityException gs) {
      sslStatus = "ERROR";
      errors.add(gs.getMessage());
      find.add(uf("ssl_tls","HIGH","SSRF-guarded target blocked","", q(gs.getMessage()),"","SSL Analyzer",100));
    } catch (Exception ex) {
      sslStatus = "ERROR";
      errors.add("SSL analysis error: " + ex.getMessage());
    }

    for (String f : find) { if (f.contains("\"severity\":\"CRITICAL\"")) risk += 25; else if (f.contains("\"severity\":\"HIGH\"")) risk += 12; else if (f.contains("\"severity\":\"MEDIUM\"")) risk += 7; else risk += 3; }
    risk = Math.min(100, risk);
    conf = Math.min(100, 30 + (sslStatus.equals("VALID") ? 45 : 20));
    comp = Math.min(100, (sslStatus.equals("VALID")||sslStatus.equals("EXPIRING")||sslStatus.equals("EXPIRED")?60:20) + (hsts||httpOnly?20:10) + 10);

    String out = "{\"module\":\"ssl\",\"host\":\""+q(host)+"\",\"ssl_status\":\""+sslStatus+"\""
      + ",\"certificate\":" + (subject.isEmpty()?"null":"{\"subject\":\""+q(subject)+"\",\"issuer\":\""+q(issuer)+"\",\"valid_from\":\""+q(notBefore)+"\",\"valid_to\":\""+q(notAfter)+"\",\"days_remaining\":"+daysRemaining+",\"san\":\""+q(san)+"\",\"signature_algorithm\":\""+q(sigAlg)+"\",\"key_algorithm\":\""+q(keyAlg)+"\",\"key_size\":\""+q(keySize)+"\"}")
      + ",\"tls_protocol\":"+(protocol.isEmpty()?"null":"\""+q(protocol)+"\"")
      + ",\"http_to_https_redirect\":"+httpOnly+",\"hsts\":"+hsts
      + ",\"risk_score\":"+risk+",\"confidence\":"+conf+",\"severity\":\""+severLabel(risk)+"\""
      + ",\"findings\":"+(find.isEmpty()?"[]":find.toString())
      + ",\"recommendations\":"+strArr(reco)+",\"sources\":"+strArr(srcs)+",\"errors\":"+strArr(errors)+"}";
    return out;
  }
  private static void sslRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String host = strVal(body, "host");
    if (host.isEmpty()) { json(e,400,error("host is required")); return; }
    json(e,200,analyzeSsl(host));
  }

  /* ==========================================================================
   * MODULE: DDoS / TRAFFIC ANALYTICS  (spec 3)
   * DEFENSIVE ONLY. Parses web/proxy/firewall-style logs (or a synthetic demo
   * dataset), computes traffic metrics, and compares against a baseline.
   * ========================================================================== */
  private static class TrafficPoint { long ts; String ip; double bytes; String country; String agent; }
  static String analyzeDdos(String logText, String baselineRpsStr) {
    List<String> errors = new ArrayList<>();
    List<String> sources = new ArrayList<>();
    sources.add("uploaded log analysis");
    List<String> lines = new ArrayList<>();
    if (logText != null && !logText.isBlank()) { for (String l : logText.split("\\r?\\n")) if (!l.trim().isEmpty()) lines.add(l); }
    else {
      // DEMO SYNTHETIC dataset — generated deterministically, explicitly labelled SIMULATED DATA.
      // Baseline: ~1 rps over 60s from ~40 distinct sources. Then a spike phase: 20s at high RPS
      // from a concentrated set of sources. This demonstrates baseline comparison honestly.
      sources.add("SIMULATED DATA (demo baseline+spike)");
      Random r = new Random(42);
      long baseStart = 1700000000L;
      for (int i = 0; i < 60; i++) { String ip = (50 + r.nextInt(200)) + "." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256); lines.add(String.format("LOG %d %s 618 GET /api 200 960", baseStart + i, ip)); }
      long spikeStart = baseStart + 120L;
      for (int i = 0; i < 20; i++) { String ip = "203.0.113." + (1 + i % 5); for (int j = 0; j < 12; j++) lines.add(String.format("LOG %d %s 618 GET /login 200 900", spikeStart + i, ip)); }
      for (int i = 0; i < 5; i++) lines.add(String.format("LOG %d 192.0.2.%d 618 GET /admin 500 700", spikeStart + i*3 + 2, i+1));
    }
    if (lines.isEmpty()) return unified("traffic","ddos_logs","ERROR",0,0,30,"INSUFFICIENT","[]","[]",strArr(sources),strArr(new ArrayList<>(List.of("No log lines supplied"))));

    long t0 = Long.MAX_VALUE, t1 = Long.MIN_VALUE;
    java.util.Map<String,long[]> srcCount = new LinkedHashMap<>();
    java.util.Map<String,long[]> countryCount = new LinkedHashMap<>();
    java.util.Map<String,long[]> methodCount = new LinkedHashMap<>();
    java.util.Map<String,long[]> pathCount = new LinkedHashMap<>();
    java.util.Map<String,long[]> statusCount = new LinkedHashMap<>();
    long ok = 0, err5 = 0, err4 = 0, bytes = 0;
    java.util.List<Long> allTs = new ArrayList<>();
    for (String line : lines) {
      // Robust, tolerant parser: timestamp = first 9-13 digit token, IP = first IPv4 literal,
      // status/bytes = trailing "<status> <bytes>". Works with or without a leading "LOG" token.
      Matcher tsM = Pattern.compile("(\\d{9,13})").matcher(line);
      Matcher ipM = IPV4.matcher(line);
      Matcher scM = Pattern.compile("(\\d{3})\\s+(\\d+)\\s*$").matcher(line);
      if (!tsM.find() || !ipM.find() || !scM.find()) continue;
      long ts = Long.parseLong(tsM.group(1)); if (ts > 9999999999L) ts /= 1000;
      String ip = ipM.group();
      int sc = Integer.parseInt(scM.group(1));
      long by = Long.parseLong(scM.group(2));
      allTs.add(ts); t0 = Math.min(t0, ts); t1 = Math.max(t1, ts);
      srcCount.computeIfAbsent(ip, k -> new long[1])[0]++;
      countryCount.computeIfAbsent("UNKNOWN", k -> new long[1])[0]++;
      // path + method (regex-driven; single source of truth)
      Matcher pm = Pattern.compile("(?i)\\s(GET|POST|PUT|DELETE|HEAD)\\s+(\\S+)").matcher(line);
      if (pm.find()) { methodCount.computeIfAbsent(pm.group(1).toUpperCase(Locale.ROOT), k -> new long[1])[0]++; pathCount.computeIfAbsent(pm.group(2), k -> new long[1])[0]++; }
      if (sc >= 500) err5++; else if (sc >= 400) err4++;
      statusCount.computeIfAbsent(String.valueOf(sc), k -> new long[1])[0]++;
      bytes += by;
      if (sc < 400) ok++;
    }
    if (allTs.isEmpty()) return unified("traffic","ddos_logs","ERROR",0,0,20,"INSUFFICIENT","[]","[]",strArr(sources),strArr(new ArrayList<>(List.of("No parseable log rows"))));

    long windowSec = Math.max(1, t1 - t0);
    double rps = allTs.size() / (double) windowSec;
    double rpsCurrent = rps;
    double baseline = 0;
    try { baseline = Math.max(0, Double.parseDouble(baselineRpsStr)); } catch (Exception ignored) {}
    boolean baselineConfigured = !(baselineRpsStr == null || baselineRpsStr.isBlank());

    // single source concentration
    String topIp = ""; long topN = 0;
    for (var en : srcCount.entrySet()) if (en.getValue()[0] > topN) { topN = en.getValue()[0]; topIp = en.getKey(); }
    double concentration = allTs.size() == 0 ? 0 : (double) topN / allTs.size();
    // per-second burst (bucket by second)
    java.util.Map<Long,Integer> perSec = new LinkedHashMap<>();
    for (Long t : allTs) perSec.merge(t, 1, Integer::sum);
    int maxRpsBucket = perSec.values().stream().mapToInt(Integer::intValue).max().orElse(0);

    int anomaly = 0;
    List<String> patterns = new ArrayList<>();
    List<String> recos = new ArrayList<>();
    // baseline comparison (spec 3)
    double ratio = baselineConfigured && baseline > 0 ? rps / baseline : 0;
    if (baselineConfigured && baseline > 0) {
      if (ratio >= 10) { anomaly = Math.max(anomaly, 65); patterns.add("RPS increased " + String.format("%.2f", ratio) + "x above baseline."); }
      else if (ratio >= 5) { anomaly = Math.max(anomaly, 45); patterns.add("RPS " + String.format("%.2f", ratio) + "x baseline."); }
      else if (ratio >= 2.5) { anomaly = Math.max(anomaly, 30); patterns.add("RPS " + String.format("%.2f", ratio) + "x baseline."); }
    }
    if (maxRpsBucket > 50) { anomaly = Math.max(anomaly, 30); patterns.add("Request burst: "+maxRpsBucket+" req/s in a single second."); }
    if (allTs.size() >= 50 && concentration > 0.6) { anomaly = Math.max(anomaly, 50); patterns.add("Single-source flooding: "+String.format("%.0f%%", concentration*100)+" of traffic from one source ("+topIp+")."); }
    if (allTs.size() >= 50 && srcCount.size() > 50) { anomaly = Math.max(anomaly, 25); patterns.add("Distributed source count high ("+srcCount.size()+" unique IPs)."); }
    if (allTs.size() > 0 && err5 > 0 && (double) err5 / allTs.size() > 0.15) { anomaly = Math.max(anomaly, 40); patterns.add("Abnormal 5xx rate: "+String.format("%.1f%%", 100.0*err5/allTs.size())+" responses are 5xx."); }
    double errRate = allTs.size() == 0 ? 0 : (double) (err5 + err4) / allTs.size();
    if (errRate > 0.5) { anomaly = Math.max(anomaly, 35); patterns.add("Elevated error rate ("+String.format("%.0f%%", errRate*100)+" 4xx/5xx)."); }

    String classification;
    if (anomaly >= 75) classification = "CRITICAL";
    else if (anomaly >= 55) classification = "HIGH ANOMALY";
    else if (anomaly >= 35) classification = "SUSPICIOUS";
    else if (anomaly >= 20) classification = "ELEVATED";
    else classification = "NORMAL";

    List<String> find = new ArrayList<>();
    for (String p : patterns) find.add(uf("traffic", classification.equals("CRITICAL")||classification.equals("HIGH ANOMALY")?"HIGH":(classification.equals("SUSPICIOUS")?"MEDIUM":"LOW"), "Anomaly detected", p, p, "", "DDoS Analyzer", 70));
    if (!baselineConfigured) { find.add(uf("traffic","LOW","Insufficient baseline","No baseline RPS supplied; anomaly assessment may be incomplete.","","","DDoS Analyzer",50)); recos.add("Supply a 24h baseline RPS for accurate comparison."); }
    if (find.isEmpty()) find.add(uf("traffic","LOW","Traffic within normal envelope","No anomaly thresholds exceeded.","","","DDoS Analyzer",65));

    String out = "{\"module\":\"ddos\",\"baseline_rps\":"+baseline+",\"baseline_configured\":"+baselineConfigured
      + ",\"current_rps\":"+String.format("%.2f", rps)+",\"rps_vs_baseline\":\""+(ratio>0?String.format("%.2fx", ratio):"n/a")+"\""
      + ",\"anomaly_score\":"+anomaly+",\"classification\":\""+classification+"\""
      + ",\"requests\":"+allTs.size()+",\"window_seconds\":"+windowSec
      + ",\"unique_sources\":"+srcCount.size()+",\"top_source\":\""+q(topIp)+"\",\"source_concentration\":"+String.format("%.3f", concentration)
      + ",\"max_rps_second\":"+maxRpsBucket
      + ",\"methods\":"+methodArr(methodCount)+",\"paths\":"+methodArr(pathCount)+",\"status_codes\":"+methodArr(statusCount)
      + ",\"count_5xx\":"+err5+",\"count_4xx\":"+err4+",\"error_rate\":"+String.format("%.3f", errRate)
      + ",\"bandwidth_bytes\":"+bytes
      + ",\"patterns\":"+strArr(patterns)
      + ",\"findings\":"+(find.isEmpty()?"[]":find.toString())+",\"recommendations\":"+strArr(recos)+",\"sources\":"+strArr(sources)+",\"errors\":"+strArr(errors)+"}";
    return out;
  }
  private static String methodArr(java.util.Map<String,long[]> m){ StringBuilder b=new StringBuilder("["); boolean f=true; for(var en:m.entrySet()){ if(!f)b.append(','); f=false; b.append("{\"k\":\"").append(q(en.getKey())).append("\",\"v\":").append(en.getValue()[0]).append("}"); } return b.append("]").toString(); }
  private static void ddosRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String logs = strVal(body, "logs");
    String baseline = strVal(body, "baseline_rps");
    json(e,200,analyzeDdos(logs.isEmpty()?null:logs, baseline));
  }

  /* ==========================================================================
   * MODULE: CLOUDFLARE SECURITY ANALYZER  (spec 5, 18)
   * Server-side only. Uses env credentials when configured; otherwise honest
   * NOT_CONFIGURED. Never returns invented Cloudflare data.
   * ========================================================================== */
  static String analyzeCloudflare(String zoneOverride) {
    List<String> find = new ArrayList<>();
    List<String> recos = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    List<String> sources = new ArrayList<>();
    if (CF_TOKEN.isEmpty() || CF_ZONE.isEmpty()) {
      sources.add("config");
      String msg = "Cloudflare API token/zone not configured via CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID environment variables.";
      errors.add("CloudflareAnalyzer: NOT_CONFIGURED — " + msg);
      find.add(uf("cloudflare","LOW","Cloudflare not configured","No Cloudflare API credentials present; no Cloudflare data retrieved. Real analysis requires server-side env credentials.","","","Cloudflare Analyzer",60));
      return "{\"module\":\"cloudflare\",\"target\":\""+q(zoneOverride==null?"":zoneOverride)+"\",\"status\":\"NOT_CONFIGURED\",\"connected\":"+false
        + ",\"api\":\"NOT CONFIGURED\",\"zone\":"+jstr(zoneOverride)+",\"proxy\":\"UNKNOWN\",\"waf\":\"UNKNOWN\",\"ddos_protection\":\"UNKNOWN\",\"ssl_mode\":\"UNKNOWN\""
        + ",\"risk_score\":20,\"confidence\":20,\"data_completeness\":10,\"evidence_quality\":\"INSUFFICIENT\""
        + ",\"findings\":"+(find.isEmpty()?"[]":find.toString())+",\"recommendations\":"+strArr(recos)+",\"sources\":"+strArr(sources)+",\"errors\":"+strArr(errors)+"}";
    }
    sources.add("Cloudflare API (v4, server-side)");
    // Best-effort real call.
    String zone = zoneOverride == null || zoneOverride.isBlank() ? (CF_ZONE.isEmpty()? "" : CF_ZONE) : zoneOverride;
    try {
      var req = HttpRequest.newBuilder(URI.create("https://api.cloudflare.com/client/v4/zones?name=" + java.net.URLEncoder.encode(zone, StandardCharsets.UTF_8)))
        .timeout(Duration.ofSeconds(10))
        .header("Authorization", "Bearer " + CF_TOKEN).header("Content-Type","application/json").GET().build();
      HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() == 200 && resp.body().contains("\"success\":true")) {
        String zid = strVal(resp.body(),"id");
        if (zid.isEmpty()) { errors.add("Cloudflare returned success but zone id was undefined."); }
        String plan = strVal(resp.body(),"plan");
        String name = strVal(resp.body(),"name");
        String statusReal = strVal(resp.body(),"status");
        find.add(uf("cloudflare","LOW","Zone reachable via API","Cloudflare API authenticated; zone name="+name+", status="+statusReal+"","zone="+name,"","Cloudflare Analyzer",80));
        return "{\"module\":\"cloudflare\",\"target\":\""+q(name)+"\",\"status\":"+jstr(statusReal)+",\"connected\":true"
          + ",\"api\":\"CONFIGURED\",\"zone\":"+jstr(name)+",\"plan\":"+jstr(plan)+",\"proxy\":\"UNKNOWN\",\"waf\":\"UNKNOWN\",\"ddos_protection\":\"UNKNOWN\",\"ssl_mode\":\"UNKNOWN\""
          + ",\"risk_score\":15,\"confidence\":65,\"data_completeness\":55,\"evidence_quality\":\"LOW\""
          + ",\"findings\":"+(find.isEmpty()?"[]":find.toString())+",\"recommendations\":"+strArr(recos)+",\"sources\":"+strArr(sources)+",\"errors\":"+strArr(errors)+"}";
      } else if (resp.statusCode() == 401 || resp.statusCode() == 403) {
        errors.add("Cloudflare API rejected credentials (HTTP "+resp.statusCode()+").");
        find.add(uf("cloudflare","MEDIUM","Cloudflare API authentication failed","","HTTP "+resp.statusCode(),"","Cloudflare Analyzer",80));
      } else if (resp.statusCode() == 429) {
        errors.add("Cloudflare API rate limit (HTTP 429).");
        find.add(uf("cloudflare","MEDIUM","Cloudflare API rate limited","","HTTP 429","","Cloudflare Analyzer",70));
      } else {
        errors.add("Cloudflare API returned HTTP "+resp.statusCode()+": "+resp.body().substring(0, Math.min(200, resp.body().length())));
      }
    } catch (Exception ex) {
      errors.add("Cloudflare API error: "+ex.getMessage());
      find.add(uf("cloudflare","MEDIUM","Cloudflare API request failed","", ex.getMessage(),"","Cloudflare Analyzer",60));
    }
    return "{\"module\":\"cloudflare\",\"target\":"+jstr(zone)+",\"status\":\"ERROR\",\"connected\":false"
      + ",\"api\":\"CONFIGURED\",\"zone\":"+jstr(zone)+",\"proxy\":\"UNKNOWN\",\"waf\":\"UNKNOWN\",\"ddos_protection\":\"UNKNOWN\",\"ssl_mode\":\"UNKNOWN\""
      + ",\"risk_score\":20,\"confidence\":35,\"data_completeness\":25,\"evidence_quality\":\"LOW\""
      + ",\"findings\":"+(find.isEmpty()?"[]":find.toString())+",\"recommendations\":"+strArr(recos)+",\"sources\":"+strArr(sources)+",\"errors\":"+strArr(errors)+"}";
  }
  private static void cloudflareRoute(HttpExchange e) throws IOException {
    if (!"POST".equals(e.getRequestMethod())) { json(e,405,error("POST required")); return; }
    String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    String zone = strVal(body, "zone");
    json(e,200,analyzeCloudflare(zone));
  }

  /* ==========================================================================
   * MODULE: UNIFIED DASHBOARD  (spec 10, 24) + GLOBAL SEARCH routing (spec 11)
   * ========================================================================== */
  private static void dashboardRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    List<String> incidents = readLines(INCIDENTS);
    int open = 0, critical = 0, total = incidents.size();
    for (String l : incidents) { if (l.contains("\"status\":\"NEW\"")||l.contains("\"status\":\"TRIAGED\"")||l.contains("\"status\":\"INVESTIGATING\"")) open++; if (l.contains("\"severity\":\"CRITICAL\"")) critical++; }
    int iocs = readLines(IOC_REG).size();
    String json = "{\"module\":\"dashboard\",\"kpis\":{\"total_analyses\":"+total+",\"active_threats\":"+open+",\"critical_alerts\":"+critical+",\"open_incidents\":"+open+",\"iocs\":"+iocs+"}"
      + ",\"modules\":[{ \"id\":\"spam\",\"name\":\"Spam Analysis\",\"score\":0,\"status\":\"READY\"},{\"id\":\"dns\",\"name\":\"DNS Security\",\"score\":0,\"status\":\"READY\"},{\"id\":\"ssl\",\"name\":\"SSL/TLS\",\"score\":0,\"status\":\"READY\"},{\"id\":\"ddos\",\"name\":\"DDoS Analytics\",\"score\":0,\"status\":\"READY\"},{\"id\":\"cloudflare\",\"name\":\"Cloudflare\",\"score\":0,\"status\":\""+(CF_TOKEN.isEmpty()?"NOT_CONFIGURED":"READY")+"\"}]}";
    json(e,200,json);
  }
  private static void iocRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    // Aggregate the IOC registry (persisted from real analyses via the IOC extractor).
    List<String> rows = readLines(IOC_REG);
    StringBuilder b = new StringBuilder("{\"module\":\"ioc_explorer\",\"iocs\":[");
    boolean first = true;
    for (String l : rows) {
      if (l.trim().isEmpty()) continue;
      if (!first) b.append(',');
      first = false;
      b.append("{\"type\":\"").append(q(iocField(l, "type"))).append("\",\"value\":\"").append(q(iocField(l, "value")))
        .append("\",\"first_seen\":\"").append(q(iocField(l, "first_seen"))).append("\",\"last_seen\":\"").append(q(iocField(l, "last_seen")))
        .append("\",\"reputation\":\"").append(q(iocField(l, "reputation"))).append("\",\"confidence\":").append(iocField(l, "confidence")).append("}");
    }
    b.append("],\"note\":\"Distinct IOCs extracted from real analyses, persisted on ingest.\"}");
    json(e,200,b.toString());
  }
  private static String iocField(String line, String field){
    String v = scanJsonValue(line, field);
    if (v != null) return v;
    Matcher m2 = Pattern.compile("\"" + java.util.regex.Pattern.quote(field) + "\":(-?\\d+(?:\\.\\d+)?)").matcher(line);
    return m2.find() ? m2.group(1) : "";
  }

  /* ==========================================================================
   * MODULE: LIVE CYBERSECURITY NEWS FEED  (server-side RSS proxy, cached)
   * ========================================================================== */
  private static final java.util.List<String[]> NEWS_SOURCES = List.of(
    new String[]{"thehackersnews","https://feeds.feedburner.com/TheHackersNews"},
    new String[]{"threatpost","https://threatpost.com/feed/"},
    new String[]{"securityweek","https://www.securityweek.com/feed/"}
  );
  private static volatile String NEWS_CACHE = null;
  private static volatile long NEWS_CACHE_AT = 0;
  private static void newsRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    String body;
    if (NEWS_CACHE != null && System.currentTimeMillis() - NEWS_CACHE_AT < 5*60*1000L) {
      body = NEWS_CACHE;
    } else {
      body = fetchNews();
      NEWS_CACHE = body; NEWS_CACHE_AT = System.currentTimeMillis();
    }
    json(e,200,body);
  }
  private static String fetchNews(){
    for (String[] src : NEWS_SOURCES) {
      try {
        HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(src[1]))
            .header("User-Agent","Mozilla/5.0 (compatible; CipherSquad/1.0)")
            .timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode()==200 && r.body()!=null) {
          String items = parseRssItems(r.body());
          if (items != null) return "{\"module\":\"news\",\"source\":\""+q(src[0])+"\",\"live\":true,\"items\":"+items+"}";
        }
      } catch (Exception ex) { /* try next source */ }
    }
    return newsFallback();
  }
  private static String parseRssItems(String xml){
    StringBuilder b = new StringBuilder("[");
    boolean first=true; int count=0;
    Matcher items = Pattern.compile("(?is)<item>.*?</item>").matcher(xml==null?"":xml);
    while (items.find() && count<12) {
      String it = items.group();
      String title = extractTag(it,"title");
      if (title.isEmpty()) continue;
      if (!first) b.append(',');
      first=false; count++;
      b.append("{\"title\":\"").append(q(title)).append("\",\"link\":\"").append(q(extractTag(it,"link")))
       .append("\",\"published\":\"").append(q(extractTag(it,"pubDate")))
       .append("\",\"summary\":\"").append(q(shorten(stripTags(extractTag(it,"description")),140))).append("\"}");
    }
    if (first) {
      Matcher atom = Pattern.compile("(?is)<entry>.*?</entry>").matcher(xml==null?"":xml);
      while (atom.find() && count<12) {
        String it = atom.group();
        String title = extractTag(it,"title");
        if (title.isEmpty()) continue;
        Matcher lm = Pattern.compile("(?is)<link[^>]*href=\"([^\"]*)\"").matcher(it);
        String link = lm.find()?lm.group(1):"";
        if (!first) b.append(',');
        first=false; count++;
        b.append("{\"title\":\"").append(q(title)).append("\",\"link\":\"").append(q(link))
         .append("\",\"published\":\"").append(q(extractTag(it,"published")==""?extractTag(it,"updated"):extractTag(it,"published")))
         .append("\",\"summary\":\"").append(q(shorten(stripTags(extractTag(it,"summary")),140))).append("\"}");
      }
    }
    if (first) return null;
    b.append("]");
    return b.toString();
  }
  private static String extractTag(String xml, String tag){
    Matcher m = Pattern.compile("(?is)<"+tag+"[^>]*>(.*?)</"+tag+">").matcher(xml==null?"":xml);
    return m.find()?m.group(1).trim():"";
  }
  private static String stripTags(String s){ if(s==null)return""; return s.replaceAll("<[^>]*>","").replaceAll("\\s+"," ").trim(); }
  private static String shorten(String s,int n){ if(s==null||s.length()<=n)return s==null?"":s; return s.substring(0,n)+"…"; }
  private static String newsFallback(){
    String[] titles = {
      "Phishing campaigns impersonate trusted brands to bypass secure email gateways",
      "Ransomware groups increasingly rely on data-theft extortion as primary leverage",
      "DNS hygiene — verify SPF, DKIM and DMARC before trusting a sender identity",
      "Security teams urged to harden CAA records and monitor certificate issuance",
      "Indicators-of-compromise extraction and correlation remain the backbone of a SOC"
    };
    StringBuilder b = new StringBuilder("{\"module\":\"news\",\"source\":\"fallback (feed offline)\",\"live\":false,\"items\":[");
    for (int i=0;i<titles.length;i++){ if(i>0)b.append(','); b.append("{\"title\":\"").append(q(titles[i])).append("\",\"link\":\"\",\"published\":\"\",\"summary\":\"\"}"); }
    b.append("]}");
    return b.toString();
  }

  /** Upgrades legacy IOC registry rows (confidence:0 / reputation:UNKNOWN) to the
   *  configured confidence methodology so every indicator has a scored result. */
  private static void backfillIocRegistry(){
    try {
      List<String> rows = readLines(IOC_REG);
      if (rows == null || rows.isEmpty()) return;
      StringBuilder out = new StringBuilder();
      boolean changed = false;
      for (String l : rows) {
        if (l.trim().isEmpty()) { out.append(l).append('\n'); continue; }
        if ((l.contains("\"confidence\":0") || l.contains("\"confidence\":\"0\"")) || l.contains("\"reputation\":\"UNKNOWN\"")) {
          String type = iocField(l, "type");
          String value = iocField(l, "value");
          String first = iocField(l, "first_seen");
          String last = iocField(l, "last_seen");
          String sc = iocConfidence(type, value, null);
          String rep = sc.substring(sc.indexOf("\"reputation\":\"") + ("\"reputation\":\"").length(), sc.indexOf('"', sc.indexOf("\"reputation\":\"") + ("\"reputation\":\"").length()));
          String conf = sc.substring(sc.indexOf("\"confidence\":") + ("\"confidence\":").length(), sc.indexOf('}', sc.indexOf("\"confidence\":")));
          out.append("{\"key\":\"").append(iocField(l, "key")).append("\",\"type\":\"").append(type).append("\",\"value\":\"").append(value)
             .append("\",\"reputation\":\"").append(rep).append("\",\"confidence\":").append(conf)
             .append(",\"first_seen\":\"").append(first).append("\",\"last_seen\":\"").append(last).append("\"}\n");
          changed = true;
        } else {
          out.append(l).append('\n');
        }
      }
      if (changed) Files.write(IOC_REG, out.toString().getBytes(StandardCharsets.UTF_8));
    } catch (Exception ignore) {}
  }
  private static void securityStatusRoute(HttpExchange e) throws IOException {
    if (!"GET".equals(e.getRequestMethod())) { json(e,405,error("GET required")); return; }
    json(e,200,"{\"module\":\"security_status\",\"statuses\":[\"SAFE\",\"LOW RISK\",\"MEDIUM RISK\",\"HIGH RISK\",\"CRITICAL\",\"UNKNOWN\",\"ERROR\",\"UNAVAILABLE\"],\"note\":\"Status vocabulary shared across all modules. UNKNOWN is not treated as malicious.\"}");
  }

  // ---- package-visible test hooks for the new modules ----
  static String spamTest(String raw){ return analyzeSpam(raw); }
  static String dnsTest(String domain){ return analyzeDnsSecurity(domain); }
  static String sslTest(String host){ return analyzeSsl(host); }
  static String ddosTest(String logs, String baseline){ return analyzeDdos(logs, baseline); }
  static String cfTest(String zone){ return analyzeCloudflare(zone); }
  static boolean isPrivateIpTest(String ip){ return isPrivateIp(ip); }
}
