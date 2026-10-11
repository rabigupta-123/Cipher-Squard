import java.util.*;
import java.util.concurrent.*;
import java.net.http.*;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * ActiveEnrich handles real-time intelligence lookups (GeoIP, Threat Intel).
 * It implements a server-side cache to respect API rate limits and improve latency.
 */
public final class ActiveEnrich {
    private static final Logger logger = Logger.getLogger(ActiveEnrich.class.getName());

    // Cache settings: 24 hours for stability, 1 hour for volatility
    private static final long CACHE_TTL_STABLE = TimeUnit.HOURS.toMillis(24);
    private static final long CACHE_TTL_VOLATILE = TimeUnit.HOURS.toMillis(1);

    private final HttpClient httpClient;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public ActiveEnrich() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .build();
    }

    private static final class CacheEntry {
        final Object value;
        final long expiresAt;
        CacheEntry(Object v, long ttl) {
            this.value = v;
            this.expiresAt = System.currentTimeMillis() + ttl;
        }
        boolean isExpired() { return System.currentTimeMillis() > expiresAt; }
    }

    /**
     * Resolves IP metadata.
     */
    public Map<String, Object> enrichIp(String ip) {
        if (ip == null || ip.isBlank()) return Collections.emptyMap();

        String key = "ip:" + ip;
        CacheEntry entry = cache.get(key);
        if (entry != null && !entry.isExpired()) {
            return (Map<String, Object>) entry.value;
        }

        try {
            // Mocking the actual API call for the skeleton.
            // In the final adapter phase, this will call VirusTotal/AbuseIPDB.
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("country", "Unknown");
            data.put("asn", "Unknown");
            data.put("is_proxy", false);
            data.put("reputation", "neutral");

            cache.put(key, new CacheEntry(data, CACHE_TTL_VOLATILE));
            return data;
        } catch (Exception e) {
            logger.warning("Enrichment failed for " + ip + ": " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    /**
     * Resolves domain metadata.
     */
    public Map<String, Object> enrichDomain(String domain) {
        if (domain == null || domain.isBlank()) return Collections.emptyMap();

        String key = "dom:" + domain;
        CacheEntry entry = cache.get(key);
        if (entry != null && !entry.isExpired()) {
            return (Map<String, Object>) entry.value;
        }

        try {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("age_days", -1);
            data.put("registrar", "Unknown");
            data.put("is_lookalike", false);

            cache.put(key, new CacheEntry(data, CACHE_TTL_STABLE));
            return data;
        } catch (Exception e) {
            logger.warning("Enrichment failed for " + domain + ": " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    public static final class DnsProvider implements Enrich.Provider {
        @Override
        public String name() { return "ActiveEnrich-DNS"; }
        @Override
        public boolean available() { return true; }
        @Override
        public String unavailableReason() { return null; }
        @Override
        public Enrich.Record lookup(String ip) {
            return new Enrich.Record();
        }
    }

    public static final class ThreatIntelProvider implements Enrich.Provider {
        @Override
        public String name() { return "ActiveEnrich-ThreatIntel"; }
        @Override
        public boolean available() { return true; }
        @Override
        public String unavailableReason() { return null; }
        @Override
        public Enrich.Record lookup(String ip) {
            return new Enrich.Record();
        }
    }
}
