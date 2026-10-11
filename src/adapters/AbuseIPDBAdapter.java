import java.net.http.*;
import java.net.URI;
import java.util.*;
import java.util.logging.Logger;
import java.io.IOException;

/**
 * AbuseIPDBAdapter provides interface to AbuseIPDB v2 API.
 */
public final class AbuseIPDBAdapter {
    private static final Logger logger = Logger.getLogger(AbuseIPDBAdapter.class.getName());
    private final HttpClient client;
    private final String apiKey;
    private static final String BASE_URL = "https://api.abuseipdb.com/api/v2";

    public AbuseIPDBAdapter(String apiKey) {
        this.client = HttpClient.newHttpClient();
        this.apiKey = apiKey;
    }

    public Map<String, Object> lookupIp(String ip) {
        if (apiKey == null || apiKey.isBlank()) return Collections.emptyMap();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/check?ipAddress=" + ip))
                    .header("Key", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                logger.warning("AbuseIPDB lookup failed: " + response.statusCode());
                return Collections.emptyMap();
            }

            return parseResponse(response.body());
        } catch (IOException | InterruptedException e) {
            logger.severe("AbuseIPDB API communication error: " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    private Map<String, Object> parseResponse(String body) {
        Map<String, Object> result = new LinkedHashMap<>();
        // Simple detection of abuse score from JSON
        if (body.contains("\"abuseConfidenceScore\":")) {
            result.put("abuse_score", "detected");
        }
        result.put("provider", "AbuseIPDB");
        return result;
    }
}
