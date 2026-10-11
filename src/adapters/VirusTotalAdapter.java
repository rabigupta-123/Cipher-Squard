import java.net.http.*;
import java.net.URI;
import java.util.*;
import java.util.logging.Logger;
import java.io.IOException;

/**
 * VirusTotalAdapter provides interface to VT v3 API.
 * It handles the API key authentication and response parsing.
 */
public final class VirusTotalAdapter {
    private static final Logger logger = Logger.getLogger(VirusTotalAdapter.class.getName());
    private final HttpClient client;
    private final String apiKey;
    private static final String BASE_URL = "https://www.virustotal.com/api/v3";

    public VirusTotalAdapter(String apiKey) {
        this.client = HttpClient.newHttpClient();
        this.apiKey = apiKey;
    }

    public Map<String, Object> lookupIp(String ip) {
        if (apiKey == null || apiKey.isBlank()) return Collections.emptyMap();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + "/ip_addresses/" + ip))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                logger.warning("VT IP lookup failed: " + response.statusCode());
                return Collections.emptyMap();
            }

            // Simplified parsing: in a real implementation, use a JSON library
            return parseVtResponse(response.body());
        } catch (IOException | InterruptedException e) {
            logger.severe("VT API communication error: " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    private Map<String, Object> parseVtResponse(String body) {
        Map<String, Object> result = new LinkedHashMap<>();
        boolean malicious = body.contains("\"malicious\":") && body.contains("true");
        result.put("malicious", malicious);
        result.put("provider", "VirusTotal");
        return result;
    }
}
