import java.util.regex.*;
import java.util.*;

public final class PIIMasker {
    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();

    static {
        // Email
        PATTERNS.put("[EMAIL_REDACTED]", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE));
        // Phone (Basic International/Local)
        PATTERNS.put("[PHONE_REDACTED]", Pattern.compile("(\\+\\d{1,3}[- ]?)?\\d{10}|(\\d{3}[- .]\\d{3}[- .]\\d{4})", Pattern.CASE_INSENSITIVE));
        // Credit Card (Basic)
        PATTERNS.put("[CARD_REDACTED]", Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b"));
    }

    public static String mask(String text) {
        if (text == null || text.isBlank()) return text;
        String masked = text;
        for (Map.Entry<String, Pattern> entry : PATTERNS.entrySet()) {
            masked = entry.getValue().matcher(masked).replaceAll(entry.getKey());
        }
        return masked;
    }

    public static Map<String, Object> maskAnalysis(Map<String, Object> analysis) {
        if (analysis == null) return null;

        // Mask fields in the 'parsed' section if present
        if (analysis.containsKey("parsed")) {
            Object parsed = analysis.get("parsed");
            if (parsed instanceof Map) {
                Map<String, Object> pMap = (Map<String, Object>) parsed;
                if (pMap.containsKey("body")) {
                    pMap.put("body", mask((String) pMap.get("body")));
                }
                if (pMap.containsKey("from")) {
                    pMap.put("from", mask((String) pMap.get("from")));
                }
            }
        }

        return analysis;
    }
}
