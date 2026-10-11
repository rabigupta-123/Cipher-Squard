/**
 * Hashing and canonical JSON: the trust anchor for the audit chain.
 *
 * There is exactly one implementation of each in the codebase, on purpose. ARCHITECTURE.md
 * L55 requires "SHA-256, single implementation, used by ingest and evidence tooling only".
 * Two SHA-256 call sites that disagree about hex casing produce a chain that verifies on one
 * machine and not another, and the failure looks exactly like tampering.
 *
 * CANONICAL JSON. A chain hash is only meaningful if serialisation is deterministic, so
 * Json.write alone is not enough - it preserves insertion order, which depends on how a map
 * happened to be built. canonical() sorts keys, so the same logical record always produces
 * the same bytes regardless of construction order. That is what makes the chain verifiable
 * by an independent implementation, which is the entire point of a hash chain.
 *
 * Ed25519 lives in Sign.java, not here. The Phase 1 brief scopes this file to hashing and
 * canonicalisation, and keeping signing out means the chain's hash has exactly one owner.
 *
 * Spec anchors: ROADMAP.md L213-219 (hash-chained audit), ARCHITECTURE.md L55, L232.
 */
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Crypto {

    private Crypto() {
    }

    // ==================================================================
    // SHA-256
    // ==================================================================

    /** Lowercase hex SHA-256. The only hex form this codebase emits. */
    public static String sha256Hex(byte[] data) {
        MessageDigest md = newSha256();
        return toHex(md.digest(data));
    }

    public static String sha256Hex(String utf8) {
        return sha256Hex(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable; JDK is broken", e);
        }
    }

    public static String toHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = HEX[v >>> 4];
            hex[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(hex);
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    // ==================================================================
    // Canonical JSON
    // ==================================================================

    /**
     * Deterministic JSON: keys sorted lexicographically by UTF-16 code unit, no whitespace,
     * fixed double format. Sorted keys rather than insertion order, because insertion order
     * is an accident of the code that built the map, not a property of the record.
     *
     * Doubles go through Json.fmt (%.10g, -0 normalised) so that 1.0 and 1 cannot produce
     * two different chain hashes for the same logical value.
     */
    public static String canonical(Object value) {
        StringBuilder sb = new StringBuilder();
        canonicalInto(value, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void canonicalInto(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            Json.write(v, sb); // reuse the single escaping implementation
        } else if (v instanceof Boolean) {
            sb.append(((Boolean) v) ? "true" : "false");
        } else if (v instanceof Double || v instanceof Float) {
            sb.append(Json.fmt(((Number) v).doubleValue()));
        } else if (v instanceof Number) {
            sb.append(v.toString());
        } else if (v instanceof Map) {
            // TreeMap sorts by natural String order, which is code-unit order. Good enough and
            // fully specified: no locale, no comparator ambiguity.
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                sorted.put(String.valueOf(e.getKey()), e.getValue());
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                Json.write(e.getKey(), sb);
                sb.append(':');
                canonicalInto(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof Iterable) {
            sb.append('[');
            boolean first = true;
            for (Object o : (Iterable<Object>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                canonicalInto(o, sb);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("cannot canonicalise " + v.getClass().getName());
        }
    }

    // ==================================================================
    // Shared helpers
    // ==================================================================

    /** Split an NDJSON file into trimmed, non-blank lines. */
    public static List<String> nonBlankLines(List<String> lines) {
        List<String> out = new ArrayList<>();
        for (String l : lines) {
            String t = l.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    /** Standalone self-check: java Crypto */
    public static void main(String[] args) {
        System.out.println("sha256(genesis seed) = "
                + sha256Hex(Config.AUDIT_GENESIS_SEED));
        Map<String, Object> a = new java.util.LinkedHashMap<>();
        a.put("b", 1.0);
        a.put("a", 2.0);
        Map<String, Object> b = new java.util.LinkedHashMap<>();
        b.put("a", 2.0);
        b.put("b", 1.0);
        System.out.println("canonical(a)=" + canonical(a));
        System.out.println("canonical(b)=" + canonical(b));
        System.out.println("order-independent=" + canonical(a).equals(canonical(b)));
        Map<String, Object> d1 = Map.of("v", 1.0);
        Map<String, Object> d2 = Map.of("v", 1);
        System.out.println("double-normalised=" + canonical(d1).equals(canonical(d2)));
        System.out.println("lowercase-hex-ok=" + sha256Hex("").equals(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
}
