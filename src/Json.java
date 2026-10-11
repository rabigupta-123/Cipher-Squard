/**
 * Minimal dependency-free JSON reader/writer.
 *
 * Deliberately NOT a general-purpose library: the platform needs a strict, allocation-bounded
 * parser for evidence files and configuration. It rejects trailing content, unterminated
 * literals, and control characters in strings rather than silently accepting them, because a
 * silently-accepted malformed evidence file would corrupt the audit chain.
 *
 * Spec: ARCHITECTURE.md L215 (zero third-party dependencies), L302 (Json.java).
 */
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {

    private final String src;
    private int pos;
    private int depth;

    /** Nesting limit. Bounds recursion so a hostile file cannot blow the stack. */
    private static final int MAX_DEPTH = 64;

    private Json(String src) {
        this.src = src;
        this.pos = 0;
        this.depth = 0;
    }

    // ==================================================================
    // Typed accessors - fail loudly, because a missing field in model.json is a bug
    // ==================================================================

    public static Map<String, Object> obj(Map<String, Object> m, String k) {
        Object v = require(m, k);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("field '" + k + "' is not an object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) v;
        return out;
    }

    public static List<Object> arr(Map<String, Object> m, String k) {
        Object v = require(m, k);
        if (!(v instanceof List)) {
            throw new IllegalArgumentException("field '" + k + "' is not an array");
        }
        @SuppressWarnings("unchecked")
        List<Object> out = (List<Object>) v;
        return out;
    }

    public static String str(Map<String, Object> m, String k) {
        Object v = require(m, k);
        if (!(v instanceof String)) {
            throw new IllegalArgumentException("field '" + k + "' is not a string");
        }
        return (String) v;
    }

    public static double num(Map<String, Object> m, String k) {
        Object v = require(m, k);
        if (!(v instanceof Double)) {
            throw new IllegalArgumentException("field '" + k + "' is not a number");
        }
        return (Double) v;
    }

    public static double num(Map<String, Object> m, String k, double fallback) {
        Object v = m.get(k);
        if (v == null) {
            return fallback;
        }
        if (!(v instanceof Double)) {
            throw new IllegalArgumentException("field '" + k + "' is not a number");
        }
        return (Double) v;
    }

    public static double[] doubles(List<Object> list, String what) {
        double[] out = new double[list.size()];
        for (int i = 0; i < out.length; i++) {
            Object v = list.get(i);
            if (!(v instanceof Double)) {
                throw new IllegalArgumentException(what + "[" + i + "] is not a number");
            }
            out[i] = (Double) v;
        }
        return out;
    }

    public static String[] strings(List<Object> list, String what) {
        String[] out = new String[list.size()];
        for (int i = 0; i < out.length; i++) {
            Object v = list.get(i);
            if (!(v instanceof String)) {
                throw new IllegalArgumentException(what + "[" + i + "] is not a string");
            }
            out[i] = (String) v;
        }
        return out;
    }

    private static Object require(Map<String, Object> m, String k) {
        if (m == null) {
            throw new IllegalArgumentException("object is null");
        }
        if (!m.containsKey(k)) {
            throw new IllegalArgumentException("missing required field '" + k + "'");
        }
        Object v = m.get(k);
        if (v == null) {
            throw new IllegalArgumentException("field '" + k + "' is null");
        }
        return v;
    }

    // ==================================================================
    // Parsing
    // ==================================================================

    public static Object parse(String text) {
        Json p = new Json(text);
        p.skipWs();
        Object v = p.value();
        p.skipWs();
        if (p.pos != p.src.length()) {
            throw new IllegalArgumentException(
                    "trailing content at offset " + p.pos + " of " + p.src.length());
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("top level value is not an object");
        }
        return (Map<String, Object>) v;
    }

    private Object value() {
        if (pos >= src.length()) {
            throw new IllegalArgumentException("unexpected end of input");
        }
        char c = src.charAt(pos);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                return literal("true", Boolean.TRUE);
            case 'f':
                return literal("false", Boolean.FALSE);
            case 'n':
                return literal("null", null);
            default:
                return number();
        }
    }

    private Map<String, Object> object() {
        enter();
        expect('{');
        Map<String, Object> m = new LinkedHashMap<>();
        skipWs();
        if (peek() == '}') {
            pos++;
            depth--;
            return m;
        }
        while (true) {
            skipWs();
            String key = string();
            skipWs();
            expect(':');
            skipWs();
            m.put(key, value());
            skipWs();
            char c = next();
            if (c == '}') {
                depth--;
                return m;
            }
            if (c != ',') {
                throw new IllegalArgumentException(
                        "expected ',' or '}' at offset " + (pos - 1) + ", found '" + c + "'");
            }
        }
    }

    private List<Object> array() {
        enter();
        expect('[');
        List<Object> list = new ArrayList<>();
        skipWs();
        if (peek() == ']') {
            pos++;
            depth--;
            return list;
        }
        while (true) {
            skipWs();
            list.add(value());
            skipWs();
            char c = next();
            if (c == ']') {
                depth--;
                return list;
            }
            if (c != ',') {
                throw new IllegalArgumentException(
                        "expected ',' or ']' at offset " + (pos - 1) + ", found '" + c + "'");
            }
        }
    }

    private void enter() {
        if (++depth > MAX_DEPTH) {
            throw new IllegalArgumentException("nesting deeper than " + MAX_DEPTH);
        }
    }

    private String string() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unterminated string");
            }
            char c = src.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (pos >= src.length()) {
                    throw new IllegalArgumentException("unterminated escape");
                }
                char e = src.charAt(pos++);
                switch (e) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/');  break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    case 'u':
                        if (pos + 4 > src.length()) {
                            throw new IllegalArgumentException("truncated \\u escape");
                        }
                        String hex = src.substring(pos, pos + 4);
                        for (int i = 0; i < 4; i++) {
                            if (Character.digit(hex.charAt(i), 16) < 0) {
                                throw new IllegalArgumentException("bad hex in \\u escape: " + hex);
                            }
                        }
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("invalid escape \\" + e);
                }
            } else if (c < 0x20) {
                throw new IllegalArgumentException(
                        "raw control character U+" + String.format("%04X", (int) c) + " in string");
            } else {
                sb.append(c);
            }
        }
    }

    private Object literal(String word, Object value) {
        if (!src.startsWith(word, pos)) {
            throw new IllegalArgumentException("invalid literal at offset " + pos);
        }
        pos += word.length();
        return value;
    }

    /**
     * Strict number scanner. No regex, no exponent overflow into Infinity, no leading '+'.
     * A value too large for a double is a hard error rather than an infinity that would
     * silently poison an arithmetic check downstream.
     */
    private Double number() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        if (pos >= src.length() || !isDigit(src.charAt(pos))) {
            throw new IllegalArgumentException("expected a number at offset " + start);
        }
        if (src.charAt(pos) == '0') {
            pos++;
        } else {
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
        }
        if (pos < src.length() && src.charAt(pos) == '.') {
            pos++;
            if (pos >= src.length() || !isDigit(src.charAt(pos))) {
                throw new IllegalArgumentException("expected a digit after '.'");
            }
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
        }
        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) {
                pos++;
            }
            if (pos >= src.length() || !isDigit(src.charAt(pos))) {
                throw new IllegalArgumentException("expected a digit in the exponent");
            }
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
        }
        double d = Double.parseDouble(src.substring(start, pos));
        if (Double.isInfinite(d) || Double.isNaN(d)) {
            throw new IllegalArgumentException("number is not finite: " + src.substring(start, pos));
        }
        return d;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= src.length()) {
            throw new IllegalArgumentException("unexpected end of input");
        }
        return src.charAt(pos);
    }

    private char next() {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char c) {
        char got = next();
        if (got != c) {
            throw new IllegalArgumentException(
                    "expected '" + c + "' at offset " + (pos - 1) + ", found '" + got + "'");
        }
    }

    // ==================================================================
    // Writing
    // ==================================================================

    /** Serialises with keys in insertion order and no whitespace. Deterministic. */
    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(v, sb);
        return sb.toString();
    }

    /**
     * Appends v to sb. Public because Crypto.canonicalInto reuses this one escaping
     * implementation rather than writing a second escaper that could drift from it.
     */
    public static void write(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            quote((String) v, sb);
        } else if (v instanceof Boolean) {
            sb.append(((Boolean) v) ? "true" : "false");
        } else if (v instanceof Double) {
            sb.append(fmt((Double) v));
        } else if (v instanceof Integer || v instanceof Long) {
            sb.append(v.toString());
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                quote(String.valueOf(e.getKey()), sb);
                sb.append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object o : (List<?>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(o, sb);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException(
                    "cannot serialise " + v.getClass().getName());
        }
    }

    /**
     * Canonical double rendering, shared with the audit chain hash (Phase 1 item 7).
     *
     * Two Java-specific hazards are handled here, both of which would corrupt a hash chain
     * quietly rather than loudly:
     *
     * 1. Java's {@code %g} does NOT strip trailing zeros the way C's does - a difference that
     *    surprises everyone who learned printf in C. {@code %.10g} of 2.0 is "2.000000000" in
     *    Java, not "2". It is still deterministic, so the chain would still verify, but every
     *    number in every report would carry nine meaningless digits. The trailing zeros are
     *    therefore stripped explicitly, by string operation, which is deterministic and so
     *    cannot break reproducibility.
     * 2. {@code -0.0} would otherwise render "-0.000000000", and a chain hash computed over
     *    "-0" would not match one computed over "0" for what is the same value.
     *
     * Exponent forms are left untouched: "1.000000000e-12" is left as-is rather than risking
     * a mantissa edit that changes the value.
     */
    public static String fmt(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException("cannot serialise non-finite double: " + d);
        }
        if (d == 0.0) {
            return Config.CANONICAL_DOUBLE_ZERO; // also catches -0.0
        }
        String s = String.format(java.util.Locale.ROOT, Config.CANONICAL_DOUBLE_FORMAT, d);
        int e = s.indexOf('e');
        if (e >= 0) {
            return s;
        }
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '0') {
            end--;
        }
        if (end > 0 && s.charAt(end - 1) == '.') {
            end--;
        }
        // end can only reach 0 for an all-zero string, which the d == 0.0 guard already caught,
        // but never return an empty token to a JSON writer.
        return end == 0 ? Config.CANONICAL_DOUBLE_ZERO : s.substring(0, end);
    }

    private static void quote(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
