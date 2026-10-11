/**
 * Offline infrastructure enrichment. Phase 2 deliverable.
 *
 * The single most important property of this class is what it does NOT do. It does not resolve
 * DNS, does not open a socket, does not call a geolocation API, and does not contain a table of
 * "known IPs" from memory. Every value it returns comes from a caller-supplied artifact: a
 * dataset file, or a WHOIS/RDAP response that the caller already holds. When no such artifact
 * exists the answer is UNKNOWN, and the answer carries a provenance string saying exactly why.
 *
 * This matters for more than tidiness. A system that quietly returns a plausible country and
 * ASN for an address it never actually asked about will have those numbers pasted into a report
 * and treated as findings. An honest UNKNOWN is a real analytical result - it tells the analyst
 * the evidence is not present, which is information. A fabricated ASN is worse than nothing,
 * because it is indistinguishable from a real one once it leaves this code.
 *
 * Structure:
 *
 *   - {@link Field} pairs every value with its {@link Status} and its provenance. There is no
 *     way to read a country out of an {@link Enrichment} without also seeing where it came from.
 *   - {@link Provider} is the extension point. {@link Registry} consults providers in order and
 *     stops at the first one that actually knows the answer, so a future real provider can be
 *     added without touching this file or inventing placeholder results.
 *   - {@link DatasetProvider} reads a local TSV. Absent file means the provider is absent, which
 *     is reported as UNAVAILABLE - a different and more actionable state than UNKNOWN.
 *   - {@link #parseRdap} and {@link #parseWhois} parse text the CALLER supplies. They are pure
 *     functions over a String, which is what makes "where did this come from" answerable.
 */
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class Enrich {

    // ==================================================================
    // Status and provenance
    // ==================================================================

    /**
     * How much is actually known about a field.
     *
     * UNKNOWN and UNAVAILABLE are deliberately distinct. UNKNOWN means nobody has supplied a
     * value yet. UNAVAILABLE means a source was configured and is missing or unreadable, so the
     * analyst knows to go fix the data rather than conclude the value does not exist.
     */
    public enum Status {
        /** A value was found and its provenance is recorded. */
        KNOWN,
        /** No source supplied a value. Not a negative finding. */
        UNKNOWN,
        /** A configured source exists but is missing, empty, or unreadable. */
        UNAVAILABLE
    }

    /**
     * One enriched attribute. A value can never be read without its status and provenance,
     * because they are the same object - there is no getter that hands back a bare string.
     */
    public static final class Field {
        public final String value;
        public final Status status;
        /** Human-readable origin: which provider/file/response, and why it is unknown. */
        public final String provenance;

        private Field(String value, Status status, String provenance) {
            this.value = value;
            this.status = status;
            this.provenance = provenance;
        }

        public static Field known(String value, String provenance) {
            if (value == null || value.isBlank()) {
                return new Field(null, Status.UNKNOWN, provenance + " (source field was blank)");
            }
            return new Field(value, Status.KNOWN, provenance);
        }

        public static Field unknown(String provenance) {
            return new Field(null, Status.UNKNOWN, provenance);
        }

        public static Field unavailable(String provenance) {
            return new Field(null, Status.UNAVAILABLE, provenance);
        }

        public boolean isKnown() {
            return status == Status.KNOWN && value != null;
        }

        /** The value, or the literal token "unknown" / "unavailable". Never null, never invented. */
        public String display() {
            if (isKnown()) return value;
            return status == Status.UNAVAILABLE ? "unavailable" : "unknown";
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("value", value);
            m.put("status", status.name());
            m.put("provenance", provenance);
            return m;
        }

        @Override
        public String toString() {
            return display() + " (" + status + ")";
        }
    }

    /** The full enrichment for one address. Every field is always present. */
    public static final class Enrichment {
        public final String ip;
        public final Field country;
        public final Field isp;
        public final Field asn;
        public final Field organization;
        public final Field hostname;
        /** True when at least one field was actually resolved. */
        public final boolean anyKnown;
        /** Names of providers consulted, in order, including those that did not know. */
        public final List<String> providersConsulted;

        Enrichment(String ip, Field country, Field isp, Field asn, Field organization,
                   Field hostname, List<String> consulted) {
            this.ip = ip;
            this.country = country;
            this.isp = isp;
            this.asn = asn;
            this.organization = organization;
            this.hostname = hostname;
            this.providersConsulted = consulted;
            this.anyKnown = country.isKnown() || isp.isKnown() || asn.isKnown()
                    || organization.isKnown() || hostname.isKnown();
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", ip);
            m.put("country", country.toMap());
            m.put("isp", isp.toMap());
            m.put("asn", asn.toMap());
            m.put("organization", organization.toMap());
            m.put("hostname", hostname.toMap());
            m.put("anyKnown", anyKnown);
            m.put("providersConsulted", providersConsulted);
            return m;
        }

        @Override
        public String toString() {
            return ip + " country=" + country.display() + " asn=" + asn.display()
                    + " org=" + organization.display();
        }
    }

    // ==================================================================
    // Provider extension point
    // ==================================================================

    /** Raw provider answer for one address. All-null means "I do not know". */
    public static final class Record {
        public String country;
        public String isp;
        public String asn;
        public String organization;
        public String hostname;

        public boolean isEmpty() {
            return country == null && isp == null && asn == null
                    && organization == null && hostname == null;
        }

        public static Record of(String country, String asn, String org, String isp, String hostname) {
            Record r = new Record();
            r.country = country;
            r.asn = asn;
            r.organization = org;
            r.isp = isp;
            r.hostname = hostname;
            return r;
        }
    }

    /**
     * An offline enrichment source.
     *
     * Implementations MUST NOT perform network I/O. A future provider that does is a different
     * kind of component and belongs behind an explicit, separately reviewed gate; the interface
     * exists so the shape of a provider is fixed without pre-committing to any of them.
     */
    public interface Provider {
        /** Stable name, recorded in every Field's provenance. */
        String name();

        /** True when the provider is actually usable. A false provider yields UNAVAILABLE. */
        boolean available();

        /** Human-readable reason when {@link #available()} is false. */
        String unavailableReason();

        /** Lookup for one address. Must return an empty Record rather than guessing. */
        Record lookup(String ip);
    }

    /**
     * Ordered provider list. First provider that knows a field wins; later providers are still
     * consulted for fields the earlier one did not supply, so partial datasets compose.
     */
    public static final class Registry {
        private final List<Provider> providers = new ArrayList<>();

        public Registry add(Provider p) {
            if (p != null) providers.add(p);
            return this;
        }

        public List<Provider> providers() {
            return List.copyOf(providers);
        }

        public boolean isEmpty() {
            return providers.isEmpty();
        }

        public Enrichment lookup(String ip) {
            if (ip == null || ip.isBlank()) {
                String why = "no IP supplied to enrich";
                return new Enrichment(String.valueOf(ip),
                        Field.unknown(why), Field.unknown(why), Field.unknown(why),
                        Field.unknown(why), Field.unknown(why), List.of());
            }

            String[] values = new String[5];
            String[] suppliedBy = new String[5];
            List<String> consulted = new ArrayList<>();
            boolean anyUnavailable = false;
            String unavailableReason = null;

            for (Provider p : providers) {
                consulted.add(p.name());
                if (!p.available()) {
                    if (unavailableReason == null) {
                        unavailableReason = p.name() + " unavailable: " + p.unavailableReason();
                    }
                    anyUnavailable = true;
                    continue;
                }
                Record r;
                try {
                    r = p.lookup(ip);
                } catch (RuntimeException e) {
                    // A broken provider must not take down the analysis, and it must not be
                    // mistaken for a provider that knows the answer.
                    if (unavailableReason == null) {
                        unavailableReason = p.name() + " failed: " + e.getClass().getSimpleName();
                    }
                    anyUnavailable = true;
                    continue;
                }
                if (r == null || r.isEmpty()) continue;
                fill(values, suppliedBy, 0, r.country, p.name());
                fill(values, suppliedBy, 1, r.isp, p.name());
                fill(values, suppliedBy, 2, r.asn, p.name());
                fill(values, suppliedBy, 3, r.organization, p.name());
                fill(values, suppliedBy, 4, r.hostname, p.name());
            }

            String defaultWhy = anyUnavailable
                    ? (unavailableReason + "; no other configured source supplied a value")
                    : defaultUnknownWhy(consulted);
            if (consulted.isEmpty()) defaultWhy = NO_PROVIDER_REASON;

            Field[] fields = new Field[5];
            String[] names = {"country", "isp", "asn", "organization", "hostname"};
            for (int i = 0; i < 5; i++) {
                if (values[i] != null) {
                    fields[i] = Field.known(values[i], "offline source " + suppliedBy[i]);
                } else {
                    fields[i] = anyUnavailable
                            ? Field.unavailable(defaultWhy + " (field: " + names[i] + ")")
                            : Field.unknown(defaultWhy + " (field: " + names[i] + ")");
                }
            }
            return new Enrichment(ip, fields[0], fields[1], fields[2], fields[3], fields[4], consulted);
        }

        private void fill(String[] values, String[] suppliedBy, int idx, String v, String provider) {
            if (v == null || v.isBlank() || values[idx] != null) return;
            values[idx] = v.trim();
            // Record which provider actually supplied this value. Without this the provenance
            // string would carry a null provider name, which defeats the entire point of
            // tracking provenance.
            suppliedBy[idx] = provider;
        }

        private static String defaultUnknownWhy(List<String> consulted) {
            if (consulted.isEmpty()) return NO_PROVIDER_REASON;
            return "no configured offline source has a record for this address; "
                    + "sources consulted: " + String.join(", ", consulted)
                    + ". No network lookup was performed.";
        }
    }

    /** The provenance recorded when nothing at all is configured. */
    public static final String NO_PROVIDER_REASON =
            "no enrichment provider configured; Phase 2 performs no network requests, "
                    + "so no country/ISP/ASN/hostname is available for this address";

    private static final Registry DEFAULT_REGISTRY = new Registry();

    public static Enrichment lookup(String ip) {
        return DEFAULT_REGISTRY.lookup(ip);
    }

    public static Registry registry() {
        return DEFAULT_REGISTRY;
    }

    public static Registry newRegistry() {
        return new Registry();
    }

    // ==================================================================
    // Offline dataset provider
    // ==================================================================

    /**
     * Reads a local TSV dataset. Header line, then one record per line:
     *
     * <pre>
     * ip            country  asn     organization        isp                 hostname
     * 203.0.113.0/24 US      AS64496 Example Networks    Example ISP          mx1.example
     * 198.51.100.7  DE      AS64500 Example Hosting     Example Hosting DE   -
     * </pre>
     *
     * The first column is either an exact address or a CIDR range. A "-" or empty cell means
     * "not known" and is stored as absent, never as a placeholder string.
     *
     * A missing or unreadable file makes the provider UNAVAILABLE rather than silently
     * contributing nothing, so the report says "the dataset is missing" instead of implying the
     * analyst checked and found nothing.
     */
    public static final class DatasetProvider implements Provider {
        private final String path;
        private final List<Row> rows = new ArrayList<>();
        private final boolean available;
        private final String reason;
        /** Hard cap on rows so a hostile or mistaken dataset cannot exhaust the heap. */
        public static final int MAX_ROWS = 200_000;

        public DatasetProvider(String path) {
            this.path = path;
            boolean ok = false;
            String why;
            if (path == null || path.isBlank()) {
                why = "no dataset path supplied";
            } else {
                try {
                    String text = java.nio.file.Files.readString(java.nio.file.Path.of(path),
                            java.nio.charset.StandardCharsets.UTF_8);
                    int loaded = parseDataset(text);
                    ok = true;
                    why = "loaded " + loaded + " records from " + path;
                } catch (java.io.IOException | RuntimeException e) {
                    why = "dataset at " + path + " could not be read ("
                            + e.getClass().getSimpleName() + ")";
                }
            }
            this.available = ok;
            this.reason = why;
        }

        @Override
        public String name() {
            return "dataset:" + (path == null ? "<none>" : path);
        }

        @Override
        public boolean available() {
            return available;
        }

        @Override
        public String unavailableReason() {
            return reason;
        }

        public int size() {
            return rows.size();
        }

        private int parseDataset(String text) {
            int n = text.length();
            int i = 0;
            int lineNo = 0;
            int loaded = 0;
            boolean first = true;
            while (i < n && loaded < MAX_ROWS) {
                int nl = text.indexOf('\n', i);
                int end = nl < 0 ? n : nl;
                String line = text.substring(i, end);
                i = nl < 0 ? n : nl + 1;
                lineNo++;
                if (!line.isEmpty() && line.charAt(line.length() - 1) == '\r') {
                    line = line.substring(0, line.length() - 1);
                }
                if (line.isBlank() || line.charAt(0) == '#') continue;
                if (first) {
                    first = false;
                    // Tolerate a header row, but do not require one.
                    if (line.toLowerCase(Locale.ROOT).startsWith("ip")) continue;
                }
                List<String> cols = splitTabs(line);
                if (cols.isEmpty()) continue;
                Row row = new Row();
                row.key = cols.get(0).trim();
                if (row.key.isEmpty()) continue;
                row.cidr = row.key.indexOf('/') > 0;
                if (row.cidr) {
                    row.base = ipv4ToLong(row.key.substring(0, row.key.indexOf('/')));
                    int slash = row.key.indexOf('/');
                    int prefix;
                    try {
                        prefix = Integer.parseInt(row.key.substring(slash + 1).trim());
                    } catch (NumberFormatException e) {
                        continue;
                    }
                    if (row.base == null || prefix < 0 || prefix > 32) continue;
                    row.prefix = prefix;
                } else {
                    row.base = ipv4ToLong(row.key);
                }
                if (row.base == null && !row.key.contains(":")) continue;
                row.isV6 = row.key.contains(":");
                row.country = cell(cols, 1);
                row.asn = cell(cols, 2);
                row.organization = cell(cols, 3);
                row.isp = cell(cols, 4);
                row.hostname = cell(cols, 5);
                rows.add(row);
                loaded++;
            }
            return loaded;
        }

        private static List<String> splitTabs(String line) {
            List<String> out = new ArrayList<>();
            int start = 0;
            for (int i = 0; i <= line.length(); i++) {
                if (i == line.length() || line.charAt(i) == '\t') {
                    out.add(line.substring(start, i));
                    start = i + 1;
                }
            }
            return out;
        }

        /** "-" and "" both mean absent. Storing "-" as a value would put the literal token
         *  "unknown" into a report cell where a real answer belongs. */
        private static String cell(List<String> cols, int idx) {
            if (idx >= cols.size()) return null;
            String v = cols.get(idx).trim();
            if (v.isEmpty() || v.equals("-") || v.equalsIgnoreCase("unknown")
                    || v.equalsIgnoreCase("n/a")) {
                return null;
            }
            return v;
        }

        @Override
        public Record lookup(String ip) {
            if (!available || ip == null) return new Record();
            Long addr = ipv4ToLong(ip);
            if (addr == null) {
                for (Row r : rows) {
                    if (r.isV6 && r.key.equalsIgnoreCase(ip)) {
                        return recordOf(r);
                    }
                }
                return new Record();
            }
            // Most specific CIDR wins; an exact address beats any range.
            // NOTE: r.base and addr are boxed Long. `r.base == addr` would compare references and
            // silently fail for every address outside the -128..127 Long cache, so both sides are
            // unboxed explicitly.
            Row best = null;
            int bestPrefix = -1;
            long target = addr.longValue();
            for (Row r : rows) {
                if (r.isV6 || r.base == null) continue;
                if (!r.cidr) {
                    if (r.base.longValue() == target) {
                        return recordOf(r);
                    }
                    continue;
                }
                if (r.prefix > bestPrefix && cidrContains(r.base.longValue(), r.prefix, target)) {
                    best = r;
                    bestPrefix = r.prefix;
                }
            }
            return best == null ? new Record() : recordOf(best);
        }

        private static Record recordOf(Row r) {
            return Record.of(r.country, r.asn, r.organization, r.isp, r.hostname);
        }

        private static final class Row {
            String key;
            Long base;
            boolean cidr;
            boolean isV6;
            int prefix;
            String country;
            String asn;
            String organization;
            String isp;
            String hostname;
        }
    }

    /** Dotted-quad to unsigned long, or null. Linear scan, no regex, no exceptions. */
    static Long ipv4ToLong(String ip) {
        if (ip == null) return null;
        int n = ip.length();
        if (n < 7 || n > 15) return null;
        long v = 0;
        int seg = 0;
        int digits = 0;
        int part = 0;
        for (int i = 0; i < n; i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                if (digits == 0) return null;
                v = (v << 8) | part;
                part = 0;
                digits = 0;
                seg++;
                if (seg > 3) return null;
            } else if (c >= '0' && c <= '9') {
                if (digits >= 3) return null;
                part = part * 10 + (c - '0');
                if (part > 255) return null;
                digits++;
            } else {
                return null;
            }
        }
        if (digits == 0 || seg != 3) return null;
        v = (v << 8) | part;
        return v & 0xFFFFFFFFL;
    }

    private static boolean cidrContains(long base, int prefix, long addr) {
        if (prefix == 0) return true;
        long mask = (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (addr & mask) == (base & mask);
    }

    // ==================================================================
    // WHOIS / RDAP parsing (caller-supplied data only)
    // ==================================================================

    /**
     * Parses an RDAP response the CALLER already holds.
     *
     * This is a pure function over a String. It performs no lookup and contacts nobody; it exists
     * so that when a caller has a response, the contents land in a typed structure with
     * provenance instead of being regex-scraped ad hoc. Malformed or unexpected JSON yields an
     * empty Record plus a reason, never a partially invented one.
     */
    public static Record parseRdap(String json) {
        Record r = new Record();
        if (json == null || json.isBlank()) {
            return r;
        }
        Object parsed;
        try {
            parsed = Json.parse(json);
        } catch (RuntimeException e) {
            return r;
        }
        if (!(parsed instanceof Map)) return r;
        Map<String, Object> root = asMap(parsed);
        if (root == null) return r;

        // RDAP networks may be wrapped in an array under "networks" (IP lookups) or be the
        // object itself (autnum lookups).
        List<Object> networks = asList(root.get("networks"));
        if (networks != null && !networks.isEmpty()) {
            for (Object o : networks) {
                Map<String, Object> n = asMap(o);
                if (n == null) continue;
                if (r.country == null) r.country = rdapCountry(n);
                if (r.hostname == null) r.hostname = rdapName(n);
                if (r.organization == null) r.organization = rdapEntityName(n, "registrant");
                if (r.isp == null) r.isp = rdapEntityName(n, "administrative");
            }
        } else {
            if (r.country == null) r.country = rdapCountry(root);
            if (r.hostname == null) r.hostname = rdapName(root);
            if (r.organization == null) r.organization = rdapEntityName(root, "registrant");
            if (r.isp == null) r.isp = rdapEntityName(root, "administrative");
            if (r.asn == null) {
                String handle = str(root.get("handle"));
                if (handle != null && handle.toUpperCase(Locale.ROOT).startsWith("AS")) r.asn = handle;
            }
        }
        return r;
    }

    private static String rdapName(Map<String, Object> node) {
        List<Object> remarks = asList(node.get("remarks"));
        if (remarks != null) {
            for (Object o : remarks) {
                Map<String, Object> rm = asMap(o);
                if (rm == null) continue;
                for (Object line : asList(rm.get("description"))) {
                    if (line instanceof String s && !s.isBlank()) return s.trim();
                }
            }
        }
        return str(node.get("name"));
    }

    private static String rdapCountry(Map<String, Object> node) {
        String c = str(node.get("country"));
        if (c != null && !c.isBlank()) return c.trim().toUpperCase(Locale.ROOT);
        List<Object> entities = asList(node.get("entities"));
        if (entities != null) {
            for (Object o : entities) {
                Map<String, Object> e = asMap(o);
                if (e == null) continue;
                String v = rdapVcardField(e, "adr", "country");
                if (v != null) return v.toUpperCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static String rdapEntityName(Map<String, Object> node, String role) {
        List<Object> entities = asList(node.get("entities"));
        if (entities == null) return null;
        for (Object o : entities) {
            Map<String, Object> e = asMap(o);
            if (e == null) continue;
            List<Object> roles = asList(e.get("roles"));
            if (roles == null) continue;
            boolean match = false;
            for (Object rl : roles) {
                if (rl instanceof String s && s.equalsIgnoreCase(role)) match = true;
            }
            if (!match) continue;
            String v = rdapVcardField(e, "fn");
            if (v != null) return v;
            return str(e.get("handle"));
        }
        return null;
    }

    /**
     * Reads a vcardArray property.
     *
     * The spec form is vcardArray = ["vcard", [ [key, params, type, value], ... ]], where the
     * value is positional - always index 3 - and an "adr" value is itself a four-element array
     * whose last element is the country. Some registrars instead emit a flattened
     * [labels..., values-map] pair. Both are accepted, because rejecting real-world data would
     * turn a usable answer into a silent UNKNOWN; the label is matched case-insensitively in
     * either shape so a schema tweak cannot silently shift which value lands in which field.
     */
    private static String rdapVcardField(Map<String, Object> entity, String... labels) {
        List<Object> arr = asList(entity.get("vcardArray"));
        if (arr == null || arr.size() < 2) return null;

        // Spec form: second element is a list of [key, params, type, value] tuples.
        List<Object> entries = asList(arr.get(1));
        if (entries != null) {
            for (Object o : entries) {
                List<Object> tuple = asList(o);
                if (tuple == null || tuple.size() < 4) continue;
                Object key = tuple.get(0);
                if (!(key instanceof String ks)) continue;
                if (!matchesLabel(ks, labels)) continue;
                String v = vcardValue(tuple.get(3), ks.equalsIgnoreCase("adr"));
                if (v != null) return v;
            }
        }

        // Flattened form: positional labels paired with a values map.
        List<Object> keys = asList(arr.get(0));
        Map<String, Object> vals = asMap(arr.get(1));
        if (keys != null && vals != null) {
            for (String want : labels) {
                for (int i = 0; i < keys.size(); i++) {
                    if (!(keys.get(i) instanceof String ks)) continue;
                    if (!ks.equalsIgnoreCase(want)) continue;
                    String v = vcardValue(vals.get(ks), ks.equalsIgnoreCase("adr"));
                    if (v != null) return v;
                }
            }
        }
        return null;
    }

    private static boolean matchesLabel(String key, String[] labels) {
        for (String l : labels) {
            if (key.equalsIgnoreCase(l)) return true;
        }
        return false;
    }

    /** Normalises a vcard value that may be a plain string or an array (as "adr" always is). */
    private static String vcardValue(Object raw, boolean isAdr) {
        List<Object> list = asList(raw);
        if (list != null) {
            // adr = [po-box, extended, locality, region, postal, country] in some registries and
            // [po-box, extended, locality, country] in others. Country is last either way.
            for (int i = list.size() - 1; i >= 0; i--) {
                if (list.get(i) instanceof String s && !s.isBlank()) return s.trim();
            }
            return null;
        }
        if (raw instanceof String s && !s.isBlank()) {
            return isAdr ? s.trim() : s.trim();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return (o instanceof Map) ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) {
        return (o instanceof List) ? (List<Object>) o : null;
    }

    private static String str(Object o) {
        return (o instanceof String s) ? s : null;
    }

    /**
     * Parses classic WHOIS text the CALLER already holds. Line-oriented, case-insensitive key
     * match, no regex and no backtracking. First occurrence of a key wins, because WHOIS output
     * often repeats keys and the first is the authoritative one.
     *
     * Recognised keys: country, netrange/inetnum/inet6num, netname, org/organisation,
     * origin/originas, and the "org-name:" that RIPE-style output uses.
     */
    public static Record parseWhois(String text) {
        Record r = new Record();
        if (text == null || text.isBlank()) return r;
        int n = text.length();
        int i = 0;
        String range = null;
        while (i < n) {
            int nl = text.indexOf('\n', i);
            int end = nl < 0 ? n : nl;
            String line = text.substring(i, end);
            i = nl < 0 ? n : nl + 1;
            if (line.isEmpty()) continue;
            if (!line.isEmpty() && line.charAt(line.length() - 1) == '\r') {
                line = line.substring(0, line.length() - 1);
            }
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String key = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String val = line.substring(colon + 1).trim();
            if (val.isEmpty() || val.equals("-")) continue;

            switch (key) {
                case "country" -> {
                    if (r.country == null) r.country = val.toUpperCase(Locale.ROOT);
                }
                case "netname", "net-name" -> {
                    if (r.organization == null) r.organization = val;
                    if (r.isp == null) r.isp = val;
                }
                case "org", "org-name", "organisation", "organization", "descr" -> {
                    if (r.organization == null) r.organization = val;
                }
                case "origin", "originas", "origin-as" -> {
                    if (r.asn == null) r.asn = val.toUpperCase(Locale.ROOT);
                }
                case "inetnum", "inet6num", "netrange" -> {
                    if (range == null) range = val;
                }
                case "hostname", "nserver" -> {
                    if (r.hostname == null) r.hostname = firstHostToken(val);
                }
                default -> {
                    // Key not recognised: ignored, not guessed.
                }
            }
        }
        if (r.asn == null && range != null) {
            // Some registries put "ASnnn" inside the netname. Only accept it when it really
            // looks like an autonomous system number.
            for (String tok : range.split("[\\s,;()]+")) {
                if (tok.length() > 2 && (tok.charAt(0) == 'A' || tok.charAt(0) == 'a')) {
                    String t = tok.toUpperCase(Locale.ROOT);
                    if (t.startsWith("AS")) {
                        boolean digits = t.length() > 2;
                        for (int k = 2; k < t.length() && digits; k++) {
                            digits = Character.isDigit(t.charAt(k));
                        }
                        if (digits) {
                            r.asn = t;
                            break;
                        }
                    }
                }
            }
        }
        return r;
    }

    private static String firstHostToken(String s) {
        String t = s.trim();
        int sp = t.indexOf(' ');
        if (sp > 0) t = t.substring(0, sp);
        if (t.isEmpty() || t.equals("-")) return null;
        return t;
    }

    /**
     * Builds a provider that serves a fixed, caller-supplied set of answers. Useful for tests and
     * for a future real provider to build on. It stores what it is given and nothing else: there
     * is no default country and no fallback ASN.
     */
    public static Provider fixedProvider(String name, Map<String, Record> table) {
        return new Provider() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean available() {
                return table != null && !table.isEmpty();
            }

            @Override
            public String unavailableReason() {
                return available() ? "" : "fixed provider '" + name + "' has no records";
            }

            @Override
            public Record lookup(String ip) {
                if (table == null || ip == null) return new Record();
                Record r = table.get(ip);
                return r == null ? new Record() : r;
            }
        };
    }

    // ==================================================================
    // Self-test
    // ==================================================================

    public static void main(String[] args) {
        System.out.println("=== no provider configured (must be honest UNKNOWN) ===");
        Enrichment none = newRegistry().lookup("203.0.113.9");
        System.out.println("country : " + none.country + " | display=" + none.country.display());
        System.out.println("provenance: " + none.country.provenance);
        System.out.println("anyKnown : " + none.anyKnown);

        System.out.println();
        System.out.println("=== caller-supplied dataset ===");
        String tsv = "ip\tcountry\tasn\torganization\tisp\thostname\n"
                + "203.0.113.0/24\tUS\tAS64496\tExample Networks\tExample ISP\tmx1.example\n"
                + "198.51.100.7\tDE\tAS64500\tExample Hosting\tExample Hosting DE\t-\n";
        java.nio.file.Path tmp;
        try {
            tmp = java.nio.file.Files.createTempFile("enrich", ".tsv");
            java.nio.file.Files.writeString(tmp, tsv, java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            System.out.println("could not stage temp dataset: " + e);
            return;
        }
        Registry reg = newRegistry().add(new DatasetProvider(tmp.toString()));
        for (String ip : new String[]{"203.0.113.9", "198.51.100.7", "192.0.2.1"}) {
            Enrichment e = reg.lookup(ip);
            System.out.println(ip + " -> country=" + e.country.display()
                    + " asn=" + e.asn.display() + " org=" + e.organization.display()
                    + " host=" + e.hostname.display()
                    + " [" + e.country.status + "]");
            if (e.country.isKnown()) {
                System.out.println("    provenance: " + e.country.provenance);
            }
        }
        try {
            java.nio.file.Files.deleteIfExists(tmp);
        } catch (java.io.IOException ignored) {
            // best effort
        }

        System.out.println();
        System.out.println("=== missing dataset -> UNAVAILABLE, not silent UNKNOWN ===");
        Enrichment miss = newRegistry().add(new DatasetProvider("no-such-file.tsv")).lookup("203.0.113.9");
        System.out.println("country: " + miss.country.status + " | " + miss.country.provenance);

        System.out.println();
        System.out.println("=== RDAP (caller-supplied) ===");
        String rdap = "{\"handle\":\"AS64496\",\"country\":\"US\","
                + "\"entities\":[{\"roles\":[\"registrant\"],\"vcardArray\":[\"vcard\","
                + "[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"Example Registrant\"],"
                + "[\"adr\",{},\"array\",[\"\",\"\",\"Berlin\",\"DE\"]]]]}]}";
        Record rr = parseRdap(rdap);
        System.out.println("country=" + rr.country + " org=" + rr.organization + " asn=" + rr.asn);

        System.out.println();
        System.out.println("=== WHOIS (caller-supplied) ===");
        String whois = "% IANA\n"
                + "inetnum:        203.0.113.0 - 203.0.113.255\n"
                + "country:        DE\n"
                + "org-name:       Example GmbH\n"
                + "origin:         AS64496\n"
                + "netname:        EXAMPLE-NET\n";
        Record wr = parseWhois(whois);
        System.out.println("country=" + wr.country + " org=" + wr.organization
                + " asn=" + wr.asn + " isp=" + wr.isp);

        System.out.println();
        System.out.println("=== garbage in, nothing out ===");
        System.out.println("rdap(\"not json\") country=" + parseRdap("not json").country);
        System.out.println("whois(\"\\x00\\x01\") country=" + parseWhois("\u0000\u0001").country);
        System.out.println("OK Enrich");
    }
}
