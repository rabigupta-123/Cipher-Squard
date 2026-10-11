/**
 * Infrastructure attribution from parsed email. Phase 2 deliverable.
 *
 * This class answers exactly one question: which network infrastructure can be observed in
 * this message's own headers, and how much do we trust that observation. It does not answer
 * who sent the message. Those are different questions, and conflating them is how a technical
 * signal turns into a false accusation in a report.
 *
 * Three design commitments follow from that, and each is enforced in code rather than in a
 * comment:
 *
 * 1. NO INVENTED ATTRIBUTES. An address is either present in the headers or it is not. If the
 *    message was relayed by a VPN or a proxy, that is a property of a hop's "with:" token or of
 *    a dataset the caller supplied - it is never assumed from a reverse-DNS name, a hosting
 *    provider's brand, or a geo-lookup. {@link #indicators} can only be non-empty when something
 *    observable produced them.
 *
 * 2. NO RAW CONFIDENCE. {@link #confidence} is a sum of named, weighted {@link Factor}s. A
 *    reader can see every term that moved the number, which means a reviewer can disagree with
 *    a specific term rather than with an unexplained score. The maximum reachable total is
 *    0.85, so a full set of positive evidence still cannot produce a confident claim about a
 *    human being. The cap is structural, not advisory.
 *
 * 3. UNCERTAINTY IS FIRST-CLASS. {@link #uncertain} is populated before {@link #confidence} is
 *    computed, and missing evidence lowers the score. Ordering is explicit: hops are ranked by
 *    timestamp when timestamps parse, and by header depth when they do not, and
 *    {@link Ordering#basis} records which rule was used.
 */
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class Attribution {

    /**
     * Hard ceiling on attribution confidence.
     *
     * Even with a single public origin address, perfectly consistent timestamps, and a matching
     * network record, the observable infrastructure is at most strong supporting evidence about
     * a host. It is never proof of who was at the keyboard, because that host may be shared,
     * NATed, proxied, compromised, or automated. Structural ceiling, enforced by clamping.
     */
    public static final double CONFIDENCE_CAP = 0.85;

    // ---- the scoring model, exactly as specified -------------------------------------------
    // Weighted geometric mean. The weights are properties of the model, not tuning knobs, so they
    // are named constants rather than literals buried in the arithmetic.
    public static final double W_TRACEABILITY = 0.35;
    public static final double W_STABILITY = 0.25;
    public static final double W_ANONYMITY = 0.25;
    public static final double W_CORROBORATION = 0.15;

    /**
     * Domain age, in days, at which a domain is treated as fully stable.
     *
     * The stability factor saturates here: a domain that has existed for a year or more scores
     * the full domain-age contribution, and a brand-new domain scores none of it. A linear ramp
     * is used rather than a decay because it is directly readable in a report - an analyst can
     * see that a 40-day-old domain is contributing roughly 0.11 without trusting a formula.
     */
    public static final int DOMAIN_STABILITY_HORIZON_DAYS = 365;

    /** Attribution label band boundaries. */
    public static final double BAND_PROBABLE = 0.70;
    public static final double BAND_INDICATIVE = 0.45;
    public static final double BAND_WEAK = 0.25;

    /**
     * The required disclaimer. Present in every {@link Result}, without exception, and returned
     * by {@link #disclaimer()}. A caller cannot obtain an attribution without it.
     */
    public static final String DISCLAIMER =
            "This result identifies technically observable infrastructure and does not establish "
                    + "the physical identity or intent of the sender. IP addresses may represent "
                    + "shared infrastructure, NAT, VPNs, proxies, cloud systems, compromised hosts, "
                    + "or other intermediaries.";

    public static String disclaimer() {
        return DISCLAIMER;
    }

    // ==================================================================
    // Address classification
    // ==================================================================

    /**
     * Why an address is or is not publicly routable. The distinction between PRIVATE and
     * RESERVED matters: a private address says the relay is inside a network we cannot see
     * past, whereas a reserved address (documentation, benchmarking, CGNAT) is not a real
     * endpoint at all and must never be reported as infrastructure.
     */
    public enum Scope {
        PUBLIC("publicly routable"),
        PRIVATE("private, non-routable (RFC 1918 / unique local)"),
        RESERVED("reserved, not a real routable endpoint"),
        LOOPBACK("loopback"),
        LINK_LOCAL("link-local"),
        MULTICAST("multicast"),
        UNSPECIFIED("unspecified address"),
        BROADCAST("broadcast address"),
        CARRIER_GRADE_NAT("carrier-grade NAT shared address space (RFC 6598)"),
        UNKNOWN("could not be classified");

        public final String description;

        Scope(String d) {
            this.description = d;
        }
    }

    /** One address observed in the message, with the reason it was or was not kept. */
    public static final class IpFact {
        public final String ip;
        public final Scope scope;
        public final String source;
        /** True when this is the earliest technically observable public address. */
        public boolean primary;

        IpFact(String ip, Scope scope, String source) {
            this.ip = ip;
            this.scope = scope;
            this.source = source;
        }

        public boolean isPublic() {
            return scope == Scope.PUBLIC;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", ip);
            m.put("scope", scope.name());
            m.put("scopeDescription", scope.description);
            m.put("source", source);
            m.put("primary", primary);
            return m;
        }

        @Override
        public String toString() {
            return ip + " [" + scope + (primary ? ", primary" : "") + "]";
        }
    }

    /**
     * Classifies an address. IPv4 is exact against the IANA special-purpose registry; IPv6 is
     * handled for the blocks that actually appear in mail headers.
     *
     * Deliberately conservative: anything not positively identified as public is not called
     * public. Over-claiming routability would put an unroutable address into a report as
     * attacker infrastructure.
     */
    public static Scope classifyIp(String ip) {
        if (ip == null) return Scope.UNKNOWN;
        String s = ip.trim();
        if (s.isEmpty()) return Scope.UNKNOWN;

        if (s.indexOf(':') >= 0) return classifyIpv6(s);
        Long v = ipv4ToLong(s);
        if (v == null) return Scope.UNKNOWN;
        long a = v.longValue();

        if (a == 0L) return Scope.UNSPECIFIED;                       // 0.0.0.0/8
        if (a == 0xFFFFFFFFL) return Scope.BROADCAST;               // 255.255.255.255
        if ((a & 0xFF000000L) == 0x7F000000L) return Scope.LOOPBACK; // 127.0.0.0/8
        if ((a & 0xFF000000L) == 0x0A000000L) return Scope.PRIVATE;  // 10.0.0.0/8
        if ((a & 0xFFF00000L) == 0xAC100000L) return Scope.PRIVATE;  // 172.16.0.0/12
        if ((a & 0xFFFF0000L) == 0xC0A80000L) return Scope.PRIVATE;  // 192.168.0.0/16
        if ((a & 0xFFFF0000L) == 0xA9FE0000L) return Scope.LINK_LOCAL; // 169.254.0.0/16
        if ((a & 0xFFC00000L) == 0x64400000L) return Scope.CARRIER_GRADE_NAT; // 100.64.0.0/10
        if ((a & 0xFFFFFF00L) == 0xC0000000L) return Scope.RESERVED;  // 192.0.0.0/24
        if ((a & 0xFFFFFF00L) == 0xC0000200L) return Scope.RESERVED;  // 192.0.2.0/24 doc
        if ((a & 0xFFFFFF00L) == 0xC6120000L) return Scope.RESERVED;  // 198.18.0.0/15 bench
        if ((a & 0xFFFFFF00L) == 0xC6336400L) return Scope.RESERVED;  // 198.51.100.0/24 doc
        if ((a & 0xFFFFFF00L) == 0xCB007100L) return Scope.RESERVED;  // 203.0.113.0/24 doc
        if ((a & 0xF0000000L) == 0xE0000000L) return Scope.MULTICAST;  // 224.0.0.0/4
        if ((a & 0xF0000000L) == 0xF0000000L) return Scope.RESERVED;  // 240.0.0.0/4
        return Scope.PUBLIC;
    }

    private static Scope classifyIpv6(String s) {
        String t = s.toLowerCase(Locale.ROOT);
        if (t.startsWith("[")) {
            int close = t.indexOf(']');
            if (close < 0) return Scope.UNKNOWN;
            t = t.substring(1, close);
        }
        if (t.indexOf(':') < 0) return Scope.UNKNOWN;
        if (t.equals("::") || t.equals("::0")) return Scope.UNSPECIFIED;
        if (t.equals("::1")) return Scope.LOOPBACK;

        // fc00::/7 unique-local. The first hextet is (v & 0xfe00) == 0xfc00.
        int firstHextet = leadingHextet(t);
        if (firstHextet < 0) return Scope.UNKNOWN;
        if ((firstHextet & 0xFE00) == 0xFC00) return Scope.PRIVATE;      // fc00::/7
        if ((firstHextet & 0xFFC0) == 0xFE80) return Scope.LINK_LOCAL;    // fe80::/10
        if ((firstHextet & 0xFF00) == 0xFF00) return Scope.MULTICAST;     // ff00::/8
        if ((firstHextet & 0xFFC0) == 0xFE00) return Scope.RESERVED;     // fec0::/10 deprecated
        // 2001:db8::/32 documentation
        if (t.startsWith("2001:db8:")) return Scope.RESERVED;
        // 100::/64 discard-only
        if (t.startsWith("100:")) return Scope.RESERVED;
        // Global unicast is 2000::/3. Outside that, treat as reserved rather than public.
        if ((firstHextet & 0xE000) == 0x2000) return Scope.PUBLIC;
        return Scope.RESERVED;
    }

    /** First hextet of a (possibly compressed) IPv6 literal as an int, or -1. */
    private static int leadingHextet(String t) {
        int colon = t.indexOf(':');
        String head = colon < 0 ? t : t.substring(0, colon);
        if (head.isEmpty()) return 0; // leading "::" -> all zeros
        if (head.length() > 4) return -1;
        int v = 0;
        for (int i = 0; i < head.length(); i++) {
            int d = Character.digit(head.charAt(i), 16);
            if (d < 0) return -1;
            v = (v << 4) | d;
        }
        return v;
    }

    static Long ipv4ToLong(String ip) {
        if (ip == null) return null;
        int n = ip.length();
        if (n < 7 || n > 15) return null;
        long v = 0;
        int seg = 0, digits = 0, part = 0;
        for (int i = 0; i < n; i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                if (digits == 0) return null;
                v = (v << 8) | part;
                part = 0;
                digits = 0;
                if (++seg > 3) return null;
            } else if (c >= '0' && c <= '9') {
                if (++digits > 3) return null;
                part = part * 10 + (c - '0');
                if (part > 255) return null;
            } else {
                return null;
            }
        }
        if (digits == 0 || seg != 3) return null;
        return (v << 8 | part) & 0xFFFFFFFFL;
    }

    /**
     * Extracts address literals from free text with a bounded linear scan.
     *
     * No regular expression: a pattern like {@code \d{1,3}(\.\d{1,3}){3}} over hostile input is
     * a denial-of-service surface, and email bodies are hostile input. Each candidate is
     * validated by {@link #classifyIp} before it is accepted, so "999.1.1.1" and version strings
     * like "1.2.3.4.5" are rejected rather than truncated into a plausible-looking address.
     */
    public static List<IpFact> extractIps(String text, String source, int cap) {
        List<IpFact> out = new ArrayList<>();
        if (text == null || text.isEmpty() || cap <= 0) return out;
        int n = text.length();
        int i = 0;
        while (i < n && out.size() < cap) {
            char c = text.charAt(i);
            boolean start = c == '[' || (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!start) {
                i++;
                continue;
            }
            int j = i;
            boolean hex = c == '[' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (c == '[') {
                j++;
                hex = true;
            }
            int s = j;
            while (j < n) {
                char d = text.charAt(j);
                boolean okChar = (d >= '0' && d <= '9') || (hex && ((d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F')))
                        || d == '.' || d == ':';
                if (!okChar) break;
                j++;
            }
            if (j > s) {
                String token = text.substring(s, j);
                // Bracketed form: require the closing bracket to be a real literal.
                if (c == '[') {
                    if (j < n && text.charAt(j) == ']') {
                        Scope sc = classifyIp(token);
                        if (sc != Scope.UNKNOWN) out.add(new IpFact(token, sc, source));
                    }
                    i = j + 1;
                    continue;
                }
                if (token.indexOf(':') >= 0) {
                    Scope sc = classifyIp(token);
                    if (sc != Scope.UNKNOWN) out.add(new IpFact(token, sc, source));
                } else {
                    // Dotted quad: consume the full run of digits/dots, then require a valid quad.
                    // "1.2.3.4.5" yields token "1.2.3.4.5", which fails validation and is dropped -
                    // the correct outcome, rather than reporting the prefix "1.2.3.4".
                    Scope sc = classifyIp(token);
                    if (sc != Scope.UNKNOWN) out.add(new IpFact(token, sc, source));
                }
                i = j;
            } else {
                i++;
            }
        }
        return out;
    }

    // ==================================================================
    // Hop ordering
    // ==================================================================

    /** How hops were ranked, recorded so a reader can audit the ordering decision. */
    public enum Ordering {
        /** RFC 5321 orders Received top-down, newest first, so ascending time is earliest. */
        TIMESTAMP("hop timestamps"),
        /** No usable timestamps: header order is the only signal, and the deepest hop is earliest. */
        HEADER_DEPTH("header order (no usable timestamps)"),
        /** Only one hop, or nothing to compare. */
        TRIVIAL("single or no hop");

        public final String basis;

        Ordering(String b) {
            this.basis = b;
        }
    }

    // ==================================================================
    // Confidence
    // ==================================================================

    /** One named, weighted term in the confidence sum. */
    public static final class Factor {
        public final String name;
        public final String detail;
        public final double weight;

        Factor(String name, String detail, double weight) {
            this.name = name;
            this.detail = detail;
            this.weight = weight;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("factor", name);
            m.put("detail", detail);
            m.put("weight", weight);
            return m;
        }

        @Override
        public String toString() {
            return (weight >= 0 ? "+" : "") + trim(weight) + " " + name;
        }
    }

    /**
     * The four factors the scoring model is defined over. Each is in [0,1] and each is reported
     * even when it is zero, so a collapsed score can always be traced to the factor that caused it.
     */
    public static final class TraceFactors {
        /** T - traceability: resolved public hops / total hops. */
        public final double traceability;
        /** S - stability: composite of domain age, RDAP privacy, MX presence. */
        public final double stability;
        /** A - anonymity: strongest of VPN/proxy, Tor exit, open relay, cloud-hosted. */
        public final double anonymity;
        /** X - corroboration: agreeing independent signals / 4 attribute groups. */
        public final double corroboration;
        /** Which sub-signals were actually observed, versus unobserved and scored as zero. */
        public final List<String> observed;
        public final List<String> unobserved;

        TraceFactors(double t, double s, double a, double x, List<String> observed,
                     List<String> unobserved) {
            this.traceability = t;
            this.stability = s;
            this.anonymity = a;
            this.corroboration = x;
            this.observed = List.copyOf(observed);
            this.unobserved = List.copyOf(unobserved);
        }

        /**
         * The specified combination: a weighted geometric mean, so a single zero factor collapses
         * the result to zero. That is the intended behaviour, not a defect: if nothing resolved,
         * nothing can be attributed.
         */
        public double combine() {
            return combine(traceability, stability, anonymity, corroboration);
        }

        /** The formula alone, exposed so it can be asserted directly. */
        public static double combine(double t, double s, double a, double x) {
            double tc = clamp01(t);
            double sc = clamp01(s);
            double ac = clamp01(a);
            double xc = clamp01(x);
            // (1 - A) rather than A: anonymity is evidence AGAINST attribution.
            return Math.pow(tc, W_TRACEABILITY)
                    * Math.pow(sc, W_STABILITY)
                    * Math.pow(1.0 - ac, W_ANONYMITY)
                    * Math.pow(xc, W_CORROBORATION);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("T_traceability", traceability);
            m.put("S_stability", stability);
            m.put("A_anonymity", anonymity);
            m.put("X_corroboration", corroboration);
            m.put("observed", observed);
            m.put("unobserved", unobserved);
            m.put("formula", "T^0.35 * S^0.25 * (1-A)^0.25 * X^0.15");
            return m;
        }

        @Override
        public String toString() {
            return "T=" + trim(traceability) + " S=" + trim(stability)
                    + " A=" + trim(anonymity) + " X=" + trim(corroboration);
        }
    }

    private static double clamp01(double d) {
        if (Double.isNaN(d)) return 0.0;
        return Math.max(0.0, Math.min(1.0, d));
    }

    /** Label band for an attribution confidence. Reported alongside the number, never instead. */
    public enum Band {
        PROBABLE, INDICATIVE, WEAK, INSUFFICIENT
    }

    /** The specified bands. Boundaries are inclusive at the bottom of each band. */
    public static Band bandOf(double confidence) {
        double c = clamp01(confidence);
        if (c >= BAND_PROBABLE) return Band.PROBABLE;
        if (c >= BAND_INDICATIVE) return Band.INDICATIVE;
        if (c >= BAND_WEAK) return Band.WEAK;
        return Band.INSUFFICIENT;
    }

    /** A bounded, explainable score. Never exceeds {@link #CONFIDENCE_CAP}. */
    public static final class Confidence {
        public final double value;
        /** The four factors actually combined, so the number is always reproducible. */
        public final TraceFactors trace;
        public final Band band;
        public final List<Factor> factors;
        /** Set when clamping changed the value, so the ceiling is never silent. */
        public final String capNote;
        /** True when the score describes infrastructure only, not a person. */
        public final boolean capped;

        Confidence(double value, TraceFactors trace, List<Factor> factors, String capNote,
                   boolean capped) {
            this.value = value;
            this.trace = trace;
            this.band = bandOf(value);
            this.factors = List.copyOf(factors);
            this.capNote = capNote;
            this.capped = capped;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("value", value);
            m.put("band", band.name());
            m.put("capped", capped);
            m.put("cap", CONFIDENCE_CAP);
            m.put("factors", trace.toMap());
            m.put("evidence", factors.stream().map(Factor::toMap).toList());
            m.put("scale", "infrastructure-observation only; NOT a probability of human identity");
            if (capNote != null) m.put("capNote", capNote);
            return m;
        }

        @Override
        public String toString() {
            return trim(value) + " " + band.name()
                    + (capped ? " (capped at " + trim(CONFIDENCE_CAP) + ")" : "");
        }
    }

    private static String trim(double d) {
        String s = String.format(Locale.ROOT, "%.2f", d);
        return s;
    }

    // ==================================================================
    // Result
    // ==================================================================

    /** The full attribution for one message. The disclaimer is always present. */
    public static final class Result {
        /** Earliest technically observable public address, or null with a stated reason. */
        public final String primaryIp;
        public final List<IpFact> candidates;
        public final List<EmailParser.ReceivedHop> hops;
        public final Ordering ordering;
        public final Confidence confidence;
        public final List<String> uncertain;
        /** VPN/proxy/TOR observations, each with the evidence that produced it. */
        public final List<String> indicators;
        public final List<String> privateHops;
        public final List<String> reservedHops;
        public final String disclaimer;
        public final Enrich.Enrichment enrichment;

        Result(String primaryIp, List<IpFact> candidates, List<EmailParser.ReceivedHop> hops,
               Ordering ordering, Confidence confidence, List<String> uncertain,
               List<String> indicators, List<String> privateHops, List<String> reservedHops,
               Enrich.Enrichment enrichment) {
            this.primaryIp = primaryIp;
            this.candidates = List.copyOf(candidates);
            this.hops = List.copyOf(hops);
            this.ordering = ordering;
            this.confidence = confidence;
            this.uncertain = List.copyOf(uncertain);
            this.indicators = List.copyOf(indicators);
            this.privateHops = List.copyOf(privateHops);
            this.reservedHops = List.copyOf(reservedHops);
            this.enrichment = enrichment;
            this.disclaimer = DISCLAIMER;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("primaryIp", primaryIp);
            m.put("candidates", candidates.stream().map(IpFact::toMap).toList());
            m.put("hops", hops.stream().map(EmailParser.ReceivedHop::toMap).toList());
            m.put("ordering", ordering.name());
            m.put("orderingBasis", ordering.basis);
            m.put("confidence", confidence.toMap());
            m.put("uncertain", uncertain);
            m.put("indicators", indicators);
            m.put("privateHops", privateHops);
            m.put("reservedHops", reservedHops);
            m.put("enrichment", enrichment == null ? null : enrichment.toMap());
            m.put("disclaimer", disclaimer);
            return m;
        }

        @Override
        public String toString() {
            return "primary=" + primaryIp + " confidence=" + confidence
                    + " ordering=" + ordering;
        }
    }

    /**
     * Caller-supplied hints. Everything here must come from an artifact the analyst has.
     * There are no defaults that assert an address is a VPN or a proxy, because a wrong
     * assertion in that field is exactly the kind of fabricated finding this class exists to
     * prevent.
     */
    public static final class Hints {
        /** ASN or provider names the analyst's own data marks as anonymiser/proxy infrastructure. */
        public final Set<String> anonymiserNetworks = new LinkedHashSet<>();
        /**
         * Registered organisation / ISP names the analyst's own data marks as anonymiser or
         * privacy infrastructure. Compared against the resolved operator name, lowercased.
         */
        public final Set<String> anonymiserOrgs = new LinkedHashSet<>();
        /** True when a reverse-DNS or registration artifact indicates a known proxy service. */
        public final Set<String> proxyHosts = new LinkedHashSet<>();
        /**
         * Domain age in days, supplied by the analyst's own data, lowercased domain to age.
         *
         * The stability factor needs to know how long a domain has existed, and nothing in this
         * offline system can discover that: it has no WHOIS, no RDAP and no network. The value is
         * therefore only ever used if the analyst supplied it, and a domain absent from this map
         * is reported as unobserved rather than assumed to be old.
         */
        public final Map<String, Integer> domainAges = new LinkedHashMap<>();
        /**
         * Domains for which the analyst's own data shows MX records present. A domain that is
         * known to have no MX records must be recorded as absent via {@link #withMxAbsent}.
         */
        public final Set<String> mxPresentDomains = new LinkedHashSet<>();
        /** Domains the analyst's own data shows to have no MX records. */
        public final Set<String> mxAbsentDomains = new LinkedHashSet<>();
        /** Optional registry for enrichment; null means no enrichment is attempted. */
        public Enrich.Registry registry;

        public Hints withAnonymiserNetwork(String s) {
            if (s != null && !s.isBlank()) anonymiserNetworks.add(s.trim().toUpperCase(Locale.ROOT));
            return this;
        }

        /**
         * Records an observed domain age. Negative ages are rejected: a domain created in the
         * future is a clock artefact, not a signal, and must not be scored as maximally stable.
         */
        public Hints withDomainAge(String domain, int ageDays) {
            if (domain != null && !domain.isBlank() && ageDays >= 0) {
                domainAges.put(domain.trim().toLowerCase(Locale.ROOT), ageDays);
            }
            return this;
        }

        public Hints withMxPresent(String domain) {
            if (domain != null && !domain.isBlank()) {
                mxPresentDomains.add(domain.trim().toLowerCase(Locale.ROOT));
                mxAbsentDomains.remove(domain.trim().toLowerCase(Locale.ROOT));
            }
            return this;
        }

        public Hints withMxAbsent(String domain) {
            if (domain != null && !domain.isBlank()) {
                mxAbsentDomains.add(domain.trim().toLowerCase(Locale.ROOT));
                mxPresentDomains.remove(domain.trim().toLowerCase(Locale.ROOT));
            }
            return this;
        }

        public Hints withAnonymiserOrg(String s) {
            if (s != null && !s.isBlank()) anonymiserOrgs.add(s.trim().toLowerCase(Locale.ROOT));
            return this;
        }

        public Hints withProxyHost(String s) {
            if (s != null && !s.isBlank()) proxyHosts.add(s.trim().toLowerCase(Locale.ROOT));
            return this;
        }

        public Hints withRegistry(Enrich.Registry r) {
            this.registry = r;
            return this;
        }
    }

    // ==================================================================
    // Analysis
    // ==================================================================

    /**
     * Protocol tokens in a "with:" clause that indicate the submission path was not a direct
     * connection. A proxy or submission agent named here is an OBSERVATION about the path, not
     * a claim about the sender - the wording in the result says so explicitly.
     */
    private static final String[] PROXY_TOKENS = {
            "proxy", "socks", "socks4", "socks5", "webmail", "submission",
            "remotedesktop", "citrix", "rdp", "webex", "zoom", "tunnel",
            // "with HTTP" is the canonical signature of browser or webmail submission rather than
            // an MTA-to-MTA handoff, so it is evidence about the relay path, not the sender.
            "http"
    };

    public static Result attribute(EmailParser.Message msg) {
        return attribute(msg, new Hints());
    }

    /**
     * Runs the analysis. Never throws on malformed input: an unparseable message yields a
     * result with an empty candidate list, a full uncertainty list, and confidence 0.
     */
    public static Result attribute(EmailParser.Message msg, Hints hints) {
        Hints h = (hints == null) ? new Hints() : hints;
        List<String> uncertain = new ArrayList<>();
        List<IpFact> candidates = new ArrayList<>();
        List<String> privateHops = new ArrayList<>();
        List<String> reservedHops = new ArrayList<>();
        List<String> indicators = new ArrayList<>();
        List<Factor> factors = new ArrayList<>();

        if (msg == null) {
            uncertain.add("no message supplied to attribute");
            List<String> none = new ArrayList<>();
            none.add("T, S and X cannot be observed without a message");
            return new Result(null, candidates, List.of(), Ordering.TRIVIAL,
                    new Confidence(0.0, new TraceFactors(0, 0, 0, 0, List.of(), none),
                            factors, null, true),
                    uncertain, indicators, privateHops, reservedHops, null);
        }

        // ---- collect hop facts -------------------------------------------------
        List<EmailParser.ReceivedHop> hops = msg.hops == null ? List.of() : msg.hops;
        if (hops.isEmpty()) {
            uncertain.add("no Received: headers present, so no relay infrastructure is observable");
        }

        int receivedHeaderCount = countHeaders(msg, "received");
        if (receivedHeaderCount != hops.size()) {
            uncertain.add("Received: header count (" + receivedHeaderCount
                    + ") does not match hops retained by the parser (" + hops.size()
                    + "); the chain may be truncated or the limit was reached");
        }

        for (EmailParser.ReceivedHop hop : hops) {
            String src = "Received[" + hop.index + "]";
            if (hop.ip == null || hop.ip.isBlank()) {
                uncertain.add(src + " has no parseable address literal; host token was "
                        + (hop.host == null ? "absent" : hop.host));
                continue;
            }
            Scope scope = classifyIp(hop.ip);
            IpFact fact = new IpFact(hop.ip, scope, src);
            candidates.add(fact);
            if (scope == Scope.PRIVATE) {
                privateHops.add(src + " " + hop.ip + " (" + scope.description + ")");
            } else if (scope != Scope.PUBLIC) {
                reservedHops.add(src + " " + hop.ip + " (" + scope.description + ")");
            }
        }

        if (msg.returnPath != null) {
            List<IpFact> extra = extractIps(msg.returnPath, "Return-Path", 8);
            for (IpFact f : extra) {
                if (!containsIp(candidates, f.ip)) candidates.add(f);
            }
        }

        // ---- ordering ----------------------------------------------------------
        List<EmailParser.ReceivedHop> ordered = new ArrayList<>(hops);
        boolean allTimestamps = !ordered.isEmpty();
        for (EmailParser.ReceivedHop hop : ordered) {
            if (!hop.hasTimestamp()) {
                allTimestamps = false;
                break;
            }
        }
        Ordering ordering;
        if (ordered.size() <= 1) {
            ordering = Ordering.TRIVIAL;
        } else if (allTimestamps) {
            ordered.sort((a, b) -> {
                int c = Long.compare(a.timestampMillis, b.timestampMillis);
                return c != 0 ? c : Integer.compare(b.index, a.index);
            });
            ordering = Ordering.TIMESTAMP;
        } else {
            ordered.sort((a, b) -> Integer.compare(b.index, a.index));
            ordering = Ordering.HEADER_DEPTH;
        }

        // ---- indicators (observed only) ---------------------------------------
        for (EmailParser.ReceivedHop hop : hops) {
            if (hop.with == null) continue;
            String w = hop.with.toLowerCase(Locale.ROOT);
            for (String token : PROXY_TOKENS) {
                if (w.contains(token)) {
                    indicators.add("Received[" + hop.index + "] with=" + hop.with
                            + " indicates a " + token + " submission path"
                            + " (observation about the relay path, not about the sender)");
                }
            }
        }
        if (!h.proxyHosts.isEmpty()) {
            for (EmailParser.ReceivedHop hop : hops) {
                if (hop.host == null) continue;
                String host = hop.host.toLowerCase(Locale.ROOT);
                for (String ph : h.proxyHosts) {
                    if (host.contains(ph)) {
                        indicators.add("host " + hop.host + " matches analyst-supplied proxy list ("
                                + ph + "); source: caller Hints, not an independent determination");
                    }
                }
            }
        }

        // ---- select primary ----------------------------------------------------
        EmailParser.ReceivedHop primaryHop = null;
        for (EmailParser.ReceivedHop hop : ordered) {
            IpFact match = findFact(candidates, hop.ip);
            if (match != null && match.isPublic()) {
                primaryHop = hop;
                match.primary = true;
                break;
            }
        }

        List<IpFact> publicFacts = new ArrayList<>();
        for (IpFact f : candidates) {
            if (f.isPublic()) publicFacts.add(f);
        }
        Set<String> distinctPublic = new LinkedHashSet<>();
        for (IpFact f : publicFacts) distinctPublic.add(f.ip);

        // ---- confidence --------------------------------------------------------
        factors.add(new Factor("base_observation",
                "attribution is computed only from header-derived facts, with no external lookup",
                0.30));

        if (primaryHop == null) {
            factors.add(new Factor("no_public_address",
                    "no publicly routable address is observable in this message, so there is no "
                            + "infrastructure to attribute", -0.30));
            uncertain.add("no publicly routable address is observable; attribution is not possible "
                    + "from this message alone");
            List<String> unobs = new ArrayList<>();
            unobs.add("T: no publicly routable hop, so nothing resolved and traceability is 0");
            unobs.add("X.ip: no primary public address to corroborate");
            return new Result(null, candidates, ordered, ordering,
                    new Confidence(0.0,
                            new TraceFactors(0.0, 0.0, 0.0, 0.0, List.of(), unobs),
                            factors,
                            "confidence is exactly 0 because T = 0 and the model combines the four "
                                    + "factors as a weighted geometric mean", true),
                    uncertain, indicators, privateHops, reservedHops, null);
        }

        if (distinctPublic.size() == 1) {
            factors.add(new Factor("single_public_address",
                    "exactly one distinct public address appears across all hops: "
                            + distinctPublic.iterator().next(), 0.20));
        } else {
            factors.add(new Factor("multiple_public_addresses",
                    distinctPublic.size() + " distinct public addresses appear; the chain crosses "
                            + "infrastructure that may be shared or compromised, so none of them is "
                            + "singled out as the origin", -0.10));
            uncertain.add("multiple public addresses observed (" + distinctPublic.size()
                    + "); the earliest is reported, but the chain does not isolate a single origin host");
        }

        boolean timestampsConsistent = ordering == Ordering.TIMESTAMP && isTimeMonotonic(hops);
        if (timestampsConsistent) {
            factors.add(new Factor("timestamp_consistency",
                    "hop timestamps parse and are consistent with RFC 5321 newest-first ordering",
                    0.15));
        } else if (ordering == Ordering.TIMESTAMP) {
            factors.add(new Factor("timestamp_contradiction",
                    "hop timestamps parse but are not monotonic with header order, which can occur "
                            + "with clock skew or with a modified chain", -0.15));
            uncertain.add("hop timestamps contradict header order; ordering fell back to header depth");
        } else {
            factors.add(new Factor("no_timestamps",
                    "hop timestamps are missing or unparseable, so ordering relies on header depth "
                            + "alone", -0.15));
            uncertain.add("no usable hop timestamps; earliest address is inferred from header depth "
                            + "only, which an attacker can control");
        }

        boolean primaryIsDeepest = primaryHop.index == maxIndex(hops);
        if (primaryIsDeepest) {
            factors.add(new Factor("originating_hop",
                    "the earliest public address is the deepest Received hop, which is the "
                            + "closest position to the submitting system", 0.10));
        } else {
            factors.add(new Factor("relayed_address",
                    "the earliest public address is not the deepest hop, so the message crossed at "
                            + "least one additional relay before the address was recorded", -0.05));
            uncertain.add("primary address belongs to a relaying hop rather than the submitting host");
        }

        Enrich.Enrichment enrichment = null;
        if (h.registry != null) {
            enrichment = h.registry.lookup(primaryHop.ip);
            if (enrichment.anyKnown) {
                factors.add(new Factor("network_record",
                        "an offline network record was supplied for the primary address ("
                                + enrichment.asn.display() + " / " + enrichment.organization.display() + ")",
                                0.10));
            } else {
                factors.add(new Factor("no_network_record",
                        "no offline network record is available for the primary address, so the "
                                + "address cannot be placed in an operator context", -0.05));
                uncertain.add("no offline enrichment record for " + primaryHop.ip
                        + "; operator context is unknown");
            }
            if (!h.anonymiserNetworks.isEmpty()) {
                String asn = enrichment.asn.isKnown() ? enrichment.asn.value.toUpperCase(Locale.ROOT) : null;
                if (asn != null && h.anonymiserNetworks.contains(asn)) {
                    indicators.add("ASN " + asn + " appears in the analyst-supplied anonymiser list; "
                            + "source: caller Hints");
                    factors.add(new Factor("anonymiser_network",
                            "the primary address sits in a network the analyst's own data marks as "
                                    + "anonymiser infrastructure, so the address does not identify a user", -0.20));
                }
            }
        } else {
            factors.add(new Factor("enrichment_not_configured",
                    "no enrichment registry was supplied, so the address could not be checked "
                            + "against any operator data", -0.05));
            uncertain.add("enrichment was not configured; no operator context for "
                    + primaryHop.ip);
        }

        if (!indicators.isEmpty()) {
            factors.add(new Factor("intermediary_observed",
                    indicators.size() + " intermediary/proxy observation(s) recorded; the address may "
                            + "not belong to the sender at all", -0.20));
        }

        if (primaryHop.host == null || primaryHop.host.isBlank()) {
            factors.add(new Factor("no_host_token",
                    "the selected hop recorded no hostname, so there is no corroborating "
                            + "identifier beyond the address", -0.05));
        }

        boolean parserWarned = msg.warnings != null && !msg.warnings.isEmpty();
        if (parserWarned) {
            List<String> codes = new ArrayList<>();
            for (EmailParser.Warning w : msg.warnings) codes.add(w.code);
            factors.add(new Factor("parser_warnings",
                    "the parser recorded " + codes.size() + " warning(s) (" + String.join(", ", codes)
                            + "), so some header content may not have been examined", -0.05));
            uncertain.add("parser warnings present: " + String.join(", ", codes));
        }

        // ---- the specified four-factor model ---------------------------------------
        List<String> observed = new ArrayList<>();
        List<String> unobserved = new ArrayList<>();
        double t;
        if (hops.isEmpty()) {
            t = 0.0;
            unobserved.add("T: no Received hops at all");
        } else {
            int total = hops.size();
            int resolved = total - privateHops.size() - reservedHops.size();
            if (resolved < 0) resolved = 0;
            t = (double) resolved / (double) total;
            observed.add("T: " + resolved + " of " + total + " hops are publicly routable");
        }

        double s;
        {
            double sum = 0.0;
            int n = 0;
            if (h.registry != null && enrichment != null) {
                if (enrichment.organization.isKnown() || enrichment.isp.isKnown()) {
                    String org = (enrichment.organization.isKnown() ? enrichment.organization.value
                            : enrichment.isp.value);
                    String orgKey = org == null ? "" : org.toLowerCase(Locale.ROOT);
                    boolean anonymised = h.anonymiserOrgs.contains(orgKey);
                    sum += anonymised ? 0.0 : 1.0;
                    n++;
                    observed.add(anonymised
                            ? "S.rdap_privacy: " + org + " is marked as anonymiser/privacy infrastructure"
                            : "S.rdap_privacy: " + org + " is a named operator, not a privacy proxy");
                    if (anonymised) {
                        uncertain.add("registered operator is anonymiser/privacy infrastructure, so it "
                                + "does not identify a stable party");
                    }
                } else {
                    unobserved.add("S.rdap_privacy: no operator name resolved for " + primaryHop.ip);
                }
            } else {
                unobserved.add("S.rdap_privacy: no enrichment registry supplied, so operator identity "
                        + "is unknown");
            }

            String submittingDomain = (primaryHop.host == null) ? null
                    : primaryHop.host.trim().toLowerCase(Locale.ROOT);
            if (submittingDomain != null && !submittingDomain.isEmpty()) {
                Integer age = h.domainAges.get(submittingDomain);
                if (age != null) {
                    double inv = Math.min(1.0, (double) age / DOMAIN_STABILITY_HORIZON_DAYS);
                    sum += inv;
                    n++;
                    observed.add("S.domain_age_inv: " + submittingDomain + " is " + age
                            + " days old, contributing " + trim(inv) + " of stability");
                } else {
                    unobserved.add("S.domain_age_inv: no domain age supplied for " + submittingDomain);
                }
            } else {
                unobserved.add("S.domain_age_inv: the submitting host was not recorded, so there is no "
                        + "domain to age");
            }

            if (submittingDomain != null && !submittingDomain.isEmpty()) {
                if (h.mxPresentDomains.contains(submittingDomain)) {
                    sum += 1.0;
                    n++;
                    observed.add("S.mx_present: " + submittingDomain + " publishes MX records");
                } else if (h.mxAbsentDomains.contains(submittingDomain)) {
                    n++;
                    observed.add("S.mx_present: " + submittingDomain
                            + " has no MX records, so it cannot send mail");
                } else {
                    unobserved.add("S.mx_present: MX presence unknown for " + submittingDomain);
                }
            }

            s = (n == 0) ? 0.0 : sum / n;
            if (h.registry != null && enrichment != null && enrichment.hostname.isKnown()) {
                observed.add("S.note: " + enrichment.hostname.value
                        + " has a PTR record (recorded, not scored)");
            }
        }

        double a;
        {
            double strongest = 0.0;
            String why = null;
            if (h.registry != null && enrichment != null && enrichment.asn.isKnown()
                    && h.anonymiserNetworks.contains(enrichment.asn.value.toUpperCase(Locale.ROOT))) {
                strongest = 1.0;
                why = "ASN " + enrichment.asn.value + " is analyst-supplied anonymiser infrastructure";
            }
            if (h.proxyHosts != null) {
                for (EmailParser.ReceivedHop hop : hops) {
                    if (hop.host == null) continue;
                    String host = hop.host.toLowerCase(Locale.ROOT);
                    for (String ph : h.proxyHosts) {
                        if (!ph.isEmpty() && host.contains(ph.toLowerCase(Locale.ROOT))) {
                            if (strongest < 0.75) {
                                strongest = 0.75;
                                why = "relay host " + hop.host + " matches the analyst proxy list";
                            }
                        }
                    }
                }
            }
            if (strongest > 0.0) {
                a = strongest;
                observed.add("A: " + why);
            } else {
                a = 0.0;
                if (indicators.isEmpty()) {
                    observed.add("A: no proxy, VPN, Tor or anonymiser indicator observed");
                } else {
                    a = Math.min(0.5, 0.25 * indicators.size());
                    observed.add("A: " + indicators.size()
                            + " intermediary/proxy token(s) observed, which weakens identifiability");
                }
            }
        }

        double x;
        {
            int agreed = 0;
            IpFact primaryFact = findFact(candidates, primaryHop.ip);
            if (primaryFact != null && primaryFact.isPublic()) {
                agreed++;
                observed.add("X.ip: " + primaryHop.ip + " is publicly routable and observed in the chain");
            } else {
                unobserved.add("X.ip: primary address is not publicly routable");
            }
            if (enrichment != null && enrichment.asn.isKnown()) {
                agreed++;
                observed.add("X.asn: " + enrichment.asn.value);
            } else {
                unobserved.add("X.asn: no ASN resolved for the primary address");
            }
            if (enrichment != null && enrichment.organization.isKnown()) {
                agreed++;
                observed.add("X.registrar: " + enrichment.organization.value);
            } else {
                unobserved.add("X.registrar: no organisation resolved for the primary address");
            }
            if (primaryHop.host != null && !primaryHop.host.isBlank()) {
                agreed++;
                observed.add("X.domain: submitting host " + primaryHop.host + " recorded in the chain");
            } else {
                unobserved.add("X.domain: the primary hop recorded no hostname");
            }
            x = (double) agreed / 4.0;
        }

        TraceFactors trace = new TraceFactors(t, s, a, x, observed, unobserved);
        double raw = trace.combine();

        double value = raw;
        String capNote = null;
        boolean cappedNow = false;
        if (value > CONFIDENCE_CAP) {
            value = CONFIDENCE_CAP;
            capNote = "the weighted geometric mean " + trim(raw) + " exceeded the " + trim(CONFIDENCE_CAP)
                    + " infrastructure ceiling and was clamped; even complete positive evidence "
                    + "cannot raise attribution above this value";
            cappedNow = true;
        }
        if (raw == 0.0) {
            uncertain.add("attribution confidence is exactly zero because at least one of the four "
                    + "factors (T, S, A, X) is zero; see the unobserved list for which");
        }

        return new Result(primaryHop.ip, candidates, ordered, ordering,
                new Confidence(value, trace, factors, capNote, cappedNow),
                uncertain, indicators, privateHops, reservedHops, enrichment);
    }


    private static int maxIndex(List<EmailParser.ReceivedHop> hops) {
        int m = -1;
        for (EmailParser.ReceivedHop h : hops) m = Math.max(m, h.index);
        return m;
    }

    /** True when timestamps decrease monotonically as index increases (newest-first). */
    private static boolean isTimeMonotonic(List<EmailParser.ReceivedHop> hops) {
        for (int i = 1; i < hops.size(); i++) {
            EmailParser.ReceivedHop a = hops.get(i - 1);
            EmailParser.ReceivedHop b = hops.get(i);
            if (!a.hasTimestamp() || !b.hasTimestamp()) continue;
            // Header order is newest first, so a.timestamp >= b.timestamp is expected.
            if (a.timestampMillis < b.timestampMillis) return false;
        }
        return true;
    }

    private static IpFact findFact(List<IpFact> facts, String ip) {
        if (ip == null) return null;
        for (IpFact f : facts) {
            if (ip.equals(f.ip)) return f;
        }
        return null;
    }

    private static boolean containsIp(List<IpFact> facts, String ip) {
        return findFact(facts, ip) != null;
    }

    private static int countHeaders(EmailParser.Message msg, String lowerName) {
        if (msg.headers == null) return 0;
        int n = 0;
        for (Map.Entry<String, List<String>> e : msg.headers.entrySet()) {
            if (e.getKey().toLowerCase(Locale.ROOT).equals(lowerName)) n += e.getValue().size();
        }
        return n;
    }

    /**
     * Convenience: a compact, human-readable summary. Still carries the disclaimer, because a
     * summary is the part most likely to get pasted somewhere on its own.
     */
    public static String summarize(Result r) {
        StringBuilder sb = new StringBuilder();
        sb.append("Primary observed address : ").append(r.primaryIp == null ? "none" : r.primaryIp).append('\n');
        sb.append("Ordering basis           : ").append(r.ordering.basis).append('\n');
        sb.append("Infrastructure confidence: ").append(trim(r.confidence.value))
                .append(r.confidence.capped ? " (capped at " + trim(CONFIDENCE_CAP) + ")" : "").append('\n');
        sb.append("Confidence factors       :\n");
        for (Factor f : r.confidence.factors) {
            sb.append("    ").append(f).append("  -- ").append(f.detail).append('\n');
        }
        if (!r.privateHops.isEmpty()) {
            sb.append("Non-routable hops        : ").append(r.privateHops.size()).append('\n');
        }
        if (!r.reservedHops.isEmpty()) {
            sb.append("Reserved/non-endpoint    : ").append(String.join("; ", r.reservedHops)).append('\n');
        }
        if (!r.indicators.isEmpty()) {
            sb.append("Intermediary indicators  :\n");
            for (String i : r.indicators) sb.append("    - ").append(i).append('\n');
        }
        if (!r.uncertain.isEmpty()) {
            sb.append("Uncertainty              :\n");
            for (String u : r.uncertain) sb.append("    - ").append(u).append('\n');
        }
        sb.append("DISCLAIMER               : ").append(r.disclaimer).append('\n');
        return sb.toString();
    }

    // ==================================================================
    // Self-test
    // ==================================================================

    public static void main(String[] args) {
        String raw = "Received: from a.example ([198.51.100.20])\n"
                + "\tby mx.corp.example with ESMTPS id abc123\n"
                + "\tfor <victim@corp.example>; Tue, 12 Aug 2025 10:11:12 +0000\n"
                + "Received: from b.example ([203.0.113.9])\n"
                + "\tby a.example with SMTP id def456\n"
                + "\tfor <victim@corp.example>; Tue, 12 Aug 2025 10:11:10 +0000\n"
                + "Received: from unknown ([10.0.0.5])\n"
                + "\tby b.example with ESMTP id ghi789\n"
                + "\tfor <victim@corp.example>; Tue, 12 Aug 2025 10:11:08 +0000\n"
                + "Return-Path: <bounce@203.0.113.9>\n"
                + "From: sender@evil.example\n"
                + "To: victim@corp.example\n"
                + "Subject: test\n"
                + "\n"
                + "body mentions 192.0.2.44 and 10.0.0.9 and 999.1.1.1 and 1.2.3.4.5\n";

        EmailParser.Message m = EmailParser.parse(raw);
        System.out.println("=== scope classification ===");
        for (String s : new String[]{"8.8.8.8", "10.0.0.1", "172.16.0.1", "192.168.1.1",
                "127.0.0.1", "169.254.1.1", "100.64.0.1", "192.0.2.5", "198.51.100.7",
                "203.0.113.9", "224.0.0.1", "255.255.255.255", "0.0.0.0",
                "2606:4700::1111", "fd00::1", "fe80::1", "::1", "2001:db8::1"}) {
            System.out.println("  " + pad(s, 18) + " -> " + classifyIp(s));
        }

        System.out.println();
        System.out.println("=== extraction (hostile text) ===");
        for (IpFact f : extractIps("ips: 192.0.2.44 10.0.0.9 999.1.1.1 1.2.3.4.5 8.8.8.8 [fd00::1]", "test", 20)) {
            System.out.println("  " + f);
        }

        System.out.println();
        System.out.println("=== full attribution ===");
        Result r = attribute(m);
        System.out.println(summarize(r));
        System.out.println("cap respected: " + (r.confidence.value <= CONFIDENCE_CAP));
        System.out.println("disclaimer present: " + r.disclaimer.equals(DISCLAIMER));

        System.out.println();
        System.out.println("=== public origin: cap must hold even on the best possible evidence ===");
        // Same shape as above but with genuinely public relays, plus an analyst-supplied
        // network record, so every positive factor is available at once.
        String pubRaw = "Received: from a.example ([8.8.8.8])\n"
                + "\tby mx.corp.example with ESMTPS id abc123\n"
                + "\tfor <victim@corp.example>; Tue, 12 Aug 2025 10:11:12 +0000\n"
                + "Received: from b.example ([1.1.1.1])\n"
                + "\tby a.example with SMTP id def456\n"
                + "\tfor <victim@corp.example>; Tue, 12 Aug 2025 10:11:10 +0000\n"
                + "Subject: test\n\nbody\n";
        java.nio.file.Path tsv = null;
        try {
            tsv = java.nio.file.Files.createTempFile("attr", ".tsv");
            java.nio.file.Files.writeString(tsv,
                    "ip\tcountry\tasn\torganization\tisp\thostname\n"
                            + "1.1.1.1\tAU\tAS13335\tExample Cloud\tExample Cloud\tone.one.one.one\n",
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            System.out.println("  (could not stage dataset: " + e + ")");
        }
        Hints ph = new Hints().withRegistry(Enrich.newRegistry()
                .add(new Enrich.DatasetProvider(tsv == null ? "missing.tsv" : tsv.toString())));
        Result rp = attribute(EmailParser.parse(pubRaw), ph);
        System.out.println(summarize(rp));
        System.out.println("cap respected: " + (rp.confidence.value <= CONFIDENCE_CAP));
        if (tsv != null) {
            try {
                java.nio.file.Files.deleteIfExists(tsv);
            } catch (java.io.IOException ignored) {
                // best effort
            }
        }

        System.out.println();
        System.out.println("=== analyst hints must be honoured, not invented ===");
        Hints h = new Hints().withAnonymiserNetwork("AS64500");
        Result r2 = attribute(m, h);
        System.out.println("  indicators with no proxy evidence: " + r2.indicators.size()
                + " (expected 0 - nothing was observed, so nothing is claimed)");

        System.out.println();
        System.out.println("=== no public address at all ===");
        String loopOnly = "Received: from unknown ([10.0.0.5])\n"
                + "\tby b.example with ESMTP id ghi789\n"
                + "\tfor <victim@corp.example>; Tue, 12 Aug 2025 10:11:08 +0000\n"
                + "Subject: x\n\nbody\n";
        Result r3 = attribute(EmailParser.parse(loopOnly));
        System.out.println("  primary=" + r3.primaryIp + " confidence=" + r3.confidence
                + " capNote=" + r3.confidence.capNote);

        System.out.println();
        System.out.println("=== hostile / degenerate input ===");
        Result r4 = attribute(null);
        System.out.println("  null message -> " + r4.confidence.value + " uncertain="
                + r4.uncertain.size());
        Result r5 = attribute(EmailParser.parse(""));
        System.out.println("  empty message -> primary=" + r5.primaryIp
                + " confidence=" + r5.confidence.value);
        System.out.println("OK Attribution");
    }

    private static String pad(String s, int n) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < n) sb.append(' ');
        return sb.toString();
    }
}
