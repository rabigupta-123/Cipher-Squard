/**
 * Item 3: observed organisation profile. Turns "who are we" into facts with an explicit
 * epistemic status, so the IDENT/NLP families prefer confirmed facts over priors.
 *
 * Spec anchors: SCORING-MODEL.md L47 ("prefer confirmed facts over priors"), L58-61
 * (replyto_free_mail and friends depend on knowing the org), L63-70.
 *
 * Schema (config/org-profile.json), as required:
 *   own_domains     : ["example.com", ...]
 *   brands          : ["PayPal", ...]                  canonical names to test lookalikes against
 *   executives      : [{name, title, aliases:[...]}]   names whose appearance in a body matters
 *   partner_domains : ["partner.example", ...]         not us, but legitimately adjacent
 *   mail_ranges     : ["10.0.0.0/8", ...]              CIDR or bare IP
 *   abuse_contact   : "abuse@example.com"
 *
 * Rules that must not drift:
 *   - A MISSING profile yields EMPTY, never an exception and never a "default org".
 *     Defaulting would manufacture evidence: a score that believes a domain has a known
 *     security policy when nobody supplied one is worse than one that admits ignorance.
 *   - A field the profile omits yields observed=false. Absence of evidence is recorded as
 *     absence, never inverted into a negative finding. This is what C_cov measures.
 *   - lookalike is the MINIMUM normalised Damerau-Levenshtein distance between the
 *     skeleton of the domain's first label and the skeleton of each brand (spec L66).
 */
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class OrgProfile {

    /** All defaults resolve here. Non-null in every accessor, so callers never null-check. */
    public static final OrgProfile EMPTY = new OrgProfile(
            List.of(), List.of(), List.of(), List.of(), List.of(), null, 0);

    private final List<String> ownDomains;
    private final List<String> brands;
    private final List<Executive> executives;
    private final List<String> partnerDomains;
    private final List<String> mailRanges;
    private final String abuseContact;
    private final int loadedAtEpochSeconds;

    private OrgProfile(List<String> ownDomains, List<String> brands, List<Executive> executives,
                       List<String> partnerDomains, List<String> mailRanges,
                       String abuseContact, int loadedAtEpochSeconds) {
        this.ownDomains = ownDomains;
        this.brands = brands;
        this.executives = executives;
        this.partnerDomains = partnerDomains;
        this.mailRanges = mailRanges;
        this.abuseContact = abuseContact;
        this.loadedAtEpochSeconds = loadedAtEpochSeconds;
    }

    /** One named person. A body mentioning them is evidence of executive impersonation. */
    public static final class Executive {
        public final String name;
        public final String title;
        public final List<String> aliases;

        Executive(String name, String title, List<String> aliases) {
            this.name = name;
            this.title = title;
            this.aliases = aliases;
        }
    }

    /**
     * The result of a lookalike comparison: which brand is nearest, how far, and whether
     * the comparison was even possible.
     */
    public static final class Lookalike {
        public final String brand;
        public final int distance;
        public final boolean observed;
        public final String reason;

        Lookalike(String brand, int distance, boolean observed, String reason) {
            this.brand = brand;
            this.distance = distance;
            this.observed = observed;
            this.reason = reason;
        }

        public boolean strong() {
            // Spec L66: "lookalike = min normalized edit distance, strong if <= 2".
            return observed && distance <= 2;
        }

        @Override
        public String toString() {
            return (observed ? "observed" : "unobserved") + " brand=" + brand
                    + " distance=" + distance + " (" + reason + ")";
        }
    }

    // ==================================================================
    // Loading
    // ==================================================================

    /**
     * Loads config/org-profile.json.
     *
     * A missing or empty file is NOT an error: it returns EMPTY. That is the difference
     * between "we have no profile" and "the profile is broken", and only the latter is worth
     * failing on. A file that exists but is malformed JSON IS an error, because silently
     * discarding a corrupt profile would hide an operator mistake behind plausible scores.
     */
    public static OrgProfile load(Path json) {
        if (json == null || !Files.isRegularFile(json)) {
            return EMPTY;
        }
        String text;
        try {
            text = Files.readString(json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read org profile: " + json, e);
        }
        if (text.isBlank()) {
            return EMPTY;
        }
        return fromMap(Json.parseObject(text), json);
    }

    /** Parses an already-decoded document. Split out so tests need no file on disk. */
    public static OrgProfile fromMap(Map<String, Object> root, Path forEvidence) {
        List<String> own = stringList(root.get("own_domains"));
        List<String> brands = stringList(root.get("brands"));
        List<String> partners = stringList(root.get("partner_domains"));
        List<String> ranges = stringList(root.get("mail_ranges"));
        String abuse = optString(root, "abuse_contact");

        List<Executive> execs = new ArrayList<>();
        Object execRaw = root.get("executives");
        if (execRaw instanceof List) {
            for (Object o : (List<?>) execRaw) {
                if (!(o instanceof Map)) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> em = (Map<String, Object>) o;
                String name = optString(em, "name");
                if (name == null) {
                    continue;
                }
                execs.add(new Executive(name, optString(em, "title"),
                        stringList(em.get("aliases"))));
            }
        }

        if (own.isEmpty() && brands.isEmpty() && execs.isEmpty() && partners.isEmpty()
                && ranges.isEmpty() && abuse == null) {
            return EMPTY;
        }
        long updated = 0L;
        Object u = root.get("updated_at_epoch_seconds");
        if (u instanceof Double) {
            updated = (long) (double) (Double) u;
        }
        return new OrgProfile(
                Collections.unmodifiableList(own),
                Collections.unmodifiableList(brands),
                Collections.unmodifiableList(execs),
                Collections.unmodifiableList(partners),
                Collections.unmodifiableList(ranges),
                abuse,
                (int) updated);
    }

    // ==================================================================
    // Observation accessors. Each returns an Observed/Lookalike, never a bare default.
    // ==================================================================

    /**
     * Is this domain ours? Exact match or a subdomain of a listed domain.
     *
     * observed=false when the profile lists no own_domains at all, which is different from
     * observed=true,value=false ("we checked our list, it is not us").
     */
    public Observed isOwnDomain(String domain) {
        String k = key(domain);
        if (k == null) {
            return Observed.unknown("domain is null or empty");
        }
        if (ownDomains.isEmpty()) {
            return Observed.unknown("org-profile.json declares no own_domains");
        }
        for (String d : ownDomains) {
            if (k.equals(d) || k.endsWith("." + d)) {
                return Observed.of(true, "matched own_domains entry " + d);
            }
        }
        return Observed.of(false, "not in own_domains (" + ownDomains.size() + " checked)");
    }

    /** Is this domain a known partner? Same observed/unobserved discipline as isOwnDomain. */
    public Observed isPartnerDomain(String domain) {
        String k = key(domain);
        if (k == null) {
            return Observed.unknown("domain is null or empty");
        }
        if (partnerDomains.isEmpty()) {
            return Observed.unknown("org-profile.json declares no partner_domains");
        }
        for (String d : partnerDomains) {
            if (k.equals(d) || k.endsWith("." + d)) {
                return Observed.of(true, "matched partner_domains entry " + d);
            }
        }
        return Observed.of(false, "not in partner_domains (" + partnerDomains.size() + " checked)");
    }

    /**
     * Is a Reply-To address legitimate? Ours or a known partner. A Reply-To pointing
     * anywhere else is the classic credential-harvest pivot, so this returns false with
     * observed=true whenever we actually have a list to check against.
     */
    public Observed isKnownReplyToDomain(String replyToDomain) {
        Observed own = isOwnDomain(replyToDomain);
        Observed partner = isPartnerDomain(replyToDomain);
        if (own.observed() || partner.observed()) {
            boolean v = own.value() || partner.value();
            return Observed.of(v, "own=" + own + " partner=" + partner);
        }
        return Observed.unknown("neither own_domains nor partner_domains is populated");
    }

    /**
     * Brand lookalike: minimum normalised Damerau-Levenshtein distance over skeletons.
     *
     * Both sides go through the same TextNormalizer first, so "p\u0430ypal.com",
     * "PAY-PAL.COM" and "paypa1.com" all collapse onto the same comparison the spec
     * describes. Transpositions count as one edit, which is what makes "paypa1" a hit.
     */
    public Lookalike brandLookalike(String domain, TextNormalizer norm) {
        if (brands.isEmpty()) {
            return new Lookalike(null, Integer.MAX_VALUE, false,
                    "org-profile.json declares no brands");
        }
        if (norm == null) {
            throw new IllegalArgumentException("brandLookalike needs a TextNormalizer");
        }
        String k = key(domain);
        if (k == null) {
            return new Lookalike(null, Integer.MAX_VALUE, false, "domain is null or empty");
        }
        String label = k;
        int dot = k.indexOf('.');
        if (dot > 0) {
            label = k.substring(0, dot);
        }
        String skel = norm.normalise(label);
        if (skel.isEmpty()) {
            return new Lookalike(null, Integer.MAX_VALUE, false, "label normalises to empty");
        }
        String bestBrand = null;
        int best = Integer.MAX_VALUE;
        for (String brand : brands) {
            String bskel = norm.normalise(brand);
            if (bskel.isEmpty()) {
                continue;
            }
            int d = Features.editDistance(skel, bskel);
            if (d < best) {
                best = d;
                bestBrand = brand;
            }
        }
        if (bestBrand == null) {
            return new Lookalike(null, Integer.MAX_VALUE, false,
                    "no brand survived normalisation");
        }
        return new Lookalike(bestBrand, best, true,
                "min_osa_over_skeletons skeleton=" + skel);
    }

    /**
     * Does the body name one of our executives? Drives exec_impersonation alongside the
     * title lexicon: "Dear Mr Okonkwo, CFO" should outscore a generic "Dear Sir".
     */
    public Observed executiveMentioned(String text) {
        if (executives.isEmpty()) {
            return Observed.unknown("org-profile.json declares no executives");
        }
        if (text == null || text.isBlank()) {
            return Observed.unknown("body text is null or empty");
        }
        String hay = text.toLowerCase(Locale.ROOT);
        for (Executive e : executives) {
            if (containsName(hay, e.name)) {
                return Observed.of(true, "body names executive " + e.name);
            }
            for (String alias : e.aliases) {
                if (containsName(hay, alias)) {
                    return Observed.of(true, "body names alias " + alias + " of " + e.name);
                }
            }
        }
        return Observed.of(false, "no listed executive named in body");
    }

    /**
     * A message that names our own abuse contact is a strong phishing signal, because a
     * legitimate abuse report does not quote the contact back at a phisher's own domain.
     */
    public Observed abuseContactQuoted(String text) {
        if (abuseContact == null) {
            return Observed.unknown("org-profile.json declares no abuse_contact");
        }
        if (text == null || text.isBlank()) {
            return Observed.unknown("body text is null or empty");
        }
        String hay = text.toLowerCase(Locale.ROOT);
        String local = abuseContact.toLowerCase(Locale.ROOT);
        boolean hit = hay.contains(local);
        if (!hit) {
            int at = local.indexOf('@');
            if (at > 0) {
                hit = hay.contains(local.substring(0, at));
            }
        }
        return Observed.of(hit, "abuse_contact=" + abuseContact + " quoted=" + hit);
    }

    /** Is this sending IP inside a declared mail_range? Supports CIDR and bare IPs. */
    public Observed inMailRange(String ip) {
        if (mailRanges.isEmpty()) {
            return Observed.unknown("org-profile.json declares no mail_ranges");
        }
        String v = key(ip);
        if (v == null) {
            return Observed.unknown("ip is null or empty");
        }
        for (String range : mailRanges) {
            if (ipInRange(v, range)) {
                return Observed.of(true, "inside mail_range " + range);
            }
        }
        return Observed.of(false, "outside all " + mailRanges.size() + " mail_ranges");
    }

    // ==================================================================
    // Plain accessors
    // ==================================================================

    public List<String> ownDomains() {
        return ownDomains;
    }

    public List<String> brands() {
        return brands;
    }

    public List<Executive> executives() {
        return executives;
    }

    public List<String> partnerDomains() {
        return partnerDomains;
    }

    public List<String> mailRanges() {
        return mailRanges;
    }

    public String abuseContact() {
        return abuseContact;
    }

    public int loadedAtEpochSeconds() {
        return loadedAtEpochSeconds;
    }

    public int entryCount() {
        return ownDomains.size() + brands.size() + executives.size()
                + partnerDomains.size() + mailRanges.size() + (abuseContact == null ? 0 : 1);
    }

    public boolean isEmpty() {
        return entryCount() == 0;
    }

    /**
     * A copy of this profile with a different brand list. Immutable: the receiver gets a new
     * object, so an enrichment stage can narrow the brand set per call without corrupting the
     * profile shared across concurrent scoring threads.
     */
    public OrgProfile withBrands(List<String> newBrands) {
        List<String> b = (newBrands == null) ? List.of() : List.copyOf(newBrands);
        return new OrgProfile(ownDomains, b, executives, partnerDomains, mailRanges,
                abuseContact, loadedAtEpochSeconds);
    }

    // ==================================================================
    // A value plus the epistemic status of that value. The status is the point:
    // a feature that reports "false" for "we never looked" is a lie the report cannot show.
    // ==================================================================

    public static final class Observed {
        private final boolean value;
        private final boolean observed;
        private final String reason;

        private Observed(boolean value, boolean observed, String reason) {
            this.value = value;
            this.observed = observed;
            this.reason = reason;
        }

        static Observed of(boolean value, String reason) {
            return new Observed(value, true, reason);
        }

        static Observed unknown(String reason) {
            return new Observed(false, false, reason);
        }

        /** The boolean a feature should use. False when unobserved, never an inverted guess. */
        public boolean value() {
            return value;
        }

        public boolean observed() {
            return observed;
        }

        public String reason() {
            return reason;
        }

        @Override
        public String toString() {
            return (observed ? "observed=" : "unobserved=") + value + " (" + reason + ")";
        }
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    /**
     * Name matching that will not fire on a substring of a longer word. "Raj" must not
     * match inside "rajnish", or every exec hit becomes noise. Requires the match to be
     * bounded by non-letter characters on both sides.
     *
     * Matches on the full name OR on any single alphabetic token of it, because
     * "Hi Aditi, approve this today" names the executive just as effectively as
     * "Aditi Raghavan" does, and the given-name form is the more common BEC phrasing.
     * Tokens shorter than 3 letters are skipped so initials like "A." or "M." cannot match.
     */
    private static boolean containsName(String haystackLower, String name) {
        String n = key(name);
        if (n == null) {
            return false;
        }
        if (wordMatch(haystackLower, n)) {
            return true;
        }
        for (String tok : n.split("[^\\p{L}]+")) {
            if (tok.length() >= 3 && wordMatch(haystackLower, tok)) {
                return true;
            }
        }
        return false;
    }

    /** Whole-word containment against letter-bounded edges. */
    private static boolean wordMatch(String haystackLower, String needleLower) {
        if (needleLower.isEmpty()) {
            return false;
        }
        int at = haystackLower.indexOf(needleLower);
        while (at >= 0) {
            boolean leftOk = at == 0 || !Character.isLetter(haystackLower.charAt(at - 1));
            int end = at + needleLower.length();
            boolean rightOk = end >= haystackLower.length()
                    || !Character.isLetter(haystackLower.charAt(end));
            if (leftOk && rightOk) {
                return true;
            }
            at = haystackLower.indexOf(needleLower, at + 1);
        }
        return false;
    }

    /** Parses dotted-quad IPv4 into a long, or returns null. */
    static Long ipv4ToLong(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        long v = 0;
        for (String p : parts) {
            int n;
            try {
                n = Integer.parseInt(p);
            } catch (NumberFormatException e) {
                return null;
            }
            if (n < 0 || n > 255) {
                return null;
            }
            v = (v << 8) | n;
        }
        return v;
    }

    /** CIDR containment for IPv4, plus exact match when the range is a bare IP. */
    static boolean ipInRange(String ip, String range) {
        String r = key(range);
        if (r == null) {
            return false;
        }
        int slash = r.indexOf('/');
        if (slash < 0) {
            return r.equals(ip);
        }
        Long addr = ipv4ToLong(ip);
        String basePart = r.substring(0, slash);
        Long base = ipv4ToLong(basePart);
        if (addr == null || base == null) {
            return false;
        }
        int bits;
        try {
            bits = Integer.parseInt(r.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            return false;
        }
        if (bits < 0 || bits > 32) {
            return false;
        }
        if (bits == 0) {
            return true;
        }
        long mask = (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
        return ((addr & mask) == (base & mask));
    }

    private static String key(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }

    private static String optString(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v instanceof String) {
            String s = ((String) v).trim();
            return s.isEmpty() ? null : s;
        }
        return null;
    }

    /** Collects a JSON array of strings, skipping non-strings and blanks. Order preserved. */
    private static List<String> stringList(Object v) {
        if (!(v instanceof List)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object o : (List<?>) v) {
            if (o instanceof String) {
                String s = ((String) o).trim();
                if (!s.isEmpty()) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    /** Standalone self-check: java OrgProfile [path] */
    public static void main(String[] args) {
        Path p = args.length > 0 ? Path.of(args[0]) : Path.of("config/org-profile.json");
        OrgProfile prof = load(p);
        TextNormalizer norm = TextNormalizer.load();
        System.out.println("profile: " + p + " entries=" + prof.entryCount()
                + " empty=" + prof.isEmpty());

        System.out.println("-- own domain --");
        for (String d : new String[]{"ciphersquad.io", "mail.ciphersquad.io",
                "evil.example", null}) {
            System.out.printf("  %-22s %s%n", String.valueOf(d), prof.isOwnDomain(d));
        }

        System.out.println("-- brand lookalike (min OSA over skeletons) --");
        for (String d : new String[]{"paypal.com", "p\u0430ypal.com", "paypa1.com",
                "paypal-verify.tk", "ciphersquad.io", "github.com"}) {
            System.out.printf("  %-22s %s%n", d, prof.brandLookalike(d, norm));
        }

        System.out.println("-- reply-to legitimacy --");
        for (String d : new String[]{"ciphersquad.io", "cloudflare.com", "evil.example"}) {
            System.out.printf("  %-22s %s%n", d, prof.isKnownReplyToDomain(d));
        }

        System.out.println("-- executives --");
        System.out.println("  name hit   " + prof.executiveMentioned(
                "Aditi, please approve this transfer today."));
        System.out.println("  alias hit  " + prof.executiveMentioned(
                "Mr Raghavan, see attached."));
        System.out.println("  no hit     " + prof.executiveMentioned(
                "Dear customer, your account needs attention."));

        System.out.println("-- abuse contact --");
        System.out.println("  quoted     " + prof.abuseContactQuoted(
                "Forward this to abuse@ciphersquad.io immediately."));
        System.out.println("  not quoted " + prof.abuseContactQuoted(
                "Contact us through the portal."));

        System.out.println("-- mail ranges --");
        System.out.println("  in   203.0.113.5  " + prof.inMailRange("203.0.113.5"));
        System.out.println("  in   203.0.114.5  " + prof.inMailRange("203.0.114.5"));
        System.out.println("  out  10.1.2.3     " + prof.inMailRange("10.1.2.3"));
        System.out.println("  bad  not-an-ip    " + prof.inMailRange("not-an-ip"));

        System.out.println("-- EMPTY profile must be unobserved, never a guessed false --");
        System.out.println("  own       " + OrgProfile.EMPTY.isOwnDomain("ciphersquad.io"));
        System.out.println("  lookalike " + OrgProfile.EMPTY.brandLookalike("paypal.com", norm));
        System.out.println("  exec      " + OrgProfile.EMPTY.executiveMentioned("Aditi"));
    }
}
