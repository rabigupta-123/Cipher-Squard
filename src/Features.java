import java.util.*;

public final class Features {

    // ==================================================================
    // The feature contract. Order here IS the model's feature order.
    // ==================================================================

    private static final String[] NAMES = {
            // ---- F1 AUTH, spec L37-45 (9) ----
            "spf_fail", "spf_none", "dkim_fail", "dkim_absent", "dmarc_fail", "dmarc_absent",
            "alignment_from_spf", "alignment_from_dkim", "dmarc_policy_strict",
            // ---- F2 ROUTE, spec L50-59 (10) ----
            "rp_from_mismatch", "replyto_mismatch", "replyto_free_mail", "messageid_anomaly",
            "received_count_n", "received_disorder", "received_private_hop",
            "received_missing_from", "helo_mismatch", "date_skew",
            // ---- F3 IDENT, spec L64-74 (11) ----
            "domain_age_inv", "domain_age_unknown", "lookalike_strong", "homoglyph_ratio",
            "digit_dash_ratio", "subdomain_depth", "suspicious_tld", "mx_absent", "rdap_privacy",
            "registrar_risk", "registrar_country_off",
            // ---- F4 NLP, spec L79-88 (10) ----
            "urgency", "authority_claim", "credential_request", "payment_request",
            "payment_channel_change", "exec_impersonation", "secrecy_pressure",
            "generic_salutation", "grammar_anomaly", "tone_incongruence",
            // ---- F5 PAYLOAD, spec L93-104 (12) ----
            "link_text_mismatch", "shortener", "ip_literal", "punycode", "at_in_url",
            "deep_redirect", "credential_form_host", "attachment_dangerous", "attachment_macro",
            "attachment_archive", "attachment_double_ext", "attachment_count_n",
            // ---- F6 INFRA, spec L109-116 (8) ----
            "ip_in_blacklist", "asn_risk", "vpn_proxy", "tor_exit", "open_relay",
            "cloud_hosted", "geo_mismatch", "reputation_low"
    };

    public enum Family {
        AUTH("F1", "Authentication"),
        ROUTE("F2", "Route"),
        IDENT("F3", "Identity"),
        NLP("F4", "NLP"),
        PAYLOAD("F5", "Payload"),
        INFRA("F6", "Infrastructure");

        public final String code;
        public final String label;

        Family(String code, String label) {
            this.code = code;
            this.label = label;
        }

        static Family byOrdinal(int i) {
            Family[] all = values();
            if (i < 0 || i >= all.length) {
                throw new IndexOutOfBoundsException("family ordinal " + i);
            }
            return all[i];
        }
    }

    private static final int[] FAMILY_SIZES = {9, 10, 11, 10, 12, 8};

    private static final int[] FAMILY_OF = new int[NAMES.length];

    static {
        int[] sizes = FAMILY_SIZES;
        int i = 0;
        for (int fam = 0; fam < sizes.length; fam++) {
            for (int j = 0; j < sizes[fam]; j++) {
                FAMILY_OF[i++] = fam;
            }
        }
        if (i != NAMES.length) {
            throw new AssertionError("family sizes sum to " + i
                    + " but NAMES has " + NAMES.length + " entries");
        }
    }

    public static final int COUNT = NAMES.length;
    public static final int FAMILY_COUNT = Family.values().length;

    public static int indexOf(String name) {
        for (int i = 0; i < NAMES.length; i++) {
            if (NAMES[i].equals(name)) {
                return i;
            }
        }
        return -1;
    }

    public static String name(int i) {
        return NAMES[i];
    }

    public static Family familyOf(int i) {
        return Family.byOrdinal(FAMILY_OF[i]);
    }

    public static int familySize(int i) {
        return FAMILY_SIZES[FAMILY_OF[i]];
    }

    public static int familySize(Family f) {
        return FAMILY_SIZES[f.ordinal()];
    }

    public static int[] becIndices() {
        int[] out = new int[Config.BEC_SUBSET.length];
        for (int i = 0; i < out.length; i++) {
            int idx = indexOf(Config.BEC_SUBSET[i]);
            if (idx < 0) {
                throw new AssertionError("BEC subset names a feature that does not exist: "
                        + Config.BEC_SUBSET[i]);
            }
            out[i] = idx;
        }
        return out;
    }

    public static final class Vector {
        private final double[] x = new double[COUNT];
        private final boolean[] observed = new boolean[COUNT];
        private final String[] reason = new String[COUNT];
        private final List<String> matchedBrands = new ArrayList<>();
        private final List<String> notes = new ArrayList<>();

        public double[] toArray() {
            return x.clone();
        }

        public boolean[] observedArray() {
            return observed.clone();
        }

        public String reason(int index) {
            if (index < 0 || index >= COUNT) {
                throw new IndexOutOfBoundsException("feature index " + index);
            }
            return reason[index];
        }

        public String reason(String name) {
            int i = indexOf(name);
            return i < 0 ? null : reason[i];
        }

        public List<String> provenance() {
            List<String> out = new ArrayList<>();
            for (int i = 0; i < COUNT; i++) {
                if (reason[i] != null) {
                    out.add(name(i) + "=" + x[i] + " (" + reason[i] + ")");
                }
            }
            return out;
        }

        public List<String> brands() {
            return matchedBrands.stream().toList();
        }

        public List<String> noteList() {
            return notes.stream().toList();
        }

        public double get(String name) {
            int i = indexOf(name);
            return i < 0 ? 0.0 : x[i];
        }

        public boolean isObserved(String name) {
            int i = indexOf(name);
            return i >= 0 && observed[i];
        }

        public void put(String name, double value) {
            put(name, value, true, "unspecified");
        }

        public void put(String name, double value, boolean obs) {
            put(name, value, obs, "unspecified");
        }

        public void put(String name, double value, boolean obs, String why) {
            int i = indexOf(name);
            if (i < 0) {
                throw new IllegalArgumentException("no such feature: " + name);
            }
            write(i, value, obs, why);
        }

        public void put(int index, double value) {
            put(index, value, true, "unspecified");
        }

        public void put(int index, double value, boolean obs) {
            put(index, value, obs, "unspecified");
        }

        private void write(int i, double value, boolean obs, String why) {
            String n = name(i);
            if (!Double.isFinite(value)) {
                value = 0.0;
                obs = false;
                notes.add("feature " + n + " was non-finite; emitted 0 with observed=false");
                reason[i] = why + " -> non-finite value quarantined";
                x[i] = 0.0;
                observed[i] = false;
                return;
            }
            if (value < 0.0 || value > 1.0) {
                notes.add("feature " + n + " = " + value
                        + " is outside [0,1]; quarantined to 0 with observed=false");
                reason[i] = why + " -> out-of-range value " + value + " quarantined";
                x[i] = 0.0;
                observed[i] = false;
                return;
            }
            x[i] = value;
            observed[i] = obs;
            reason[i] = why;
        }

        public int observedCount() {
            int n = 0;
            for (boolean o : observed) {
                if (o) {
                    n++;
                }
            }
            return n;
        }

        public int unobservedCount() {
            return COUNT - observedCount();
        }

        public boolean isObserved(int index) {
            if (index < 0 || index >= COUNT) {
                throw new IndexOutOfBoundsException("feature index " + index);
            }
            return observed[index];
        }

        public double get(int index) {
            if (index < 0 || index >= COUNT) {
                throw new IndexOutOfBoundsException("feature index " + index);
            }
            return x[index];
        }

        public void put(int index, double value, boolean obs, String why) {
            if (index < 0 || index >= COUNT) {
                throw new IndexOutOfBoundsException("feature index " + index
                        + " is outside [0, " + COUNT + ")");
            }
            write(index, value, obs, why);
        }

        public double[] becVector() {
            int[] idx = becIndices();
            double[] out = new double[idx.length];
            for (int i = 0; i < idx.length; i++) {
                out[i] = observed[idx[i]] ? x[idx[i]] : 0.0;
            }
            return out;
        }

        public double coverage(double[][] beta, int predictedClass) {
            double num = 0.0;
            double den = 0.0;
            for (int f = 0; f < COUNT; f++) {
                double v = Math.abs(beta[predictedClass][f]);
                den += v;
                if (observed[f]) {
                    num += v;
                }
            }
            if (den <= 0.0) {
                return 0.0;
            }
            return Math.min(1.0, num / den);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            for (int f = 0; f < COUNT; f++) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("family", Config.FAMILY_NAMES[FAMILY_OF[f]]);
                e.put("value", x[f]);
                e.put("observed", observed[f]);
                e.put("reason", reason[f]);
                m.put(NAMES[f], e);
            }
            return m;
        }
    }

    // ==================================================================
    // Evidence the extractor is allowed to read
    // ==================================================================

    public static final class Evidence {
        public String fromDomain;
        public String returnPathDomain;
        public String replyToDomain;
        public Long domainAgeDays;
        public Boolean mxPresent;
        public Boolean rdapPrivacy;
        public String registrar;
        public String registrarCountry;
        public String orgCountry;
        public String sendingIp;
        public String sendingAsn;
        public Boolean ipBlacklisted;
        public Boolean asnRisk;
        public Boolean vpnProxy;
        public Boolean torExit;
        public Boolean openRelay;
        public Boolean cloudHosted;
        public String originCountry;
        public Boolean reputationLow;
        public List<String> brands;
    }

    // ==================================================================
    // Semantic Lexicons
    // ==================================================================

    private static final class LexiconEntry {
        final String phrase;
        final double weight;
        LexiconEntry(String p, double w) { this.phrase = p; this.weight = w; }
    }

    private static final List<LexiconEntry> URGENCY_LEX = List.of(
        new LexiconEntry("act immediately or account will be suspended", 1.0),
        new LexiconEntry("final notice", 0.8),
        new LexiconEntry("time sensitive", 0.6),
        new LexiconEntry("urgent", 0.4),
        new LexiconEntry("asap", 0.3),
        new LexiconEntry("immediately", 0.3),
        new LexiconEntry("right away", 0.3),
        new LexiconEntry("deadline", 0.4),
        new LexiconEntry("expires", 0.4)
    );

    private static final List<LexiconEntry> AUTHORITY_LEX = List.of(
        new LexiconEntry("required by law", 1.0),
        new LexiconEntry("by order of the director", 0.9),
        new LexiconEntry("mandatory compliance", 0.9),
        new LexiconEntry("per company policy", 0.7),
        new LexiconEntry("official notice", 0.6),
        new LexiconEntry("official", 0.3),
        new LexiconEntry("authorized", 0.3),
        new LexiconEntry("audit", 0.4)
    );

    private static final List<LexiconEntry> SECRECY_LEX = List.of(
        new LexiconEntry("strictly confidential: do not forward", 1.0),
        new LexiconEntry("keep this between us", 0.9),
        new LexiconEntry("off the record", 0.7),
        new LexiconEntry("internal use only", 0.6),
        new LexiconEntry("confidential", 0.3),
        new LexiconEntry("discreet", 0.3),
        new LexiconEntry("private", 0.2)
    );

    private static final String[] CREDENTIAL = {
        "password", "passcode", "otp", "one-time code", "verification code",
        "mfa", "2fa", "re-authenticate", "reauthenticate", "confirm your identity",
        "sign in to verify", "log in to confirm", "security code", "pin"
    };

    private static final String[] PAYMENT = {
        "invoice", "wire", "remittance", "payment", "bank details", "billing",
        "outstanding", "settlement", "credit", "acct", "account update", "refund"
    };

    private static final String[] CHANNEL_CHANGE = {
        "change the bank", "update the bank", "new bank account", "new account number",
        "change our bank", "revised bank", "amend the account", "change the account number",
        "new payment details", "update payment details", "corrected bank details",
        "change beneficiary", "new beneficiary"
    };

    private static final String[] EXEC = {
        "ceo", "cfo", "coo", "cto", "ciso", "chief executive", "chief financial",
        "vice president", " vp", "director", "dean", "principal", "partner",
        "head of", "president", "founder", "chairman", "managing director", "gm"
    };

    private static final String[] GENERIC_SALUTATION = {
        "dear customer", "dear user", "dear staff", "dear member", "dear client",
        "dear sir", "dear madam", "dear account holder", "dear beneficiary",
        "dear team", "dear all", "dear friend", "valued customer"
    };

    private static final String[] DANGEROUS_EXT = {
        "exe", "scr", "js", "vbs", "lnk", "jar", "hta", "pif", "com", "cmd", "bat",
        "msi", "ps1", "wsf", "cpl", "reg", "sh", "vb", "jse"
    };

    private static final String[] MACRO_EXT = {
        "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "potm", "ppsm", "sldm"
    };

    private static final String[] ARCHIVE_EXT = {
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso", "img"
    };

    private static final String[] SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "lnkd.in",
        "rebrand.ly", "s.id", "tiny.cc", "soo.gd", "clck.ru", "v.gd"
    };

    private static final String[] FREE_MAIL = {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
        "hotmail.co.uk", "outlook.com", "live.com", "msn.com", "aol.com",
        "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me",
        "gmx.com", "gmx.de", "mail.com", "yandex.ru", "zoho.com", "fastmail.com"
    };

    private static final String[] SUSPICIOUS_TLD = {
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work", "rest",
        "country", "kim", "science", "party", "review", "stream", "download", "loan",
        "racing", "win", "bid", "date", "faith", "trade", "accountant", "cricket",
        "men", "zip", "mov", "cam", "quest", "cfd", "sbs", "buzz"
    };

    private static final String[] ELEVATED_REGISTRARS = {
        "namecheap", "godaddy", "porkbun", "keybase", "njalla", "west", "enom",
        "namesilo", "dynadot", "bigcommerce"
    };

    // ==================================================================
    // Extraction
    // ==================================================================

    private final TextNormalizer norm;
    private final OrgProfile profile;

    public Features(TextNormalizer norm, OrgProfile profile) {
        this.norm = norm;
        this.profile = profile == null ? OrgProfile.EMPTY : profile;
    }

    public Vector extract(Headers.Result h, Evidence ev) {
        Vector v = new Vector();
        Evidence e = ev == null ? new Evidence() : ev;

        String fromDomain = firstNonNull(e.fromDomain, domainOfHeader(h, "from"));
        String returnPath = firstNonNull(e.returnPathDomain, domainOfHeader(h, "return-path"));
        String replyTo = firstNonNull(e.replyToDomain, domainOfHeader(h, "reply-to"));
        String body = h.bodyText == null ? "" : h.bodyText;
        String subject = firstNonNull(h.first("subject"), "");
        String fromDisplay = Headers.displayNameOf(h.first("from"));
        String fromAddr = Headers.addressOf(h.first("from"));
        String fullText = (subject + "\n" + body).toLowerCase(Locale.ROOT);

        extractAuth(h, v, fromDomain, returnPath);
        extractRoute(h, v, fromDomain, returnPath, replyTo);
        extractIdent(h, v, fromDomain, e);
        extractNlp(v, fullText, body, subject, fromDisplay, fromAddr);
        extractPayload(h, v, fullText);
        extractInfra(v, e, fromDomain);
        summariseUnobserved(v);
        return v;
    }

    private void summariseUnobserved(Vector v) {
        int n = 0;
        for (int i = 0; i < COUNT; i++) {
            if (!v.isObserved(NAMES[i])) {
                n++;
            }
        }
        if (n > 0) {
            v.notes.add(n + " of " + COUNT + " features unobserved, so C_cov is reduced: "
                    + unobservedList(v));
        }
    }

    private String unobservedList(Vector v) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < COUNT; i++) {
            if (!v.isObserved(NAMES[i])) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(NAMES[i]);
            }
        }
        return sb.toString();
    }

    private void extractAuth(Headers.Result h, Vector v, String fromDomain, String returnPath) {
        String spf = authResult(h, "spf");
        if (spf == null || spf.equals("none")) {
            v.put("spf_none", 1.0);
            v.put("spf_fail", 0.0, false);
        } else {
            v.put("spf_none", 0.0);
            v.put("spf_fail", isFailish(spf) ? 1.0 : 0.0);
        }

        String dkim = authResult(h, "dkim");
        boolean dkimAbsent = (dkim == null) && !h.has("dkim-signature");
        v.put("dkim_absent", dkimAbsent ? 1.0 : 0.0);
        v.put("dkim_fail", (dkim == null) ? 0.0 : (isFailish(dkim) ? 1.0 : 0.0), !dkimAbsent);

        String dmarc = authResult(h, "dmarc");
        v.put("dmarc_absent", dmarc == null ? 1.0 : 0.0);
        v.put("dmarc_fail", dmarc == null ? 0.0 : ("fail".equals(dkim(dmarc)) ? 1.0 : 0.0),
                dmarc != null);
        v.put("dmarc_policy_strict", policyStrict(dmarc) ? 1.0 : 0.0, dmarc != null);

        boolean rpKnown = returnPath != null && fromDomain != null;
        v.put("alignment_from_spf", rpKnown && !returnPath.equals(fromDomain) ? 1.0 : 0.0,
                rpKnown);

        String dkimDomain = dkimDomain(h);
        boolean dkimDomKnown = dkimDomain != null && fromDomain != null;
        v.put("alignment_from_dkim",
                dkimDomKnown && !dkimDomain.equals(fromDomain) ? 1.0 : 0.0, dkimDomKnown);
    }

    private void extractRoute(Headers.Result h, Vector v, String fromDomain,
                              String returnPath, String replyTo) {
        boolean both = returnPath != null && fromDomain != null;
        v.put("rp_from_mismatch", both && !returnPath.equals(fromDomain) ? 1.0 : 0.0, both);

        boolean rtKnown = replyTo != null && fromDomain != null;
        v.put("replyto_mismatch", rtKnown && !replyTo.equals(fromDomain) ? 1.0 : 0.0, rtKnown);
        if (rtKnown) {
            v.put("replyto_free_mail", contains(FREE_MAIL, replyTo) ? 1.0 : 0.0);
        } else {
            v.put("replyto_free_mail", 0.0, false);
        }

        String msgId = h.first("message-id");
        boolean msgIdPresent = msgId != null && !msgId.isBlank();
        boolean malformed = !msgIdPresent || !msgId.contains("@");
        boolean foreign = false;
        if (msgIdPresent && msgId.contains("@")) {
            String md = Headers.domainOf(msgId.trim().replace("<", "").replace(">", ""));
            foreign = md != null && fromDomain != null && !md.equals(fromDomain);
        }
        v.put("messageid_anomaly", (malformed || foreign) ? 1.0 : 0.0, msgIdPresent);

        List<String> received = h.all("received");
        int hops = received.size();
        v.put("received_count_n", Math.min(hops / 8.0, 1.0));
        v.put("received_disorder", nonMonotonicCount(received) / Math.max(1.0, hops));
        v.put("received_private_hop", privateHopPresent(received) ? 1.0 : 0.0, hops > 0);
        v.put("received_missing_from", hops > 0 && !received.get(0).toLowerCase(Locale.ROOT)
                .contains("from ") ? 1.0 : 0.0, hops > 0);
        v.put("helo_mismatch", 0.0, false);
        v.put("date_skew", dateSkewHours(h) / 1440.0, dateSkewHours(h) >= 0);
    }

    private void extractIdent(Headers.Result h, Vector v, String fromDomain, Evidence e) {
        List<String> brandList = e.brands != null && !e.brands.isEmpty()
                ? e.brands : profile.brands();
        if (fromDomain != null && brandList != null && !brandList.isEmpty()) {
            OrgProfile.Lookalike lk = profile.withBrands(brandList)
                    .brandLookalike(fromDomain, norm);
            v.put("lookalike_strong", lk.strong() ? 1.0 : 0.0, lk.observed);
            if (lk.strong()) {
                v.matchedBrands.add(lk.brand + " (damerau_levenshtein=" + lk.distance + ")");
            }
            if (!lk.observed) {
                v.notes.add("lookalike_strong unobserved: " + lk.reason);
            }
        } else {
            v.put("lookalike_strong", 0.0, false);
            v.notes.add("lookalike_strong unobserved: no brand list and no org profile");
        }

        v.put("homoglyph_ratio", fromDomain == null ? 0.0 : norm.homoglyphRatio(fromDomain),
                fromDomain != null);

        if (fromDomain != null) {
            String label = firstLabel(fromDomain);
            if (!label.isEmpty()) {
                int hits = 0;
                for (int i = 0; i < label.length(); i++) {
                    char c = label.charAt(i);
                    if ((c >= '0' && c <= '9') || c == '-') {
                        hits++;
                    }
                }
                v.put("digit_dash_ratio", Math.min(1.0, (double) hits / label.length()));
            } else {
                v.put("digit_dash_ratio", 0.0, false);
            }
        } else {
            v.put("digit_dash_ratio", 0.0, false);
        }

        if (fromDomain != null) {
            int labels = 1;
            for (int i = 0; i < fromDomain.length(); i++) {
                if (fromDomain.charAt(i) == '.') {
                    labels++;
                }
            }
            v.put("subdomain_depth", 1.0 - 1.0 / (1.0 + Math.max(0, labels - 2)));
        } else {
            v.put("subdomain_depth", 0.0, false);
        }

        if (fromDomain != null) {
            int dot = fromDomain.lastIndexOf('.');
            String tld = dot < 0 ? "" : fromDomain.substring(dot + 1);
            v.put("suspicious_tld", contains(SUSPICIOUS_TLD, tld) ? 1.0 : 0.0);
        } else {
            v.put("suspicious_tld", 0.0, false);
        }

        if (e.domainAgeDays == null) {
            v.put("domain_age_inv", 0.0, false);
            v.put("domain_age_unknown", 1.0);
        } else {
            double age = e.domainAgeDays;
            v.put("domain_age_inv",
                    1.0 - Math.min(Math.log1p(Math.max(0, age)) / Math.log1p(3650.0), 1.0));
            v.put("domain_age_unknown", 0.0);
        }
        if (e.mxPresent == null) {
            v.put("mx_absent", 0.0, false);
        } else {
            v.put("mx_absent", e.mxPresent ? 0.0 : 1.0);
        }
        if (e.rdapPrivacy == null) {
            v.put("rdap_privacy", 0.0, false);
        } else {
            v.put("rdap_privacy", e.rdapPrivacy ? 1.0 : 0.0);
        }
        if (e.registrar == null) {
            v.put("registrar_risk", 0.0, false);
        } else {
            v.put("registrar_risk", containsIgnoreCase(ELEVATED_REGISTRARS, e.registrar)
                    ? 1.0 : 0.0);
        }
        if (e.registrarCountry == null || e.orgCountry == null) {
            v.put("registrar_country_off", 0.0, false);
        } else {
            v.put("registrar_country_off",
            e.registrarCountry.equalsIgnoreCase(e.orgCountry) ? 0.0 : 1.0);
        }
    }

    private void extractNlp(Vector v, String text, String body, String subject,
                            String displayName, String fromAddr) {

        // Weighted Semantic Analysis for Urgency, Authority, Secrecy
        WeightedResult urgencyRes = weightedHits(text, URGENCY_LEX);
        v.put("urgency", Math.min(1.0, urgencyRes.totalWeight / 1.5),
            true, "matched: " + (urgencyRes.triggers.isEmpty() ? "none" : String.join(", ", urgencyRes.triggers)));

        WeightedResult authRes = weightedHits(text, AUTHORITY_LEX);
        v.put("authority_claim", Math.min(1.0, authRes.totalWeight / 1.5),
            true, "matched: " + (authRes.triggers.isEmpty() ? "none" : String.join(", ", authRes.triggers)));

        WeightedResult secrecyRes = weightedHits(text, SECRECY_LEX);
        v.put("secrecy_pressure", Math.min(1.0, secrecyRes.totalWeight / 1.5),
            true, "matched: " + (secrecyRes.triggers.isEmpty() ? "none" : String.join(", ", secrecyRes.triggers)));

        // Other NLP features remain frequency-based
        v.put("credential_request", countHits(text, CREDENTIAL) / 2.0);
        v.put("payment_request", countHits(text, PAYMENT) / 3.0);
        v.put("payment_channel_change", Math.min(1.0, countHits(text, CHANNEL_CHANGE) / 2.0));
        v.put("exec_impersonation", execSignal(v, subject, displayName, fromAddr, body));
        v.put("generic_salutation", countHits(text, GENERIC_SALUTATION) > 0 ? 1.0 : 0.0);
        v.put("grammar_anomaly", grammarAnomaly(text));
        v.put("tone_incongruence", toneIncongruence(displayName, text));
    }

    private void extractPayload(Headers.Result h, Vector v, String text) {
        v.put("link_text_mismatch", linkTextMismatch(text));
        v.put("shortener", anyHostIn(h.urls, SHORTENERS) ? 1.0 : 0.0);
        v.put("ip_literal", anyIpLiteralUrl(h.urls) ? 1.0 : 0.0);
        v.put("punycode", anyPunycode(h.urls) ? 1.0 : 0.0);
        v.put("at_in_url", anyAtInUrl(h.urls) ? 1.0 : 0.0);
        v.put("deep_redirect", deepRedirect(h.urls) ? 1.0 : 0.0);
        v.put("credential_form_host", credentialFormHost(h) ? 1.0 : 0.0);

        int dangerous = 0;
        int macro = 0;
        int archive = 0;
        int doubleExt = 0;
        for (Headers.Part p : h.parts) {
            String name = p.filename == null ? "" : p.filename.toLowerCase(Locale.ROOT);
            if (name.isEmpty()) {
                continue;
            }
            if (contains(DANGEROUS_EXT, extOf(name))) {
                dangerous++;
            }
            if (contains(MACRO_EXT, extOf(name))) {
                macro++;
            }
            if (contains(ARCHIVE_EXT, extOf(name))) {
                archive++;
            }
            if (hasDoubleExtension(name) || containsRtlOverride(name)) {
                doubleExt++;
            }
        }
        v.put("attachment_dangerous", dangerous > 0 ? 1.0 : 0.0);
        v.put("attachment_macro", macro > 0 ? 1.0 : 0.0);
        v.put("attachment_archive", archive > 0 ? 1.0 : 0.0);
        v.put("attachment_double_ext", doubleExt > 0 ? 1.0 : 0.0);
        int attachCount = 0;
        for (Headers.Part p : h.parts) {
            if (p.filename != null && !p.filename.isBlank()) {
                attachCount++;
            }
        }
        v.put("attachment_count_n", Math.min(attachCount / 4.0, 1.0));
    }

    private void extractInfra(Vector v, Evidence e, String fromDomain) {
        putBool(v, "ip_in_blacklist", e.ipBlacklisted);
        putBool(v, "asn_risk", e.asnRisk);
        putBool(v, "vpn_proxy", e.vpnProxy);
        putBool(v, "tor_exit", e.torExit);
        putBool(v, "open_relay", e.openRelay);
        putBool(v, "cloud_hosted", e.cloudHosted);
        if (e.originCountry == null || e.registrarCountry == null) {
            v.put("geo_mismatch", 0.0, false);
        } else {
            v.put("geo_mismatch", e.originCountry.equalsIgnoreCase(e.registrarCountry)
                    ? 0.0 : 1.0);
        }
        putBool(v, "reputation_low", e.reputationLow);
    }

    private void putBool(Vector v, String name, Boolean b) {
        if (b == null) {
            v.put(name, 0.0, false, "not checked");
        } else {
            v.put(name, b ? 1.0 : 0.0, true, b ? "checked: present" : "checked: absent");
        }
    }

    private static String firstNonNull(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    private static String domainOfHeader(Headers.Result h, String name) {
        return Headers.domainOf(Headers.addressOf(h.first(name)));
    }

    private static String firstLabel(String domain) {
        int dot = domain.indexOf('.');
        return dot < 0 ? domain : domain.substring(0, dot);
    }

    private static String extOf(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot < 0 ? "" : filename.substring(dot + 1);
    }

    private static String authResult(Headers.Result h, String method) {
        for (String ar : h.all("authentication-results")) {
            String lower = ar.toLowerCase(Locale.ROOT);
            int at = lower.indexOf(method);
            if (at < 0) {
                continue;
            }
            int eq = lower.indexOf('=', at);
            if (eq < 0) {
                continue;
            }
            int start = eq + 1;
            int end = start;
            while (end < lower.length() && !Character.isWhitespace(lower.charAt(end))
                    && lower.charAt(end) != ';') {
                end++;
            }
            String res = lower.substring(start, end);
            if (res.equals("none")) {
                return "none";
            }
            return res;
        }
        return null;
    }

    private static String dkim(String s) {
        return s == null ? null : s.trim();
    }

    private static boolean isFailish(String result) {
        String r = result.toLowerCase(Locale.ROOT);
        return r.equals("fail") || r.equals("softfail") || r.equals("temperror")
                || r.equals("permerror") || r.startsWith("fail");
    }

    private static boolean policyStrict(String dmarc) {
        if (dmarc == null) {
            return false;
        }
        String d = dmarc.toLowerCase(Locale.ROOT);
        int at = d.indexOf("p=");
        if (at < 0) {
            return false;
        }
        String p = d.substring(at + 2);
        int end = 0;
        while (end < p.length() && Character.isLetter(p.charAt(end))) {
            end++;
        }
        String policy = p.substring(0, end);
        return policy.equals("reject") || policy.equals("quarantine");
    }

    private static String dkimDomain(Headers.Result h) {
        for (String d : h.all("dkim-signature")) {
            int at = d.toLowerCase(Locale.ROOT).indexOf("d=");
            if (at < 0) {
                continue;
            }
            String rest = d.substring(at + 2).trim();
            int end = 0;
            while (end < rest.length() && (Character.isLetterOrDigit(rest.charAt(end))
                    || rest.charAt(end) == '.' || rest.charAt(end) == '-')) {
                end++;
            }
            if (end > 0) {
                return rest.substring(0, end).toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static int nonMonotonicCount(List<String> received) {
        long prev = Long.MAX_VALUE;
        int bad = 0;
        for (String r : received) {
            Long ts = parseRfc5322DateIn(r);
            if (ts == null) {
                continue;
            }
            if (ts > prev) {
                bad++;
            }
            prev = ts;
        }
        return bad;
    }

    private static boolean privateHopPresent(List<String> received) {
        for (String r : received) {
            for (String tok : r.split("[\\[\\](),;]")) {
                String t = tok.trim();
                if (t.startsWith("10.") || t.startsWith("192.168.") || t.startsWith("172.16.")
                        || t.startsWith("172.17.") || t.startsWith("172.18.")
                        || t.startsWith("172.19.") || t.startsWith("172.2")
                        || t.startsWith("172.30.") || t.startsWith("172.31.")
                        || t.equals("127.0.0.1") || t.startsWith("fe80:")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static double dateSkewHours(Headers.Result h) {
        String date = h.first("date");
        if (date == null) {
            return -1;
        }
        Long msgTs = parseRfc5322Date(date);
        if (msgTs == null) {
            return -1;
        }
        List<String> received = h.all("received");
        for (String r : received) {
            Long ts = parseRfc5322DateIn(r);
            if (ts != null) {
                return Math.abs(msgTs - ts) / 3_600_000.0;
            }
        }
        return -1;
    }

    static Long parseRfc5322Date(String s) {
        if (s == null) {
            return null;
        }
        String d = s.trim().replaceAll("\\s+", " ");
        int cut = d.lastIndexOf(' ');
        if (cut < 0) {
            return null;
        }
        String zone = d.substring(cut + 1);
        String body = d.substring(0, cut);
        int paren = body.indexOf(" (");
        if (paren > 0) {
            body = body.substring(0, paren);
        }
        String zoneOffset = zoneOffsetOf(zone);
        if (zoneOffset == null) {
            return null;
        }
        try {
            return java.time.ZonedDateTime.parse(body + " " + zoneOffset,
                    java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME)
                    .toInstant().toEpochMilli();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String zoneOffsetOf(String zone) {
        String z = zone.trim();
        if (z.matches("[+-]\\d{4}")) {
            return z;
        }
        String upper = z.toUpperCase(Locale.ROOT);
        if (upper.equals("GMT") || upper.equals("UT") || upper.equals("UTC") || upper.equals("Z")) {
            return "+0000";
        }
        if (upper.length() == 1) {
            char c = upper.charAt(0);
            if (c >= 'A' && c <= 'I') {
                return "-0" + (c - 'A' + 1) + "00";
            }
            if (c >= 'K' && c <= 'M') {
                return "-0" + (c - 'K' + 10) + "00";
            }
            if (c >= 'N' && c <= 'Y') {
                return "+0" + (c - 'N' + 1) + "00";
            }
        }
        return null;
    }

    static Long parseRfc5322DateIn(String s) {
        int at = s.indexOf(';');
        if (at < 0) {
            return null;
        }
        return parseRfc5322Date(s.substring(at + 1));
    }

    private static int countHits(String text, String[] lexicon) {
        int n = 0;
        for (String cue : lexicon) {
            if (text.contains(cue)) {
                n++;
            }
        }
        return n;
    }

    private static boolean contains(String[] arr, String s) {
        for (String a : arr) {
            if (a.equals(s)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsIgnoreCase(String[] arr, String s) {
        if (s == null) {
            return false;
        }
        String t = s.toLowerCase(Locale.ROOT);
        for (String a : arr) {
            if (a.equals(t)) {
                return true;
            }
        }
        return false;
    }

    private static boolean anyHostIn(List<String> urls, String[] hosts) {
        for (String u : urls) {
            String h = hostOf(u);
            if (h != null && contains(hosts, h)) {
                return true;
            }
        }
        return false;
    }

    static String hostOf(String url) {
        if (url == null) {
            return null;
        }
        int at = url.indexOf('@');
        int start = url.indexOf("//");
        start = (start < 0) ? 0 : start + 2;
        int end = start;
        if (at >= 0 && at > start) {
            end = at;
        } else {
            while (end < url.length() && url.charAt(end) != '/'
                    && url.charAt(end) != '?' && url.charAt(end) != '#') {
                end++;
            }
        }
        String h = url.substring(start, end).toLowerCase(Locale.ROOT);
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            return close < 0 ? h : h.substring(1, close);
        }
        int colon = h.indexOf(':');
        return colon < 0 ? h : h.substring(0, colon);
    }

    private static boolean anyIpLiteralUrl(List<String> urls) {
        for (String u : urls) {
            String h = hostOf(u);
            if (h == null || h.isEmpty()) {
                continue;
            }
            if (h.indexOf('.') >= 0) {
                boolean allDigits = true;
                for (int i = 0; i < h.length(); i++) {
                    if (!Character.isDigit(h.charAt(i)) && h.charAt(i) != '.') {
                        allDigits = false;
                        break;
                    }
                }
                if (allDigits) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean anyPunycode(List<String> urls) {
        for (String u : urls) {
            String h = hostOf(u);
            if (h != null && h.startsWith("xn--")) {
                return true;
            }
            for (String label : (h == null ? "" : h).split("\\.")) {
                if (label.startsWith("xn--")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean anyAtInUrl(List<String> urls) {
        for (String u : urls) {
            int start = u.indexOf("//");
            if (start < 0) {
                continue;
            }
            int end = u.indexOf('/', start + 2);
            String authority = (end < 0) ? u.substring(start + 2) : u.substring(start + 2, end);
            if (authority.indexOf('@') >= 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean deepRedirect(List<String> urls) {
        for (String u : urls) {
            int n = 0;
            int at = u.indexOf('?');
            if (at >= 0) {
                String q = u.substring(at + 1);
                for (String kv : q.split("[&;]")) {
                    String k = kv.toLowerCase(Locale.ROOT);
                    if (k.startsWith("url=") || k.startsWith("target=")
                            || k.startsWith("next=") || k.startsWith("redirect=")
                            || k.startsWith("dest=") || k.startsWith("continue=")
                            || k.startsWith("u=")) {
                        n++;
                    }
                }
            }
            if (n >= 2) {
                return true;
            }
        }
        return false;
    }

    private static boolean credentialFormHost(Headers.Result h) {
        String from = Features.domainOfHeader(h, "from");
        if (from == null) {
            return false;
        }
        String body = h.bodyText == null ? "" : h.bodyText.toLowerCase(Locale.ROOT);
        boolean formy = body.contains("<form") || body.contains("<input")
                || body.contains("type=\"password\"") || body.contains("type='password'")
                || body.contains("sign in") || body.contains("log in");
        if (!formy) {
            return false;
        }
        for (String u : h.urls) {
            String host = hostOf(u);
            if (host != null && !host.equals(from) && !host.endsWith("." + from)) {
                return true;
            }
        }
        return false;
    }

    private static double linkTextMismatch(String text) {
        int anchors = 0;
        int mismatched = 0;
        String lower = text.toLowerCase(Locale.ROOT);
        int at = 0;
        while (true) {
            int a = lower.indexOf("<a ", at);
            if (a < 0) {
                break;
            }
            int gt = lower.indexOf('>', a);
            if (gt < 0) {
                break;
            }
            String tag = lower.substring(a, gt);
            int hrefAt = tag.indexOf("href=");
            String href = null;
            if (hrefAt >= 0) {
                int s = hrefAt + 5;
                if (s < tag.length() && (tag.charAt(s) == '"' || tag.charAt(s) == '\'')) {
                    char q = tag.charAt(s);
                    int e = tag.indexOf(q, s + 1);
                    href = (e < 0) ? tag.substring(s + 1) : tag.substring(s + 1, e);
                } else {
                    int e = s;
                    while (e < tag.length() && !Character.isWhitespace(tag.charAt(e))) {
                        e++;
                    }
                    href = tag.substring(s, e);
                }
            }
            int close = lower.indexOf("</a>", gt);
            String inner = (close < 0) ? "" : text.substring(gt + 1, Math.min(close, text.length()));
            anchors++;
            if (href != null) {
                String host = hostOf(href);
                if (host != null && !host.isEmpty() && !inner.toLowerCase(Locale.ROOT).contains(host)
                        && !inner.toLowerCase(Locale.ROOT).contains(stripTld(host))) {
                    mismatched++;
                }
            }
            at = gt + 1;
        }
        return anchors == 0 ? 0.0 : (double) mismatched / anchors;
    }

    private static String stripTld(String host) {
        String[] parts = host.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2];
        }
        return host;
    }

    private static boolean hasDoubleExtension(String filename) {
        int d1 = filename.lastIndexOf('.');
        if (d1 <= 0) {
            return false;
        }
        String firstExt = filename.substring(0, d1);
        int d2 = firstExt.lastIndexOf('.');
        if (d2 < 0) {
            return false;
        }
        String mid = filename.substring(d2 + 1, d1).toLowerCase(Locale.ROOT);
        return (contains(new String[]{"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                "txt", "rtf", "jpg", "png", "gif", "csv"}, mid) || mid.isEmpty());
    }

    private static boolean containsRtlOverride(String filename) {
        return filename.indexOf("‮") >= 0 || filename.indexOf("‭") >= 0
                || filename.indexOf("‏") >= 0;
    }

    private double execSignal(Vector v, String subject, String displayName, String fromAddr,
                              String body) {
        String hay = ((subject == null ? "" : subject) + " "
                + (displayName == null ? "" : displayName) + " "
                + (fromAddr == null ? "" : fromAddr)).toLowerCase(Locale.ROOT);
        int n = countHits(hay, EXEC);
        double titleSignal = (n == 0) ? 0.0 : Math.min(1.0, 0.5 + 0.25 * n);

        OrgProfile.Observed named = profile.executiveMentioned(body);
        if (!named.observed()) {
            return titleSignal;
        }
        if (!named.value()) {
            return titleSignal * 0.5;
        }
        v.notes.add("exec_impersonation: " + named.reason());
        return 1.0;
    }

    private static double grammarAnomaly(String text) {
        int words = 0;
        int upper = 0;
        int exclam = 0;
        int nonAscii = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c)) {
                words++;
            } else if (Character.isUpperCase(c)) {
                upper++;
            } else if (c > 127) {
                nonAscii++;
            }
            if (c == '!') {
                exclam++;
            }
        }
        if (words == 0) {
            return 0.0;
        }
        double upperRatio = (double) upper / (text.length() + 1);
        double exclamRatio = (double) exclam / (words + 1);
        double nonAsciiRatio = (double) nonAscii / (text.length() + 1);
        return Math.min(1.0, upperRatio * 0.8 + exclamRatio * 0.15 + nonAsciiRatio * 0.3);
    }

    private static double toneIncongruence(String displayName, String text) {
        if (displayName == null || displayName.isBlank() || text == null || text.isEmpty()) {
            return 0.0;
        }
        boolean formalDisplay = displayName.toLowerCase(Locale.ROOT).matches(".*\\b(department|"
                + "office|service|team|support|administrator|info|no-?reply)\\b.*");

        // Fix: Use URGENCY_LEX instead of non-existent URGENCY array
        double urgentWeight = 0.0;
        for (LexiconEntry e : URGENCY_LEX) {
            if (text.toLowerCase(Locale.ROOT).contains(e.phrase)) {
                urgentWeight += e.weight;
            }
        }

        if (formalDisplay && urgentWeight >= 1.0) {
            return 1.0;
        }
        return Math.min(1.0, urgentWeight / 3.0);
    }

    // New Weighted Result class
    private static final class WeightedResult {
        final double totalWeight;
        final List<String> triggers;
        WeightedResult(double tw, List<String> tr) {
            this.totalWeight = tw;
            this.triggers = tr;
        }
    }

    private static WeightedResult weightedHits(String text, List<LexiconEntry> lexicon) {
        double totalWeight = 0.0;
        List<String> triggers = new ArrayList<>();
        String workingText = text;

        for (LexiconEntry entry : lexicon) {
            if (workingText.contains(entry.phrase)) {
                totalWeight += entry.weight;
                if (entry.weight >= 0.5) triggers.add(entry.phrase);
                workingText = workingText.replace(entry.phrase, " ");
            }
        }
        return new WeightedResult(totalWeight, triggers);
    }

    /**
     * Calculates the restricted Damerau-Levenshtein distance (Optimal String Alignment) between two strings.
     *
     * <p>Permitted operations (each with unit cost 1):
     * <ul>
     *   <li>Insertion: inserting a single character (e.g. "paypal" -> "paypall", cost 1)</li>
     *   <li>Deletion: deleting a single character (e.g. "paypals" -> "paypal", cost 1)</li>
     *   <li>Substitution: replacing a character (e.g. "paypal" -> "paypa1", cost 1)</li>
     *   <li>Transposition: swapping two adjacent characters (e.g. "paypla" -> "paypal", cost 1)</li>
     * </ul>
     *
     * <p>Complexity: O(|a| * |b|) time and space.
     *
     * @param a The first string (normalized skeleton).
     * @param b The second string (brand canonical skeleton).
     * @return The minimum edit operations required to transform {@code a} into {@code b}.
     */
    public static int editDistance(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        int n = a.length();
        int m = b.length();
        if (n == 0) return m;
        if (m == 0) return n;

        int[][] d = new int[n + 1][m + 1];
        for (int i = 0; i <= n; i++) d[i][0] = i;
        for (int j = 0; j <= m; j++) d[0][j] = j;

        for (int i = 1; i <= n; i++) {
            char ca = a.charAt(i - 1);
            for (int j = 1; j <= m; j++) {
                char cb = b.charAt(j - 1);
                int cost = (ca == cb) ? 0 : 1;
                d[i][j] = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + cost);
                if (i > 1 && j > 1 && ca == b.charAt(j - 2) && a.charAt(i - 2) == cb) {
                    d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
                }
            }
        }
        return d[n][m];
    }
}
