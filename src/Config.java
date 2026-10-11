/**
 * Every constant the platform uses, in one place, each traced to a line in
 * docs/SCORING-MODEL.md or docs/ARCHITECTURE.md.
 *
 * Rule from SCORING-MODEL.md L5-6: "No score may be hardcoded, invented, or produced by a
 * code path that is not described here." Nothing in this file is a tuning guess: each field
 * carries the spec line it comes from. The only deliberately hand-set values are
 * INITIAL_B0 / INITIAL_BETA / INITIAL_G, which exist solely to initialise tools/fit.java and
 * are superseded by data/model.json (see docs/PHASE1-NOTES.md C-08 and C-09).
 */
public final class Config {

    private Config() {
    }

    // ==================================================================
    // Model shape - SCORING-MODEL.md L133-137
    // ==================================================================

    /** K, the number of classes. Spec L133-137. */
    public static final int K = 8;

    /**
     * Class names in fixed spec order. Spec L135-136.
     * NOTE: this is the SPEC taxonomy, not the prompt body's taxonomy.
     * See docs/PHASE1-NOTES.md C-01.
     */
    public static final String[] CLASS_NAMES = {
            "legitimate",   // 0
            "suspicious",   // 1
            "impersonation",// 2
            "phishing",     // 3
            "bec",          // 4
            "fraud",        // 5
            "malware",      // 6
            "spam"          // 7
    };

    public static final int CLASS_LEGITIMATE = 0;

    /**
     * Class index of BEC. Named because the model reports the base classifier's BEC
     * probability alongside the blended one, and "4" at that call site would be opaque.
     * Pinned by an assertion against CLASS_NAMES so the two cannot drift apart.
     */
    public static final int CLASS_BEC = 4;

    /**
     * The eight-way taxonomy as a closed set of values.
     *
     * Spec L133-137 requires exactly eight TYPED classes. A String[] cannot satisfy that: it
     * admits typos at every call site, an out-of-range index throws a bare
     * ArrayIndexOutOfBoundsException with no class name in the message, and nothing stops a
     * caller from inventing a ninth label. An enum makes the set closed and gives every
     * misuse a named failure.
     *
     * Ordinals are the class indices, and {@link #CLASS_OF} asserts that mapping in both
     * directions, so the enum and {@link #CLASS_NAMES} cannot drift apart silently.
     */
    public enum Cls {
        LEGITIMATE,     // 0
        SUSPICIOUS,     // 1
        IMPERSONATION,  // 2
        PHISHING,       // 3
        BEC,            // 4
        FRAUD,          // 5
        MALWARE,        // 6
        SPAM;           // 7

        /** The class index this value occupies. */
        public int index() {
            return ordinal();
        }

        /** The spec name for this class. */
        public String label() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }

        /** Reverse lookup. Fails loudly rather than returning a default. */
        public static Cls of(int index) {
            Cls[] all = values();
            if (index < 0 || index >= all.length) {
                throw new IllegalArgumentException("class index " + index
                        + " is outside the " + all.length + "-way taxonomy");
            }
            return all[index];
        }
    }

    /** Defensive accessor for the class-name array, which is otherwise publicly mutable. */
    public static String[] classNames() {
        return CLASS_NAMES.clone();
    }

    /** The typed class for a class index. */
    public static Cls classOf(int index) {
        return Cls.of(index);
    }

    static {
        if (!CLASS_NAMES[CLASS_BEC].equals("bec")) {
            throw new AssertionError("CLASS_BEC=" + CLASS_BEC
                    + " does not name bec, it names " + CLASS_NAMES[CLASS_BEC]);
        }
        if (Cls.values().length != K) {
            throw new AssertionError("Cls has " + Cls.values().length
                    + " values but K=" + K);
        }
        // Both directions: the enum's labels must reproduce the array exactly, in order.
        for (Cls c : Cls.values()) {
            if (!CLASS_NAMES[c.index()].equals(c.label())) {
                throw new AssertionError("taxonomy drift: index " + c.index()
                        + " is '" + CLASS_NAMES[c.index()] + "' in CLASS_NAMES but '"
                        + c.label() + "' in Cls");
            }
        }
    }

    // ==================================================================
    // Feature families - SCORING-MODEL.md L35-123
    // ==================================================================

    /** Family identifiers, spec order F1..F6. */
    public static final String[] FAMILY_NAMES = {
            "AUTH",    // F1 - Authentication / header integrity   (L35)
            "ROUTE",   // F2 - Routing / relay authenticity       (L48)
            "IDENT",   // F3 - Identity / domain intelligence     (L62)
            "NLP",     // F4 - Content / language                 (L77)
            "PAYLOAD", // F5 - Payload / links                    (L91)
            "INFRA"    // F6 - Infrastructure reputation          (L107)
    };

    public static final int FAM_AUTH = 0;
    public static final int FAM_ROUTE = 1;
    public static final int FAM_IDENT = 2;
    public static final int FAM_NLP = 3;
    public static final int FAM_PAYLOAD = 4;
    public static final int FAM_INFRA = 5;

    /**
     * Family weights. Spec L119-123. Reported alongside C_cov for analyst context; the
     * normative definition of v_f used by C_cov is |beta_f| per spec L270.
     * See docs/PHASE1-NOTES.md C-10 / OD-2.
     */
    public static final double[] FAMILY_WEIGHTS = {0.20, 0.18, 0.18, 0.17, 0.15, 0.12};

    // ==================================================================
    // Scoring constants - SCORING-MODEL.md section 2
    // ==================================================================

    /** Per-term clip bound c. Spec L146 and L231. */
    public static final double CLIP_C = 2.5;

    /** Noisy-OR weight for the BEC head. Spec L187. */
    public static final double W_BEC = 0.35;

    /**
     * Initial b0 (bias per class) used ONLY to initialise the offline fitter.
     * Never used for scoring at runtime once data/model.json exists.
     */
    public static final double[] INITIAL_B0 = {
            4.00,   // legitimate   - prior strongly favours clean, authenticated mail
            -0.60,  // suspicious
            -1.00,  // impersonation
            -0.20,  // phishing
            -1.20,  // bec
            -1.70,  // fraud
            -0.40,  // malware
            0.60    // spam - low prior; a legitimate-looking message keeps this class alive
    };

    /**
     * Hand-set initial bias toward a class. Column = feature, row = class.
     * Layout is (K x F) where F is the number of model dimensions. See OD-1 in
     * docs/PHASE1-NOTES.md: the shipped model uses one dimension per named sub-feature.
     *
     * These are INITIAL VALUES for tools/fit.java only. The strings below are the fitter's
     * starting prior, derived from the feature semantics in spec L35-117; they are not a
     * substitute for fitting and the engine never reports a score from them when a fitted
     * model is present.
     */
    public static final double[][] INITIAL_BETA_BY_FAMILY = {
            //            AUTH   ROUTE  IDENT  NLP  PAYLOAD INFRA
            /* legit   */ { -1.8,  -1.9,  -1.2,  -1.7,  -0.9,  -0.8 },
            /* suspic. */ {  0.8,   1.0,   0.9,   0.7,   0.5,   0.9 },
            /* imperson*/ {  0.7,   1.8,   1.2,   0.9,   0.3,   0.4 },
            /* phish   */ {  1.6,   0.8,   1.4,   1.6,   1.0,   0.5 },
            /* bec     */ {  0.6,   1.1,   0.5,   1.9,   0.2,   0.4 },
            /* fraud   */ {  0.5,   1.0,   0.7,   1.9,   0.3,   0.5 },
            /* malware */ {  0.4,   0.4,   0.4,   0.5,   1.9,   0.3 },
            /* spam    */ {  0.5,   0.6,   0.7,   0.9,   0.3,   1.0 }
    };

    /**
     * Initial coefficients for the BEC head, over the BEC-relevant subset only.
     * Spec L175-178 names the subset. Index 0 is the bias g_0.
     */
    public static final double[] INITIAL_G = {-3.2,
            0.30,   // exec_impersonation
            0.85,   // payment_channel_change
            0.55,   // secrecy_pressure
            0.45,   // urgency
            0.30,   // authority_claim
            0.25,   // replyto_mismatch
            0.30,   // replyto_free_mail
            0.10,   // received_count_n
            0.20,   // domain_age_inv
            0.15,   // dmarc_policy_strict
            0.20    // attachment_archive
    };

    /**
     * The BEC-relevant feature subset, in the order of INITIAL_G (after the bias).
     * Spec L176-178.
     */
    public static final String[] BEC_SUBSET = {
            "exec_impersonation",
            "payment_channel_change",
            "secrecy_pressure",
            "urgency",
            "authority_claim",
            "replyto_mismatch",
            "replyto_free_mail",
            "received_count_n",
            "domain_age_inv",
            "dmarc_policy_strict",
            "attachment_archive"
    };

    // ==================================================================
    // Confidence - SCORING-MODEL.md section 5
    // ==================================================================

    /** C_model exponent. Spec L266. */
    public static final double GAMMA = 0.7;

    /** Below this, abstain. Spec L286. */
    public static final double C_ABSTAIN = 0.50;

    /** At or above this, eligible for automated policy. Spec L288. */
    public static final double C_AUTOMATED = 0.70;

    public static final String VERDICT_UNDETERMINED = "UNDETERMINED";
    public static final String VERDICT_LOW_CONFIDENCE = "LOW_CONFIDENCE_REVIEW_ADVISED";

    // ==================================================================
    // Attribution - SCORING-MODEL.md section 6
    // ==================================================================

    public static final double C_ATTR_W_TRACEABILITY = 0.35;
    public static final double C_ATTR_W_STABILITY = 0.25;
    public static final double C_ATTR_W_ANONYMITY = 0.25;
    public static final double C_ATTR_W_CORROBORATION = 0.15;

    /** Hard cap. Spec L314. */
    public static final double C_ATTR_CAP = 0.85;

    public static final double C_ATTR_BAND_PROBABLE = 0.70;
    public static final double C_ATTR_BAND_INDICATIVE = 0.45;
    public static final double C_ATTR_BAND_WEAK = 0.25;

    /**
     * Mandatory disclaimer. Spec L319-320, verified byte-exact: 154 characters, pure ASCII,
     * apostrophe is U+0027. Every surface showing C_attr must print this.
     * See docs/PHASE1-NOTES.md section 4.
     */
    public static final String DISCLAIMER =
            "Geolocation indicates infrastructure registration/hosting. It is not personal "
            + "attribution and must not be treated as evidence of an individual's location.";

    // ==================================================================
    // Bands and alerts - SCORING-MODEL.md section 3
    // ==================================================================

    public static final String BAND_HIGH = "HIGH-RISK";
    public static final String BAND_SUSPICIOUS = "SUSPICIOUS";
    public static final String BAND_LOW = "LOW";

    /**
     * FPR caps for constrained threshold selection. Spec L200-201.
     * NOTE: this is the spec's empirical method. The prompt body's cost-ratio formula
     * (tau = C_FP/(C_FP+C_FN)) was rejected - see docs/PHASE1-NOTES.md C-05.
     */
    public static final double FPR_CAP_HIGH = 0.010;
    public static final double FPR_CAP_SUSPICIOUS = 0.050;

    /**
     * Fallback thresholds used ONLY before the fitter has derived real ones. Recorded in
     * model.json as such. The spec requires thresholds be derived and stored (L213-215);
     * these are a starting point for the constrained optimisation, not a published result.
     */
    public static final double TAU_HIGH_FALLBACK = 60.0;
    public static final double TAU_SUSPICIOUS_FALLBACK = 40.0;

    /** Operational alert severity ladder. Spec L219. Distinct from bands. */
    public static final double ALERT_MEDIUM = 40.0;
    public static final double ALERT_HIGH = 60.0;
    public static final double ALERT_CRITICAL = 80.0;

    // ==================================================================
    // Campaign correlation - SCORING-MODEL.md section 7
    // ==================================================================

    public static final double SIM_W_HEADERS = 0.25;
    public static final double SIM_W_DOMAINS = 0.30;
    public static final double SIM_W_IPS = 0.20;
    public static final double SIM_W_TEXT = 0.20;
    public static final double SIM_W_ATTACHMENTS = 0.05;

    /** Edge retention threshold. Spec L351. */
    public static final double TAU_CLUSTER = 0.62;

    // ==================================================================
    // Calibration and evaluation - SCORING-MODEL.md section 8
    // ==================================================================

    /** Equal-width reliability bins. Spec L410. Prompt body said 15; spec wins. */
    public static final int ECE_BINS = 10;

    /** Spec L509 target; reported honestly, not asserted. See OD-3. */
    public static final double ECE_TARGET = 0.05;

    public static final double FPR_TARGET = 0.01;

    /** Bootstrap resample count and fixed seed for the macro-F1 CI. */
    public static final int BOOTSTRAP_RESAMPLES = 1000;
    public static final long BOOTSTRAP_SEED = 20260925L;

    // ==================================================================
    // Offline fitting - SCORING-MODEL.md section 9
    // ==================================================================

    public static final double FIT_LAMBDA = 1e-3;
    public static final double FIT_LEARNING_RATE = 0.05;
    public static final double FIT_GRADIENT_TOLERANCE = 1e-6;
    public static final int FIT_MAX_ITERATIONS = 5000;
    public static final int FIT_BATCH_SIZE = 32;
    public static final int FIT_TRAIN_PERCENT = 70;
    public static final int FIT_VALIDATION_PERCENT = 15;
    public static final int FIT_TEST_PERCENT = 15;
    public static final long FIT_SEED = 20260925L;

    /** Temperature scaling for the BEC head. Spec L416-419. */
    public static final int TEMPERATURE_GRID = 200;
    public static final double TEMPERATURE_MIN = 0.05;
    public static final double TEMPERATURE_MAX = 5.0;

    // ==================================================================
    // Parser limits - Phase 1 item 1
    // Exceeding any limit yields a parse_warning and truncation, never an exception.
    //
    // PROVENANCE: the six numeric caps below are stated verbatim in the task's item 1 and are
    // NOT specified in ARCHITECTURE.md, so the task governs. MAX_HEADER_LINE_BYTES,
    // MAX_MIME_DEPTH, MAX_MIME_PARTS and PARSE_TIME_BUDGET_MS are not specified anywhere and
    // are additions; they are called out separately in docs/PHASE1-NOTES.md C-15 so a reviewer
    // can tell a requirement from an assumption.
    //
    // An earlier revision of Config used 2 MB / 500 headers / 500 URLs, which matched NEITHER
    // the task text NOR any spec. That was drift, not a decision, and is corrected here.
    // ==================================================================

    public static final long MAX_MESSAGE_BYTES = 5L * 1024 * 1024;   // 5 MB   (item 1)
    public static final int MAX_HEADERS = 100;                        // 100    (item 1)
    public static final int MAX_RECEIVED_HEADERS = 25;                // 25     (item 1)
    public static final int MAX_URLS = 1000;                          // 1000   (item 1)
    public static final long MAX_ATTACHMENT_BYTES = 10L * 1024 * 1024; // 10 MB (item 1)
    public static final int MAX_BASE64_LINES = 2000;                  // 2000   (item 1)

    // --- not specified by the task or the specs: defensive additions ---------------
    public static final int MAX_HEADER_LINE_BYTES = 8 * 1024;         // 8 KB
    public static final int MAX_MIME_DEPTH = 8;
    public static final int MAX_MIME_PARTS = 200;
    public static final long MAX_DECODED_BYTES = 10L * 1024 * 1024;   // 10 MB
    public static final long PARSE_TIME_BUDGET_MS = 2000;             // 2 s

    // ==================================================================
    // Enrichment deadlines, cache TTL, circuit breaker - ARCHITECTURE.md L51-54
    // ==================================================================

    public static final long ENRICH_PER_SOURCE_TIMEOUT_MS = 2000;     // 2 s
    public static final long ENRICH_GLOBAL_DEADLINE_MS = 6000;       // 6 s

    public static final long CACHE_TTL_GEO_MS = 24L * 60 * 60 * 1000;
    public static final long CACHE_TTL_DNS_MS = 15L * 60 * 1000;
    public static final long CACHE_TTL_RDAP_MS = 24L * 60 * 60 * 1000;
    public static final long CACHE_TTL_REPUTATION_MS = 60L * 60 * 1000;

    public static final int BREAKER_FAILURE_THRESHOLD = 3;
    public static final long BREAKER_OPEN_MS = 10L * 60 * 1000;

    // ==================================================================
    // Audit chain - Phase 1 item 7
    // ==================================================================

    public static final String AUDIT_GENESIS_SEED = "cipher-squad-genesis";
    public static final int AUDIT_SIGN_EVERY_N = 50;
    public static final String SIGNATURE_NOT_CONFIGURED = "NOT_CONFIGURED";

    /**
     * Fixed formatter for doubles in canonical JSON. Documented per Phase 1 item 7 so that
     * independent implementations reproduce byte-identical chain hashes.
     * 10 significant digits, trailing zeros stripped, -0 normalised to 0.
     */
    public static final String CANONICAL_DOUBLE_FORMAT = "%.10g";
    public static final String CANONICAL_DOUBLE_ZERO = "0";

    // ==================================================================
    // Server - ARCHITECTURE.md section 7
    // ==================================================================

    public static final String DEFAULT_BIND_ADDRESS = "127.0.0.1";
    public static final int DEFAULT_PORT = 8080;
    public static final long MAX_REQUEST_BODY_BYTES = 2L * 1024 * 1024;

    public static final int AUTH_PBKDF2_ITERATIONS = 120_000;
    public static final int AUTH_SALT_BYTES = 16;
    public static final int AUTH_SESSION_TOKEN_BYTES = 32;
    public static final long AUTH_SESSION_TTL_MS = 8L * 60 * 60 * 1000;
    public static final int AUTH_MAX_FAILURES = 5;
    public static final long AUTH_FAILURE_WINDOW_MS = 15L * 60 * 1000;

    // ==================================================================
    // Outbound probe guard - ARCHITECTURE.md L243-248
    // ==================================================================

    public static final int SSRF_MAX_REDIRECTS = 3;
    public static final long SSRF_TIMEOUT_MS = 3000;
    public static final long SSRF_MAX_RESPONSE_BYTES = 512L * 1024;
}
