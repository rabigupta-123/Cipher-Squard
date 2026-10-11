/**
 * The model and the single scoring path. SCORING-MODEL.md sections 2, 3, 5, 6.
 *
 * "Single model and single explanation path" is a design requirement, not a slogan. There is
 * exactly one forward pass (softmax), exactly one risk function, and exactly one explanation
 * routine. Findings and the headline score are produced by the same arithmetic in the same
 * call, so a finding can never disagree with the score it is offered as an explanation for.
 *
 * Order of operations, and why it is this order:
 *   1. z_k   = b0_k + SUM_f clip(beta_fk * x_f, -c, +c)      L146. Clip BEFORE summing, so
 *             no single feature can dominate regardless of its scale.
 *   2. p     = softmax(z) with the max shifted out first, so exp() never overflows.
 *   3. risk  = 100 * (1 - p_legitimate)                        L152-156
 *   4. bec   = sigmoid(g . x_bec), temperature-scaled by T     L175-181
 *   5. risk_final = 100 * (1 - (1-P_notlegit)(1 - w*P_bec))   L186-187
 *   6. C_model = (1 - H_norm)^gamma                            L266
 *   7. C_attr = min(T^0.35 S^0.25 (1-A)^0.25 X^0.15, 0.85)     L309, L314
 *
 * The clip in step 1 is the reason the explanation in step 8 must also clip: a feature
 * reported as driving the score by more than c would contradict the score.
 */
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class Model {

    /** Where the fitted parameters came from. Reported verbatim in every report. */
    public enum Source {
        /** data/model.json exists and loaded. */
        FITTED,
        /** Initialisation matrix, not fitted. Scores from it are advisory only. */
        HAND_SET_UNCALIBRATED
    }

    public final double[] b0;          // K
    public final double[][] beta;      // K x F, row-major
    public final double[] g;           // BEC head, index 0 is the bias
    public final int featureCount;
    public final double tauHigh;
    public final double tauSuspicious;
    public final double tauCluster;
    public final double temperature;   // T for the BEC head
    public final double gamma;         // C_model exponent
    public final String version;
    public final Source source;
    public final String trainedOn;
    public final Map<String, Object> metrics;

    public static final int K = Config.K;

    public Model(double[] b0, double[][] beta, double[] g, int featureCount,
                 double tauHigh, double tauSuspicious, double tauCluster,
                 double temperature, double gamma,
                 String version, Source source, String trainedOn, Map<String, Object> metrics) {
        if (b0.length != K) {
            throw new IllegalArgumentException("b0 has " + b0.length + " entries, expected " + K);
        }
        if (beta.length != K) {
            throw new IllegalArgumentException("beta has " + beta.length + " rows, expected " + K);
        }
        for (int k = 0; k < K; k++) {
            if (beta[k].length != featureCount) {
                throw new IllegalArgumentException("beta[" + k + "] has " + beta[k].length
                        + " columns, expected featureCount=" + featureCount);
            }
        }
        this.b0 = b0.clone();
        this.beta = new double[K][];
        for (int k = 0; k < K; k++) {
            this.beta[k] = beta[k].clone();
        }
        this.g = g.clone();
        this.featureCount = featureCount;
        this.tauHigh = tauHigh;
        this.tauSuspicious = tauSuspicious;
        this.tauCluster = tauCluster;
        this.temperature = temperature;
        this.gamma = gamma;
        this.version = version;
        this.source = source;
        this.trainedOn = trainedOn;
        this.metrics = metrics == null ? Map.of() : new LinkedHashMap<>(metrics);
    }

    // ==================================================================
    // Step 1: logits
    // ==================================================================

    /**
     * z_k = b0_k + SUM_f clip(beta_fk * x_f, -c, +c). SCORING-MODEL.md L144-146.
     *
     * Also returns the per-term matrix so the explanation can quote exactly the numbers that
     * produced the score, instead of recomputing them and risking disagreement.
     */
    public static final class Logits {
        public final double[] z = new double[K];
        public final double[][] terms = new double[K][];
        public int clippedTerms;
        /**
         * The intercept per class, kept beside the terms so the decomposition
         * z_k = intercept_k + sum_f terms[k][f] can be checked without re-deriving it.
         */
        public final double[] intercept = new double[K];
        /**
         * The observed mask actually used, length featureCount. A null mask means "all
         * observed"; this array always materialises the decision so a consumer can see which
         * features were allowed to contribute.
         */
        public boolean[] observed;
        /** How many features were treated as unobserved and therefore zeroed. */
        public int unobservedCount;
    }

    public Logits logits(double[] x) {
        return logits(x, null);
    }

    /**
     * As {@link #logits(double[])}, but an unobserved feature contributes exactly 0.
     *
     * The spec is explicit: for unobserved features the contribution is 0 unless explicitly
     * configured otherwise, because a missing observation is an absence of evidence and must
     * not push a message toward any class. Zeroing is done by substituting x_f = 0, which is
     * also the only way to keep the term matrix consistent with the reported logit.
     *
     * @param observed  length must equal x.length, or null to treat every feature as observed
     */
    public Logits logits(double[] x, boolean[] observed) {
        requireFeatureLength(x);
        if (observed != null && observed.length != x.length) {
            throw new IllegalArgumentException("observed mask has " + observed.length
                    + " entries, expected " + x.length);
        }
        Logits out = new Logits();
        out.observed = new boolean[x.length];
        for (int f = 0; f < x.length; f++) {
            out.observed[f] = (observed == null) || observed[f];
            if (!out.observed[f]) {
                out.unobservedCount++;
            }
        }
        for (int k = 0; k < K; k++) {
            double sum = b0[k];
            double[] row = new double[featureCount];
            out.intercept[k] = b0[k];
            for (int f = 0; f < featureCount; f++) {
                boolean obs = out.observed[f];
                if (!obs) {
                    // Unobserved: contributes nothing, and is recorded as a zero term so the
                    // explanation cannot claim a feature drove a score it never entered.
                    row[f] = 0.0;
                    continue;
                }
                double t = beta[k][f] * x[f];
                if (t > Config.CLIP_C) {
                    t = Config.CLIP_C;
                    out.clippedTerms++;
                } else if (t < -Config.CLIP_C) {
                    t = -Config.CLIP_C;
                    out.clippedTerms++;
                }
                row[f] = t;
                sum += t;
            }
            out.terms[k] = row;
            out.z[k] = sum;
        }
        return out;
    }

    /**
     * Noisy-OR: P = 1 - PRODUCT(1 - p_i).
     *
     * Exposed as a standalone static so it can be tested on its own, and so the blending step
     * is a named, auditable function rather than arithmetic buried in score().
     *
     * Each p_i is clamped to [0,1] first. A caller passing evidence strength of 1.4 or -0.2
     * gets a defined answer instead of a probability outside [0,1], which would silently
     * corrupt risk_final. Empty evidence yields 0.0, not NaN: "no evidence" must not become
     * "certain".
     *
     * PRODUCT(1-p_i) can underflow to 0.0 for many strong inputs, which is correct - the
     * result saturates at 1.0 rather than going NaN.
     */
    public static double noisyOr(double[] evidenceProbabilities) {
        if (evidenceProbabilities == null || evidenceProbabilities.length == 0) {
            return 0.0;
        }
        double product = 1.0;
        for (int i = 0; i < evidenceProbabilities.length; i++) {
            double p = evidenceProbabilities[i];
            if (!Double.isFinite(p)) {
                throw new IllegalArgumentException(
                        "BEC evidence p[" + i + "] is not finite: " + p);
            }
            if (p < 0.0) {
                p = 0.0;
            } else if (p > 1.0) {
                p = 1.0;
            }
            product *= (1.0 - p);
        }
        return 1.0 - product;
    }

    // ==================================================================
    // Step 2: softmax
    // ==================================================================

    /**
     * Numerically stable softmax: subtract the max before exp.
     *
     * This is what keeps the engine alive on a hostile feature vector. At logits of +/-1e4 a
     * naive exp() overflows to Infinity, every probability becomes NaN, and every downstream
     * comparison silently returns false - a verifier would report "ok" on garbage. Max
     * subtraction makes exp() arguments non-positive, so the result is always finite.
     * SCORING-MODEL.md L148-150.
     */
    public static double[] softmax(double[] z) {
        if (z.length != K) {
            throw new IllegalArgumentException("logit vector has " + z.length + " entries");
        }
        double max = Double.NEGATIVE_INFINITY;
        for (double v : z) {
            if (v > max) {
                max = v;
            }
        }
        double[] p = new double[K];
        double sum = 0.0;
        for (int k = 0; k < K; k++) {
            double e = Math.exp(z[k] - max);
            p[k] = e;
            sum += e;
        }
        // sum >= 1 always, because the max element contributes exp(0) = 1. So this cannot
        // divide by zero even for a fully saturated vector.
        for (int k = 0; k < K; k++) {
            p[k] /= sum;
        }
        return p;
    }

    // ==================================================================
    // Steps 3-7: the score
    // ==================================================================

    public static final class Score {
        public double[] p = new double[K];
        public Logits logits;
        public double risk;            // 100*(1-P(legitimate))
        public double becScore;        // 100*P(bec), reported separately per L182
        public double riskFinal;       // noisy-OR blend per L186

        // --- BEC Noisy-OR, exposed separately per the Phase 1 brief ---
        /** Defensive copy of the evidence probabilities fed to the Noisy-OR. */
        public final List<Double> becEvidence = new ArrayList<>();
        /** 1 - PRODUCT(1 - p_i) over becEvidence. NOT a calibrated probability. */
        public double becNoisyOr;
        /**
         * P(BEC) from the base classifier's dedicated BEC head, before any evidence blending.
         * This is the quantity the documented risk formula consumes.
         */
        public double becBaseProbability;
        /**
         * P(BEC) as it appears in the K-way softmax. Tracked alongside becBaseProbability so a
         * report can show the two separately; the two are NOT the same number and conflating
         * them is how a head value gets presented as a calibrated class probability.
         */
        public double becClassProbability;
        /** P(BEC) after the explicit blend. Equals the value used in riskFinal. */
        public double becBlendedProbability;
        /** The blend weight actually applied, so a report can state it. */
        public double becBlendWeight;
        /** Human-readable statement of how becBlendedProbability was derived. */
        public String becBlendMethod = "none";
        /** True only when becNoisyOr is backed by real evidence, not by the sigmoid prior. */
        public boolean becEvidenceBacked;

        public double cModel;          // (1-H_norm)^gamma
        public double cAttr;          // capped per L314
        public String band;
        public String verdict;
        public boolean alertEligible;
        public boolean caseCreationEnabled;
        public String abstentionReason;
        public int argmax;
        public List<Finding> findings = new ArrayList<>();

        // --- provenance: which model produced this score ---
        /** Model version string, so a stored score can be traced to the weights that made it. */
        public String modelVersion = "unknown";
        /** Weights source, per the Model.Source taxonomy. */
        public String weightsSource = "unknown";
        /** Training-set identifier, or "none" for a hand-set uncalibrated model. */
        public String trainedOn = "none";
        /** The intercept of the score, exposed so the output is auditable without re-deriving it. */
        public final double[] intercept = new double[K];

        /** The argmax class as a typed value, not an int index into Config.CLASS_NAMES. */
        public Config.Cls argmaxClass;
    }

    /**
     * Full scoring pass. Pure: reads only its arguments and the model, so it is the unit that
     * the tests call repeatedly. ARCHITECTURE.md L152 (inference purity).
     *
     * @param x      feature vector, length featureCount
     * @param becX   BEC-head feature subset, length g.length-1, or null to skip the BEC head
     * @param attr   attribution inputs T, S, A, X in [0,1]
     */
    public Score score(double[] x, double[] becX, Attribution attr) {
        return score(x, null, becX, null, attr);
    }

    /**
     * Full scoring pass with the observed mask and external BEC evidence.
     *
     * @param x          feature vector, length featureCount
     * @param observed   observed flags, or null to treat all as observed
     * @param becX       BEC-head subset, or null to skip the BEC head
     * @param becEvidence independent evidence probabilities for the Noisy-OR, or null
     * @param attr       attribution inputs, or null
     */
    public Score score(double[] x, boolean[] observed, double[] becX,
                       double[] becEvidence, Attribution attr) {
        Score s = new Score();
        s.logits = logits(x, observed);
        s.p = softmax(s.logits.z);
        if (becEvidence != null) {
            for (double p : becEvidence) {
                s.becEvidence.add(p);
            }
        }

        int best = 0;
        for (int k = 1; k < K; k++) {
            if (s.p[k] > s.p[best]) {
                best = k;
            }
        }
        s.argmax = best;
        s.argmaxClass = Config.Cls.of(best);
        s.modelVersion = version;
        s.weightsSource = source == null ? "unknown" : source.name();
        s.trainedOn = trainedOn;
        System.arraycopy(s.logits.intercept, 0, s.intercept, 0, K);

        s.risk = 100.0 * (1.0 - s.p[Config.CLASS_LEGITIMATE]);

        double pBec = 0.0;
        if (becX != null && g.length > 1) {
            if (becX.length != g.length - 1) {
                throw new IllegalArgumentException("BEC vector has " + becX.length
                        + " entries, expected " + (g.length - 1));
            }
            double acc = g[0];
            for (int i = 0; i < becX.length; i++) {
                acc += g[i + 1] * becX[i];
            }
            pBec = sigmoid(acc / Math.max(1e-6, temperature));
        }
        s.becClassProbability = s.p[Config.CLASS_BEC];
        s.becBaseProbability = pBec;
        s.becBlendWeight = Config.W_BEC;
        s.becScore = 100.0 * pBec;

        // Explicit, deterministic BEC blending. Two named quantities are kept apart and both
        // are reported, because conflating them is how a heuristic score gets presented as a
        // calibrated probability:
        //   becNoisyOr          - 1 - PRODUCT(1 - p_i) over caller-supplied EVIDENCE. A
        //                         saturating combination of independent hints. It is NOT a
        //                         probability the model was fitted to produce, and calling it
        //                         one would be a false precision claim.
        //   becBaseProbability  - the dedicated BEC head's output, before evidence blending.
        // becBlendedProbability is the explicit blend of the two and is the ONLY BEC value
        // that reaches riskFinal. The classifier's class distribution is never overwritten;
        // s.p stays exactly as softmax produced it, so it remains a valid distribution.
        s.becNoisyOr = noisyOr(becEvidence);
        s.becEvidenceBacked = becEvidence != null && becEvidence.length > 0;
        s.becBlendedProbability = 1.0
                - (1.0 - s.becBaseProbability) * (1.0 - s.becBlendWeight * s.becNoisyOr);
        s.becBlendMethod = s.becEvidenceBacked
                ? "1 - (1 - P_bec_head) * (1 - " + s.becBlendWeight + " * Noisy-OR evidence)"
                : "BEC head only (no external evidence supplied)";

        double pNotLegit = 1.0 - s.p[Config.CLASS_LEGITIMATE];
        // Uses the blended value, not the raw head. With no evidence supplied becNoisyOr is 0,
        // so becBlendedProbability == becBaseProbability and this reduces exactly to the
        // documented L186 formula; with evidence it is the blend the brief requires.
        s.riskFinal = 100.0 * (1.0
                - (1.0 - pNotLegit) * (1.0 - s.becBlendWeight * s.becBlendedProbability));

        // Normalised entropy over K classes, in [0,1]. SCORING-MODEL.md L264-266.
        double h = 0.0;
        for (double pk : s.p) {
            if (pk > 0.0) {
                h -= pk * Math.log(pk);
            }
        }
        double hNorm = h / Math.log(K);
        s.cModel = Math.pow(1.0 - hNorm, gamma);

        s.cAttr = attr == null ? 0.0 : attr.compute();

        s.band = s.riskFinal >= tauHigh ? Config.BAND_HIGH
                : s.riskFinal >= tauSuspicious ? Config.BAND_SUSPICIOUS
                : Config.BAND_LOW;

        applyAbstention(s);
        s.findings = explain(s, x);
        return s;
    }

    /**
     * The abstention gate. SCORING-MODEL.md L286-288 and the prompt's RULES clause, which
     * agree: C < 0.50 is UNDETERMINED with alerts and case creation OFF.
     *
     * A second, independent reason to abstain: an uncalibrated model. Reporting
     * weights_source honestly is what lets a reader know that a number from this engine is
     * advisory, so it gates automation as well as confidence.
     */
    private void applyAbstention(Score s) {
        if (s.cModel < Config.C_ABSTAIN) {
            s.verdict = Config.VERDICT_UNDETERMINED;
            s.alertEligible = false;
            s.caseCreationEnabled = false;
            s.abstentionReason = "C_model=" + fmt(s.cModel) + " < "
                    + fmt(Config.C_ABSTAIN) + "; no alert, no case";
            return;
        }
        if (s.cModel < Config.C_AUTOMATED) {
            s.verdict = Config.VERDICT_LOW_CONFIDENCE;
            s.alertEligible = false;
            s.caseCreationEnabled = false;
            s.abstentionReason = "C_model=" + fmt(s.cModel) + " in ["
                    + fmt(Config.C_ABSTAIN) + ", " + fmt(Config.C_AUTOMATED) + ")";
            return;
        }
        s.verdict = "DETERMINED";
        s.alertEligible = (source == Source.FITTED);
        s.caseCreationEnabled = (source == Source.FITTED);
        s.abstentionReason = (source == Source.FITTED)
                ? null
                : "weights_source=" + source.name() + "; scores are advisory only";
    }

    // ==================================================================
    // Step 8: explanation, from the same arithmetic as the score
    // ==================================================================

    public static final class Finding {
        public final int featureIndex;
        public final int family;
        public final double x;
        public final double beta;
        /** clip(beta*x, -c, +c), identical to the value summed into z. */
        public final double contribution;

        Finding(int featureIndex, int family, double x, double beta, double contribution) {
            this.featureIndex = featureIndex;
            this.family = family;
            this.x = x;
            this.beta = beta;
            this.contribution = contribution;
        }
    }

    /**
     * Ranks features by how much they moved the predicted class, using the SAME clipped terms
     * the forward pass summed. SCORING-MODEL.md L229-231.
     *
     * Reusing logits.terms rather than recomputing clip(beta*x) here is deliberate: a second
     * implementation of the clip is a second thing that can be wrong, and a finding that
     * quotes a different number than the one that produced the score is worse than no
     * finding at all.
     */
    public List<Finding> explain(Score s, double[] x) {
        int k = s.argmax;
        List<Finding> out = new ArrayList<>();
        for (int f = 0; f < featureCount; f++) {
            out.add(new Finding(f, familyOf(f), x[f], beta[k][f], s.logits.terms[k][f]));
        }
        out.sort((a, b) -> Double.compare(
                Math.abs(b.contribution), Math.abs(a.contribution)));
        return out;
    }

    private int familyOf(int featureIndex) {
        if (featureIndex < 0 || featureIndex >= featureCount) {
            throw new IllegalArgumentException("feature index out of range: " + featureIndex);
        }
        int per = featureCount / Config.FAMILY_NAMES.length;
        if (per == 0) {
            return 0;
        }
        int fam = featureIndex / per;
        return Math.min(fam, Config.FAMILY_NAMES.length - 1);
    }

    // ==================================================================
    // Attribution
    // ==================================================================

    /**
     * C_attr inputs. SCORING-MODEL.md L300-316.
     *
     * T traceability, S stability, A anonymity, X corroboration, each in [0,1]. Out-of-range
     * values are clamped rather than rejected: these come from enrichment adapters whose
     * inputs are partly attacker-influenced, and a clamp degrades the score instead of
     * failing the request.
     */
    public static final class Attribution {
        public double traceability = 0.5;
        public double stability = 0.5;
        public double anonymity = 0.5;
        public double corroboration = 0.5;

        double compute() {
            double t = clamp(traceability);
            double s = clamp(stability);
            double a = clamp(anonymity);
            double x = clamp(corroboration);
            double v = Math.pow(t, Config.C_ATTR_W_TRACEABILITY)
                    * Math.pow(s, Config.C_ATTR_W_STABILITY)
                    * Math.pow(1.0 - a, Config.C_ATTR_W_ANONYMITY)
                    * Math.pow(x, Config.C_ATTR_W_CORROBORATION);
            return Math.min(v, Config.C_ATTR_CAP);
        }

        private static double clamp(double d) {
            if (Double.isNaN(d)) {
                return 0.0;
            }
            return Math.max(0.0, Math.min(1.0, d));
        }

        /** Attribution label band. SCORING-MODEL.md L322-327. */
        public String band(double cAttr) {
            if (cAttr >= Config.C_ATTR_BAND_PROBABLE) {
                return "PROBABLE";
            }
            if (cAttr >= Config.C_ATTR_BAND_INDICATIVE) {
                return "INDICATIVE";
            }
            if (cAttr >= Config.C_ATTR_BAND_WEAK) {
                return "WEAK";
            }
            return "INSUFFICIENT";
        }
    }

    public static double sigmoid(double t) {
        if (t >= 0) {
            return 1.0 / (1.0 + Math.exp(-t));
        }
        double e = Math.exp(t);
        return e / (1.0 + e);
    }

    /** Format a double the way the report does, via the single canonical formatter. */
    public static String fmt(double d) {
        return Json.fmt(d);
    }

    private void requireFeatureLength(double[] x) {
        if (x == null) {
            throw new IllegalArgumentException("feature vector is null");
        }
        if (x.length != featureCount) {
            throw new IllegalArgumentException("feature vector has " + x.length
                    + " entries, expected " + featureCount);
        }
        for (int i = 0; i < x.length; i++) {
            if (Double.isNaN(x[i]) || Double.isInfinite(x[i])) {
                throw new IllegalArgumentException("feature " + i + " is not finite: " + x[i]);
            }
        }
    }

    // ==================================================================
    // Serialisation
    // ==================================================================

    /** Writes data/model.json. Shape fixed by ARCHITECTURE.md L216-217. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", version);
        List<Object> b = new ArrayList<>();
        for (double v : b0) {
            b.add(v);
        }
        m.put("b0", b);
        List<Object> rows = new ArrayList<>();
        for (int k = 0; k < K; k++) {
            List<Object> row = new ArrayList<>();
            for (double v : beta[k]) {
                row.add(v);
            }
            rows.add(row);
        }
        m.put("beta", rows);
        List<Object> gv = new ArrayList<>();
        for (double v : g) {
            gv.add(v);
        }
        m.put("g", gv);
        m.put("gamma", gamma);
        m.put("temperature", temperature);
        m.put("tau_high", tauHigh);
        m.put("tau_susp", tauSuspicious);
        m.put("tau_cluster", tauCluster);
        m.put("clip_c", Config.CLIP_C);
        m.put("w_bec", Config.W_BEC);
        m.put("feature_count", (double) featureCount);
        m.put("trained_on", trainedOn == null ? "unknown" : trainedOn);
        m.put("weights_source", source.name().toLowerCase(Locale.ROOT));
        m.put("disclaimer", Config.DISCLAIMER);
        m.put("metrics", new LinkedHashMap<>(metrics));
        return m;
    }

    /**
     * Reads data/model.json.
     *
     * Returns null when the file does not exist, so the caller can decide. Per
     * ARCHITECTURE.md L269 the ENGINE refuses rather than scoring; returning null lets it
     * produce the MODEL_MISSING log line instead of throwing here, where the message would
     * have no context. See docs/PHASE1-NOTES.md C-08.
     */
    public static Model fromMap(Map<String, Object> m) {
        if (m == null) {
            return null;
        }
        double[] b0 = Json.doubles(Json.arr(m, "b0"), "b0");
        List<Object> betaRows = Json.arr(m, "beta");
        if (betaRows.size() != K) {
            throw new IllegalArgumentException("model.beta has " + betaRows.size()
                    + " rows, expected " + K);
        }
        int fc = betaRows.isEmpty() ? 0
                : Json.doubles((List<Object>) betaRows.get(0), "beta[0]").length;
        double[][] beta = new double[K][];
        for (int k = 0; k < K; k++) {
            beta[k] = Json.doubles((List<Object>) betaRows.get(k), "beta[" + k + "]");
        }
        double[] g = Json.doubles(Json.arr(m, "g"), "g");
        Map<String, Object> metrics = m.containsKey("metrics")
                ? Json.obj(m, "metrics") : Map.of();

        // weights_source is a STRING ("hand_set_uncalibrated" / "fitted"), so Json.num()
        // would throw "not a number" on every well-formed model file. Read it as a string.
        // An unrecognised value is a configuration error, not a silent default: pretending a
        // mislabelled model is hand-set would hide exactly the disclosure the field exists for.
        String src = optStr(m, "weights_source");
        if (src == null) {
            throw new IllegalArgumentException(
                    "model is missing required string field 'weights_source'");
        }
        Source source = switch (src) {
            case "hand_set_uncalibrated" -> Source.HAND_SET_UNCALIBRATED;
            case "fitted" -> Source.FITTED;
            default -> throw new IllegalArgumentException(
                    "unknown weights_source '" + src + "'; expected 'fitted' or "
                    + "'hand_set_uncalibrated'");
        };

        return new Model(b0, beta, g, fc,
                Json.num(m, "tau_high", Config.TAU_HIGH_FALLBACK),
                Json.num(m, "tau_susp", Config.TAU_SUSPICIOUS_FALLBACK),
                Json.num(m, "tau_cluster", Config.TAU_CLUSTER),
                Json.num(m, "temperature", 1.0),
                Json.num(m, "gamma", Config.GAMMA),
                optStr(m, "version") == null ? "unversioned" : optStr(m, "version"),
                source,
                optStr(m, "trained_on"),
                metrics);
    }

    private static String optStr(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof String ? (String) v : null;
    }

    /**
     * The deterministic baseline configuration: hand-set priors, expanded to the real
     * feature dimensionality.
     *
     * Config.INITIAL_BETA_BY_FAMILY is authored per FAMILY (6 columns), but Features emits one
     * dimension per named sub-feature (60). The baseline therefore expands each family weight
     * across that family's members, scaled by 1/size, so a family's total possible
     * contribution is the authored weight rather than size times the weight. Without the
     * 1/size scale, PAYLOAD's twelve members at 1.9 each would contribute up to 22.8 and
     * swamp every other signal.
     *
     * THESE ARE NOT TRAINED WEIGHTS. They are hand-set priors chosen to be directionally
     * sensible (auth failures lean phishing; archive attachments lean malware), and nothing
     * more. Scores from this model are advisory, it reports Source.HAND_SET_UNCALIBRATED,
     * automation is gated off by that flag, and no accuracy figure is claimed for it. The
     * coefficient source is a separate method so that a fitted model replaces this wholesale
     * without touching any scoring code.
     */
    public static Model initial() {
        int f = Features.COUNT;
        double[][] byFamily = Config.INITIAL_BETA_BY_FAMILY;
        double[][] beta = new double[K][];
        for (int k = 0; k < K; k++) {
            beta[k] = new double[f];
            for (int i = 0; i < f; i++) {
                beta[k][i] = byFamily[k][Features.familyOf(i).ordinal()]
                        / Features.familySize(i);
            }
        }
        return new Model(Config.INITIAL_B0, beta, Config.INITIAL_G, f,
                Config.TAU_HIGH_FALLBACK, Config.TAU_SUSPICIOUS_FALLBACK, Config.TAU_CLUSTER,
                1.0, Config.GAMMA, "hand-set-initial/" + f + "f",
                Source.HAND_SET_UNCALIBRATED, "none", Map.of());
    }

    /** Standalone self-check: java Model */
    public static void main(String[] args) {
        Model m = initial();
        // The baseline model now has all 60 real features, so the probe vector is built at the
        // model's own width. A hand-written 6-element literal would throw at requireFeatureLength.
        double[] x = new double[m.featureCount];
        for (int i = 0; i < x.length; i++) {
            x[i] = 0.10 * (i % 10);
        }
        double[] bec = new double[Config.BEC_SUBSET.length];
        Attribution attr = new Attribution();
        Score s = m.score(x, bec, attr);
        System.out.println("features=" + m.featureCount + " classes=" + K);
        System.out.println("argmax=" + s.argmaxClass.label()
                + " (index " + s.argmax + ")");
        System.out.println("model=" + s.modelVersion + " source=" + s.weightsSource
                + " trained_on=" + s.trainedOn);
        System.out.println("unobserved=" + s.logits.unobservedCount
                + " clipped_terms=" + s.logits.clippedTerms);
        System.out.println("risk=" + fmt(s.risk) + " risk_final=" + fmt(s.riskFinal)
                + " bec=" + fmt(s.becScore));
        System.out.println("bec_head=" + fmt(s.becBaseProbability)
                + " bec_class=" + fmt(s.becClassProbability)
                + " bec_blend=" + fmt(s.becBlendedProbability)
                + " method=" + s.becBlendMethod);

        // Evidence must be visible in the output, not folded in silently.
        Score withEvidence = m.score(x, null, bec, new double[]{0.9, 0.6}, attr);
        System.out.println("with evidence: bec_noisy_or=" + fmt(withEvidence.becNoisyOr)
                + " bec_blend=" + fmt(withEvidence.becBlendedProbability)
                + " risk_final=" + fmt(withEvidence.riskFinal));

        System.out.println("C_model=" + fmt(s.cModel) + " C_attr=" + fmt(s.cAttr)
                + " band=" + attr.band(s.cAttr));
        System.out.println("verdict=" + s.verdict + " alerts=" + s.alertEligible);
        double sum = 0;
        for (double p : s.p) {
            sum += p;
        }
        System.out.println("sum(p)=" + fmt(sum - 1.0) + " (delta from 1)");
        // Overflow probe: naive exp() would produce NaN here.
        double[] hot = new double[8];
        java.util.Arrays.fill(hot, 1e4);
        double[] sp = softmax(hot);
        double hotSum = 0;
        for (double p : sp) {
            hotSum += p;
        }
        System.out.println("sum(softmax(1e4))=" + fmt(hotSum - 1.0) + " anyNaN="
                + java.util.Arrays.stream(sp).anyMatch(Double::isNaN));
    }
}
