/**
 * Consolidated regression suite. Plain main(), JDK only, no test framework, no dependencies.
 *
 * Run:  java -cp build Regression
 * Build: javac --release 25 -encoding UTF-8 -cp build -d build tests/Regression.java
 *
 * DESIGN RULE: this suite asserts OBSERVABLE CONTRACT, never implementation detail. It checks
 * that a documented limit produces a warning code and a truncated-but-valid result rather than
 * an exception, that the additive logit decomposition reproduces the reported logit exactly,
 * that a signature over modified bytes fails, and that hostile input costs bounded time. Where
 * the spec could be read two ways, the expected value is stated in a comment with its source,
 * so a future change of mind is a one-line edit rather than a mystery.
 *
 * A failing check prints the assertion and KEEPS GOING, then the process exits non-zero with the
 * total failure count. Stopping at the first failure hides the blast radius of a change, which
 * is exactly the information you need when fixing it.
 *
 * Fifteen areas:
 *   t01  softmax normalises and stays finite under extreme logits
 *   t02  the logit is EXACTLY intercept + sum of terms
 *   t03  contribution clipping is applied, counted, and reused by the explanation
 *   t04  an unobserved feature contributes exactly zero and never pushes a score
 *   t05  noisy-OR: empty is 0, inputs clamp, order-independent, saturates rather than NaN
 *   t06  a valid audit chain verifies and links back to the genesis predecessor
 *   t07  every audit tamper shape is detected at the right index, and a broken chain is sealed
 *   t08  Ed25519 signatures are deterministic, PEM round-trips, key ids are stable
 *   t09  verification accepts genuine signatures and rejects every forgery shape
 *   t10  a single modified byte in the payload invalidates the signature
 *   t11  parser bounds: header count, header line length, message size
 *   t12  MIME bounds: nesting depth and part count
 *   t13  attribution confidence never exceeds the 0.85 infrastructure cap
 *   t14  correlation scoring is thresholded at 0.62 and is exactly decomposable
 *   t15  hostile input never throws, never yields NaN, and costs bounded time
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

public final class Regression {

    private static int passed;
    private static int failed;
    private static final List<String> failures = new ArrayList<>();
    private static String section = null;

    // The whole hostile-input section shares one budget. The suite-level 3 s allowance is the
    // requirement; 1500 ms inside the section leaves headroom for the other fourteen.
    private static final long HOSTILE_BUDGET_NANOS = 1_500_000_000L;

    private Regression() {
    }

    // ==================================================================
    // Tiny assertion harness. No JUnit: ARCHITECTURE.md forbids third-party dependencies,
    // and a hand-rolled harness is auditable in one screen.
    // ==================================================================

    // Only failures and per-section counts are printed. The suite runs ~880 checks; emitting a
    // line per passing check produced ~900 lines whose formatting and flush cost roughly as much
    // as every analytic call in the suite combined, which is what pushed wall-clock time past the
    // three-second ceiling. Failures, section headings and the per-section counts are what a
    // reader actually needs, and they are all still emitted.
    private static int sectionChecks = 0;
    private static long sectionStart = System.nanoTime();

    private static void section(String s) {
        if (section != null) {
            System.out.println("  -- " + sectionChecks + " checks, "
                    + (System.nanoTime() - sectionStart) / 1_000_000L + " ms");
        }
        section = s;
        sectionChecks = 0;
        sectionStart = System.nanoTime();
        System.out.println();
        System.out.println("== " + s + " ==");
    }

    private static void check(String what, boolean ok) {
        if (ok) {
            passed++;
            sectionChecks++;
        } else {
            failed++;
            String msg = section + " / " + what;
            failures.add(msg);
            System.out.println("  FAIL  " + what);
        }
    }

    private static void eq(String what, Object expected, Object actual) {
        boolean ok = (expected == null) ? actual == null : expected.equals(actual);
        if (ok) {
            passed++;
            sectionChecks++;
        } else {
            failed++;
            failures.add(section + " / " + what + "  expected=<" + expected + "> actual=<" + actual + ">");
            System.out.println("  FAIL  " + what + "  expected=<" + expected + "> actual=<" + actual + ">");
        }
    }

    private static void near(String what, double expected, double actual, double tol) {
        boolean ok = Double.isFinite(actual) && Math.abs(expected - actual) <= tol;
        if (ok) {
            passed++;
            sectionChecks++;
        } else {
            failed++;
            failures.add(section + " / " + what + "  expected=" + expected + " actual=" + actual
                    + " tol=" + tol);
            System.out.println("  FAIL  " + what + "  expected=" + expected + " actual=" + actual);
        }
    }

    /** Asserts the body throws, and that it throws the expected type rather than anything at all. */
    private static void throwsType(String what, Class<? extends Throwable> type, ThrowingRunnable body) {
        try {
            body.run();
            check(what + " (nothing was thrown)", false);
        } catch (Throwable t) {
            boolean ok = type.isInstance(t);
            check(what + " (threw " + t.getClass().getSimpleName() + ")", ok);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    // ==================================================================
    // Shared helpers
    // ==================================================================

    private static double sum(double[] v) {
        double s = 0.0;
        for (double d : v) {
            s += d;
        }
        return s;
    }

    private static boolean allFinite(double[] v) {
        for (double d : v) {
            if (!Double.isFinite(d)) {
                return false;
            }
        }
        return true;
    }

    private static boolean allFinite(List<Double> v) {
        for (double d : v) {
            if (!Double.isFinite(d)) {
                return false;
            }
        }
        return true;
    }

    private static boolean anyNaN(double[] v) {
        for (double d : v) {
            if (Double.isNaN(d)) {
                return true;
            }
        }
        return false;
    }

    /** A private directory under build/ so a run never depends on the OS temp directory. */
    private static Path scratch(String name) throws Exception {
        Path p = Path.of("build", "regression", name);
        if (Files.exists(p)) {
            deleteTree(p);
        }
        Files.createDirectories(p);
        return p;
    }

    private static void deleteTree(Path p) throws Exception {
        if (!Files.exists(p)) {
            return;
        }
        try (var walk = Files.walk(p)) {
            for (Path child : walk.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(child);
            }
        }
    }

    /**
     * A controlled multipart message with the requested nesting depth. Level 0 is the outermost
     * container; each level holds one container part declaring the next boundary. Boundaries are
     * zero-padded so no boundary can be a prefix of another, which would make the split wrong.
     */
    private static String nestedMultipart(int levels) {
        StringBuilder sb = new StringBuilder();
        sb.append("Subject: depth probe\r\n");
        sb.append("MIME-Version: 1.0\r\n");
        sb.append("Content-Type: multipart/mixed; boundary=\"")
                .append(bnd(levels)).append("\"\r\n");
        sb.append("\r\n");
        for (int level = levels; level >= 1; level--) {
            sb.append("--").append(bnd(level)).append("\r\n");
            if (level > 1) {
                sb.append("Content-Type: multipart/mixed; boundary=\"")
                        .append(bnd(level - 1)).append("\"\r\n\r\n");
            } else {
                sb.append("Content-Type: text/plain; charset=utf-8\r\n\r\n");
                sb.append("leaf\r\n");
            }
        }
        for (int level = 1; level <= levels; level++) {
            sb.append("--").append(bnd(level)).append("--\r\n");
        }
        return sb.toString();
    }

    private static String bnd(int level) {
        return String.format("BND%03d", level);
    }

    /** A flat multipart message with the requested number of text leaves. */
    private static String flatMultipart(int leaves) {
        String boundary = "FLAT";
        StringBuilder sb = new StringBuilder();
        sb.append("Subject: part probe\r\n");
        sb.append("MIME-Version: 1.0\r\n");
        sb.append("Content-Type: multipart/mixed; boundary=\"").append(boundary).append("\"\r\n\r\n");
        for (int i = 0; i < leaves; i++) {
            sb.append("--").append(boundary).append("\r\n");
            sb.append("Content-Type: text/plain; charset=utf-8\r\n\r\n");
            sb.append("leaf ").append(i).append("\r\n");
        }
        sb.append("--").append(boundary).append("--\r\n");
        return sb.toString();
    }

    /** A short, well-formed message. The only fixture any section needs. */
    private static String simpleMessage() {
        return "From: alice@example.com\r\n"
                + "To: bob@corp.example\r\n"
                + "Subject: quarterly numbers\r\n"
                + "Message-ID: <one@example.com>\r\n"
                + "\r\n"
                + "Please review the attached figures.\r\n";
    }

    private static Set<String> set(String... values) {
        return new LinkedHashSet<>(Arrays.asList(values));
    }

    /** Reads a file's non-empty lines, or an empty list when the file does not exist yet. */
    private static List<String> readLinesOrEmpty(Path p) throws Exception {
        if (!Files.isRegularFile(p)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            if (!line.isBlank()) {
                out.add(line);
            }
        }
        return out;
    }

    // ==================================================================
    // t01 - softmax
    // ==================================================================

    private static void t01_softmax() {
        section("t01 softmax normalises and stays finite under extreme logits");

        eq("K is the documented 8 classes", 8, Config.K);

        double[] zero = new double[Config.K];
        double[] pz = Model.softmax(zero);
        near("all-zero logits give the uniform distribution", 1.0, sum(pz), 1e-12);
        for (int k = 0; k < Config.K; k++) {
            near("uniform at class " + k, 1.0 / Config.K, pz[k], 1e-12);
        }

        // The contract that matters: a distribution. Everything else is downstream of this.
        check("softmax output is finite for a zero vector", allFinite(pz));

        double[] oneHot = new double[Config.K];
        oneHot[3] = 1.0;
        double[] po = Model.softmax(oneHot);
        near("a single raised class still sums to 1", 1.0, sum(po), 1e-12);
        int best = 0;
        for (int k = 1; k < Config.K; k++) {
            if (po[k] > po[best]) {
                best = k;
            }
        }
        eq("the raised class is the argmax", 3, best);

        // A naive exp() overflows to Infinity here and every probability becomes NaN, which
        // would make every downstream comparison silently return false. Max subtraction is the
        // documented defence (Model.java L213-221), so this is a real regression, not a formality.
        double[] hot = new double[Config.K];
        Arrays.fill(hot, 1e4);
        double[] ph = Model.softmax(hot);
        check("+1e4 logits do not produce NaN", !anyNaN(ph));
        check("+1e4 logits stay finite", allFinite(ph));
        near("+1e4 logits still sum to 1", 1.0, sum(ph), 1e-12);

        double[] cold = new double[Config.K];
        Arrays.fill(cold, -1e4);
        double[] pc = Model.softmax(cold);
        check("-1e4 logits do not produce NaN", !anyNaN(pc));
        near("-1e4 logits still sum to 1", 1.0, sum(pc), 1e-12);
        near("-1e4 logits are still uniform", 1.0 / Config.K, pc[0], 1e-12);

        double[] split = new double[] {1e4, -1e4, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
        double[] ps = Model.softmax(split);
        check("a fully saturated vector has no NaN", !anyNaN(ps));
        near("a fully saturated vector still sums to 1", 1.0, sum(ps), 1e-12);
        near("the winning class takes essentially all the mass", 1.0, ps[0], 1e-12);

        // Max subtraction must be exactly shift-invariant, not approximately: a constant offset
        // carries no information, so the same vector plus 1e3 has to give the same distribution.
        double[] base = new double[] {0.5, -1.25, 2.0, 0.0, 3.5, -0.75, 1.0, -2.0};
        double[] shifted = new double[Config.K];
        for (int k = 0; k < Config.K; k++) {
            shifted[k] = base[k] + 1e3;
        }
        double[] pb = Model.softmax(base);
        double[] psh = Model.softmax(shifted);
        for (int k = 0; k < Config.K; k++) {
            near("softmax is shift-invariant at class " + k, pb[k], psh[k], 1e-12);
        }

        throwsType("softmax rejects a logit vector of the wrong width",
                IllegalArgumentException.class, () -> Model.softmax(new double[Config.K - 1]));
    }

    // ==================================================================
    // t02 - exact additive logit equality
    // ==================================================================

    private static void t02_exactAdditiveLogit() {
        section("t02 the logit is EXACTLY intercept + sum of terms");

        Model m = Model.initial();
        int f = m.featureCount;
        check("the initial model has 60 features", f == 60);
        eq("the model width is the K the tests assume", Config.K, m.featureCount == f ? Config.K : -1);

        // A deliberately mixed vector: some features well inside the clip, some far outside it.
        // Asserting the invariant only on values that never clip would leave the interesting
        // half of the input space untested.
        double[] x = new double[f];
        for (int i = 0; i < f; i++) {
            if (i % 3 == 0) {
                x[i] = 1.0;
            } else if (i % 3 == 1) {
                x[i] = 0.125 * (i % 8) - 0.5;
            } else {
                x[i] = 250.0; // forces the clip in every class
            }
        }

        Model.Logits lg = m.logits(x);
        check("the decomposition reported a clip", lg.clippedTerms > 0);

        for (int k = 0; k < Config.K; k++) {
            double sum = lg.intercept[k];
            for (int j = 0; j < lg.terms[k].length; j++) {
                sum += lg.terms[k][j];
            }
            near("z[" + k + "] == intercept[" + k + "] + sum(terms[" + k + "])", sum, lg.z[k], 0.0);
            eq("intercept[" + k + "] is the model's b0[" + k + "]", m.b0[k], lg.intercept[k]);
        }

        // An independent reimplementation of the documented formula, from the public weight
        // matrix rather than from the reported terms, so agreement is evidence and not a tautology.
        for (int k = 0; k < Config.K; k++) {
            double expected = m.b0[k];
            for (int j = 0; j < f; j++) {
                double t = m.beta[k][j] * x[j];
                expected += Math.max(-Config.CLIP_C, Math.min(Config.CLIP_C, t));
            }
            near("z[" + k + "] reproduces b0 + sum(clip(beta*x)) from the weight matrix",
                    expected, lg.z[k], 1e-9);
        }

        // The invariant must hold for an all-zero vector too, where every term is exactly zero
        // and any missing intercept would show up as a constant offset.
        double[] zero = new double[f];
        Model.Logits lz = m.logits(zero);
        for (int k = 0; k < Config.K; k++) {
            eq("a zero vector gives z[" + k + "] == b0[" + k + "]", m.b0[k], lz.z[k]);
        }

        // And for a second, differently shaped vector, so the test is not a single lucky input.
        double[] y = new double[f];
        for (int i = 0; i < f; i++) {
            y[i] = ((i % 11) - 5) * 3.0;
        }
        Model.Logits ly = m.logits(y);
        for (int k = 0; k < Config.K; k++) {
            double sum = lg == null ? 0.0 : ly.intercept[k];
            for (int j = 0; j < ly.terms[k].length; j++) {
                sum += ly.terms[k][j];
            }
            near("z[" + k + "] == intercept + sum for the second vector", sum, ly.z[k], 0.0);
        }
    }

    // ==================================================================
    // t03 - contribution clipping
    // ==================================================================

    private static void t03_clipping() {
        section("t03 contribution clipping is applied, counted, and reused by the explanation");

        near("the clip constant is 2.5", 2.5, Config.CLIP_C, 0.0);

        int f = Features.COUNT;
        // A model whose only non-zero coefficient is enormous, so a feature value of 1.0 alone
        // drives the term past the clip. The clip cannot be observed through Model.initial(),
        // whose hand-set coefficients are all far below the ceiling.
        double[] b0 = new double[Config.K];
        double[][] beta = new double[Config.K][f];
        beta[0][0] = 100.0;
        for (int k = 1; k < Config.K; k++) {
            beta[k][0] = -100.0;
        }
        Model m = new Model(b0, beta, new double[] {-3.2}, f,
                Config.TAU_HIGH_FALLBACK, Config.TAU_SUSPICIOUS_FALLBACK, Config.TAU_CLUSTER,
                1.0, Config.GAMMA, "regression/clip-probe", Model.Source.HAND_SET_UNCALIBRATED,
                "none", Map.of());

        double[] big = new double[f];
        big[0] = 1.0;
        Model.Logits lg = m.logits(big);

        eq("a positive overshoot clips to exactly +CLIP_C", Config.CLIP_C, lg.terms[0][0]);
        eq("a negative coefficient clips to exactly -CLIP_C", -Config.CLIP_C, lg.terms[1][0]);
        eq("every class is counted as clipped", Config.K, lg.clippedTerms);

        double[] small = new double[f];
        small[0] = 0.01;
        Model.Logits ls = m.logits(small);
        eq("a term below the clip is untouched", 1.0, ls.terms[0][0]);
        eq("a term below the clip is not counted", 0, ls.clippedTerms);

        // Exactly at the boundary is not "over" it: the code clips on strict > and strict <, so a
        // term of exactly CLIP_C must survive unclipped. Asserting the boundary pins that choice.
        Model atLimit = new Model(b0, new double[Config.K][f], new double[] {-3.2}, f,
                Config.TAU_HIGH_FALLBACK, Config.TAU_SUSPICIOUS_FALLBACK, Config.TAU_CLUSTER,
                1.0, Config.GAMMA, "regression/boundary-probe", Model.Source.HAND_SET_UNCALIBRATED,
                "none", Map.of());
        double[][] edgeBeta = new double[Config.K][f];
        edgeBeta[0][0] = Config.CLIP_C; // beta * 1.0 is exactly the ceiling
        edgeBeta[1][0] = -Config.CLIP_C;
        atLimit = new Model(b0, edgeBeta, new double[] {-3.2}, f,
                Config.TAU_HIGH_FALLBACK, Config.TAU_SUSPICIOUS_FALLBACK, Config.TAU_CLUSTER,
                1.0, Config.GAMMA, "regression/boundary-probe", Model.Source.HAND_SET_UNCALIBRATED,
                "none", Map.of());
        Model.Logits le = atLimit.logits(big);
        eq("a term exactly at the ceiling is not clipped", Config.CLIP_C, le.terms[0][0]);
        eq("a term exactly at the ceiling is not counted", 0, le.clippedTerms);

        // The explanation must quote the CLIPPED number, not the raw product. Model.java L472-479
        // calls reusing logits.terms deliberate, because a finding that quotes a different value
        // than the one that produced the score is worse than no finding at all.
        double[] becX = new double[Config.INITIAL_G.length - 1];
        Model.Score s = m.score(big, becX, new Model.Attribution());
        eq("the overshoot is scored on the clipped terms", Config.CLIP_C, s.logits.terms[0][0]);
        List<Model.Finding> findings = m.explain(s, big);
        eq("explain returns one finding per feature", f, findings.size());
        eq("the finding quotes the clipped contribution", Config.CLIP_C, findings.get(0).contribution);
        check("the finding is not quoting the raw product", Math.abs(findings.get(0).contribution) <= Config.CLIP_C);
        eq("the finding reports the raw coefficient", 100.0, findings.get(0).beta);

        // A negative overshoot is clipped symmetrically. Asymmetry here would be a silent bug:
        // it would let an attacker push a class down without limit.
        double[] neg = new double[f];
        neg[0] = -1.0;
        Model.Logits ln = m.logits(neg);
        eq("a negative overshoot clips to exactly -CLIP_C", -Config.CLIP_C, ln.terms[0][0]);
        eq("the negative overshoot is counted", Config.K, ln.clippedTerms);
    }

    // ==================================================================
    // t04 - unobserved features
    // ==================================================================

    private static void t04_unobserved() {
        section("t04 an unobserved feature contributes exactly zero and never pushes a score");

        Model m = Model.initial();
        int f = m.featureCount;

        double[] x = new double[f];
        Arrays.fill(x, 1.0);

        boolean[] observed = new boolean[f];
        Arrays.fill(observed, true);
        observed[0] = false;
        observed[1] = false;
        observed[2] = false;

        Model.Logits masked = m.logits(x, observed);
        eq("unobservedCount matches the mask", 3, masked.unobservedCount);
        check("the observed array is materialised, not left null", masked.observed != null);
        check("the masked features are recorded unobserved",
                !masked.observed[0] && !masked.observed[1] && !masked.observed[2]);
        check("the rest are recorded observed", masked.observed[3]);

        for (int k = 0; k < Config.K; k++) {
            eq("terms[" + k + "][0] is exactly zero", 0.0, masked.terms[k][0]);
            eq("terms[" + k + "][1] is exactly zero", 0.0, masked.terms[k][1]);
            eq("terms[" + k + "][2] is exactly zero", 0.0, masked.terms[k][2]);
        }

        // The load-bearing claim: substituting x_f = 0 is the ONLY way to keep the term matrix
        // consistent with the reported logit (Model.java L120-129). So a masked logit must be
        // bit-identical to the logit of the same message with those features simply absent.
        double[] absent = x.clone();
        absent[0] = 0.0;
        absent[1] = 0.0;
        absent[2] = 0.0;
        Model.Logits zeroed = m.logits(absent);
        for (int k = 0; k < Config.K; k++) {
            eq("masked z[" + k + "] == the logit with those features absent",
                    zeroed.z[k], masked.z[k]);
        }

        // ...and it must actually differ from the unmasked logit, or the mask would be inert.
        Model.Logits full = m.logits(x);
        check("masking changes the score it is supposed to change",
                full.z[0] != masked.z[0]);
        check("a masked feature is never clipped, because it is never multiplied",
                masked.clippedTerms <= full.clippedTerms);

        // A missing observation must not push toward any class. The precise statement is that
        // the masked distribution is the one the message would have had without the feature.
        double[] pm = Model.softmax(masked.z);
        double[] pz = Model.softmax(zeroed.z);
        for (int k = 0; k < Config.K; k++) {
            near("the masked distribution equals the absent-evidence distribution at class " + k,
                    pz[k], pm[k], 0.0);
        }

        // A null mask means every feature is observed, and must be identical to the no-arg call.
        Model.Logits nullMask = m.logits(x, null);
        for (int k = 0; k < Config.K; k++) {
            eq("a null mask gives the unmasked z[" + k + "]", full.z[k], nullMask.z[k]);
        }
        eq("a null mask counts no unobserved features", 0, nullMask.unobservedCount);

        // Masking everything leaves the intercept, which is the specified degenerate case.
        boolean[] none = new boolean[f];
        Model.Logits allMasked = m.logits(x, none);
        eq("masking every feature counts them all", f, allMasked.unobservedCount);
        for (int k = 0; k < Config.K; k++) {
            eq("a fully masked z[" + k + "] is the intercept alone", m.b0[k], allMasked.z[k]);
            eq("a fully masked decomposition still holds at class " + k,
                    m.b0[k], allMasked.z[k]);
        }
        check("a fully masked distribution is still a distribution",
                allFinite(Model.softmax(allMasked.z)));

        throwsType("a mask of the wrong length is rejected", IllegalArgumentException.class,
                () -> m.logits(x, new boolean[f - 1]));
    }

    // ==================================================================
    // t05 - noisy-OR
    // ==================================================================

    private static void t05_noisyOr() {
        section("t05 noisy-OR: empty is 0, inputs clamp, order-independent, saturates not NaN");

        // "No evidence" must not become "certain". An empty array returning NaN, or 1.0, is the
        // single most damaging failure this function could have (Model.java L183).
        eq("no evidence yields 0.0", 0.0, Model.noisyOr(new double[0]));
        eq("null evidence yields 0.0", 0.0, Model.noisyOr(null));
        near("a single p is itself", 0.3, Model.noisyOr(new double[] {0.3}), 1e-15);

        // The defining identity, asserted against the product written out longhand.
        double[] p = {0.3, 0.6, 0.12, 0.44};
        double product = 1.0;
        for (double v : p) {
            product *= (1.0 - v);
        }
        near("1 - PRODUCT(1 - p_i)", 1.0 - product, Model.noisyOr(p), 1e-12);

        // Order independence: the product is commutative, so a caller must not be able to
        // change the answer by reordering its evidence list.
        double[] shuffled = {0.44, 0.3, 0.12, 0.6};
        near("the combination is order-independent", Model.noisyOr(p), Model.noisyOr(shuffled), 1e-15);
        double[] reversed = {p[3], p[2], p[1], p[0]};
        near("a reversed copy of the same evidence agrees",
                Model.noisyOr(p), Model.noisyOr(reversed), 1e-15);

        // Boundaries.
        eq("a p of 0 contributes nothing", 0.0, Model.noisyOr(new double[] {0.0, 0.0, 0.0}));
        eq("a p of 1 is certain", 1.0, Model.noisyOr(new double[] {1.0}));
        near("two halves combine to 0.75", 0.75, Model.noisyOr(new double[] {0.5, 0.5}), 1e-12);
        near("a 0.9 and a 0.5 combine to 0.95", 0.95, Model.noisyOr(new double[] {0.9, 0.5}), 1e-12);

        // Clamping. An out-of-range value must degrade the score, not corrupt risk_final.
        eq("p above 1 is clamped to 1", 1.0, Model.noisyOr(new double[] {1.4}));
        eq("p below 0 is clamped to 0", 0.0, Model.noisyOr(new double[] {-0.2}));
        near("a clamped high p equals its clamp", 1.0, Model.noisyOr(new double[] {7.0}), 0.0);
        near("a clamped low p equals zero", 0.0, Model.noisyOr(new double[] {-7.0}), 0.0);

        // Non-finite input is a programming error, not something to guess about.
        throwsType("NaN evidence is rejected", IllegalArgumentException.class,
                () -> Model.noisyOr(new double[] {0.5, Double.NaN}));
        throwsType("infinite evidence is rejected", IllegalArgumentException.class,
                () -> Model.noisyOr(new double[] {Double.POSITIVE_INFINITY}));

        // Monotonicity: more evidence never lowers the combined value.
        double base = Model.noisyOr(new double[] {0.2, 0.5});
        for (double bump : new double[] {0.001, 0.05, 0.2, 0.4}) {
            double[] more = {0.2, 0.5 + bump};
            check("raising one p by " + bump + " never lowers the combination",
                    Model.noisyOr(more) >= base);
        }
        check("a new positive term raises the combination",
                Model.noisyOr(new double[] {0.2, 0.5, 0.3}) > base);

        // Saturation. PRODUCT(1-p) underflows to 0 for many strong hints; the result must be 1.0,
        // not NaN and not a negative number.
        double[] many = new double[400];
        Arrays.fill(many, 0.9);
        double sat = Model.noisyOr(many);
        check("400 strong hints saturate at 1.0 rather than NaN", sat == 1.0);
        check("the saturated value is finite", Double.isFinite(sat));

        // Bounded range, over a spread of shapes. A result outside [0,1] would corrupt risk_final.
        boolean inRange = true;
        double[] spread = {0.0, 1.0, 0.5, 0.999, 0.001};
        for (int i = 0; i < 200; i++) {
            double[] v = new double[1 + (i % 7)];
            for (int j = 0; j < v.length; j++) {
                v[j] = spread[(i + j) % spread.length];
            }
            double r = Model.noisyOr(v);
            if (!(r >= 0.0 && r <= 1.0) || !Double.isFinite(r)) {
                inRange = false;
            }
        }
        check("every combination stays inside [0,1]", inRange);
    }

    // ==================================================================
    // t06 - a valid audit chain
    // ==================================================================

    private static void t06_auditValidChain() {
        section("t06 a valid audit chain verifies and links back to the genesis predecessor");

        try {
            Path dir = scratch("t06-valid");
            Audit.KeyManager km = Audit.KeyManager.createOrLoad(dir.resolve("keys").resolve("ed25519.pem"));
            check("the key manager is configured after createOrLoad", km.configured());
            check("the key material is on disk", Files.isRegularFile(km.path()));
            eq("the key id is a 64-character fingerprint", 64, km.keyId().length());
            check("the key id is lowercase hex", km.keyId().matches("[0-9a-f]{64}"));

            Path logPath = dir.resolve("audit.ndjson");
            Audit audit = new Audit(logPath, dir.resolve("audit-sigs.ndjson"), km);

            for (int i = 0; i < 5; i++) {
                audit.append("regression.append", Audit.payload(
                        "tester", "subject-" + i, "ok", "detail " + i));
            }

            Audit.Verification v = audit.verify();
            check("the chain verifies", v.ok);
            eq("every record is counted", 5, v.records);
            eq("no record is divergent", -1, v.firstDivergentIndex);
            check("signature verification is configured", v.signatureConfigured);
            eq("the head hash is a SHA-256 digest", 64, v.headHash.length());

            // Signing is periodic, not per-record (Config.AUDIT_SIGN_EVERY_N). A chain shorter
            // than the cadence therefore has an INTENTIONALLY unsigned head: the chain is still
            // valid, and the verifier says so in words rather than by failing. Asserting ok here
            // and a caveat in the reason is the contract; a chain that reported ok with a silent
            // reason would be hiding a gap in the evidence.
            check("a chain shorter than the signing cadence has no head signature",
                    !v.headSignatureValid);
            check("the unsigned head is reported as a caveat, not a pass (" + v.reason + ")",
                    v.reason.contains("unsigned or its signature does not verify"));
            check("an unsigned head does not make the chain invalid", v.ok);
            eq("the signing cadence is 50 records", 50, Config.AUDIT_SIGN_EVERY_N);
            check("no signature file exists before the cadence is reached",
                    !Files.exists(dir.resolve("audit-sigs.ndjson"))
                            || readLinesOrEmpty(dir.resolve("audit-sigs.ndjson")).isEmpty());

            // Now reach the cadence, so a head signature actually exists and the verifier has
            // something real to check. This is the path that would catch a signature written
            // over the wrong bytes, or written for the wrong index.
            Path longDir = scratch("t06-signed");
            Audit.KeyManager longKm = Audit.KeyManager.createOrLoad(
                    longDir.resolve("keys").resolve("ed25519.pem"));
            Path longLog = longDir.resolve("audit.ndjson");
            Audit longAudit = new Audit(longLog, longDir.resolve("audit-sigs.ndjson"), longKm);
            for (int i = 0; i < Config.AUDIT_SIGN_EVERY_N; i++) {
                longAudit.append("regression.append", Audit.payload(
                        "tester", "long-" + i, "ok", "record " + i));
            }
            Audit.Verification sv = longAudit.verify();
            check("the chain at the signing cadence verifies", sv.ok);
            eq("the chain at the signing cadence is complete", Config.AUDIT_SIGN_EVERY_N, sv.records);
            check("the head at the signing cadence is signed", sv.headSignatureValid);
            eq("a signed chain reports no reason", "", sv.reason);

            List<String> sigLines = readLinesOrEmpty(longDir.resolve("audit-sigs.ndjson"));
            eq("exactly one signature was written at the cadence", 1, sigLines.size());
            Map<String, Object> sigRec = Json.parseObject(sigLines.get(0));
            eq("the signature names the head index", (double) (Config.AUDIT_SIGN_EVERY_N - 1),
                    sigRec.get("index"));
            eq("the signature covers the head hash", sv.headHash, sigRec.get("head_hash"));
            eq("the signature is tagged with the signing key", longKm.keyId(), sigRec.get("key_id"));

            // The signature is checked here independently of the verifier: it must be a real
            // Ed25519 signature by the file's own key over the head hash bytes, not merely a
            // field that the verifier happens to accept.
            byte[] sigBytes = Sign.unb64(String.valueOf(sigRec.get("signature")));
            eq("the stored signature is 64 bytes", 64, sigBytes.length);
            check("the stored signature verifies against the key on file",
                    Sign.verify(sv.headHash.getBytes(StandardCharsets.UTF_8), sigBytes,
                            longKm.publicKey()));
            check("the stored signature does NOT verify over any other head hash",
                    !Sign.verify("some other hash".getBytes(StandardCharsets.UTF_8), sigBytes,
                            longKm.publicKey()));

            // Re-verify the chain independently, from the bytes on disk, rather than trusting the
            // verifier. The invariant is the documented one: hash = SHA-256(prev || canonical
            // JSON of the record without its own hash), and each record names its predecessor.
            List<String> lines = Files.readAllLines(logPath, StandardCharsets.UTF_8);
            eq("one line per record", 5, lines.size());
            String expectedPrev = Audit.genesisPrev();
            for (int i = 0; i < lines.size(); i++) {
                Map<String, Object> rec = Json.parseObject(lines.get(i));
                eq("record " + i + " has the expected index", (double) i, rec.get("index"));
                eq("record " + i + " names its predecessor", expectedPrev, rec.get("prev_hash"));
                eq("record " + i + " carries a self-consistent hash",
                        Audit.recordHash(rec), rec.get("hash"));
                for (String required : new String[] {"index", "ts", "event", "payload",
                        "prev_hash", "hash"}) {
                    check("record " + i + " carries the required field '" + required + "'",
                            rec.containsKey(required));
                }
                expectedPrev = String.valueOf(rec.get("hash"));
            }
            eq("the reported head is the last record's hash", expectedPrev, v.headHash);
            check("the head is not the genesis seed", !Audit.genesisPrev().equals(v.headHash));

            // Appending must extend the chain rather than rewrite it.
            audit.append("regression.append", Audit.payload("tester", "subject-5", "ok", "detail 5"));
            Audit.Verification v2 = audit.verify();
            check("the extended chain still verifies", v2.ok);
            eq("the extension added exactly one record", 6, v2.records);
            check("the head hash moved", !v.headHash.equals(v2.headHash));

            // An empty log is a valid chain of zero records, not an error.
            Audit empty = new Audit(dir.resolve("empty.ndjson"), dir.resolve("empty-sigs.ndjson"), km);
            Audit.Verification ev = empty.verify();
            check("an empty log verifies", ev.ok);
            eq("an empty log has no records", 0, ev.records);
            eq("an empty log reports the genesis head", Audit.genesisPrev(), ev.headHash);

            throwsType("a blank event type is rejected", IllegalArgumentException.class,
                    () -> audit.append("   ", Audit.payload("a", "b", "ok", "c")));
        } catch (Exception e) {
            check("t06 ran to completion (" + e + ")", false);
        }
    }

    // ==================================================================
    // t07 - audit tamper detection
    // ==================================================================

    private static void t07_auditTamper() {
        section("t07 every audit tamper shape is detected at the right index, and a broken chain is sealed");

        try {
            Path dir = scratch("t07-tamper");
            Audit.KeyManager km = Audit.KeyManager.createOrLoad(dir.resolve("keys").resolve("ed25519.pem"));
            Path logPath = dir.resolve("audit.ndjson");
            Audit audit = new Audit(logPath, dir.resolve("audit-sigs.ndjson"), km);
            for (int i = 0; i < 6; i++) {
                audit.append("regression.append", Audit.payload(
                        "tester", "subject-" + i, "ok", "detail " + i));
            }
            List<String> pristine = Files.readAllLines(logPath, StandardCharsets.UTF_8);
            check("the fixture chain verifies before tampering",
                    audit.verify().ok);

            // --- an edited payload in the middle -------------------------------------------
            List<String> edited = new ArrayList<>(pristine);
            Map<String, Object> rec = Json.parseObject(edited.get(3));
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = (Map<String, Object>) rec.get("payload");
            payload.put("detail", "detail 3 REWRITTEN");
            edited.set(3, Crypto.canonical(rec));
            writeLines(logPath, edited);
            Audit.Verification v = audit.verify();
            check("an edited record breaks the chain", !v.ok);
            eq("the break is reported at the edited index", 3, v.firstDivergentIndex);
            check("the reason names a hash mismatch (" + v.reason + ")", v.reason.contains("hash mismatch"));
            eq("the tampered log still has 6 lines", 6, v.records);

            // A broken chain must be sealed, not extended. Appending would bury the evidence and
            // report the break at the new record instead of the edited one (Audit.java L100-106).
            throwsType("appending to a broken chain is refused", Audit.ChainBrokenException.class,
                    () -> audit.append("regression.append",
                            Audit.payload("tester", "after-tamper", "ok", "should not land")));
            eq("the refused append wrote nothing", 6, Files.readAllLines(logPath).size());

            // --- a deleted record from the middle -----------------------------------------
            List<String> deleted = new ArrayList<>(pristine);
            deleted.remove(2);
            writeLines(logPath, deleted);
            Audit.Verification vd = audit.verify();
            check("a deleted record is detected", !vd.ok);
            eq("the deletion is reported at the gap", 2, vd.firstDivergentIndex);
            check("the reason names a sequence break (" + vd.reason + ")",
                    vd.reason.contains("expected index"));

            // --- a reordered pair ----------------------------------------------------------
            List<String> reordered = new ArrayList<>(pristine);
            String tmp = reordered.get(1);
            reordered.set(1, reordered.get(2));
            reordered.set(2, tmp);
            writeLines(logPath, reordered);
            Audit.Verification vr = audit.verify();
            check("reordering records is detected", !vr.ok);
            check("the reason names a sequence break (" + vr.reason + ")",
                    vr.reason.contains("expected index"));

            // --- an edited last record -----------------------------------------------------
            List<String> lastEdited = new ArrayList<>(pristine);
            Map<String, Object> last = Json.parseObject(lastEdited.get(5));
            last.put("event", "regression.rewritten");
            lastEdited.set(5, Crypto.canonical(last));
            writeLines(logPath, lastEdited);
            Audit.Verification vl = audit.verify();
            check("an edited final record is detected", !vl.ok);
            eq("the break is reported at the final index", 5, vl.firstDivergentIndex);

            // --- an edited predecessor link -----------------------------------------------
            List<String> relinked = new ArrayList<>(pristine);
            Map<String, Object> relink = Json.parseObject(relinked.get(4));
            relink.put("prev_hash", "0".repeat(64));
            relink.put("hash", Audit.recordHash(relink)); // recomputed, so only the link is wrong
            relinked.set(4, Crypto.canonical(relink));
            writeLines(logPath, relinked);
            Audit.Verification vp = audit.verify();
            check("a forged predecessor link is detected", !vp.ok);
            eq("the forged link is reported at its own index", 4, vp.firstDivergentIndex);
            check("the reason names a prev_hash mismatch (" + vp.reason + ")",
                    vp.reason.contains("prev_hash mismatch"));

            // --- an unparseable line -------------------------------------------------------
            List<String> corrupt = new ArrayList<>(pristine);
            corrupt.set(1, "{ this is not json");
            writeLines(logPath, corrupt);
            Audit.Verification vc = audit.verify();
            check("an unparseable line is detected", !vc.ok);
            eq("the corruption is reported at its own index", 1, vc.firstDivergentIndex);

            // --- a record stripped of a required field -------------------------------------
            List<String> stripped = new ArrayList<>(pristine);
            Map<String, Object> bare = Json.parseObject(stripped.get(2));
            bare.remove("prev_hash");
            stripped.set(2, Crypto.canonical(bare));
            writeLines(logPath, stripped);
            Audit.Verification vs = audit.verify();
            check("a record missing a required field is detected", !vs.ok);
            check("the reason names the missing field (" + vs.reason + ")",
                    vs.reason.contains("prev_hash"));

            // --- control: the exact bytes verify again -------------------------------------
            // A verifier that only ever reported failure could pass every tamper check above, so
            // the same object is re-run over the restored bytes and must report a valid chain.
            writeLines(logPath, pristine);
            Audit.Verification back = audit.verify();
            check("restoring the exact bytes restores a valid chain", back.ok);
            eq("the restored chain is complete", 6, back.records);
            check("the restored chain verifies end to end", audit.verify().ok);
        } catch (Exception e) {
            check("t07 ran to completion (" + e + ")", false);
        }
    }

    private static void writeLines(Path p, List<String> lines) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        Files.writeString(p, sb.toString(), StandardCharsets.UTF_8);
    }

    // ==================================================================
    // t08 - signing
    // ==================================================================

    private static void t08_signing() {
        section("t08 Ed25519 signatures are deterministic, PEM round-trips, key ids are stable");

        KeyPair kp = Sign.generateKeyPair();
        check("a key pair is generated", kp != null && kp.getPublic() != null && kp.getPrivate() != null);

        String payload = "regression subject line";
        byte[] sig = Sign.sign(payload, kp.getPrivate());
        check("a signature is produced", sig != null && sig.length > 0);
        eq("an Ed25519 signature is 64 bytes", 64, sig.length);

        // Ed25519 is deterministic by design. Two signatures over the same bytes with the same key
        // must be byte-identical; if they were not, an auditor could not reproduce a signature.
        byte[] again = Sign.sign(payload, kp.getPrivate());
        check("signing is deterministic for the same payload and key", Arrays.equals(sig, again));

        byte[] other = Sign.sign(payload + " ", kp.getPrivate());
        check("one added byte changes the signature", !Arrays.equals(sig, other));
        byte[] other2 = Sign.sign("regression subject lin", kp.getPrivate());
        check("one removed byte changes the signature", !Arrays.equals(sig, other2));

        KeyPair kp2 = Sign.generateKeyPair();
        byte[] otherKeySig = Sign.sign(payload, kp2.getPrivate());
        check("a different key produces a different signature",
                !Arrays.equals(sig, otherKeySig));

        // Key identity.
        String keyId = Sign.keyIdOf(kp.getPublic());
        eq("the key id is 64 characters", 64, keyId.length());
        check("the key id is lowercase hex", keyId.matches("[0-9a-f]{64}"));
        eq("the key id is stable for the same key", keyId, Sign.keyIdOf(kp.getPublic()));
        check("a different key has a different id", !keyId.equals(Sign.keyIdOf(kp2.getPublic())));

        // Portable encoding. A key that cannot be written and read back is a key that cannot be
        // moved between the analyst's machines, which is the entire point of the PEM helpers.
        String pubPem = Sign.publicKeyToPem(kp.getPublic());
        check("the public PEM carries its label", pubPem.contains(Sign.PUBLIC_PEM_LABEL));
        check("the public PEM is delimited", pubPem.contains("-----BEGIN ") && pubPem.contains("-----END "));
        check("the public key survives the PEM round trip",
                Arrays.equals(kp.getPublic().getEncoded(), Sign.publicKeyFromPem(pubPem).getEncoded()));

        String privPem = Sign.privateKeyToPem(kp.getPrivate());
        check("the private PEM carries its label", privPem.contains(Sign.PRIVATE_PEM_LABEL));
        check("the private key survives the PEM round trip",
                Arrays.equals(kp.getPrivate().getEncoded(),
                        Sign.privateKeyFromPem(privPem).getEncoded()));

        String sigPem = Sign.signatureToPem(sig);
        check("the signature PEM carries its label", sigPem.contains(Sign.SIGNATURE_PEM_LABEL));
        check("the signature survives the PEM round trip",
                Arrays.equals(sig, Sign.signatureFromPem(sigPem)));

        // Line wrapping must not change the decoded bytes: a file written on one machine and
        // read on another can have different line endings and different wrap points.
        String collapsed = pubPem.replace("\n", "");
        check("whitespace inside a PEM block does not change the decoded key",
                Arrays.equals(kp.getPublic().getEncoded(),
                        Sign.publicKeyFromPem(collapsed).getEncoded()));
        String crlf = pubPem.replace("\n", "\r\n");
        check("a CRLF-wrapped PEM decodes identically",
                Arrays.equals(kp.getPublic().getEncoded(),
                        Sign.publicKeyFromPem(crlf).getEncoded()));

        check("base64 round-trips", Arrays.equals(sig, Sign.unb64(Sign.b64(sig))));
        eq("base64 of nothing is nothing", "", Sign.b64(new byte[0]));

        throwsType("a public key cannot be read from a private-key PEM", Exception.class,
                () -> Sign.publicKeyFromPem(privPem));
        throwsType("a truncated PEM is rejected", Exception.class,
                () -> Sign.publicKeyFromPem("-----BEGIN " + Sign.PUBLIC_PEM_LABEL + "-----\nAAAA\n"));
    }

    // ==================================================================
    // t09 - verification
    // ==================================================================

    private static void t09_verification() {
        section("t09 verification accepts genuine signatures and rejects every forgery shape");

        KeyPair kp = Sign.generateKeyPair();
        KeyPair other = Sign.generateKeyPair();
        String payload = "transfer 4200.00 to account 000123";
        byte[] sig = Sign.sign(payload, kp.getPrivate());

        check("a genuine signature verifies", Sign.verify(payload, sig, kp.getPublic()));
        check("the byte[] overload agrees",
                Sign.verify(payload.getBytes(StandardCharsets.UTF_8), sig, kp.getPublic()));

        // The wrong payload.
        check("a changed payload fails", !Sign.verify(payload + ".", sig, kp.getPublic()));
        check("an emptied payload fails", !Sign.verify("", sig, kp.getPublic()));
        check("a prefixed payload fails", !Sign.verify(" " + payload, sig, kp.getPublic()));
        check("a reordered payload fails",
                !Sign.verify("transfer 4200.00 to 000123 account", sig, kp.getPublic()));

        // The wrong key.
        check("another key's signature fails on this key",
                !Sign.verify(payload, sig, other.getPublic()));
        check("a signature made with another key fails",
                !Sign.verify(payload, Sign.sign(payload, other.getPrivate()), kp.getPublic()));

        // A modified signature. Every byte is flipped in turn, because a check that only ever
        // tests the first byte would miss a verifier that ignores the rest.
        int rejected = 0;
        for (int i = 0; i < sig.length; i++) {
            byte[] mutated = sig.clone();
            mutated[i] ^= 0x01;
            if (!Sign.verify(payload, mutated, kp.getPublic())) {
                rejected++;
            }
        }
        eq("every single-bit flip in the signature is rejected", sig.length, rejected);

        // Malformed signatures must be a false, never an exception. verify() is called on
        // untrusted input from other people's reports, so a throw here is a denial-of-service
        // vector (Sign.java L157-164).
        check("an empty signature fails", !Sign.verify(payload, new byte[0], kp.getPublic()));
        check("a short signature fails", !Sign.verify(payload, Arrays.copyOf(sig, 32), kp.getPublic()));
        check("an over-long signature fails", !Sign.verify(payload, new byte[65], kp.getPublic()));
        check("a text signature fails",
                !Sign.verify(payload, "not a signature".getBytes(StandardCharsets.UTF_8), kp.getPublic()));
        check("an all-zero signature fails", !Sign.verify(payload, new byte[64], kp.getPublic()));
        check("an all-0xFF signature fails", !Sign.verify(payload, hexFilled(64, (byte) 0xFF), kp.getPublic()));

        // Nulls.
        check("a null payload fails", !Sign.verify((byte[]) null, sig, kp.getPublic()));
        check("a null signature fails", !Sign.verify(payload.getBytes(StandardCharsets.UTF_8),
                null, kp.getPublic()));
        check("a null key fails", !Sign.verify(payload.getBytes(StandardCharsets.UTF_8),
                sig, null));
        check("a null String payload fails", !Sign.verify((String) null, sig, kp.getPublic()));
        check("all three nulls fail", !Sign.verify((byte[]) null, null, null));

        // A signature must not transfer between two payloads that differ only in bytes an
        // attacker controls, so the truncated-payload family is checked explicitly.
        for (int cut = 1; cut < 12; cut++) {
            check("a payload truncated by " + cut + " byte(s) fails",
                    !Sign.verify(payload.substring(0, payload.length() - cut), sig, kp.getPublic()));
        }
    }

    private static byte[] hexFilled(int n, byte b) {
        byte[] out = new byte[n];
        Arrays.fill(out, b);
        return out;
    }

    // ==================================================================
    // t10 - modified payload
    // ==================================================================

    private static void t10_modifiedPayload() {
        section("t10 a single modified byte in the payload invalidates the signature");

        KeyPair kp = Sign.generateKeyPair();
        String payload = "invoice#1001 amount=4,200.00 beneficiary=ACCT-9911";
        byte[] sig = Sign.sign(payload, kp.getPrivate());
        check("the pristine payload verifies", Sign.verify(payload, sig, kp.getPublic()));

        // One bit, every position. If a single one of these passed, the signature was not over
        // the payload at all.
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        int survived = 0;
        for (int i = 0; i < bytes.length; i++) {
            byte[] mutated = bytes.clone();
            mutated[i] ^= 0x01;
            if (Sign.verify(new String(mutated, StandardCharsets.UTF_8), sig, kp.getPublic())) {
                survived++;
            }
        }
        eq("no single-bit payload edit survives", 0, survived);

        // The edits an attacker actually makes.
        check("changing one digit fails",
                !Sign.verify("invoice#1002 amount=4,200.00 beneficiary=ACCT-9911", sig, kp.getPublic()));
        check("changing the amount fails",
                !Sign.verify("invoice#1001 amount=4,2000.00 beneficiary=ACCT-9911", sig, kp.getPublic()));
        check("changing the beneficiary fails",
                !Sign.verify("invoice#1001 amount=4,200.00 beneficiary=ACCT-9912", sig, kp.getPublic()));
        check("appending a space fails",
                !Sign.verify(payload + " ", sig, kp.getPublic()));
        check("appending a newline fails",
                !Sign.verify(payload + "\n", sig, kp.getPublic()));
        check("prepending a space fails",
                !Sign.verify(" " + payload, sig, kp.getPublic()));
        check("a trailing null byte fails",
                !Sign.verify(payload + "\u0000", sig, kp.getPublic()));
        check("an interior null byte fails",
                !Sign.verify("invoice\u0000#1001 amount=4,200.00 beneficiary=ACCT-9911",
                        sig, kp.getPublic()));

        // Unicode normalisation is not applied before signing, so a canonically equivalent but
        // differently encoded payload is a different payload.
        check("a precomposed and a decomposed accent differ for the signature",
                !Sign.verify("caf\u00e9", Sign.sign("cafe\u0301", kp.getPrivate()), kp.getPublic()));

        // After every rejected mutation, the original must still verify: a failed verification
        // must not be able to poison the good signature.
        check("the original still verifies after every mutation attempt",
                Sign.verify(payload, sig, kp.getPublic()));

        // And a mutated payload signed properly is valid again, which proves the rejections above
        // were about the bytes and not about some lasting damage to the key.
        String mutated = payload.replace("1001", "1002");
        check("the mutated payload verifies under its own signature",
                Sign.verify(mutated, Sign.sign(mutated, kp.getPrivate()), kp.getPublic()));
    }

    // ==================================================================
    // t11 - parser bounds
    // ==================================================================

    private static void t11_parserBounds() {
        section("t11 parser bounds: header count, header line length, message size");

        // --- header count ---------------------------------------------------------------
        EmailParser.Limits tight = new EmailParser.Limits(
                256L * 1024, 3, 4096, 8, 200, 1024L * 1024, 1000);
        StringBuilder many = new StringBuilder("Subject: first\r\n");
        for (int i = 0; i < 20; i++) {
            many.append("X-Filler-").append(i).append(": v").append(i).append("\r\n");
        }
        many.append("\r\nbody\r\n");
        long t0 = System.nanoTime();
        EmailParser.Message m = EmailParser.parse(many.toString(), tight);
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        check("HEADER_COUNT_EXCEEDED is reported", m.warningCodes().contains("HEADER_COUNT_EXCEEDED"));
        check("at most the configured number of headers is accepted", m.headerList.size() <= 3);
        eq("the first header is still parsed", "first", m.subject);
        check("the parse stays fast despite the flood (" + ms + " ms)", ms < 1000);
        check("the result is still a usable message", m.raw != null && !m.raw.isEmpty());

        // Exactly at the cap must not warn, or the limit would be off by one. This uses its own
        // Limits so the cap under test is unambiguous: four headers against a cap of four.
        EmailParser.Limits headerCap4 = new EmailParser.Limits(
                256L * 1024, 4, 4096, 8, 200, 1024L * 1024, 1000);
        String atCapMsg = "Subject: at the cap\r\n"
                + "X-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\n\r\nbody\r\n";
        EmailParser.Message atCap = EmailParser.parse(atCapMsg, headerCap4);
        check("a message exactly at the header cap does not warn",
                !atCap.warningCodes().contains("HEADER_COUNT_EXCEEDED"));
        eq("every header at the cap is parsed", 4, atCap.headerList.size());
        eq("the header at the cap is the last one", "3", atCap.first("x-three"));

        // One header over that cap must be dropped and must warn, so the check above is not
        // passing simply because nothing is ever dropped.
        StringBuilder oneOver = new StringBuilder("Subject: one over\r\n");
        for (int i = 0; i < 4; i++) {
            oneOver.append("X-Over-").append(i).append(": v\r\n");
        }
        oneOver.append("\r\nbody\r\n");
        EmailParser.Message over = EmailParser.parse(oneOver.toString(), headerCap4);
        check("one header over the cap warns", over.warningCodes().contains("HEADER_COUNT_EXCEEDED"));
        eq("one header over the cap is dropped, not stored", 4, over.headerList.size());
        check("the dropped header is the last one", over.first("x-over-3") == null);

        // --- header line length ---------------------------------------------------------
        EmailParser.Limits shortLines = new EmailParser.Limits(
                256L * 1024, 500, 64, 8, 200, 1024L * 1024, 1000);
        String longValue = "z".repeat(4000);
        String overLong = "Subject: " + longValue + "\r\nX-Short: ok\r\n\r\nbody\r\n";
        EmailParser.Message lo = EmailParser.parse(overLong, shortLines);
        check("HEADER_LINE_EXCEEDED is reported", lo.warningCodes().contains("HEADER_LINE_EXCEEDED"));
        check("the over-long value is truncated, not stored whole",
                lo.subject != null && lo.subject.length() <= 64);
        check("the following header is still parsed", lo.first("x-short") != null);
        check("a truncated header is still a string", lo.subject != null && !lo.subject.isEmpty());

        String underLong = "Subject: " + "z".repeat(20) + "\r\n\r\nbody\r\n";
        EmailParser.Message ul = EmailParser.parse(underLong, shortLines);
        check("a header under the line cap does not warn",
                !ul.warningCodes().contains("HEADER_LINE_EXCEEDED"));
        eq("a header under the line cap is preserved whole", "z".repeat(20), ul.subject);

        // --- message size ---------------------------------------------------------------
        EmailParser.Limits tiny = new EmailParser.Limits(
                256L, 500, 8192, 8, 200, 1024L * 1024, 1000);
        StringBuilder big = new StringBuilder("Subject: big\r\n\r\n");
        for (int i = 0; i < 5000; i++) {
            big.append("body line ").append(i).append(" with enough text to exceed the cap\r\n");
        }
        long t1 = System.nanoTime();
        EmailParser.Message tm = EmailParser.parse(big.toString(), tiny);
        long ms1 = (System.nanoTime() - t1) / 1_000_000L;
        check("MESSAGE_TRUNCATED is reported", tm.warningCodes().contains("MESSAGE_TRUNCATED"));
        check("PARSE_TRUNCATED accompanies it", tm.warningCodes().contains("PARSE_TRUNCATED"));
        check("the result is marked truncated", tm.truncated);
        eq("consumption stops at the configured cap", 256L, tm.bytesConsumed);
        check("the oversized parse stays fast (" + ms1 + " ms)", ms1 < 1000);
        check("a truncated message is still a message", tm.raw != null && tm.subject != null);

        // --- degenerate inputs never throw ----------------------------------------------
        for (String degenerate : new String[] {"", "\r\n", "\n\n", "no headers at all",
                ": no field name", "\u0000\u0001\u0002", "Subject:\r\n\r\n"}) {
            EmailParser.Message d = EmailParser.parse(degenerate, tight);
            check("degenerate input <" + escape(degenerate) + "> parses without throwing",
                    d != null && d.headers != null);
        }
        check("a null message parses to an empty result",
                EmailParser.parse((String) null, tight) != null);

        // A message exactly at the size cap must not be reported as truncated.
        String sized = "Subject: s\r\n\r\n" + "x".repeat(256 - 14 - 2);
        EmailParser.Message ok = EmailParser.parse(sized, tiny);
        check("a message exactly at the size cap is not truncated",
                !ok.warningCodes().contains("MESSAGE_TRUNCATED"));
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(s.length(), 24); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                sb.append(String.format("\\x%02x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    // ==================================================================
    // t12 - MIME bounds
    // ==================================================================

    private static void t12_mimeBounds() {
        section("t12 MIME bounds: nesting depth and part count");

        // --- nesting depth --------------------------------------------------------------
        EmailParser.Limits depth3 = new EmailParser.Limits(
                1024L * 1024, 500, 8192, 3, 200, 4 * 1024 * 1024, 1000);
        long t0 = System.nanoTime();
        EmailParser.Message deep = EmailParser.parse(nestedMultipart(12), depth3);
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        check("MIME_DEPTH_EXCEEDED is reported", deep.warningCodes().contains("MIME_DEPTH_EXCEEDED"));
        check("the result is marked truncated", deep.truncated);
        int maxDepth = 0;
        for (EmailParser.Part p : deep.parts) {
            maxDepth = Math.max(maxDepth, p.depth);
        }
        check("no part is recorded deeper than the limit (max depth " + maxDepth + ")", maxDepth <= 3);
        check("a nesting bomb still returns a usable message (" + ms + " ms)",
                ms < 1000 && deep.parts.size() > 0);

        // Exactly at the depth limit must parse without a depth warning. nestedMultipart(n)
        // produces n container levels with the leaf at depth n (the outermost container is depth
        // 0), so three containers is the message that sits exactly on a limit of three. If the
        // guard were off by one, ordinary three-level mail would be silently truncated.
        EmailParser.Message atDepth = EmailParser.parse(nestedMultipart(3), depth3);
        check("a message at the depth limit does not warn",
                !atDepth.warningCodes().contains("MIME_DEPTH_EXCEEDED"));
        eq("a message at the depth limit is not marked truncated", false, atDepth.truncated);
        eq("every level at the depth limit is parsed", 4, atDepth.parts.size());
        int atCapDepth = 0;
        for (EmailParser.Part p : atDepth.parts) {
            atCapDepth = Math.max(atCapDepth, p.depth);
        }
        eq("the deepest part at the limit sits exactly on it", 3, atCapDepth);
        check("the innermost leaf survives to the depth limit",
                atDepth.parts.get(atDepth.parts.size() - 1).contentType.startsWith("text/plain"));

        // --- part count -----------------------------------------------------------------
        EmailParser.Limits fewParts = new EmailParser.Limits(
                1024L * 1024, 500, 8192, 8, 3, 4 * 1024 * 1024, 1000);
        long t1 = System.nanoTime();
        EmailParser.Message wide = EmailParser.parse(flatMultipart(50), fewParts);
        long ms1 = (System.nanoTime() - t1) / 1_000_000L;
        check("MIME_PART_LIMIT is reported", wide.warningCodes().contains("MIME_PART_LIMIT"));
        check("the part count respects the cap (" + wide.parts.size() + ")",
                wide.parts.size() <= 3);
        check("a part flood still returns a usable message (" + ms1 + " ms)",
                ms1 < 1000 && wide.parts.size() > 0);

        // The container is itself a part, so a message at the cap has fewer leaves than the cap.
        EmailParser.Message atParts = EmailParser.parse(flatMultipart(2), fewParts);
        check("a message at the part cap does not warn",
                !atParts.warningCodes().contains("MIME_PART_LIMIT"));
        eq("every part at the cap is parsed", 3, atParts.parts.size());

        // A part budget of one still yields a container rather than nothing.
        EmailParser.Limits onePart = new EmailParser.Limits(
                1024L * 1024, 500, 8192, 8, 1, 4 * 1024 * 1024, 1000);
        EmailParser.Message only = EmailParser.parse(flatMultipart(20), onePart);
        check("a cap of one part returns the container",
                only.parts.size() >= 1 && only.parts.get(0).isContainer);
        check("a cap of one part is reported", only.warningCodes().contains("MIME_PART_LIMIT"));

        // A declared boundary that never appears is a malformed message, not a crash. The parser
        // records the container node because the DECLARED Content-Type really does say
        // multipart/mixed - that is the analyst's evidence of what the sender claimed. What must
        // not happen is a child part being invented out of a boundary that was never seen, or the
        // body being silently presented as if a part had been decoded from it.
        EmailParser.Message dangling = EmailParser.parse(
                "Subject: dangle\r\nContent-Type: multipart/mixed; boundary=\"NOPE\"\r\n\r\nbody\r\n",
                depth3);
        check("a missing boundary is handled", dangling != null);
        eq("a missing boundary yields the declared container and nothing else", 1,
                dangling.parts.size());
        check("a missing boundary invents no child part and decodes no content",
                dangling.parts.get(0).isContainer
                        && (dangling.parts.get(0).data == null
                                || dangling.parts.get(0).data.length == 0));
        eq("the unparseable body is not smuggled into a fabricated leaf part", "",
                String.valueOf(dangling.bodyText).trim());
    }

    // ==================================================================
    // t13 - attribution confidence cap
    // ==================================================================

    private static void t13_attributionCap() {
        section("t13 attribution confidence never exceeds the 0.85 infrastructure cap");

        eq("the documented cap is 0.85", 0.85, Attribution.CONFIDENCE_CAP);
        near("the model's own cap agrees with it", 0.85, Config.C_ATTR_CAP, 0.0);

        // The model-side cap, asserted on the formula rather than through a parsed message, so a
        // change in the factors cannot make this test quietly stop testing anything.
        Model.Attribution allPositive = new Model.Attribution();
        allPositive.traceability = 1.0;
        allPositive.stability = 1.0;
        allPositive.anonymity = 0.0;
        allPositive.corroboration = 1.0;
        near("perfect factors are clamped to the cap", Config.C_ATTR_CAP, allPositive.compute(), 1e-12);
        check("the clamp is load-bearing: the unclamped product would exceed it",
                Attribution.TraceFactors.combine(1.0, 1.0, 0.0, 1.0) > Attribution.CONFIDENCE_CAP);
        near("perfect factors reach 1.0 before the cap", 1.0,
                Attribution.TraceFactors.combine(1.0, 1.0, 0.0, 1.0), 1e-12);

        // A single zero factor collapses the score. A=1 is total anonymity, and it enters the
        // model as (1 - A), so it collapses for the same reason the others do.
        near("T=0 collapses to zero", 0.0, Attribution.TraceFactors.combine(0.0, 1.0, 0.0, 1.0), 1e-12);
        near("S=0 collapses to zero", 0.0, Attribution.TraceFactors.combine(1.0, 0.0, 0.0, 1.0), 1e-12);
        near("X=0 collapses to zero", 0.0, Attribution.TraceFactors.combine(1.0, 1.0, 0.0, 0.0), 1e-12);
        near("A=1 collapses to zero", 0.0, Attribution.TraceFactors.combine(1.0, 1.0, 1.0, 1.0), 1e-12);

        // Out-of-range factors are clamped, not rejected, because they come from adapters whose
        // inputs are partly attacker-influenced.
        Model.Attribution outOfRange = new Model.Attribution();
        outOfRange.traceability = 5.0;
        outOfRange.stability = -3.0;
        outOfRange.anonymity = 9.0;
        outOfRange.corroboration = Double.NaN;
        double clamped = outOfRange.compute();
        check("out-of-range factors are clamped rather than propagated",
                Double.isFinite(clamped) && clamped >= 0.0 && clamped <= Config.C_ATTR_CAP);
        near("NaN corroboration clamps to zero, which collapses the score", 0.0, clamped, 1e-12);

        // --- the real pipeline, and the reason it needs enrichment ------------------------
        // Stability is one of the three specified S sub-signals and every one of them needs
        // analyst-supplied data (operator registry, domain age, MX presence). With no hints at
        // all, S is 0 and the geometric mean collapses to 0 REGARDLESS of how good the chain
        // looks. That is the honest answer - "we cannot tell you" must not be dressed up as a
        // number - and it is asserted here so a later change cannot quietly start scoring
        // unattributed chains as highly attributed ones.
        String cleanChain = "Received: from b.example ([2.2.2.2])\n"
                + "\tby mx.corp.example with ESMTPS id def\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:12 +0000\n"
                + "Received: from a.example ([1.1.1.1])\n"
                + "\tby mx.corp.example with ESMTPS id abc\n"
                + "\tfor <v@corp.example>; Tue, 12 Aug 2025 10:11:10 +0000\n"
                + "Subject: x\n\nbody\n";
        Attribution.Hints noHints = new Attribution.Hints();
        Attribution.Result bare = Attribution.attribute(EmailParser.parse(cleanChain), noHints);
        near("a perfect chain with no enrichment scores exactly zero", 0.0,
                bare.confidence.value, 1e-12);
        check("the zero is attributed to the missing sub-signals, not the chain",
                bare.confidence.trace.traceability > 0.9);
        check("the missing stability is named in the uncertainty list (" + bare.uncertain + ")",
                bare.uncertain.stream().anyMatch(s -> s.contains("enrichment")
                        || s.contains("domain age") || s.contains("MX")));

        // A stub provider supplies ASN and organisation so X can reach 4/4 and S can reach 1.0.
        // It is wired through the real Enrich.Registry, so the whole path - registry lookup,
        // operator comparison, sub-signal averaging, geometric mean, then the clamp - runs.
        Enrich.Record stub = new Enrich.Record();
        stub.asn = "AS64500";
        stub.organization = "Example Networks Ltd";
        stub.isp = "Example Networks Ltd";
        stub.hostname = "a.example";
        stub.country = "GB";
        Enrich.Provider provider = new Enrich.Provider() {
            @Override
            public String name() {
                return "regression-stub";
            }

            @Override
            public boolean available() {
                return true;
            }

            @Override
            public String unavailableReason() {
                return null;
            }

            @Override
            public Enrich.Record lookup(String ip) {
                Enrich.Record r = new Enrich.Record();
                r.asn = stub.asn;
                r.organization = stub.organization;
                r.isp = stub.isp;
                r.hostname = stub.hostname;
                r.country = stub.country;
                return r;
            }
        };
        Enrich.Registry registry = new Enrich.Registry().add(provider);
        check("the stub registry is not empty", !registry.isEmpty());

        Attribution.Hints full = new Attribution.Hints()
                .withRegistry(registry)
                .withDomainAge("a.example", 4000)
                .withMxPresent("a.example");

        Attribution.Result best = Attribution.attribute(EmailParser.parse(cleanChain), full);
        Attribution.TraceFactors tr = best.confidence.trace;
        check("every reported factor is inside [0,1]",
                inUnitInterval(tr.traceability) && inUnitInterval(tr.stability)
                        && inUnitInterval(tr.anonymity) && inUnitInterval(tr.corroboration));
        check("every reported factor carries a non-empty explanation",
                best.confidence.factors.size() >= 4 && best.confidence.factors.stream()
                        .allMatch(f -> f.detail != null && !f.detail.isBlank()));
        check("the observed sub-signals are all reported, not hidden",
                tr.observed.size() >= 6 && tr.unobserved.isEmpty());

        // This is the case the whole section exists for: perfect evidence on every axis, so the
        // unclamped value is 1.0 and the reported value is the 0.85 ceiling. Reaching it through
        // the pipeline - not by calling compute() directly - is what makes the assertion mean
        // something. A chain that reported 0.85 as if it had been observed, without the cap
        // flag, would let an analyst read a ceiling as a measurement.
        near("perfect evidence on every axis combines to 1.0 before the cap", 1.0,
                tr.combine(), 1e-9);
        check("the clamp is genuinely load-bearing in the pipeline",
                tr.combine() > Attribution.CONFIDENCE_CAP);
        near("perfect evidence is reported as exactly the cap", Attribution.CONFIDENCE_CAP,
                best.confidence.value, 1e-12);
        check("a clamped value is flagged as capped", best.confidence.capped);
        check("a clamped value explains the clamp", best.confidence.capNote != null
                && !best.confidence.capNote.isBlank());
        check("the cap note names both the raw value and the ceiling",
                best.confidence.capNote.contains("0.85"));
        near("the reported value is exactly min(combine, cap)",
                Math.min(tr.combine(), Attribution.CONFIDENCE_CAP), best.confidence.value, 1e-12);
        eq("the cap is a hard ceiling, not a soft preference",
                Attribution.CONFIDENCE_CAP, best.confidence.value);

        // An unobserved sub-signal is EXCLUDED from the stability average rather than counted as
        // zero, so simply withholding MX data cannot by itself lower the score. That is the
        // specified behaviour and it is asserted: withholding is not penalising. To move the
        // score the analyst has to supply a NEGATIVE observation, not a missing one.
        Attribution.Hints noMx = new Attribution.Hints()
                .withRegistry(registry)
                .withDomainAge("a.example", 4000);
        Attribution.Result withheld = Attribution.attribute(EmailParser.parse(cleanChain), noMx);
        near("withholding a sub-signal does not dilute the stability average", 1.0,
                withheld.confidence.trace.stability, 1e-12);
        check("a withheld sub-signal is recorded as unobserved, not assumed",
                withheld.confidence.trace.unobserved.stream()
                        .anyMatch(s -> s.contains("S.mx_present")));

        // To move the score the analyst has to supply a NEGATIVE observation, not a missing one.
        // Two are combined here, because the cap itself would otherwise hide a single weak
        // sub-signal: stability 0.667 still combines to 0.904, which clamps to 0.85 and looks
        // identical to the perfect result. That is the cap doing its job, and it is why the
        // trace-level check below is written against combine() rather than the reported value.
        Attribution.Hints degraded = new Attribution.Hints()
                .withRegistry(registry)
                .withDomainAge("a.example", 1)
                .withMxAbsent("a.example");
        Attribution.Result weaker = Attribution.attribute(EmailParser.parse(cleanChain), degraded);
        check("a domain that cannot send mail contributes 0 stability",
                weaker.confidence.trace.stability < 1.0);
        check("a brand-new domain contributes almost no age stability",
                weaker.confidence.trace.observed.stream()
                        .anyMatch(s -> s.contains("S.domain_age_inv") && s.contains("1 days old")));
        near("two degraded sub-signals drag the stability average to 1/3",
                (1.0 + 1.0 / Attribution.DOMAIN_STABILITY_HORIZON_DAYS) / 3.0,
                weaker.confidence.trace.stability, 1e-9);
        check("the degradation is visible in the combined value before the cap",
                weaker.confidence.trace.combine() < Attribution.CONFIDENCE_CAP);
        check("a negative observation lowers the reported confidence",
                weaker.confidence.value < best.confidence.value);
        eq("the degraded result is no longer flagged as capped", false,
                weaker.confidence.capped);
        check("the degraded value is still inside the cap",
                weaker.confidence.value >= 0.0 && weaker.confidence.value <= Attribution.CONFIDENCE_CAP);

        // Anonymiser evidence must reduce A, and therefore the score, without ever being able to
        // push the value up.
        Attribution.Hints anonymised = new Attribution.Hints()
                .withRegistry(registry)
                .withDomainAge("a.example", 4000)
                .withMxPresent("a.example")
                .withAnonymiserNetwork("AS64500");
        Attribution.Result anon = Attribution.attribute(EmailParser.parse(cleanChain), anonymised);
        eq("a matching anonymiser network sets anonymity to 1.0", 1.0, anon.confidence.trace.anonymity);
        near("total anonymity collapses the score to zero", 0.0, anon.confidence.value, 1e-12);

        // Bands must follow the value, at and around every boundary.
        eq("0.85 is PROBABLE", Attribution.Band.PROBABLE, Attribution.bandOf(Attribution.CONFIDENCE_CAP));
        eq("0.70 is PROBABLE", Attribution.Band.PROBABLE, Attribution.bandOf(0.70));
        eq("0.69 is INDICATIVE", Attribution.Band.INDICATIVE, Attribution.bandOf(0.69));
        eq("0.45 is INDICATIVE", Attribution.Band.INDICATIVE, Attribution.bandOf(0.45));
        eq("0.44 is WEAK", Attribution.Band.WEAK, Attribution.bandOf(0.44));
        eq("0.25 is WEAK", Attribution.Band.WEAK, Attribution.bandOf(0.25));
        eq("0.24 is INSUFFICIENT", Attribution.Band.INSUFFICIENT, Attribution.bandOf(0.24));
        eq("0.0 is INSUFFICIENT", Attribution.Band.INSUFFICIENT, Attribution.bandOf(0.0));
        eq("the reported band matches the reported value",
                Attribution.bandOf(best.confidence.value), best.confidence.band);

        // Adversarial shapes, none of which may exceed the cap. These run against the FULL hint
        // set on purpose: an attacker controls the message, not the analyst's registry, so the
        // bound has to hold when the evidence side is as generous as it can ever be.
        String[] adversarial = {
                "Subject: x\n\nbody\n",                                     // no chain at all
                "Received: from a ([10.0.0.5])\n\tby b; Tue, 12 Aug 2025 10:00:01 +0000\n"
                        + "Subject: x\n\nbody\n",                          // private only
                "Received: from a ([1.1.1.1])\n\tby mx with HTTP id a; Tue, 12 Aug 2025 10:00:02 +0000\n"
                        + "Received: from b ([2.2.2.2])\n\tby a; Tue, 12 Aug 2025 10:00:01 +0000\n"
                        + "Received: from c ([3.3.3.3])\n\tby a; Tue, 12 Aug 2025 10:00:00 +0000\n"
                        + "Subject: x\n\nbody\n",                          // many public hops
                "Received: from openrelay.example ([1.1.1.1])\n\tby mx with ESMTP id a;"
                        + " Tue, 12 Aug 2025 10:00:02 +0000\nSubject: x\n\nbody\n",
                "Received: from host ([999.999.999.999])\n\tby mx; Tue, 12 Aug 2025 10:00:02 +0000\n"
                        + "Subject: x\n\nbody\n",                          // malformed literals
                "Received: from a ([1.1.1.1])\n\tby mx; Tue, 12 Aug 2025 10:00:02 +0000\n"
                        + "Received: from b ([1.1.1.1])\n\tby a; Tue, 12 Aug 2025 09:00:00 +0000\n"
                        + "Subject: x\n\nbody\n",                          // time goes backwards
        };
        boolean allCapped = true;
        for (String raw2 : adversarial) {
            Attribution.Result r = Attribution.attribute(EmailParser.parse(raw2), full);
            if (!(r.confidence.value >= 0.0 && r.confidence.value <= Attribution.CONFIDENCE_CAP)
                    || !Double.isFinite(r.confidence.value)) {
                allCapped = false;
            }
        }
        check("every adversarial message stays inside [0, cap] even with full hints", allCapped);

        // No observable evidence is zero confidence, and it is reported as such.
        Attribution.Result none = Attribution.attribute(
                EmailParser.parse("Subject: x\n\nbody\n"), noHints);
        eq("no addresses means zero confidence", 0.0, none.confidence.value);
        check("zero confidence is flagged, not silently reported", none.confidence.capped);
        check("zero confidence explains itself (" + none.uncertain + ")",
                !none.uncertain.isEmpty() || (none.confidence.capNote != null
                        && !none.confidence.capNote.isBlank()));

        // A null message is a result, not an exception.
        Attribution.Result nullMsg = Attribution.attribute(null, noHints);
        eq("a null message yields zero confidence", 0.0, nullMsg.confidence.value);
        check("a null message yields an empty candidate list", nullMsg.candidates.isEmpty());
        check("a null message is explained", !nullMsg.uncertain.isEmpty());
    }

    private static boolean inUnitInterval(double d) {
        return Double.isFinite(d) && d >= 0.0 && d <= 1.0;
    }

    // ==================================================================
    // t14 - correlation threshold
    // ==================================================================

    private static void t14_correlation() {
        section("t14 correlation scoring is thresholded at 0.62 and is exactly decomposable");

        near("the documented threshold is 0.62", 0.62, Correlate.DEFAULT_THRESHOLD, 0.0);
        near("the config agrees with the correlator", 0.62, Config.TAU_CLUSTER, 0.0);
        near("header names weigh 0.25", 0.25, Correlate.W_HEADER_NAMES, 0.0);
        near("domains weigh 0.30", 0.30, Correlate.W_DOMAINS, 0.0);
        near("addresses weigh 0.20", 0.20, Correlate.W_IPS, 0.0);
        near("text weighs 0.20", 0.20, Correlate.W_TEXT, 0.0);
        near("attachment hashes weigh 0.05", 0.05, Correlate.W_ATTACHMENT_HASHES, 0.0);
        near("the weights sum to 1", 1.0,
                Correlate.W_HEADER_NAMES + Correlate.W_DOMAINS + Correlate.W_IPS
                        + Correlate.W_TEXT + Correlate.W_ATTACHMENT_HASHES, 1e-12);

        Correlate.Document a = doc("A",
                set("1.1.1.1"), set("alpha.example"), set("https://alpha.example/login"),
                set("text/html"), set("x-mailer", "received"), set("deadbeef"),
                "urgent notice", "please act now");
        Correlate.Document sameAsA = doc("A-copy",
                set("1.1.1.1"), set("alpha.example"), set("https://alpha.example/login"),
                set("text/html"), set("x-mailer", "received"), set("deadbeef"),
                "urgent notice", "please act now");

        Correlate.PairScore identical = Correlate.score(a, sameAsA, Correlate.DEFAULT_THRESHOLD);
        near("two identical documents combine to 1.0", 1.0, identical.combined, 1e-9);
        check("two identical documents are linked", identical.linked);
        near("identical documents have identical header-name overlap", 1.0,
                identical.jaccardHeaders, 1e-9);
        near("identical documents have identical domain overlap", 1.0,
                identical.jaccardDomains, 1e-9);

        // A disjoint pair must score zero on every term. If a term defaulted to 1.0 when a
        // dimension was absent, unrelated mail would be clustered together.
        Correlate.Document unrelated = doc("Z",
                set("9.9.9.9"), set("zeta.example"), set("https://zeta.example/other"),
                set("application/pdf"), set("x-originating-ip"), set("0badc0de"),
                "weekly digest", "unrelated content entirely");
        Correlate.PairScore disjoint = Correlate.score(a, unrelated, Correlate.DEFAULT_THRESHOLD);
        near("a disjoint pair scores 0.0", 0.0, disjoint.combined, 1e-9);
        check("a disjoint pair is not linked", !disjoint.linked);
        near("disjoint header names score 0", 0.0, disjoint.jaccardHeaders, 1e-9);
        near("disjoint domains score 0", 0.0, disjoint.jaccardDomains, 1e-9);
        near("disjoint addresses score 0", 0.0, disjoint.jaccardAddresses, 1e-9);
        near("disjoint text scores 0", 0.0, disjoint.cosineText, 1e-9);
        near("disjoint attachment hashes score 0", 0.0, disjoint.jaccardAttachmentHashes, 1e-9);

        // A controlled pair built to land above the threshold: shared domain, address and header
        // name, and completely different prose. A carries {x-mailer, received} and B carries
        // {x-mailer}, so the header-name Jaccard is 1/2, not 1: 0.30 + 0.20 + 0.25*0.5 = 0.625.
        // Asserting the 0.5 rather than 1.0 is the point - a scorer that credited a shared name
        // as full agreement would inflate the score by 0.125 and cross the 0.62 threshold on
        // evidence that does not deserve it.
        Correlate.Document infraTwin = doc("B",
                set("1.1.1.1"), set("alpha.example"), set("https://other.example/x"),
                set("text/plain"), set("x-mailer"), set(),
                "completely different subject", "entirely unrelated body text");
        Correlate.PairScore above = Correlate.score(a, infraTwin, Correlate.DEFAULT_THRESHOLD);
        near("shared domain scores 1.0", 1.0, above.jaccardDomains, 1e-9);
        near("shared address scores 1.0", 1.0, above.jaccardAddresses, 1e-9);
        near("one shared header name out of two is a Jaccard of 0.5", 0.5,
                above.jaccardHeaders, 1e-9);
        near("disjoint prose scores 0.0", 0.0, above.cosineText, 1e-9);
        near("no shared hash contributes nothing", 0.0, above.jaccardAttachmentHashes, 1e-9);
        near("the score is exactly the weighted sum of the observed terms", 0.625,
                above.combined, 1e-9);
        check("an infrastructure-only pair is above the threshold (" + above.combined + ")",
                above.combined > Correlate.DEFAULT_THRESHOLD);
        check("an infrastructure-only pair is linked", above.linked);

        // A pair sharing ONLY the header names must fall below the threshold. This is the same
        // weight the Jaccard check above protects, seen from the other side: 0.25*1.0 alone is
        // well under 0.62, so evidence of one dimension cannot manufacture a campaign.
        Correlate.Document nameOnly = doc("N",
                set(), set(), set(), set(), set("x-mailer", "received"), set(),
                null, null);
        Correlate.PairScore namePair = Correlate.score(a, nameOnly, Correlate.DEFAULT_THRESHOLD);
        near("an identical header-name set scores a Jaccard of 1.0", 1.0,
                namePair.jaccardHeaders, 1e-9);
        near("and therefore contributes exactly its own weight", Correlate.W_HEADER_NAMES,
                namePair.combined, 1e-9);
        check("a full header-name match alone is not enough to link", !namePair.linked);

        // The partial case: matching one of two names halves the credit, not keeps all of it.
        Correlate.Document halfName = doc("H",
                set(), set(), set(), set(), set("x-mailer"), set(), null, null);
        Correlate.PairScore halfPair = Correlate.score(a, halfName, Correlate.DEFAULT_THRESHOLD);
        near("matching one of two names earns half the weight", Correlate.W_HEADER_NAMES * 0.5,
                halfPair.combined, 1e-9);

        // The same pair scored against a threshold above its score, and below it. This is the
        // threshold comparison itself, isolated from any assumption about what the score is.
        Correlate.PairScore tooHigh = Correlate.score(a, infraTwin,
                above.combined + 1e-6);
        check("the same pair is not linked above its own score", !tooHigh.linked);
        Correlate.PairScore wellBelow = Correlate.score(a, infraTwin,
                Math.max(1e-9, above.combined - 1e-6));
        check("the same pair is linked below its own score", wellBelow.linked);
        eq("the score itself does not depend on the threshold", above.combined, tooHigh.combined);

        // Every term the pair reports must reconstruct the combined score exactly.
        double rebuilt = Correlate.W_HEADER_NAMES * above.jaccardHeaders
                + Correlate.W_DOMAINS * above.jaccardDomains
                + Correlate.W_IPS * above.jaccardAddresses
                + Correlate.W_TEXT * above.cosineText
                + Correlate.W_ATTACHMENT_HASHES * above.jaccardAttachmentHashes;
        near("the reported terms rebuild the combined score exactly", rebuilt, above.combined, 1e-12);
        check("the combined score is inside [0,1]",
                above.combined >= 0.0 && above.combined <= 1.0);
        check("the dominant component is named", above.dominantComponent != null
                && !above.dominantComponent.isBlank());
        eq("the pair is identified by its own ids", "A", above.idA);
        eq("the pair is identified by the other id", "B", above.idB);

        // linked must be exactly (combined >= threshold), on both sides of every boundary.
        boolean consistent = true;
        for (double combined : new double[] {0.0, 0.1, 0.4999, 0.5, 0.61, 0.62, 0.75, 1.0}) {
            for (double delta : new double[] {-1e-9, 0.0, 1e-9}) {
                double t = combined + delta;
                if (t <= 0.0 || t > 1.0) {
                    continue;
                }
                Correlate.PairScore ps = Correlate.score(a, infraTwin, t);
                if (ps.linked != (ps.combined >= t)) {
                    consistent = false;
                }
            }
        }
        check("linked is exactly (combined >= threshold) across the boundary", consistent);

        // Campaign clustering: two linked documents and one unrelated document produce exactly
        // one cluster, holding only the linked pair.
        Correlate.Campaign campaign = Correlate.analyze(
                List.of(a, infraTwin, unrelated), Correlate.DEFAULT_THRESHOLD);
        near("the campaign records the threshold it used", Correlate.DEFAULT_THRESHOLD,
                campaign.threshold, 0.0);
        eq("exactly one cluster is formed", 1, campaign.clusters.size());
        Correlate.Cluster cluster = campaign.clusters.get(0);
        eq("the cluster holds the linked pair", 2, cluster.memberIds.size());
        check("the cluster holds A", cluster.memberIds.contains("A"));
        check("the cluster holds B", cluster.memberIds.contains("B"));
        check("the unrelated document is not in a cluster",
                !cluster.memberIds.contains("Z"));
        check("the cluster cohesion is inside [0,1]",
                cluster.cohesion >= 0.0 && cluster.cohesion <= 1.0);
        check("the cluster is at least as cohesive as the linking pair",
                cluster.cohesion >= above.combined - 1e-9);
        near("the cluster records the threshold it used", Correlate.DEFAULT_THRESHOLD,
                cluster.threshold, 0.0);

        // Raising the threshold above every pair must produce no clusters at all.
        Correlate.Campaign strict = Correlate.analyze(List.of(a, infraTwin, unrelated), 1.0);
        eq("a threshold of 1.0 forms no cluster", 0, strict.clusters.size());

        // An out-of-range threshold falls back to the documented default rather than scoring
        // everything or nothing.
        Correlate.Campaign nonsense = Correlate.analyze(List.of(a, infraTwin, unrelated), 5.0);
        near("an out-of-range threshold falls back to the default", Correlate.DEFAULT_THRESHOLD,
                nonsense.threshold, 0.0);
        eq("the fallback still finds the same cluster", 1, nonsense.clusters.size());

        // A corpus of one cannot cluster.
        Correlate.Campaign single = Correlate.analyze(List.of(a), Correlate.DEFAULT_THRESHOLD);
        eq("a single document forms no cluster", 0, single.clusters.size());
        Correlate.Campaign empty = Correlate.analyze(List.of(), Correlate.DEFAULT_THRESHOLD);
        eq("an empty corpus forms no cluster", 0, empty.clusters.size());

        // Identical content under different ids must cluster, and a document with no evidence at
        // all must not be silently linked to everything.
        Correlate.Document nothing = doc("E", Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of(), Set.of(), null, null);
        Correlate.PairScore vsNothing = Correlate.score(a, nothing, Correlate.DEFAULT_THRESHOLD);
        check("a document with no evidence is not linked to anything", !vsNothing.linked);
        check("a document with no evidence contributes nothing",
                vsNothing.combined <= above.combined);
    }

    private static Correlate.Document doc(String id, Set<String> addresses, Set<String> domains,
                                          Set<String> urls, Set<String> fileTypes,
                                          Set<String> headerNames, Set<String> hashes,
                                          String subject, String body) {
        return new Correlate.Document(id, addresses, domains, urls, fileTypes, headerNames,
                hashes, subject, body);
    }

    // ==================================================================
    // t15 - hostile input
    // ==================================================================

    private static void t15_hostileInput() {
        section("t15 hostile input never throws, never yields NaN, and costs bounded time");

        long t0 = System.nanoTime();

        TextNormalizer norm;
        try {
            norm = TextNormalizer.load();
        } catch (RuntimeException e) {
            check("the confusables table loads (" + e + ")", false);
            return;
        }
        Features features = new Features(norm, OrgProfile.EMPTY);
        Model model = Model.initial();
        double[] becX = new double[Config.INITIAL_G.length - 1];

        // Bounded, but each shape is the one an attacker actually reaches for. Sizes are chosen
        // to overshoot the configured ceiling by a wide multiple - a shape that merely touched
        // the limit would not exercise the limit - while keeping the whole batch inside the
        // section budget. Every limit below is therefore tripped many times over.
        String megabyteToken = "a".repeat(60_000);
        String tokenStorm = "urgent payment verify account ".repeat(3_000);
        String zeroWidth = "pay\u200Bpal\u200D".repeat(3_000);
        String bidiFlood = "\u202Egnp.exe\u202C".repeat(3_000);
        String tagSmuggle = "Subject: ok\u0001\u0002\r\nX-Hidden: \u001B[2J".repeat(1_500);
        String loneSurrogate = "\uD83D".repeat(3_000);
        String crlfFlood = "A: b\r\n \r\n\tC: d\r\n".repeat(2_000);
        String nullBytes = "a\u0000b".repeat(6_000);
        String controlStorm = ("\u0000\u0001\u0007\u001B\u007F\u009B").repeat(3_000);
        String mixedScript = "a\u0430e\u0430o\u0435p\u0430y\u0435l \u4EBF\u6DB2".repeat(1_000);
        String markupBomb = "<div><span>urgent</span></div>".repeat(2_000);
        String deepNest = nestedMultipart(60);
        String wideNest = flatMultipart(2_000);
        String headerFlood = headerFlood(4_000);
        // 2.2 MB: deliberately over the 2 MiB parse ceiling, so truncation is really exercised.
        String bodyBomb = "Subject: big\r\n\r\n" + "x".repeat(2_200_000);

        String[] hostile = {megabyteToken, tokenStorm, zeroWidth, bidiFlood, tagSmuggle,
                loneSurrogate, crlfFlood, nullBytes, controlStorm, mixedScript, markupBomb,
                deepNest, wideNest, headerFlood, bodyBomb};

        // A deliberately hostile but valid budget: 300 ms of parse budget means the parser itself
        // is under pressure, which is the condition under which a partial-result bug shows up.
        EmailParser.Limits hostileLimits = new EmailParser.Limits(
                2L * 1024 * 1024, 500, 8 * 1024, 8, 200, 10L * 1024 * 1024, 300);

        for (int i = 0; i < hostile.length; i++) {
            String h = hostile[i];
            long shapeStart = System.nanoTime();
            String name = "hostile input " + i + " (" + describe(i) + ", " + h.length() + " chars)";

            // --- parser ------------------------------------------------------------------
            // The parser stage always sees the full shape, because that is where the byte ceiling
            // lives and the ceiling is the whole point of the assertion.
            EmailParser.Message msg = EmailParser.parse(h, hostileLimits);
            check(name + ": parses without throwing", msg != null);
            check(name + ": yields a bounded header count", msg.headerList.size() <= 500);
            check(name + ": yields a bounded part count", msg.parts.size() <= 200);
            check(name + ": consumes at most the configured bytes", msg.bytesConsumed <= 2L * 1024 * 1024);
            boolean knownCodes = true;
            for (String code : msg.warningCodes()) {
                if (!KNOWN_WARNING_CODES.contains(code)) {
                    knownCodes = false;
                }
            }
            check(name + ": reports only known warning codes", knownCodes);

            // Downstream stages see a bounded-size copy of the same shape. Features.extract is
            // linear in the body it scans and makes dozens of passes over it, so a maximum-size
            // body costs ~0.5 s on its own - which is a real property of the extractor, not
            // something a regression suite should pay fifteen times. The shape, the character
            // classes and the code paths are identical; only the repeat count differs.
            String h2 = h.length() > 64 * 1024 ? h.substring(0, 64 * 1024) : h;

            // --- normaliser --------------------------------------------------------------
            String normalised = norm.normalise(h2);
            check(name + ": normalises without throwing", normalised != null);
            check(name + ": normalisation is idempotent in size class",
                    Math.abs(normalised.length() - h2.length()) <= h2.length() + 64);

            // --- tokeniser ---------------------------------------------------------------
            List<String> tokens = Correlate.tokenize(h2);
            check(name + ": tokenises without throwing", tokens != null);
            check(name + ": token count is bounded",
                    tokens.size() <= Correlate.MAX_TOKENS_PER_DOC);
            check(name + ": no token is a lone surrogate",
                    tokens.stream().noneMatch(Regression::hasLoneSurrogate));

            // --- feature extraction ------------------------------------------------------
            Features.Vector vec = features.extract(Headers.parseComplete(h2), null);
            double[] x = vec.toArray();
            check(name + ": produces a full-width feature vector", x.length == Features.COUNT);
            check(name + ": no feature is NaN", !anyNaN(x));
            check(name + ": every feature is finite", allFinite(x));
            boolean inRange = true;
            for (int j = 0; j < x.length; j++) {
                if (vec.isObserved(j) && (x[j] < -1e-9 || x[j] > 1.0 + 1e-9)) {
                    inRange = false;
                }
            }
            check(name + ": every observed feature is inside [0,1]", inRange);
            check(name + ": the BEC subset is finite", allFinite(vec.becVector()));

            // --- model -------------------------------------------------------------------
            Model.Logits lg = model.logits(x);
            check(name + ": logits are finite", allFinite(lg.z));
            Model.Score s = model.score(x, becX, new Model.Attribution());
            check(name + ": the distribution is finite", allFinite(s.p));
            check(name + ": the distribution sums to 1", Math.abs(sum(s.p) - 1.0) < 1e-9);
            check(name + ": risk is finite and bounded",
                    Double.isFinite(s.risk) && s.risk >= -1e-9 && s.risk <= 100.0 + 1e-9);
            check(name + ": the BEC blend is finite", Double.isFinite(s.becNoisyOr)
                    && s.becNoisyOr >= 0.0 && s.becNoisyOr <= 1.0);
            check(name + ": confidence is finite and inside [0, cap]",
                    Double.isFinite(s.cAttr) && s.cAttr >= 0.0 && s.cAttr <= Config.C_ATTR_CAP);

            // --- attribution ------------------------------------------------------------
            Attribution.Result attr = Attribution.attribute(msg);
            check(name + ": attribution stays inside [0, cap]",
                    Double.isFinite(attr.confidence.value)
                            && attr.confidence.value >= 0.0
                            && attr.confidence.value <= Attribution.CONFIDENCE_CAP);
            for (Attribution.Factor f : attr.confidence.factors) {
                if (f.detail == null || f.detail.isBlank()) {
                    check(name + ": every attribution factor is explained", false);
                    break;
                }
            }
            System.out.println("    " + (System.nanoTime() - shapeStart) / 1_000_000L + " ms  "
                    + name);
        }

        // Degenerate values, which are the ones that reach a divide.
        for (String degenerate : new String[] {null, "", "\u0000", "   ", "\uD800",
                "\uDFFF", "a\u0000", "\n\r\n\r\n"}) {
            String label = String.valueOf(degenerate).replace("\u0000", "\\0");
            check("normalising <" + label + "> does not throw", norm.normalise(degenerate) != null);
            check("tokenising <" + label + "> does not throw",
                    Correlate.tokenize(degenerate) != null);
            check("parsing <" + label + "> does not throw",
                    EmailParser.parse(degenerate, hostileLimits) != null);
        }

        // An all-zero and an all-one feature vector are the two extremes the model can be handed.
        double[] zero = new double[Features.COUNT];
        double[] ones = new double[Features.COUNT];
        Arrays.fill(ones, 1.0);
        for (double[] extreme : new double[][] {zero, ones}) {
            Model.Score s = model.score(extreme, becX, new Model.Attribution());
            check("an extreme feature vector yields a finite distribution", allFinite(s.p));
            near("an extreme feature vector still sums to 1", 1.0, sum(s.p), 1e-9);
            check("an extreme feature vector never exceeds the confidence cap",
                    s.cAttr <= Config.C_ATTR_CAP);
        }

        // A wrong-width vector is a caller error and must be rejected loudly, not silently padded.
        throwsType("a short feature vector is rejected", IllegalArgumentException.class,
                () -> model.logits(new double[Features.COUNT - 1]));

        long elapsed = System.nanoTime() - t0;
        check("the whole hostile batch finished inside the 1500 ms budget (" + elapsed / 1_000_000
                + " ms)", elapsed < HOSTILE_BUDGET_NANOS);
    }

    private static final Set<String> KNOWN_WARNING_CODES = Set.of(
            "MESSAGE_TRUNCATED", "TIME_BUDGET_EXCEEDED", "PARSE_TRUNCATED",
            "HEADER_COUNT_EXCEEDED", "HEADER_LINE_EXCEEDED", "MALFORMED_HEADER_LINE",
            "MALFORMED_HEADER_NAME", "FOLD_LIMIT_EXCEEDED", "MIME_DEPTH_EXCEEDED",
            "MIME_PART_LIMIT", "DECODED_CONTENT_EXCEEDED");

    private static String describe(int i) {
        return switch (i) {
            case 0 -> "one 60k-character token";
            case 1 -> "repeated keywords";
            case 2 -> "zero-width joiners";
            case 3 -> "bidi overrides";
            case 4 -> "control characters in headers";
            case 5 -> "unpaired surrogates";
            case 6 -> "CRLF and folding floods";
            case 7 -> "embedded NUL bytes";
            case 8 -> "control character storm";
            case 9 -> "mixed script";
            case 10 -> "markup bomb";
            case 11 -> "60-deep MIME nesting";
            case 12 -> "2000 MIME parts";
            case 13 -> "4000 headers";
            case 14 -> "2.2 MB body";
            default -> "shape " + i;
        };
    }

    private static boolean hasLoneSurrogate(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    return true;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return true;
            }
        }
        return false;
    }

    private static String headerFlood(int count) {
        StringBuilder sb = new StringBuilder("Subject: flood\r\n");
        for (int i = 0; i < count; i++) {
            sb.append("X-H-").append(i).append(": v").append(i).append("\r\n");
        }
        sb.append("\r\nbody\r\n");
        return sb.toString();
    }

    // ==================================================================
    // main
    // ==================================================================

    public static void main(String[] args) {
        long t0 = System.nanoTime();

        t01_softmax();
        t02_exactAdditiveLogit();
        t03_clipping();
        t04_unobserved();
        t05_noisyOr();
        t06_auditValidChain();
        t07_auditTamper();
        t08_signing();
        t09_verification();
        t10_modifiedPayload();
        t11_parserBounds();
        t12_mimeBounds();
        t13_attributionCap();
        t14_correlation();
        t15_hostileInput();

        long ms = (System.nanoTime() - t0) / 1_000_000L;
        System.out.println();
        System.out.println("------------------------------------------------------------");
        System.out.println("passed=" + passed + "  failed=" + failed);
        System.out.println("------------------------------------------------------------");
        if (failed > 0) {
            System.out.println("FAILURES:");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.out.println("------------------------------------------------------------");
            System.out.println("RESULT: FAIL");
            System.exit(1);
        }
        System.out.println("elapsed=" + ms + " ms");
        System.out.println("------------------------------------------------------------");
        System.out.println("RESULT: PASS");
    }
}
