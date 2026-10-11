/**
 * Unicode-aware text normalisation for lookalike detection. Phase 1 item 2.
 *
 * Contract, in order:
 *   1. NFKC            - compatibility composition, so fullwidth and ligature spellings
 *                        collapse onto their ASCII equivalents.
 *   2. strip invisibles- zero-width and bidi control characters are DELETED, not replaced
 *                        with a space. A space would change the label's structure;
 *                        deletion restores the character the sender hoped we would not see.
 *   3. fold            - data/confusables.tsv, see that file's header for provenance.
 *   4. lowercase       - Locale.ROOT, so Turkish dotless-i rules cannot make the result
 *                        depend on the server's default locale.
 *
 * The output is the *skeleton*: a canonical form used only for lookalike distance and
 * domain-registry equivalence. It is never displayed, never logged as an address, and never
 * used to construct a URL that gets fetched.
 *
 * Idempotence is load-time enforced, not assumed. See loadMap().
 *
 * Spec anchors: SCORING-MODEL.md L84 (homoglyph_ratio), L88 (mixed_script),
 * L62-70 (IDENT family), and the inference-purity rule at ARCHITECTURE.md L152.
 */
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class TextNormalizer {

    private static final String DEFAULT_RESOURCE = "data/confusables.tsv";

    /** Character-folding targets, keyed by source code point. */
    private final Map<Integer, String> fold;

    /** Unicode script of each folded source, for the mixed_script rule. */
    private final Map<Integer, String> scriptOf;

    private final Path source;

    private TextNormalizer(Map<Integer, String> fold, Map<Integer, String> scriptOf, Path source) {
        this.fold = fold;
        this.scriptOf = scriptOf;
        this.source = source;
    }

    /** Loads the table at the default repo-relative path. */
    public static TextNormalizer load() {
        return load(Path.of(DEFAULT_RESOURCE));
    }

    /**
     * Loads and validates a folding table.
     *
     * Refuses to load on: a malformed row, a source that maps to two different targets, or a
     * table that is not idempotent. Those are load errors rather than warnings because each
     * one silently changes what "the same domain" means, and a wrong equivalence here would
     * merge two unrelated registrations in the domain registry.
     */
    public static TextNormalizer load(Path tsv) {
        Map<Integer, String> fold = new HashMap<>();
        Map<Integer, String> scripts = new HashMap<>();
        Map<Integer, String> claimed = new HashMap<>();

        List<String> lines;
        try {
            lines = Files.readAllLines(tsv, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read confusables table: " + tsv, e);
        }

        int lineNo = 0;
        for (String raw : lines) {
            lineNo++;
            String line = raw;
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1);
            }
            if (line.isEmpty() || line.charAt(0) == '#') {
                continue;
            }
            String[] f = line.split("\t", -1);
            if (f.length < 3) {
                throw new IllegalStateException(
                        tsv + ":" + lineNo + ": expected at least 3 tab-separated fields");
            }
            String srcText = f[0].trim();
            String dstText = f[1];
            String script = f[2].trim();

            if (srcText.isEmpty() || dstText.isEmpty()) {
                throw new IllegalStateException(tsv + ":" + lineNo + ": empty source or target");
            }
            int cp;
            if (srcText.length() == 1) {
                cp = srcText.codePointAt(0);
            } else if (srcText.startsWith("U+") || srcText.startsWith("u+")) {
                cp = Integer.parseInt(srcText.substring(2), 16);
            } else {
                throw new IllegalStateException(
                        tsv + ":" + lineNo + ": source must be one char or U+XXXX, found '" + srcText + "'");
            }
            if (!Character.isDefined(cp)) {
                throw new IllegalStateException(
                        tsv + ":" + lineNo + ": U+" + Integer.toHexString(cp) + " is not a code point");
            }
            if (srcText.length() == 1 && srcText.codePointAt(0) != cp) {
                throw new IllegalStateException(tsv + ":" + lineNo + ": source literal does not match U+");
            }

            String prior = claimed.get(cp);
            if (prior != null && !prior.equals(dstText)) {
                throw new IllegalStateException(tsv + ":" + lineNo
                        + ": U+" + hex(cp) + " is claimed to map to both '" + prior
                        + "' and '" + dstText + "'");
            }
            claimed.put(cp, dstText);
            fold.put(cp, dstText);
            scripts.put(cp, script);
        }

        if (fold.isEmpty()) {
            throw new IllegalStateException("confusables table is empty: " + tsv);
        }

        TextNormalizer n = new TextNormalizer(fold, scripts, tsv);
        n.verifyIdempotent(tsv);
        return n;
    }

    /**
     * Folding must be a projection: folding a target must return the target unchanged.
     * Checked over every row plus every target, so a two-character target like "bl" is
     * validated as a whole, not character by character.
     */
    private void verifyIdempotent(Path tsv) {
        for (Map.Entry<Integer, String> e : fold.entrySet()) {
            String round = foldString(e.getValue());
            if (!round.equals(e.getValue())) {
                throw new IllegalStateException(tsv + ": U+" + hex(e.getKey()) + " maps to '"
                        + e.getValue() + "' which folds again to '" + round
                        + "'; normalise() would not be idempotent");
            }
        }
    }

    // ==================================================================
    // The four normalisation stages
    // ==================================================================

    /** Stages 1-4. Returns the skeleton. Null in, empty out. */
    public String normalise(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        String s1 = Normalizer.normalize(s, Normalizer.Form.NFKC);
        String s2 = stripInvisibles(s1);
        String s3 = foldString(s2);
        return s3.toLowerCase(Locale.ROOT);
    }

    /**
     * Strip zero-width, bidi-override and soft-hyphen characters.
     *
     * Iterates by CODE POINT, so a surrogate pair is tested and removed as one unit. A
     * charAt() loop would split a pair and leave a lone surrogate behind, which is exactly
     * the kind of malformed string that makes a later regex crawl.
     *
     * Deleted rather than replaced with a space: "pay<ZWSP>pal" and "paypal" must become the
     * same token, and a space would leave "pay pal" - a different token.
     */
    static String stripInvisibles(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (isInvisible(cp)) {
                continue;
            }
            sb.appendCodePoint(cp);
        }
        return sb.toString();
    }

    private static boolean isInvisible(int cp) {
        switch (cp) {
            // Zero-width space, non-joiner, joiner, invisible times, invisible separator,
            // invisible plus, invisible minus, Mongolian vowel separator, word joiner.
            case 0x200B: case 0x200C: case 0x200D:
            case 0x2060: case 0x2061: case 0x2062: case 0x2063: case 0x2064:
            case 0x180E: case 0xFEFF:
            // Bidi embedding, override and isolate controls.
            case 0x202A: case 0x202B: case 0x202C: case 0x202D: case 0x202E:
            case 0x2066: case 0x2067: case 0x2068: case 0x2069:
            // Tag characters, used to smuggle text past naive filters.
            case 0xE0000: case 0xE0001: case 0xE0002: case 0xE0003: case 0xE0004:
            case 0xE0005: case 0xE0006: case 0xE0007: case 0xE0008: case 0xE0009:
            case 0xE000A: case 0xE000B: case 0xE000C: case 0xE000D: case 0xE000E:
            // Soft hyphen.
            case 0x00AD:
                return true;
            default:
                return false;
        }
    }

    /** Stage 3 in isolation, used by verifyIdempotent. */
    private String foldString(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            String t = fold.get(cp);
            if (t == null) {
                sb.appendCodePoint(cp);
            } else {
                sb.append(t);
            }
        }
        return sb.toString();
    }

    // ==================================================================
    // Derived features
    // ==================================================================

    /**
     * Fraction of characters that the folding stage changed. SCORING-MODEL.md L84.
     *
     * A position counts as changed exactly when it was replaced by a table entry. Every
     * target in the table is ASCII, so "was in the table" and "was disguised" are the same
     * predicate, and the ratio needs no string comparison at all.
     *
     * Counting this way avoids walking two strings in parallel, which is where the previous
     * implementation was wrong: it indexed the folded output with an offset into the source,
     * so once a substitution changed the length every subsequent comparison compared
     * unrelated characters. That reported 0.833 for the clean string "PayPal".
     *
     * Denominator is the NFKC, invisible-stripped length, so invisible padding cannot dilute
     * the ratio: a domain padded with 200 zero-width spaces is not "mostly clean". Returns 0
     * for an empty input, which the caller treats as "not observed" rather than "clean".
     */
    public double homoglyphRatio(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        String s2 = stripInvisibles(Normalizer.normalize(s, Normalizer.Form.NFKC));
        int total = 0;
        int changed = 0;
        int i = 0;
        while (i < s2.length()) {
            int cp = s2.codePointAt(i);
            i += Character.charCount(cp);
            total++;
            if (fold.containsKey(cp)) {
                changed++;
            }
        }
        if (total == 0) {
            return 0.0;
        }
        return Math.min(1.0, (double) changed / (double) total);
    }

    /**
     * True when the string mixes Latin with Cyrillic or Greek, or mixes two of those scripts.
     * SCORING-MODEL.md L88.
     *
     * Detection is driven by the FOLD TABLE first, then by Character.UnicodeScript. Both are
     * needed, and the reason is specific: UTS #39 lists confusables that UnicodeScript reports
     * as COMMON or as LATIN. U+1D0F LATIN LETTER SMALL CAPITAL O, U+217C SMALL ROMAN NUMERAL
     * FIFTY and U+217E SMALL ROMAN NUMERAL FIVE HUNDRED are all Latin-script to
     * UnicodeScript, yet all three are deliberate lookalikes used in real phishing domains.
     * A script-only rule passes all three, which is precisely the evasion that
     * corpus/evasion/ exists to catch. Anything in the fold table is therefore treated as
     * "disguised Latin" and drives the mixed-script decision.
     *
     * CJK, Arabic, Devanagari and digits are ignored rather than treated as "other": a
     * legitimate Japanese subject line must not read as mixed-script, or every
     * international sender becomes a lookalike candidate. A label of a single non-Latin
     * script returns false, since "all Cyrillic" is a language, not a mixing signal.
     * Returns false below two qualifying code points so a stray accent cannot trip it.
     */
    public boolean mixedScript(String s) {
        if (s == null) {
            return false;
        }
        String s1 = stripInvisibles(Normalizer.normalize(s, Normalizer.Form.NFKC));
        boolean sawLatin = false;
        boolean sawOther = false;
        int qualifying = 0;
        int i = 0;
        while (i < s1.length()) {
            int cp = s1.codePointAt(i);
            i += Character.charCount(cp);
            if (!Character.isLetter(cp)) {
                continue;
            }
            Character.UnicodeScript sc = Character.UnicodeScript.of(cp);
            boolean isCyrillicOrGreek = (sc == Character.UnicodeScript.CYRILLIC)
                    || (sc == Character.UnicodeScript.GREEK);
            // A table entry that UnicodeScript does not already call Cyrillic or Greek counts
            // as disguised Latin. That covers Latin (U+1D0F, U+217C) and other scripts the
            // table folds to ASCII (Cherokee U+13A0 -> g), without ever reclassifying a
            // genuinely Cyrillic or Greek letter as Latin - which is what an earlier version
            // of this method did, and it silently reported mixed_script=false for
            // "p\u0430ypal.com", the exact case the rule exists to catch.
            boolean latin = (sc == Character.UnicodeScript.LATIN)
                    || (!isCyrillicOrGreek && isFoldedLatin(cp));
            boolean other = isCyrillicOrGreek;
            if (latin) {
                sawLatin = true;
                qualifying++;
            } else if (other) {
                sawOther = true;
                qualifying++;
            } else {
                continue; // CJK, Arabic, Devanagari, ... not a mixing signal
            }
            if (qualifying >= 2 && sawLatin && sawOther) {
                return true;
            }
        }
        return false;
    }

    /**
     * True when the code point is a table entry whose target is ASCII, i.e. it is Latin
     * wearing a costume. Excludes the leet rows, which map a digit to a letter: a digit is
     * not a script, and counting "0" as Latin would make every code-number subject
     * mixed-script. See data/confusables.tsv for the provenance of the distinction.
     */
    private boolean isFoldedLatin(int cp) {
        String script = scriptOf.get(cp);
        if (script == null || script.equals("leet")) {
            return false;
        }
        String t = fold.get(cp);
        if (t == null) {
            return false;
        }
        for (int j = 0; j < t.length(); j++) {
            if (t.charAt(j) > 0x7f) {
                return false;
            }
        }
        return true;
    }

    /**
     * Script label from the table when the character is a known confusable, else from
     * UnicodeScript. Kept separate from mixedScript so callers can report WHY a label was
     * flagged rather than only that it was.
     */
    public String scriptOf(int cp) {
        String fromTable = scriptOf.get(cp);
        if (fromTable != null && !fromTable.equals("Latn") && !fromTable.equals("leet")) {
            return fromTable;
        }
        Character.UnicodeScript sc = Character.UnicodeScript.of(cp);
        switch (sc) {
            case LATIN:  return "Latn";
            case CYRILLIC: return "Cyr";
            case GREEK:  return "Grek";
            case COMMON: case INHERITED: case UNKNOWN: return "Zyyy";
            default: return sc.name();
        }
    }

    /** Which scripts appear in the string, for the report. Deterministic order. */
    public Map<String, Integer> scriptHistogram(String s) {
        Map<String, Integer> hist = new LinkedHashMap<>();
        if (s == null) {
            return hist;
        }
        String s1 = stripInvisibles(Normalizer.normalize(s, Normalizer.Form.NFKC));
        int i = 0;
        while (i < s1.length()) {
            int cp = s1.codePointAt(i);
            i += Character.charCount(cp);
            if (Character.isLetter(cp)) {
                hist.merge(scriptOf(cp), 1, Integer::sum);
            }
        }
        return hist;
    }

    /** Path the table was loaded from, for the evidence record. */
    public Path source() {
        return source;
    }

    public int mappingCount() {
        return fold.size();
    }

    /** UTS #39 name of a code point, or "U+XXXX" when unassigned. */
    public static String nameOf(int cp) {
        return Character.isDefined(cp) ? Character.getName(cp) : "U+" + hex(cp);
    }

    private static String hex(int cp) {
        return String.format(Locale.ROOT, "%04X", cp);
    }

    /** Standalone self-check: java TextNormalizer. */
    public static void main(String[] args) {
        TextNormalizer n = load();
        System.out.println("confusables: " + n.mappingCount() + " mappings from " + n.source());
        String[] probes = {
                "PayPal", "p\u0430ypal.com", "p\u0430\u044Bpal.com", "pаypаl.com",
                "\uFF30\uFF41\uFF59\uFF30\uFF41\uFF4C", "раypal.com", "\u03C1aypal.com",
                "g\u043E\u043Egle.com", "micros\u043Eft.com"
        };
        for (String p : probes) {
            System.out.printf("  %-34s -> %-24s ratio=%.3f mixed=%s%n",
                    printable(p), n.normalise(p), n.homoglyphRatio(p), n.mixedScript(p));
        }
    }

    private static String printable(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
