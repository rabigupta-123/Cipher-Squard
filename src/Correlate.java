/**
 * Campaign correlation across parsed messages. Phase 2 deliverable.
 *
 * Correlating messages is the step where analytical mistakes become expensive, because a
 * cluster is the unit people act on. Two decisions shape this implementation:
 *
 * 1. NO COMPONENT IS HIDDEN. {@link PairScore} carries every individual similarity that was
 *    computed - six Jaccard components and two cosine components - alongside the combined
 *    number. A combined score on its own invites the reader to accept a threshold decision they
 *    cannot audit. Exposing the parts means a reviewer can see that a pair linked on URLs
 *    rather than on shared infrastructure, and judge that for themselves.
 *
 * 2. SIMILARITY IS NOT IDENTITY. These scores measure how alike two messages are in specific,
 *    named ways. They do not establish a common operator. The output carries an explicit
 *    statement of that limit, and the linkage reason is reported next to the score rather than
 *    being inferred from it.
 *
 * Empty-input handling is explicit rather than delegated to arithmetic. Jaccard of two empty
 * sets is defined here as 0.0, not NaN and not 1.0. Treating two empty sets as identical would
 * collapse every message that failed to parse into one giant "identical" cluster, which is the
 * most damaging possible failure for this component.
 *
 * Bounding: token counts, vocabulary size, document count, and every input string are capped.
 * Correlation runs over attacker-influenced content, so unbounded tokenization is a
 * denial-of-service surface, not a theoretical concern.
 */
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public final class Correlate {

    /** Default linkage threshold, matching the project configuration. */
    public static final double DEFAULT_THRESHOLD = 0.62;

    /** The limit on what these scores mean. Carried on every aggregate result. */
    public static final String DISCLAIMER =
            "Similarity scores measure how alike messages are in specific, named dimensions "
                    + "(shared addresses, domains, URLs, file types, subject and body text). A cluster "
                    + "indicates shared observable characteristics only. It does not establish a common "
                    + "actor, attribution, or intent: shared infrastructure, common providers, and "
                    + "reused boilerplate can all produce high similarity between unrelated senders.";

    public static String disclaimer() {
        return DISCLAIMER;
    }

    // ==================================================================
    // Bounds
    // ==================================================================

    /** Max distinct tokens kept per document. Prevents one huge body from dominating a pair. */
    public static final int MAX_TOKENS_PER_DOC = 4000;
    /** Max distinct terms tracked corpus-wide for IDF. */
    public static final int MAX_VOCAB = 50_000;
    /** Max documents in one correlation run. O(n^2) pairwise scoring needs a ceiling. */
    public static final int MAX_DOCUMENTS = 500;

    /**
     * Ceiling on the number of token-lists {@link #buildIdf} will fold into a document-frequency
     * table.
     *
     * The bound is the message ceiling, because {@link #pairwise} contributes exactly one
     * token-list per message. Document frequency is a property of the message set: a term that
     * appears in a message counts once for that message no matter how many fields of it the term
     * appears in. So the IDF corpus is the messages, and this ceiling can never truncate a
     * legitimate run.
     *
     * The defensive multiple of two exists only for direct callers of {@link #buildIdf} who pass
     * their own list, so an oversized external corpus is bounded rather than folded in full.
     */
    private static final int MAX_IDF_DOCUMENTS = 2 * MAX_DOCUMENTS;
    /** Max characters of any single input string. */
    public static final int MAX_INPUT_CHARS = 1_000_000;
    /** Tokens shorter or longer than this are dropped as uninformative. */
    public static final int MIN_TOKEN_LEN = 2;
    public static final int MAX_TOKEN_LEN = 32;
    /** Max distinct values per feature set. */
    public static final int MAX_SET_SIZE = 512;

    // ==================================================================
    // Tokenization
    // ==================================================================

    /**
     * Lowercases and splits on non-alphanumeric characters, dropping out-of-range token lengths.
     * Single pass, no regex, no backtracking, bounded output.
     *
     * Digits are kept: invoice numbers, amounts, and account fragments are frequently the most
     * discriminative tokens in a business-email campaign.
     */
    public static List<String> tokenize(String text) {
        List<String> out = new ArrayList<>();
        if (text == null || text.isEmpty()) return out;
        int n = Math.min(text.length(), MAX_INPUT_CHARS);
        int start = -1;
        for (int i = 0; i <= n; i++) {
            char c = (i < n) ? text.charAt(i) : ' ';
            boolean wordChar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (wordChar) {
                if (start < 0) start = i;
            } else if (start >= 0) {
                int len = i - start;
                if (len >= MIN_TOKEN_LEN && len <= MAX_TOKEN_LEN) {
                    if (out.size() < MAX_TOKENS_PER_DOC) {
                        out.add(text.substring(start, i).toLowerCase(Locale.ROOT));
                    }
                }
                start = -1;
            }
        }
        return out;
    }

    /** Distinct tokens, bounded and deterministically ordered. */
    public static Set<String> tokenSet(String text) {
        return new TreeSet<>(tokenize(text));
    }

    /** Bounded distinct set from a list, preserving nothing but the values. */
    public static Set<String> boundedSet(Iterable<String> values, int cap) {
        Set<String> out = new LinkedHashSet<>();
        if (values == null) return out;
        for (String v : values) {
            if (v == null) continue;
            String t = v.trim();
            if (t.isEmpty()) continue;
            if (out.size() >= cap) break;
            out.add(t);
        }
        return out;
    }

    // ==================================================================
    // Jaccard
    // ==================================================================

    /**
     * Jaccard similarity: |A n B| / |A u B|.
     *
     * Empty handling is defined, not incidental:
     *   - either set empty -> 0.0. Two messages that share no observable features are not
     *     similar, and one that failed to parse must not be declared similar to anything.
     *   - both empty -> 0.0, not 1.0. "Both have nothing" is an absence of evidence, and scoring
     *     it as perfect identity would fuse every empty document into one cluster.
     */
    public static double jaccard(Set<String> a, Set<String> b) {
        if (a == null || b == null) return 0.0;
        int as = a.size();
        int bs = b.size();
        if (as == 0 || bs == 0) return 0.0;
        if (as > MAX_SET_SIZE) a = head(a);
        if (bs > MAX_SET_SIZE) b = head(b);
        int inter = 0;
        Set<String> small = (a.size() <= b.size()) ? a : b;
        Set<String> large = (a.size() <= b.size()) ? b : a;
        for (String s : small) {
            if (large.contains(s)) inter++;
        }
        int union = a.size() + b.size() - inter;
        if (union <= 0) return 0.0;
        return (double) inter / (double) union;
    }

    private static Set<String> head(Set<String> s) {
        Set<String> out = new LinkedHashSet<>();
        int i = 0;
        for (String v : s) {
            if (i++ >= MAX_SET_SIZE) break;
            out.add(v);
        }
        return out;
    }

    // ==================================================================
    // TF-IDF / cosine
    // ==================================================================

    /**
     * An L2-normalised sparse term-weight vector.
     *
     * The zero vector is representable rather than excluded, because an all-stopword document
     * produces one legitimately. Cosine against it is defined as 0.0 instead of NaN - see
     * {@link #cosine}.
     */
    public static final class Vector {
        public final Map<String, Double> weights;
        public final double norm;
        public final int rawTermCount;

        Vector(Map<String, Double> weights, double norm, int rawTermCount) {
            this.weights = Collections.unmodifiableMap(weights);
            this.norm = norm;
            this.rawTermCount = rawTermCount;
        }

        public boolean isZero() {
            return norm == 0.0;
        }
    }

    /**
     * Smoothed inverse document frequency, built once per correlation run.
     *
     * idf(t) = ln((N + 1) / (df(t) + 1)) + 1
     *
     * The +1 on both sides keeps the log argument above 1, so a term appearing in every document
     * still gets a strictly positive weight and the arithmetic can never produce NaN or a
     * negative weight for a real term.
     */
    public static Map<String, Double> buildIdf(List<List<String>> documents) {
        Map<String, Integer> df = new TreeMap<>();
        int n = documents == null ? 0 : documents.size();
        if (n == 0) return Collections.emptyMap();
        int capped = Math.min(n, MAX_IDF_DOCUMENTS);
        for (int i = 0; i < capped; i++) {
            List<String> doc = documents.get(i);
            if (doc == null) continue;
            Set<String> seen = new TreeSet<>();
            for (String t : doc) {
                if (t == null || t.isEmpty()) continue;
                seen.add(t);
                if (df.size() >= MAX_VOCAB && !df.containsKey(t)) continue;
            }
            for (String t : seen) {
                df.merge(t, 1, Integer::sum);
            }
        }
        Map<String, Double> idf = new TreeMap<>();
        for (Map.Entry<String, Integer> e : df.entrySet()) {
            idf.put(e.getKey(), Math.log((capped + 1.0) / (e.getValue() + 1.0)) + 1.0);
        }
        return idf;
    }

    /** Builds a normalised TF-IDF vector for one document. */
    public static Vector vectorize(List<String> tokens, Map<String, Double> idf) {
        Map<String, Double> tf = new TreeMap<>();
        int total = 0;
        if (tokens != null) {
            for (String t : tokens) {
                if (t == null || t.isEmpty()) continue;
                total++;
                if (tf.size() >= MAX_VOCAB && !tf.containsKey(t)) continue;
                tf.merge(t, 1.0, Double::sum);
            }
        }
        Map<String, Double> w = new TreeMap<>();
        double sumSq = 0.0;
        for (Map.Entry<String, Double> e : tf.entrySet()) {
            double idfVal = (idf == null) ? 1.0 : idf.getOrDefault(e.getKey(), 1.0);
            // Sublinear term frequency: the tenth occurrence of a word says far less than the first.
            double weight = (1.0 + Math.log(e.getValue())) * idfVal;
            w.put(e.getKey(), weight);
            sumSq += weight * weight;
        }
        double norm = Math.sqrt(sumSq);
        if (norm > 0.0) {
            for (Map.Entry<String, Double> e : w.entrySet()) {
                e.setValue(e.getValue() / norm);
            }
        }
        // Report the norm of the weights actually stored, not the pre-normalisation magnitude.
        // A field named 'norm' that is not the L2 norm of 'weights' is a trap for any caller
        // that checks it, and the pre-normalisation value is not recoverable from the map.
        return new Vector(w, norm > 0.0 ? 1.0 : 0.0, total);
    }

    public static Vector vectorize(String text, Map<String, Double> idf) {
        return vectorize(tokenize(text), idf);
    }

    /**
     * Cosine similarity of two L2-normalised vectors.
     *
     * If either vector has zero norm the result is 0.0, not NaN. That case is real: a document
     * consisting only of short tokens, or one that shares no vocabulary with the corpus, has no
     * direction, and 0 is the honest answer. Returning NaN here would silently poison every
     * threshold comparison downstream, since NaN compares false against everything.
     */
    public static double cosine(Vector a, Vector b) {
        if (a == null || b == null) return 0.0;
        if (a.isZero() || b.isZero()) return 0.0;
        // Iterate the smaller map.
        Map<String, Double> small = a.weights.size() <= b.weights.size() ? a.weights : b.weights;
        Map<String, Double> large = a.weights.size() <= b.weights.size() ? b.weights : a.weights;
        double dot = 0.0;
        for (Map.Entry<String, Double> e : small.entrySet()) {
            Double other = large.get(e.getKey());
            if (other != null) dot += e.getValue() * other;
        }
        // Clamp: accumulated floating-point error can push a self-comparison a hair above 1.
        if (dot < 0.0) return 0.0;
        if (dot > 1.0) return 1.0;
        return dot;
    }

    // ==================================================================
    // Document model
    // ==================================================================

    /**
     * The comparable view of one message. Deliberately separate from the parser's types so the
     * scoring functions can be exercised directly, and so a caller can supply features from a
     * source other than a raw message.
     */
    public static final class Document {
        public final String id;
        public final Set<String> addresses;
        public final Set<String> domains;
        public final Set<String> urls;
        public final Set<String> fileTypes;
        /**
         * Header NAMES present, lowercased. The structural fingerprint of a message: two emails
         * from the same toolkit tend to carry the same unusual header set even when every value
         * differs, which is why this is a scored term and not just a diagnostic.
         */
        public final Set<String> headerNames;
        /**
         * SHA-256 (hex) of each attachment's decoded bytes. The strongest single phishing-kit
         * signal available: a reused malicious attachment hashes identically across a campaign
         * even when every textual feature has been rewritten.
         */
        public final Set<String> attachmentHashes;
        public final String subject;
        public final String body;
        /** Final blended risk in [0,100] for this message, or NaN when not scored. */
        public final double risk;
        /** Combined confidence in [0,1] for this message, or NaN when not scored. */
        public final double confidence;
        /** Observed time in epoch millis, or Long.MIN_VALUE when unknown. */
        public final long observedAt;

        /**
         * Convenience for a document with no observable header-name or attachment-hash evidence.
         * Both scored terms then evaluate to 0, which is the correct result for absent evidence
         * rather than a silent full score.
         */
        public Document(String id, Set<String> addresses, Set<String> domains, Set<String> urls,
                        Set<String> fileTypes, String subject, String body) {
            this(id, addresses, domains, urls, fileTypes, Set.of(), Set.of(), subject, body);
        }

        public Document(String id, Set<String> addresses, Set<String> domains, Set<String> urls,
                        Set<String> fileTypes, Set<String> headerNames,
                        Set<String> attachmentHashes, String subject, String body) {
            this(id, addresses, domains, urls, fileTypes, headerNames, attachmentHashes,
                    subject, body, Double.NaN, Double.NaN, Long.MIN_VALUE);
        }

        public Document(String id, Set<String> addresses, Set<String> domains, Set<String> urls,
                        Set<String> fileTypes, Set<String> headerNames,
                        Set<String> attachmentHashes, String subject, String body,
                        double risk, double confidence, long observedAt) {
            this.id = (id == null || id.isBlank()) ? "doc" : id;
            this.addresses = copySet(addresses);
            this.domains = copySet(domains);
            this.urls = copySet(urls);
            this.fileTypes = copySet(fileTypes);
            this.headerNames = copySet(headerNames);
            this.attachmentHashes = copySet(attachmentHashes);
            this.subject = truncate(subject);
            this.body = truncate(body);
            this.risk = (Double.isNaN(risk)) ? risk : Math.max(0.0, Math.min(100.0, risk));
            this.confidence = (Double.isNaN(confidence)) ? confidence
                    : Math.max(0.0, Math.min(1.0, confidence));
            this.observedAt = observedAt;
        }

        private static String truncate(String s) {
            if (s == null) return "";
            return s.length() <= MAX_INPUT_CHARS ? s : s.substring(0, MAX_INPUT_CHARS);
        }

        private static Set<String> copySet(Set<String> s) {
            return boundedSet(s == null ? List.of() : s, MAX_SET_SIZE);
        }

        public List<String> subjectTokens() {
            return tokenize(subject);
        }

        public List<String> bodyTokens() {
            return tokenize(body);
        }

        /**
         * The text stream the content term is computed over: subject and body together. The
         * similarity model defines one text channel, not two, so subject and body are combined
         * here rather than scored separately and averaged.
         */
        public List<String> textTokens() {
            List<String> out = new ArrayList<>(subjectTokens());
            out.addAll(bodyTokens());
            return out;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("addresses", addresses);
            m.put("domains", domains);
            m.put("urls", urls);
            m.put("fileTypes", fileTypes);
            m.put("headerNames", headerNames);
            m.put("attachmentHashes", attachmentHashes);
            m.put("subjectChars", subject.length());
            m.put("bodyChars", body.length());
            m.put("risk", Double.isNaN(risk) ? null : risk);
            m.put("confidence", Double.isNaN(confidence) ? null : confidence);
            m.put("observedAt", observedAt == Long.MIN_VALUE ? null : observedAt);
            return m;
        }
    }

    /** Flattens a message plus its attribution result into a {@link Document}. */
    public static Document documentOf(String id, EmailParser.Message m, Attribution.Result attr) {
        Set<String> addresses = new TreeSet<>();
        Set<String> domains = new TreeSet<>();
        Set<String> urls = new TreeSet<>();
        Set<String> fileTypes = new TreeSet<>();
        Set<String> headerNames = new TreeSet<>();
        Set<String> hashes = new TreeSet<>();
        long observedAt = Long.MIN_VALUE;

        if (m != null) {
            if (m.headerList != null) {
                for (EmailParser.Header h : m.headerList) {
                    if (h != null && h.name != null && !h.name.isBlank()) {
                        headerNames.add(h.name.trim().toLowerCase(Locale.ROOT));
                    }
                }
            } else if (m.headers != null) {
                for (String k : m.headers.keySet()) {
                    if (k != null && !k.isBlank()) headerNames.add(k.trim().toLowerCase(Locale.ROOT));
                }
            }
            if (m.hops != null) {
                for (EmailParser.ReceivedHop h : m.hops) {
                    if (h.ip != null && !h.ip.isBlank()) addresses.add(h.ip);
                    if (h.timestampMillis != Long.MIN_VALUE
                            && (observedAt == Long.MIN_VALUE || h.timestampMillis < observedAt)) {
                        observedAt = h.timestampMillis;
                    }
                }
            }
            if (m.urls != null) urls.addAll(m.urls);
            if (m.from != null) {
                for (EmailParser.Address a : m.from) {
                    if (a.domain != null) domains.add(a.domain.toLowerCase(Locale.ROOT));
                }
            }
            if (m.returnPath != null) {
                for (EmailParser.Address a :
                        EmailParser.parseAddressList(m.returnPath, 0, 8)) {
                    if (a.domain != null) domains.add(a.domain.toLowerCase(Locale.ROOT));
                }
            }
            if (m.parts != null) {
                for (EmailParser.Part p : m.parts) {
                    if (!p.isAttachment) continue;
                    if (p.contentType != null && !p.contentType.isBlank()) {
                        fileTypes.add(p.contentType.toLowerCase(Locale.ROOT));
                    }
                    String h = contentHash(p);
                    if (h != null) hashes.add(h);
                }
            }
        }
        if (attr != null && attr.primaryIp != null) addresses.add(attr.primaryIp);

        double risk = Double.NaN;
        double confidence = Double.NaN;
        if (attr != null && attr.confidence != null) confidence = attr.confidence.value;

        return new Document(id, addresses, domains, urls, fileTypes, headerNames, hashes,
                m == null ? "" : m.subject, bodyTextOf(m), risk, confidence, observedAt);
    }

    /** Largest attachment payload that is hashed. Bounded so scoring stays predictable. */
    public static final int MAX_HASH_BYTES = 8 * 1024 * 1024;

    /**
     * SHA-256 of an attachment's decoded bytes, lowercased hex. Returns null when there is nothing
     * to hash, so an absent hash is never confused with the hash of empty content.
     */
    public static String contentHash(EmailParser.Part p) {
        if (p == null || p.data == null || p.data.length == 0) return null;
        byte[] buf = p.data;
        if (buf.length > MAX_HASH_BYTES) {
            // Hash a bounded prefix and mark it, so two different oversized attachments of the
            // same prefix cannot be reported as an exact match.
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                md.update(buf, 0, MAX_HASH_BYTES);
                return "sha256:" + hex(md.digest()) + ":prefix" + MAX_HASH_BYTES;
            } catch (java.security.NoSuchAlgorithmException e) {
                return null;
            }
        }
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return "sha256:" + hex(md.digest(buf));
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the platform; if it is somehow absent, report nothing
            // rather than substituting a weaker or invented digest.
            return null;
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16));
            sb.append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    /** Concatenates the decoded text of non-attachment parts, bounded. */
    public static String bodyTextOf(EmailParser.Message m) {
        if (m == null || m.parts == null) return "";
        StringBuilder sb = new StringBuilder();
        int budget = MAX_INPUT_CHARS;
        for (EmailParser.Part p : m.parts) {
            if (p == null || p.isAttachment || p.isContainer || p.data == null) continue;
            if (sb.length() >= budget) break;
            String ct = p.contentType == null ? "" : p.contentType.toLowerCase(Locale.ROOT);
            if (!ct.startsWith("text/")) continue;
            // Respect the declared charset when it is one we can decode; otherwise ISO-8859-1,
            // which never throws and preserves the byte values for later inspection.
            String cs = "ISO-8859-1";
            if (p.charset != null) {
                try {
                    java.nio.charset.Charset c = java.nio.charset.Charset.forName(p.charset);
                    cs = c.name();
                } catch (RuntimeException ignored) {
                    // Unknown charset: fall through to the lossless default rather than guessing.
                    cs = "ISO-8859-1";
                }
            }
            try {
                sb.append(new String(p.data, java.nio.charset.Charset.forName(cs)));
            } catch (RuntimeException ignored) {
                sb.append(new String(p.data, java.nio.charset.StandardCharsets.ISO_8859_1));
            }
            if (sb.length() > budget) {
                sb.setLength(budget);
                break;
            }
        }
        return sb.toString();
    }

    // ==================================================================
    // Pairwise scoring
    // ==================================================================

    /**
     * Every component similarity for one pair, plus the combined score and the reason it
     * combined that way. The components are public fields on purpose: this is the audit surface.
     */
    public static final class PairScore {
        public final String idA;
        public final String idB;
        public final double jaccardAddresses;
        public final double jaccardDomains;
        public final double jaccardUrls;
        public final double jaccardFileTypes;
        public final double jaccardSubject;
        public final double jaccardBody;
        public final double cosineSubject;
        public final double cosineBody;
        /** J(headers) - the scored structural-fingerprint term. */
        public final double jaccardHeaders;
        /** J(attachment_hashes) - the scored shared-attachment term. */
        public final double jaccardAttachmentHashes;
        /** cos(tfidf(text)) over subject+body - the scored content term. */
        public final double cosineText;
        /** Infrastructure roll-up, retained for reporting: J(domains) and J(ips) together. */
        public final double infrastructure;
        /** Content roll-up, retained for reporting. */
        public final double content;
        public final double combined;
        /** Highest-contributing component, for a human-readable linkage reason. */
        public final String dominantComponent;
        public final boolean linked;

        PairScore(String idA, String idB, double jaccardAddresses, double jaccardDomains,
                  double jaccardUrls, double jaccardFileTypes, double jaccardSubject,
                  double jaccardBody, double cosineSubject, double cosineBody,
                  double jaccardHeaders, double jaccardAttachmentHashes, double cosineText,
                  double infrastructure, double content, double combined,
                  String dominantComponent, boolean linked) {
            this.idA = idA;
            this.idB = idB;
            this.jaccardAddresses = jaccardAddresses;
            this.jaccardDomains = jaccardDomains;
            this.jaccardUrls = jaccardUrls;
            this.jaccardFileTypes = jaccardFileTypes;
            this.jaccardSubject = jaccardSubject;
            this.jaccardBody = jaccardBody;
            this.cosineSubject = cosineSubject;
            this.cosineBody = cosineBody;
            this.jaccardHeaders = jaccardHeaders;
            this.jaccardAttachmentHashes = jaccardAttachmentHashes;
            this.cosineText = cosineText;
            this.infrastructure = infrastructure;
            this.content = content;
            this.combined = combined;
            this.dominantComponent = dominantComponent;
            this.linked = linked;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("a", idA);
            m.put("b", idB);
            m.put("jaccard.addresses", round(jaccardAddresses));
            m.put("jaccard.domains", round(jaccardDomains));
            m.put("jaccard.urls", round(jaccardUrls));
            m.put("jaccard.fileTypes", round(jaccardFileTypes));
            m.put("jaccard.subject", round(jaccardSubject));
            m.put("jaccard.body", round(jaccardBody));
            m.put("cosine.subject", round(cosineSubject));
            m.put("cosine.body", round(cosineBody));
            m.put("scored.jaccard.headers", round(jaccardHeaders));
            m.put("scored.jaccard.attachmentHashes", round(jaccardAttachmentHashes));
            m.put("scored.cosine.text", round(cosineText));
            m.put("scored.term.headerNames", W_HEADER_NAMES * jaccardHeaders);
            m.put("scored.term.domains", W_DOMAINS * jaccardDomains);
            m.put("scored.term.ips", W_IPS * jaccardAddresses);
            m.put("scored.term.text", W_TEXT * cosineText);
            m.put("scored.term.attachmentHashes", W_ATTACHMENT_HASHES * jaccardAttachmentHashes);
            m.put("infrastructure", round(infrastructure));
            m.put("content", round(content));
            m.put("combined", round(combined));
            m.put("dominantComponent", dominantComponent);
            m.put("linked", linked);
            return m;
        }

        @Override
        public String toString() {
            return idA + " ~ " + idB + " combined=" + round(combined)
                    + " (infra=" + round(infrastructure) + ", content=" + round(content)
                    + ", dominant=" + dominantComponent + ", linked=" + linked + ")";
        }
    }

    private static double round(double d) {
        return Math.round(d * 10000.0) / 10000.0;
    }

    /**
     * Weights for the combined score, exactly as specified:
     *
     * <pre>
     * sim = 0.25*J(headers) + 0.30*J(domains) + 0.20*J(ips)
     *     + 0.20*cos(tfidf(text)) + 0.05*J(attachment_hashes)
     * </pre>
     *
     * They sum to 1, so {@code combined} lands in [0,1] without further scaling. Domains are
     * weighted above addresses because a reused sending domain is harder to accidental than a
     * shared relay or cloud address. The two smallest terms are the strongest when they fire:
     * an identical attachment hash is near-conclusive for a common kit, and a distinctive header
     * set is a toolkit fingerprint, so neither needs a large weight to matter.
     *
     * <p>The superseded form was {@code INFRA_WEIGHT*max(J(addr),J(dom)) +
     * CONTENT_WEIGHT*content}. It was replaced because it discarded the header-name and
     * attachment-hash terms entirely and could not reward agreement on both domain and address at
     * once, since {@code max} saturates. Those constants are kept only so older callers and
     * stored results remain readable.
     */
    public static final double W_HEADER_NAMES = 0.25;
    public static final double W_DOMAINS = 0.30;
    public static final double W_IPS = 0.20;
    public static final double W_TEXT = 0.20;
    public static final double W_ATTACHMENT_HASHES = 0.05;

    /** Superseded roll-up weights, retained for continuity of previously reported numbers. */
    public static final double INFRA_WEIGHT = 0.6;
    public static final double CONTENT_WEIGHT = 0.4;

    /**
     * Scores one pair in isolation, building IDF from those two documents only.
     *
     * Suitable for inspecting a single comparison. For anything comparative, use
     * {@link #pairwise} or {@link #analyze}, which build one corpus-wide IDF and share it across
     * every pair - a per-pair IDF would weight the same term differently in each comparison,
     * making the resulting cosine values impossible to compare across the run.
     */
    public static PairScore score(Document a, Document b, double threshold) {
        // One token-list per message, for the same reason as pairwise(): df counts messages.
        Map<String, Double> idf = buildIdf(List.of(a.textTokens(), b.textTokens()));
        return scoreWithIdf(a, b, threshold, idf);
    }

    static PairScore scoreWithIdf(Document a, Document b, double threshold, Map<String, Double> idf) {
        double jAddr = jaccard(a.addresses, b.addresses);
        double jDom = jaccard(a.domains, b.domains);
        double jUrl = jaccard(a.urls, b.urls);
        double jFile = jaccard(a.fileTypes, b.fileTypes);

        Set<String> sa = new TreeSet<>(a.subjectTokens());
        Set<String> sb = new TreeSet<>(b.subjectTokens());
        Set<String> ba = new TreeSet<>(a.bodyTokens());
        Set<String> bb = new TreeSet<>(b.bodyTokens());
        double jSub = jaccard(sa, sb);
        double jBody = jaccard(ba, bb);

        double cosSub = cosine(vectorize(a.subjectTokens(), idf), vectorize(b.subjectTokens(), idf));
        double cosBody = cosine(vectorize(a.bodyTokens(), idf), vectorize(b.bodyTokens(), idf));

        // The three scored terms that the earlier roll-up had discarded or collapsed.
        double jHdr = jaccard(a.headerNames, b.headerNames);
        double jHash = jaccard(a.attachmentHashes, b.attachmentHashes);
        double cosText = cosine(vectorize(a.textTokens(), idf), vectorize(b.textTokens(), idf));

        // The specified combination:
        //   0.25*J(headers) + 0.30*J(domains) + 0.20*J(ips)
        //        + 0.20*cos(tfidf(text)) + 0.05*J(attachment_hashes)
        // All five terms are additive and all weights sum to 1, so two emails agreeing on both
        // domain and address score strictly higher than either alone. The earlier max(infra,
        // content) form could not express that, and it discarded the header and attachment terms
        // entirely - which is where a reused phishing-kit attachment would have shown up.
        double combined = W_HEADER_NAMES * jHdr
                + W_DOMAINS * jDom
                + W_IPS * jAddr
                + W_TEXT * cosText
                + W_ATTACHMENT_HASHES * jHash;
        combined = Math.max(0.0, Math.min(1.0, combined));

        // Reporting roll-ups, no longer load-bearing for the score itself.
        double infra = Math.max(jAddr, jDom);
        double content = 0.5 * jBody + 0.5 * cosBody;

        String dominant = dominantComponent(jHdr, jHash, cosText, jAddr, jDom, jUrl, jFile, jSub,
                jBody, cosSub, cosBody);
        return new PairScore(a.id, b.id, jAddr, jDom, jUrl, jFile, jSub, jBody, cosSub, cosBody,
                jHdr, jHash, cosText, infra, content, combined, dominant, combined >= threshold);
    }

    private static String dominantComponent(double jHdr, double jHash, double cosText,
                                            double jAddr, double jDom, double jUrl, double jFile,
                                            double jSub, double jBody, double cosSub, double cosBody) {
        String best = "none";
        double bestV = 0.0;
        double[] vals = {jHdr, jHash, cosText, jAddr, jDom, jUrl, jFile, jSub, jBody, cosSub, cosBody};
        String[] names = {"header-names", "attachment-hashes", "text-tfidf", "addresses", "domains",
                "urls", "fileTypes", "subject-set", "body-set", "subject-tfidf", "body-tfidf"};
        for (int i = 0; i < vals.length; i++) {
            if (vals[i] > bestV) {
                bestV = vals[i];
                best = names[i];
            }
        }
        return bestV == 0.0 ? "none" : best;
    }

    /**
     * Scores every pair in a corpus. O(n^2) with n bounded by {@link #MAX_DOCUMENTS}; exceeding
     * the bound is reported in the returned list rather than silently truncating the input,
     * because a truncated corpus would produce a plausible-looking but incomplete cluster set.
     */
    public static List<PairScore> pairwise(List<Document> docs, double threshold) {
        List<PairScore> out = new ArrayList<>();
        if (docs == null) return out;
        int n = Math.min(docs.size(), MAX_DOCUMENTS);
        // One corpus-wide IDF shared by every pair, so term weights - and therefore the cosine
        // values - mean the same thing in every comparison in this run.
        //
        // One token-list per message, not per field. The scored term is
        // cos(tfidf(subject+body)), so subject+body is the document that term weights must be
        // fitted on, and df must count each message once: feeding subject, body and the combined
        // stream separately would triple N, let a term in a single message accrue df up to 3, and
        // - because that triples the corpus past MAX_IDF_DOCUMENTS - silently drop the combined
        // streams entirely once the run grew. The subject-only and body-only cosines remain
        // available as diagnostics; they are reported, not scored, so they borrow the weights
        // derived from the field they actually came from.
        List<List<String>> all = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            all.add(docs.get(i).textTokens());
        }
        Map<String, Double> idf = buildIdf(all);
        for (int i = 0; i < n; i++) {
            for (int j = i + 1; j < n; j++) {
                out.add(scoreWithIdf(docs.get(i), docs.get(j), threshold, idf));
            }
        }
        return out;
    }

    // ==================================================================
    // Clustering
    // ==================================================================

    /**
     * A group of documents joined by at least one pair at or above the threshold.
     *
     * Transitive closure via union-find. That is a real analytical property and a real risk: A
     * links to B, B links to C, but A and C may be dissimilar. {@link #weakestLink} reports the
     * minimum internal combined score so a reviewer can see how much the grouping leans on the
     * transitive step, instead of discovering it later.
     */
    public static final class Cluster {
        public final List<String> memberIds;
        public final double cohesion;
        /** Lowest combined score of ANY pair in the cluster, including below-threshold ones. */
        public final double weakestLink;
        public final String dominantComponent;

        /** Threshold that produced this cluster. Retained so reported linkage is never a constant. */
        public final double threshold;

        // ---- specified campaign aggregates -------------------------------------
        /** n_emails. Identical to {@link #size()}; named because the model reports it as such. */
        public final int nEmails;
        /**
         * Campaign risk by noisy-OR over member risks:
         * {@code 100 * (1 - PRODUCT_j (1 - risk_j/100))}.
         * NaN when no member carried a risk, because an unobserved risk is not zero risk.
         */
        public final double riskCampaign;
        /**
         * Mean member confidence, never the maximum. Reporting the max would let one confident
         * email speak for a whole campaign, which the model explicitly forbids.
         */
        public final double confidenceMean;
        /** Earliest observed member time in epoch millis, or Long.MIN_VALUE if none known. */
        public final long earliestObserved;
        /** Latest observed member time in epoch millis, or Long.MIN_VALUE if none known. */
        public final long latestObserved;

        Cluster(List<String> members, double cohesion, double weakest, String dominant, double threshold) {
            this(members, cohesion, weakest, dominant, threshold,
                    Double.NaN, Double.NaN, Long.MIN_VALUE, Long.MIN_VALUE);
        }

        Cluster(List<String> members, double cohesion, double weakest, String dominant, double threshold,
                double riskCampaign, double confidenceMean, long earliest, long latest) {
            this.memberIds = List.copyOf(members);
            this.cohesion = cohesion;
            this.weakestLink = weakest;
            this.dominantComponent = dominant;
            this.threshold = threshold;
            this.nEmails = this.memberIds.size();
            this.riskCampaign = riskCampaign;
            this.confidenceMean = confidenceMean;
            this.earliestObserved = earliest;
            this.latestObserved = latest;
        }

        public int size() {
            return memberIds.size();
        }

        /**
         * Noisy-OR over per-member risks in [0,100].
         *
         * A campaign of several medium-risk emails must not stay medium: independent weak signals
         * accumulate. A member with no observed risk is skipped rather than counted as 0, so an
         * unscored email cannot drag the campaign down. Returns NaN when nothing was scored.
         */
        public static double noisyOr(List<Double> risks) {
            if (risks == null || risks.isEmpty()) return Double.NaN;
            double survive = 1.0;
            boolean any = false;
            for (Double r : risks) {
                if (r == null || Double.isNaN(r)) continue;
                double c = Math.max(0.0, Math.min(100.0, r)) / 100.0;
                survive *= (1.0 - c);
                any = true;
            }
            if (!any) return Double.NaN;
            return 100.0 * (1.0 - survive);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("members", memberIds);
            m.put("size", memberIds.size());
            m.put("n_emails", nEmails);
            m.put("cohesion", round(cohesion));
            m.put("weakestInternalPair", round(weakestLink));
            m.put("weakestPairLinked", weakestLink >= threshold);
            m.put("threshold", round(threshold));
            m.put("dominantComponent", dominantComponent);
            m.put("risk_campaign", Double.isNaN(riskCampaign) ? null : round(riskCampaign));
            m.put("risk_campaign_display", Double.isNaN(riskCampaign) ? null
                    : String.format(Locale.ROOT, "%.1f", riskCampaign));
            m.put("confidence_mean", Double.isNaN(confidenceMean) ? null : round(confidenceMean));
            m.put("earliest_observed", earliestObserved == Long.MIN_VALUE ? null : earliestObserved);
            m.put("latest_observed", latestObserved == Long.MIN_VALUE ? null : latestObserved);
            return m;
        }

        @Override
        public String toString() {
            return "cluster" + memberIds + " cohesion=" + round(cohesion)
                    + " weakest=" + round(weakestLink)
                    + " n_emails=" + nEmails
                    + " risk_campaign=" + (Double.isNaN(riskCampaign) ? "n/a"
                            : String.format(Locale.ROOT, "%.2f", riskCampaign))
                    + " confidence_mean=" + (Double.isNaN(confidenceMean) ? "n/a"
                            : String.format(Locale.ROOT, "%.3f", confidenceMean));
        }
    }

    /** Union-find over document ids, with deterministic output ordering. */
    public static List<Cluster> cluster(List<PairScore> pairs, double threshold) {
        if (pairs == null || pairs.isEmpty()) return List.of();
        Map<String, String> parent = new TreeMap<>();
        for (PairScore p : pairs) {
            parent.putIfAbsent(p.idA, p.idA);
            parent.putIfAbsent(p.idB, p.idB);
        }
        for (PairScore p : pairs) {
            if (p.combined >= threshold) {
                String ra = find(parent, p.idA);
                String rb = find(parent, p.idB);
                if (!ra.equals(rb)) {
                    // Deterministic merge: the lexicographically smaller root wins, so the
                    // resulting grouping does not depend on pair iteration order.
                    if (ra.compareTo(rb) <= 0) parent.put(rb, ra);
                    else parent.put(ra, rb);
                }
            }
        }
        Map<String, List<String>> groups = new TreeMap<>();
        for (String id : parent.keySet()) {
            groups.computeIfAbsent(find(parent, id), k -> new ArrayList<>()).add(id);
        }
        Map<String, List<PairScore>> linkedByRoot = new LinkedHashMap<>();
        // Every pair that falls inside a group, INCLUDING sub-threshold ones. The weakest of
        // those is the informative number: a cluster built by transitive closure can contain
        // pairs that scored far below the threshold, and reporting only the above-threshold
        // minimum would always print a value >= threshold and hide that entirely.
        Map<String, List<PairScore>> allByRoot = new LinkedHashMap<>();
        for (PairScore p : pairs) {
            String root = find(parent, p.idA);
            allByRoot.computeIfAbsent(root, k -> new ArrayList<>()).add(p);
            if (p.combined >= threshold) {
                linkedByRoot.computeIfAbsent(root, k -> new ArrayList<>()).add(p);
            }
        }
        List<Cluster> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : groups.entrySet()) {
            // Only report groups with more than one member. Singletons are not "clusters"
            // and their members are reported in Campaign.unclustered instead.
            if (e.getValue().size() <= 1) continue;
            List<PairScore> linked = linkedByRoot.getOrDefault(e.getKey(), List.of());
            List<PairScore> internal = allByRoot.getOrDefault(e.getKey(), List.of());
            double sum = 0.0;
            for (PairScore p : linked) sum += p.combined;
            double cohesion = linked.isEmpty() ? 0.0 : sum / linked.size();
            double min = 1.0;
            for (PairScore p : internal) min = Math.min(min, p.combined);
            if (internal.isEmpty()) min = 0.0;
            Map<String, Integer> counts = new TreeMap<>();
            for (PairScore p : linked) {
                counts.merge(p.dominantComponent, 1, Integer::sum);
            }
            String dom = "none";
            int best = -1;
            for (Map.Entry<String, Integer> c : counts.entrySet()) {
                if (c.getValue() > best) {
                    best = c.getValue();
                    dom = c.getKey();
                }
            }
            out.add(new Cluster(e.getValue(), cohesion, min, dom, threshold));
        }
        out.sort(Comparator.comparingInt((Cluster c) -> -c.size())
                .thenComparing(c -> String.join(",", c.memberIds)));
        return out;
    }

    /**
     * Fills in the specified campaign aggregates for each cluster, from the documents themselves.
     *
     * <p>Kept separate from {@link #cluster} so the pure graph step can be exercised without any
     * scoring metadata attached, and so a caller can rebuild aggregates after scoring documents
     * it already clustered.
     */
    public static List<Cluster> withAggregates(List<Cluster> clusters, List<Document> docs) {
        if (clusters == null || clusters.isEmpty()) return List.of();
        Map<String, Document> byId = new TreeMap<>();
        if (docs != null) {
            for (Document d : docs) {
                if (d != null) byId.putIfAbsent(d.id, d);
            }
        }
        List<Cluster> out = new ArrayList<>();
        for (Cluster c : clusters) {
            List<Double> risks = new ArrayList<>();
            double confSum = 0.0;
            int confN = 0;
            long earliest = Long.MIN_VALUE;
            long latest = Long.MIN_VALUE;
            for (String id : c.memberIds) {
                Document d = byId.get(id);
                if (d == null) continue;
                if (!Double.isNaN(d.risk)) risks.add(d.risk);
                if (!Double.isNaN(d.confidence)) {
                    confSum += d.confidence;
                    confN++;
                }
                if (d.observedAt != Long.MIN_VALUE) {
                    if (earliest == Long.MIN_VALUE || d.observedAt < earliest) earliest = d.observedAt;
                    if (latest == Long.MIN_VALUE || d.observedAt > latest) latest = d.observedAt;
                }
            }
            out.add(new Cluster(c.memberIds, c.cohesion, c.weakestLink, c.dominantComponent,
                    c.threshold, Cluster.noisyOr(risks),
                    (confN == 0) ? Double.NaN : confSum / confN, earliest, latest));
        }
        return out;
    }

    private static String find(Map<String, String> parent, String x) {
        String p = parent.get(x);
        if (p == null) return x;
        if (p.equals(x)) return x;
        String root = find(parent, p);
        parent.put(x, root); // path compression
        return root;
    }

    // ==================================================================
    // Corpus result
    // ==================================================================

    /** The correlation result for a corpus. Carries the threshold used and the scope limit. */
    public static final class Campaign {
        public final double threshold;
        public final int documentsConsidered;
        public final boolean truncatedAtDocumentLimit;
        public final List<PairScore> pairs;
        public final List<Cluster> clusters;
        public final List<String> unclustered;
        public final String disclaimer;

        Campaign(double threshold, int considered, boolean truncated, List<PairScore> pairs,
                 List<Cluster> clusters, List<String> unclustered) {
            this.threshold = threshold;
            this.documentsConsidered = considered;
            this.truncatedAtDocumentLimit = truncated;
            this.pairs = List.copyOf(pairs);
            this.clusters = List.copyOf(clusters);
            this.unclustered = List.copyOf(unclustered);
            this.disclaimer = DISCLAIMER;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("threshold", threshold);
            m.put("documentsConsidered", documentsConsidered);
            m.put("truncatedAtDocumentLimit", truncatedAtDocumentLimit);
            m.put("clusterCount", clusters.size());
            m.put("clusters", clusters.stream().map(Cluster::toMap).toList());
            m.put("unclustered", unclustered);
            m.put("pairCount", pairs.size());
            m.put("pairs", pairs.stream().filter(p -> p.linked).map(PairScore::toMap).toList());
            m.put("disclaimer", disclaimer);
            return m;
        }

        @Override
        public String toString() {
            return "Campaign{docs=" + documentsConsidered + ", threshold=" + threshold
                    + ", clusters=" + clusters.size() + ", linkedPairs="
                    + pairs.stream().filter(p -> p.linked).count() + "}";
        }
    }

    /** Runs pairwise scoring and clustering over a document list. */
    public static Campaign analyze(List<Document> docs, double threshold) {
        double t = (threshold > 0.0 && threshold <= 1.0) ? threshold : DEFAULT_THRESHOLD;
        List<PairScore> pairs = pairwise(docs, t);
        List<Cluster> clusters = withAggregates(cluster(pairs, t), docs);
        List<String> unclustered = new ArrayList<>();
        if (docs != null) {
            Set<String> clustered = new TreeSet<>();
            for (Cluster c : clusters) {
                if (c.size() > 1) clustered.addAll(c.memberIds);
            }
            int n = Math.min(docs.size(), MAX_DOCUMENTS);
            for (int i = 0; i < n; i++) {
                String id = docs.get(i).id;
                if (!clustered.contains(id)) unclustered.add(id);
            }
        }
        boolean truncated = docs != null && docs.size() > MAX_DOCUMENTS;
        return new Campaign(t, docs == null ? 0 : docs.size(), truncated, pairs, clusters, unclustered);
    }

    public static Campaign analyze(List<Document> docs) {
        return analyze(docs, DEFAULT_THRESHOLD);
    }

    // ==================================================================
    // Self-test
    // ==================================================================

    public static void main(String[] args) {
        System.out.println("=== Jaccard, including the empty cases ===");
        Set<String> a = Set.of("x", "y", "z");
        Set<String> b = Set.of("y", "z", "w");
        Set<String> empty = Set.of();
        System.out.println("  |{x,y,z} n {y,z,w}| / union = " + jaccard(a, b) + "  (expect 0.5)");
        System.out.println("  identical                       = " + jaccard(a, a) + "  (expect 1.0)");
        System.out.println("  disjoint                        = " + jaccard(a, Set.of("p", "q"))
                + "  (expect 0.0)");
        System.out.println("  one empty, other full           = " + jaccard(empty, a) + "  (expect 0.0)");
        System.out.println("  BOTH empty                      = " + jaccard(empty, empty)
                + "  (expect 0.0, NOT 1.0 and NOT NaN)");
        System.out.println("  null handling                   = " + jaccard(null, a)
                + " / " + jaccard(null, null));

        System.out.println();
        System.out.println("=== tokenizer bounds ===");
        StringBuilder huge = new StringBuilder();
        for (int i = 0; i < 50_000; i++) huge.append("word").append(i % 97).append(' ');
        System.out.println("  input chars=" + huge.length()
                + " tokens kept=" + tokenize(huge.toString()).size()
                + " (cap " + MAX_TOKENS_PER_DOC + ")");
        System.out.println("  null -> " + tokenize(null).size() + ", empty -> " + tokenize("").size());
        System.out.println("  single letters dropped: " + tokenize("a b cc ddd"));

        System.out.println();
        System.out.println("=== TF-IDF / cosine ===");
        List<List<String>> docs = List.of(
                tokenize("wire transfer invoice payment urgent bank"),
                tokenize("wire transfer invoice payment urgent bank"),
                tokenize("common word quarterly newsletter recipes"));
        Map<String, Double> idf = buildIdf(docs);
        System.out.println("  vocabulary=" + idf.size());
        System.out.println("  idf('common')=" + round(idf.getOrDefault("common", -1.0))
                + "   appears in all 3 docs -> discounted");
        System.out.println("  idf('wire') =" + round(idf.getOrDefault("wire", -1.0))
                + "   appears in 2 of 3    -> weighted higher");
        System.out.println("  idf('recipes')=" + round(idf.getOrDefault("recipes", -1.0))
                + "   appears in 1 of 3  -> weighted highest");
        Vector v1 = vectorize(docs.get(0), idf);
        Vector v2 = vectorize(docs.get(1), idf);
        Vector v3 = vectorize(docs.get(2), idf);
        Vector vz = vectorize(List.of(), idf);
        System.out.println("  cos(identical)   = " + round(cosine(v1, v2)) + "  (expect 1.0)");
        System.out.println("  cos(different)   = " + round(cosine(v1, v3)));
        System.out.println("  cos vs ZERO VEC = " + round(cosine(v1, vz)) + "  (expect 0.0, NOT NaN)");
        System.out.println("  zero norm flag   = " + vz.isZero());
        System.out.println("  null vectors     = " + cosine(null, v1));
        System.out.println("  self-cos <= 1    = " + (cosine(v1, v1) <= 1.0));
        System.out.println("  idf is corpus-scoped, not pair-scoped: pairwise() shares one idf");

        System.out.println();
        System.out.println("=== corpus clustering at 0.62 ===");
        List<Document> corpus = new ArrayList<>();
        corpus.add(new Document("m1", Set.of("1.1.1.1"), Set.of("evil.example"),
                Set.of("http://evil.example/pay"), Set.of("application/pdf"),
                "Urgent wire transfer", "please send the bank details today invoice attached"));
        corpus.add(new Document("m2", Set.of("1.1.1.1"), Set.of("evil.example"),
                Set.of("http://evil.example/pay"), Set.of("application/pdf"),
                "Urgent wire transfer", "please send the bank details today invoice attached"));
        corpus.add(new Document("m3", Set.of("8.8.8.8"), Set.of("other.example"),
                Set.of("http://other.example/x"), Set.of("text/csv"),
                "Quarterly newsletter", "recipes gardening tips for the weekend"));
        corpus.add(new Document("m4", Set.of("9.9.9.9"), Set.of("third.example"),
                Set.of(), Set.of(), "", ""));
        Campaign c = analyze(corpus, DEFAULT_THRESHOLD);
        System.out.println("  " + c);
        for (Cluster cl : c.clusters) {
            System.out.println("    " + cl);
        }
        System.out.println("  unclustered=" + c.unclustered);
        System.out.println("  linked pairs with components:");
        for (PairScore p : c.pairs) {
            if (p.linked) {
                System.out.println("    " + p);
                System.out.println("      " + p.toMap());
            }
        }

        System.out.println();
        System.out.println("=== transitive clustering is visible, not hidden ===");
        // Overlapping-but-diverging bodies: a~b and b~c clear the threshold, a~c does not.
        // The union-find still groups all three, so weakestInternalLink is the only place a
        // reviewer can see that the outer pair is weak.
        List<Document> chain = List.of(
                new Document("a", Set.of(), Set.of(), Set.of(), Set.of(), "", "alpha beta"),
                new Document("b", Set.of(), Set.of(), Set.of(), Set.of(), "", "alpha beta gamma"),
                new Document("c", Set.of(), Set.of(), Set.of(), Set.of(), "", "beta gamma"));
        Campaign cc = analyze(chain, DEFAULT_THRESHOLD);
        double ab = round(score(chain.get(0), chain.get(1), DEFAULT_THRESHOLD).combined);
        double bc = round(score(chain.get(1), chain.get(2), DEFAULT_THRESHOLD).combined);
        double ac = round(score(chain.get(0), chain.get(2), DEFAULT_THRESHOLD).combined);
        System.out.println("  a~b=" + ab + "  b~c=" + bc + "  a~c=" + ac
                + "   (a~c should be below " + DEFAULT_THRESHOLD + ")");
        for (PairScore p : cc.pairs) {
            System.out.println("    " + p);
        }
        for (Cluster cl : cc.clusters) {
            System.out.println("    " + cl);
        }

        System.out.println();
        System.out.println("=== degenerate corpora ===");
        System.out.println("  " + analyze(List.of(), DEFAULT_THRESHOLD));
        System.out.println("  " + analyze(null, DEFAULT_THRESHOLD));
        System.out.println("  two empty documents -> "
                + round(score(new Document("x", null, null, null, null, "", ""),
                        new Document("y", null, null, null, null, "", ""),
                        DEFAULT_THRESHOLD).combined));
        System.out.println("  bad threshold (0 and 5.0) fall back to default: "
                + analyze(corpus, 0.0).threshold + " / " + analyze(corpus, 5.0).threshold);

        System.out.println();
        System.out.println("OK Correlate");
    }
}
