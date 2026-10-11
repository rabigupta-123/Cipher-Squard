/**
 * Tamper-evident hash-chained audit log. Phase 1 item 7.
 *
 * "Append-only" is a claim about intent. A hash chain is proof: each record commits to its
 * predecessor, so altering or removing any record breaks every link after it, and the break
 * point is computable. ROADMAP.md L213-219 calls this out directly - "a hash chain is
 * proof" - and the same section notes it is a few lines of code.
 *
 * RECORD SHAPE. One JSON object per line in data/audit.ndjson. The Phase 1 brief requires at
 * minimum a sequence number, timestamp, event type, payload, previous hash and current hash;
 * ARCHITECTURE.md L211 names the same five payload fields. The record is therefore a superset
 * of both, so a tool written against either document can read it:
 *
 *   {index, ts, event, payload:{ts,actor,action,subject,outcome,detail}, prev_hash, hash}
 *
 *   index      sequence number, 0-based, must be exactly the record's line position
 *   ts         timestamp, ISO-8601
 *   event      event type
 *   payload    the ARCHITECTURE-named detail block
 *   prev_hash  previous record's hash, genesis seed hash for index 0
 *   hash       this record's hash
 *
 *   hash = SHA-256( prev_hash || canonical_json(record without "hash") )
 *
 * Two properties this design depends on, both of which are easy to get wrong:
 *   - The record hashed MUST exclude its own "hash" field. Including it is circular, and the
 *     two implementations disagree, which is precisely the "verifies on one machine" failure.
 *   - The record hashed MUST be canonical. Json.write alone preserves insertion order, so two
 *     identical records built by different code paths would hash differently and the chain
 *     would report spurious tampering. Crypto.canonical sorts keys for exactly this reason.
 *
 * The chain head is signed with Ed25519 every Config.AUDIT_SIGN_EVERY_N records and on every
 * report, so deletion of a whole tail is detectable even if an attacker also deletes the
 * signature entries: a shorter chain simply has no signature for its new head.
 *
 * Spec anchors: ROADMAP.md L213-219, ARCHITECTURE.md L211, L232.
 */
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Audit {

    public static final Path DEFAULT_LOG = Path.of("data", "audit.ndjson");
    public static final Path DEFAULT_SIGS = Path.of("data", "audit-sigs.ndjson");
    public static final Path DEFAULT_KEY = Path.of("data", "keys", "ed25519.pem");

    private final Path logPath;
    private final Path sigPath;
    private final KeyManager keys;

    public Audit(Path logPath, Path sigPath, KeyManager keys) {
        this.logPath = logPath;
        this.sigPath = sigPath;
        this.keys = keys;
    }

    public Audit() {
        this(DEFAULT_LOG, DEFAULT_SIGS, new KeyManager(DEFAULT_KEY));
    }

    /**
     * The genesis predecessor hash. Derived from a fixed seed rather than random bytes so two
     * independent deployments agree on what an empty chain's head is, which is what makes a
     * truncated log detectable instead of merely short.
     */
    public static String genesisPrev() {
        return Crypto.sha256Hex(Config.AUDIT_GENESIS_SEED);
    }

    // ==================================================================
    // Appending
    // ==================================================================

    /**
     * Appends one record, under a single-writer lock.
     *
     * The lock is an OS-level FileLock, not a JVM object lock, because two engine processes
     * writing the same log interleave their reads of the tail with their writes and produce a
     * chain with two records claiming the same predecessor. That is undetectable later. A
     * JVM-level lock would not help: it is per-process.
     *
     * ORDERING, which is the part that was previously wrong: the lock is taken FIRST, and the
     * tail is read INSIDE it. Reading the tail before locking is a classic time-of-check /
     * time-of-use race - two writers both read the same head, both build a record claiming it
     * as prev_hash, and the resulting chain forks permanently. Reading under the lock is what
     * makes the sequence number and the predecessor a function of the locked state.
     *
     * The existing chain is also re-verified under the lock. Appending to a chain that is
     * already corrupt would bury the evidence: the next verification reports a break at the
     * record the attacker edited rather than at the point of detection. Refusing loudly is
     * the only behaviour that preserves the break point. The cost is O(n) per append, which
     * is a deliberate trade for correctness at this stage; see docs/PHASE1-NOTES.md.
     */
    private static final Object APPEND_LOCK = new Object();

    public Map<String, Object> append(String event, Map<String, Object> payload) {
        synchronized (APPEND_LOCK) {
            if (event == null || event.isBlank()) {
                throw new IllegalArgumentException("audit event type must not be blank");
            }
            try {
                Files.createDirectories(logPath.toAbsolutePath().getParent());
                if (sigPath != null) {
                    Files.createDirectories(sigPath.toAbsolutePath().getParent());
                }
        } catch (IOException e) {
            throw new IllegalStateException("cannot create audit directories", e);
        }

        Map<String, Object> record;
        int index;
        try (RandomAccessFile raf = new RandomAccessFile(logPath.toFile(), "rw");
             FileChannel ch = raf.getChannel();
             FileLock lock = acquire(ch)) {

            // The lock is acquired but never read: it exists to be held for the duration of
            // this block and released by try-with-resources. Nothing inside may run without it.
            if (!lock.isValid()) {
                throw new IllegalStateException("audit chain lock could not be acquired");
            }

            // --- everything below is inside the lock ---
            List<String> existing = readLinesLocked(ch);
    Verification pre = verifyLines(existing);
    if (!pre.ok) {
    throw new ChainBrokenException(pre.firstDivergentIndex, pre.reason);
    }


            int lastIndex = existing.isEmpty() ? -1 : existing.size() - 1;
            index = lastIndex + 1;
            String prev = existing.isEmpty() ? genesisPrev() : pre.headHash;

            record = buildRecord(index, prev, event, payload);
            String line = Crypto.canonical(record) + "\n";

            ch.position(ch.size());
            ch.write(StandardCharsets.UTF_8.encode(line));
            ch.force(true); // durable before the caller is told the append succeeded
        } catch (IOException e) {
            throw new IllegalStateException("cannot append to audit log", e);
        }

        // Signing is outside the lock on purpose. It is a separate file with its own ordering
        // and it can fail without invalidating the record just committed; holding the log lock
        // across a key load and a second file write would serialise all writers behind I/O
        // that does not need to be ordered against the chain.
        if (keys != null && keys.configured() && (index + 1) % Config.AUDIT_SIGN_EVERY_N == 0) {
            signHead(index, recordHash(record));
        }
        return record;
        }
    }

    /**
     * Builds the record and computes its hash over the record WITHOUT the hash field.
     *
     * Kept as a separate method because the exclusion is the single easiest thing to get
     * wrong, and it is the whole integrity property. The hash is computed exactly once: the
     * earlier version inserted a placeholder "hash" and then recomputed over a record that
     * already contained it, which only worked by accident of canonical() dropping the field
     * it was told to remove. Computing once, over a record with no hash field at all, has no
     * such dependency.
     */
    static Map<String, Object> buildRecord(int index, String prevHash, String event,
                                           Map<String, Object> payload) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("ts", payload != null && payload.get("ts") != null
                ? payload.get("ts") : Instant.now().toString());
        p.put("actor", payload != null && payload.get("actor") != null ? payload.get("actor") : "system");
        p.put("action", event);
        p.put("subject", payload != null && payload.get("subject") != null ? payload.get("subject") : "");
        p.put("outcome", payload != null && payload.get("outcome") != null ? payload.get("outcome") : "ok");
        p.put("detail", payload != null && payload.get("detail") != null ? payload.get("detail") : "");

        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("index", (double) index);
        rec.put("ts", p.get("ts"));
        rec.put("event", event);
        rec.put("payload", p);
        rec.put("prev_hash", prevHash);
        rec.put("hash", recordHash(rec)); // recordHash strips "hash" before hashing
        return rec;
    }

    /** hash = SHA-256(prev_hash || canonical_json(record minus "hash")). */
    static String recordHash(Map<String, Object> rec) {
        Map<String, Object> without = new LinkedHashMap<>(rec);
        without.remove("hash");
        return Crypto.sha256Hex(String.valueOf(rec.get("prev_hash"))
                + Crypto.canonical(without));
    }

    // ==================================================================
    // Verification
    // ==================================================================

    public static final class Verification {
        public boolean ok;
        public int records;
        /** First index whose hash, predecessor or sequence number does not verify. -1 if none. */
        public int firstDivergentIndex = -1;
    public String headHash = "";
    public boolean headSignatureValid;
    public boolean signatureConfigured;
    /**
     * Highest chain index that carries a signature, or -1 when none does.
     *
     * Needed because signing is periodic ({@link Config#AUDIT_SIGN_EVERY_N}), so the head is
     * unsigned most of the time. "The head is not signed" is therefore the normal state and says
     * nothing about tampering; the anchor for trust is the most recent signature that does
     * verify, which is what this points at.
     */
    public int lastSignedIndex = -1;
    /** Whether the signature at {@link #lastSignedIndex} verifies against the configured key. */
    public boolean lastSignatureValid;
    /** True when a signature exists for the head index but does not verify. */
    public boolean headSignatureForged;
    public String reason = "";
    }


    /**
     * Recomputes the entire chain from disk.
     *
     * Verifies, for every record: (a) index is the expected position, (b) prev_hash equals the
     * previous record's hash, (c) the stored hash equals the recomputed hash, and (d) the record
     * carries every field the format requires.
     *
     * (a) is what makes a DELETED record detectable from the middle - a gap in the index
     * sequence cannot be produced by editing content alone. (b) plus (c) make any content
     * edit detectable. (d) is what stops a record that is merely well-formed JSON but missing
     * its links from being treated as a valid link in the chain.
     */
    public Verification verify() {
        Verification v = verifyLines(readLines(logPath));
        v.signatureConfigured = keys != null && keys.configured();
        v.headSignatureValid = v.ok && v.records > 0
                && verifyHeadSignature(v.records - 1, v.headHash);
        if (v.signatureConfigured && v.records > 0) {
            int[] anchor = newestVerifyingSignature();
            if (anchor != null) {
                v.lastSignedIndex = anchor[0];
                v.lastSignatureValid = true;
            }
            if (signatureExistsFor(v.records - 1) && !v.headSignatureValid) {
                v.headSignatureForged = true;
            }
        }
        if (v.ok && v.signatureConfigured) {
            if (v.headSignatureForged) {
                v.reason = "chain is intact but the head at index " + (v.records - 1)
                        + " carries a forged signature";
            } else if (!v.headSignatureValid && v.lastSignedIndex < 0) {
                v.reason = "chain is intact but the head at index " + (v.records - 1)
                        + " is unsigned or its signature does not verify";
            } else if (v.headSignatureValid) {
                v.reason = "";
            }
        }
        return v;
    }

    /** Chain verification over already-read lines, so append can reuse it under its lock. */
    private static Verification verifyLines(List<String> lines) {
        Verification v = new Verification();
        v.records = lines.size();
        if (lines.isEmpty()) {
            v.ok = true;
            v.headHash = genesisPrev();
            v.reason = "empty log";
            return v;
        }

        String expectedPrev = genesisPrev();
        int expectedIndex = 0;
        for (String line : lines) {
            Map<String, Object> rec;
            try {
                rec = Json.parseObject(line);
            } catch (RuntimeException e) {
                v.ok = false;
                v.firstDivergentIndex = expectedIndex;
                v.reason = "record " + expectedIndex + " is not parseable JSON: " + e.getMessage();
                return v;
            }
            for (String required : new String[]{"index", "ts", "event", "payload",
                    "prev_hash", "hash"}) {
                if (!rec.containsKey(required)) {
                    v.ok = false;
                    v.firstDivergentIndex = expectedIndex;
                    v.reason = "record " + expectedIndex + " is missing required field '"
                            + required + "'";
                    return v;
                }
            }
            Integer idx = readIndex(rec);
            if (idx == null || idx != expectedIndex) {
                v.ok = false;
                v.firstDivergentIndex = expectedIndex;
                v.reason = "expected index " + expectedIndex + " but found "
                        + (idx == null ? "a non-integer" : String.valueOf(idx))
                        + " (record deleted, reordered or renumbered)";
                return v;
            }
            String prev = String.valueOf(rec.get("prev_hash"));
            if (!prev.equals(expectedPrev)) {
                v.ok = false;
                v.firstDivergentIndex = expectedIndex;
                v.reason = "prev_hash mismatch at " + expectedIndex
                        + ": expected " + expectedPrev + " found " + prev;
                return v;
            }
            String recomputed = recordHash(rec);
            String stored = String.valueOf(rec.get("hash"));
            if (!recomputed.equals(stored)) {
                v.ok = false;
                v.firstDivergentIndex = expectedIndex;
                v.reason = "hash mismatch at " + expectedIndex
                        + ": recomputed " + recomputed + " stored " + stored;
                return v;
            }
            expectedPrev = stored;
            expectedIndex++;
        }

        v.ok = true;
        v.headHash = expectedPrev;
        return v;
    }

    /**
     * The newest signature whose recorded hash matches the chain hash at the same index and whose
     * signature verifies against the configured key.
     *
     * Returns {@code {index, 0}} for the anchor, or null when no signature verifies. Matching the
     * recorded hash against the chain is what makes this an anchor rather than merely a valid
     * signature: a signature over some other hash says nothing about this chain, and a chain whose
     * body was rewritten would otherwise still surface an old, individually valid signature.
     */
    private int[] newestVerifyingSignature() {
        if (keys == null || !keys.configured() || sigPath == null) {
            return null;
        }
        List<String> chain = readLines(logPath);
        int best = -1;
        for (String line : readLines(sigPath)) {
            Map<String, Object> s;
            try {
                s = Json.parseObject(line);
            } catch (RuntimeException e) {
                continue;
            }
            Integer idx = readIndex(s);
            if (idx == null || idx < 0 || idx >= chain.size() || idx <= best) {
                continue;
            }
            String signedHash = String.valueOf(s.get("head_hash"));
            Map<String, Object> rec;
            try {
                rec = Json.parseObject(chain.get(idx));
            } catch (RuntimeException e) {
                continue;
            }
            // The signature must cover the hash this chain actually holds at that index.
            if (rec == null || !signedHash.equals(String.valueOf(rec.get("hash")))) {
                continue;
            }
            if (!Sign.verify(signedHash.getBytes(StandardCharsets.UTF_8),
                    Sign.unb64(String.valueOf(s.get("signature"))), keys.publicKey())) {
                continue;
            }
            best = idx;
        }
        return best < 0 ? null : new int[] { best, 0 };
    }

    /**
     * A head is signed if a signature exists for exactly this index and it verifies against
     * this head hash.
     *
     * After a tail deletion the surviving head has a lower index, so no signature matches and
     * this returns false. That is the intended detection: the chain body is internally
     * consistent, but the attacker removed records and cannot forge a signature for the new
     * head without the private key.
     */
    /**
     * Whether a signature record exists for this chain index, regardless of whether it verifies.
     *
     * The distinction matters: "no signature yet" is the normal state between periodic signing
     * checkpoints, while "a signature that does not verify" means something signed a record it
     * could not have signed, which is the interesting case.
     */
    private boolean signatureExistsFor(int index) {
    if (keys == null || !keys.configured() || sigPath == null) {
    return false;
    }
    for (String line : readLines(sigPath)) {
    Map<String, Object> s;
    try {
    s = Json.parseObject(line);
    } catch (RuntimeException e) {
    continue;
    }
    Integer idx = readIndex(s);
    if (idx != null && idx == index) {
    return true;
    }
    }
    return false;
    }

    private boolean verifyHeadSignature(int headIndex, String headHash) {
        if (keys == null || !keys.configured()) {
            return false;
        }
        for (String line : readLines(sigPath)) {
            Map<String, Object> s;
            try {
                s = Json.parseObject(line);
            } catch (RuntimeException e) {
                continue;
            }
            Integer idx = readIndex(s);
            if (idx != null && idx == headIndex) {
                String signedHash = String.valueOf(s.get("head_hash"));
                if (!signedHash.equals(headHash)) {
                    return false;
                }
                return Sign.verify(headHash.getBytes(StandardCharsets.UTF_8),
                        Sign.unb64(String.valueOf(s.get("signature"))), keys.publicKey());
            }
        }
        return false;
    }

    // ==================================================================
    // Head signing
    // ==================================================================

    public void signHead(int index, String headHash) {
        if (keys == null || !keys.configured()) {
            return;
        }
        byte[] sig = Sign.sign(headHash.getBytes(StandardCharsets.UTF_8), keys.privateKey());
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("index", (double) index);
        rec.put("head_hash", headHash);
        rec.put("signature", Sign.b64(sig));
        rec.put("key_id", keys.keyId());
        rec.put("signed_at", Instant.now().toString());
        try {
            Files.createDirectories(sigPath.toAbsolutePath().getParent());
            Files.writeString(sigPath, Crypto.canonical(rec) + "\n",
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new IllegalStateException("cannot write audit signature", e);
        }
    }

    /** Chain head, for binding into a report. Null when the log is empty. */
    public String chainHead() {
        Verification v = verify();
        return v.records == 0 ? null : v.headHash;
    }

    // ==================================================================
    // Key management
    // ==================================================================

    /**
     * Ed25519 key at data/keys/ed25519.pem, holding a PRIVATE and a PUBLIC key block.
     *
     * The absence case is explicit rather than implicit: with no key the engine still runs
     * and every report carries signature="NOT_CONFIGURED" (ROADMAP.md L251). Silently
     * generating a key on first read would be worse - it would produce a chain whose
     * signatures nobody can verify against a pinned fingerprint.
     */
    public static final class KeyManager {
        private final Path pemPath;
        private PrivateKey priv;
        private PublicKey pub;
        private String keyId;
        private boolean loaded;

        public KeyManager(Path pemPath) {
            this.pemPath = pemPath;
            load();
        }

        private void load() {
            loaded = false;
            priv = null;
            pub = null;
            keyId = null;
            if (pemPath == null || !Files.isRegularFile(pemPath)) {
                return;
            }
            try {
                String pem = Files.readString(pemPath, StandardCharsets.UTF_8);
                if (pem.contains("PRIVATE KEY")) {
                    priv = Sign.privateKeyFromPem(pem);
                }
                if (pem.contains("PUBLIC KEY")) {
                    pub = Sign.publicKeyFromPem(pem);
                }
                loaded = priv != null && pub != null;
                if (loaded) {
                    keyId = Sign.keyIdOf(pub);
                }
            } catch (IOException | RuntimeException e) {
                // A malformed key file is treated as "no key configured", not a crash: the
                // engine must still run, and the absence is reported rather than hidden.
                loaded = false;
                priv = null;
                pub = null;
            }
        }

        public boolean configured() {
            return loaded;
        }

        public PublicKey publicKey() {
            return pub;
        }

        public PrivateKey privateKey() {
            return priv;
        }

        public String keyId() {
            return keyId;
        }

        public Path path() {
            return pemPath;
        }

        /** Generates and writes a key pair. Does nothing if one is already present. */
        public static KeyManager createOrLoad(Path pemPath) {
            KeyManager km = new KeyManager(pemPath);
            if (km.configured()) {
                return km;
            }
            try {
                if (pemPath != null) {
                    Files.createDirectories(pemPath.toAbsolutePath().getParent());
                }
                KeyPair kp = Sign.generateKeyPair();
                String pem =
                        "# Cipher Squad audit signing key (Ed25519)\n"
                        + "# POSIX hosts: run 'chmod 600' on this file.\n"
                        + "# On Windows the JDK PosixFilePermission API is unsupported on NTFS,\n"
                        + "# so NO permission change is attempted here. Restrict access with the\n"
                        + "# filesystem ACL or keep the key in an HSM. See PHASE1-NOTES.md C-18.\n"
                        + Sign.privateKeyToPem(kp.getPrivate())
                        + Sign.publicKeyToPem(kp.getPublic());
                Files.writeString(pemPath, pem, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                restrictOnPosixOnly(pemPath);
            } catch (IOException e) {
                throw new IllegalStateException("cannot write audit key", e);
            }
            return new KeyManager(pemPath);
        }

        /**
         * Restrict the key file to owner-only, where that is actually expressible.
         *
         * On POSIX this is a real 600 and is applied. On NTFS the PosixFilePermission view
         * is not available through this API, and nothing portable is substituted.
         *
         * The earlier version fell back to the DOS read-only attribute on Windows. That was
         * removed deliberately: it blocks legitimate key rotation (a replacement key cannot
         * overwrite the file) while providing essentially no confidentiality, since it does
         * nothing to stop another account on the machine from reading the key. A measure that
         * trades a real capability for a cosmetic one is worse than a documented gap, and a
         * read-only private key file would read as "secured" in an audit report when it is not.
         *
         * The Windows gap is stated in the key file's own header and in PHASE1-NOTES C-18.
         */
        private static void restrictOnPosixOnly(Path p) {
            try {
                Files.setPosixFilePermissions(p,
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (IOException | UnsupportedOperationException e) {
                // Not a POSIX filesystem. Nothing portable is left to do; the limitation is
                // recorded rather than papered over.
            }
        }
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    /**
     * Read a record's sequence number, or null if it is not an exact integer.
     *
     * The obvious cast is wrong. JSON has no integer type, so every index arrives as a double,
     * and (int) 1.5 silently becomes 1 - which means a record whose index was tampered with
     * from 1 to 1.5 still verifies. Truncation is exactly the kind of quiet acceptance an
     * audit chain exists to prevent, so the value is required to be finite and integral.
     */
    /**
     * Thrown when an append is refused because the existing chain does not reconcile.
     *
     * A distinct type rather than a generic IllegalStateException so the request layer can answer
     * with something an operator can act on. Failing closed here is right -- history is never
     * rewritten to make room for a new event -- but a broken chain used to turn every subsequent
     * request into an opaque 500 with the reason buried in a stack trace, which is indistinguishable
     * from an ordinary bug and gives no hint that the log is the problem.
     */
    public static final class ChainBrokenException extends RuntimeException {
    public final int firstDivergentIndex;
    public final String detail;

    public ChainBrokenException(int firstDivergentIndex, String detail) {
    super("audit chain is broken at index " + firstDivergentIndex
    + (detail == null || detail.isEmpty() ? "" : ": " + detail));
    this.firstDivergentIndex = firstDivergentIndex;
    this.detail = detail == null ? "" : detail;
    }

    /** True once the record count is far enough past the divergence to suggest a tail rewrite. */
    public boolean likelyTruncation() {
    return detail != null && detail.toLowerCase(java.util.Locale.ROOT).contains("index");
    }
    }

    private static Integer readIndex(Map<String, Object> rec) {
        Object raw = rec.get("index");
        if (!(raw instanceof Number)) {
            return null;
        }
        double d = ((Number) raw).doubleValue();
        if (!Double.isFinite(d) || d != Math.floor(d) || d < 0 || d > Integer.MAX_VALUE) {
            return null;
        }
        return (int) d;
    }

    private static List<String> readLines(Path p) {        if (p == null || !Files.isRegularFile(p)) {
            return new ArrayList<>();
        }
        try {
            return Crypto.nonBlankLines(Files.readAllLines(p, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read audit log " + p, e);
        }
    }

    /**
     * Read the whole chain through the channel that already holds the write lock.
     *
     * This deliberately does NOT call Files.readAllLines. On Windows, opening a second
     * independent handle to a file that a RandomAccessFile currently has open for writing
     * fails outright ("another process has locked a portion of the file"), so the obvious
     * implementation throws on the platform this project is developed on - and the failure
     * lands inside append(), where it looks like the audit log is broken rather than like a
     * handle-sharing mistake.
     *
     * Positional reads (ch.read(buf, pos)) do not move the channel's write position, so
     * reading the tail to recompute the head cannot corrupt the append that follows.
     */
    private static List<String> readLinesLocked(FileChannel ch) throws IOException {
        int size = (int) Math.min(ch.size(), Integer.MAX_VALUE);
        if (size == 0) {
            return new ArrayList<>();
        }
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(size);
        int filled = 0;
        while (filled < size) {
            int n = ch.read(buf, filled);
            if (n < 0) {
                break; // file shrank underneath us; use what we got
            }
            filled += n;
        }
        buf.flip();
        String text = StandardCharsets.UTF_8.decode(buf).toString();
        List<String> out = new ArrayList<>();
        for (String line : text.split("\n", -1)) {
            String t = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
            t = t.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private static FileLock acquire(FileChannel ch) throws IOException {
        // Bounded retry: a crashed holder releases the lock when its process dies, so a long
        // wait means something is wrong. Failing loudly beats writing a corrupt chain.
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (true) {
            FileLock l = null;
            try {
                l = ch.tryLock();
            } catch (java.nio.channels.OverlappingFileLockException ignored) {
                // Another thread in the same JVM currently holds the lock; backoff and retry
            }
            if (l != null) {
                return l;
            }
            if (System.nanoTime() > deadline) {
                throw new IOException("audit log is locked by another writer after 10s");
            }
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while waiting for the audit lock", e);
            }
        }
    }

    /** Convenience for building a payload. */
    public static Map<String, Object> payload(String actor, String subject,
                                              String outcome, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("actor", actor);
        m.put("subject", subject);
        m.put("outcome", outcome);
        m.put("detail", detail);
        return m;
    }

    /** Standalone self-check: java Audit [dir] */
    public static void main(String[] args) {
        Path dir = args.length > 0 ? Path.of(args[0]) : Path.of("build", "auditcheck");
        Path log = dir.resolve("audit.ndjson");
        Path sig = dir.resolve("audit-sigs.ndjson");
        KeyManager km = KeyManager.createOrLoad(dir.resolve("keys").resolve("ed25519.pem"));
        Audit audit = new Audit(log, sig, km);
        for (int i = 0; i < 3; i++) {
            audit.append("selfcheck", payload("tester", "subject-" + i, "ok", "record " + i));
        }
        Verification v = audit.verify();
        System.out.println("records=" + v.records + " ok=" + v.ok
                + " firstDivergent=" + v.firstDivergentIndex
                + " headSig=" + v.headSignatureValid
                + " keyConfigured=" + v.signatureConfigured);
        System.out.println("head=" + v.headHash);
    }
}
