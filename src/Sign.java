/**
 * Ed25519 detached signatures, for signing report and evidence artefacts.
 *
 * The Phase 1 brief names this file Sign.java and scopes it to Ed25519 alone, so the
 * signing half of the old Crypto class lives here and Crypto keeps only canonical JSON
 * and SHA-256. The split is not cosmetic: "one place that signs" and "one place that
 * hashes" are two different trust claims, and the audit chain depends on the second
 * being uncontaminated by the first.
 *
 * WHY THE JDK PROVIDER. ROADMAP.md L234-251 requires Ed25519 with no dependencies, and
 * java.security supplies it from JDK 15 onward. There is deliberately no algorithm name
 * in this file that a caller can influence: a caller cannot ask for "EdDSA", "Ed25519/
 * SHA-512" or a provider-qualified string, so a future config file cannot downgrade the
 * signature scheme. Ed25519 is fixed-strength; there is no weak variant to fall back to.
 *
 * WHAT IS SIGNED. The payload is SHA-256'd first and the Ed25519 signature is taken over
 * that digest, per ROADMAP.md L246. Ed25519 already hashes internally (SHA-512), so this
 * is not a security requirement - it is a domain-separation step that makes a signed
 * artefact of the same content byte-identical regardless of which pipeline produced it.
 *
 * KEY HANDLING. Private keys are read from and written to disk, never embedded in source
 * and never logged. sign() takes a PrivateKey and returns bytes; it has no code path that
 * prints, formats, or transmits the key. Overwriting a private key file on disk is the
 * caller's decision and is deliberately not done here, because silently truncating a key
 * that may be the only copy is worse than leaving a stale file with an obvious name.
 *
 * Spec anchors: ROADMAP.md L234-251, ARCHITECTURE.md L55, L232.
 */
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class Sign {

    private Sign() {
    }

    /** The single algorithm string in this file. Not configurable, not caller-supplied. */
    private static final String ALG = "Ed25519";

    public static final String PUBLIC_PEM_LABEL = "CIPHER SQUAD ED25519 PUBLIC KEY";
    public static final String PRIVATE_PEM_LABEL = "CIPHER SQUAD ED25519 PRIVATE KEY";
    public static final String SIGNATURE_PEM_LABEL = "CIPHER SQUAD ED25519 SIGNATURE";

    // ==================================================================
    // Keys
    // ==================================================================

    /**
     * key_id = SHA-256 of the DER-encoded SubjectPublicKeyInfo, lowercase hex.
     *
     * ROADMAP.md L247 names `key_id` without defining it, so the definition is pinned in
     * docs/PHASE1-NOTES.md. A key_id is therefore comparable across runs and machines, and
     * a signature report can state exactly which public key must be presented to verify it.
     * It is a fingerprint, not a secret, and safe to publish.
     */
    public static String keyIdOf(PublicKey key) {
        requirePublicKey(key);
        return Crypto.sha256Hex(key.getEncoded());
    }

    public static KeyPair generateKeyPair() {
        try {
            // No AlgorithmParameterSpec and no seed-size initialisation: Ed25519 is
            // fixed-size, and SecureRandom.initialize(int) would be a meaningless call here.
            // The provider sources its own randomness.
            return KeyPairGenerator.getInstance(ALG).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable; JDK is missing the provider", e);
        }
    }

    public static PublicKey publicKeyFromDer(byte[] der) {
        try {
            return KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // Reported as a caller error, not a crash: a corrupt key file is bad input, and
            // the message must not echo the key material.
            throw new IllegalArgumentException("not a valid Ed25519 public key", e);
        }
    }

    public static PrivateKey privateKeyFromDer(byte[] der) {
        try {
            return KeyFactory.getInstance(ALG).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalArgumentException("not a valid Ed25519 private key", e);
        }
    }

    public static PublicKey publicKeyFromPem(String pem) {
        return publicKeyFromDer(fromPem(pem, PUBLIC_PEM_LABEL));
    }

    public static PrivateKey privateKeyFromPem(String pem) {
        return privateKeyFromDer(fromPem(pem, PRIVATE_PEM_LABEL));
    }

    public static String publicKeyToPem(PublicKey key) {
        requirePublicKey(key);
        return toPem(PUBLIC_PEM_LABEL, key.getEncoded());
    }

    /**
     * Export a private key. Deliberately requires an explicit label argument, so a caller
     * cannot accidentally write a private key out under a public-key filename.
     */
    public static String privateKeyToPem(PrivateKey key) {
        if (key == null) {
            throw new IllegalArgumentException("private key is null");
        }
        return toPem(PRIVATE_PEM_LABEL, key.getEncoded());
    }

    // ==================================================================
    // Sign / verify
    // ==================================================================

    /** Sign UTF-8 text. */
    public static byte[] sign(String utf8, PrivateKey key) {
        return sign(utf8.getBytes(StandardCharsets.UTF_8), key);
    }

    /**
     * Sign raw bytes. Returns the raw 64-byte Ed25519 signature.
     *
     * A null key is rejected rather than allowed to surface as a NullPointerException from
     * the JCA layer, because "null private key" almost always means a key file failed to
     * load and a bare NPE hides that.
     */
    public static byte[] sign(byte[] payload, PrivateKey key) {
        if (key == null) {
            throw new IllegalArgumentException("private key is null; cannot sign");
        }
        if (payload == null) {
            throw new IllegalArgumentException("payload is null; cannot sign");
        }
        try {
            Signature s = Signature.getInstance(ALG);
            s.initSign(key);
            s.update(Crypto.sha256Hex(payload).getBytes(StandardCharsets.UTF_8));
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    /**
     * Verify a detached signature over raw bytes.
     *
     * Returns false - never throws - for a bad signature, a malformed signature blob, or a
     * key of the wrong type. Verification is called on untrusted input from other people's
     * reports, so an exception here would be a denial-of-service vector: a caller in a
     * report pipeline would be forced to catch, and anything that forgot would crash on
     * input an attacker controls.
     */
    public static boolean verify(byte[] payload, byte[] signature, PublicKey key) {
        if (payload == null || signature == null || key == null) {
            return false;
        }
        try {
            Signature s = Signature.getInstance(ALG);
            s.initVerify(key);
            s.update(Crypto.sha256Hex(payload).getBytes(StandardCharsets.UTF_8));
            return s.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    public static boolean verify(String utf8, byte[] signature, PublicKey key) {
        return utf8 != null && verify(utf8.getBytes(StandardCharsets.UTF_8), signature, key);
    }

    // ==================================================================
    // Portable encoding
    // ==================================================================

    public static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static byte[] unb64(String s) {
        return Base64.getDecoder().decode(s);
    }

    public static String toPem(String label, byte[] der) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(label).append("-----\n");
        String encoded = b64(der);
        for (int i = 0; i < encoded.length(); i += 64) {
            sb.append(encoded, i, Math.min(encoded.length(), i + 64)).append('\n');
        }
        sb.append("-----END ").append(label).append("-----\n");
        return sb.toString();
    }

    /**
     * Extract the DER body of a labelled PEM block. Whitespace inside the block is
     * stripped, so a line-wrapped file and a single-line file parse identically.
     */
    public static byte[] fromPem(String pem, String label) {
        if (pem == null) {
            throw new IllegalArgumentException("PEM text is null");
        }
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int a = pem.indexOf(begin);
        int b = pem.indexOf(end, a < 0 ? 0 : a);
        if (a < 0 || b < 0) {
            throw new IllegalArgumentException("no " + label + " PEM block found");
        }
        return unb64(pem.substring(a + begin.length(), b).replaceAll("\\s", ""));
    }

    /** Wrap a raw signature in a PEM block, for report artefacts that are text. */
    public static String signatureToPem(byte[] signature) {
        return toPem(SIGNATURE_PEM_LABEL, signature);
    }

    public static byte[] signatureFromPem(String pem) {
        return fromPem(pem, SIGNATURE_PEM_LABEL);
    }

    private static void requirePublicKey(PublicKey key) {
        if (key == null) {
            throw new IllegalArgumentException("public key is null");
        }
    }

    /** Standalone self-check: java Sign */
    public static void main(String[] args) {
        KeyPair kp = generateKeyPair();
        byte[] sig = sign("hello", kp.getPrivate());
        System.out.println("key_id=" + keyIdOf(kp.getPublic()).substring(0, 16) + "...");
        System.out.println("signature_bytes=" + sig.length);
        System.out.println("verify ok=" + verify("hello", sig, kp.getPublic()));
        System.out.println("verify tampered="
                + verify("hell0", sig, kp.getPublic()));
        System.out.println("verify wrong key=" + verify("hello", sig, generateKeyPair().getPublic()));

        // PEM round trip, both keys.
        String pubPem = publicKeyToPem(kp.getPublic());
        String privPem = privateKeyToPem(kp.getPrivate());
        KeyPair restored = new KeyPair(
                publicKeyFromPem(pubPem), privateKeyFromPem(privPem));
        System.out.println("pem roundtrip pub=" + restored.getPublic().equals(kp.getPublic())
                + " priv=" + restored.getPrivate().equals(kp.getPrivate()));
        System.out.println("verify via restored priv="
                + verify("hello", sign("hello", restored.getPrivate()), restored.getPublic()));
        System.out.println("signature pem roundtrip="
                + verify("hello", signatureFromPem(signatureToPem(sig)), kp.getPublic()));
    }
}
