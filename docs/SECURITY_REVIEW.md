# CIPHER SQUAD — Comprehensive Security Review
**Platform: Pure Java JDK 25 Local-First Threat Detection Engine**

## 1. Threat Model & Security Posture
The platform operates on the premise of **Zero-Trust Input & Local-First Isolation**. As an email forensic investigation engine, it accepts untrusted inputs (malformed MIME, hostile RFC 822 emails, weaponized attachment names, spoofed headers, and adversarial Unicode homoglyphs).

## 2. Security Controls & Implementation Review

### 2.1 SSRF Guard ([App.java](file:///sih_java/src/App.java#L2630))
- **Defense Mechanism**: Multi-stage structural and IP resolution validation.
- **Rules Enforced**:
  - Rejects loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fd00::/8`).
  - Blocks cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
  - DNS Rebinding Prevention: Resolves hostnames via `InetAddress.getAllByName(host)` and verifies every returned IP against the denied ranges before any connection attempt.
- **Verification Evidence**: `phase3.java` test `t08_ssrf` passed with 38 distinct test vectors verified.

### 2.2 Tamper-Evident Hash-Chained Audit Trail ([Audit.java](file:///sih_java/src/Audit.java))
- **Defense Mechanism**: Append-only cryptographic linear hash chain with OS file locking (`FileLock`) and periodic asymmetric digital signatures.
- **Mathematical Invariant**:
  $$\text{Hash}_i = \text{SHA-256}(\text{Hash}_{i-1} \parallel \text{CanonicalJSON}(\text{Record}_i \setminus \{\text{"hash"}\}))$$
  Index 0 links back to fixed genesis predecessor `Crypto.sha256Hex("cipher-squad-genesis")`.
- **Signature Anchoring**:
  Signed every `Config.AUDIT_SIGN_EVERY_N` (50) records using Ed25519 (`Sign.java`) key pair. Verified offline by independent verification consumers.
- **Tamper Detection**: Detects any payload edit, record insertion, record deletion, record re-ordering, fractional/negative sequence numbers, and unparseable lines. Once broken, the chain seals itself and refuses further appends (`ChainBrokenException`).
- **Verification Evidence**: `Phase1Regression` tests T13-T15 and `Regression` tests `t06`, `t07` passed.

### 2.3 Path Traversal & HTTP Request Sanitization
- Rejects paths containing `..`, null bytes, `%00`, or malformed percent-encodings (`%ZZ`).
- Rejects HTTP requests with body size exceeding maximum limits (`MAX_BODY_BYTES`).
- Binds strictly to `127.0.0.1` (loopback only) by default, eliminating network exposure.

### 2.4 Authentication & Anti-Brute Force Protection
- Passwords derived using PBKDF2 with HMAC-SHA256 at 120,000 iterations (`Config.AUTH_PBKDF2_ITERATIONS`).
- Account lockout policy: Automatically locks out an account after 5 consecutive failures within 15 minutes (`isLocked`). Even correct passwords are timed out and rejected during the lockout window to prevent online guessing.
- Session tokens are cryptographically secure 256-bit random hex strings (`SecureRandom`).

### 2.5 Input Buffer & Memory Resource Safety
- All parser loops are bounded by explicit limits (`EmailParser.Limits`):
  - Maximum header size ceiling.
  - Maximum recursion depth for MIME parts.
  - Bounded base64 / quoted-printable decoder memory buffer.
