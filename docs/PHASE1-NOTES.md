# PHASE1-NOTES.md

Phase 1 build notes, conflict register and open decisions.

## 0. Provenance of the authoritative specs

The repository was empty at Phase 1 start (`sih2026`: 0 tracked files, no commits, no stash,
no dangling git objects). The governing specs were **not** at the repo root. They were located
off-repo and copied in byte-exactly (SHA-256 verified identical):

| Spec | Origin (off-repo) | Copied to | SHA-256 (first 16) |
|---|---|---|---|
| ARCHITECTURE.md | `C:\Users\rabig\Downloads\freebucks\docs\` | `docs/ARCHITECTURE.md` | `00BDD90FBD1ABD2E` |
| SCORING-MODEL.md | `C:\Users\rabig\Downloads\freebucks\docs\` | `docs/SCORING-MODEL.md` | `B8ADA39B3D2E36F7` |
| ROADMAP.md | `C:\Users\rabig\Downloads\freebucks\docs\` | `docs/ROADMAP.md` | `6E3EB26B4C9D4789` |
| docs/REVIEW-A.md | **does not exist on this machine** | n/a | n/a |

`freebucks` is a misleadingly named directory; its ARCHITECTURE.md is titled
"Cipher Squad - Architecture and Analysis Flow" and mandates JDK 25 + zero third-party Java
dependencies, which matches this build.

**Do not confuse** with `C:\Users\rabig\Downloads\cipher squard -ai powered email threat detection\`.
That is a *Python/FastAPI* codebase (~25 backend modules, ~40 pytest files) with a different,
unrelated `docs/ARCHITECTURE.md` (a Python Phase 1 ADR log) and **no** SCORING-MODEL.md. It is
not the Java engine and was not used as a source of truth.

## 1. Greenfield, not an extension

Both prompt bodies state "Inspect the existing source tree and extend it. Do not rewrite working
code." **No Java source tree exists.** Evidence:

- `sih2026`: empty git repo.
- `Desktop\AI - Powered email threat detection\`: `App.java`, `index.html`, `README.md`,
  `run.ps1` are all **0 bytes**; only `CipherSquad\run.ps1` (2891 B) has content.
- The only populated Cipher Squad code is the Python project above, which is a different codebase.

Consequence: Phase 1 is a greenfield implementation. "Do not rewrite working code" is satisfied
vacuously. Nothing is being discarded. Decided with user approval.

## 2. Conflict register (specs win, per both prompt bodies)

Every conflict between the prompt body and the specs, with the governing spec line and the
resolution actually implemented.

### C-01 Class taxonomy - CHANGED
- Prompt body: `LEGITIMATE, CREDENTIAL_PHISHING, BEC, MALWARE_DELIVERY, INVOICE_FRAUD, ADVANCE_FEE, SPAM_BULK, SPOOFING_ONLY`
- Spec SCORING-MODEL L135-136: `0 legitimate  1 suspicious  2 impersonation  3 phishing  4 bec  5 fraud  6 malware  7 spam`
- **Resolution:** spec taxonomy implemented. The prompt list is a *different* 8-class taxonomy
  (splitting phishing/credential-phish, adding invoice/advance-fee, lacking suspicious/impersonation).
  K=8 is unchanged.

### C-02 Feature families - CHANGED
- Prompt body: F1 auth, F2 sender identity, F3 URLs, F4 content, F5 attachments, F6 routing
- Spec L35-117: F1 AUTH, F2 ROUTE, F3 IDENT, F4 NLP, F5 PAYLOAD, F6 INFRA
- Only F1 and F4 coincide. The prompt's F2/F3/F5/F6 do not map onto the spec's F2/F3/F5/F6.
- **Resolution:** spec families implemented verbatim. In particular **F6 is INFRA (ASN/VPN/TOR/
  cloud/reputation), not routing** - routing lives in F2.

### C-03 Feature granularity - CHANGED
- Prompt body: 6 scalar features `x_f`.
- Spec L35-117: **60 named sub-features**, each with its own definition, normalisation and
  expected-value semantics.
- **Resolution:** the model is fitted over the 60 named sub-features. See Open Decision OD-1.

### C-04 ECE bin count - CHANGED
- Prompt body: ECE with 15 bins.
- Spec L410: `B = 10 equal-width bins over [0,1]`.
- **Resolution:** 10 bins.

### C-05 Thresholds - CHANGED
- Prompt body: `tau = C_FP / (C_FP + C_FN)`, defaults `auto-block C_FP=20,C_FN=1`, `alert C_FP=5,C_FN=1`.
- Spec L200-215: empirically derived `tau_high = max{tau : FPR(tau) <= 0.010}` and
  `tau_susp = max{tau : FPR(tau) <= 0.050}`, persisted in `model.json` with the achieved FPR/recall
  and the split it was fitted on.
- **Resolution:** spec method implemented. The prompt's cost-ratio formula is a different
  concept (cost-optimal vs recall-maximising-under-FPR-cap) and is **retired**. The spec's
  alert severity ladder (LOW>=20 / MEDIUM>=40 / HIGH>=60 / CRITICAL>=80, L219) is retained
  because it is a separate operational construct in the spec.

### C-06 Clustering - CHANGED
- Prompt body: link on shared sender domain, shared URL host, or subject-simhash Hamming <= 6.
- Spec L336-353: `sim = 0.25*J(headers) + 0.30*J(domains) + 0.20*J(ips) + 0.20*cos(tfidf) + 0.05*J(attachment_hashes)`,
  keep edges `sim >= tau_cluster = 0.62`, union-find over connected components.
- **Resolution:** spec similarity and `tau_cluster = 0.62` implemented. Simhash is not used.

### C-07 Model file location and name - CHANGED
- Prompt body: `config/weights.json`.
- Spec ARCH L216-217 and SCORING L214: `data/model.json` holding
  `{version, beta[], g[], gamma, tau_high, tau_susp, tau_cluster, lambda, trained_on, metrics{...}}`.
- **Resolution:** `data/model.json`. The prompt's `config/weights.json` is not produced.

### C-08 Missing-model behaviour - CHANGED (safety-relevant)
- Prompt body item 4: "Engine loads weights.json if present; otherwise it falls back to the Config
  hand-set weights and reports `weights_source: hand-set-uncalibrated`."
- Spec ARCH L269: **"Model file missing | Refuse to start analysis, log `MODEL_MISSING`; do not
  fall back to a guessed score."**
- **Resolution: the spec's refusal is implemented.** A hand-set weight fallback would return a
  score the spec explicitly forbids. To keep the refusal off the normal operating path, a
  genuinely fitted `data/model.json` is produced by `tools/fit.java` and shipped, so
  `weights_source` is `fitted`. The hand-set matrix in `Config` exists only as the *initialisation*
  for the fitter, and `hand-set-uncalibrated` is reachable **only** if the model file is deleted -
  in which case analysis refuses with `MODEL_MISSING` per spec rather than silently scoring.

### C-09 Gradient clipping in the fitter - CHANGED
- Prompt body item 4: "gradient ZEROED for clipped terms exactly as in the forward pass."
- Spec L445-447: the gradient is the plain multinomial gradient
  `dJ/dbeta_fk = SUM_n (P_nk - y_nk) * x_nf + 2*lambda*beta_fk`, with no clip masking.
- **Resolution:** spec gradient used. Note this is not merely cosmetic: the forward pass clips
  `beta_fk * x_f` to +/-2.5 (L146), so masking the gradient at the clip boundary makes the
  fitter unable to recover a coefficient that has been pinned by the clip. The spec's plain
  gradient keeps the fitter convergent. The clip remains in the forward pass and in attribution
  as required (L146, L231).

### C-10 Coverage weights - CHANGED
- Prompt body: hand-set `v_f` coverage weights.
- Spec L119-123 gives fixed family weights `W_AUTH 0.20, W_ROUTE 0.18, W_IDENT 0.18, W_NLP 0.17,
  W_PAYLOAD 0.15, W_INFRA 0.12`; spec L270 separately defines `v_f` as "its absolute learned
  coefficient".
- The spec states both. **Resolution:** `C_cov = SUM_observed v_f / SUM_all v_f` with
  `v_f = |beta_f|` (L270, the normative definition), and the family weights `W_*` are reported
  alongside for analyst context. See Open Decision OD-2.

### C-11 Class and file names - CHANGED
- Prompt body: `JsonUtil`, `EmailParser`, `ForensicEngine`, `ForensicEngineTest`, `tools/Fit.java`,
  `tools/Evaluate.java`, `tools/EvasionRun.java`, `tools/VerifyReport.java`.
- Spec ARCH L291-318 recommends: `Json.java`, `Headers.java`, `Model.java`, `Features.java`,
  `Correlate.java`, `Report.java`, `Store.java`, `tools/fit.java`, `tools/evaluate.java`,
  `tests/regression.java`.
- **Resolution:** spec names used. ARCH L289 calls the layout "Recommended", so the Phase 1
  additions `TextNormalizer.java` (item 2), `OrgProfile.java` (item 3), `data/confusables.tsv`
  and `config/org-profile.json` are added without contradicting it. `tests/regression.java` is
  the test entry point; class names are lower-camel per the spec layout.

### C-12 Java version - CHANGED
- An earlier prompt revision said Java 17; the current body, ARCH L11 and the installed JDK
  all say 25.
- **Resolution:** JDK 25 (`--release 25`). Machine has JDK 25.0.2 LTS at
  `C:\Program Files\Java\jdk-25.0.2`.

### C-13 Test assertion on `0.6r` - DROPPED
- Prompt body requires "base64-decoded `0.6r` appears in attachment extensions".
- The spec's attachment features are `attachment_dangerous` (exe/scr/js/vbs/lnk/jar/hta),
  `attachment_macro`, `attachment_archive`, `attachment_double_ext` (L100-103). There is no
  "archive extension" feature, and `0.6r` is not in any spec list.
- **Resolution:** assertion dropped. Inventing a feature to satisfy it would violate "no score
  may be hardcoded, invented, or produced by a code path that is not described here" (L5-6).
  The zero-width / homoglyph domain and skeleton-equality assertions are kept, since they map
  onto real spec features (`homoglyph_ratio`, `lookalike_strong`).

### C-14 `bec_score` wording - RECONCILED
- Spec L182: "`bec_score` is reported separately and never folded back into `risk`."
- Spec L186: `risk_final = 100 * (1 - (1 - P_notlegit) * (1 - w_bec * P_bec))`.
- These are reconcilable, not contradictory: `bec_score = 100*P_bec` is reported standalone and
  is not substituted into `risk`; `risk_final` is a *separate* blended quantity that consumes
  `w_bec * P_bec` via noisy-OR.
- **Resolution:** both emitted. `risk` and `bec_score` reported independently; `risk_final` is
  the noisy-OR blend and is what alerts fire on.

### C-15 Prompt additions that do NOT conflict (kept)
  - Ed25519 report signing, the hash-chained audit log, evasion harness, alert gating on
    `weights_source == "fitted"`, and the `homepage`/`security.txt` mismatch test are **not**
    contradicted by the specs and are kept.
  - Ed25519 is specified in **ROADMAP.md L234-251** (section 2.2, "Digitally signed forensic
    reports"), not in ARCHITECTURE.md. An earlier draft of this file cited ARCHITECTURE.md for
    it; that citation was wrong and is corrected here. ROADMAP L241 notes "Ed25519 is in the
    JDK - no dependencies", so it costs nothing.
  - The hash-chained audit log is specified in **ROADMAP.md L213-219** (section 2.1), likewise
    not ARCHITECTURE.md. Same correction.
  - Loopback binding is ARCHITECTURE.md **L230** ("loopback bind by default"), so
    `127.0.0.1` as the default bind address is spec-consistent. The spec states it as a
    *default*, not a hard constant, so the address is overridable; it is not.

### C-16 Audit record shape - SUPERSET ADOPTED
- Prompt body item 7: `{index, ts, event, payload, prev_hash, hash}` with
  `hash = SHA-256(prev_hash || canonical_json(record sans hash))` and
  `genesis prev = SHA-256("cipher-squad-genesis")`.
- Spec ARCHITECTURE.md L211: `data/audit.ndjson  {ts, actor, action, subject, outcome, detail}`.
- Spec ROADMAP.md L215 only states the property: "Each audit record carries the hash of its
  predecessor, forming a verifiable chain".
- These are not contradictory but neither fully contains the other: the spec names the
  operational fields, the prompt names the chain mechanics the spec leaves as prose.
- **Resolution:** adopt the prompt's chain structure **and** carry the spec's named fields
  (`actor`, `action`, `subject`, `outcome`, `detail`) inside the record's `payload` object, so
  the emitted record is a superset satisfying both documents. Chain mechanics follow the
  prompt exactly, since the spec does not specify them precisely enough to override it.

### C-17 Report signature envelope - SUPERSET ADOPTED
- Prompt body item 7: reports carry `{sig_alg, key_id = SHA-256 of public key, signature,
  signed_at, chain_head}`; the signature is over the chain head.
- Spec ROADMAP.md L246-248: `sig = Ed25519.sign( SHA256( canonical_report_body ), private_key )`,
  `envelope = {report, sig_alg:"Ed25519", key_id, public_key, signature, signed_at}`, and a
  verify step that must "recompute hash, verify signature, verify chain-head binding".
- The spec signs the *report body* and treats chain-head binding as a separate verification
  step; the prompt signs the *chain head*. Signing the chain head instead of the body would
  make the signature independent of the report content, so a valid report body could be
  swapped for another under the same signature.
- **Resolution:** sign `SHA-256(canonical_report_body)` per ROADMAP L246, and place
  `chain_head` **inside the signed body**, which is what actually implements ROADMAP L248's
  "verify chain-head binding" and simultaneously gives the prompt its `chain_head` field. The
  envelope is a superset of both: `{sig_alg, key_id, public_key, signature, signed_at,
  chain_head}`. `tools/VerifyReport.java` re-derives the body hash, verifies the signature, and
  checks `chain_head` against the audit log, which is all three verifications ROADMAP L248
  asks for.

### C-18 `chmod 600` on the signing key - NOT POSSIBLE ON THIS PLATFORM
  - See C-23 for the current position. The short version: POSIX `600` is applied where the
    filesystem supports it, and on Windows the key is written unprotected and the gap is
    stated rather than papered over with a read-only attribute.
- Prompt body item 7: key at `data/keys/ed25519.pem`, "note chmod 600".
- No spec mentions file permissions. The platform is Windows (`win32`, PowerShell 5.1), which
  has no `chmod`; the `java.nio.file.attribute.PosixFilePermission` API throws
  `UnsupportedOperationException` on a non-POSIX file system.
- **Resolution:** do not fake it. The key is written with owner-only ACL where the platform
  supports it via `AclFileAttributeView` (NTFS), the key file is created with restrictive ACLs
  by `KeyStore.java`, and both `README.md` and the generated key comment state the intended
  POSIX requirement (`chmod 600`) together with the honest statement that on Windows the
  guarantee comes from the inherited profile ACL rather than POSIX bits. This is recorded as a
  platform limitation, not silently claimed as done.

## 3. Open decisions needing user confirmation

**OD-1. Model dimensionality.** Spec §1 defines 60 named sub-features; §2 writes
`SUM_f` without stating whether `f` ranges over sub-features or the 6 families. Implemented as
**60 sub-feature dimensions**, because §4's rationale template requires a per-finding
`expected_value`, which only makes sense for a named sub-feature
(`attachment_double_ext` has an expected value; "PAYLOAD" does not). If the intent was 6 family
dimensions, `beta` and `g` must be re-shaped and `fit.java` re-run.

**OD-2. Coverage weight source.** Spec L119-123 and L270 disagree (fixed family weights vs
`|beta_f|`). Implemented as `v_f = |beta_f|` per the normative definition in §5.2, with family
weights reported for context. If fixed family weights were intended, `C_cov` changes and the
abstention gate (C < 0.50) will fire at different rates.

**OD-3. Calibration split and ECE target.** Spec §11 test 9 requires ECE < 0.05 on the test
split, or the failure printed. Weights are fitted on a **synthetic** corpus, so this target is
not achievable in any meaningful sense. The test asserts the *pipeline* runs and prints ECE; the
value itself is reported honestly, not asserted.

## 4. Encoding hazard (will corrupt the exact disclaimer)

`docs/SCORING-MODEL.md` and `ARCHITECTURE.md` are **BOM-less UTF-8** containing em-dashes and
ellipses. Windows PowerShell 5.1's console and `Get-Content` default to a legacy code page and
render these as `?`, silently corrupting any string read through them. Observed during spec
extraction.

Mitigation in force: all spec reads use `[System.IO.File]::ReadAllLines(path, [Text.Encoding]::UTF8)`
or the `read` tool, never `Get-Content` without `-Encoding UTF8`. The disclaimer constant is
verified byte-exact (see below).

**Exact disclaimer string** (spec L319-320, verified: 154 characters, pure ASCII, apostrophe is
U+0027 in `individual's`):

```
Geolocation indicates infrastructure registration/hosting. It is not personal attribution and must not be treated as evidence of an individual's location.
```

## 5. Machine capability baseline (honest status, Phase 1)

| Capability | Status | Evidence |
|---|---|---|
| JDK 25 | LIVE | 25.0.2 LTS, `C:\Program Files\Java\jdk-25.0.2` |
| PowerShell | 5.1 | `run.ps1` avoids `&&` and PS7-only syntax |
| ip-api.com geolocation | reachable | `http://ip-api.com/json/8.8.8.8` returned real data |
| RDAP (rdap.org) | reachable | HTTP 200 for `https://rdap.org/domain/example.com` |
| Yara | binary present | `yara64.exe` (WinGet) |
| ClamAV | absent | no `clamscan`/`clamdscan` on PATH |
| Rspamd | absent | no `rspamc` on PATH; needs external config |
| Network for core tests | not required | core suite is offline-only by design |

## 6. Known limitations carried into Phase 1

- Weights are fit on **SYNTHETIC** data. Not evidence of real-world accuracy. Uncalibrated for
  real traffic.
- No malware sandbox. No attachment static analysis. No QR decoding.
- Enrichment is **offline** in Phase 1: no ip-api/RDAP/DNS network calls in the test path.
  `Enrich` adapters and their circuit breakers are wired but the deterministic suite stubs them.
- `InferenceEngine` is pure: no file, network or wall-clock reads. This is the structural rule
  that makes the model testable without fixtures.

### C-19 Parser limits: task text governs, and Config had drifted
  - Item 1 of the task states six caps verbatim: 5 MB message, 100 headers, 25 `Received`,
    1000 URLs, 10 MB attachment, 2000 base64 lines. **The specs are silent on all six**, so the
    task governs and these are requirements, not prompt additions.
  - `Config` previously carried 2 MB / 500 headers / 500 URLs, which matched neither the task
    nor any spec. That was unexplained drift and is now corrected to the task values.
  - Two caps had **no enforcement at all**: the `Received` count and the base64 line count. Both
    are now enforced, with new warning codes `RECEIVED_COUNT_EXCEEDED` and
    `BASE64_LINE_LIMIT_EXCEEDED`. The `Received` cap keeps the OLDEST hops (closest to the
    sender) and discards the tail, because the tail is attacker-controlled.
  - Remaining `Config` values not stated by the task or specs, and therefore **additions**:
    `MAX_HEADER_LINE_BYTES` (8 KB), `MAX_MIME_DEPTH` (8), `MAX_MIME_PARTS` (200),
    `MAX_DECODED_BYTES` (10 MB), `PARSE_TIME_BUDGET_MS` (2 s). These are defensive bounds
    needed to make the parser total, not spec requirements.

### C-20 Greek upsilon folds to `y`, not `u` (deliberate deviation)
  - The task requires the Greek spellings of a brand to reduce to the **same** skeleton as the
    Latin one. `confusables.tsv` mapped capital upsilon `U+03A5` to `y` but small upsilon
    `U+03C5` to `u`, so the Greek spelling of `paypal` folded to `paupal` - a different skeleton,
    which defeats the entire point of the lookup.
  - `U+03C5` and `U+03CD` are therefore mapped to `y`, consistent with `U+03A5`. Upsilon is the
    etymological ancestor of Latin `y`, so `y` is the defensible target.
  - **Cost, stated honestly:** this makes `U+03C5` indistinguishable from Latin `u` after
    normalisation. Genuine Greek text containing upsilon is folded as though it said `y`. That
    is an accepted false-positive risk in exchange for not missing the attack, and it only
    affects the *skeleton*, which feeds edit-distance lookalike scoring - never a verdict on
    its own.

### C-21 Defects found and fixed by `tests/regression.java` (items 1-3)
  - **LF-only bodies were corrupted.** `parseComplete` advanced past the header/body blank line
    by a hardcoded 4 bytes (CRLF), so a bare-LF message lost its first two body characters
    (`body` -> `dy`). Now measured with `skipLineBreak` twice. This silently corrupted every
    LF-only message, which is a large share of real mail from Unix senders.
  - **MIME parts without a blank line threw.** `indexOfBlankLine` can return -1; the result
    was passed straight into `indexOfLineEnd`, throwing `StringIndexOutOfBoundsException` on
    truncated or hostile MIME. A parser advertised as never throwing on bad input did throw.
  - **MIME depth cap truncated silently.** The guard at `depth >= MAX_MIME_DEPTH` returned
    without emitting any warning, so a message nesting past the cap hid content with no
    `parse_warning`. It now reports `MIME_DEPTH_EXCEEDED`.
  - **`received` cap NPE.** The first implementation read `headers.get("received")` before the
    key existed, throwing on the very first `Received` header.
  - **Unobserved features were unexplained.** `Vector.notes` now carries one summary note
    naming every unobserved feature and the resulting C_cov reduction, so a report can explain
    a lowered confidence without re-diffing the vector.
  - `Model.java` still compiles with an unchecked-operations warning and still has the
    `weights_source` / family-split defects recorded above. Those belong to item 4 and are
    **not** fixed yet.

### C-22 Class split: `Sign.java` and `Audit.java` extracted from `Crypto.java`
  - `Crypto.java` previously held four unrelated responsibilities: canonical JSON, SHA-256,
    Ed25519 signing, and the audit chain. The brief requires the last two to be separate
    deliverables, so they now live in `Sign.java` and `Audit.java` and `AuditLog.java` is
  - deleted. `Crypto` is retained, but only as the canonical-JSON and SHA-256 support that
  audit and signing both call; its signing API is gone and no caller references it.
  - The hash contract is unchanged, so existing chains and signatures still verify.

### C-23 Windows cannot do `chmod 600` on a file, and pretending otherwise is worse
  - Supersedes the position in C-18. The earlier implementation set the DOS read-only
    attribute on the PEM and reported the key as protected. That is not a security control:
    a read-only file is trivially cleared with `attrib -R`, and the attribute says nothing
    about who can read the key. It also broke the test suite, because a read-only fixture
    cannot be replaced on a second run.
  - `KeyManager.createOrLoad` now applies POSIX `600` **only when the filesystem reports
    POSIX support**, and otherwise writes normal permissions while recording honestly that
    the key is not access-restricted. On Windows the operator must set an NTFS ACL on the key
    file and the containing directory, or keep the key in an HSM or a secrets manager. This
    is a deployment requirement, not something the code can satisfy.

### C-24 The audit chain must be read through the locked channel on Windows
  - `append` takes a process-wide `FileLock` on the chain, verifies it, and appends under that
    lock. The first implementation then read the chain with `Files.readAllLines(path)` from
    inside the lock. On Windows that opens a *second* independent handle to a file the
    `RandomAccessFile` currently holds open for writing, and it fails outright:
    `IOException: The process cannot access the file because another process has locked a
    portion of the file`.
  - The symptom was deeply misleading - the exception surfaced as `cannot read audit log`,
    which reads as "the log is corrupt" rather than "this code is doing something the platform
    forbids". It broke every single append, on an empty chain, with no corruption present.
  - `readLinesLocked(FileChannel)` now reads the whole chain through the channel that already
    holds the lock, using positional reads (`ch.read(buf, pos)`) which do not move the write
    position, so reading the tail to recompute the head cannot corrupt the append that follows.

### C-25 A fractional sequence number passed verification
  - Verification read the record index as `(int) (double) rec.get("index")`. JSON has no
    integer type, so every index arrives as a double, and **`(int) 1.5` is `1`**. A record
    renumbered from `1` to `1.5` therefore verified as if it were untouched.
  - `readIndex` now requires the value to be a finite, non-negative, exactly integral
    `Number` and returns null otherwise. A non-integer index is a tamper signal, and quietly
    truncating it is precisely the acceptance an audit chain exists to prevent.

### C-26 The BEC blend was computed, reported, and then discarded
  - `riskFinal` consumed the raw BEC **head** value `pBec`, while `becBlendedProbability` was
    computed and stored for the report. The published blend and the published score were two
    different numbers: a report could state one while the score came from the other.
  - `riskFinal` now uses `becBlendedProbability`. With no external evidence `becNoisyOr` is 0,
    so the blend collapses to the head and the formula reduces **exactly** to the documented
    L186 expression - no behaviour change in the no-evidence case, and correct in the
    evidence case. A test reproduces `riskFinal` from the published fields to keep them pinned.

### C-27 `becBaseProbability` was documented as a softmax value but was not one
  - The field's javadoc said "P(BEC) from the base classifier's softmax" while the blend used
  - the dedicated head's sigmoid output. The two are different quantities.
  - Resolved by reporting both, with explicit names: `becBaseProbability` is the BEC **head**,
    which is what the risk formula consumes, and `becClassProbability` is the softmax class
    probability. The test asserts they are distinct, so they cannot silently be conflated again.

### C-28 The eight classes are now typed, not eight strings
  - `Config.CLASS_NAMES` is a `String[]`, which cannot satisfy "exactly eight typed classes":
    it admits typos at call sites, an out-of-range index throws a bare
    `ArrayIndexOutOfBoundsException` naming no class, and nothing prevents a ninth label.
  - `Config.Cls` is a closed enum whose ordinals are the class indices. A static block asserts
    the enum and `CLASS_NAMES` agree in both directions, so they cannot drift apart silently.
    `Config.classNames()` returns a defensive copy because the array is still publicly mutable.
  - `Score.argmaxClass` carries the typed argmax, and `Score` also now carries `intercept`,
    `modelVersion`, `weightsSource`, and `trainedOn` so a stored score can be traced to the
    weights that produced it.

### C-29 The baseline model covered 6 of 60 features
  - `Model.initial()` built a 6-feature weight matrix and advertised `featureCount = 6`, so
    every one of the other 54 declared features was silently unavailable and the coefficients
    for the real model were all zero. A caller passing 60 features was rejected outright.
  - The baseline now expands each class's `INITIAL_BETA_BY_FAMILY` row across all 60 real
    features, scaled by `1 / familySize`, so the hand-set weights actually reach every feature.
    It is still explicitly `HAND_SET_UNCALIBRATED` and makes no accuracy claim.

### C-30 Features: range, provenance, and escaping arrays
  - **Range.** Features are declared normalised to `[0,1]`, but `put` accepted anything. An
    out-of-range value is now quarantined to 0 with `observed = false` and a note, rather than
    clamped - clamping would hide the upstream bug and quietly change the score, making a wrong
    number look like a legitimate weak signal.
  - **Provenance.** `Vector` records a per-feature `reason` for every write, exposed via
    `reason(int)`, `reason(String)`, `provenance()`, and `toMap()`. Without it a dump says
    `dkim_fail = 1.0` and not whether the header was absent, malformed, or never examined.
  - **Escaping state.** `x` and `observed` were public arrays, so any caller could write `1e9`
    into a feature and the `[0,1]` contract became a comment. They are now private, reachable
    through `get`, `isObserved`, `toArray()`, and `observedArray()`, which all return copies.

