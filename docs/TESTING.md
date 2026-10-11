# CIPHER SQUAD — Comprehensive Testing Architecture & Guide
**Platform:** Pure Java JDK 25 Local-First Threat Detection Engine  
**Test Automation Runner:** `run-tests.ps1`

---

## 1. Testing Strategy & Pyramid

The platform utilizes a multi-layered testing architecture designed for 100% offline reproducibility without external test frameworks or third-party dependencies:

```
                  ┌───────────────────────────────┐
                  │    Phase 3: HTTP API & E2E    │  387 Assertions
                  │   Auth, SSRF, Cases, STIX,    │  Loopback Server Integration
                  │         PDF Reporting         │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  │ Phase 2 & Extended Regression │  787 Assertions
                  │ Lookalikes, Homoglyphs, Blend │  Calibration & Feature Verification
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  │   Frozen Phase 1 Regression   │  1,395 Assertions (513 + 882)
                  │ Core Math, Softmax, Features, │  Linear Hash-Chain Tamper Detection
                  │       Damerau-Levenshtein     │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  │     Module Unit Self-Tests    │  135 Assertions
                  │ EmailParser, Enrich,          │  Direct Component Validation
                  │ Attribution, Correlate        │
                  └───────────────────────────────┘
```

---

## 2. Test Suite Inventory

### 2.1 Module Self-Tests
- **EmailParser (`EmailParser.main`)**:
  - *Location:* [src/EmailParser.java](file:///sih_java/src/EmailParser.java)
  - *Target:* RFC 5322 MIME stream parser, boundary extraction, hop extraction.
  - *Execution:* `java -cp build EmailParser`
  - *Expected Result:* `OK EmailParser` (42 assertions).
- **Enrich (`Enrich.main`)**:
  - *Location:* [src/Enrich.java](file:///sih_java/src/Enrich.java)
  - *Target:* Offline provider dataset querying, IP address normalization, GeoLite2 parsing.
  - *Execution:* `java -cp build Enrich`
  - *Expected Result:* `OK Enrich` (28 assertions).
- **Attribution (`Attribution.main`)**:
  - *Location:* [src/Attribution.java](file:///sih_java/src/Attribution.java)
  - *Target:* Hop sequencing, delay calculations, impossible travel detection (> 900 km/h).
  - *Execution:* `java -cp build Attribution`
  - *Expected Result:* `OK Attribution` (35 assertions).
- **Correlate (`Correlate.main`)**:
  - *Location:* [src/Correlate.java](file:///sih_java/src/Correlate.java)
  - *Target:* Multi-indicator Jaccard distance and weighted cosine clustering.
  - *Execution:* `java -cp build Correlate`
  - *Expected Result:* `OK Correlate` (30 assertions).

### 2.2 Phase 1 Regression Suite (`Phase1Regression.main`)
- *Location:* [tests/Phase1Regression.java](file:///sih_java/tests/Phase1Regression.java)
- *Scope:*
  - T1–T3: Feature bounds, feature vector validation, missing value masks.
  - T4–T6: Bounded linear logits, max-shifted softmax numeric stability, extreme logits ($[-10^9, 10^9]$).
  - T7–T8: Unobserved epistemic status, BEC Noisy-OR Bayesian blending.
  - T9–T12: NFKC normalisation, 5 zero-width invisibles stripping, mixed-script detection, confusable projection table determinism.
  - T13–T15: Audit log append, verification, and tamper detection (payload modification, deletion, reordering, truncation, malformed JSON, fractional index).
  - T16: Ed25519 key generation, deterministic signing, and public key verification.
- *Execution:* `java -cp build Phase1Regression`
- *Expected Result:* `passed=513 failed=0` (513 assertions).

### 2.3 Frozen System Regression Suite (`Regression.main`)
- *Location:* [tests/Regression.java](file:///sih_java/tests/Regression.java)
- *Scope:* Complete system regression spanning all 26 feature extractors, authentication, periodic audit signing cadence (every 50 records), and tamper seal verification.
- *Execution:* `java -cp build Regression`
- *Expected Result:* `passed=882 failed=0` (882 assertions).

### 2.4 Phase 2 Calibration Suite (`phase2.main`)
- *Location:* [tests/phase2.java](file:///sih_java/tests/phase2.java)
- *Scope:* Fine-grained calibration tests over lookalike distance thresholds, brand skeletons, Cyrillic/Greek homoglyphs, and risk band classification.
- *Execution:* `java -cp build phase2`
- *Expected Result:* `passed=787 failed=0` (787 assertions).

### 2.5 Phase 3 HTTP API & Integration Suite (`phase3.main`)
- *Location:* [tests/phase3.java](file:///sih_java/tests/phase3.java)
- *Scope:*
  - `t01_binding`: Loopback only (`127.0.0.1`), external interface binding denied.
  - `t02_routing`: Method constraints, 404 for unmapped paths, 405 for invalid methods.
  - `t03_traversal`: Path traversal (`..`, null bytes, `%00`) blocked.
  - `t04_oversized`: Request body ceiling enforcement (`MAX_BODY_BYTES`).
  - `t05_badPercent`: Malformed percent encoding rejected.
  - `t06_authSession`: Basic auth bootstrapping and session token validity.
  - `t07_lockout`: Brute-force lockout after 5 failures within 15 minutes.
  - `t08_ssrf`: Comprehensive SSRF filter (loopback, RFC 1918, link-local, cloud metadata, DNS rebinding).
  - `t09_audit`: Verification endpoint response hardening and live tamper detection.
  - `t10_cases`: Bounded case search, pagination, and persistence.
  - `t11_stix`: OASIS STIX 2.1 JSON bundle export validation.
  - `t12_console`: Static HTML console serving with dynamic CSP nonces.
  - `t13_report`: Pure JDK PDF 1.4 report generation and validation.
  - `t14_breakdown`: Explainable feature breakdown serialization.
  - `t15_auditAssurance`: Multi-stage audit assurance verification (`EMPTY` -> `UNSIGNED` -> `SIGNED` -> `TAMPERED`).
- *Execution:* `java -Dcipher.squad.dataDir=build/test-state -cp build phase3`
- *Expected Result:* `passed=387 failed=0` (387 assertions).

---

## 3. Boundary & Negative Testing Coverage

| Scenario | Test Location | Invariant Verified |
| :--- | :--- | :--- |
| **Empty Input** | `EmailParser.java`, `phase3.java` | Returns 400 Bad Request or empty part list; no NPE. |
| **Malformed MIME** | `EmailParser.java` | Tolerates missing headers, unterminated boundaries, truncated parts. |
| **Oversized Body** | `phase3.java:t04_oversized` | Rejects payload with 413 or RequestException; halts stream read. |
| **Path Traversal** | `phase3.java:t03_traversal` | Blocks `../../etc/passwd`, null bytes `%00`; returns 400/404. |
| **SSRF to Metadata** | `phase3.java:t08_ssrf` | Blocks `169.254.169.254`, `metadata.google.internal`, DNS rebinding. |
| **Brute Force Lockout** | `phase3.java:t07_lockout` | Enforces lockout on 5th failure; rejects valid password during lockout. |
| **Audit Log Tampering** | `Phase1Regression:T15`, `Regression:t07` | Detects modified payload, deleted row, reordered lines, sealed against append. |
| **Extreme Logits** | `Phase1Regression:T6` | Softmax remains numerically finite and sums to 1.0 under $z = \pm 10^9$. |
| **Unobserved Data** | `Phase1Regression:T7` | Missing inputs produce zero logit contribution, not guessed priors. |

---

## 4. Test Execution & Reporting Instructions

### 4.1 Running the Full Matrix
Execute from project root:
```powershell
.\run-tests.ps1
```
Use `-Quiet` to suppress individual stage logs and only output the final pass/fail banner:
```powershell
.\run-tests.ps1 -Quiet
```

### 4.2 Verified Execution Console Output
```
==> compiling
compile        PASS

==> running
EmailParser    PASS
               OK EmailParser
Enrich         PASS
               OK Enrich
Attribution    PASS
               OK Attribution
Correlate      PASS
               OK Correlate
Phase1Regression PASS
               passed=513  failed=0  (833 ms)
Regression     PASS
               passed=882  failed=0
phase2         PASS
               passed=787  failed=0  (3020 ms)
phase3         PASS
               passed=387  failed=0  (5869 ms)

ALL STAGES PASSED (8 stages)
```

---

## 5. Regression Testing Workflow for Developers

When modifying core components, follow this targeted re-verification workflow:
1. **Modifying Parsing Logic (`EmailParser.java`, `Headers.java`)**:
   Run `java -cp build EmailParser` and `java -cp build Phase1Regression`.
2. **Modifying Feature Vector or Normalization (`Features.java`, `TextNormalizer.java`)**:
   Run `java -cp build Phase1Regression` and `java -cp build phase2`.
3. **Modifying Scoring or Model Formulas (`Model.java`)**:
   Run `java -cp build Phase1Regression` and `java -cp build Regression`.
4. **Modifying Audit Logging or Signatures (`Audit.java`, `Sign.java`)**:
   Run `java -cp build Phase1Regression`, `java -cp build Regression`, and `java -Dcipher.squad.dataDir=build/test-state -cp build phase3`.
5. **Modifying HTTP Routes, Handlers or Server (`App.java`, `Http.java`)**:
   Run `java -Dcipher.squad.dataDir=build/test-state -cp build phase3`.
6. **Pre-Commit Verification**:
   Always execute `.\run-tests.ps1` before committing to ensure all 2,569 assertions pass.
