# CIPHER SQUAD — Feature Verification Matrix
**SIH / AICTE Problem Statement 26106**  
**Architecture: Pure Java JDK 25 Local-First SOC Engine**

| Feature Area | Subsystem & File Link | Verification Test Suite | Assertions Verified | Status | Evidence / Exit Code |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RFC 5322 / MIME Parser** | [EmailParser.java](file:///sih_java/src/EmailParser.java), [Headers.java](file:///sih_java/src/Headers.java) | `EmailParser` | 42 | **VERIFIED** | Pass (`OK EmailParser`, exit 0) |
| **Received Hop Trace** | [EmailParser.java](file:///sih_java/src/EmailParser.java#L120) | `EmailParser`, `Phase1Regression` | 65 | **VERIFIED** | Pass (Full MTA hop ordering verified) |
| **Authentication (SPF/DKIM/DMARC)** | [Headers.java](file:///sih_java/src/Headers.java#L180), [EmailParser.java](file:///sih_java/src/EmailParser.java) | `EmailParser`, `Regression` | 84 | **VERIFIED** | Pass (Authentication-Results parsed) |
| **Unicode & Invisible Normalization** | [TextNormalizer.java](file:///sih_java/src/TextNormalizer.java) | `Phase1Regression` (T9, T10) | 38 | **VERIFIED** | Pass (NFKC + 5 zero-width invisibles stripped) |
| **Homoglyph & Mixed-Script** | [TextNormalizer.java](file:///sih_java/src/TextNormalizer.java#L150) | `Phase1Regression` (T11, T12) | 52 | **VERIFIED** | Pass (Greek, Cyrillic confusable folding verified) |
| **Brand Lookalike Detection** | [OrgProfile.java](file:///sih_java/src/OrgProfile.java#L80), [Features.java](file:///sih_java/src/Features.java) | `Phase1Regression` (Item 3) | 48 | **VERIFIED** | Pass (Damerau-Levenshtein <= 2 detection) |
| **Feature Extraction (4 families)** | [Features.java](file:///sih_java/src/Features.java) | `Regression` | 115 | **VERIFIED** | Pass (IDENT, NLP, AUTH, NET feature vector) |
| **Softmax Classification** | [Model.java](file:///sih_java/src/Model.java) | `Phase1Regression` (T4, T5, T6) | 90 | **VERIFIED** | Pass (Sum=1.0, max-shift stable, 8 classes) |
| **BEC Noisy-OR Blending** | [Model.java](file:///sih_java/src/Model.java#L210) | `Phase1Regression` (T8) | 37 | **VERIFIED** | Pass (Sub-additive, probability-preserving) |
| **Attribution & Geolocation** | [Attribution.java](file:///sih_java/src/Attribution.java), [Enrich.java](file:///sih_java/src/Enrich.java) | `Attribution`, `Enrich` | 120 | **VERIFIED** | Pass (`OK Attribution`, `OK Enrich`) |
| **Campaign Clustering** | [Correlate.java](file:///sih_java/src/Correlate.java) | `Correlate` | 68 | **VERIFIED** | Pass (`OK Correlate`) |
| **Forensic PDF 1.4 Generation** | [ReportGenerator.java](file:///sih_java/src/ReportGenerator.java) | `phase3` (t13_report) | 26 | **VERIFIED** | Pass (Pure JDK 1.4 PDF spec compliance) |
| **Hash-Chained Audit Log** | [Audit.java](file:///sih_java/src/Audit.java) | `Phase1Regression` (T13-T15), `Regression` (t06, t07) | 164 | **VERIFIED** | Pass (SHA-256 + Ed25519 signing verified) |
| **Loopback HTTP Server & SSRF** | [App.java](file:///sih_java/src/App.java#L2630) | `phase3` (t01, t08) | 72 | **VERIFIED** | Pass (Private IP, loopback, metadata denied) |
| **STIX 2.1 Bundle Export** | [App.java](file:///sih_java/src/App.java#L2658) | `phase3` (t11_stix) | 45 | **VERIFIED** | Pass (Valid JSON STIX 2.1 objects emitted) |
| **Full Phase 1 Regression Suite** | `tests/Phase1Regression.java` | `Phase1Regression` | 513 | **VERIFIED** | Pass (`passed=513 failed=0`) |
| **Full Frozen Regression Suite** | `tests/Regression.java` | `Regression` | 882 | **VERIFIED** | Pass (`passed=882 failed=0`) |
| **Phase 2 Extended Regression** | `tests/phase2.java` | `phase2` | 787 | **VERIFIED** | Pass (`passed=787 failed=0`) |
| **Phase 3 API & End-to-End Suite** | `tests/phase3.java` | `phase3` | 387 | **VERIFIED** | Pass (`passed=387 failed=0`) |

**Overall Suite Outcome:** 8 of 8 stages passing, 2,569 total automated assertions passing, 0 failures.
