# CIPHER SQUAD — Detection Engine Architecture
**Platform: Pure Java JDK 25 Local-First Threat Detection Engine**

## 1. Engine Architecture & Signal Flow

```
[ RFC 822 Email ]
       │
       ▼
[ EmailParser & Headers ] ──▶ Hop Extraction & Auth-Results Parsing
       │
       ▼
[ TextNormalizer ]        ──▶ NFKC, Invisible Stripping, Confusable Folding
       │
       ▼
[ Features Extraction ]   ──▶ IDENT, NLP, AUTH, NET Feature Vector (26 dims)
       │
       ▼
[ Multi-Class Model ]     ──▶ Max-Shifted Softmax + BEC Noisy-OR Blend
       │
       ▼
[ Attribution & Enrich ]  ──▶ Geolocation, ASN, Reroute / Anomaly Factors
       │
       ▼
[ CampaignEngine / Case ] ──▶ Jaccard Clustering + Tamper-Evident Audit Append
```

## 2. Subsystem Specifications

### 2.1 Parser Subsystem ([EmailParser.java](file:///sih_java/src/EmailParser.java), [Headers.java](file:///sih_java/src/Headers.java))
- Pure JDK RFC 5322 & RFC 2045/2046 compliant stream parser.
- Extracts `Received:` headers in strict reverse chronological order, tracking sender IP, receiving MTA, ESMTP ID, timestamps, and delay deltas.
- Extracts `Authentication-Results` for SPF, DKIM, DMARC statuses.
- Tolerates malformed MIME, folded header lines, and nested multipart boundaries without crashing.

### 2.2 Text Normalization Subsystem ([TextNormalizer.java](file:///sih_java/src/TextNormalizer.java))
- **Stage 1 (NFKC Composition)**: Folds fullwidth forms and ligatures to canonical ASCII.
- **Stage 2 (Invisible Stripping)**: Explicitly strips U+200B (Zero Width Space), U+200C (ZWNJ), U+200D (ZWJ), U+2060 (Word Joiner), and U+FEFF (BOM/ZWNBSP).
- **Stage 3 (Confusable Folding)**: Deterministic character projection mapping using `data/confusables.tsv`. Folds Cyrillic (e.g., Cyrillic 'а', 'е', 'о', 'р') and Greek (e.g., 'π', 'α', 'υ', 'ρ', 'λ') homoglyphs.
- **Stage 4 (Script Analysis)**: Calculates script distribution and flags mixed-script strings.

### 2.3 Feature Vector Families ([Features.java](file:///sih_java/src/Features.java))
- **IDENT Family**:
  - `lookalike_distance`: Minimum Damerau-Levenshtein distance between domain skeleton and known brands.
  - `replyto_freemail`: Mismatch between sender domain and free webmail Reply-To.
  - `exec_impersonation`: Detection of executive names or aliases in From/Display-Name or body.
- **NLP Family**:
  - Urgency keywords, financial / wire transfer requests, credential harvesting triggers.
  - Homoglyph ratio and mixed-script frequency in domain and body.
- **AUTH Family**:
  - `spf_pass`, `spf_fail`, `dkim_pass`, `dkim_fail`, `dmarc_pass`, `dmarc_fail`.
  - Alignment checks between RFC 5321.MailFrom and RFC 5322.From.
- **NET Family**:
  - Hop delay anomalies (e.g., negative delta or massive pause).
  - Geolocation jump anomalies (impossible travel velocity > 900 km/h between successive hops).
  - High-risk / bulletproof ASN and dynamic IP sender flags.

### 2.4 Correlation & Campaign Clustering ([Correlate.java](file:///sih_java/src/Correlate.java))
- Compares email feature vectors using weighted cosine similarity and indicator Jaccard similarity across domains, URLs, sender IP subnets, and attachment hashes.
- Automatically groups related attacks into persistent campaigns (`CampaignEngine.java`).
