# Cipher Squad — Architecture and Analysis Flow

Companion to `docs/SCORING-MODEL.md`, which defines every number. This file defines how data
moves, where each computation lives, and where the system must fail honestly.

---

## 1. Architectural principles

1. **Local-first.** Runs on one machine with JDK 25's built-in `HttpServer` and zero third-party
   Java dependencies. No cloud, no database, no message broker.
2. **Deterministic core, network at the edges.** The model (Section 2 of the scoring doc) is pure
   arithmetic over a feature vector. Every network dependency (geolocation, DNS, RDAP, scanners)
   is an enrichment that can fail without breaking the verdict.
3. **Transactional evidence.** The raw message is hashed at ingest, before any transformation.
   Every later artifact is derived from that hash-anchored original.
4. **Honest degradation.** A failed source yields `observed = false` and a reduced confidence —
   never a fabricated value, never a silent default.
5. **Explainability is structural.** The model is linear, so the per-feature attribution is the
   exact decomposition, not an approximation produced by a separate explanation step.
6. **Every action is auditable.** Auth, analysis, case changes and evidence access append to an
   append-only audit log.

---

## 2. Layer map

```
+-----------------------------------------------------------------------------------+
| L9  PRESENTATION      index.html SPA: dashboard, relay map, findings, reports      |
+-----------------------------------------------------------------------------------+
| L8  GOVERNANCE        auth, RBAC, audit log, retention, masking, evidence integrity|
+-----------------------------------------------------------------------------------+
| L7  DECISION          bands, alert thresholds, policy engine, auto-case creation   |
+-----------------------------------------------------------------------------------+
| L6  CORRELATION       entity graph, similarity, union-find clustering, noisy-OR    |
+-----------------------------------------------------------------------------------+
| L5  INFERENCE         softmax model, BEC head, risk, confidence, attribution       |
+-----------------------------------------------------------------------------------+
| L4  ENRICHMENT        ip-api, DNS, RDAP, reputation, ClamAV/Rspamd/Yara adapters   |
+-----------------------------------------------------------------------------------+
| L3  FEATURE EXTRACTION  six families -> FeatureVector + observed[] flags           |
+-----------------------------------------------------------------------------------+
| L2  NORMALISATION     MIME parse, header unfold, ordering, canonicalise, SHA-256   |
+-----------------------------------------------------------------------------------+
| L1  INGEST            paste, .eml upload, Gmail header blob, API POST, file watch  |
+-----------------------------------------------------------------------------------+
```

### Cross-cutting concerns
- **Cache** — TTL keyed by indicator: geo 24h, DNS 15m, RDAP 24h, reputation 1h.
- **Circuit breaker** — 3 consecutive failures opens a source for 10 minutes.
- **Deadlines** — 2s per enrichment source, 6s global; inference never blocks on a source.
- **Audit sink** — append-only NDJSON, written last so it records the final outcome.
- **Hash utility** — SHA-256, single implementation, used by ingest and evidence tooling only.

---

## 3. Component responsibilities

| Component | Owns | Must never |
|---|---|---|
| `Ingest` | Accepting raw bytes, hashing, dedupe by hash | Mutate or reformat the raw message |
| `Normaliser` | MIME walk, header unfolding, charset decoding, chain ordering | Cast a heuristic vote |
| `FeatureExtractor` | All six feature families, `observed[]` flags | Perform network I/O |
| `Enricher` | Bounded, parallel, cached lookups; source health state | Invent a value when a source fails |
| `InferenceEngine` | Softmax, BEC head, risk, confidence, coverage | Read files, network, or wall-clock time |
| `Explainer` | Per-feature contributions, rationales, ordering | Add or remove any evidence |
| `Correlator` | Entity graph, similarity, clustering, campaign noisy-OR | Attribute to a person |
| `Decision` | Bands, alerts, policy, case creation | Fire an alert on `C < 0.50` |
| `Reporter` | JSON report, evidence manifest, chain-of-custody block | Omits the calibration metadata |
| `Governance` | Auth, throttling, RBAC, audit, retention, masking | Serve a path outside the web root |

`InferenceEngine` being pure is the single most important structural rule: it makes the model
unit-testable with no fixtures, no network and no clock.

---

## 4. Primary flow — analysing one email

```
   raw email
      |
      v
[1] INGEST
      hash = sha256(raw)  ·  dedupe check  ·  audit("ingest", hash)
      |
[2] NORMALISE
      decode transfer encodings + charsets
      unfold headers, preserve original order
      split into ordered header records + body parts
      derive: header chain indices, body text, attachment inventory
      |
[3] EXTRACT FEATURES            (pure, no I/O, microseconds)
      F1 AUTH  F2 ROUTE  F3 IDENT  F4 NLP  F5 PAYLOAD  F6 INFRA
      --> x[F], observed[F], and the raw evidence values behind each flag
      |
[4] ENRICH                      (parallel, deadline-bounded, cached)
      ---- fan-out over CompletableFuture, global deadline 6s ----
      |  ip-api geolocation   -> country, region, city, ISP, ASN, lat/lon
      |  DNS                  -> A, AAAA, MX, TXT, NS, CNAME, SPF, DMARC
      |  RDAP                 -> registrar, created, updated, expiry, privacy
      |  reputation store     -> local blocklist + prior-incident matches
      |  scanner adapters     -> ClamAV / Rspamd / Yara
      ---- each returns a SourceResult(value | UNAVAILABLE | NOT_CONFIGURED) ----
      fill derived features: domain_age_inv, lookalike_strong, asn_risk,
      vpn_proxy, tor_exit, cloud_hosted, geo_mismatch, reputation_low
      |
[5] INFERENCE                   (pure maths, see SCORING-MODEL.md sections 2-6)
      z_k = beta_0k + SUM clip(beta_fk * x_f)
      P(k|x) = softmax(z)
      risk, bec_score, risk_final, C_model, C_cov, C, C_attr
      |
[6] EXPLAIN
      contribution_f = clip(beta_f,k* * x_f)     for the winning class
      assert SUM contributions + bias == z_k*
      sort by |contribution| desc, attach rationale strings
      |
[7] CONFIDENCE GATE
      C < 0.50  --> UNDETERMINED, analyst queue, NO auto-alert, NO auto-case
      C >= 0.50 --> continue
      |
[8] CORRELATE
      upsert entities: domains, IPs, ASNs, registrars, reply-to aliases, attachment hashes
      score similarity against recent emails; union-find at tau_cluster = 0.62
      recompute campaign risk with the noisy-OR formula
      |
[9] DECIDE
      band from tau_susp / tau_high
      severity from 20/40/60/80 ladder
      if risk_final >= alert_threshold --> emit webhook alert (JSON)
      if band == HIGH-RISK         --> open or attach to investigation case
      |
[10] REPORT
      JSON forensic report: verdict, risk, band, confidence, attribution (+ cap + disclaimer),
      full findings with contributions, relay chain with per-hop geolocation,
      SPF/DKIM/DMARC alignment table, evidence manifest of SHA-256 hashes,
      model metadata (beta version, thresholds, calibration figures, ECE)
      |
[11] PERSIST + AUDIT
      append analysis to case store; append audit record (outcome last)
      |
      v
   JSON response to console
```

### Why this order
- The hash precedes everything so the evidence anchor is independent of parsing decisions.
- Feature extraction precedes enrichment so the model can run on a partial vector; enrichment
  only fills `observed[]` and adds derived features.
- The confidence gate sits **before** the decision layer, so low-confidence verdicts can never
  trigger an alert or create a case. That ordering is the safety property.
- Correlation runs after inference because clustering needs the final risk of each member.

---

## 5. Supporting flows

### 5.1 Standalone forensic tool call
```
request -> authz check -> cache lookup -> (hit: return) | (miss: single bounded call)
        -> normalise result -> audit append -> return with source + timestamp
On failure: HTTP 502/503 with {"status":"UNAVAILABLE","source":...,"reason":...}
Never return an empty object that reads like a real result.
```

### 5.2 Scanner status
```
on demand: probe each adapter with a short timeout
  result returned      -> LIVE
  reachable but unconfigured -> NOT_CONFIGURED
  binary/endpoint absent or error -> UNAVAILABLE
Return a per-adapter object. The console shows four distinct visual states, not a single badge.
```

### 5.3 Alert delivery
```
analysis completes -> risk_final >= threshold -> build payload
payload: severity, risk_score, classification, confidence, case_id, top findings, report ref
         -> POST to configured webhook(s) with 3s timeout, 3 retries, jittered backoff
         -> delivery outcome recorded in audit (delivered | failed | dropped)
Local receiver endpoint stores payloads as NDJSON so end-to-end alerting is verifiable offline.
Never mark an alert delivered unless the HTTP response said so.
```

### 5.4 Analyst feedback (the improvement loop)
```
analyst overrides a verdict
   -> append {features, model verdict, analyst verdict, note} to data/feedback.ndjson
   -> if new labelled samples >= 20, the console shows "retrain ready"
   -> offline refit (SCORING-MODEL.md section 9) produces new beta + recomputed thresholds
   -> new model.json ships with its calibration figures; old version kept for rollback
```
The system never retrains itself silently at runtime. Every model change is a reviewed, versioned
artifact with its own accuracy report.

### 5.5 Live flow (near-real-time)
```
file watcher / API ingest -> same pipeline -> alert emitted before a human opens the mailbox
```
The path from ingest to alert must not include any human step. That is what makes it
"before user interaction".

---

## 6. Data model (NDJSON stores)

```
data/cases.ndjson      {id, created, status, title, risk_campaign, confidence_mean,
                        members[], entities[], notes[], timeline[]}
data/audit.ndjson      {ts, actor, action, subject, outcome, detail}   append-only
data/users.ndjson      {user, salt, iterations, hash, roles, created, disabled}
data/alerts.ndjson     {ts, severity, risk_score, classification, confidence, case_id,
                        findings[], report_ref, delivery}
data/feedback.ndjson   {ts, email_hash, features, model_verdict, analyst_verdict, note}
data/model.json        {version, beta[], g[], gamma, tau_high, tau_susp, tau_cluster,
                        lambda, trained_on, metrics{brier, ece, macro_f1, mcc, pr_auc}}
data/reports/<hash>.json   immutable forensic report per analysed message
```
Rules: append-only for `audit` and `feedback`; `reports` written once and never edited; retention
policy trims by age; masking applied on read for configured sensitive fields, not on write, so the
underlying evidence stays intact.

---

## 7. Security boundaries

```
Internet / user
   |  (loopback bind by default)
   v
[ Auth gate ]   PBKDF2-HMAC-SHA256, 120k iterations, 16-byte salt, constant-time compare
   |            per-account AND per-IP throttle; 5 fails / 15 min -> HTTP 429 + temp lock
   |            dummy-hash verification for unknown accounts (equal cost, no enumeration)
   |            32-byte SecureRandom session tokens, 8h expiry, no tokens in URLs
   v
[ Routes ]  JSON only; body size bounded; input validated before use
   |
   +--> [ Static handler ]  canonicalise path -> assert inside web root -> else 404
   |
   +--> [ Analysis routes ] -> pure pipeline
   |
   +--> [ Outbound ]  SSRF guard (PhishGuard probe + any user-supplied URL)
                      resolve first, block loopback/link-local/private/multicast/reserved,
                      re-validate after every redirect, cap redirects, cap response size,
                      timeout 3s
                      Process execution for scanners: argument vector only, allow-listed
                      binaries, no shell interpolation, no user-controlled arguments
   v
[ Enrichment ]  outbound allow-list: ip-api.com, DNS resolver, RDAP endpoints, configured scanners
```

Response headers on every route: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, restrictive `Content-Security-Policy`,
`Cache-Control: no-store` for authenticated responses.

---

## 8. Failure modes and required behaviour

| Failure | Required behaviour |
|---|---|
| Geolocation source down | `observed=false`, features degrade, `C_cov` drops, network badge `UNAVAILABLE` |
| DNS timeout | `domain_age_unknown` set, no invented age |
| RDAP rate-limited | `NOT_CONFIGURED`/`UNAVAILABLE`, privacy flags set to `unknown`, not `false` |
| Scanner binary missing | Adapter reports `UNAVAILABLE`; scan endpoint returns 503, not `"clean"` |
| Malformed MIME | Parse what is possible, list the parse errors as findings, never crash |
| Body over limit | HTTP 413 with the limit stated |
| Model file missing | Refuse to start analysis, log `MODEL_MISSING`; do not fall back to a guessed score |
| Partial enrichment | Verdict still returned, confidence reduced, reasons listed |

The single rule behind all of these: **a failure is data the analyst must see, not a condition to
be smoothed over.**

---

## 9. Observability

Per request, record: request id, actor, route, duration, cache hits/misses, per-source outcome and
latency, model version, verdict, confidence, whether an alert fired, and whether the audit append
succeeded. Aggregate counters the console displays: requests, cache hit rate, per-source health,
alerts by severity, abstention rate, and mean confidence.

Track **abstention rate** and **mean confidence** as first-class health metrics — a rising
abstention rate means enrichment is degrading, and that is the earliest visible sign of trouble.

---

## 10. Recommended file layout

```
run.ps1                     compile + launch, port check, clear error if occupied
index.html                  full SPA (inline CSS + JS, no CDN, works offline)
src/
  App.java                  bootstrap, routing table, lifecycle
  Http.java                 request/response helpers, security headers
  Json.java                 parser + serialiser (the only JSON implementation)
  Model.java                beta, g, gamma, thresholds, softmax, confidence
  Features.java             six feature families, observed[] tracking
  Headers.java              RFC 822 header parser, chain ordering, alignment checks
  Enrich.java               ip-api / DNS / RDAP clients, cache, breaker, deadlines
  Correlate.java            entity graph, similarity, union-find, noisy-OR
  Auth.java                 PBKDF2, throttling, sessions, RBAC helpers
  Store.java                NDJSON append/read, retention, masking on read
  Report.java               forensic report assembly, evidence manifest
  Ssrf.java                 address validation + guarded probe
  Scanners.java             ClamAV / Rspamd / Yara adapters with honest status
data/                       NDJSON stores, created on first run
tools/
  fit.java                  offline coefficient fitting + threshold derivation
  evaluate.java             corpus runner, all metrics from SCORING-MODEL.md section 8
tests/
  regression.java           deterministic assertions (target 567, report real numbers)
  accuracy-corpus/          labelled phishing / bec / malware / spam / clean samples
  smoke-audit.java          ~35 endpoint sweep
docs/
  SCORING-MODEL.md          this model specification
  ARCHITECTURE.md           this document
```

---

## 11. Definition of done for the intelligence layer

1. Every displayed number traces to a formula in `SCORING-MODEL.md`.
2. Contribution additivity asserted in tests to 1e-9.
3. Thresholds derived by constrained optimisation and stored with their achieved FPR/recall.
4. Calibration (Brier, ECE, reliability diagram) reported on the held-out test split.
5. The confidence gate provably blocks auto-action below `C = 0.50`.
6. Attribution confidence capped at 0.85 with the disclaimer rendered wherever it appears.
7. Campaign risk uses noisy-OR and reports mean (not max) member confidence.
8. Every enrichment failure produces a visible `UNAVAILABLE`/`NOT_CONFIGURED` state.
9. Analyst feedback is captured and the offline refit consumes it.
10. The full test command prints real PASS/FAIL, macro-F1, MCC, PR-AUC, Brier and ECE.
