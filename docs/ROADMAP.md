# Cipher Squad — Feature Roadmap: What to Add Next

Ordered by value per unit of effort. Each item says **what**, **why it matters**, the **mechanism
or formula**, the rough **effort** (S / M / L), and **where it plugs in** to the existing
architecture.

Everything here is achievable in pure JDK 25 with no third-party dependencies.

---

## Tier 0 — Foundation gaps. Fix these first; they raise accuracy more than any model work.

### 0.1 Organisational profile (own domains, brands, executives)

**What.** A configuration file declaring: your organisation's own domains, your brand names and
their common misspellings, your executive/principal names and titles, your expected partner and
vendor domains, and your mail infrastructure ranges.

**Why it matters.** An impersonation detector that doesn't know who or what is being impersonated
is guessing. Lookalike scoring needs a target brand. Executive-impersonation detection needs the
actual executive roster. This single addition raises precision on impersonation and BEC more than
any coefficient tuning.

**Mechanism.**
```
profile = { own_domains[], brands[], executives[{name, title, aliases}],
            partner_domains[], mail_ranges[], abuse_contact }
```
Feeds `lookalike_strong` (distance to each brand, take min), `exec_impersonation` (matched against
the roster rather than a generic title pattern), and `geo_mismatch` (registrar country vs org
country). Cache the derived brand trigrams at startup.

**Effort:** S · **Plugs in:** L3 feature extraction, L9 config UI.

### 0.2 Unicode normalisation and confusable folding

**What.** A mandatory pre-processing pass applied to every extracted string: NFKC normalise, strip
zero-width and bidi control characters, fold homoglyph confusables to a canonical skeleton, then
lowercase.

**Why it matters.** Without it, `rnicrosoft.com`, `mіcrosoft.com` (Cyrillic і) and
`micro\u200bsoft.com` all bypass string matching silently. This is the most common evasion and the
cheapest fix. Do it before **every** comparison, in one shared class, so no code path can skip it.

**Mechanism.**
```
normalise(s):
   s = NFKC(s)
   s = remove chars in {U+200B..U+200D, U+2060, U+FEFF, U+00AD, U+202A..U+202E}
   s = map through confusables table  (embed a few thousand high-value mappings)
   return lowercase(s)
```
Then compute `homoglyph_ratio` as the fraction of characters changed by step 3 — that changed
fraction is itself the signal.

**Effort:** S · **Plugs in:** L2 normalisation, used by all of L3.

### 0.3 Sender behavioural baselining

**What.** A per-sender rolling profile built from that sender's own history: usual originating IPs
and ASNs, usual request types, usual language and tone, usual sending hour and weekday, usual
attachment types. Score each new email by deviation from its sender's profile.

**Why it matters.** This is the difference between a rule matcher and a system that learns. It
catches the compromised-account case that signatures can never catch: perfectly valid
authentication, valid domain, valid everything — but the behaviour is not that sender's
behaviour. It also gives you a legitimate AI/ML story that is honest.

**Mechanism.**
```
profile_s:  mu_f, sigma_f for each continuous feature (Welford, streaming, no storage blowup)
deviation   d = sqrt( SUM_f max(0, (x_f - mu_f) / max(sigma_f, eps))^2 / |F| )
profile_anomaly = 1 - exp(-d / d0)                   d0 tunes to ~1.5
```
One-sided on purpose: behaving *better* than usual must not raise risk. Cold start emits
`first_contact = true` and contributes 0 rather than a guess. Require `n >= 8` observations before
the profile is considered active, and expose that count in the UI.

New derived features: `profile_anomaly`, `first_contact`, `new_ip_for_sender`,
`new_geo_for_sender`, `unusual_request_type_for_sender`.

**Effort:** M · **Plugs in:** L3 features, L5 inference; persistence in a `data/profiles.ndjson`.

### 0.4 Thread-hijacking and reply-chain integrity

**What.** Detect BEC injected into an existing conversation — the highest-loss attack pattern and
one that authenticates perfectly because it comes from the real mailbox.

**Why it matters.** Payment-diversion BEC overwhelmingly arrives as a reply inside a live thread.
No header authentication can catch it.

**Mechanism.**
```
thread_key   = normalise(subject with Re:/Fwd:/AW:/TR: stripped) + participant domain set
continuity   = In-Reply-To / References present AND thread_key seen before
hijack_score = continuity
             AND ( new originating IP or new geo or first-time request type )
             AND ( payment_request or payment_channel_change or urgency )
```
Fire as a distinct finding with elevated weight, and surface the prior thread alongside it so the
analyst sees the deviation in context.

**Effort:** M · **Plugs in:** L3 + L6 correlation.

### 0.5 Cost-sensitive decision threshold

**What.** Replace the hardcoded threshold with an expected-cost rule driven by configurable costs.

**Why it matters.** Blocking a legitimate invoice costs an organisation far more than letting a
spam through. A fixed threshold ignores that entirely. This also gives you a principled way to
explain every threshold in the report.

**Mechanism.** The Bayes-optimal rule under asymmetric loss collapses to a threshold:
```
alert  iff  risk * C_FN > (1 - risk) * C_FP
     <=>   risk > C_FP / (C_FP + C_FN)
```
So `tau = C_FP / (C_FP + C_FN)` with defaults `C_FP = 20`, `C_FN = 1` → `tau ≈ 0.952` for
auto-block, and a lower `C_FN` for "alert only". Expose both budgets in config; document that this
is the derivation, not a guess.

**Effort:** S · **Plugs in:** L7 decision layer.

---

## Tier 1 — Detection depth. This is where the project outclasses comparable entries.

### 1.1 Attachment static analysis (no sandbox required)

**What.** Deep static inspection of attachments: OOXML (docx/xlsx/pptx) and ODF relationship
extraction, OLE/CFB macro extraction, PDF JavaScript and OpenAction detection, embedded-URL
extraction from documents, archive recursion with a zip-bomb guard, RTF object detection, and
filename RLO/double-extension handling.

**Why it matters.** The problem statement explicitly names malware delivery via attachments. The
README currently admits no sandbox — but static analysis needs no sandbox and produces real,
citable indicators. Extracting the actual URLs embedded in a malicious document is a genuine
forensic result.

**Mechanism.** All feasible with `java.util.zip`, `javax.imageio` and byte-pattern scanning:
```
docx/xlsx/pptx : zip -> read word/_rels/*.rels, extract Target URLs, inspect vbaProject.bin
OLE/CFB        : locate 'Macro' streams, scan for AutoOpen/Shell/CreateObject keywords
PDF            : find /JavaScript, /OpenAction, /Launch, /URI, count obfuscation layers
archive        : recurse to depth 3; abort if decompressed/compressed ratio > 100 or total > 50MB
results        : embedded_urls[], macro_keywords[], pdf_actions[], nested_depth, bombs_detected
```
Feed extracted URLs straight into the existing PhishGuard pipeline — that reuse is the value.

**Effort:** L · **Plugs in:** L3 payload family, forensic toolkit tab.

### 1.2 QR-code (quishing) detection

**What.** Detect QR codes in image attachments and inline images, decode them, and run the decoded
URL through PhishGuard.

**Why it matters.** Quishing is the current frontline evasion of link-rewriting defenses, because
the URL never appears in the message body as text. Almost no student project handles it, and it is
visually impressive in a demo.

**Mechanism.** `javax.imageio` for decode, then a pure-Java QR decoder: binarise, locate the three
finder patterns, perspective-correct, extract the bit matrix, strip the format/version info,
Reed-Solomon error correction, decode the payload. Then classify the payload type (URL, wifi
config, vCard, plain text) and route URLs onward.

**Effort:** L · **Plugs in:** L3 payload family, PhishGuard.

### 1.3 Phishing-kit fingerprinting and infrastructure clustering

**What.** Cluster phishing sites by kit rather than by domain, so one actor using 40 domains
collapses into one campaign.

**Why it matters.** This is real threat-intelligence tradecraft and it directly answers the
"correlate infrastructure / campaign-level attribution" requirement. It also makes the graph view
genuinely interesting.

**Mechanism.**
```
favicon_hash   = base64( murmurhash3_32( favicon_bytes ) )        Shodan-compatible
structure_hash = SHA256( normalised DOM tag-path skeleton, scripts stripped )
cert_hash      = set of SANs + issuing CA from the TLS chain
kit_id         = SHA256( favicon_hash || structure_hash || cert_hash )
```
Also harvest sibling infrastructure from Certificate Transparency (crt.sh JSON API) by querying
the certificate's SANs — passive, no active scanning, and it reveals sibling domains the attacker
registered in the same batch. MurmurHash3 is ~40 lines of pure Java.

**Effort:** M · **Plugs in:** L4 enrichment, L6 graph, L9 campaign view.

### 1.4 Evasion and red-team corpus

**What.** A labelled adversarial test set of deliberately obfuscated phishing samples: homoglyph
domains, zero-width characters, image-only bodies with no extractable text, HTML comment
injection, white-on-white invisible text, CSS-displayed vs DOM-text mismatch, base64/Rot13 body
encoding, split-token urgency words, legitimate-looking HTML template wrappers, and slow-loris
header padding.

**Why it matters.** This is the single most credible thing in the whole project. Reporting
"we attacked our own detector and detected X% of evasions, then hardened these two families"
demonstrates engineering maturity that no amount of feature count can match. It also justifies the
Unicode normaliser and the DOM-vs-rendered text comparison.

**Mechanism.** Run the corpus through the pipeline, report per-evasion-family detection rate as a
first-class metric alongside accuracy. For every evasion that succeeds, either add a normalisation
step or document it as a known limitation with the reason.

**Effort:** M · **Plugs in:** tests, evaluation report.

---

## Tier 2 — Evidentiary and compliance. This is what "legal and evidentiary standards" actually requires.

### 2.1 Tamper-evident hash-chained audit log

**What.** Each audit record carries the hash of its predecessor, forming a verifiable chain with a
`/audit/verify` endpoint that reports the first divergent index.

**Why it matters.** "Append-only" is a claim; a hash chain is proof. It is a few lines of code and
it arguably satisfies the chain-of-custody requirement more concretely than anything else in the
build.

**Mechanism.**
```
h_n = SHA256( h_{n-1} || canonical_json( record_n ) )
genesis h_0 = SHA256( "cipher-squad-genesis" )
verify: recompute from genesis; report first index where recomputed != stored
```
Canonical JSON means deterministic key ordering — a small serialiser mode, not a new dependency.
Optionally anchor the chain head by printing it in each forensic report, so reports are bound to
the log state at generation time.

**Effort:** S · **Plugs in:** L8 governance, Store, audit tab.

### 2.2 Digitally signed forensic reports

**What.** Sign each report with Ed25519. Include the public key, a key id and the signature in the
report's envelope, plus a standalone verification tool.

**Why it matters.** A signed report with a published key is materially stronger evidence than a
JSON file, and it directly addresses "digitally signed forensic reports to strengthen chain of
custody" from the recommendations section. Ed25519 is in the JDK — no dependencies.

**Mechanism.**
```
KeyPairGenerator.getInstance("Ed25519")            (JDK 15+)
sig = Ed25519.sign( SHA256( canonical_report_body ), private_key )
envelope = { report, sig_alg:"Ed25519", key_id, public_key, signature, signed_at }
verify tool: recompute hash, verify signature, verify chain-head binding
```
Private key stored outside the web root with a documented file-permission recommendation. If no
key is configured, reports are issued unsigned with an explicit `signature: NOT_CONFIGURED` field
— never a placeholder that looks valid.

**Effort:** S · **Plugs in:** Reporter, Governance, report viewer.

### 2.3 STIX 2.1 / MISP-compatible export

**What.** Export indicators and campaigns as a STIX 2.1 bundle (indicators, observed-data,
relationships, identity) and as a MISP-compatible event JSON.

**Why it matters.** It makes the platform an actual citizen of a SOC and a CERT workflow instead of
a closed box. "Our output is ingestible by national CERT tooling" is a strong line for an AICTE
problem statement.

**Mechanism.** STIX is JSON with a fixed object schema — the hand-rolled serialiser already
handles it. Map: domain → `domain-name` indicator, IP → `ipv4-addr`, campaign → `campaign` +
`relationship` objects, sender → `identity`. Publish a `/export/stix?case=` route.

**Effort:** M · **Plugs in:** Reporter, case view.

### 2.4 RBAC, TOTP second factor, and dual control

**What.** Four roles — analyst, senior analyst, administrator, auditor. TOTP (RFC 6238) second
factor available per user. Dual control on consequential actions: evidence export, retention
changes and case deletion require two distinct approvals.

**Why it matters.** The governance section currently lists recommendations rather than implemented
controls. Implementing RBAC and MFA moves compliance from aspirational to demonstrated, and the
auditor role with read-only log access is exactly what an institutional deployment needs.

**Mechanism.** TOTP in pure Java: `Mac.getInstance("HmacSHA1")` over the counter,
`HOTP = truncate(HMAC(K, counter)) mod 10^6`, 30s step, ±1 step drift window. Secret stored
encrypted-at-rest alongside the password hash. Dual control: a pending-approval record in NDJSON
that a second role must counter-sign, with both actor ids in the audit entry.

**Effort:** M · **Plugs in:** L8.

### 2.5 Field-level masking and retention enforcement

**What.** Configurable masking rules (which fields are redacted per role, applied on read) and an
enforced retention policy with a scheduled trim that logs what it removed.

**Why it matters.** The problem statement explicitly asks for "configurable retention and masking
mechanisms." Currently that's a described intention; make it an enforced, auditable mechanism.

**Mechanism.** Mask-on-read only — the stored evidence stays intact, so masking never destroys
forensic value. Retention trim writes a tombstone audit record per deleted item listing id, age
and policy rule applied.

**Effort:** S · **Plugs in:** Store, Governance.

---

## Tier 3 — Analyst workflow and scale. These make it feel like a product.

### 3.1 Uncertainty sampling / active learning queue

**What.** A prioritised analyst queue that surfaces the emails whose labels would most improve the
model: smallest decision margin first, plus the largest missing-evidence gaps.

**Why it matters.** Analysts have limited time. Labelling the borderline cases and then refitting
is the correct way to convert human effort into accuracy — far more effective than labelling at
random. It also makes the feedback loop visibly purposeful.

**Mechanism.**
```
priority = w1 * (1 - margin)  +  w2 * (1 - C_cov)  +  w3 * severity_of_class
margin = p_(1) - p_(2)
```
After each batch of labels, refit offline and report the before/after metrics with confidence
intervals so the improvement is measured, not asserted.

**Effort:** M · **Plugs in:** L5/L9, feedback store.

### 3.2 Bulk ingestion and institution-scale campaign mapping

**What.** Import a folder of `.eml` files or an mbox archive, run the full pipeline across
thousands of messages, and render a campaign map plus a ranked summary.

**Why it matters.** It proves the platform works at institutional scale rather than on one email
at a time, and it is the most visually compelling demo you can build. It also exercises caching,
batching and memory behaviour under real load.

**Mechanism.** mbox splitting on `From ` lines with escaping handled; bounded worker pool; the
existing cache handles the enrichment amplification since real mailboxes have heavy indicator
overlap; progress streamed to the UI. Report throughput, cache hit rate and memory high-water mark.

**Effort:** M · **Plugs in:** L1 ingest, L6, L9.

### 3.3 Response playbooks and takedown drafting

**What.** Configurable response actions per band: notify the affected internal user, generate a
quarantine instruction for the mail admin, open a case, and draft a takedown/abuse report
pre-populated from RDAP abuse contacts, registrar details and the evidence manifest.

**Why it matters.** Detection without response leaves value on the table, and the abuse-report
draft is a concrete deliverable for "support to law enforcement agencies" — an explicit expected
outcome in the problem statement.

**Mechanism.** Playbooks are declarative config (JSON), evaluated by the decision layer, with each
action's outcome audited. Takedown drafts are templates rendered with case data and issued as
`.eml` or plain text for the analyst to review. Never auto-send to external parties — draft only,
human approves, and record the approval.

**Effort:** M · **Plugs in:** L7, Reporter.

### 3.4 Statistical rigour in evaluation

**What.** Bootstrap confidence intervals on every reported metric, McNemar's test when comparing
model versions, and a results table that reports uncertainty rather than bare numbers.

**Why it matters.** "Macro-F1 improved from 0.91 to 0.94 (95% CI [0.02, 0.05], McNemar p < 0.01)"
is a categorically stronger claim than "accuracy improved." It costs little and it signals that
you understand evaluation rather than just reporting a flattering number.

**Mechanism.**
```
bootstrap:  1000 resamples with replacement, report 2.5th/97.5th percentiles on each metric
McNemar:    chi-square on the 2x2 discordant table, 1 df, report p
```
Also report per-class support so the reader can see where the corpus is thin — thin classes are
the honest explanation for any weak per-class number.

**Effort:** S · **Plugs in:** tools/evaluate.java, self-test output.

---

## What NOT to add — scope discipline

These are common additions that will hurt a submission more than help it:

- **A real malware sandbox.** Out of scope, legally fraught, and requires infrastructure you don't
  have. Static analysis plus honest `UNAVAILABLE` reporting is the stronger position.
- **A trained deep-learning classifier.** With a corpus of hundreds of messages you cannot train or
  validate one credibly, and an unjustified neural model is worse evidence than a calibrated
  linear one. Keep the logistic model and put the effort into the corpus instead — better data
  raises accuracy more than a bigger model at this scale.
- **Claims about commercial blocklists or threat feeds.** If you don't have licensed feeds, say so.
  An evaluator who finds an unsupported claim about intelligence quality will discount everything
  else in the report.
- **Auto-sending notifications to external parties.** Draft, review, approve, then send. Automating
  outbound abuse mail from a student project is a genuine liability.
- **A second, parallel scoring path.** One model, one explanation, one calibration report. Two
  scoring implementations that disagree is the fastest way to lose an evaluator's trust.

---

## Suggested sequencing

| Order | Item | Why this order |
|---|---|---|
| 1 | 0.1 org profile, 0.2 Unicode normaliser | Cheapest large accuracy win; everything else depends on them |
| 2 | 0.5 cost-sensitive threshold, 2.1 hash-chained log | Small effort, disproportionate credibility |
| 3 | 0.4 thread hijacking, 0.3 sender baselines | Covers the BEC and compromised-account cases authentication can't |
| 4 | 2.2 signed reports, 2.5 masking+retention | Completes the evidentiary story the problem statement asks for |
| 5 | 1.4 evasion corpus | Convert hardening work into measured, reportable results |
| 6 | 1.1 attachment static analysis, 1.2 quishing | Deepen the payload story with real indicators |
| 7 | 1.3 kit fingerprinting, 3.2 bulk ingestion | Campaign-scale correlation and the strongest demo |
| 8 | 3.1 active learning, 3.4 statistical rigour, 2.3 STIX | Close the improvement loop and interoperate |
| 9 | 2.4 RBAC+MFA, 3.3 playbooks | Institutional deployment readiness |

---

## The three-line pitch this produces

> Cipher Squad detects fraudulent email with a calibrated model whose every score is exactly
> explainable, abstains rather than guessing when evidence is incomplete, hardens itself against a
> red-team evasion corpus it attacks itself with, proves its audit trail with a hash chain, and
> issues Ed25519-signed forensic reports that export as STIX — with every unavailable service
> reported honestly rather than faked.
