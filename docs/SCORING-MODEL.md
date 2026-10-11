# Cipher Squad — Detection, Scoring, Confidence and Accuracy Model

This document defines the exact mathematics the platform must implement. Every number the
console shows (risk score, band, confidence, attribution confidence, campaign risk, accuracy)
must be traceable to a formula in this file. No score may be hardcoded, invented, or produced
by a code path that is not described here.

Everything is deterministic and pure-Java (JDK standard library only). There is no runtime
training and no third-party math library.

---

## 0. Notation

```
x        feature vector for one email, x = (x_1 ... x_F)
x_f      feature f, normalised so x_f in [0,1] unless stated; 1 = fully triggered
b_f      boolean indicator form of x_f (b_f = 1 if x_f >= 0.5)
beta_f   learned coefficient for feature f
beta_0   bias / intercept
z        logit
p        probability
K        number of classes
```

All logarithms are natural unless written `log2`.

---

## 1. Feature vector (extraction contract)

Features are grouped in six families. The extractor must emit a named, documented value for
every feature, plus an `observed` flag (`true` when the underlying data was actually obtainable).

### F1 — Authentication / header integrity (AUTH)
```
spf_fail              SPF result is fail/softfail/temperror/permerror
spf_none              SPF result absent or "none"
dkim_fail             DKIM result is fail/temperror/permerror
dkim_absent           no DKIM-Signature header in the chain
dmarc_fail            DMARC result is fail
dmarc_absent          no DMARC record resolvable for the From domain
alignment_from_spf    Return-Path domain != From domain  (AUTH)
alignment_from_dkim   DKIM d= domain != From domain
dmarc_policy_strict   policy is reject or quarantine
```

### F2 — Routing / relay authenticity (ROUTE)
```
rp_from_mismatch      Return-Path != From            (strong impersonation signal)
replyto_mismatch      Reply-To domain != From domain
replyto_free_mail     Reply-To on a consumer mail provider
messageid_anomaly     Message-ID malformed, absent, or from a foreign domain
received_count_n      min(hop_count / 8, 1)
received_disorder     Received timestamps non-monotonic, normalised count
received_private_hop  private/reserved IP appears mid-chain (relay forgery)
received_missing_from earliest hop has no "from" clause
helo_mismatch         HELO name inconsistent with sending IP reverse DNS
date_skew             Date differs from first Received by > 30 min
```

### F3 — Identity / domain intelligence (IDENT)
```
domain_age_inv        1 - min(log1p(age_days)/log1p(3650), 1)   (younger = higher)
domain_age_unknown    RDAP lookup failed or no creation date
lookalike_strong      Damerau-Levenshtein to target brand <= 2  (normalised)
homoglyph_ratio       fraction of characters replaced by Cyrillic/Greek confusables
digit_dash_ratio      (digits + dashes) / len(domain_label), clipped to 1
subdomain_depth       1 - 1/(1 + max(0, labels - 2))
suspicious_tld        TLD in high-abuse set
mx_absent             no MX record for the sending domain
rdap_privacy          registrant redacted / privacy proxy
registrar_risk        registrar in elevated-abuse set
registrar_country_off sending domain registrar country != org country
```

### F4 — Content / language (NLP)
```
urgency               normalised count of urgency/pressure cues
authority_claim       claims of institutional authority or policy mandate
credential_request    asks for password, OTP, MFA, "re-authenticate"
payment_request       invoice, wire, remittance, bank detail change
payment_channel_change  specifically a change of bank account details
exec_impersonation    sender claims executive/principal/dean/CFO role
secrecy_pressure      "confidential", "do not discuss", "between us"
generic_salutation    "Dear Customer/User/Staff" with no name
grammar_anomaly       perplexity/irregularity proxy score
tone_incongruence     mismatch between display name and message register
```

### F5 — Payload / links (PAYLOAD)
```
link_text_mismatch    fraction of anchors whose href domain != link text domain
shortener             shortened-URL host present
ip_literal            URL host is a raw IP address
punycode              xn-- label present
at_in_url             userinfo "@" obfuscation present
deep_redirect         >= 2 redirectors nested in link params
credential_form_host  link points to a non-brand host hosting a login form
attachment_dangerous  exe/scr/js/vbs/lnk/jar/hta
attachment_macro      macro-enabled Office container
attachment_archive    archive container
attachment_double_ext double extension or RLO filename trick
attachment_count_n    min(count / 4, 1)
```

### F6 — Infrastructure reputation (INFRA)
```
ip_in_blacklist       matched against local blocklist store
asn_risk              ASN in hosting/bulletproof/VPS bulk set
vpn_proxy             VPN or open-proxy indicator
tor_exit              TOR exit node indicator
open_relay            known open relay
cloud_hosted          originating IP belongs to a major cloud provider
geo_mismatch          originating country != From-domain registrar country
reputation_low        any threat-intel hit for IP or domain
```

Feature families carry family weights (used for coverage, Section 5):
```
W_AUTH 0.20   W_ROUTE 0.18   W_IDENT 0.18
W_NLP  0.17   W_PAYLOAD 0.15 W_INFRA 0.12
```

---

## 2. Model: multinomial logistic regression (softmax)

The classifier is a **linear model over an explicit feature vector**, which means it is
simultaneously (a) a real ML model, (b) fully deterministic, (c) exactly explainable.
Do not replace it with an opaque "AI score".

Classes, in fixed order:
```
0 legitimate   1 suspicious   2 impersonation   3 phishing
4 bec          5 fraud        6 malware         7 spam
```

Score for class k:
```
z_k = beta_0k + SUM_f ( beta_fk * x_f )
```

Clip each term before summing, so no single feature can dominate:
```
term_fk = clip( beta_fk * x_f , -c , +c )        c = 2.5
```

Probability:
```
P(k | x) = exp(z_k) / SUM_j exp(z_j)
```
Numerically stable form (always use this):
```
m = max_j z_j
P(k | x) = exp(z_k - m) / SUM_j exp(z_j - m)
```

Verdict:
```
k* = argmax_k P(k | x)
```

### Risk score
Risk is the probability the message is **not legitimate**, scaled to 0-100:
```
risk = 100 * ( 1 - P(legitimate | x) )
```
Rounding: report `round(risk)` for display, keep full precision internally.

### BEC sub-model
BEC gets an additional dedicated score from its own small logistic head, because BEC emails are
frequently clean on authentication (they come from a real, compromised mailbox):
```
z_bec = g_0 + SUM_f ( g_f * x_f )      over the BEC-relevant subset only
   (exec_impersonation, payment_channel_change, secrecy_pressure,
    urgency, authority_claim, replyto_mismatch, replyto_free_mail,
    received_count_n, domain_age_inv, dmarc_policy_strict, attachment_archive)
P_bec = sigmoid(z_bec) = 1 / (1 + exp(-z_bec))
bec_score = 100 * P_bec
```
Reported separately and never folded back into `risk` — an analyst must see both numbers.

### Final blended risk (what alerts fire on)
```
risk_final = 100 * ( 1 - ( 1 - P_notlegit ) * ( 1 - w_bec * P_bec ) )
             where P_notlegit = 1 - P(legitimate | x),  w_bec = 0.35
```
This is the noisy-OR combination: two independent evidence sources, neither able to fully
override the other.

---

## 3. Band thresholds (derived, not guessed)

Bands are **not** arbitrary round numbers. They are selected on the validation split by
constrained optimisation:

```
tau_high = max { tau : FPR(tau) <= 0.010 }      maximise recall subject to 1% FP
tau_susp = max { tau : FPR(tau) <= 0.050 }      maximise recall subject to 5% FP
```
where
```
FPR(tau) = #{ y=0 and risk>=tau } / #{ y=0 }
```
Band assignment:
```
risk >= tau_high   -> HIGH-RISK
risk >= tau_susp   -> SUSPICIOUS
otherwise          -> LOW
```
Store `tau_high`, `tau_susp`, the split it was fitted on and the achieved FPR/recall in a
`model.json` metadata file. Show them in the console and in every report. If the corpus changes,
the thresholds must be re-derived and the metadata updated.

Alert severity ladder (operational, distinct from bands):
```
LOW >= 20   MEDIUM >= 40   HIGH >= 60   CRITICAL >= 80
```

---

## 4. Explanation: exact additive attribution

For a linear model the per-feature contribution **is** the exact additive decomposition of the
logit. This is faithful, not a post-hoc approximation, and it is free.

For the winning class `k*`:
```
contribution_f = clip( beta_f,k* * x_f , -c , +c )
```
Then, verifiably:
```
SUM_f contribution_f + beta_0k* = z_k*
```
Contract requirements:
- Every finding shown to the analyst carries `feature`, `observed_value`, `expected_value`,
  `contribution`, and a one-sentence English rationale.
- Sort findings by `|contribution|` descending.
- Assert additivity in the test suite: `|SUM contributions + bias - z_k*| < 1e-9`.
- Distinguish `direction = +` (raises risk) from `direction = -` (lowers risk). Emails have
  exculpatory evidence too (valid DKIM, aged domain, aligned SPF) and the UI must show it.

Rationale template:
```
"{feature_label}: observed {observed}, expected {expected}; contributes {contribution:+.2f} to the {class} logit."
```

---

## 5. Confidence

Confidence is **not** the probability. Probability answers "how likely is phishing";
confidence answers "how much should I trust this verdict". Two independent factors.

### 5.1 Model confidence (from the distribution)
Normalised Shannon entropy over the class distribution:
```
H(p)    = -SUM_k p_k * ln(p_k)
H_norm  = H(p) / ln(K)                     in [0,1];  0 = certain, 1 = uniform
C_model = 1 - H_norm                       in [0,1]
```
Scaled so real-world distributions do not read as falsely certain:
```
C_model = (1 - H_norm)^gamma ,  gamma = 0.7
```

### 5.2 Evidence coverage (from what was actually observable)
Each feature f has an informativeness weight `v_f` (its absolute learned coefficient).
```
C_cov = SUM_{f : observed_f} v_f  /  SUM_{f in ALL} v_f
```
If every lookup failed, `C_cov` collapses toward 0 and the verdict must visibly weaken.
Features whose family had no enrichment attempt are `observed = false`.

### 5.3 Combined confidence
```
C = C_model * C_cov
```
Multiplicative on purpose: a confident model on 20% of the evidence must not report high
confidence. Report `C` as a percentage with two significant figures.

### 5.4 Abstention rule
```
if C < 0.50             -> verdict = UNDETERMINED, route to analyst queue, no auto-action
if 0.50 <= C < 0.70     -> verdict stands, flagged "low confidence, review advised"
if C >= 0.70            -> verdict stands, eligible for automated policy
```
An abstaining system is a trustworthy system. Never suppress the abstention path.

---

## 6. Attribution confidence (probable origin)

Separate quantity, computed only for the sender-origin assessment. Four factors, all in [0,1]:

```
T  traceability     resolved_public_hops / total_hops        (geolocated share of chain)
S  stability        composite of domain_age_inv, rdap_privacy(-), mx presence
A  anonymity        max(vpn_proxy, tor_exit, open_relay, cloud_hosted_ephemeral)
X  corroboration    agreement of independent signals on one cluster:
                    |shared attributes across IP/ASN/registrar/domain groups| / 4
```

Combined as a **weighted geometric mean** so any single zero factor collapses the result
(correct behaviour: if nothing resolved, nothing can be attributed):
```
C_attr = T^0.35 * S^0.25 * (1 - A)^0.25 * X^0.15
```

Hard cap and disclaimer, enforced in code and in the UI:
```
C_attr = min(C_attr, 0.85)
```
Rationale for the cap: free geolocation and RDAP data describe **infrastructure registration and
hosting**, never a person. Every surface that shows `C_attr` must print:

> Geolocation indicates infrastructure registration/hosting. It is not personal attribution and
> must not be treated as evidence of an individual's location.

Attribution label bands:
```
C_attr >= 0.70   PROBABLE (high traceability)
0.45 - 0.70      INDICATIVE
0.25 - 0.45      WEAK
< 0.25           INSUFFICIENT
```

---

## 7. Campaign correlation

### 7.1 Pairwise similarity
```
sim(a,b) = 0.25 * J(headers) + 0.30 * J(domains) + 0.20 * J(ips)
         + 0.20 * cos(tfidf(text_a), tfidf(text_b)) + 0.05 * J(attachment_hashes)
```
where `J` is Jaccard on the respective entity sets:
```
J(A,B) = |A intersect B| / |A union B|
```
and cosine on sublinear TF-IDF vectors:
```
tf(t,d)  = 1 + ln(count(t,d))
idf(t)   = ln( (1 + N) / (1 + df(t)) ) + 1
cos(a,b) = (a . b) / (||a|| * ||b||)
```

### 7.2 Clustering
Build a weighted undirected graph; keep edges with `sim >= tau_cluster = 0.62`.
Connected components (union-find) are campaigns. Log the chosen `tau_cluster`; re-derive it
by maximising modularity on the labelled corpus rather than leaving it as a magic number.

### 7.3 Campaign risk (noisy-OR)
A campaign of several medium-risk emails must not stay medium:
```
risk_campaign = 100 * ( 1 - PRODUCT_j ( 1 - risk_final_j / 100 ) )
```
Also report `n_emails`, `confidence_mean = mean(C_j)` (not max — never claim more confidence
than the average member supports), and the campaign's earliest and latest observed timestamps.

---

## 8. Accuracy and validation metrics

Computed against the labelled evaluation corpus. Report all of these, never a single
cherry-picked number.

### 8.1 Per-class
```
precision_k = TP_k / (TP_k + FP_k)
recall_k    = TP_k / (TP_k + FN_k)
F1_k        = 2 * precision_k * recall_k / (precision_k + recall_k)
support_k   = TP_k + FN_k
```

### 8.2 Aggregate
```
macro_F1   = (1/K) * SUM_k F1_k
micro_F1   = 2 * P_micro * R_micro / (P_micro + R_micro)      (pooled over all classes)
accuracy   = correct / N
balanced_accuracy = (1/K) * SUM_k recall_k
```

### 8.3 Binary high-risk decision (the one operations cares about)
Collapse to `phish = {risk >= tau_high}`:
```
MCC = (TP*TN - FP*FN) / sqrt( (TP+FP)(TP+FN)(TN+FP)(TN+FN) )
FPR = FP / (FP + TN)          target < 0.01
TPR = TP / (TP + FN)
```
Matthews correlation coefficient is the headline number for imbalanced email data; report it
alongside macro-F1. Also report:
```
TPR_at_FPR_0.1pct   = TPR at the threshold where FPR = 0.001
```

### 8.4 Ranking quality
```
ROC-AUC  : trapezoidal area under the TPR-vs-FPR curve over sorted scores
PR-AUC   : trapezoidal area under the precision-vs-recall curve
           (prefer PR-AUC; email corpora are heavily imbalanced)
```
Threshold sweep uses all unique scores; no interpolation of ties.

### 8.5 Calibration (this is what makes the numbers believable)
```
Brier = (1/N) * SUM_n ( p_n - y_n )^2           lower is better
B = 10 equal-width bins over [0,1]
acc(B_b)  = mean(y_n in bin b)
conf(B_b) = mean(p_n in bin b)
ECE = SUM_b ( |B_b| / N ) * | acc(B_b) - conf(B_b) |      target < 0.05
MCE = max_b | acc(B_b) - conf(B_b) |
```
If `ECE > 0.05`, apply **temperature scaling** to the logits and refit `T` alone:
```
z_k' = z_k / T      choose T minimising NLL on the validation split
```
Then re-run the calibration report. Ship a reliability diagram (predicted vs observed) in the
console and in the self-test output.

### 8.6 Confidence quality
The confidence number itself must be validated, not asserted:
```
coverage_of_confidence = P( verdict correct | C reported in [0.9, 1.0] )
```
If accuracy among high-confidence verdicts is not materially above overall accuracy, `gamma`
and the coverage weights must be retuned. Report this in the self-test.

---

## 9. Offline fitting procedure (how beta is obtained)

Fitting happens offline, in a script, never at runtime. The Java application loads fixed
coefficients.

Objective (L2-regularised multinomial negative log-likelihood):
```
J(B) = -SUM_n SUM_k  y_nk * ln P_nk  +  lambda * SUM_k ||beta_k||^2
```

Gradient:
```
dJ/dbeta_fk = SUM_n ( P_nk - y_nk ) * x_nf  +  2 * lambda * beta_fk
dJ/dbeta_0k = SUM_n ( P_nk - y_nk )
```

Solve with gradient descent or Newton/IRLS. Recommended settings:
```
lambda        = 1e-3        (ridge; guards against separable features)
learning_rate = 0.05 with 1/sqrt(t) decay
iterations    = until max |gradient| < 1e-6, cap 5000
standardise continuous features to mean 0 / unit variance before fitting
class weights = N / (K * n_k)     (compensate class imbalance)
split         = 70 / 15 / 15 train / validation / test, stratified, fixed seed
```
Fit on train. Select `lambda`, `gamma`, `tau_high`, `tau_susp`, `tau_cluster` on validation.
Report once on test. Never tune on test.

### Analyst feedback loop
Every analyst override writes a labelled record to `data/feedback.ndjson`:
```
{ "ts": ..., "email_hash": ..., "features": {...}, "model_verdict": "...",
  "analyst_verdict": "...", "note": "..." }
```
Refitting consumes the original corpus plus this file. This is the real improvement path and it
must be wired up, not just documented — surface a "retrain ready: N new labelled samples"
indicator when `N >= 20`.

---

## 10. Robustness rules

- **No single-feature dominance.** The `clip(..., -c, +c)` step in Sections 2 and 4 enforces this.
  Verify in tests that no single feature moves `risk` by more than 22 points.
- **Cache with TTL.** geolocation 24h, DNS 15m, RDAP 24h, reputation 1h. Cache hits must set
  `observed = true` (the fact was determined).
- **Circuit breaker.** After 3 consecutive failures a network source opens for 10 min and its
  features become `observed = false` with reason `SOURCE_UNAVAILABLE`. Never substitute a
  default value and pretend it was observed.
- **Timeouts.** 2s per source, 6s global enrichment deadline. Inference must succeed on partial
  features — that is precisely what `C_cov` exists to express.
- **Determinism.** Same input and same cache state must produce a bit-identical score. All
  rounding happens at the display layer only.

---

## 11. Required tests for this model

1. `SUM contributions + bias == z_k*` within 1e-9 for 100 random feature vectors.
2. Softmax stability: `z` values of 1e6 magnitude produce no NaN/Inf.
3. `risk` monotone non-decreasing in every positively-weighted feature.
4. `C_model = 1` for a one-hot distribution and `0` for a uniform one.
5. `C_cov = 1` when all sources succeed, `< 0.6` when all enrichment fails.
6. Abstention fires when `C < 0.5` and never auto-actions.
7. `C_attr` is 0 when no hop resolved (`T = 0`) and never exceeds 0.85.
8. Noisy-OR: five emails at risk 50 yield campaign risk >= 96.9.
9. Calibration: ECE on the test split is reported and `< 0.05`, or the failure is printed.
10. Thresholds satisfy `FPR(tau_high) <= 0.010` on validation, asserted numerically.
