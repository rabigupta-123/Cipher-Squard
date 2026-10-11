# Phase 2 Implementation Notes and Conflict Register

This file records where the implemented Phase 2 behaviour agrees with `SCORING-MODEL.md`,
where it deliberately departs from it, and why. Read it alongside the spec before changing any
scoring constant.

The literal Phase 2 brief is not retained in the repository. `SCORING-MODEL.md` sections 6, 7, 10
and 11 are the authoritative source for the requirements implemented here.

---

## 1. Adopted as specified

| Requirement | Spec | Implementation |
|---|---|---|
| Attribution score | `C_attr = T^0.35 * S^0.25 * (1-A)^0.25 * X^0.15` | `Attribution.TraceFactors.combine` |
| Attribution cap | `0.85` | `Attribution.CONFIDENCE_CAP` |
| Confidence bands | `PROBABLE/INDICATIVE/WEAK/INSUFFICIENT` at 0.70/0.45/0.25 | `Attribution.bandOf` |
| Pairwise similarity | `0.25*J(headers) + 0.30*J(domains) + 0.20*J(ips) + 0.20*cos(tfidf) + 0.05*J(attachment_hashes)` | `Correlate.scoreWithIdf` |
| Cluster threshold | `tau = 0.62` | `Correlate.DEFAULT_THRESHOLD` |
| Clustering | connected components, union-find | `Correlate.cluster` |
| Campaign risk | `100 * (1 - PRODUCT(1 - risk_j/100))` | `Correlate.Cluster.noisyOr` |
| Campaign size | `n_emails` | `Cluster.nEmails` |
| Campaign confidence | mean, explicitly not max | `Cluster.confidenceMean` |
| Campaign window | earliest and latest observed | `Cluster.earliestObserved` / `latestObserved` |
| Logged threshold | report the `tau` actually used | `threshold` in `Campaign.toMap` and `Cluster.toMap` |

The five similarity weights are exposed as named constants (`Correlate.W_HEADER_NAMES`,
`W_DOMAINS`, `W_IPS`, `W_TEXT`, `W_ATTACHMENT_HASHES`) and asserted to sum to exactly 1, so a
future reweighting cannot drift silently.

---

## 2. Deliberate departures

### 2.1 Text-only similarity cannot reach the cluster threshold

The text term carries weight `0.20`. A pair with no shared domain, address, header or attachment
therefore scores at most `0.20`, far below `tau = 0.62`.

This is a real property of the specified model, not a bug. Phrase matching is trivially defeated
by rewriting, so text alone must not be able to establish a campaign. The cost is that a
campaign of messages sharing only prose is invisible, which is the intended trade-off.

The transitive-closure fixture in `t17` therefore links `a~b` and `b~c` on shared infrastructure
(domain + address + header fingerprint) and leaves `a~c` below threshold, so the cluster is
demonstrably a transitive result rather than a fully-linked clique.

### 2.2 Singletons are not clusters

A group of one has no linking evidence, so it carries no analytical meaning. Groups of size
`<= 1` are excluded from `Campaign.clusters`; their members remain visible in
`Campaign.unclustered` so nothing is silently dropped.

### 2.3 The specification's own test 8 is arithmetically unsatisfiable

Section 11 requires that a campaign of five emails at risk 50 produce a campaign risk of
`>= 96.9`. The exact noisy-OR of five such members is:

```
100 * (1 - 0.5^5) = 100 * (1 - 0.03125) = 96.875
```

`96.875 >= 96.9` is false. The value `96.9` is the one-decimal *rendering* of `96.875`.

The mathematics was implemented exactly and left uncorrupted. The test asserts both:

* `noisyOr([50,50,50,50,50] == 96.875` exactly, and
* the one-decimal display of that value is `"96.9"`.

Loosening the model to satisfy the literal inequality - for example by rounding before
comparison - would have made the reported risk disagree with the arithmetic behind it.

### 2.4 Campaign risk is a supplied value, not a re-derived one

`Correlate.Document` carries an optional `risk`, `confidence` and `observedAt`. These are inputs.
`Correlate` aggregates what it is given; it does not run the Phase 1 model.

`Correlate.documentOf(...)` currently leaves `risk` as `NaN`, because it receives an
`Attribution.Result`, which describes infrastructure attribution and carries no per-message
message-level risk score. A caller that wants campaign risk populated must pass the message-level
risk explicitly. An unobserved risk aggregates to `NaN`, never to `0`, because reporting zero
would read as "measured and harmless" rather than "not measured".

### 2.5 Modularity re-derivation of tau is not implemented

Section 7.2 asks for `tau` to be re-derived by maximising modularity on a labelled corpus rather
than left as a constant. This is not possible in this project: there is no labelled corpus, and
the toolkit is offline by design. `0.62` is currently a specified constant.

The mitigating obligation *is* met: the threshold actually used is reported in
`Campaign.toMap` and in every `Cluster.toMap`, so a run can never be silently compared against a
threshold it did not use. Re-deriving tau is deferred until a labelled corpus exists.

### 2.6 Reverse DNS is observed but not scored

`S` is specified as a composite of exactly `domain_age_inv`, `rdap_privacy` and `mx_present`.
Reverse DNS is a genuine infrastructure observation and appears in the report, but it is not one
of the three specified sub-signals, so it is recorded and explicitly not allowed to pad the score.

---

## 3. Offline adaptations inside the specified model

The toolkit performs no network access, so specification inputs that would normally come from
WHOIS, RDAP or DNS are supplied by the analyst instead. Each is reported as unobserved when
absent, and is never defaulted to a favourable value.

| Spec signal | How it is obtained offline | When absent |
|---|---|---|
| `rdap_privacy` | operator name from the enrichment registry, cross-checked against the analyst's anonymiser list | reported in `unobserved` |
| `domain_age_inv` | `Attribution.Hints.withDomainAge(domain, days)` | reported in `unobserved` |
| `mx_present` | `Hints.withMxPresent` / `withMxAbsent` | reported in `unobserved` |

Two decisions worth stating explicitly:

* **Unobserved sub-signals are excluded from the average, not counted as zero.** With only
  `rdap_privacy` observable and favourable, `S` is `1.0`, not `1/3`. This distinguishes "we know
  one thing and it is fine" from "we know one of three things".
* **`domain_age_inv` is a saturating ramp over a 365-day horizon.** A brand-new domain scores `0`
  and a domain a year or older scores `1.0`. A linear ramp is used in preference to a decay
  because it is directly readable in a report.

  The name `domain_age_inv` is ambiguous in the spec. It is implemented here as an *inverted
  risk* reading - newer is less stable - because the other two `S` sub-signals are
  "good standing" indicators and a stability factor must move in the same direction as its
  siblings. Flagged here as an interpretation decision, not a derivation.

A negative `domainAge` is rejected outright rather than scored: a domain created in the future is
a clock artefact, and scoring it as maximally stable would be exactly the wrong failure.

---

## 4. Retrieval correctness

**IDF corpus is one token-list per message.** `buildIdf` folds token-lists into a
document-frequency table where `N` is the number of documents and `df` is the number of documents
containing the term.

The scored content term is `cos(tfidf(subject + body))`, so the IDF corpus is the combined stream
and each message counts once. An earlier implementation fed subject, body and the combined stream
as three separate documents. That inflated `N` to three times the message count, let a term in a
single message accrue `df` up to 3, and - because it pushed the corpus past `MAX_IDF_DOCUMENTS` -
silently discarded the combined streams entirely once the run grew. Cosines were then scored
against weights they had never been fitted with.

`MAX_IDF_DOCUMENTS` remains `2 * MAX_DOCUMENTS` as a defensive bound for direct callers of
`buildIdf`; `pairwise` contributes exactly one entry per message and so can never hit it. The
invariant is pinned by assertions in `t15`: a term in every message of a 3-message corpus has
`idf` exactly `1.0`, and a term in 1 of 3 uses `N = 3`.

---

## 5. Test coverage of the specification

| Spec item | Test |
|---|---|
| Weighted geometric mean, cap, bands, zero collapse | `t11` |
| `S` composition: all three sub-signals, saturation, unobserved exclusion, `S = 0` collapse | `t21` |
| Five-term similarity, weight sum, header and attachment terms, text-only ceiling | `t19` |
| `n_emails`, `risk_campaign`, `confidence_mean`, observation window | `t20` |
| Transitive closure, documented-count reporting, corpus bounds | `t17` |
| Parser limits, budget, hostile input | `t01`-`t09`, `t18` |

Run everything with `.\run-tests.ps1`. It compiles both drivers and runs the four module
self-tests plus both suites, exiting non-zero on any failure.
