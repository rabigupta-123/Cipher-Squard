# CIPHER SQUAD — Scoring and Confidence Model
**Platform: Pure Java JDK 25 Local-First Threat Detection Engine**

## 1. Classification & Scoring Formulation

### 1.1 Bounded Linear Logits ([Model.java](file:///sih_java/src/Model.java))
For each class $k \in \{0, \dots, 7\}$ (Legitimate, Suspicious, Impersonation, Phishing, BEC, Fraud, Malware, Spam):
$$z_k = \beta_{0, k} + \sum_{j=1}^{d} \text{clip}(\beta_{j, k} \cdot x_j, -2.5, 2.5)$$
where each individual feature contribution is strictly clamped to $[-2.5, +2.5]$ to prevent a single outlier from dominating the model decision.

### 1.2 Max-Shifted Softmax
Probabilities are computed using numerically stable softmax:
$$M = \max_k z_k$$
$$P(Y = k) = \frac{\exp(z_k - M)}{\sum_{m=0}^{7} \exp(z_m - M)}$$
Ensures finite probability values regardless of extreme logit inputs ($z \in [-10^9, 10^9]$). Verified to sum to $1.0 \pm 10^{-9}$.

### 1.3 BEC Noisy-OR Blending
Business Email Compromise (BEC) combines statistical classifier probability with independent discrete forensic signals (lookalike domain, executive impersonation, wire transfer trigger) using a sub-additive Noisy-OR formulation:
$$P_{\text{hints}} = 1 - \prod_{i=1}^{m} (1 - h_i)$$
$$P_{\text{BEC, final}} = 1 - (1 - P_{\text{BEC, softmax}})(1 - w_{\text{blend}} \cdot P_{\text{hints}})$$
This ensures that confirmed forensic evidence monotonically elevates the BEC score without overflowing or distorting the remaining class distributions.

### 1.4 Final Risk Score
$$R_{\text{final}} = \min(100.0, \max(0.0, 100.0 \cdot \max_{k \neq 0} P(Y = k)))$$

### 1.5 Risk Band Thresholds
| Band | Risk Final Range | Recommended SOC Action |
| :--- | :--- | :--- |
| **CRITICAL** | $85.0 \le R_{\text{final}} \le 100.0$ | Automated Quarantine, Alert SOC Lead, Open Case |
| **HIGH** | $70.0 \le R_{\text{final}} < 85.0$ | Quarantine Mailbox, Flag for Investigation |
| **MEDIUM** | $40.0 \le R_{\text{final}} < 70.0$ | Add Ingress Warning Banner, Log Indicator |
| **LOW** | $15.0 \le R_{\text{final}} < 40.0$ | Routine Ingress Monitoring |
| **BENIGN** | $0.0 \le R_{\text{final}} < 15.0$ | Allow Delivery |

## 2. Epistemic Confidence Model ($C_{\text{cov}}$ & $C_{\text{acc}}$)

The platform rejects guessed or fabricated evidence:
- **Coverage Confidence ($C_{\text{cov}}$)**:
  $$C_{\text{cov}} = \frac{\sum_{j=1}^{d} \mathbb{I}(x_j \text{ is observed})}{\text{Total Expected Features}}$$
  When a profile or enrichment source is absent, features are flagged `observed=false` and drop out of the model entirely rather than assuming zero or negative findings.
- **Accuracy Confidence ($C_{\text{acc}}$)**:
  Measures verification confidence across SPF/DKIM cryptographic signatures and MTA provenance.
