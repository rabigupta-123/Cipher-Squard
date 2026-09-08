# Cipher Squad — AI Email Threat Detection, Geolocation & Forensic Intelligence Platform

A working, local-first forensic intelligence platform for the AICTE Cyber Security Cell
problem statement: detect phishing, spoofed, impersonated and fraudulent email, trace its
relay path, estimate its origin with geolocation, and generate investigative intelligence.

Built as a zero-dependency Java (JDK 25) local API plus a single-page web console.

## Run

```powershell
.\run.ps1
```

Then open **http://127.0.0.1:8080** in a browser. The script compiles the Java engine, starts the
ClamAV daemon + alert inbox, and serves the web console. Paste a complete raw email (headers +
body) and click **Analyze email**, or use **Load demo** to see the full pipeline with a realistic
high-risk sample.

## Sign-in

The platform is access-controlled. On first run a default admin is bootstrapped:

- **Email:** `admin@cipher.local`
- **Password:** `CipherSquad#2026` (override with the `SENTINEL_ADMIN_PW` environment variable)

The login screen is a full orange-branded landing page with the Cipher Squad shield logo. The
landing/login UI is intentionally adversarial: honest failure responses and hard boundaries so it
cannot be talked around. Sessions expire after 8 hours.

**Login hardening (server side):**

- Passwords are stored as PBKDF2-HMAC-SHA256 (120 000 iterations, 16-byte salt) and verified with
  constant-time comparison.
- Brute-force throttling: failed attempts are tracked per-account **and** per-IP in a 15-minute
  window; crossing 5 failures locks both keys for 60 s and the API answers `429` with a retry delay
  (the lock is checked *before* password verification, so even the correct password is refused
  while locked).
- Timing equalization: an unknown account is verified against an equal-cost dummy hash so response
  time cannot reveal whether an account exists, and unknown-user / wrong-password / valid-user
  responses are identical.
- Sessions use 32-byte SecureRandom tokens, persist across restarts until TTL, and every
  sign-in/sign-out is written to `data/audit.ndjson` (respecting the lockout).

## Testing

- **Regression suite:** `tests/run-tests.ps1` compiles the engine with the 567-assertion suite and
  reports `PASS=nnn FAIL=0`. Run it from the repository root:
  `powershell -ExecutionPolicy Bypass -File .\tests\run-tests.ps1`
- **Accuracy corpus:** labeled phishing / BEC / malware / spam / clean samples are scored against
  the live `/api/analyze` endpoint and the results are checked against risk-band targets
  (BEC payment-diversion and executive-impersonation samples must land HIGH; clean samples must
  stay SAFE).

## What it does

**Email analysis (real, on paste):**
- Header forensics: Return-Path, From, Reply-To, Message-ID, Received chain, alignment.
- Sender authentication: parses SPF / DKIM / DMARC results and flags failures.
- Heuristic corpus (NLP-style): urgency, credential requests, payment diversion, executive
  impersonation, cloud-file lures, dangerous attachment types, URL patterns.
- Scoring 0–100 with verdicts (low / suspicious / high risk) and threat categories.
- **BEC / payment-diversion tier**: a convergent financial-request pattern (executive-impersonation
  x finance, or finance x deadline) gets a dedicated, bounded risk uplift so URL-less business
  email compromise is not structurally under-reported by the network/URL categories.
  Authority-impersonation detection covers real BEC scripts ("in a board meeting", "cannot take
  calls", "no phone", "on a plane", "client meeting").
- **Relay tracing**: reconstructs Received hops and picks the earliest public IP.
- **Geolocation**: maps every relay IP to country / region / city / ISP / ASN via ip-api.com
  (proxied server-side) and highlights the likely source on a geo map.
- SHA-256 evidence hash and downloadable JSON forensic report.
- High-risk results are saved as an investigation case automatically.

**Forensic toolkit page:**
- **IP geolocation** — country, region, city, ISP, ASN, coordinates.
- **DNS records** — A/AAAA, MX, NS, TXT (SPF/DKIM/DMARC tokens), CNAME, SOA.
- **Registrar (RDAP/WHOIS)** — registration, expiry, status, nameservers, contacts.
- **URL deep-link analyzer** — scheme, host, path, punycode/homograph and lure-pattern flags.
- **Evidence hashing** — SHA-256, with SHA-1 for chain-of-custody records.
- **Standalone header parser** — splits and normalises any pasted header block.
- **Actor language profile** — social-engineering signal scan of body text.

**Forensic integrations (new):**
- **Gmail forensics** — header-only sender/spoof analysis for Gmail / Google Workspace senders
  (Message-ID structure, Google Received-relay evidence, ARC seal, auth-reference, SPF/DKIM
  alignment, header formatting). No Google Workspace API is queried; signals come from the
  message itself.
- **PhishGuard** — website/URL phishing analyzer. Fingerprints brand impersonation, typosquat,
  suspicious keyword clusters, plain-HTTP delivery, IP-literal hosts and URL-embedded
  credentials; enables an SSRF-guarded live HTTP probe against public hosts.
- **Scanner integrations** — ClamAV (clamd TCP `INSTREAM`), Rspamd (`checkv2` HTTP) and Yara
  (rules-dir subprocess) REST scanner endpoints. Each engine reports **LIVE** only when the
  backing service produced a verdict; otherwise it is honestly reported as **UNAVAILABLE** or
  **NOT_CONFIGURED** — results are never fabricated. See `.env.example`.

**Dashboard, cases, threat intelligence, reports, settings** — session detections, persisted
cases (localStorage), source-cluster map, tamper-evident export records, and policy toggles.

## Architecture

- `index.html` — the full web console (single-page, light/dark themes, orange-branded login
  landing page with inline SVG Cipher Squad logo + favicon).
- `server/src/main/java/com/sentinelmail/App.java` — JDK `HttpServer` API. Access-controlled
  routes: `/api/analyze`, `/api/geolocate`, `/api/dns`, `/api/whois`, `/api/domain-intelligence`,
  `/api/cases`, `/api/enrichment-status`, `/api/scanners/status`, `/api/scanners/scan`,
  `/api/phishguard/analyze`, plus `/api/auth/login|logout|me`, `/api/users`, `/api/channels`,
  `/api/self-test`, and the SOC modules (`/api/analyze/spam|dns|ssl|ddos|cloudflare`,
  `/api/dashboard`). No third-party dependencies.
- `run.ps1` — compile + launch, and wire up `start-scanners.ps1` + `start-alert-inbox.ps1`.
- `data/cases.ndjson` — persisted case records (runtime data, git-ignored).

Enrichment providers are hit server-side (avoids browser CORS), and every value is labelled
with a source/time caveat. The server binds to localhost deliberately.

## Honest limitations

- IP geolocation reflects **infrastructure registration, not personal identity**. An IP alone
  is never attribution to an individual.
- Uses the free ip-api.com tier and rdap.org bootstrap; no malware sandbox, no block-list feeds,
  no trained ML classifier yet. ClamAV / Rspamd / Yara are scanned against only if their backend
  is reachable and configured — otherwise the platform honestly reports them as unavailable.
- **Out-of-the-box scanners (current deployment):** ClamAV (clamd on `127.0.0.1:3310`) and **Yara**
  (binary auto-detected; bundled phishing rules loaded automatically from `<project>/yara-rules`).
  Both report **LIVE** and return real MATCH/CLEAN verdicts. **Rspamd** has no Windows build, so it
  honestly reports **NOT_CONFIGURED** unless `RSPAMD_URL`/`RSPAMD_KEY` are set on a Unix host; the
  platform's built-in spam engine (`/api/analyze/spam`) covers that signal.
- The ClamAV backend is **fully self-contained in this repository**: signature database in
  `<project>/clamav-db`, generated configs in `<project>/config`. Install the binaries once with
  `winget install Cisco.ClamAV`, then `start-scanners.ps1` regenerates configs, bootstraps the DB if
  missing, and starts the daemon (up to 90 s cold-load poll). Update signatures any time with
  `powershell -ExecutionPolicy Bypass -File .\start-scanners.ps1 -Update`.

## Outbound alerts (active)

Every analyzed email triggers alert dispatch if it meets a channel's threshold — severity label,
risk score, classification, incident id, top findings and a report link are POSTed per channel with
retry (3 attempts + backoff) and every send is written to `data/audit.ndjson`.

- **Default channel (current deployment):** a `webhook` channel named `local-alert-inbox` at
  `http://127.0.0.1:9290/alert/`, threshold **HIGH**, enabled. The receiver (`start-alert-inbox.ps1`,
  wired into `run.ps1`) stores every alert as JSON in `data/alert_inbox.ndjson` and replies 200 — so
  the pipeline is verified end-to-end out of the box.
- **Pointing at a real SOC:** open the console → **Integrations** → *Alert channels* and add a
  channel (type `email|slack|webhook`), or POST `/api/channels`:
  - `{"type":"slack","name":"ops","destination":"https://hooks.slack.com/services/...","threshold":"HIGH","enabled":"true"}`
  - `{"type":"webhook","name":"pagerduty","destination":"https://events.pagerduty.com/v2/enqueue/...","threshold":"CRITICAL","enabled":"true"}`
  - `{"type":"email","name":"soc","destination":"soc@corp.example","threshold":"MEDIUM","enabled":"true","config":"{\"smtp_host\":\"smtp.corp.example\",\"smtp_port\":587,\"smtp_user\":\"...\",\"smtp_pass\":\"...\",\"from\":\"cipher-squad@corp.example\"}"}`
- Thresholds fire at or above their band: `LOW≥20`, `MEDIUM≥40`, `HIGH≥60`, `CRITICAL≥80`. Disable a
  channel anytime via the UI toggle or `POST /api/channel/state` `{"id":"...","enabled":"false"}`.
- The demo email uses internet-facing sample IPs so mapping is illustrative of real Tor/proxy
  infrastructure (ForPrivacyNET) rather than a real incident.

## Production checklist

Put it behind TLS, SSO/MFA, and RBAC; use encrypted evidence storage and immutable logging;
add a licensed threat-intel provider; add a trained classifier with an evaluation dataset and
analyst feedback loop; and sign exported reports (chain of custody).
