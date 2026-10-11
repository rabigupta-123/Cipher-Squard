# CIPHER SQUAD — Comprehensive API Reference
**Protocol:** HTTP/1.1  
**Default Loopback Address:** `http://127.0.0.1:8080`  
**Security Headers Emitted:** `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`

---

## 1. Endpoint Summary Table

| HTTP Verb | Path | Auth Required | Purpose | Response Type |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` or `/index.html` | No | Serves the single-page SOC Analyst Web Console with nonce CSP | `text/html; charset=utf-8` |
| `POST` | `/api/analyze` | Basic / Session | Parses & analyzes an RFC 822 email; returns scores, hops, indicators | `application/json; charset=utf-8` |
| `GET` | `/api/cases` | Basic / Session | Lists and paginates forensic cases from local case store | `application/json; charset=utf-8` |
| `GET` | `/api/audit/verify` | Basic / Session | Verifies the cryptographic integrity of the SHA-256 audit log | `application/json; charset=utf-8` |
| `GET` | `/export/stix` | Basic / Session | Exports an existing case's indicators as an OASIS STIX 2.1 bundle | `application/stix+json; charset=utf-8` |
| `POST` | `/export/stix` | Basic / Session | Generates an OASIS STIX 2.1 bundle from submitted indicator JSON | `application/stix+json; charset=utf-8` |
| `GET` | `/api/report` | Basic / Session | Generates and streams a court-admissible PDF 1.4 forensic report | `application/pdf` |

---

## 2. Authentication Model

The API requires HTTP Basic Authentication or an active session token:
- **HTTP Header:** `Authorization: Basic <base64(username:password)>`
- **Session Token:** Generated upon first valid authentication and maintained in memory for 8 hours (`AUTH_SESSION_TTL_MS`).
- **Account Protection:** 5 consecutive failed login attempts within 15 minutes trigger an automated account lockout.

---

## 3. Detailed Endpoint Specifications

### 3.1 Analyze Email
`POST /api/analyze`

Submits an RFC 5322 raw email for threat detection, feature extraction, relay-chain tracing, and risk calculation.

- **Request Headers:**
  - `Content-Type: message/rfc822`
  - `Authorization: Basic <credentials>`
- **Query Parameters:**
  - `openCase` (*optional*, boolean): When `true`, forces case creation regardless of automation thresholds.
- **Example Request:**
  ```http
  POST /api/analyze HTTP/1.1
  Host: 127.0.0.1:8080
  Authorization: Basic YWRtaW46Q2lwaGVyU3F1YWQyMDI2IQ==
  Content-Type: message/rfc822
  Content-Length: 412

  Received: from mail.evil-lookalike.test (mail.evil-lookalike.test [198.51.100.45])
      by mx1.ciphersquad.io with ESMTP id 827419
      for <executive@ciphersquad.io>; Mon, 12 Oct 2026 09:14:00 +0000
  From: CEO <ceo@evil-lookalike.test>
  To: finance@ciphersquad.io
  Subject: Urgent Wire Transfer Request
  Date: Mon, 12 Oct 2026 09:13:50 +0000

  Please execute an immediate wire transfer of $45,000 to the attached account.
  ```

- **Example Response (`200 OK`):**
  ```json
  {
    "documentId": "a7b3c2d1e0f9847123958abcdef45678901234567890abcdef1234567890abcd",
    "score": {
      "verdict": "BEC",
      "riskFinal": 92.4,
      "confidence": 0.88,
      "band": "CRITICAL",
      "probabilities": {
        "LEGITIMATE": 0.015,
        "SUSPICIOUS": 0.025,
        "IMPERSONATION": 0.082,
        "PHISHING": 0.045,
        "BEC": 0.924,
        "FRAUD": 0.071,
        "MALWARE": 0.005,
        "SPAM": 0.012
      },
      "caseCreationEnabled": true,
      "abstentionReason": null
    },
    "attribution": {
      "originIp": "198.51.100.45",
      "country": "US",
      "asn": "AS64496",
      "anomalies": ["lookalike_domain", "executive_name_quoted"]
    },
    "hops": [
      {
        "index": 0,
        "fromHost": "mail.evil-lookalike.test",
        "fromIp": "198.51.100.45",
        "byHost": "mx1.ciphersquad.io",
        "protocol": "ESMTP",
        "id": "827419",
        "timestamp": "2026-10-12T09:14:00Z",
        "delaySeconds": 10
      }
    ],
    "caseId": "case-3f9e8a1c",
    "caseOrigin": "MODEL_AUTOMATION",
    "audit": {
      "assurance": "SIGNED",
      "records": 51,
      "headHash": "89ab12cd34ef5678...",
      "headSignatureValid": true
    }
  }
  ```

---

### 3.2 List Cases
`GET /api/cases`

Retrieves forensic investigation cases from local persistent storage (`data/cases.ndjson`).

- **Query Parameters:**
  - `limit` (*optional*, integer, default: `50`, max: `500`): Maximum records to retrieve.
- **Example Response (`200 OK`):**
  ```json
  {
    "records": [
      {
        "id": "case-3f9e8a1c",
        "documentId": "a7b3c2d1...",
        "status": "OPEN",
        "title": "BEC Detection: Urgent Wire Transfer Request",
        "subject": "Urgent Wire Transfer Request",
        "messageId": "<msg-923847@mail>",
        "observedAt": 1767225600,
        "createdAt": 1767225605,
        "risk": 92.4,
        "riskFinal": 92.4,
        "confidence": 0.88,
        "verdict": "BEC",
        "band": "CRITICAL",
        "domains": ["evil-lookalike.test"],
        "addresses": ["ceo@evil-lookalike.test"],
        "hopAddresses": ["198.51.100.45"],
        "evidenceHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    ],
    "truncated": false
  }
  ```

---

### 3.3 Verify Audit Chain
`GET /api/audit/verify`

Independently checks every record in `data/audit.ndjson`, validates the linear SHA-256 hash progression from genesis, and verifies Ed25519 digital signatures.

- **Example Response (`200 OK`):**
  ```json
  {
    "ok": true,
    "valid": true,
    "assurance": "SIGNED",
    "records": 51,
    "firstDivergentIndex": -1,
    "headHash": "89ab12cd34ef5678901234567890abcdef1234567890abcdef1234567890abcd",
    "headSignatureValid": true,
    "signatureConfigured": true,
    "lastSignedIndex": 49,
    "lastSignatureValid": true,
    "signEveryN": 50,
    "reason": "",
    "log": "audit.ndjson"
  }
  ```

---

### 3.4 Export STIX 2.1 Bundle
`GET /export/stix?case=<caseId>` or `POST /export/stix`

Exports indicators of compromise (IOCs) formatted as an OASIS STIX 2.1 JSON bundle.

- **Example Response (`200 OK`, `application/stix+json`):**
  ```json
  {
    "type": "bundle",
    "id": "bundle--2c64b63e-7b3f-5a8a-9821-6f4b93a8d1e2",
    "objects": [
      {
        "type": "email-message",
        "id": "email-message--5a8123bc-9182-5812-a1b2-984712039847",
        "spec_version": "2.1",
        "is_multipart": false,
        "from_ref": "email-addr--1a2b3c4d-...",
        "to_refs": ["email-addr--5e6f7a8b-..."],
        "subject": "Urgent Wire Transfer Request"
      },
      {
        "type": "email-addr",
        "id": "email-addr--1a2b3c4d-9182-5812-a1b2-984712039847",
        "spec_version": "2.1",
        "value": "ceo@evil-lookalike.test"
      },
      {
        "type": "ipv4-addr",
        "id": "ipv4-addr--9f8e7d6c-9182-5812-a1b2-984712039847",
        "spec_version": "2.1",
        "value": "198.51.100.45"
      }
    ]
  }
  ```

---

### 3.5 Generate Forensic Report
`GET /api/report?caseId=<caseId>`

Streams a court-admissible PDF 1.4 forensic report.

- **Response:** Binary stream with `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="report-<caseId>.pdf"`.
