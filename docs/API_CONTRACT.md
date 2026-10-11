# CIPHER SQUAD — SOC API Contract
**Platform: Pure Java JDK 25 Built-in HttpServer**  
**Host Binding:** `127.0.0.1:[port]` (Loopback only)  
**Authentication:** HTTP Basic Auth (`Authorization: Basic <base64>`) or Session Bearer Token.

---

### 1. `POST /api/analyze`
Submits an RFC 822 email message for complete threat analysis, hop trace, attribution, and scoring.

- **Headers**:
  - `Content-Type: message/rfc822`
  - `Authorization: Basic <credentials>` (Optional for unauthenticated basic parse, required for SOC analysts)
- **Query Parameters**:
  - `openCase=true`: Explicitly forces a case to be opened even if model automation did not reach the threshold.
- **Response** (`200 OK`, `application/json`):
```json
{
  "documentId": "sha256-hash-of-email",
  "score": {
    "verdict": "BEC",
    "riskFinal": 92.4,
    "confidence": 0.88,
    "band": "CRITICAL",
    "probabilities": { "LEGITIMATE": 0.02, "PHISHING": 0.05, "BEC": 0.924, ... }
  },
  "attribution": {
    "originIp": "198.51.100.24",
    "country": "US",
    "asn": "AS13335",
    "anomalies": ["hop_delay_excessive", "lookalike_sender"]
  },
  "hops": [
    { "index": 0, "ip": "198.51.100.24", "by": "mx.victim.com", "delaySeconds": 2 }
  ],
  "caseId": "case-94a2b1c8",
  "audit": {
    "assurance": "SIGNED",
    "records": 50,
    "headHash": "3f8a...",
    "headSignatureValid": true
  }
}
```

---

### 2. `GET /api/cases`
Paginates forensic cases stored in the local append-only NDJSON store.

- **Query Parameters**:
  - `limit`: Maximum records to return (capped at 500).
  - `offset`: Starting index offset.
- **Response** (`200 OK`, `application/json`):
```json
{
  "records": [
    {
      "id": "case-94a2b1c8",
      "status": "OPEN",
      "verdict": "BEC",
      "riskFinal": 92.4,
      "band": "CRITICAL",
      "observedAt": 1767225600
    }
  ],
  "truncated": false
}
```

---

### 3. `GET /api/audit/verify`
Performs an independent verification of the cryptographic audit chain and returns its integrity status.

- **Response** (`200 OK`, `application/json`):
```json
{
  "ok": true,
  "valid": true,
  "assurance": "SIGNED",
  "records": 50,
  "headHash": "8a3f...",
  "headSignatureValid": true,
  "signatureConfigured": true,
  "lastSignedIndex": 49,
  "lastSignatureValid": true,
  "signEveryN": 50,
  "log": "audit.ndjson"
}
```

---

### 4. `POST /api/stix` or `GET /api/stix?messageId=<id>`
Exports observed indicators into an industry-standard STIX 2.1 JSON bundle.

- **Response** (`200 OK`, `application/json`):
```json
{
  "type": "bundle",
  "id": "bundle--2c64b63e-...",
  "objects": [
    { "type": "email-message", "id": "email-message--...", "from_ref": "email-addr--..." },
    { "type": "email-addr", "value": "attacker@evil.test" },
    { "type": "ipv4-addr", "value": "198.51.100.24" }
  ]
}
```

---

### 5. `GET /api/report?caseId=<id>`
Generates and downloads a court-admissible, standalone PDF 1.4 forensic report.

- **Response** (`200 OK`, `application/pdf`):
  - Binary stream compliant with PDF 1.4 specification generated using 100% pure JDK capabilities (zero third-party dependencies).
