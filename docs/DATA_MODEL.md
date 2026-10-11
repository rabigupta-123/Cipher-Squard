# CIPHER SQUAD — Storage Architecture & Data Model
**Platform:** Pure Java JDK 25 Local-First Threat Detection Engine  
**Persistence Paradigm:** File-Based Append-Only NDJSON (Newline-Delimited JSON)

---

## 1. Storage Architecture Overview

Cipher Squad utilizes a **local-first, file-based persistence architecture**. The platform deliberately does not require an external relational database (such as PostgreSQL or MySQL) or embedded native C-library binaries (such as SQLite), ensuring 100% portable operation across air-gapped environments.

### Storage Safety & Concurrency Principles
- **Append-Only Serialization**: Records are emitted as atomic, single-line JSON objects followed by a newline (`\n`).
- **OS-Level File Locking (`FileLock`)**: Writes to `data/audit.ndjson` and `data/cases.ndjson` obtain an exclusive operating-system lock via `java.nio.channels.FileChannel.tryLock()` to prevent multi-process interleaving.
- **Fail-Safe Recovery**: Interrupted writes or trailing partial lines are detected during verification; corrupt tail lines do not retroactively invalidate prior verified blocks.

---

## 2. Persisted Entity Schemas

### 2.1 Case Record Schema (`data/cases.ndjson`)
Stores security investigation cases generated through model automation (critical threat threshold) or manual analyst triage.

```json
{
  "id": "case-3f9e8a1c",
  "documentId": "a7b3c2d1e0f9847123958abcdef45678901234567890abcdef1234567890abcd",
  "status": "OPEN",
  "title": "BEC Detection: Urgent Wire Transfer Request",
  "subject": "Urgent Wire Transfer Request",
  "messageId": "<msg-923847@mail.evil-lookalike.test>",
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
  "urls": ["http://evil-lookalike.test/login"],
  "attachmentHashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  "members": ["admin"],
  "evidenceHash": "89ab12cd34ef5678901234567890abcdef1234567890abcdef1234567890abcd"
}
```

| Field Name | JSON Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `id` | `string` | Yes | Unique case identifier: `case-` followed by random hex string. |
| `documentId` | `string` | Yes | SHA-256 hash of the analyzed raw RFC 822 email payload. |
| `status` | `string` | Yes | Case lifecycle state: `OPEN`, `RESOLVED`, `CLOSED`. |
| `title` | `string` | Yes | Formatted summary of the threat verdict and subject. |
| `subject` | `string` | No | RFC 5322 Subject header. |
| `messageId` | `string` | No | RFC 5322 Message-ID header. |
| `observedAt` | `number` | Yes | Unix epoch seconds of email transmission. |
| `createdAt` | `number` | Yes | Unix epoch seconds when the case record was opened. |
| `risk` | `number` | Yes | Raw statistical classifier risk score ($0.0 \dots 100.0$). |
| `riskFinal` | `number` | Yes | Final blended risk score accounting for Noisy-OR evidence. |
| `confidence` | `number` | Yes | Epistemic coverage confidence metric $C_{cov} \in [0.0, 1.0]$. |
| `verdict` | `string` | Yes | Primary threat category (`LEGITIMATE`, `PHISHING`, `BEC`, etc.). |
| `band` | `string` | Yes | Operational risk band: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`. |
| `domains` | `array[string]` | Yes | All sender, reply-to, and embedded domain indicators. |
| `addresses` | `array[string]` | Yes | Extracted email addresses. |
| `hopAddresses` | `array[string]` | Yes | IP addresses parsed from `Received:` transit headers. |
| `urls` | `array[string]` | Yes | URLs parsed from message body. |
| `attachmentHashes` | `array[string]` | Yes | SHA-256 hashes of attached files. |
| `evidenceHash` | `string` | Yes | Cryptographic SHA-256 hash binding all case evidence. |

---

### 2.2 Audit Trail Record Schema (`data/audit.ndjson`)
Tamper-evident, linear cryptographic hash chain of all system events.

```json
{
  "index": 0,
  "ts": "2026-10-12T09:14:05.123456Z",
  "event": "analysis",
  "payload": {
    "action": "analysis",
    "actor": "admin",
    "subject": "a7b3c2d1e0f9847123958abcdef45678901234567890abcdef1234567890abcd",
    "outcome": "success",
    "detail": "score=92.4",
    "ts": "2026-10-12T09:14:05.123456Z"
  },
  "prev_hash": "eb52dd73b251b57c8abe4e5c005fdbb5c4a4a7aa53e8d217ad8c973f9b50b1aa",
  "hash": "b898492679fcd5cded68ea865a5ce0bc7b180147049365114b55f6cab5928aee"
}
```

| Field Name | JSON Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `index` | `number` | Yes | 0-based sequential integer strictly matching line number. |
| `ts` | `string` | Yes | ISO-8601 UTC timestamp of record creation. |
| `event` | `string` | Yes | Standard event identifier (`analysis`, `case.open`, `auth.provision`, `login.success`). |
| `payload` | `object` | Yes | Standard detail object containing `actor`, `subject`, `outcome`, `detail`. |
| `prev_hash` | `string` | Yes | SHA-256 hash of previous record (or genesis seed for index 0). |
| `hash` | `string` | Yes | SHA-256 hash over $\text{prev\_hash} \parallel \text{canonicalJSON}(\text{record} \setminus \{\text{"hash"}\})$. |

---

### 2.3 Periodic Signature Record Schema (`data/audit-sigs.ndjson`)
Stores cryptographic digital signatures anchored to specific chain indices.

```json
{
  "index": 49,
  "head_hash": "b898492679fcd5cded68ea865a5ce0bc7b180147049365114b55f6cab5928aee",
  "signature": "MEYCIQDx...",
  "key_id": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
  "signed_at": "2026-10-12T09:14:05.200Z"
}
```

---

### 2.4 User Credential Record Schema (`data/users.ndjson`)
Stores analyst authorization definitions and PBKDF2 password hashes.

```json
{
  "name": "admin",
  "roles": ["admin", "analyst"],
  "salt": "a1b2c3d4e5f67890123456789abcdef0",
  "derived": "f0e1d2c3b4a5968778695a4b3c2d1e0f",
  "iterations": 120000,
  "created_at": "2026-10-12T09:00:00Z"
}
```

---

## 3. Schema Evolution & Migration Guidance

When introducing additional fields to persistent records:
1. **Additive Changes Only**: New fields must be marked optional with default values supplied when parsing older records.
2. **Never Edit Past Audit Records**: `data/audit.ndjson` is cryptographically immutable. Altering an existing line breaks the linear hash chain from that line forward.
3. **Case Backup Procedure**:
   ```powershell
   Copy-Item data/cases.ndjson "data/cases-backup-$(Get-Date -Format 'yyyyMMdd').ndjson"
   ```
