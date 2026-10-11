# CIPHER SQUAD — Error Handling & Failure Isolation Architecture
**Platform:** Pure Java JDK 25 Local-First Threat Detection Engine

---

## 1. Architectural Distinction: Backend Isolation vs. Frontend Boundaries

Unlike multi-tier web applications that rely on client-side framework error boundaries (e.g., React Error Boundary classes), Cipher Squad implements **technology-specific failure isolation** appropriate for its architecture:
- **Backend (Java SE 25)**: Employs typed exception hierarchies, thread-local request tracking, bounded memory allocations, strict HTTP status code translation, and fail-closed cryptographic seals.
- **Frontend (Vanilla HTML5/ES6 SPA)**: Employs `window.onerror`, unhandled promise rejection listeners (`unhandledrejection`), async fetch guards, visual error banners, and non-blocking toast notifications.

---

## 2. Backend Error-Boundary Audit

| Execution Boundary | Potential Failure Condition | Exception Type / Signal | Current Handling & Isolation | Server-Side Logging | Public Leakage Guard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HTTP Request Reader** | Body exceeds `MAX_BODY_BYTES` (50MB) | `Http.RequestException` (413) | Terminates stream read, discards remainder, returns 413. | Logged to console with byte count. | Safe generic message: `request entity too large`. No buffer contents echoed. |
| **Path & Percent Escapes** | Malformed URL encoding (`%ZZ`), null byte (`%00`), path traversal (`..`) | `Http.RequestException` (400) | Aborts dispatch, returns 400 Bad Request. | Logged as malformed URI error. | Raw unparseable bytes suppressed. |
| **Route Dispatch** | Unregistered endpoint path | Unmatched Route (404) | Emits standard JSON 404 response. | Normal request log. | No internal filesystem paths disclosed. |
| **Method Dispatch** | Disallowed method (e.g. `POST /api/cases`) | Method mismatch (405) | Emits 405 Method Not Allowed with required `Allow:` header. | Normal request log. | Clear RFC-compliant header. |
| **Authentication Gate** | Missing or malformed Basic / Bearer token | Auth Failure (401) | Emits 401 Unauthorized with `WWW-Authenticate: Basic` header. | Increments failure counter in `byAccount` map. | Password values zeroed (`Arrays.fill(pw, '0')`); never logged. |
| **Brute-Force Guard** | $\ge 5$ failed attempts within 15 mins | Account Lockout | Enforces 15-minute freeze window; rejects even correct passwords during window. | Audit log record `login.failure` appended with `account locked`. | Returns 401. Does not reveal whether user exists. |
| **RFC 5322 MIME Parser** | Malformed headers, unclosed boundary, corrupt base64 | Parser Warning / `BadMessage` | Traps exception; records warning in `Message.warnings`; parses surviving parts. | Logs warning to parser context. | Partial parse succeeds; malformed part marked uninspected. |
| **Unicode Normalizer** | Unknown script, invalid code points | `IllegalArgumentException` | Skips unmapped code point; preserves canonical representation. | None (high-throughput pipeline). | Preserves idempotence invariant. |
| **Softmax Numeric Math** | Logits $\pm \infty$, NaN | Clamped Logit / `ModelException` | Clamps inputs to $[-2.5, 2.5]$; uses max-shifted subtraction $z_k - \max(z)$. | Model rejects NaN feature explicitly in validation. | Guaranteed finite probability sum = 1.0. |
| **SSRF Verification** | Host resolves to private IP, link-local, cloud metadata | `App.Ssrf.Decision` (Denied) | Rejects target; halts outbound dispatch; returns `deny(reason)`. | Logged with reason (`loopback`, `cloud_metadata`). | Destination IP/hostname rejected before socket allocation. |
| **Audit Log Write** | Disk full, file lock contention > 10s | `IOException`, `TimeoutException` | Bounded retry loop (10s); aborts if locked; fails request with 503. | High-priority alert: `audit log locked after 10s`. | Refuses operation rather than writing corrupt record. |
| **Audit Verification** | Tampered hash, deleted row, gap in index sequence | `Audit.ChainBrokenException` | **Fails closed**: Seals audit chain, halts all write operations, returns 503. | High-severity alert: `audit chain broken at index N`. | Informs operator of divergence index; refuses to bury tampering. |

---

## 3. Standardized Error-Response Contract

All API error responses adhere to the standard JSON structure implemented by [Http.java](file:///sih_java/src/Http.java#L319):

```json
{
  "ok": false,
  "error": "reason_code",
  "message": "Human-readable descriptive explanation of the error.",
  "status": 400
}
```

### Standard HTTP Status Codes Utilized
- **`400 Bad Request`**: Malformed JSON, unparseable RFC 822 email, invalid query parameters.
- **`401 Unauthorized`**: Missing, invalid, or locked credentials.
- **`403 Forbidden`**: Insufficient role privileges for the requested action.
- **`404 Not Found`**: Non-existent API route or case identifier.
- **`405 Method Not Allowed`**: Unsupported HTTP verb on route; emits `Allow:` header.
- **`413 Payload Too Large`**: Request body exceeds the configured maximum ceiling (`MAX_BODY_BYTES`).
- **`415 Unsupported Media Type`**: Expected `message/rfc822` but received incompatible payload.
- **`500 Internal Server Error`**: Unexpected runtime exceptions. Stack traces are strictly logged to `System.err` and **never** returned in the HTTP response.
- **`503 Service Unavailable`**: Service overloaded or audit chain broken (`audit_chain_broken`).

---

## 4. Frontend Failure Isolation (Single-Page Console)

The analyst web console ([index.html](file:///sih_java/index.html)) implements comprehensive client-side error trapping:

1. **Global Unhandled Error Listeners**:
   ```javascript
   window.addEventListener('error', function(event) {
     console.error('[Console] Unhandled script error:', event.error);
     showGlobalToast('An unexpected UI error occurred. Please refresh.', 'error');
   });

   window.addEventListener('unhandledrejection', function(event) {
     console.error('[Console] Unhandled promise rejection:', event.reason);
     showGlobalToast('Network request or background operation failed.', 'warning');
   });
   ```
2. **Network Resilience & Fetch Guards**:
   All asynchronous API invocations wrap requests in `try ... catch` blocks with status code inspection.
   - On `401 Unauthorized`: Displays session expiration notice and redirects analyst to login modal.
   - On `503 Service Unavailable`: Shows an audit integrity warning banner advising operator action.
   - On Network Disconnection: Retains entered data in local form state; does not clear inputs.
3. **Empty-State & Loading Indicators**:
   All dynamic sections (Hop Timeline, Indicator Tables, Case Lists) render dedicated empty-state containers when datasets are zero-length or unavailable.

---

## 5. Failure-Isolation & Degraded Mode Policy

- **Independent Enrichment Failure**: If an external or offline enrichment source (e.g., GeoIP database) cannot locate an IP address, the attribution engine returns `status: "unresolved"` with `country: null`. It **does not** fail the email analysis or produce false negative scores.
- **Epistemic Integrity**: The scoring engine never converts absence of evidence into an affirmative clean verdict. An analysis with missing components transparently reports reduced coverage confidence ($C_{cov} < 1.0$).
