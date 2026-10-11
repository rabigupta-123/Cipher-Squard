# CIPHER SQUAD — Operational Boundaries & Known Limitations
**Platform: Pure Java JDK 25 Local-First Threat Detection Engine**

## 1. Architectural Boundaries

### 1.1 Local-First & Zero-Third-Party Architecture
- The system is built to function 100% offline with zero external dependencies (no Spring Boot, no external database drivers, no external PDF generation libraries).
- All geolocation and ASN intelligence originates from local snapshots (`data/ip2asn.tsv`, `data/geolite2.tsv`). Real-time live WHOIS or BGP looking-glass queries require opt-in external network adapters configured with explicit timeout guards.

### 1.2 Bounded Ingress Buffers
- Maximum email message size is capped at 50 MB (`MAX_BODY_BYTES`) to prevent denial-of-service via resource exhaustion in single-node SOC deployments.
- In-memory stream decoders operate under strict allocation limits (`DecodeBudget`). Encrypted or password-protected ZIP/PDF payloads are flagged as suspicious/uninspectable rather than attempting computational brute-forcing.

### 1.3 Case & Audit Storage Scaling
- Audit records and forensic cases are stored in local, append-only NDJSON format (`data/audit.ndjson`, `data/cases.ndjson`) protected by OS-level file locking.
- For deployments exceeding 1,000,000 cases per year, an external enterprise database adapter can be mounted without breaking the cryptographic linear hash chain.

### 1.4 PDF 1.4 Styling Scope
- PDF reports are generated via pure JDK 25 streams following the standard PDF 1.4 specification. Complex HTML-to-PDF CSS rendering engines are avoided to preserve zero-dependency stability and prevent SSRF / rendering RCE vulnerabilities.
