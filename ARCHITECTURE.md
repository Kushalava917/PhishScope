# Architecture

Browser → Next.js workspace → same-origin `/api` rewrite → FastAPI → SQLAlchemy → SQLite. Outbound calls exist only in the four fixed provider adapters and only behind a validated, explicit IOC lookup request. The static forensic engine has no network I/O.

## Data model

| Table | Purpose and lifecycle |
| --- | --- |
| investigations | UUID, name, original base64 bytes, display text, SHA-256, creation time, simulation tag, notes, completion status |
| analysis_revisions | UUID, investigation FK, creation timestamp, immutable JSON engine result |
| indicators | Revision/investigation FKs, value, type, structured evidence and extraction confidence |
| intelligence | Provider, selected value, result/status, timestamp, investigation FK; serves as lookup history and cache |
| report_exports | Investigation/revision FKs, format, generated-at timestamp, output SHA-256 |
| settings | Validated preference object; never stores API keys |

UUIDs and UTC ISO-8601 timestamps are used throughout. SQLite WAL, busy timeout and enforced foreign keys are enabled on each connection. The model uses portable SQLAlchemy JSON/Text/String types. Alembic `0001` uses explicit frozen schema operations; future changes should add versioned revisions, never mutate an applied migration. Back up data before migrations.

## Investigation transaction

1. Bound request body before JSON/multipart parsing (8 MiB request envelope).
2. Validate extension, declared MIME, byte length (5 MiB), textual structure and mandatory From/Subject.
3. Parse MIME into metadata and text without evaluating or fetching content.
4. Compute attachment digests, flags, indicators, mappings, risk and conditional recommendations.
5. Commit original evidence, first revision and deduplicated indicators together.
6. Show the persisted record; dashboard counters query stored cases.

Re-analysis always reads original base64 bytes and creates a new revision and IOC rows. Original source and earlier findings are retained. Current views use the latest revision; the Evidence & history view opens each previous revision. Notes are editable current analyst commentary, not immutable forensic evidence. Reports record their revision and output digest; exported bytes are downloaded rather than archived server-side. Intelligence results are separate from revisioned local analysis and remain available on re-analysis.

## Forensic rules

Rules identify reported authentication failures, Reply-To/display-name mismatch, recognized-brand sender mismatch, unusual sender domain structure, urgency, credential/payment language, link-text/target mismatch, hidden/active HTML, shortened URLs, encoded/user-info/IP authorities, redirect parameters, risky/double attachment extensions, selected MIME/signature discrepancies, duplicate singleton headers and incomplete provenance headers. URL targets in redirect parameters are metadata hypotheses only.

Public suffix matching uses the library's bundled snapshot with update URLs disabled; no DNS or public-suffix downloads occur. Header authentication values are not cryptographic verification. Attachment signature checks are intentionally limited to recognized simple formats; no AV or sandbox engine is included.

IOC evidence stores extraction locations and excerpts. Domain/email/hash values are normalized, and `(type,value)` is deduplicated within a revision. Synthetic examples use `.example`, RFC documentation addresses and inert bytes. Computed file digests are real hashes of inert fixture contents, not asserted malware hashes.

## Risk and ATT&CK

Each unique rule code contributes once, even if many identical links trigger findings. Score is the sum capped at 100: 0–24 low, 25–49 medium, 50–74 high, 75–100 critical. These are application conventions. External reputation is separate; unknown sender/domain reputation is not assigned invented points. No recipient interaction or compromise is inferred.

T1566 and delivery sub-techniques require corroborating suspicious findings. Attachment execution remains an unverified hypothesis. T1204.001 is considered only when a suspicious link is paired with execution-related language; credential requests alone do not establish its execution semantics. Official sources: [Phishing](https://attack.mitre.org/techniques/T1566/), [Malicious Link](https://attack.mitre.org/techniques/T1204/001/), [Malicious File](https://attack.mitre.org/techniques/T1204/002/). Curated definitions reviewed 2026-11-05.

## Providers and reports

Fixed HTTPS hosts, a 10-second timeout and no followed redirects prevent fetching attacker-supplied URLs. All provider calls occur server-side; keys come from environment configuration. Results record actual provider fields and errors. URLScan existing-record counts do not imply maliciousness. AbuseIPDB abuse reports are not malware detections. See official [VirusTotal](https://docs.virustotal.com/reference/overview), [URLScan](https://docs.urlscan.io/pages/api-intro), [AbuseIPDB](https://docs.abuseipdb.com/), and [Safe Browsing](https://developers.google.com/safe-browsing/v4/lookup-api) documentation.

Report preview and all formats derive from one section builder. PDF text is escaped before ReportLab markup processing, tables repeat header rows and split long cells, and page footers carry classification and numbering. The cover plus 18 sections implements the requested 19-part report. Metadata, findings, evidence register, limitations, references, notes and export timeline come from stored records.

## Operational scope

Local single-analyst workload; synchronous parsing and report generation. No queue, login, RBAC, tenant boundary, antivirus execution environment, retention daemon or live mailbox/EDR integration. For shared deployments, add authenticated identity, access control, encryption, quotas, pagination, queued jobs, audit logging, secret management and tested PostgreSQL migrations before exposure.
