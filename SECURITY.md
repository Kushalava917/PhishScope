# Security boundaries

PhishScope is designed for a single local analyst. The operating-system account owns all evidence and controls every investigation. This release has no multi-user authentication/authorization. Keep the provided loopback bindings. A host/origin allowlist is not a substitute for authentication.

## Implemented protections

- API request envelope limited to 8 MiB before body parsing; original email capped at 5 MiB; maximum 200 MIME parts. Unexpected recursive structures are rejected.
- Only `.eml` and `.txt` uploads with allowed MIME declarations; binary signatures, NUL content and missing From/Subject are rejected. MIME declarations are untrusted and supplemented by actual email parsing.
- Sanitized display filenames are never used to write attacker-chosen filesystem paths. Attachment bytes are only decoded and hashed in memory.
- React escapes all email strings. HTML email is represented as inert plain text, with no HTML injection, iframe, remote image, link navigation or attachment execution.
- Fixed provider URLs, no target fetching or redirects, request timeouts, private/reserved/sensitive-value exclusions, explicit indicator disclosure consent, simulation lookup blocking, local rate limits, and successful-result caching.
- API keys stay in environment variables; configuration status exposes no key bytes. Errors omit provider request URLs and credentials.
- SQLAlchemy parameterized ORM operations; foreign-key cascades; isolated test database.
- Mutation origin and Sec-Fetch-Site validation, trusted Host allowlist and restricted CORS origins. Do not add arbitrary domains or wildcard values.
- No-store API responses, nosniff, referrer suppression, frontend frame restrictions and CSP. Next.js hydration uses inline scripts, so script-src includes unsafe-inline; no claim of a strict nonce CSP is made.
- CSV formula prefix escaping; PDF markup escaping; export files are served with attachment Content-Disposition.
- Typed DELETE confirmation in UI; direct API deletion is intentionally permitted for the same local analyst principal.
- Docker containers run non-root; backend port is not published; frontend publish binds loopback.

## Evidence privacy

The SQLite file contains full original email evidence and attachments in base64. Filesystem encryption/ACLs and backups belong to the local operator. The app does not encrypt evidence at rest, redact sensitive content from reports, or securely overwrite deleted SQLite pages/WAL files. Deletion removes records logically; it is not forensic media sanitization. Downloads contain the original record data, so handle them as confidential.

Public values may still be sensitive. URL paths and hashes can disclose information; the analyst must review the selected value before explicitly consenting. Query/fragment/user-info URLs, private/reserved IPs, simulations and email addresses are blocked. Indicator hostnames are checked syntactically without DNS resolution; the application never connects to them directly.

## Assessment integrity

Authentication-Results supplied in a file can be forged. UI/reports display them as reported claims, never cryptographic verification. No internet result is invented in offline mode. A provider's no-detection response is not a safe verdict; no_record, missing keys, errors and rate limits remain unverified. The local score does not incorporate invented domain/sender reputation. Email-only evidence cannot establish a click, code execution or breach.

## Validation and remaining controls

Automated checks cover upload abuse, size rejection, foreign-key deletion, origin/host checks, secret non-disclosure, PDF escaping/content, inert browser XSS payloads and no email HTML resource rendering. `npm audit --omit=dev` returned zero published vulnerabilities for the installed production dependency tree on 2026-11-05. This is a bounded build-time verification, not an exhaustive penetration test or security certification.

Shared deployment requires authentication/RBAC, CSRF/session design appropriate to that authentication, TLS, per-user quotas and durable audit logging, an encrypted datastore, backup/retention policy, independent security review and monitored provider secrets. Large malformed input/resource-exhaustion hardening beyond the enforced limits needs workload-specific testing. PostgreSQL and Docker runtime are not delivery-tested. Do not expose this installation to the public internet.
