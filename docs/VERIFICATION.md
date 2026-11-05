# Delivery verification — 2026-11-05

Verified on Windows with Node.js 24.18.0, npm 12.0.2 and Python 3.14. Frontend resolved Next.js 16.4.5; backend resolved FastAPI 0.139.2, SQLAlchemy 2.0.57, Pydantic 2.14.2 and ReportLab 4.5.1. Exact dependency trees are committed in the lock files.

| Check actually executed | Result |
| --- | --- |
| `python -m pytest backend/tests -q` | **60 passed**; 3.67 seconds on the final run |
| `npm test` | **7 passed**; 8.19 seconds on the final run |
| `npm run test:e2e` against the production services | **5 passed**; 20.1 seconds |
| `npm run build` | **Passed**, optimized webpack production build including TypeScript and page generation |
| `npm run typecheck` | **Passed**, no TypeScript errors |
| `python -m ruff check backend --select F` | **Passed** |
| `python -m pip check` | **Passed**, no broken requirements |
| `npm audit --omit=dev --json` | **0 known production dependency vulnerabilities** |
| `python -m pip_audit -r backend/requirements.lock.txt --disable-pip --no-deps` | **No known vulnerabilities found** |
| `docker compose config --quiet` | **Passed** |
| Documented PowerShell `scripts/start.ps1 -Production` | **Passed**, rebuilt and started both loopback services |

## Browser acceptance coverage

1. Indicator detail/disclosure consent, reserved-value submission blocked before network access, Escape dismissal/focus restoration, JSON export, original analysis revision view and typed confirmed deletion.
2. Actual synthetic phishing submission, parsed email/authentication, IOC search/filter/CSV, evidence-supported T1566.002 mapping, response recommendations, saved analyst notes, formatted report preview, real PDF download, extracted PDF content checks, reopening saved data and retained re-analysis revision.
3. Benign message scoring 0/100 with no supported phishing mappings.
4. Pasted email and multipart `.eml` upload, byte-perfect original evidence retrieval, settings persistence, and navigation through forensics, IOC intelligence, ATT&CK and reports.
5. Hostile HTML email remains inert with no rendered image/script/frame resources; 390px mobile navigation and no viewport overflow.

No browser runtime errors were observed in the primary investigation workflow. The tests do not skip or disable any failing case. The initial mobile overflow and dialog focus restoration failures were fixed and the complete final suite passed. Generated test cases are cleaned up after the suite. Four labelled, safe synthetic cases were then loaded for documentation screenshots and a sample PDF.

## Evidence artifacts

- `docs/screenshots/overview.png`
- `docs/screenshots/investigation.png`
- `docs/screenshots/report.png`
- `docs/screenshots/mobile.png`
- `docs/sample-incident-report.pdf`

These artifacts come from actual stored synthetic investigation records. They are not fabricated intelligence results or placeholder dashboards.

## Unverified targets and limitations

- Real authenticated provider calls were **not executed** because no user API keys were supplied. Four provider adapters, result persistence/caching, missing credentials, error/rate-limit/timeout handling and response interpretation are covered with explicit deterministic test doubles. No test reputation is written to the actual analyst workspace.
- Docker images/containers were **not built or run**: Docker Desktop's Linux engine pipe was unavailable. Only Compose configuration was validated.
- PostgreSQL was **not exercised**. The default tested database is SQLite; model portability does not constitute PostgreSQL runtime verification.
- The application is a single-user loopback workspace without built-in authentication, RBAC or encrypted storage. Public/multi-user deployment is outside this verified release scope.
- The MITRE explorer is a five-technique curated subset. Local risk is heuristic. No recipient interaction, endpoint execution, independent SPF/DKIM verification or confirmed breach is claimed.
- PDF uses portable built-in fonts and replaces unsupported non-ASCII glyphs with `?`; original evidence and JSON/Markdown preserve source characters (Markdown safely escapes HTML).
- Tests report one upstream Starlette warning about its future HTTPX test-client migration; Vitest reports a future configuration-loader warning. Neither is a failing test or runtime error.

The Windows restricted shell blocked Python async loopback initialization and some build operations. Required compiler/test/server commands were rerun with approved local process access. Webpack is the configured build path because Turbopack failed during worker startup on this machine.
