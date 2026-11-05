# Verification

Tests must be run from the repository root or frontend directory as shown. Never interpret fixture provider responses as actual reputation evidence.

## Backend

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -q
```

The suite uses a disposable SQLite file, initializes the schema, clears domain rows between tests, and runs application migrations through lifespan. It does not touch the local workspace evidence database. Coverage includes parsing and headers, missing/conflicting authentication, sender/Reply-To analysis, URL/domain/IPv4/IPv6/hash extraction, attachment hashes, deduplication, evidence-backed mappings, unique-factor scoring, benign control, API creation/persistence/revisions/deletion, byte-perfect source downloads, notes, PDF page text, Markdown/JSON exports, search/filter/settings, file type/MIME/size validation, host/origin/request limits, missing keys and provider timeouts/HTTP failures.

Provider adapters are tested with explicit mocked HTTP responses (success, malformed/error, missing record, unauthorized and rate-limited). Live authenticated provider requests are not tested without keys. No indicators are submitted to real providers by the tests.

## Frontend

```powershell
Set-Location frontend
npm test
npm run typecheck
npm run build
```

Vitest + Testing Library checks empty data-derived dashboard, navigation, paste submission, upload/demo input switching, indicator evidence/export controls and disclosure consent, MITRE search, settings save and API error/retry states.

## End-to-end

Start both services, then:

```powershell
Set-Location frontend
npx playwright install chromium
npm run test:e2e
```

Playwright uses real Chromium and the actual running API/database. Its phishing workflow covers dashboard → demonstration submission → parsed sender/authentication → extracted URLs/search/filter/CSV → ATT&CK → response → saved notes → preview → PDF download → PDF text inspection with pypdf → reopen → re-analysis/revision persistence. Other tests cover a benign email, paste and upload, settings, all eight page routes, inert stored-XSS content, and mobile navigation/layout. Tests delete only the cases they created afterward. Browser tests write transient test evidence and change the analyst preference back to SOC Analyst; use a dedicated workspace for test-only runs.

The PDF downloaded by the browser is saved under `frontend/test-results/`, ignored by Git. HTML traces and failure screenshots are also ignored. Unit tests and Playwright execute without paid APIs.

## Delivery results

Execution results are recorded in `docs/VERIFICATION.md`. Windows sandbox loopback restrictions prevented Python async tests and some frontend compiler workers from starting in the restricted shell; those commands were executed with approved local process access. Webpack replaces Turbopack for this environment. No failed test is skipped or disabled.

Docker Compose configuration is validated independently with `docker compose config --quiet`. Docker image/runtime and PostgreSQL are separate unvalidated deployment targets. A successful local production build does not imply those targets were exercised.
