# Contributing to PhishScope

## Development

Follow the README setup for Python 3.14 and Node.js 24. Run the backend from the repository root and the frontend from `frontend/`. Add schema changes as new Alembic revisions; never rewrite an applied migration.

Before submitting a change:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -q
Set-Location frontend
npm test
npm run typecheck
npm run build
# With the backend and frontend running:
npm run test:e2e
```

The GitHub Actions workflow runs these checks on Ubuntu. TypeScript and Python source must remain readable and typed where appropriate. Preserve explainable findings and distinguish reported evidence from interpretation.

## Evidence and privacy

- Use reserved domains, documentation IP ranges and inert attachment contents in test fixtures.
- Never commit `.env` files, API tokens, local evidence databases, real messages, private attachments or sensitive screenshots.
- Do not include real investigation evidence in issue reports. Reproduce failures with a minimal synthetic message instead.
- Keep provider calls explicit and backend-only. Missing credentials, provider errors and no records must never become fabricated malicious or safe verdicts.
- Do not infer a click, execution or breach from email evidence alone.
- Mark changed scoring/mapping behavior in the PR, with supporting tests and limitations.

## Pull requests and issues

Describe the concrete behavior, why it changes, how it was verified, and any migration or security implications. CI must pass. Test failures should be fixed rather than skipped. Report security concerns privately to the repository owner before disclosing details; do not post credentials or exploit evidence publicly.

## Reuse

No open-source license is granted by this repository. Ask the owner for permission before redistributing or reusing the software.
