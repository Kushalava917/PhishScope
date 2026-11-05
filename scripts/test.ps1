$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q
if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
Push-Location frontend
try {
    npm test
    if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed.' }
    npm run typecheck
    if ($LASTEXITCODE -ne 0) { throw 'TypeScript check failed.' }
} finally { Pop-Location }
Write-Host 'Unit and integration checks passed. With both services running: cd frontend; npm run test:e2e'
