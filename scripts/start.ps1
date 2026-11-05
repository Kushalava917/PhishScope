param([switch]$Production)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) { throw 'Run .\scripts\setup.ps1 first.' }
foreach ($localPort in @(8000,3000)) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$localPort)
    try { $listener.Start() } catch { throw "Local port $localPort is already in use. Stop the existing service first." } finally { $listener.Stop() }
}
if ($Production) {
    Push-Location frontend
    try {
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Production build failed.' }
    } finally { Pop-Location }
}
New-Item -ItemType Directory -Force -Path logs | Out-Null
$backendProcess = Start-Process -FilePath "$projectRoot\.venv\Scripts\python.exe" -ArgumentList @('-m','uvicorn','backend.main:app','--host','127.0.0.1','--port','8000') -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput "$projectRoot\logs\backend.log" -RedirectStandardError "$projectRoot\logs\backend-error.log" -PassThru
try {
    $ready = $false
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        if ($backendProcess.HasExited) { throw 'Backend exited. Check logs\backend-error.log. Ports may already be in use.' }
        try { $null = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 1; $ready=$true; break } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw 'Backend did not become ready. Check logs.' }
    Write-Host 'PhishScope: http://127.0.0.1:3000 - Ctrl+C stops both services.'
    Push-Location frontend
    try { if ($Production) { npm run start } else { npm run dev } } finally { Pop-Location }
} finally {
    if (-not $backendProcess.HasExited) { & taskkill.exe /PID $backendProcess.Id /T /F | Out-Null }
}
