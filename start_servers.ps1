# Q-SHIELD - Start Backend & Frontend Development Servers
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Q-SHIELD - Quantum-Ready Trust & Revocation Plane      " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "[!] Virtual environment not found at $venvPython. Using system python." -ForegroundColor Yellow
    $venvPython = "python"
}

Write-Host "`n[1/2] Launching FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Cyan
$backend = Start-Process -FilePath $venvPython -ArgumentList "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload" -PassThru

Write-Host "[2/2] Launching Vite Frontend on http://localhost:5173..." -ForegroundColor Cyan
$frontend = Start-Process -FilePath "npm.cmd" -ArgumentList "run", "dev" -WorkingDirectory (Join-Path $PSScriptRoot "frontend") -PassThru

Write-Host "`n>>> Q-SHIELD is now running! <<<" -ForegroundColor Green
Write-Host "  Web Console:  http://localhost:5173" -ForegroundColor White
Write-Host "  Backend API:  http://127.0.0.1:8000" -ForegroundColor White
Write-Host "  OpenAPI Docs: http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "`nPress Ctrl+C or enter 'stop' to shut down both servers.`n" -ForegroundColor Yellow

try {
    while ($true) {
        $input = Read-Host
        if ($input -eq "stop" -or $input -eq "exit" -or $input -eq "q") {
            break
        }
    }
} finally {
    Write-Host "`nStopping servers..." -ForegroundColor Yellow
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue }
    if ($frontend -and -not $frontend.HasExited) { Stop-Process -Id $frontend.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "Both servers stopped successfully." -ForegroundColor Green
}
