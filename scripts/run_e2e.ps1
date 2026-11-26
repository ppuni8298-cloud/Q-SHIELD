$ErrorActionPreference = "Stop"

$venvPython = "$PSScriptRoot\..\.venv\Scripts\python.exe"
$npmCmd = "npm.cmd"

Write-Host "=== Starting FastAPI Backend on port 8000 using $venvPython ==="
$backend = Start-Process -FilePath $venvPython -ArgumentList "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1" -PassThru -NoNewWindow

Write-Host "=== Starting Vite Preview on port 4173 ==="
$frontend = Start-Process -FilePath $npmCmd -ArgumentList "run", "preview", "--prefix", "frontend", "--", "--port", "4173", "--host", "127.0.0.1" -PassThru -NoNewWindow

Start-Sleep -Seconds 5

try {
    Write-Host "=== Running Playwright End-to-End Tests ==="
    cd frontend
    npx.cmd playwright test
    $playwrightExit = $LASTEXITCODE
    cd ..
    if ($playwrightExit -ne 0) {
        Write-Error "Playwright E2E tests failed with exit code $playwrightExit"
    } else {
        Write-Host "=== Playwright E2E Tests Succeeded! ==="
    }
} finally {
    Write-Host "=== Terminating background servers ==="
    if ($backend -and -not $backend.HasExited) {
        Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
    }
    if ($frontend -and -not $frontend.HasExited) {
        Stop-Process -Id $frontend.Id -Force -ErrorAction SilentlyContinue
    }
}
