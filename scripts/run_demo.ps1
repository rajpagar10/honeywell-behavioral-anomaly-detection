param(
    [switch]$SkipInstall,
    [switch]$NoBrowser,
    [int]$ReplayIntervalMs = 25
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$badp = Join-Path $projectRoot ".venv\Scripts\badp.exe"
$streamlit = Join-Path $projectRoot ".venv\Scripts\streamlit.exe"
$artifacts = Join-Path $projectRoot "artifacts\demo"

if (-not (Test-Path -LiteralPath $python)) {
    py -3.12 -m venv (Join-Path $projectRoot ".venv")
}
if (-not $SkipInstall) {
    & $python -m pip install -e "${projectRoot}[ml,dashboard]"
}

Set-Location $projectRoot
if (-not (Test-Path -LiteralPath "data\samples\honeywell_demo\manifest.json")) {
    & $badp generate-data --generator-config config/generator/demo.yaml `
        --output data/samples/honeywell_demo
}
& $badp train-model --dataset data/samples/honeywell_demo `
    --training-config config/training/fast.yaml --output artifacts/models/fast
& $badp init-db

New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$env:BADP_INTELLIGENCE__ALERT_THRESHOLD = "40"
$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = "false"
$api = Start-Process -FilePath $badp -ArgumentList "serve" -WorkingDirectory $projectRoot `
    -WindowStyle Hidden -PassThru

for ($attempt = 0; $attempt -lt 60; $attempt++) {
    try {
        Invoke-RestMethod "http://127.0.0.1:8000/health" | Out-Null
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

$dashboard = Start-Process -FilePath $streamlit `
    -ArgumentList "run","dashboard/app.py","--server.port","8501" `
    -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
$body = @{ interval_ms = $ReplayIntervalMs; max_events = 2000 } | ConvertTo-Json
Invoke-RestMethod -Method Post -ContentType "application/json" -Body $body `
    "http://127.0.0.1:8000/api/v1/replay/start" | Out-Null

@{ api = $api.Id; dashboard = $dashboard.Id } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $artifacts "processes.json")
if (-not $NoBrowser) {
    Start-Process "http://127.0.0.1:8501"
}
Write-Host "Dashboard: http://127.0.0.1:8501"
Write-Host "API docs:  http://127.0.0.1:8000/docs"
Write-Host "Stop with: powershell -ExecutionPolicy Bypass -File scripts/stop_demo.ps1"
