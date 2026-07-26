$projectRoot = Split-Path -Parent $PSScriptRoot
$processFile = Join-Path $projectRoot "artifacts\demo\processes.json"
if (Test-Path -LiteralPath $processFile) {
    $processes = Get-Content -LiteralPath $processFile | ConvertFrom-Json
    @($processes.api, $processes.dashboard) | ForEach-Object {
        Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Demo processes stopped."
} else {
    Write-Host "No demo process file found."
}
