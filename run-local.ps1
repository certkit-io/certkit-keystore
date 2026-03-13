$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$configPath = Join-Path $root "config.json"
$storageDir = Join-Path $root "test-storage"

if (-not (Test-Path $configPath)) {
    $key = Read-Host "Enter registration key"
    if (-not $key) {
        Write-Error "Registration key is required"
        exit 1
    }
    go run ./cmd/certkit-keystore install --key $key --config $configPath --storage-dir $storageDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

go run ./cmd/certkit-keystore run --config $configPath
