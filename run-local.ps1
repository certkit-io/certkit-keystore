$ErrorActionPreference = "Stop"
$env:CERTKIT_API_BASE = "https://localhost:44301"
$root = $PSScriptRoot
$configPath = Join-Path $root "config.json"
$storageDir = Join-Path $root "test-storage"
$keystoreHost = "host.docker.internal"
$port = 8989

if (-not (Test-Path $configPath)) {
    go run ./cmd/certkit-keystore install --host $keystoreHost --port $port --config $configPath --storage-dir $storageDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

go run ./cmd/certkit-keystore run --config $configPath
