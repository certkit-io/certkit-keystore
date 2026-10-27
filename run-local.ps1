$ErrorActionPreference = "Stop"
$env:CERTKIT_API_BASE = "https://localhost:44301"
$root = $PSScriptRoot
# Dev builds keep their config and log here instead of the standard locations.
$env:CERTKIT_KEYSTORE_DEV_DIR = $root
$configPath = Join-Path $root "config.json"
$storageDir = Join-Path $root "test-storage"
$keystoreHost = "host.docker.internal"
$port = 8989

if (-not (Test-Path $configPath)) {
    go run ./cmd/certkit-keystore install --host $keystoreHost --port $port --storage-dir $storageDir --no-service
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

go run ./cmd/certkit-keystore run
