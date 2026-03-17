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
    $keystoreHost = Read-Host "Enter host (e.g. localhost, keystore.example.com)"
    if (-not $keystoreHost) {
        Write-Error "Host is required"
        exit 1
    }
    $port = Read-Host "Enter port (default: 443)"
    if (-not $port) { $port = "443" }
    go run ./cmd/certkit-keystore install --key $key --host $keystoreHost --port $port --config $configPath --storage-dir $storageDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

go run ./cmd/certkit-keystore run --config $configPath
