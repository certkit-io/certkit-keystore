param(
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"

$MODULE = "github.com/certkit-io/certkit-keystore"
$CMD_PATH = "./cmd/certkit-keystore"
$BINARY_NAME = "certkit-keystore"

# Resolve version metadata from git
try { $VERSION = & git describe --tags 2>&1 | Where-Object { $_ -is [string] } } catch { $VERSION = $null }
if (-not $VERSION -or $VERSION -match "fatal") {
    try { $VERSION = & git rev-parse --short HEAD 2>&1 } catch { $VERSION = $null }
    if (-not $VERSION) { $VERSION = "dev" }
}
try { $COMMIT = & git rev-parse --short HEAD 2>&1 } catch { $COMMIT = $null }
if (-not $COMMIT) { $COMMIT = "unknown" }
$BUILD_DATE = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$LDFLAGS = "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE"

Write-Host "Building $BINARY_NAME $VERSION (commit: $COMMIT, date: $BUILD_DATE)"
Write-Host ""

# Clean and create output directory
if (Test-Path $OutputDir) {
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Path $OutputDir | Out-Null

$env:CGO_ENABLED = "0"

# Build Windows amd64
Write-Host "Building windows/amd64..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
& go build -trimpath -ldflags $LDFLAGS -o "$OutputDir/${BINARY_NAME}.exe" $CMD_PATH
if ($LASTEXITCODE -ne 0) { throw "Windows build failed" }

# Build Linux amd64
Write-Host "Building linux/amd64..."
$env:GOOS = "linux"
$env:GOARCH = "amd64"
& go build -trimpath -ldflags $LDFLAGS -o "$OutputDir/${BINARY_NAME}" $CMD_PATH
if ($LASTEXITCODE -ne 0) { throw "Linux build failed" }

# Generate checksums
Write-Host ""
Write-Host "Generating checksums..."
Get-ChildItem -Path $OutputDir -File | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)" | Out-File -Append -FilePath "$OutputDir/checksums.txt" -Encoding utf8
    Write-Host "  $hash  $($_.Name)"
}

Write-Host ""
Write-Host "Build complete. Binaries in $OutputDir/"
