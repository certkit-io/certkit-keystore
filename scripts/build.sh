#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

MODULE="github.com/certkit-io/certkit-keystore"
CMD_PATH="./cmd/certkit-keystore"
BINARY_NAME="certkit-keystore"
DIST_DIR="${DIST_DIR:-dist}"

# Resolve version metadata from git
VERSION=$(git describe --tags 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

echo "Building ${BINARY_NAME} ${VERSION} (commit: ${COMMIT}, date: ${BUILD_DATE})"
echo ""

# Clean and create output directory
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}/bin"

# Windows resources (.syso): icon + VERSIONINFO + manifest. The generated file
# is suffixed _windows_amd64 so only the windows build links it.
# Accept X.Y.Z or a prerelease tag X.Y.Z-<suffix>, but NOT git-describe
# output (1.1.0-35-gabc123[-dirty]) - dev builds keep 0.0.0.
BASE="${VERSION#v}"
VER_NUMERIC="0.0.0"
if echo "$BASE" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' &&
   ! echo "$BASE" | grep -Eq -- '-[0-9]+-g[0-9a-f]+(-dirty)?$' &&
   ! echo "$BASE" | grep -Eq -- '-dirty$'; then
  VER_NUMERIC="$(echo "$BASE" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*$/\1/')"
fi
echo "Generating Windows resources (go-winres, version ${VER_NUMERIC})..."
go run github.com/tc-hib/go-winres@v0.3.3 make \
  --in winres/winres.json \
  --arch amd64 \
  --product-version "$VER_NUMERIC" \
  --file-version "$VER_NUMERIC" \
  --out cmd/certkit-keystore/rsrc

export CGO_ENABLED=0

# Build Linux amd64
echo "Building linux/amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS}" -o "${DIST_DIR}/bin/${BINARY_NAME}-linux-amd64" ${CMD_PATH}

# Build Windows amd64
echo "Building windows/amd64..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS}" -o "${DIST_DIR}/bin/${BINARY_NAME}-windows-amd64.exe" ${CMD_PATH}

# In CI, checksums are generated in the release job AFTER code signing
# (signing changes the file hashes). Locally they are still handy.
if [ "${SKIP_CHECKSUMS:-0}" = "1" ]; then
  echo ""
  echo "Skipping checksums (SKIP_CHECKSUMS=1)"
else
  echo ""
  echo "Generating checksums..."
  (
    cd "${DIST_DIR}/bin"
    sha256sum * > ../checksums.txt
  )
  cat "${DIST_DIR}/checksums.txt"
fi

echo ""
echo "Build complete. Binaries in ${DIST_DIR}/bin/"
