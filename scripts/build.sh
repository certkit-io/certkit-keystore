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

export CGO_ENABLED=0

# Build Linux amd64
echo "Building linux/amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS}" -o "${DIST_DIR}/bin/${BINARY_NAME}-linux-amd64" ${CMD_PATH}

# Build Windows amd64
echo "Building windows/amd64..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS}" -o "${DIST_DIR}/bin/${BINARY_NAME}-windows-amd64.exe" ${CMD_PATH}

# Generate checksums
echo ""
echo "Generating checksums..."
cd "${DIST_DIR}/bin"
sha256sum * > ../checksums.txt
cat ../checksums.txt

echo ""
echo "Build complete. Binaries in ${DIST_DIR}/bin/"
