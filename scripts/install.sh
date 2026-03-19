#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ...)" >&2
  exit 1
fi

OWNER="certkit-io"
REPO="certkit-keystore"
BIN_NAME="certkit-keystore"
INSTALL_DIR="/usr/local/bin"

FIRST_INSTALL=0
if [[ ! -f "${INSTALL_DIR}/${BIN_NAME}" ]]; then
  FIRST_INSTALL=1
fi

echo ""
echo "Installing CertKit Keystore..."
echo ""

# Resolve release tag (latest unless VERSION set)
if [[ -n "${VERSION:-}" ]]; then
  TAG="$VERSION"
else
  TAG="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/${OWNER}/${REPO}/releases/latest" | sed -n 's#.*/tag/##p')"
  if [[ -z "$TAG" ]]; then
    echo "Failed to determine latest release tag" >&2
    exit 1
  fi
fi

echo "Using release tag: ${TAG}"

ASSET_BIN="${BIN_NAME}-linux-amd64"
ASSET_SHA="checksums.txt"
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${ASSET_BIN}"
curl -fsSL "${BASE_URL}/${ASSET_BIN}" -o "$tmp/${ASSET_BIN}"

echo "Downloading checksums"
curl -fsSL "${BASE_URL}/${ASSET_SHA}" -o "$tmp/${ASSET_SHA}"

echo "Verifying checksum"
(
  cd "$tmp"
  grep -E "^[a-f0-9]{64}[[:space:]]+${ASSET_BIN}\$" "${ASSET_SHA}" | sha256sum -c -
)

echo "Installing binary to ${INSTALL_DIR}/${BIN_NAME}"
install -m 0755 "$tmp/${ASSET_BIN}" "${INSTALL_DIR}/${BIN_NAME}"

echo ""
echo "Running certkit-keystore install..."
echo ""
"${INSTALL_DIR}/${BIN_NAME}" install </dev/tty

if [[ $FIRST_INSTALL -eq 0 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    echo "Restarting ${BIN_NAME}.service"
    systemctl restart "${BIN_NAME}.service"
  fi
fi

echo ""
echo "Installation complete."
echo ""
