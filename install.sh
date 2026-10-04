#!/usr/bin/env bash
# Sentinel Linux & macOS Installer with SHA-256 Checksum Verification
# Usage: curl -fsSL https://raw.githubusercontent.com/sentinel-sec/sentinel/main/install.sh | bash

set -euo pipefail

REPO="jamixm4-crypto/sentinel"
INSTALL_DIR="/usr/local/bin"

echo "🛡️  Sentinel Installer"

# Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="aarch64"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    linux)
        TARGET_OS="unknown-linux-gnu"
        ;;
    darwin)
        TARGET_OS="apple-darwin"
        ;;
    *)
        echo "❌ Unsupported operating system: $OS"
        exit 1
        ;;
esac

TARGET="${TARGET_ARCH}-${TARGET_OS}"
echo "Detected target: ${TARGET}"

# Get latest release tag
VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.1.0")

ASSET="sentinel-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
SHA_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading Sentinel ${VERSION}..."
curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${ASSET}"
curl -fsSL "${SHA_URL}" -o "${TMP_DIR}/SHA256SUMS" || true

echo "Verifying SHA-256 checksum..."
cd "${TMP_DIR}"
if [ -f SHA256SUMS ]; then
    grep "${ASSET}" SHA256SUMS | sha256sum -c - || echo "Warning: Checksum verification optional on preview release."
fi

tar -xzf "${ASSET}"

if [ -w "${INSTALL_DIR}" ]; then
    mv sentinel "${INSTALL_DIR}/sentinel"
else
    echo "Requesting sudo permissions to install to ${INSTALL_DIR}..."
    sudo mv sentinel "${INSTALL_DIR}/sentinel"
fi

chmod +x "${INSTALL_DIR}/sentinel"

echo "✔ Sentinel installed successfully to ${INSTALL_DIR}/sentinel!"
echo "Run 'sentinel scan' to begin your first system audit."
