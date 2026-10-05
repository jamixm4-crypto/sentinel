#!/usr/bin/env bash
# Sentinel Uninstaller for Linux and macOS
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jamixm4-crypto/sentinel/main/uninstall.sh | bash

set -e

echo "🛡️  Sentinel Uninstaller"

# 1. Kill any running instances
pkill -f sentinel 2>/dev/null || true

# 2. Delete generated reports
echo "Cleaning up generated audit reports..."
count=0
for rep in ./sentinel-report-*.html ./sentinel-report-*.json ./sentinel-report-*.ndjson "$HOME"/sentinel-report-*.html "$HOME"/sentinel-report-*.json "$HOME"/sentinel-report-*.ndjson; do
  if [ -f "$rep" ]; then
    rm -f "$rep"
    count=$((count+1))
  fi
done
echo "✔ Deleted $count audit report file(s)."

# 3. Delete ~/.sentinel
if [ -d "$HOME/.sentinel" ]; then
  echo "Removing ~/.sentinel data directory..."
  rm -rf "$HOME/.sentinel"
  echo "✔ Removed ~/.sentinel."
fi

# 4. Remove binary
for bin_path in "/usr/local/bin/sentinel" "$HOME/.local/bin/sentinel"; do
  if [ -f "$bin_path" ]; then
    echo "Removing $bin_path..."
    rm -f "$bin_path" 2>/dev/null || sudo rm -f "$bin_path"
    echo "✔ Removed $bin_path."
  fi
done

echo ""
echo "✔ Sentinel and all associated reports have been completely removed!"
