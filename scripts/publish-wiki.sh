#!/usr/bin/env bash
set -euo pipefail

WIKI_REMOTE="${1:-git@github.com:jamixm4-crypto/sentinel.wiki.git}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WIKI_SRC="$PROJECT_ROOT/wiki"
TEMP_DIR="/tmp/sentinel_wiki_push"

echo "Publishing Wiki to $WIKI_REMOTE..."
rm -rf "$TEMP_DIR"

if git clone "$WIKI_REMOTE" "$TEMP_DIR" 2>/dev/null; then
    echo "Cloned existing wiki."
else
    echo "Initializing new wiki repo..."
    mkdir -p "$TEMP_DIR"
    git -C "$TEMP_DIR" init
    git -C "$TEMP_DIR" checkout -b master
    git -C "$TEMP_DIR" remote add origin "$WIKI_REMOTE"
fi

cp -f "$WIKI_SRC"/*.md "$TEMP_DIR/"
git -C "$TEMP_DIR" add .
git -C "$TEMP_DIR" commit -m "docs(wiki): update Sentinel knowledge base documentation" --allow-empty
git -C "$TEMP_DIR" push -u origin master --force

echo "Wiki published successfully."
