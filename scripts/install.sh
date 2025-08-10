#!/usr/bin/env bash
# Remote installer: downloads latest binary or falls back to python setup.
set -euo pipefail
REPO="xapqrt/vault.sh"
BIN="vaultsh"
API="https://api.github.com/repos/$REPO/releases/latest"
echo "Installing $BIN (vault.sh)"
TMP=$(mktemp -d)
cd "$TMP"
ARCH=$(uname -m)
OS=$(uname | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux*) PLATFORM=linux ;;
  darwin*) PLATFORM=macos ;;
  *) PLATFORM=unknown ;;
esac
if [ "$PLATFORM" = unknown ]; then echo "Unsupported platform" >&2; exit 1; fi
echo "Fetching release metadata..."
URL=$(curl -fsSL "$API" | grep browser_download_url | grep "$BIN-$PLATFORM" | cut -d '"' -f4 | head -n1 || true)
if [ -n "${URL:-}" ]; then
  echo "Downloading binary: $URL"; curl -fsSL "$URL" -o "$BIN"; chmod +x "$BIN"; mv "$BIN" /usr/local/bin/ || sudo mv "$BIN" /usr/local/bin/
  echo "Installed /usr/local/bin/$BIN"; which $BIN; echo "Run: $BIN --help"; exit 0
fi
echo "Binary not found; falling back to Python setup.";
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || { echo "Python 3 required" >&2; exit 1; }
if [ ! -d vault.sh ]; then git clone https://github.com/$REPO.git vault.sh; fi
cd vault.sh
$PY -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r config/requirements.txt
echo "Run with: python -m src.main --help"
