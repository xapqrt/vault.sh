#!/usr/bin/env bash
set -euo pipefail
echo "[vault.sh] One-click local dev setup"
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || { echo "Python 3 not found" >&2; exit 1; }
if [ ! -d .venv ]; then
  echo "Creating virtual env (.venv)";
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
echo "Installing deps..."; pip install -q -r config/requirements.txt
echo "Smoke test..."; python -m src.main --help >/dev/null || { echo "CLI failed"; exit 1; }
echo "Done. Try: python -m src.main init"
