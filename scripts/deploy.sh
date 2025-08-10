#!/usr/bin/env bash
set -euo pipefail

echo "[deploy] Starting lightweight deployment check"

if [ ! -f config/requirements.txt ]; then
	echo "Missing config/requirements.txt" >&2
	exit 1
fi

python -m pip install -r config/requirements.txt
echo "[deploy] Dependencies installed"

echo "[deploy] Running tests"
pytest -q

echo "[deploy] OK"

