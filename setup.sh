#!/usr/bin/env bash
# API Fortress - one-time setup for macOS / Linux
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
"$PY" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
echo "[1/4] Creating virtual environment .venv"
[ -d .venv ] || "$PY" -m venv .venv
echo "[2/4] Installing dependencies"
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements.txt
echo "[3/4] Creating .env"
[ -f .env ] || cp .env.example .env
echo "[4/4] Running test suite"
.venv/bin/python -m pytest -q
echo -e "\nSetup complete. Start with: ./start.sh"
