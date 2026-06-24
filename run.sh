#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
fi

.venv/bin/python3 db_init.py

echo "[*] Starting USB Security Engine (Ctrl+C to stop)..."
echo "[*] For HID blocking, run with sudo: sudo $0"
echo

exec .venv/bin/python3 changed.py
