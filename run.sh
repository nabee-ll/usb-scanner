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

echo "[*] Disabling Raspberry Pi desktop USB automounting..."
# Since this script may be run as root (sudo), we target the 'pi' user specifically
if [[ -d /home/pi ]]; then
    mkdir -p /home/pi/.config/pcmanfm/LXDE-pi/
    echo -e "[volume]\nmount_on_startup=0\nmount_removable=0\nautorun=0" > /home/pi/.config/pcmanfm/LXDE-pi/pcmanfm.conf
    chown -R pi:pi /home/pi/.config/pcmanfm || true
fi

echo "[*] Starting USB Security Engine (Ctrl+C to stop)..."
echo "[*] For storage accept/block enforcement and HID blocking, run with sudo: sudo $0"
echo

exec .venv/bin/python3 changed.py
