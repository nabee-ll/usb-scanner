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

echo "[*] Disabling desktop USB automounting at the OS level..."
if [[ "$EUID" -eq 0 ]]; then
    # Disable pcmanfm automount (for older LXDE)
    if [[ -d /home/pi ]]; then
        mkdir -p /home/pi/.config/pcmanfm/LXDE-pi/
        echo -e "[volume]\nmount_on_startup=0\nmount_removable=0\nautorun=0" > /home/pi/.config/pcmanfm/LXDE-pi/pcmanfm.conf
        chown -R pi:pi /home/pi/.config/pcmanfm || true
    fi
    # Add udev rule to hide USB drives from udisks2 (stops all Wayland/desktop popups)
    echo 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"' > /etc/udev/rules.d/99-hide-usb-from-udisks.rules
    udevadm control --reload-rules
    udevadm trigger
else
    echo "[!] Please run this script with sudo to disable USB automount popups."
fi

echo "[*] Starting USB Security Engine (Ctrl+C to stop)..."
echo "[*] For storage accept/block enforcement and HID blocking, run with sudo: sudo $0"
echo

exec .venv/bin/python3 changed.py
