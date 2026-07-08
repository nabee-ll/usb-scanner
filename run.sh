#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# ── Virtual Environment Setup ────────────────────────────────────────────────
if [[ ! -d .venv ]]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi

echo "[*] Installing / updating dependencies..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

# ── Database Init ────────────────────────────────────────────────────────────
.venv/bin/python3 db_init.py

# ── Disable Desktop USB Automounting ────────────────────────────────────────
echo "[*] Disabling desktop USB automounting at the OS level..."
if [[ "$EUID" -eq 0 ]]; then
    # Disable pcmanfm automount (for older LXDE)
    if [[ -d /home/pi ]]; then
        mkdir -p /home/pi/.config/pcmanfm/LXDE-pi/
        echo -e "[volume]\nmount_on_startup=0\nmount_removable=0\nautorun=0" > /home/pi/.config/pcmanfm/LXDE-pi/pcmanfm.conf
        chown -R pi:pi /home/pi/.config/pcmanfm || true
    fi
    # Disable for current sudo user if different
    REAL_USER="${SUDO_USER:-pi}"
    REAL_HOME=$(eval echo "~$REAL_USER")
    if [[ -d "$REAL_HOME" && "$REAL_HOME" != "/home/pi" ]]; then
        mkdir -p "$REAL_HOME/.config/pcmanfm/LXDE-pi/"
        echo -e "[volume]\nmount_on_startup=0\nmount_removable=0\nautorun=0" > "$REAL_HOME/.config/pcmanfm/LXDE-pi/pcmanfm.conf"
        chown -R "$REAL_USER":"$REAL_USER" "$REAL_HOME/.config/pcmanfm" || true
    fi
    # Add udev rule to hide USB drives from udisks2 (stops all Wayland/desktop popups)
    echo 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"' > /etc/udev/rules.d/99-hide-usb-from-udisks.rules
    udevadm control --reload-rules
    udevadm trigger
else
    echo "[!] Please run this script with sudo for full USB control: sudo ./run.sh"
fi

echo "[*] Starting USB Security Interface (Ctrl+C to stop)..."
echo

# ── Launch UI ────────────────────────────────────────────────────────────────
# Set PYTHONPATH so that ui/usb-scanner-ui modules can import each other by short name
export PYTHONPATH="$ROOT/ui/usb-scanner-ui:$ROOT"

# Change into the UI directory so relative imports work cleanly
cd "$ROOT/ui/usb-scanner-ui"
exec "$ROOT/.venv/bin/python3" main_sys.py
