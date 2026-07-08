@echo off
set ROOT=%~dp0
cd /d "%ROOT%"

if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
)

echo [*] Starting USB Security Interface...
set PYTHONPATH=%ROOT%
.venv\Scripts\python ui\usb-scanner-ui\main_sys.py
pause
