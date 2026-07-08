import json
import subprocess
import threading
import os
import sys
from PyQt6.QtCore import QObject, pyqtSignal

class BackendManager(QObject):
    log_received = pyqtSignal(str)
    device_detected = pyqtSignal(dict)
    prompt_received = pyqtSignal(str, dict)
    scan_progress = pyqtSignal(int, str)
    scan_complete = pyqtSignal(dict)
    status_update = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = None
        self.reader_thread = None
        self.is_running = False

    def start_backend(self):
        backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "changed.py"))
        venv_python_linux = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".venv", "bin", "python3"))
        venv_python_win = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".venv", "Scripts", "python.exe"))
        
        # We try to run with sudo if on Linux/macOS, otherwise just python3
        cmd = []
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            python_exec = venv_python_linux if os.path.exists(venv_python_linux) else "python3"
            cmd = ["sudo", python_exec, backend_path, "--ui-mode"]
        else:
            python_exec = venv_python_win if os.path.exists(venv_python_win) else "python"
            cmd = [python_exec, backend_path, "--ui-mode"]
            
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.DEVNULL, # Ignore stderr to keep terminal clean
                text=True,
                bufsize=1
            )
            self.is_running = True
            self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self.reader_thread.start()
        except Exception as e:
            self.log_received.emit(f"Failed to start backend: {e}")

    def _read_output(self):
        while self.is_running and self.process:
            try:
                line = self.process.stdout.readline()
                if not line:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    payload = json.loads(line)
                    self._handle_payload(payload)
                except json.JSONDecodeError:
                    # Not JSON, maybe a stray print? Send it to log anyway
                    self.log_received.emit(line)
            except Exception as e:
                pass
                
    def _handle_payload(self, payload):
        event_type = payload.get("type")
        if event_type == "log":
            self.log_received.emit(payload.get("message", ""))
        elif event_type == "device_detected":
            self.device_detected.emit(payload)
        elif event_type == "prompt":
            prompt_id = payload.get("prompt_id", "unknown")
            self.prompt_received.emit(prompt_id, payload)
        elif event_type == "scan_progress":
            self.scan_progress.emit(payload.get("progress", 0), payload.get("message", ""))
        elif event_type == "scan_complete":
            self.scan_complete.emit(payload)
        elif event_type == "status_update":
            self.status_update.emit(payload.get("vid_pid", ""), payload.get("status", ""))

    def send_response(self, response_dict):
        """Send a JSON response back to the backend process."""
        if self.process and self.process.stdin:
            try:
                self.process.stdin.write(json.dumps(response_dict) + "\n")
                self.process.stdin.flush()
            except Exception:
                pass

    def stop(self):
        self.is_running = False
        if self.process:
            self.process.terminate()
