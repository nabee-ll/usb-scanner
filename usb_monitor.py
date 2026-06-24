import pyudev
import os
import time
import sqlite3
import hashlib
from datetime import datetime

# -------------------------------------------------
# DATABASE CONFIG
# -------------------------------------------------
import os

DB_NAME = os.path.join(os.path.dirname(__file__), "test_malware.db")

def check_hash(sha256_hash):
    """Check if SHA256 hash exists in malware database."""
    try:
        sha256_hash = sha256_hash.strip().lower()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT signature, severity
            FROM malware_hashes
            WHERE sha256_hash = ?
        """, (sha256_hash,))

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "signature": result[0],
                "severity": result[1]
            }

        return None

    except Exception as e:
        print(f"[!] Database lookup failed: {e}")
        return None

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    CHUNK_SIZE = 1024 * 1024  # 1MB
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Hashing failed for {file_path}: {e}")
        return None

# -------------------------------------------------
# PHASE 1 + 2 – FILE ENGINE (SMART FILTER + HASH CHECK)
# -------------------------------------------------
def scan_files_with_malware_check(mount_path):
    high_risk_files = []
    medium_risk_files = []
    low_risk_files = []
    structural_flags = []

    total_files = 0
    risk_score = 0

    suspicious_extensions = [".exe", ".bat", ".ps1", ".vbs", ".scr"]

    for root, dirs, files in os.walk(mount_path):
        for file in files:
            total_files += 1
            file_path = os.path.join(root, file)
            lower_file = file.lower()

            # Show scanning progress
            print(f"Scanning: {file_path}", end="\r")

            try:
                size = os.path.getsize(file_path)
            except:
                size = 0

            # -------------------------------
            # Smart Filter Rules
            # -------------------------------
            rule_applied = False
            if any(lower_file.endswith(ext) for ext in suspicious_extensions):
                high_risk_files.append({"path": file_path, "size": size, "reason": "Executable file"})
                risk_score += 3
                rule_applied = True

            elif lower_file == "autorun.inf":
                high_risk_files.append({"path": file_path, "size": size, "reason": "Autorun file"})
                structural_flags.append("Autorun file detected")
                risk_score += 5
                rule_applied = True

            elif file.startswith("."):
                medium_risk_files.append({"path": file_path, "size": size, "reason": "Hidden file"})
                risk_score += 1
                rule_applied = True

            else:
                parts = lower_file.split(".")
                if len(parts) > 2:
                    if any(lower_file.endswith(ext) for ext in suspicious_extensions):
                        high_risk_files.append({"path": file_path, "size": size, "reason": "Double extension executable"})
                        risk_score += 4
                    else:
                        medium_risk_files.append({"path": file_path, "size": size, "reason": "Double extension file"})
                        risk_score += 2
                    rule_applied = True

            # -------------------------------
            # Malware Hash Check (Phase 2)
            # -------------------------------
            sha = calculate_sha256(file_path)
            if sha:
                result = check_hash(sha)
                if result:
                    high_risk_files.append({
                        "path": file_path,
                        "size": size,
                        "reason": f"Malware Detected: {result['signature']}"
                    })
                    risk_score += 10  # Assign higher weight for confirmed malware
                    rule_applied = True

            # -------------------------------
            # Normal File
            # -------------------------------
            if not rule_applied:
                low_risk_files.append({"path": file_path, "size": size, "reason": "Normal file"})

    return {
        "total_files": total_files,
        "risk_score": risk_score,
        "high_risk": high_risk_files,
        "medium_risk": medium_risk_files,
        "low_risk": low_risk_files,
        "structural_flags": structural_flags
    }

# -------------------------------------------------
# GET MOUNT POINT
# -------------------------------------------------
def find_mount_point(device_node):
    with open("/proc/mounts", "r") as f:
        for line in f:
            parts = line.split()
            if parts[0] == device_node:
                return parts[1].replace("\\040", " ")
    return None

def wait_for_mount(device_node, timeout=15):
    for _ in range(timeout):
        time.sleep(1)
        mount_path = find_mount_point(device_node)
        if mount_path and os.path.exists(mount_path):
            return mount_path
    return None

# -------------------------------------------------
# USB MONITOR
# -------------------------------------------------
def monitor_usb():
    print("[*] Waiting for USB storage device...\n")
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")

    try:
        for device in iter(monitor.poll, None):
            if device.action == "add" and device.device_type == "partition":
                if device.get("ID_BUS") != "usb":
                    continue

                print("\n[+] USB Storage Partition Detected")
                parent = device.parent
                vendor = parent.get("ID_VENDOR", "Unknown")
                model = parent.get("ID_MODEL", "Unknown")
                serial = parent.get("ID_SERIAL_SHORT", "Unknown")

                print("\n--- Device Information ---")
                print(f"Vendor : {vendor}")
                print(f"Model  : {model}")
                print(f"Serial : {serial}")
                print(f"Node   : {device.device_node}")

                mount_path = wait_for_mount(device.device_node)
                if not mount_path:
                    print("[!] Could not detect mount path automatically.\n")
                    continue

                print(f"[+] Mounted at: {mount_path}\n")
                print("[*] Starting full scan... please wait.\n")

                report = scan_files_with_malware_check(mount_path)

                # ---------------------------------
                # PRINT REPORT
                # ---------------------------------
                print("\n----- SCAN REPORT -----")
                print(f"Scan Time       : {datetime.now()}")
                print(f"Total Files     : {report['total_files']}")
                print(f"High Risk Files : {len(report['high_risk'])}")
                print(f"Medium Risk     : {len(report['medium_risk'])}")
                print(f"Low Risk        : {len(report['low_risk'])}")
                print(f"Risk Score      : {report['risk_score']}")

                if report['risk_score'] >= 10:
                    print("Threat Level    : HIGH")
                elif report['risk_score'] >= 5:
                    print("Threat Level    : MEDIUM")
                elif report['risk_score'] > 0:
                    print("Threat Level    : LOW")
                else:
                    print("Threat Level    : CLEAN")

                print("\n--- High Risk Files ---")
                for f in report["high_risk"]:
                    print(f"[HIGH] {f['path']} --> {f['reason']}")
                print("=" * 60)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting gracefully...")
        return

# -------------------------------------------------
# ENTRY
# -------------------------------------------------
if __name__ == "__main__":
    monitor_usb()
