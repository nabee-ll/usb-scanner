import pyudev
import os
import time
import sqlite3
import hashlib
import fcntl
import struct
import threading
import re
import math
import collections
import zipfile
import io
import json
import base64
import binascii
import concurrent.futures
import warnings
import shutil
from datetime import datetime
import subprocess

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

from db_init import DB_NAME, ensure_database

# ==========================================
# TERMINAL COLORS
# ==========================================
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    END    = "\033[0m"

# ==========================================
# HID WHITELIST
# Add YOUR trusted devices here as "vid:pid": "Name"
# Run `lsusb` to find your device IDs.
# ==========================================
HID_RISK_CACHE = {}

HID_WHITELIST = {
    "413c:2113": "Dell KB216 Wired Keyboard",     # corrected PID
    "413c:3020": "Dell KB216 Wired Keyboard (alt)",
    "0461:4d15": "Primax Electronics Keyboard",
    "046d:c534": "Logitech USB Receiver",
    "093a:2510": "PixArt Optical USB Mouse",
    "1c4f:0034": "SIGMACHIP USB Mouse",            # now whitelisted
}


def format_vid_pid(vid, pid):
    """Normalize vendor/product IDs to the whitelist key format."""
    return f"{str(vid).lower()}:{str(pid).lower()}"


def is_whitelisted_hid(vid, pid):
    return format_vid_pid(vid, pid) in HID_WHITELIST

# Bus type 0003 = USB HID.
# 001e = platform/HDMI, 0011 = i8042/PS2, 0019 = GPIO.
# Non-USB buses can NEVER be USB HID attack devices — filter them out.
USB_BUS_TYPE = "0003"

# ==========================================
# STATIC ANALYSIS ENGINE (INTEGRATED)
# ==========================================
def calculate_risk(findings):
    total_risk = sum(f.get('risk', 0) for f in findings)
    if total_risk >= 8:
        return "HIGH"
    elif total_risk >= 4:
        return "MEDIUM"
    elif total_risk > 0:
        return "LOW"
    return "CLEAN"

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c)

def extract_strings(data: bytes, min_len: int = 6) -> list:
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [s.decode("ascii", errors="ignore") for s in ascii_re.findall(data)]

def static_analyze(file_path: str) -> list:
    '''
    Perform deep static analysis without execution.
    Returns a list of findings (dictionaries with 'issue' and 'risk' score).
    '''
    findings = []
    try:
        file_size = os.path.getsize(file_path)
        # 3. Skip very large files (>100MB) to prevent freezing
        if file_size > 100 * 1024 * 1024:
            findings.append({"issue": "File too large (>100MB)", "risk": 1})
            return findings
            
        # Extension-based Type
        ext = os.path.splitext(file_path)[1].lower()
        
        with open(file_path, 'rb') as f:
            head = f.read(4)
            f.seek(0)
            data = f.read()
            
        # 1. File Type Validation (Magic Bytes Anti-evasion)
        is_exe = head[:2] == b"MZ"
        is_zip = head[:4] == b"PK\x03\x04"
        is_elf = head[:4] == b"\x7fELF"
        
        if is_exe and ext not in ['.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl']:
            findings.append({"issue": f"Magic byte mismatch: EXE disguised as {ext}", "risk": 8})
        if is_zip and ext not in ['.zip', '.jar', '.apk', '.docx', '.xlsx']:
            if ext in ['.jpg', '.png', '.mp3', '.pdf']:
                findings.append({"issue": f"Magic byte mismatch: ZIP/Archive disguised as {ext}", "risk": 7})

        # Entropy Check (packed code)
        entropy = calc_entropy(data)
        if entropy > 7.4:
            findings.append({"issue": f"Very high entropy ({entropy:.2f}) - packed/encrypted", "risk": 7})
        elif entropy > 6.8:
            findings.append({"issue": f"Elevated entropy ({entropy:.2f}) - obfuscation", "risk": 3})

        # 7. Safe Archive Handling
        if is_zip or ext in ['.zip', '.apk', '.jar']:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    entries = zf.infolist()
                    if len(entries) > 2000:
                        findings.append({"issue": "Archive contains abnormally high file count (>2000)", "risk": 4})
                    
                    suspicious_exts = {'.exe', '.bat', '.ps1', '.py', '.sh', '.vbs', '.js', '.cmd', '.dll'}
                    sus_files = []
                    total_uncompressed = 0
                    
                    for e in entries[:2000]:  # limit inspection depth
                        total_uncompressed += e.file_size
                        e_ext = os.path.splitext(e.filename)[1].lower()
                        if e_ext in suspicious_exts:
                            sus_files.append(e.filename)
                            
                        # Double extension check
                        parts = e.filename.split('.')
                        if len(parts) > 2 and f".{parts[-1].lower()}" in suspicious_exts:
                            findings.append({"issue": f"Double extension in archive: {e.filename}", "risk": 8})
                            
                    if total_uncompressed > 500 * 1024 * 1024:  # 500MB extraction limit bomb
                        findings.append({"issue": "Possible zip bomb (huge uncompressed ratio)", "risk": 6})
                        
                    if sus_files:
                        findings.append({"issue": f"Archive payload contains executables/scripts: {', '.join(sus_files[:3])}", "risk": 6})
            except zipfile.BadZipFile:
                findings.append({"issue": "Corrupt or password-protected archive", "risk": 4})
            except Exception:
                pass

        # Content Decoding
        is_script = ext in ['.bat', '.ps1', '.sh', '.py', '.vbs', '.js', '.cmd']
        text_content = ""
        if is_script:
            text_content = data.decode("utf-8", errors="ignore")
        elif is_exe or is_elf:
            text_content = "\n".join(extract_strings(data))
            
        if text_content:
            # Dangerous Strings Risk Weighting
            dangerous_patterns = [
                (r"powershell(\.exe)?\s+(?:-w\s+hidden|-enc|-nop|-ep\s+bypass)", 9, "PowerShell stealth execution"),
                (r"nc\s+.*-e\s+/bin/(?:sh|bash)", 10, "Netcat reverse shell"),
                (r"bash\s+-i\s+>&", 10, "Bash interactive reverse shell"),
                (r"curl\s+.*\|\s*(?:bash|sh|python)", 10, "Pipe-to-shell remote execution"),
                (r"Invoke-Expression|IEX\s*\(", 8, "PowerShell arbitrary code execution (IEX)"),
                (r"cmd(?:\.exe)?\s+/c", 6, "CMD shell execution"),
                (r"WScript\.Shell", 7, "VBScript Win32 shell execution"),
                (r"VirtualAllocEx|WriteProcessMemory", 8, "Process Injection APIs"),
                (r"SetWindowsHookEx", 8, "Keylogging APIs")
            ]
            for pat, risk, desc in dangerous_patterns:
                if re.search(pat, text_content, re.IGNORECASE):
                    findings.append({"issue": desc, "risk": risk})
            
            # 6. Base64 Payload Safe Detection & Decoding
            b64_blobs = re.findall(r"(?:[A-Za-z0-9+/]{40,}={0,2})", text_content)
            if b64_blobs:
                findings.append({"issue": f"Encoded Base64 strings detected ({len(b64_blobs)})", "risk": 4})
                for blob in b64_blobs:
                    try:
                        decoded = base64.b64decode(blob).decode('utf-8', errors='ignore')
                        if re.search(r"Invoke-|powershell|cmd\.exe|WScript", decoded, re.IGNORECASE):
                            findings.append({"issue": "Base64 decoded payload contains malicious execution commands", "risk": 8})
                    except Exception:
                        pass
                        
            # 5. URL and IP Extraction
            urls = re.findall(r"https?://[^\s\"'>]{4,200}", text_content, re.IGNORECASE)
            ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text_content)
            
            private_ip_re = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|255\.)")
            external_ips = [ip for ip in set(ips) if not private_ip_re.match(ip)]
            unique_urls = list(set(urls))
            
            if external_ips:
                findings.append({"issue": f"IPv4 Addresses Extracted: {', '.join(external_ips[:3])}", "risk": 6})
            if unique_urls:
                findings.append({"issue": f"URLs (HTTP/HTTPS) Extracted: {', '.join(unique_urls[:3])}", "risk": 4})
                
    except Exception as e:
         findings.append({"issue": f"Static analysis error: {str(e)}", "risk": 0})
         
    return findings

# ==========================================
# DATABASE CONFIG
# ==========================================
def check_hash(sha256_hash):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT signature, severity FROM malware_hashes WHERE sha256_hash = ?",
            (sha256_hash.lower(),)
        )
        result = cursor.fetchone()
        conn.close()
        return {"signature": result[0], "severity": result[1]} if result else None
    except Exception as e:
        print(f"Database error: {e}")
        return None

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def _clamav_command():
    """Prefer clamdscan when available, otherwise fall back to clamscan."""
    clamdscan = shutil.which("clamdscan")
    if clamdscan:
        return [clamdscan, "--no-summary"]
    clamscan = shutil.which("clamscan")
    if clamscan:
        return [clamscan, "--no-summary"]
    return None


def clamav_scan_file(file_path):
    """Return ClamAV findings for a single file, or an empty list when clean/unavailable."""
    command = _clamav_command()
    if not command:
        return []
    try:
        result = subprocess.run(
            command + [file_path],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return [{"issue": f"ClamAV scan skipped: {e}", "risk": 0}]

    output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
    if result.returncode == 1:
        signature = "infected file"
        for line in output.splitlines():
            if " FOUND" in line:
                signature = line.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                break
        return [{"issue": f"ClamAV MALWARE DETECTED: {signature}", "risk": 15}]
    if result.returncode > 1:
        return [{"issue": f"ClamAV scan error: {output[:160]}", "risk": 0}]
    return []

# ==========================================
# STORAGE MONITOR
# ==========================================
def find_mount_point(device_node):
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if parts[0] == device_node:
                    return parts[1].replace("\\040", " ")
    except Exception:
        pass
    return None

def try_mount_with_udisks(device_node):
    """Ask udisks to mount the partition when desktop auto-mount is slow or missing."""
    try:
        result = subprocess.run(
            ["udisksctl", "mount", "-b", device_node, "--no-user-interaction"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if " at " in line:
                return line.split(" at ", 1)[1].strip().rstrip(".")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def wait_for_mount(device_node, timeout=15):
    for attempt in range(timeout):
        mount = find_mount_point(device_node)
        if mount and os.path.exists(mount):
            return mount
        if attempt == 4:
            mount = try_mount_with_udisks(device_node)
            if mount and os.path.exists(mount):
                return mount
        time.sleep(1)
    return None


def is_root_user():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def unmount_storage(device_node=None, mount_path=None):
    """Best-effort unmount used to keep unsafe storage unavailable."""
    success = False
    commands = []
    if device_node and shutil.which("udisksctl"):
        commands.append(["udisksctl", "unmount", "-b", device_node, "--no-user-interaction"])
    if mount_path:
        commands.append(["umount", mount_path])

    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                success = True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return success


def quarantine_mount_path(device_node):
    safe_name = os.path.basename(device_node).replace("/", "_")
    return os.path.join("/tmp", "usb_scanner_quarantine", safe_name)


def mount_for_quarantine_scan(device_node):
    """
    Mount a USB partition read-only with execution/device bits disabled for scanning.
    Returns (mount_path, is_quarantine_mount).
    """
    existing_mount = find_mount_point(device_node)
    if existing_mount:
        print(Colors.YELLOW + f"[*] USB auto-mounted at {existing_mount}; unmounting before safety scan." + Colors.END)
        unmount_storage(device_node, existing_mount)

    if not is_root_user():
        print(Colors.YELLOW +
              "[!] Not running as root. Cannot enforce read-only quarantine mount; using existing OS mount if available." +
              Colors.END)
        mount = wait_for_mount(device_node)
        return mount, False

    mount_path = quarantine_mount_path(device_node)
    try:
        os.makedirs(mount_path, mode=0o700, exist_ok=True)
        result = subprocess.run(
            ["mount", "-o", "ro,nosuid,nodev,noexec", device_node, mount_path],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0:
            print(Colors.GREEN + f"[+] Quarantine-mounted read-only at {mount_path}" + Colors.END)
            return mount_path, True
        print(Colors.YELLOW + f"[!] Quarantine mount failed: {result.stderr.strip()}" + Colors.END)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        print(Colors.YELLOW + f"[!] Quarantine mount error: {e}" + Colors.END)

    mount = wait_for_mount(device_node)
    return mount, False


def release_storage_for_use(device_node, mount_path, is_quarantine_mount):
    """Unmount scan mount and remount normally only after a clean verdict."""
    if is_quarantine_mount:
        unmount_storage(mount_path=mount_path)
    if shutil.which("udisksctl"):
        mount = try_mount_with_udisks(device_node)
        if mount:
            print(Colors.GREEN + f"[✓] Device accepted and mounted for user access at {mount}" + Colors.END)
            return True
    print(Colors.GREEN + "[✓] Device accepted. It is safe to mount/use normally." + Colors.END)
    return True


def keep_storage_blocked(device_node, mount_path, is_quarantine_mount):
    """Remove unsafe storage from the filesystem view."""
    if mount_path:
        unmount_storage(device_node, mount_path)
    if is_quarantine_mount:
        try:
            os.rmdir(mount_path)
        except OSError:
            pass
    print(Colors.RED + f"[!] Device rejected. {device_node} is not mounted for user access." + Colors.END)


# ==========================================
# MTP / PHONE STORAGE SUPPORT
# ==========================================
def is_mtp_or_ptp_device(device):
    """Best-effort udev detection for phones that expose files through MTP/PTP."""
    checks = [
        device.get("ID_MTP_DEVICE"),
        device.get("ID_MEDIA_PLAYER"),
        device.get("ID_PTP_DEVICE"),
        device.get("MTP_NO_PROBE"),
    ]
    if any(str(value).lower() in {"1", "true", "yes"} for value in checks if value):
        return True

    searchable = " ".join(
        str(value).lower()
        for value in [
            device.get("ID_USB_CLASS_FROM_DATABASE"),
            device.get("ID_USB_INTERFACES"),
            device.get("ID_MODEL"),
            device.get("ID_VENDOR"),
            device.get("ID_USB_DRIVER"),
        ]
        if value
    )
    return any(token in searchable for token in ("mtp", "ptp", "still imaging", "media player"))


def _gvfs_mtp_roots():
    uid = os.getuid() if hasattr(os, "getuid") else None
    candidates = []
    if uid is not None:
        candidates.append(f"/run/user/{uid}/gvfs")
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(os.path.join(xdg_runtime, "gvfs"))
    return [path for path in candidates if os.path.isdir(path)]


def find_existing_mtp_mounts():
    mounts = []
    for gvfs_root in _gvfs_mtp_roots():
        try:
            for name in os.listdir(gvfs_root):
                path = os.path.join(gvfs_root, name)
                if name.startswith(("mtp:", "gphoto2:")) and os.path.isdir(path):
                    mounts.append(path)
        except OSError:
            continue
    return mounts


def try_mount_with_gio(device):
    """Ask GVFS/GIO to mount the MTP/PTP device if the desktop stack is available."""
    if not shutil.which("gio"):
        return []

    before = set(find_existing_mtp_mounts())
    device_file = device.device_node or device.get("DEVNAME")
    mount_targets = []
    if device_file:
        mount_targets.append(device_file)

    # Some desktops need a generic MTP volume activation instead of a dev node.
    mount_targets.extend(["mtp://", "gphoto2://"])

    for target in mount_targets:
        try:
            subprocess.run(
                ["gio", "mount", target],
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue

        after = set(find_existing_mtp_mounts())
        new_mounts = list(after - before)
        if new_mounts:
            return new_mounts
    return list(set(find_existing_mtp_mounts()) - before)


def try_mount_with_fuse_mtp(device):
    """Mount the first available MTP device with simple-mtpfs or jmtpfs when installed."""
    helper = shutil.which("simple-mtpfs") or shutil.which("jmtpfs")
    if not helper:
        return None

    vid = str(device.get("ID_VENDOR_ID", "unknown")).lower()
    pid = str(device.get("ID_MODEL_ID", "unknown")).lower()
    mount_root = os.path.join("/tmp", "usb_scanner_mtp")
    mount_path = os.path.join(mount_root, f"{vid}_{pid}")
    try:
        os.makedirs(mount_path, mode=0o700, exist_ok=True)
        result = subprocess.run(
            [helper, mount_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and os.path.isdir(mount_path):
            return mount_path
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def wait_for_mtp_mount(device, timeout=20):
    """Return accessible MTP/PTP mount paths for a connected phone."""
    for attempt in range(timeout):
        mounts = find_existing_mtp_mounts()
        if mounts:
            return mounts

        if attempt == 3:
            mounts = try_mount_with_gio(device)
            if mounts:
                return mounts

        if attempt == 7:
            mount = try_mount_with_fuse_mtp(device)
            if mount:
                return [mount]

        time.sleep(1)
    return []

def scan_file_task(path):
    findings = []
    
    sha = calculate_sha256(path)
    if sha:
        result = check_hash(sha)
        if result:
            findings.append({"issue": f"DB MALWARE DETECTED: {result['signature']}", "risk": 15})

    findings.extend(clamav_scan_file(path))
            
    try:
        sa_findings = static_analyze(path)
        if sa_findings:
            findings.extend(sa_findings)
    except Exception as e:
        findings.append({"issue": f"Analysis error: {str(e)}", "risk": 0})
        
    return path, findings

def scan_storage(mount_path, device_info=None):
    print(Colors.CYAN + Colors.BOLD + "\n[ SCANNING ] High-Speed Threaded FS Analysis...\n" + Colors.END)
    
    master_risk_score = 0
    malware_detected = False
    all_files = []
    malicious_files = []
    
    try:
        for root, dirs, files in os.walk(mount_path):
            for file in files:
                all_files.append(os.path.join(root, file))
    except Exception as e:
        print(f"Directory read error: {e}")
        
    log_file = os.path.join(os.path.dirname(__file__), "scan_log.json")
    
    # 9. Performance Optimization: ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_path = {executor.submit(scan_file_task, path): path for path in all_files}
        
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                # 4. Timeout Protection (3 seconds)
                res_path, findings = future.result(timeout=3.0)
            except concurrent.futures.TimeoutError:
                findings = [{"issue": "File scanning timed out (>3s limit)", "risk": 2}]
            except Exception as e:
                findings = [{"issue": f"Thread exception: {e}", "risk": 0}]
            
            if not findings:
                continue

            # 2. Risk Scoring Engine Integration
            risk_level = calculate_risk(findings)
            r_score = sum(f.get('risk', 0) for f in findings)
            master_risk_score += r_score
            
            if risk_level in ["HIGH", "MEDIUM"]:
                malware_detected = True
                malicious_files.append(path)
            
            # Print cleanly
            if risk_level == "HIGH":
                color = Colors.RED
            elif risk_level == "MEDIUM":
                color = Colors.YELLOW
            else:
                color = Colors.CYAN
                
            print(f"\n{color}{Colors.BOLD}[*] {risk_level} RISK FILE: {path}{Colors.END}")
            for f in findings:
                print(f"{color}  -> {f['issue']} (Risk: {f.get('risk')}){Colors.END}")
                
            # 8. Structured Logging System
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "device": device_info if device_info else mount_path,
                "file": path,
                "risk_level": risk_level,
                "risk_score": r_score,
                "findings": findings
            }
            try:
                with open(log_file, "a") as lf:
                    lf.write(json.dumps(log_entry) + "\n")
            except Exception:
                pass

    print(" " * 80, end="\r")
    return master_risk_score, malware_detected, malicious_files

# ==========================================
# THREAT LEVEL LABEL
# ==========================================
def threat_level(score):
    if score >= 15:
        return Colors.RED    + Colors.BOLD + "HIGH"   + Colors.END
    elif score >= 8:
        return Colors.YELLOW + Colors.BOLD + "MEDIUM" + Colors.END
    elif score > 0:
        return Colors.GREEN  + Colors.BOLD + "LOW"    + Colors.END
    else:
        return Colors.BLUE   + Colors.BOLD + "CLEAN"  + Colors.END

# ==========================================
# USB STORAGE HANDLER
# ==========================================
def analyze_descriptors(device):
    return {
        "vendor":     device.get("ID_VENDOR",                "Unknown"),
        "model":      device.get("ID_MODEL",                 "Unknown"),
        "serial":     device.get("ID_SERIAL_SHORT",          "Unknown"),
        "vid":        device.get("ID_VENDOR_ID",             "Unknown"),
        "pid":        device.get("ID_MODEL_ID",              "Unknown"),
        "subsystem":  device.properties.get("SUBSYSTEM"),
        "usb_class":  device.get("ID_USB_CLASS_FROM_DATABASE","Unknown"),
        "usb_driver": device.get("ID_USB_DRIVER",            "Unknown"),
    }

def structural_rules(descriptor):
    risk, flags = 0, []
    if descriptor["serial"] == "Unknown":
        risk += 1
        flags.append("Missing serial number")
    return risk, flags


def usb_device_has_storage(device):
    """True if this USB device exposes a storage partition."""
    context = pyudev.Context()
    for block_device in context.list_devices(subsystem="block"):
        if block_device.device_type == "partition":
            parent = block_device.find_parent("usb", "usb_device")
            if parent and parent.device_path == device.device_path:
                return True
    return False


def print_whitelisted_hid_report(usb_info, vid_pid):
    print("\n" + "━" * 60)
    print(Colors.BOLD + Colors.GREEN + "        WHITELISTED HID DEVICE — TRUSTED        " + Colors.END)
    print("━" * 60)
    print(f" Time           : {datetime.now()}")
    print(f" Device         : {HID_WHITELIST[vid_pid]}")
    print(f" VID:PID        : {vid_pid}")
    print(f" Vendor         : {usb_info['vendor']}")
    print(f" Model          : {usb_info['model']}")
    print(f"\n✓ Device is WHITELISTED — no storage to scan, will not be blocked")
    print("━" * 60 + "\n")
    print(Colors.GREEN + "[✓] Device analysis complete. Ready for next device..." + Colors.END)

def generate_pdf_report(usb_info, base_risk, storage_risk, hid_risk, total_risk, malware_detected, flags, sanitized=False):
    if FPDF is None:
        print(Colors.YELLOW +
              "[!] PDF skipped — install dependencies: .venv/bin/pip install -r requirements.txt" +
              Colors.END)
        return
    try:
        pdf_dir = os.path.join(os.path.dirname(__file__), "reports")
        os.makedirs(pdf_dir, mode=0o755, exist_ok=True)
            
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{usb_info['vid']}_{usb_info['pid']}_{timestamp_str}.pdf"
        filepath = os.path.join(pdf_dir, filename)
        
        pdf = FPDF()
        pdf.add_page()
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            
            # 1. Header Banner
            pdf.set_fill_color(41, 128, 185) # Blue header
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", 'B', 18)
            pdf.cell(0, 15, " USB Security Scan Report ", 0, 1, 'C', fill=True)
            pdf.ln(5)
            
            # 2. Threat Level Banner
            level_str = "CLEAN"
            fill_r, fill_g, fill_b = 39, 174, 96 # Green
            if sanitized:
                level_str = "HIGH RISK - DEVICE SANITIZED (ALLOWED)"
                fill_r, fill_g, fill_b = 241, 196, 15 # Yellow/Orange
            elif malware_detected or total_risk >= 15:
                level_str = "HIGH RISK - DEVICE BLOCKED"
                fill_r, fill_g, fill_b = 192, 57, 43 # Red
            elif total_risk >= 8:
                level_str = "MEDIUM RISK - DEVICE BLOCKED"
                fill_r, fill_g, fill_b = 211, 84, 0 # Orange/Yellow
            elif total_risk > 0:
                level_str = "LOW RISK"
                fill_r, fill_g, fill_b = 243, 156, 18 # Yellow
            
            pdf.set_fill_color(fill_r, fill_g, fill_b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", 'B', 14)
            pdf.cell(0, 12, f" Overall Threat Level: {level_str} ", 0, 1, 'C', fill=True)
            pdf.ln(10)
            
            # Restore colors for text
            pdf.set_text_color(0, 0, 0)
            
            # 3. Summary Paragraph
            pdf.set_font("Helvetica", '', 11)
            pdf.multi_cell(0, 6, f"This report was automatically generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}. "
                                 "It summarizes the hardware, storage, and behavioral analysis of the connected USB device. "
                                 f"The device achieved a total risk score of {total_risk}. Scores above 7 indicate malicious behavior that triggers automatic blocking.")
            pdf.ln(8)
            
            # 4. Device Information Table
            pdf.set_fill_color(236, 240, 241) # Light gray for headers
            pdf.set_font("Helvetica", 'B', 12)
            pdf.cell(0, 8, " Device Identity", border="B", ln=1)
            pdf.ln(2)
            
            col1 = 50
            col2 = 140
            
            info_rows = [
                ("Vendor / Model", f"{usb_info['vendor']} / {usb_info['model']}"),
                ("Hardware ID (VID:PID)", f"{usb_info['vid']}:{usb_info['pid']}"),
                ("Serial Number", usb_info['serial']),
                ("USB Class", usb_info['usb_class'])
            ]
            
            for label, val in info_rows:
                pdf.set_font("Helvetica", 'B', 10)
                pdf.cell(col1, 8, label, border=0)
                pdf.set_font("Helvetica", '', 10)
                pdf.cell(col2, 8, val, border=0, ln=1)
                
            pdf.ln(6)
            
            # 5. Risk Breakdown
            pdf.set_font("Helvetica", 'B', 12)
            pdf.cell(0, 8, " Risk Score Breakdown", border="B", ln=1)
            pdf.ln(2)
            
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(col1, 8, "Hardware Anomalies:")
            pdf.set_font("Helvetica", '', 10)
            pdf.cell(col2, 8, str(base_risk), ln=1)
            
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(col1, 8, "Storage / Filesystem:")
            pdf.set_font("Helvetica", '', 10)
            pdf.cell(col2, 8, str(storage_risk), ln=1)
            
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(col1, 8, "HID / Keystroke Injection:")
            pdf.set_font("Helvetica", '', 10)
            pdf.cell(col2, 8, str(hid_risk), ln=1)
            
            pdf.ln(2)
            pdf.set_draw_color(0, 0, 0)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(2)
            
            pdf.set_font("Helvetica", 'B', 11)
            pdf.cell(col1, 8, "Total Risk Score:")
            pdf.set_font("Helvetica", 'B', 11)
            pdf.cell(col2, 8, str(total_risk), ln=1)
            
            if sanitized:
                pdf.ln(4)
                pdf.set_fill_color(255, 243, 205)
                pdf.set_text_color(133, 100, 4)
                pdf.set_font("Helvetica", 'B', 10)
                pdf.multi_cell(0, 8, "[SANITIZED] Malicious files were deleted by user. Drive was allowed after cleanup.", border=1, align='C', fill=True)
                pdf.set_text_color(0, 0, 0)
            
            pdf.ln(6)
            
            # 6. Malware Warning if applicable
            if malware_detected:
                pdf.set_fill_color(255, 235, 238) # Light red
                pdf.set_text_color(192, 57, 43)
                pdf.set_font("Helvetica", 'B', 12)
                pdf.multi_cell(0, 10, "[!] MALWARE OR MALICIOUS SCRIPTS DETECTED ON DEVICE", border=1, align='C', fill=True)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(6)
            
            # 7. Detailed Findings
            pdf.set_font("Helvetica", 'B', 12)
            pdf.cell(0, 8, " Detailed Findings & Flags", border="B", ln=1)
            pdf.ln(4)
            
            pdf.set_font("Helvetica", '', 10)
            if not flags and not malware_detected:
                pdf.cell(0, 8, "No anomalies or malicious indicators were found on this device.", ln=1)
            else:
                for f in flags:
                    pdf.set_font("Helvetica", 'B', 10)
                    pdf.cell(5, 6, "-")
                    pdf.set_font("Helvetica", '', 10)
                    pdf.multi_cell(0, 6, f)
            
            pdf.ln(15)
            # Footer
            pdf.set_text_color(127, 140, 141)
            pdf.set_font("Helvetica", 'I', 9)
            pdf.cell(0, 10, "End of automated security report.", 0, 1, 'C')
        
        pdf.output(filepath)
        print(Colors.GREEN + f"[+] PDF Report Generated: {filepath}" + Colors.END)
    except Exception as e:
        print(Colors.RED + f"[!] Failed to generate PDF: {e}" + Colors.END)

def handle_usb_device(device):
    try:
        usb_info = analyze_descriptors(device)
        vid_pid = format_vid_pid(usb_info["vid"], usb_info["pid"])

        # Whitelisted keyboard/mouse — skip full report (check before 3s wait)
        if vid_pid in HID_WHITELIST and not usb_device_has_storage(device):
            print(Colors.CYAN + f"\n[ EVENT ] Whitelisted device connected: {HID_WHITELIST[vid_pid]}" + Colors.END)
            print_whitelisted_hid_report(usb_info, vid_pid)
            return

        print(Colors.CYAN + "\n[ EVENT ] USB Device Detected - Analyzing..." + Colors.END)
        time.sleep(3)

        # ── Phase 1: Hardware / HID analysis ──────────────────────────────────
        base_risk, flags = structural_rules(usb_info)
        hid_data = HID_RISK_CACHE.get(vid_pid, {"risk": 0, "flags": []})
        hid_risk = hid_data["risk"]
        flags.extend(hid_data["flags"])
        
        # ── Phase 2: Storage scan ─────────────────────────────────────────────
        storage_risk = 0
        malware_detected = False
        has_storage = False
        scanned_paths = []
        scanned_storage = []
        all_malicious_files = []
        antivirus_available = _clamav_command() is not None

        # Retry partition detection — kernel may need extra time to register block devices
        for attempt in range(5):
            context = pyudev.Context()
            for block_device in context.list_devices(subsystem="block"):
                # A block device is mountable if it has a filesystem. This catches both normal partitions
                # (/dev/sda1) and superfloppy formatted drives that have the filesystem directly on the disk (/dev/sda).
                is_mountable = block_device.get("ID_FS_USAGE") == "filesystem"
                if is_mountable or block_device.device_type == "partition":
                    parent = block_device.find_parent("usb", "usb_device")
                    if parent and parent.device_path == device.device_path:
                        has_storage = True
                        if not antivirus_available:
                            storage_risk += 5
                            flags.append("ClamAV unavailable; storage cannot be accepted as safe")
                        print(Colors.CYAN + f"[*] Found partition: {block_device.device_node}" + Colors.END)
                        mount, quarantine_mount = mount_for_quarantine_scan(block_device.device_node)
                        if mount:
                            print(f"[+] Scanning from {mount}")
                            scanned_paths.append(mount)
                            scanned_storage.append({
                                "device_node": block_device.device_node,
                                "mount_path": mount,
                                "quarantine_mount": quarantine_mount,
                                "safe": False,
                            })
                            pr, pm, pbad = scan_storage(mount, usb_info)
                            storage_risk += pr
                            if pm:
                                malware_detected = True
                                all_malicious_files.extend(pbad)
                        else:
                            storage_risk += 15
                            flags.append(f"Could not mount {block_device.device_node} for safety scan (blocked by default)")
                            print(Colors.RED + f"[!] Could not mount {block_device.device_node} for safety scan" + Colors.END)
            if has_storage:
                break
            if attempt < 4:
                print(Colors.YELLOW + f"[*] Waiting for partitions to appear... (attempt {attempt + 2}/5)" + Colors.END)
                time.sleep(2)

        if not has_storage and is_mtp_or_ptp_device(device):
            has_storage = True
            flags.append("Mobile phone detected through MTP/PTP")
            if not antivirus_available:
                storage_risk += 5
                flags.append("ClamAV unavailable; phone storage cannot be accepted as safe")
            print(Colors.CYAN + "[*] Mobile phone storage mode detected (MTP/PTP)" + Colors.END)
            print(Colors.CYAN + "[*] Waiting for phone file-transfer mount..." + Colors.END)
            mtp_mounts = wait_for_mtp_mount(device)
            if mtp_mounts:
                for mount in mtp_mounts:
                    print(f"[+] Phone storage accessible at {mount}")
                    scanned_paths.append(mount)
                    pr, pm, pbad = scan_storage(mount, usb_info)
                    storage_risk += pr
                    if pm:
                        malware_detected = True
                        all_malicious_files.extend(pbad)
            else:
                storage_risk += 15
                flags.append("MTP/PTP phone detected but no accessible file-transfer mount found (blocked by default)")
                print(Colors.YELLOW +
                      "[!] Phone detected, but files are not accessible. Unlock the phone and select File Transfer/MTP." +
                      Colors.END)

        if not has_storage:
            flags.append("No block storage or MTP/PTP file-transfer interface found")

        # ── Phase 3: Save ORIGINAL scan results (before any user intervention) ──
        original_storage_risk = storage_risk
        original_malware_detected = malware_detected
        original_total_risk = base_risk + storage_risk + hid_risk

        # ── Phase 4: Sanitization prompt ──────────────────────────────────────
        sanitized = False
        if malware_detected and all_malicious_files:
            print("\n" + "=" * 60)
            print(Colors.RED + Colors.BOLD + "  [!] MALICIOUS FILES DETECTED ON THIS DRIVE" + Colors.END)
            print("=" * 60)
            print(Colors.YELLOW + f"  Found {len(all_malicious_files)} dangerous file(s):" + Colors.END)
            for i, f in enumerate(all_malicious_files, 1):
                print(Colors.RED + f"    {i}. {f}" + Colors.END)
            print()
            print(Colors.CYAN + "  You have two options:" + Colors.END)
            print("    [y] DELETE the malicious files and allow access to the rest of the drive")
            print("    [n] BLOCK the entire drive (no access)")
            print()
            user_input = input(Colors.YELLOW + Colors.BOLD + "  Do you want to sanitize this drive? (y/n): " + Colors.END).strip().lower()

            if user_input == 'y':
                print()
                
                # The drive was mounted read-only for safety during the scan.
                # We must temporarily remount it as read-write to delete the viruses.
                for item in scanned_storage:
                    if item["quarantine_mount"]:
                        try:
                            subprocess.run(["mount", "-o", "remount,rw", item["mount_path"]], capture_output=True)
                        except Exception:
                            pass

                all_deleted = True
                for f in all_malicious_files:
                    try:
                        os.remove(f)
                        print(Colors.GREEN + f"  [OK] Deleted: {f}" + Colors.END)
                    except Exception as e:
                        print(Colors.RED + f"  [FAIL] Could not delete {f}: {e}" + Colors.END)
                        all_deleted = False
                
                if all_deleted:
                    malware_detected = False
                    storage_risk = 0
                    sanitized = True
                    flags.append(f"REMEDIATION: {len(all_malicious_files)} malicious file(s) were deleted by user")
                    print(Colors.GREEN + Colors.BOLD + "\n  [OK] All malicious files removed. Drive is now safe to use." + Colors.END)
                else:
                    flags.append("REMEDIATION FAILED: Some malicious files could not be deleted")
                    print(Colors.RED + "\n  [!] Some files could not be removed. Drive will remain BLOCKED." + Colors.END)
            else:
                flags.append("User declined sanitization; drive blocked")
                print(Colors.RED + "\n  [!] User declined. Drive will remain BLOCKED." + Colors.END)
            print("=" * 60)

        # ── Phase 5: Final risk calculation (post-sanitization) ───────────────
        total_risk = base_risk + storage_risk + hid_risk

        # ── Phase 6: Terminal Report ──────────────────────────────────────────
        print("\n" + "=" * 60)
        print(Colors.BOLD + Colors.CYAN + "        COMPLETE USB DEVICE SECURITY REPORT        " + Colors.END)
        print("=" * 60)
        print(f"  Time           : {datetime.now()}")
        print(f"  Vendor         : {usb_info['vendor']}")
        print(f"  Model          : {usb_info['model']}")
        print(f"  VID:PID        : {vid_pid}")
        print(f"  Serial         : {usb_info['serial']}")
        print(f"  USB Class      : {usb_info['usb_class']}")
        print(f"  USB Driver     : {usb_info['usb_driver']}")
        print("-" * 60)
        print(f"  Hardware Risk  : {base_risk}")
        print(f"  Storage Risk   : {original_storage_risk}" + (f" -> 0 (sanitized)" if sanitized else ""))
        print(f"  HID Risk       : {hid_risk}")
        if sanitized:
            print(f"  Original Total : {original_total_risk}")
            print(f"  Final Total    : {total_risk} (after sanitization)")
        else:
            print(f"  Total Risk     : {total_risk}")
        print(f"  Threat Level   : {threat_level(total_risk)}")
        if sanitized:
            print(Colors.GREEN + Colors.BOLD + "  Status         : SANITIZED - Drive cleaned and allowed" + Colors.END)
        elif malware_detected:
            print(Colors.RED + Colors.BOLD + "  Status         : BLOCKED - Malware detected" + Colors.END)
        if scanned_paths:
            print(f"\n  Scanned Paths:")
            for path in scanned_paths:
                print(f"    - {path}")
        if vid_pid in HID_WHITELIST:
            print(f"\n  HID Whitelist  : {HID_WHITELIST[vid_pid]}")
        if flags:
            print(f"\n  Flags / Findings:")
            for f in flags:
                print(f"    - {f}")
        print("=" * 60 + "\n")
        
        # ── Phase 7: Generate PDF Report ──────────────────────────────────────
        # The PDF must reflect the ORIGINAL scan findings, not the post-sanitization state.
        # We pass both original and sanitized values so the PDF is accurate.
        generate_pdf_report(
            usb_info,
            base_risk,
            original_storage_risk,
            hid_risk,
            original_total_risk,
            original_malware_detected,
            flags,
            sanitized=sanitized,
        )
        
        # ── Phase 8: Device access decision ───────────────────────────────────
        # A sanitized device is safe. A clean-scanned device is safe.
        # Everything else stays blocked.
        safe_to_use = sanitized or (bool(scanned_paths) and not malware_detected and storage_risk == 0)
        if safe_to_use:
            if sanitized:
                print(Colors.GREEN + "[*] Device SANITIZED. Accepting device for user access..." + Colors.END)
            else:
                print(Colors.GREEN + "[*] Device is CLEAN. Accepting device for user access..." + Colors.END)
            if base_risk > 0:
                print(Colors.YELLOW + f"[*] Hardware warning kept for report only; storage scan is clean. Hardware risk: {base_risk}" + Colors.END)
            for item in scanned_storage:
                release_storage_for_use(
                    item["device_node"],
                    item["mount_path"],
                    item["quarantine_mount"],
                )
            usb_port = _sysfs_port_from_vid_pid(usb_info['vid'], usb_info['pid'])
            if usb_port:
                authorize_usb_device(usb_port)
            else:
                print(Colors.YELLOW + "[!] Could not determine sysfs port to authorize." + Colors.END)
        else:
            reason_parts = []
            if malware_detected:
                reason_parts.append("malware found on device")
            if storage_risk > 0:
                reason_parts.append(f"storage risk score = {storage_risk}")
            if not scanned_paths:
                reason_parts.append("no partitions could be scanned")
            reason_str = ", ".join(reason_parts) if reason_parts else "unknown"
            print(Colors.RED + f"[!] Device is NOT SAFE. Keeping storage unavailable." + Colors.END)
            print(Colors.RED + f"    Reason: {reason_str}" + Colors.END)
            for item in scanned_storage:
                keep_storage_blocked(
                    item["device_node"],
                    item["mount_path"],
                    item["quarantine_mount"],
                )
            usb_port = _sysfs_port_from_vid_pid(usb_info['vid'], usb_info['pid'])
            if usb_port:
                deauthorize_usb_device(usb_port)

        print(Colors.GREEN + "[OK] Device analysis complete. Ready for next device..." + Colors.END)
    except Exception as e:
        print(Colors.RED + f"\n[!] Error handling USB device: {e}" + Colors.END)


def monitor_usb():
    print(Colors.CYAN + Colors.BOLD + "\n[*] Intelligent USB Security Engine Started" + Colors.END)
    print(Colors.GREEN + "[*] Monitoring for USB devices... (Press Ctrl+C to stop)\n" + Colors.END)
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="usb")
    monitor.start()
    processed_devices = set()
    try:
        for device in iter(monitor.poll, None):
            if device.action == "add" and device.get("DEVTYPE") == "usb_device":
                device_id = (f"{device.get('ID_VENDOR_ID')}:{device.get('ID_MODEL_ID')}"
                             f":{device.get('ID_SERIAL_SHORT', '')}")
                if device_id in processed_devices:
                    continue
                processed_devices.add(device_id)
                t = threading.Thread(target=handle_usb_device, args=(device,), daemon=True)
                t.start()
                if len(processed_devices) > 100:
                    processed_devices.clear()
    except KeyboardInterrupt:
        print("\n" + Colors.YELLOW + "[!] Stopping USB Security Engine..." + Colors.END)
        print(Colors.GREEN + "[✓] Shutdown complete. Goodbye.\n" + Colors.END)

# ==========================================
# /proc/bus/input/devices PARSER
# Keyed by eventX — unique per interface.
# ==========================================
def _parse_proc_input(filter_event=None):
    """
    Parse /proc/bus/input/devices.
    If filter_event is given (e.g. 'event5'), return only that entry or None.
    Otherwise return a dict of all USB HID entries keyed by eventX.
    Filters out non-USB buses.
    """
    results = {}
    try:
        with open("/proc/bus/input/devices") as f:
            content = f.read()
        for entry in content.split("\n\n"):
            if not entry.strip():
                continue
            info = {}
            for line in entry.strip().split("\n"):
                if line.startswith("I:"):
                    m = re.search(r"Bus=(\w+)\s+Vendor=([0-9a-f]+)\s+Product=([0-9a-f]+)", line)
                    if m:
                        info["bus"]        = m.group(1)
                        info["vendor_id"]  = m.group(2)
                        info["product_id"] = m.group(3)
                elif line.startswith("N:"):
                    m = re.search(r'Name="([^"]*)"', line)
                    if m:
                        info["name"] = m.group(1)
                elif line.startswith("P:"):
                    m = re.search(r"Phys=(\S+)", line)
                    if m:
                        info["phys"] = m.group(1)
                elif line.startswith("U:"):
                    m = re.search(r"Uniq=(\S+)", line)
                    if m:
                        info["uniq"] = m.group(1)
                elif line.startswith("H:"):
                    m = re.search(r"Handlers=(.+)", line)
                    if m:
                        parts = m.group(1).split()
                        info["handlers"]        = [h for h in parts if h.startswith("event")]
                        info["has_kbd_handler"] = "kbd" in parts
                elif line.startswith("B:"):
                    if "KEY=" in line:
                        info["has_key"] = True
                    if "BTN=" in line and not line.endswith("BTN="):
                        info["has_btn"] = True
                    if "REL=" in line and not line.endswith("REL="):
                        info["has_rel"] = True
                    if "ABS=" in line and not line.endswith("ABS="):
                        info["has_abs"] = True

            # Must be USB bus
            if info.get("bus") != USB_BUS_TYPE:
                continue
            handlers = info.get("handlers", [])
            if not handlers:
                continue
            if "vendor_id" not in info:
                continue

            info["device_id"] = f"{info['vendor_id']}:{info['product_id']}"
            key = handlers[0]

            if filter_event:
                if filter_event in handlers:
                    return info   # return single entry directly
            else:
                results[key] = info

    except Exception as e:
        print(f"[!] Error parsing /proc/bus/input/devices: {e}")

    return None if filter_event else results

# ==========================================
# HID RISK SCORING
# ==========================================
def has_serial(device_info):
    phys = device_info.get("phys", "")
    try:
        m = re.search(r"usb-(.+?)/", phys)
        if m:
            serial_path = f"/sys/bus/usb/devices/{m.group(1)}/serial"
            if os.path.exists(serial_path):
                with open(serial_path) as f:
                    return len(f.read().strip()) > 0
    except Exception:
        pass
    return False

def calculate_hid_risk(device_info, event_key):
    risk, flags = 0, []
    vid_pid = device_info.get("device_id", event_key)

    if vid_pid not in HID_WHITELIST:
        risk += 5
        flags.append("Unknown vendor/product ID (not in whitelist)")

    if not has_serial(device_info):
        risk += 3
        flags.append("Missing or empty serial number")

    if device_info.get("has_key") and (device_info.get("has_btn") or device_info.get("has_rel")):
        risk += 7
        flags.append("Composite HID (keyboard + mouse in one interface)")

    handlers = device_info.get("handlers", [])
    if len(handlers) > 1:
        risk += 4
        flags.append(f"Multiple event handlers: {handlers}")

    name = device_info.get("name", "").lower()
    if name in {"usb keyboard", "usb mouse", "usb input device", "keyboard",
                "hid keyboard", "hid mouse", "generic keyboard"}:
        risk += 3
        flags.append("Generic device name (common HID spoof)")

    if device_info.get("has_kbd_handler"):
        risk += 6
        flags.append("Keyboard handler (kbd) — keystroke injection capable")

    return risk, flags

# ==========================================
# SYSFS / UNBIND HELPERS
# ==========================================
def authorize_usb_device(usb_port):
    """
    Explicitly allow the OS to load drivers.
    Requires the udev default-deny rule to be active.
    """
    if not usb_port: return False
    try:
        auth_path = f"/sys/bus/usb/devices/{usb_port}/authorized"
        if os.path.exists(auth_path):
            with open(auth_path, "w") as f:
                f.write("1")
            print(Colors.GREEN + f"  [✓] Authorized USB port {usb_port} for use." + Colors.END)
            return True
    except PermissionError:
        print(Colors.RED + "  [!] Permission denied. Must run scanner as root/sudo to authorize USBs." + Colors.END)
    except Exception as e:
        print(Colors.YELLOW + f"  [!] Failed to authorize {usb_port}: {e}" + Colors.END)
    return False


def deauthorize_usb_device(usb_port):
    """Deny a USB device after an unsafe verdict, when sysfs authorization is available."""
    if not usb_port:
        return False
    try:
        auth_path = f"/sys/bus/usb/devices/{usb_port}/authorized"
        if os.path.exists(auth_path):
            with open(auth_path, "w") as f:
                f.write("0")
            print(Colors.RED + f"  [✓] Deauthorized USB port {usb_port}; device blocked." + Colors.END)
            return True
    except PermissionError:
        print(Colors.RED + "  [!] Permission denied. Run with sudo to deauthorize unsafe USBs." + Colors.END)
    except Exception as e:
        print(Colors.YELLOW + f"  [!] Failed to deauthorize {usb_port}: {e}" + Colors.END)
    return False

def _sysfs_port_from_phys(phys):
    """Return the USB device port (e.g. '1-1.4') from a phys string."""
    if not phys:
        return None
    phys_prefix = phys.split("/")[0]
    try:
        base = "/sys/bus/usb/devices"
        for dev_entry in os.listdir(base):
            if ":" in dev_entry:
                continue
            dev_path = os.path.join(base, dev_entry)
            try:
                for iface in os.listdir(dev_path):
                    input_path = os.path.join(dev_path, iface, "input")
                    if not os.path.isdir(input_path):
                        continue
                    for input_dev in os.listdir(input_path):
                        phys_file = os.path.join(input_path, input_dev, "phys")
                        if not os.path.exists(phys_file):
                            continue
                        try:
                            with open(phys_file) as pf:
                                if pf.read().strip().startswith(phys_prefix):
                                    return dev_entry
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception:
        pass
    return None

def _sysfs_port_from_vid_pid(vendor_id, product_id):
    try:
        base = "/sys/bus/usb/devices"
        for entry in os.listdir(base):
            if ":" in entry:
                continue
            vp = os.path.join(base, entry, "idVendor")
            pp = os.path.join(base, entry, "idProduct")
            if os.path.exists(vp) and os.path.exists(pp):
                with open(vp) as fv, open(pp) as fp:
                    if fv.read().strip() == vendor_id and fp.read().strip() == product_id:
                        return entry
    except Exception:
        pass
    return None

def _unbind_usbhid(usb_port):
    unbind_path = "/sys/bus/usb/drivers/usbhid/unbind"
    base = "/sys/bus/usb/devices"
    unbound = 0
    try:
        for entry in os.listdir(base):
            if not entry.startswith(usb_port + ":"):
                continue
            driver_link = os.path.join(base, entry, "driver")
            if os.path.islink(driver_link) and \
               os.path.basename(os.readlink(driver_link)) == "usbhid":
                try:
                    with open(unbind_path, "w") as f:
                        f.write(entry)
                    print(Colors.RED + f"  [✓] Unbound {entry} from usbhid" + Colors.END)
                    unbound += 1
                except Exception as e:
                    print(Colors.YELLOW + f"  [!] Unbind failed for {entry}: {e}" + Colors.END)
    except Exception as e:
        print(Colors.YELLOW + f"  [!] sysfs unbind error: {e}" + Colors.END)
    return unbound

# ==========================================
# EVIOCREVOKE  (_IOW('E', 0x91, int))
# ==========================================
EVIOCREVOKE = 0x40044591

def _revoke_event_node(event_path):
    try:
        fd = os.open(event_path, os.O_RDWR | os.O_NONBLOCK)
        try:
            fcntl.ioctl(fd, EVIOCREVOKE, 0)
            return True
        finally:
            os.close(fd)
    except PermissionError:
        return None
    except Exception:
        return False

# ==========================================
# HID BLOCKING ENGINE
# ==========================================
def block_hid_device(device_info, event_key):
    handlers   = device_info.get("handlers", [])
    vendor_id  = device_info.get("vendor_id", "")
    product_id = device_info.get("product_id", "")
    phys       = device_info.get("phys", "")

    print(Colors.RED + Colors.BOLD + "\n[BLOCKING] Disabling HID device NOW..." + Colors.END)
    any_success = False
    need_root   = False

    # Method 1: EVIOCREVOKE (instant)
    print(Colors.YELLOW + "  [→] Method 1: EVIOCREVOKE ioctl..." + Colors.END)
    for handler in handlers:
        ep = f"/dev/input/{handler}"
        if not os.path.exists(ep):
            continue
        r = _revoke_event_node(ep)
        if r is True:
            print(Colors.RED + f"  [✓] REVOKED {ep} — kernel stopped all input" + Colors.END)
            any_success = True
        elif r is None:
            print(Colors.YELLOW + f"  [!] {ep}: need root" + Colors.END)
            need_root = True
        else:
            print(Colors.YELLOW + f"  [!] {ep}: EVIOCREVOKE failed" + Colors.END)

    # Method 2: usbhid driver unbind
    print(Colors.YELLOW + "  [→] Method 2: usbhid driver unbind..." + Colors.END)
    usb_port = _sysfs_port_from_phys(phys) if phys else None
    if usb_port:
        print(f"  [*] sysfs port (phys): {usb_port}")
    else:
        usb_port = _sysfs_port_from_vid_pid(vendor_id, product_id)
        if usb_port:
            print(f"  [*] sysfs port (VID:PID): {usb_port}")
    if usb_port:
        n = _unbind_usbhid(usb_port)
        if n > 0:
            any_success = True
        else:
            print(Colors.YELLOW + f"  [!] No usbhid interfaces found under {usb_port}" + Colors.END)
    else:
        print(Colors.YELLOW + "  [!] Could not determine sysfs port — skipping unbind" + Colors.END)

    # Method 3: chmod 000
    print(Colors.YELLOW + "  [→] Method 3: Revoking event node permissions..." + Colors.END)
    for handler in handlers:
        ep = f"/dev/input/{handler}"
        if not os.path.exists(ep):
            continue
        try:
            os.chmod(ep, 0o000)
            print(Colors.RED + f"  [✓] chmod 000 on {ep}" + Colors.END)
            any_success = True
        except PermissionError:
            print(Colors.YELLOW + f"  [!] chmod {ep}: need root" + Colors.END)
            need_root = True
        except Exception as e:
            print(Colors.YELLOW + f"  [!] chmod error: {e}" + Colors.END)

    print()
    if any_success:
        print(Colors.RED + Colors.BOLD + "★ HID DEVICE BLOCKED — keystrokes suppressed ★\n" + Colors.END)
    elif need_root:
        print(Colors.RED + Colors.BOLD + "✗ NEED ROOT — run: sudo python3 usb_hid_scanner.py\n" + Colors.END)
    else:
        print(Colors.RED + Colors.BOLD + "✗ BLOCKING FAILED (device may already be gone)\n" + Colors.END)
    return any_success

# ==========================================
# KEYSTROKE INJECTION DETECTOR
# ==========================================
def detect_keystroke_injection(event_path, timeout=0.5):
    try:
        if not os.path.exists(event_path):
            return False
        with open(event_path, "rb") as f:
            start = time.time()
            times = []
            while (time.time() - start) < timeout:
                data = f.read(16)
                if len(data) < 16:
                    break
                ev_type = int.from_bytes(data[8:10], "little")
                if ev_type == 1:
                    now = time.time()
                    times.append(now)
                    if len(times) >= 2 and 0 < (times[-1] - times[-2]) * 1000 < 10:
                        return True
        return False
    except PermissionError:
        return None
    except Exception:
        return False

# ==========================================
# PROCESS CORRELATION
# ==========================================
ATTACK_CMDS = ["wget", "curl", "nc", "ncat", "nmap", "xterm",
               "gnome-terminal", "konsole", "terminator",
               "perl", "ruby", "php", "powershell"]

def check_suspicious_processes(since_time, timeout=2):
    suspicious = []
    if time.time() - since_time > timeout:
        return suspicious
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().decode("utf-8", errors="ignore").replace("\x00", " ").strip()
                for ac in ATTACK_CMDS:
                    if ac in cmd:
                        suspicious.append({"pid": pid, "cmdline": cmd[:100], "type": ac})
                        break
            except Exception:
                pass
    except Exception:
        pass
    return suspicious

# ==========================================
# HID MONITOR — pyudev kernel event driven
#
# WHY pyudev INSTEAD OF POLLING:
# The old approach polled /proc/bus/input/devices every 100ms. P4wnP1 and
# similar attack tools connect, inject a full payload, and disconnect in
# under one second. The poll loop simply never caught the device — it was
# already gone before the next poll ran.
#
# Now we subscribe directly to kernel uevents on the 'input' subsystem via
# pyudev. The moment the kernel registers a new /dev/input/eventX node we
# receive the callback in milliseconds — no polling delay at all. We then
# immediately fast-block any keyboard interface that isn't whitelisted,
# BEFORE doing any further scoring or analysis.
# ==========================================
def _process_hid_event(event_name, seen_events):
    """Analyse and optionally block a newly appeared HID interface."""
    if event_name in seen_events:
        return
    seen_events.add(event_name)

    connection_time = time.time()

    device_info = None
    for delay in (0.05, 0.15, 0.3, 0.5, 1.0):
        time.sleep(delay)
        device_info = _parse_proc_input(filter_event=event_name)
        if device_info is not None:
            break
    if device_info is None:
        print(Colors.YELLOW +
              f"[!] {event_name}: not found in /proc/bus/input/devices "
              f"(non-USB or already disconnected — skipping)" +
              Colors.END)
        return

    vid_pid = device_info.get("device_id", event_name)
    if vid_pid in HID_WHITELIST:
        print(Colors.GREEN + f"\n[ HID ] WHITELISTED device connected: {HID_WHITELIST[vid_pid]} ({vid_pid})" + Colors.END)
        return

    risk_score, flags = calculate_hid_risk(device_info, event_name)

    print(Colors.CYAN + "\n[ HID DEVICE DETECTED ]\n" + Colors.END)
    print(f" Time               : {datetime.now()}")
    print(f" Device ID          : {vid_pid}")
    print(f" Name               : {device_info.get('name', 'Unknown')}")
    print(f" Event Handler      : {event_name}  (all: {device_info.get('handlers', [])})")
    print(f" Bus Type           : USB ({device_info.get('bus', '?')})")
    print(f" Keyboard Interface : "
          f"{'YES ← can inject keystrokes' if device_info.get('has_kbd_handler') else 'No'}")
    print("\n" + "-" * 60)
    print(f" Base Risk Score    : {risk_score}")

    # ── FAST-BLOCK: unknown keyboard interface ────────────────────────────────
    already_blocked = False
    if device_info.get("has_kbd_handler") and vid_pid not in HID_WHITELIST:
        print(Colors.RED + Colors.BOLD +
              "\n⚡ UNKNOWN KEYBOARD INTERFACE — BLOCKING NOW ⚡" + Colors.END)
        block_hid_device(device_info, event_name)
        already_blocked = True

    # ── Injection timing check ────────────────────────────────────────────────
    injection_risk = 0
    handlers = device_info.get("handlers", [])
    if handlers and not already_blocked:
        r = detect_keystroke_injection(f"/dev/input/{handlers[0]}", timeout=0.5)
        if r is True:
            injection_risk = 8
            print(f" Keystroke Pattern  : DETECTED (+8 risk)")
        elif r is None:
            print(f" Keystroke Pattern  : (requires root)")
        else:
            print(f" Keystroke Pattern  : None detected")
    else:
        print(f" Keystroke Pattern  : N/A (device blocked before check)")

    # ── Process correlation ───────────────────────────────────────────────────
    process_risk = 0
    sprocs = check_suspicious_processes(connection_time, timeout=2)
    if sprocs:
        process_risk = 5
        print(f" Suspicious Process : YES (+5 risk)")
        for p in sprocs[:3]:
            print(f"   - PID {p['pid']}: {p['cmdline'][:60]}")
    else:
        print(f" Suspicious Process : None")

    # ── Final score ───────────────────────────────────────────────────────────
    total_risk = risk_score + injection_risk + process_risk
    
    if vid_pid not in HID_RISK_CACHE:
        HID_RISK_CACHE[vid_pid] = {"risk": 0, "flags": []}
    HID_RISK_CACHE[vid_pid]["risk"] += total_risk
    HID_RISK_CACHE[vid_pid]["flags"].extend(flags)
    if injection_risk > 0:
        HID_RISK_CACHE[vid_pid]["flags"].append("Keystroke injection pattern detected")
    if process_risk > 0:
        HID_RISK_CACHE[vid_pid]["flags"].append("Suspicious process correlation detected")

    print(f" Total Risk Score   : {total_risk}")
    print(f" Threat Level       : {threat_level(total_risk)}")

    if flags:
        print("\n Hardware Flags:")
        for flag in flags:
            print(f"  • {flag}")

    if vid_pid in HID_WHITELIST:
        print(f"\n✓ Device is WHITELISTED: {HID_WHITELIST[vid_pid]}")
    else:
        print(f"\n⚠️  Device is NOT in whitelist")
    print("━" * 60 + "\n")

    # ── Score-based block for non-keyboard high-risk devices ──────────────────
    if not already_blocked and total_risk >= 8:
        label = ("⚠️  HIGH RISK HID DEVICE — BLOCKING ⚠️"
                 if total_risk >= 15 else
                 "⚠️  MEDIUM RISK HID DEVICE — BLOCKING ⚠️")
        print(Colors.RED + Colors.BOLD + label + Colors.END + "\n")
        block_hid_device(device_info, event_name)


def hid_monitor():
    """
    HID monitor driven by pyudev kernel uevents on the 'input' subsystem.
    Reacts the instant the kernel registers a new /dev/input/eventX node.
    """
    print(Colors.CYAN + Colors.BOLD + "\n[*] HID Attack Detection Engine Started" + Colors.END)
    print(Colors.GREEN + "[*] Monitoring for HID devices... (Press Ctrl+C to stop)\n" + Colors.END)

    seen_events = set()

    # Snapshot existing devices so we don't alert on pre-connected hardware
    existing = _parse_proc_input()
    seen_events.update(existing.keys())
    if existing:
        pre = ", ".join(f"{v['device_id']} ({k})" for k, v in existing.items())
        print(Colors.GREEN + f"[*] Pre-existing USB HID devices (ignored): {pre}" +
              Colors.END + "\n")

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="input")
    monitor.start()

    try:
        for udev_device in iter(monitor.poll, None):
            if udev_device.action != "add":
                continue
            dev_node = udev_device.device_node
            if not dev_node or not dev_node.startswith("/dev/input/event"):
                continue
            event_name = os.path.basename(dev_node)
            t = threading.Thread(
                target=_process_hid_event,
                args=(event_name, seen_events),
                daemon=True
            )
            t.start()

    except KeyboardInterrupt:
        print("\n" + Colors.YELLOW + "[!] Stopping HID Detection Engine..." + Colors.END)
    except Exception as e:
        print(Colors.RED + f"\n[!] HID monitor error: {e}" + Colors.END)


# ==========================================
# MAIN ENTRY POINT
# ==========================================
if __name__ == "__main__":
    db_path = ensure_database()
    print(Colors.GREEN + f"[*] Malware database: {db_path}" + Colors.END)
    print(Colors.GREEN + f"[*] HID whitelist: {len(HID_WHITELIST)} trusted device(s)" + Colors.END)
    if not is_root_user():
        print(Colors.YELLOW +
              "[!] Not running as root. USB storage can be scanned, but accept/block enforcement requires: sudo ./run.sh" +
              Colors.END)
    if FPDF is None:
        print(Colors.YELLOW +
              "[!] fpdf2 not installed — PDF reports disabled. " 
              "Run: .venv/bin/pip install -r requirements.txt" +
              Colors.END)
    hid_thread = threading.Thread(target=hid_monitor, daemon=True)
    hid_thread.start()
    monitor_usb()
