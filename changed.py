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
from datetime import datetime
from fpdf import FPDF

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
HID_WHITELIST = {
    "413c:2113": "Dell KB216 Wired Keyboard",     # corrected PID
    "413c:3020": "Dell KB216 Wired Keyboard (alt)",
    "0461:4d15": "Primax Electronics Keyboard",
    "046d:c534": "Logitech USB Receiver",
    "093a:2510": "PixArt Optical USB Mouse",
    "1c4f:0034": "SIGMACHIP USB Mouse",            # now whitelisted
}

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
DB_NAME = os.path.join(os.path.dirname(__file__), "test_malware.db")

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

def wait_for_mount(device_node, timeout=15):
    for _ in range(timeout):
        time.sleep(1)
        mount = find_mount_point(device_node)
        if mount and os.path.exists(mount):
            return mount
    return None

def scan_file_task(path):
    findings = []
    
    sha = calculate_sha256(path)
    if sha:
        result = check_hash(sha)
        if result:
            findings.append({"issue": f"DB MALWARE DETECTED: {result['signature']}", "risk": 15})
            
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
    return master_risk_score, malware_detected

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

def generate_pdf_report(usb_info, base_risk, storage_risk, total_risk, malware_detected, flags):
    try:
        pdf_dir = os.path.join(os.path.dirname(__file__), "reports")
        if not os.path.exists(pdf_dir):
            os.makedirs(pdf_dir)
            
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{usb_info['vid']}_{usb_info['pid']}_{timestamp_str}.pdf"
        filepath = os.path.join(pdf_dir, filename)
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        
        # Header
        pdf.cell(190, 10, "Intelligent USB Security Engine - Scan Report", 0, 1, 'C')
        pdf.ln(10)
        
        # Device details
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(190, 10, "Device Information", 0, 1, 'L')
        pdf.set_font("Arial", '', 11)
        pdf.cell(50, 8, f"Time: ", 0, 0)
        pdf.cell(140, 8, f"{datetime.now()}", 0, 1)
        pdf.cell(50, 8, f"Vendor/Model: ", 0, 0)
        pdf.cell(140, 8, f"{usb_info['vendor']} / {usb_info['model']}", 0, 1)
        pdf.cell(50, 8, f"VID:PID: ", 0, 0)
        pdf.cell(140, 8, f"{usb_info['vid']}:{usb_info['pid']}", 0, 1)
        pdf.cell(50, 8, f"Serial: ", 0, 0)
        pdf.cell(140, 8, f"{usb_info['serial']}", 0, 1)
        pdf.ln(10)
        
        # Risk scores
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(190, 10, "Security Analysis Results", 0, 1, 'L')
        pdf.set_font("Arial", '', 11)
        pdf.cell(50, 8, "Hardware Risk:", 0, 0)
        pdf.cell(140, 8, str(base_risk), 0, 1)
        pdf.cell(50, 8, "Storage Risk:", 0, 0)
        pdf.cell(140, 8, str(storage_risk), 0, 1)
        pdf.cell(50, 8, "Total Risk Score:", 0, 0)
        pdf.cell(140, 8, str(total_risk), 0, 1)
        
        level_str = "CLEAN"
        if total_risk >= 15: level_str = "HIGH"
        elif total_risk >= 8: level_str = "MEDIUM"
        elif total_risk > 0: level_str = "LOW"
        
        pdf.cell(50, 8, "Threat Level:", 0, 0)
        pdf.cell(140, 8, level_str, 0, 1)
        pdf.ln(10)
        
        if malware_detected:
            pdf.set_font("Arial", 'B', 14)
            pdf.set_text_color(255, 0, 0)
            pdf.cell(190, 10, "WARNING: MALWARE DETECTED ON DEVICE", 0, 1, 'L')
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)
            
        if flags:
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, "Hardware Anomalies / Flags:", 0, 1, 'L')
            pdf.set_font("Arial", '', 11)
            for f in flags:
                pdf.cell(190, 8, f" - {f}", 0, 1, 'L')
                
        # Footer
        pdf.ln(10)
        pdf.set_font("Arial", 'I', 9)
        pdf.cell(190, 10, "End of report.", 0, 1, 'C')
        
        pdf.output(filepath)
        print(Colors.GREEN + f"[+] PDF Report Generated: {filepath}" + Colors.END)
    except Exception as e:
        print(Colors.RED + f"[!] Failed to generate PDF: {e}" + Colors.END)

def handle_usb_device(device):
    try:
        print(Colors.CYAN + "\n[ EVENT ] USB Device Detected - Analyzing..." + Colors.END)
        time.sleep(3)

        usb_info = analyze_descriptors(device)
        base_risk, flags = structural_rules(usb_info)
        storage_risk, malware_detected = 0, False

        context = pyudev.Context()
        for block_device in context.list_devices(subsystem="block"):
            if block_device.device_type == "partition":
                parent = block_device.find_parent("usb", "usb_device")
                if parent and parent.device_path == device.device_path:
                    print(Colors.CYAN + f"[*] Found partition: {block_device.device_node}" + Colors.END)
                    mount = wait_for_mount(block_device.device_node)
                    if mount:
                        print(f"[+] Mounted at {mount}")
                        pr, pm = scan_storage(mount)
                        storage_risk += pr
                        if pm:
                            malware_detected = True
                    else:
                        print(Colors.YELLOW + f"[!] Mount not found for {block_device.device_node}" + Colors.END)

        total_risk = base_risk + storage_risk
        print("\n" + "━" * 60)
        print(Colors.BOLD + Colors.CYAN + "        COMPLETE USB DEVICE SECURITY REPORT        " + Colors.END)
        print("━" * 60)
        print(f" Time           : {datetime.now()}")
        print(f" Vendor         : {usb_info['vendor']}")
        print(f" Model          : {usb_info['model']}")
        print(f" VID:PID        : {usb_info['vid']}:{usb_info['pid']}")
        print(f" Serial         : {usb_info['serial']}")
        print(f" USB Class      : {usb_info['usb_class']}")
        print(f" USB Driver     : {usb_info['usb_driver']}")
        print("\n" + "-" * 60)
        print(f" Hardware Risk  : {base_risk}")
        print(f" Storage Risk   : {storage_risk}")
        print(f" Total Risk     : {total_risk}")
        print(f" Threat Level   : {threat_level(total_risk)}")
        if malware_detected:
            print("\n" + Colors.RED + Colors.BOLD + "⚠️  MALWARE DETECTED ON DEVICE ⚠️" + Colors.END)
        if flags:
            print("\n Hardware Flags:")
            for f in flags:
                print(f"  • {f}")
        print("━" * 60 + "\n")
        
        # Generate the PDF Report
        generate_pdf_report(usb_info, base_risk, storage_risk, total_risk, malware_detected, flags)
        
        print(Colors.GREEN + "[✓] Device analysis complete. Ready for next device..." + Colors.END)
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

    # Give kernel 50ms to finish writing /proc/bus/input/devices
    time.sleep(0.05)

    device_info = _parse_proc_input(filter_event=event_name)
    if device_info is None:
        # Retry once — very fast devices may not be listed yet
        time.sleep(0.1)
        device_info = _parse_proc_input(filter_event=event_name)
    if device_info is None:
        print(Colors.YELLOW +
              f"[!] {event_name}: not found in /proc/bus/input/devices "
              f"(non-USB or already disconnected — skipping)" +
              Colors.END)
        return

    vid_pid = device_info.get("device_id", event_name)
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
    hid_thread = threading.Thread(target=hid_monitor, daemon=True)
    hid_thread.start()
    monitor_usb()
