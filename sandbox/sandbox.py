#!/usr/bin/env python3
"""
Sandbox v1.0.0 — Automated File Analysis Engine
Part of Optimus Suite

Static analysis of suspicious files in an isolated environment.
Receives files, computes hashes, extracts strings, measures entropy,
analyzes PE headers, scans with YARA rules, and generates reports.

Launch: python sandbox.py
Port:   8890 (WebSocket fallback)
"""

import asyncio
import base64
import hashlib
import json
import logging
import math
import mimetypes
import os
import re
import shutil
import struct
import sys
import threading
import time
import uuid

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

from datetime import datetime
from pathlib import Path
from typing import Optional

# ─── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Sandbox")

# ─── Optional imports ───────────────────────────────────────────────────
HAS_WS = False
try:
    import websockets
    HAS_WS = True
except ImportError:
    logger.info("websockets not installed — WebSocket mode unavailable")

HAS_WEBVIEW = False
try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    logger.info("pywebview not installed — native window unavailable")

HAS_YARA = False
try:
    import yara
    HAS_YARA = True
except ImportError:
    logger.info("yara-python not installed — YARA scanning disabled")

HAS_PEFILE = False
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    logger.info("pefile not installed — PE analysis disabled")

HAS_PERMISSIONS = False
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
    from permissions import PermissionManager
    HAS_PERMISSIONS = True
except ImportError:
    PermissionManager = None

HAS_TOAST = False
try:
    from toast_notifications import toast_event, toast_threat
    HAS_TOAST = True
except ImportError:
    pass

# ─── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
SUITE_DIR = BASE_DIR.parent
QUARANTINE_DIR = BASE_DIR / "quarantine"
REPORTS_DIR = BASE_DIR / "reports"
SIGNATURES_DIR = BASE_DIR / "signatures"
DASHBOARD_FILE = BASE_DIR / "sandbox_dashboard.html"

for d in [QUARANTINE_DIR, REPORTS_DIR, SIGNATURES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

VERSION = "1.0.0"
WS_PORT = 8890

# ═══════════════════════════════════════════════════════════════════════
# SUSPICIOUS PATTERN DATABASE
# ═══════════════════════════════════════════════════════════════════════

SUSPICIOUS_PATTERNS = {
    "shell_commands": {
        "weight": 15,
        "mitre": "T1059 — Command and Scripting Interpreter",
        "patterns": [
            b"cmd.exe", b"powershell", b"/bin/sh", b"/bin/bash",
            b"command.com", b"wscript", b"cscript", b"mshta",
        ],
    },
    "process_injection": {
        "weight": 25,
        "mitre": "T1055 — Process Injection",
        "patterns": [
            b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
            b"NtWriteVirtualMemory", b"RtlCreateUserThread",
            b"QueueUserAPC", b"SetWindowsHookEx", b"NtMapViewOfSection",
        ],
    },
    "persistence": {
        "weight": 20,
        "mitre": "T1547 — Boot or Logon Autostart Execution",
        "patterns": [
            b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            b"crontab", b"systemd", b"LaunchAgent", b"LaunchDaemon",
            b"schtasks", b"at.exe", b"TaskScheduler",
        ],
    },
    "network_indicators": {
        "weight": 10,
        "mitre": "T1071 — Application Layer Protocol",
        "patterns": [
            b"URLDownloadToFile", b"InternetOpenUrl", b"HttpSendRequest",
            b"WinHttpOpen", b"socket", b"WSAStartup", b"connect(",
        ],
    },
    "obfuscation": {
        "weight": 15,
        "mitre": "T1027 — Obfuscated Files or Information",
        "patterns": [
            b"base64", b"fromCharCode", b"String.fromCharCode",
            b"eval(", b"exec(", b"atob(", b"btoa(",
            b"charCodeAt", b"unescape(",
        ],
    },
    "crypto_ransomware": {
        "weight": 20,
        "mitre": "T1486 — Data Encrypted for Impact",
        "patterns": [
            b"CryptEncrypt", b"CryptGenKey", b"AES", b"RSA",
            b"encrypt", b"decrypt", b"bitcoin", b".onion",
            b"vssadmin", b"bcdedit", b"wbadmin",
        ],
    },
    "credential_tools": {
        "weight": 25,
        "mitre": "T1003 — OS Credential Dumping",
        "patterns": [
            b"mimikatz", b"lazagne", b"procdump", b"lsass",
            b"sekurlsa", b"SAM database", b"hashdump",
        ],
    },
}

# Known-bad hashes (demo entries)
KNOWN_BAD_HASHES = {
    # EICAR test file SHA256
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    # Additional demo hashes
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

# Script analysis patterns
DANGEROUS_SCRIPT_CALLS = {
    "python": [
        "eval(", "exec(", "subprocess", "os.system(", "os.popen(",
        "__import__", "compile(", "importlib", "pickle.loads",
    ],
    "javascript": [
        "eval(", "Function(", "setTimeout(", "setInterval(",
        "document.write(", "innerHTML", "fromCharCode",
        "ActiveXObject", "WScript.Shell",
    ],
    "powershell": [
        "Invoke-Expression", "IEX(", "Invoke-WebRequest",
        "DownloadString", "DownloadFile", "Start-Process",
        "New-Object Net.WebClient", "-enc ", "-EncodedCommand",
        "Set-ExecutionPolicy", "Bypass",
    ],
    "batch": [
        "del /f", "rmdir /s", "format ", "reg add", "reg delete",
        "net user", "net localgroup", "netsh firewall", "bcdedit",
        "attrib +h", "icacls", "takeown",
    ],
}

SCRIPT_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".vbs": "javascript",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
}

# ═══════════════════════════════════════════════════════════════════════
# FILE RECEIVER
# ═══════════════════════════════════════════════════════════════════════

class FileReceiver:
    """Accepts files via path, base64, or drag-and-drop. Copies to quarantine."""

    def __init__(self):
        self.queue: list[dict] = []
        self._lock = threading.Lock()

    def submit_path(self, file_path: str) -> Optional[dict]:
        """Submit a file by its filesystem path."""
        src = Path(file_path)
        if not src.exists():
            logger.warning(f"File not found: {file_path}")
            return None
        if not src.is_file():
            logger.warning(f"Not a file: {file_path}")
            return None

        file_id = uuid.uuid4().hex[:12]
        dest = QUARANTINE_DIR / f"{file_id}_{src.name}"
        try:
            shutil.copy2(str(src), str(dest))
        except Exception as e:
            logger.error(f"Failed to copy file to quarantine: {e}")
            return None

        entry = {
            "file_id": file_id,
            "original_name": src.name,
            "quarantine_path": str(dest),
            "size": dest.stat().st_size,
            "submitted_at": datetime.now().isoformat(),
            "status": "queued",
        }
        with self._lock:
            self.queue.append(entry)
        logger.info(f"File queued: {src.name} -> {file_id}")
        return entry

    def submit_base64(self, data: str, filename: str) -> Optional[dict]:
        """Submit a file from base64-encoded data."""
        try:
            raw = base64.b64decode(data)
        except Exception as e:
            logger.error(f"Invalid base64 data: {e}")
            return None

        file_id = uuid.uuid4().hex[:12]
        safe_name = re.sub(r'[^\w.\-]', '_', filename)
        dest = QUARANTINE_DIR / f"{file_id}_{safe_name}"
        try:
            dest.write_bytes(raw)
        except Exception as e:
            logger.error(f"Failed to write file: {e}")
            return None

        entry = {
            "file_id": file_id,
            "original_name": filename,
            "quarantine_path": str(dest),
            "size": len(raw),
            "submitted_at": datetime.now().isoformat(),
            "status": "queued",
        }
        with self._lock:
            self.queue.append(entry)
        logger.info(f"Base64 file queued: {filename} -> {file_id}")
        return entry

    def get_queue(self) -> list:
        with self._lock:
            return list(self.queue)

    def update_status(self, file_id: str, status: str):
        with self._lock:
            for item in self.queue:
                if item["file_id"] == file_id:
                    item["status"] = status
                    break


# ═══════════════════════════════════════════════════════════════════════
# HASH CHECKER
# ═══════════════════════════════════════════════════════════════════════

class HashChecker:
    """Computes MD5, SHA1, SHA256 and checks against known-bad databases."""

    @staticmethod
    def compute_hashes(file_path: str) -> dict:
        """Compute all three hash digests for a file."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except Exception as e:
            logger.error(f"Hash computation failed: {e}")
            return {"md5": "", "sha1": "", "sha256": "", "error": str(e)}

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    @staticmethod
    def check_known_bad(sha256_hash: str) -> bool:
        """Check SHA256 against local known-bad hash database."""
        return sha256_hash.lower() in KNOWN_BAD_HASHES

    @staticmethod
    def check_virustotal(sha256_hash: str, api_key: str = "") -> Optional[dict]:
        """Optional VirusTotal API lookup (requires API key)."""
        if not api_key:
            return None
        try:
            import urllib.request
            url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
            req = urllib.request.Request(url, headers={"x-apikey": api_key})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()),
                }
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed: {e}")
            return None


# ═══════════════════════════════════════════════════════════════════════
# STRING EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════

class StringExtractor:
    """Extracts ASCII/Unicode strings and searches for suspicious patterns."""

    MIN_STRING_LEN = 4

    @staticmethod
    def extract_ascii_strings(data: bytes, min_len: int = 4) -> list:
        """Extract printable ASCII strings of minimum length."""
        pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]

    @staticmethod
    def extract_unicode_strings(data: bytes, min_len: int = 4) -> list:
        """Extract UTF-16LE strings (common in Windows binaries)."""
        pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len)
        results = []
        for m in pattern.finditer(data):
            try:
                s = m.group().decode("utf-16-le", errors="ignore")
                if len(s) >= min_len:
                    results.append(s)
            except Exception:
                pass
        return results

    @staticmethod
    def find_suspicious_strings(strings: list) -> dict:
        """Categorize strings by suspicious pattern matches."""
        found = {}
        for category, info in SUSPICIOUS_PATTERNS.items():
            matches = []
            for s in strings:
                s_bytes = s.encode("utf-8", errors="ignore")
                for pat in info["patterns"]:
                    if pat.lower() in s_bytes.lower():
                        if s not in matches:
                            matches.append(s)
            if matches:
                found[category] = {
                    "matches": matches[:20],  # cap at 20 per category
                    "count": len(matches),
                    "weight": info["weight"],
                    "mitre": info["mitre"],
                }
        return found

    @staticmethod
    def extract_iocs(strings: list) -> dict:
        """Extract indicators of compromise: IPs, URLs, domains."""
        iocs = {"ips": [], "urls": [], "domains": [], "emails": []}

        ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_re = re.compile(r'https?://[^\s<>"\']+')
        domain_re = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|onion)\b')
        email_re = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

        for s in strings:
            for ip in ip_re.findall(s):
                # Filter out common non-suspicious IPs
                if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255") and ip not in iocs["ips"]:
                    iocs["ips"].append(ip)
            for url in url_re.findall(s):
                if url not in iocs["urls"]:
                    iocs["urls"].append(url)
            for dom in domain_re.findall(s):
                if dom not in iocs["domains"] and not dom.startswith("www.microsoft.com"):
                    iocs["domains"].append(dom)
            for email in email_re.findall(s):
                if email not in iocs["emails"]:
                    iocs["emails"].append(email)

        # Cap results
        for key in iocs:
            iocs[key] = iocs[key][:50]

        return iocs


# ═══════════════════════════════════════════════════════════════════════
# ENTROPY ANALYZER
# ═══════════════════════════════════════════════════════════════════════

class EntropyAnalyzer:
    """Shannon entropy analysis per block and whole file."""

    BLOCK_SIZE = 256

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def analyze(cls, file_path: str) -> dict:
        """Compute whole-file and per-block entropy."""
        try:
            data = Path(file_path).read_bytes()
        except Exception as e:
            return {"overall": 0.0, "map": [], "interpretation": "error", "error": str(e)}

        overall = cls.shannon_entropy(data)

        # Per-block entropy map
        block_map = []
        for i in range(0, len(data), cls.BLOCK_SIZE):
            block = data[i:i + cls.BLOCK_SIZE]
            block_map.append(round(cls.shannon_entropy(block), 2))

        # Interpretation
        if overall > 7.0:
            interpretation = "encrypted_or_packed"
        elif overall > 6.0:
            interpretation = "compressed_or_obfuscated"
        elif overall > 4.0:
            interpretation = "normal_binary"
        elif overall > 2.0:
            interpretation = "normal_text"
        else:
            interpretation = "low_entropy_padding"

        return {
            "overall": overall,
            "map": block_map,
            "block_count": len(block_map),
            "interpretation": interpretation,
            "max_block": max(block_map) if block_map else 0.0,
            "min_block": min(block_map) if block_map else 0.0,
            "avg_block": round(sum(block_map) / len(block_map), 4) if block_map else 0.0,
        }


# ═══════════════════════════════════════════════════════════════════════
# PE ANALYZER (Windows PE files)
# ═══════════════════════════════════════════════════════════════════════

class PEAnalyzer:
    """Analyzes PE (Portable Executable) files — imports, sections, packers."""

    PACKER_SIGNATURES = {
        b"UPX0": "UPX",
        b"UPX1": "UPX",
        b"UPX!": "UPX",
        b".themida": "Themida",
        b".vmp0": "VMProtect",
        b".vmp1": "VMProtect",
        b"ASPack": "ASPack",
        b"PECompact": "PECompact",
        b".ndata": "NSIS Installer",
    }

    SUSPICIOUS_IMPORTS = {
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtWriteVirtualMemory", "RtlCreateUserThread", "LoadLibraryA",
        "GetProcAddress", "VirtualProtectEx", "OpenProcess",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "SetWindowsHookExA",
    }

    @classmethod
    def analyze(cls, file_path: str) -> Optional[dict]:
        """Full PE analysis — returns None if not a PE or pefile unavailable."""
        if not HAS_PEFILE:
            # Fallback: raw header inspection
            return cls._raw_pe_check(file_path)

        try:
            pe = pefile.PE(file_path)
        except Exception:
            return None

        result = {
            "is_pe": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem if hasattr(pe.OPTIONAL_HEADER, "Subsystem") else 0,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [],
            "imports": [],
            "exports": [],
            "suspicious_imports": [],
            "compilation_timestamp": "",
            "packer_detected": [],
        }

        # Compilation timestamp
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            result["compilation_timestamp"] = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception:
            pass

        # Sections
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode("ascii", errors="ignore")
            result["sections"].append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 4),
                "characteristics": hex(section.Characteristics),
            })
            # Packer detection via section names
            for sig, packer in cls.PACKER_SIGNATURES.items():
                if sig in section.Name:
                    if packer not in result["packer_detected"]:
                        result["packer_detected"].append(packer)

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii", errors="ignore")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode("ascii", errors="ignore")
                        funcs.append(fname)
                        if fname in cls.SUSPICIOUS_IMPORTS:
                            result["suspicious_imports"].append(fname)
                result["imports"].append({"dll": dll_name, "functions": funcs[:30]})

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["exports"].append(exp.name.decode("ascii", errors="ignore"))

        pe.close()
        return result

    @classmethod
    def _raw_pe_check(cls, file_path: str) -> Optional[dict]:
        """Minimal PE inspection without pefile library."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(4096)
        except Exception:
            return None

        if header[:2] != b"MZ":
            return None

        result = {
            "is_pe": True,
            "machine": "unknown",
            "sections": [],
            "imports": [],
            "exports": [],
            "suspicious_imports": [],
            "packer_detected": [],
            "note": "Limited analysis — install pefile for full PE inspection",
        }

        # Check for packer signatures in raw header
        for sig, packer in cls.PACKER_SIGNATURES.items():
            if sig in header:
                if packer not in result["packer_detected"]:
                    result["packer_detected"].append(packer)

        # Try to read PE offset and basic fields
        try:
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", header, pe_offset + 4)[0]
                result["machine"] = hex(machine)
                ts = struct.unpack_from("<I", header, pe_offset + 8)[0]
                try:
                    result["compilation_timestamp"] = datetime.utcfromtimestamp(ts).isoformat() + "Z"
                except Exception:
                    pass
        except Exception:
            pass

        return result


# ═══════════════════════════════════════════════════════════════════════
# SCRIPT ANALYZER
# ═══════════════════════════════════════════════════════════════════════

class ScriptAnalyzer:
    """Analyzes script files for dangerous calls and obfuscation."""

    @staticmethod
    def detect_language(file_path: str) -> Optional[str]:
        """Detect script language by extension."""
        ext = Path(file_path).suffix.lower()
        return SCRIPT_EXTENSIONS.get(ext)

    @classmethod
    def analyze(cls, file_path: str) -> Optional[dict]:
        """Analyze a script file for dangerous patterns."""
        lang = cls.detect_language(file_path)
        if not lang:
            return None

        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        result = {
            "language": lang,
            "lines": content.count("\n") + 1,
            "dangerous_calls": [],
            "obfuscation_indicators": [],
            "network_calls": [],
            "file_operations": [],
        }

        content_lower = content.lower()
        patterns = DANGEROUS_SCRIPT_CALLS.get(lang, [])

        # Dangerous function calls
        for pat in patterns:
            if pat.lower() in content_lower:
                # Find the line containing the pattern
                for i, line in enumerate(content.split("\n"), 1):
                    if pat.lower() in line.lower():
                        result["dangerous_calls"].append({
                            "pattern": pat,
                            "line": i,
                            "context": line.strip()[:120],
                        })
                        break

        # Obfuscation detection
        obf_patterns = [
            (r'(?:chr\(|\\x[0-9a-f]{2}){5,}', "Character code obfuscation"),
            (r'(?:base64|b64decode|atob)', "Base64 encoding"),
            (r'(?:\\u[0-9a-f]{4}){4,}', "Unicode escape sequences"),
            (r'(?:eval|exec)\s*\(.*(?:decode|decompress|unpack)', "Eval with decode/decompress"),
            (r'(?:replace|split|join|reverse)\s*\(.*\)\s*\.(?:replace|split|join|reverse)', "String manipulation chain"),
            (r'\+\s*["\'][^"\']{1,3}["\']\s*\+', "String concatenation tricks"),
        ]
        for pat, desc in obf_patterns:
            if re.search(pat, content, re.IGNORECASE):
                result["obfuscation_indicators"].append(desc)

        # Network calls
        net_patterns = [
            (r'(?:requests?\.(?:get|post)|urllib|urlopen|fetch|XMLHttpRequest|Invoke-WebRequest|curl|wget)', "HTTP request"),
            (r'(?:socket|connect|bind|listen)', "Socket operation"),
            (r'(?:ftp|ssh|telnet|smtp|imap)', "Protocol usage"),
        ]
        for pat, desc in net_patterns:
            if re.search(pat, content, re.IGNORECASE):
                result["network_calls"].append(desc)

        # File operations
        file_patterns = [
            (r'(?:open\s*\(|fopen|CreateFile|WriteFile)', "File open/create"),
            (r'(?:os\.remove|os\.unlink|del |rm |shutil\.rmtree)', "File deletion"),
            (r'(?:os\.rename|shutil\.move|Move-Item)', "File move/rename"),
            (r'(?:zipfile|tarfile|7z|rar|Compress-Archive)', "Archive operation"),
        ]
        for pat, desc in file_patterns:
            if re.search(pat, content, re.IGNORECASE):
                result["file_operations"].append(desc)

        return result


# ═══════════════════════════════════════════════════════════════════════
# YARA SCANNER
# ═══════════════════════════════════════════════════════════════════════

class YARAScanner:
    """Scans files against YARA rules in sandbox/signatures/."""

    def __init__(self):
        self.rules = []
        self._compiled = None
        self._load_rules()

    def _load_rules(self):
        """Load and compile all .yar files from signatures directory."""
        if not HAS_YARA:
            logger.info("YARA not available — scanner disabled")
            return

        yar_files = list(SIGNATURES_DIR.glob("*.yar")) + list(SIGNATURES_DIR.glob("*.yara"))
        if not yar_files:
            logger.info("No YARA rule files found in signatures/")
            return

        filepaths = {}
        for i, yf in enumerate(yar_files):
            filepaths[f"ns_{i}"] = str(yf)

        try:
            self._compiled = yara.compile(filepaths=filepaths)
            logger.info(f"Loaded {len(yar_files)} YARA rule file(s)")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self._compiled = None

    def scan(self, file_path: str) -> list:
        """Scan a file against all loaded YARA rules."""
        if not self._compiled:
            return []
        try:
            matches = self._compiled.match(file_path, timeout=30)
            results = []
            for match in matches:
                results.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags) if match.tags else [],
                    "meta": dict(match.meta) if match.meta else {},
                    "strings_matched": len(match.strings) if match.strings else 0,
                })
            return results
        except Exception as e:
            logger.warning(f"YARA scan failed: {e}")
            return []

    def reload_rules(self):
        """Reload rules from disk."""
        self._load_rules()


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generates comprehensive analysis reports with verdicts and scores."""

    @staticmethod
    def generate(file_id: str, file_info: dict, hashes: dict,
                 strings_found: dict, entropy: dict, pe_info: Optional[dict],
                 script_info: Optional[dict], yara_matches: list,
                 iocs: dict) -> dict:
        """Generate the full analysis report."""

        # ── Risk score calculation ──────────────────────────────────────
        risk_score = 0

        # String-based score
        for category, data in strings_found.items():
            risk_score += min(data["weight"] * min(data["count"], 5), 25)

        # Hash in known-bad DB
        if hashes.get("sha256") and HashChecker.check_known_bad(hashes["sha256"]):
            risk_score += 40

        # Entropy score
        if entropy.get("overall", 0) > 7.2:
            risk_score += 15
        elif entropy.get("overall", 0) > 7.0:
            risk_score += 8

        # PE analysis score
        if pe_info:
            if pe_info.get("packer_detected"):
                risk_score += 15
            suspicious_count = len(pe_info.get("suspicious_imports", []))
            risk_score += min(suspicious_count * 5, 20)

        # Script analysis score
        if script_info:
            risk_score += min(len(script_info.get("dangerous_calls", [])) * 8, 25)
            risk_score += min(len(script_info.get("obfuscation_indicators", [])) * 10, 20)

        # YARA matches
        for match in yara_matches:
            severity = match.get("meta", {}).get("severity", "medium")
            if severity == "critical":
                risk_score += 25
            elif severity == "high":
                risk_score += 15
            else:
                risk_score += 8

        # IOC score
        ioc_total = sum(len(v) for v in iocs.values())
        risk_score += min(ioc_total * 2, 15)

        # Clamp
        risk_score = min(risk_score, 100)

        # ── Verdict ─────────────────────────────────────────────────────
        if risk_score >= 70:
            verdict = "malicious"
        elif risk_score >= 30:
            verdict = "suspicious"
        else:
            verdict = "clean"

        # ── MITRE techniques ────────────────────────────────────────────
        mitre_techniques = []
        seen_mitre = set()
        for category, data in strings_found.items():
            mitre_id = data.get("mitre", "")
            if mitre_id and mitre_id not in seen_mitre:
                seen_mitre.add(mitre_id)
                mitre_techniques.append(mitre_id)
        if pe_info and pe_info.get("packer_detected"):
            t = "T1027.002 — Software Packing"
            if t not in seen_mitre:
                mitre_techniques.append(t)
        if script_info and script_info.get("obfuscation_indicators"):
            t = "T1027 — Obfuscated Files or Information"
            if t not in seen_mitre:
                mitre_techniques.append(t)

        # ── File info ───────────────────────────────────────────────────
        mime_type, _ = mimetypes.guess_type(file_info.get("original_name", ""))

        report = {
            "file_id": file_id,
            "timestamp": datetime.now().isoformat(),
            "verdict": verdict,
            "risk_score": risk_score,
            "file_info": {
                "name": file_info.get("original_name", "unknown"),
                "size": file_info.get("size", 0),
                "mime_type": mime_type or "application/octet-stream",
                "hashes": hashes,
            },
            "strings_found": strings_found,
            "entropy": entropy,
            "pe_info": pe_info,
            "script_info": script_info,
            "yara_matches": yara_matches,
            "ioc_list": iocs,
            "mitre_techniques": mitre_techniques,
        }

        # Save to disk
        report_path = REPORTS_DIR / f"{file_id}.json"
        try:
            report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            logger.info(f"Report saved: {report_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

        return report


# ═══════════════════════════════════════════════════════════════════════
# SANDBOX ENGINE
# ═══════════════════════════════════════════════════════════════════════

class SandboxEngine:
    """Main engine — orchestrates submission, analysis, and reporting."""

    def __init__(self):
        self.receiver = FileReceiver()
        self.hash_checker = HashChecker()
        self.string_extractor = StringExtractor()
        self.entropy_analyzer = EntropyAnalyzer()
        self.pe_analyzer = PEAnalyzer()
        self.script_analyzer = ScriptAnalyzer()
        self.yara_scanner = YARAScanner()
        self.report_generator = ReportGenerator()

        self.reports: dict[str, dict] = {}
        self.analyzing: set = set()
        self.clients: set = set()       # WebSocket clients
        self.loop = None
        self.state_task = None
        self._lock = threading.Lock()

        # Load existing reports from disk
        self._load_existing_reports()

    def _load_existing_reports(self):
        """Load previously saved reports."""
        for rfile in REPORTS_DIR.glob("*.json"):
            try:
                data = json.loads(rfile.read_text(encoding="utf-8"))
                fid = data.get("file_id", rfile.stem)
                self.reports[fid] = data
            except Exception:
                pass
        if self.reports:
            logger.info(f"Loaded {len(self.reports)} existing report(s)")

    def submit_file(self, path: str) -> Optional[dict]:
        """Submit a file for analysis."""
        entry = self.receiver.submit_path(path)
        if entry:
            threading.Thread(target=self.analyze, args=(entry["file_id"],), daemon=True).start()
            if HAS_TOAST:
                try:
                    toast_event("Sandbox", f"File submitted: {entry['original_name']}")
                except Exception:
                    pass
        return entry

    def submit_base64(self, data: str, filename: str) -> Optional[dict]:
        """Submit a base64-encoded file for analysis."""
        entry = self.receiver.submit_base64(data, filename)
        if entry:
            threading.Thread(target=self.analyze, args=(entry["file_id"],), daemon=True).start()
        return entry

    def analyze(self, file_id: str):
        """Run full analysis pipeline on a queued file."""
        # Find the queue entry
        entry = None
        for item in self.receiver.get_queue():
            if item["file_id"] == file_id:
                entry = item
                break
        if not entry:
            logger.warning(f"File not found in queue: {file_id}")
            return

        self.receiver.update_status(file_id, "analyzing")
        self.analyzing.add(file_id)
        fpath = entry["quarantine_path"]

        logger.info(f"Starting analysis of {entry['original_name']} ({file_id})")

        try:
            # 1. Hash computation
            hashes = self.hash_checker.compute_hashes(fpath)

            # 2. Read file data for string extraction
            try:
                raw_data = Path(fpath).read_bytes()
            except Exception:
                raw_data = b""

            # 3. String extraction
            ascii_strings = self.string_extractor.extract_ascii_strings(raw_data)
            unicode_strings = self.string_extractor.extract_unicode_strings(raw_data)
            all_strings = list(set(ascii_strings + unicode_strings))
            strings_found = self.string_extractor.find_suspicious_strings(all_strings)

            # 4. IOC extraction
            iocs = self.string_extractor.extract_iocs(all_strings)

            # 5. Entropy analysis
            entropy = self.entropy_analyzer.analyze(fpath)

            # 6. PE analysis (if applicable)
            pe_info = None
            if raw_data[:2] == b"MZ":
                pe_info = self.pe_analyzer.analyze(fpath)

            # 7. Script analysis (if applicable)
            script_info = self.script_analyzer.analyze(fpath)

            # 8. YARA scan
            yara_matches = self.yara_scanner.scan(fpath)

            # 9. Generate report
            report = self.report_generator.generate(
                file_id=file_id,
                file_info=entry,
                hashes=hashes,
                strings_found=strings_found,
                entropy=entropy,
                pe_info=pe_info,
                script_info=script_info,
                yara_matches=yara_matches,
                iocs=iocs,
            )

            with self._lock:
                self.reports[file_id] = report

            self.receiver.update_status(file_id, "completed")
            logger.info(f"Analysis complete: {entry['original_name']} — verdict={report['verdict']} score={report['risk_score']}")

            if HAS_TOAST and report["verdict"] == "malicious":
                try:
                    toast_threat("Sandbox", entry["original_name"], "critical",
                                 f"Score: {report['risk_score']}/100")
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Analysis failed for {file_id}: {e}")
            self.receiver.update_status(file_id, "error")
        finally:
            self.analyzing.discard(file_id)

    def get_report(self, file_id: str) -> Optional[dict]:
        """Get a specific analysis report."""
        return self.reports.get(file_id)

    def get_recent_reports(self, limit: int = 20) -> list:
        """Get recent reports sorted by timestamp."""
        reports = list(self.reports.values())
        reports.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        return reports[:limit]

    def get_queue(self) -> list:
        """Get current submission queue."""
        return self.receiver.get_queue()

    def delete_report(self, file_id: str) -> bool:
        """Delete a report and its quarantined file."""
        if file_id not in self.reports:
            return False
        del self.reports[file_id]

        # Remove report file
        report_path = REPORTS_DIR / f"{file_id}.json"
        try:
            report_path.unlink(missing_ok=True)
        except Exception:
            pass

        # Remove quarantined file
        for item in self.receiver.get_queue():
            if item["file_id"] == file_id:
                try:
                    Path(item["quarantine_path"]).unlink(missing_ok=True)
                except Exception:
                    pass
                break

        return True

    def build_state(self) -> dict:
        """Build full state for dashboard."""
        recent = self.get_recent_reports(50)
        today = datetime.now().strftime("%Y-%m-%d")
        today_reports = [r for r in recent if r.get("timestamp", "").startswith(today)]
        malicious_today = sum(1 for r in today_reports if r.get("verdict") == "malicious")
        suspicious_today = sum(1 for r in today_reports if r.get("verdict") == "suspicious")
        avg_score = round(sum(r.get("risk_score", 0) for r in today_reports) / max(len(today_reports), 1), 1)

        return {
            "type": "state",
            "version": VERSION,
            "queue": self.get_queue(),
            "analyzing": list(self.analyzing),
            "recent_reports": recent[:20],
            "stats": {
                "total_reports": len(self.reports),
                "analyzed_today": len(today_reports),
                "malicious_today": malicious_today,
                "suspicious_today": suspicious_today,
                "avg_score": avg_score,
                "yara_available": HAS_YARA,
                "pefile_available": HAS_PEFILE,
            },
        }

    async def handle_command(self, ws, data: dict):
        """Handle a WebSocket command."""
        cmd = data.get("cmd", "")

        if cmd == "get_state":
            state = self.build_state()
            await ws.send(json.dumps(state, default=str))

        elif cmd == "submit_file":
            path = data.get("path", "")
            entry = self.submit_file(path)
            await ws.send(json.dumps({"type": "submitted", "entry": entry}, default=str))

        elif cmd == "submit_base64":
            b64 = data.get("data", "")
            filename = data.get("filename", "unknown")
            entry = self.submit_base64(b64, filename)
            await ws.send(json.dumps({"type": "submitted", "entry": entry}, default=str))

        elif cmd == "get_report":
            file_id = data.get("file_id", "")
            report = self.get_report(file_id)
            await ws.send(json.dumps({"type": "report", "report": report}, default=str))

        elif cmd == "get_recent":
            limit = data.get("limit", 20)
            reports = self.get_recent_reports(limit)
            await ws.send(json.dumps({"type": "recent_reports", "reports": reports}, default=str))

        elif cmd == "delete_report":
            file_id = data.get("file_id", "")
            ok = self.delete_report(file_id)
            await ws.send(json.dumps({"type": "deleted", "file_id": file_id, "success": ok}))

    async def broadcast_state(self):
        """Periodically broadcast state to all WebSocket clients."""
        while True:
            if self.clients:
                state = self.build_state()
                msg = json.dumps(state, default=str)
                dead = set()
                for ws in self.clients:
                    try:
                        await ws.send(msg)
                    except Exception:
                        dead.add(ws)
                self.clients -= dead
            await asyncio.sleep(3)


# ═══════════════════════════════════════════════════════════════════════
# GLOBAL ENGINE
# ═══════════════════════════════════════════════════════════════════════

ENGINE = SandboxEngine()


# ═══════════════════════════════════════════════════════════════════════
# PYWEBVIEW JS API
# ═══════════════════════════════════════════════════════════════════════

class SandboxAPI:
    """pywebview JavaScript API — called from the dashboard."""

    def __init__(self):
        self._window = None
        self._stop_broadcast = False
        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

    def set_window(self, window):
        self._window = window

    def get_state(self) -> dict:
        return ENGINE.build_state()

    def submit_file(self, path: str) -> dict:
        entry = ENGINE.submit_file(path)
        return entry if entry else {"error": "Failed to submit file"}

    def submit_base64(self, data: str, filename: str) -> dict:
        entry = ENGINE.submit_base64(data, filename)
        return entry if entry else {"error": "Failed to submit file"}

    def get_report(self, file_id: str) -> dict:
        report = ENGINE.get_report(file_id)
        return report if report else {"error": "Report not found"}

    def get_recent_reports(self, limit: int = 20) -> list:
        return ENGINE.get_recent_reports(limit)

    def browse_file(self) -> dict:
        """Open native file dialog to select a file."""
        if not self._window:
            return {"error": "No window context"}
        try:
            result = self._window.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
                file_types=("All files (*.*)",),
            )
            if result and len(result) > 0:
                path = result[0]
                entry = ENGINE.submit_file(str(path))
                return entry if entry else {"error": "Failed to submit"}
            return {"cancelled": True}
        except Exception as e:
            return {"error": str(e)}

    def delete_report(self, file_id: str) -> dict:
        ok = ENGINE.delete_report(file_id)
        return {"success": ok}

    def get_queue(self) -> list:
        return ENGINE.get_queue()

    # ─── Permission methods ─────────────────────────────────────────────

    def perm_get_state(self) -> dict:
        if not self._perm:
            return {"available": False, "enabled": False, "locked": False}
        state = self._perm.get_state()
        return {
            "available": True,
            "enabled": state.get("enabled", False),
            "locked": state.get("locked", False),
            "user": self._auth_user,
        }

    def perm_check(self, action: str = "execute") -> dict:
        if not self._perm:
            return {"allowed": True}
        return {"allowed": self._perm.check("sandbox", action)}

    def perm_lock(self) -> dict:
        if not self._perm:
            return {"success": False, "error": "permissions not available"}
        self._auth_user = None
        return {"success": self._perm.lock("sandbox")}

    def perm_unlock(self, password: str) -> dict:
        if not self._perm:
            return {"success": False, "error": "permissions not available"}
        ok, user = self._perm.authenticate("sandbox", password)
        if ok:
            self._auth_user = user
            self._perm.unlock("sandbox")
        return {"success": ok, "user": user}


# ═══════════════════════════════════════════════════════════════════════
# STATE BROADCASTER (pywebview mode)
# ═══════════════════════════════════════════════════════════════════════

def _pywebview_state_broadcast(api: SandboxAPI):
    """Background thread: push state to pywebview window periodically."""
    while not api._stop_broadcast:
        try:
            if api._window:
                state = ENGINE.build_state()
                js_data = json.dumps(state, default=str)
                api._window.evaluate_js(f"handleMsg({js_data})")
        except Exception:
            pass
        interval = 1 if ENGINE.analyzing else 4
        time.sleep(interval)


# ═══════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER (fallback mode)
# ═══════════════════════════════════════════════════════════════════════

async def ws_handler(websocket):
    """WebSocket connection handler — fallback when pywebview unavailable."""
    ENGINE.clients.add(websocket)
    remote = websocket.remote_address
    logger.info(f"Client connected: {remote}")
    try:
        state = ENGINE.build_state()
        await websocket.send(json.dumps(state, default=str))

        async for message in websocket:
            try:
                data = json.loads(message)
                await ENGINE.handle_command(websocket, data)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
            except Exception as e:
                await websocket.send(json.dumps({"type": "error", "message": str(e)}))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        ENGINE.clients.discard(websocket)
        logger.info(f"Client disconnected: {remote}")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def format_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def main_webview():
    """Launch with pywebview — native window, direct API calls."""

    print(f"""
+======================================================+
|        Sandbox v{VERSION}                                 |
|        File Analysis Engine — Optimus Suite       |
+======================================================+
|  Mode    : Native window (pywebview)                  |
|  YARA    : {'ON ' if HAS_YARA else 'OFF'}                                        |
|  PE      : {'ON ' if HAS_PEFILE else 'OFF'}                                        |
+======================================================+
    """)

    api = SandboxAPI()
    dashboard_path = str(DASHBOARD_FILE)

    window = webview.create_window(
        "Sandbox \u2014 Optimus Suite",
        dashboard_path,
        js_api=api,
        width=1300,
        height=850,
        min_size=(1000, 650),
        background_color="#0f0f13",
    )
    api.set_window(window)

    def on_loaded():
        logger.info("Dashboard loaded in native window")
        threading.Thread(target=_pywebview_state_broadcast, args=(api,), daemon=True).start()

    window.events.loaded += on_loaded

    try:
        webview.start(debug=False)
    finally:
        api._stop_broadcast = True
        logger.info("Sandbox closed.")


async def main_async():
    """Fallback: WebSocket mode when pywebview is not available."""
    ENGINE.loop = asyncio.get_event_loop()
    ENGINE.state_task = asyncio.create_task(ENGINE.broadcast_state())

    port = WS_PORT
    print(f"""
+======================================================+
|        Sandbox v{VERSION}                                 |
|        File Analysis Engine — Optimus Suite       |
+======================================================+
|  Mode      : WebSocket (fallback)                     |
|  WebSocket : ws://localhost:{port}                     |
|  Dashboard : sandbox_dashboard.html                   |
|  YARA      : {'ON ' if HAS_YARA else 'OFF'}                                       |
|  PE        : {'ON ' if HAS_PEFILE else 'OFF'}                                       |
+======================================================+
    """)

    try:
        async with websockets.serve(ws_handler, "localhost", port):
            logger.info(f"WebSocket server started on port {port}")
            await asyncio.Future()
    except Exception as e:
        for fallback in range(port + 1, port + 5):
            try:
                async with websockets.serve(ws_handler, "localhost", fallback):
                    logger.info(f"WebSocket server started on port {fallback} (fallback)")
                    await asyncio.Future()
            except Exception:
                continue
        logger.error(f"Cannot start WebSocket server: {e}")


def main():
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    if not headless and HAS_WEBVIEW:
        logger.info("pywebview detected — launching native window")
        main_webview()
    elif HAS_WS:
        logger.info("Launching in WebSocket mode")
        try:
            asyncio.run(main_async())
        except KeyboardInterrupt:
            logger.info("Sandbox shutting down...")
    else:
        print("[!] Neither pywebview nor websockets available.")
        print("    Install one of them:  pip install pywebview  OR  pip install websockets")
        sys.exit(1)


if __name__ == "__main__":
    main()
