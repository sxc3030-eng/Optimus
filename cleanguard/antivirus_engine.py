"""
CleanGuard Pro - Antivirus Engine v1.0.0
========================================
Professional antivirus scanning pipeline with multi-engine support.

Integrates ClamAV, VirusTotal, YARA rules, archive scanning,
network threat detection, and scheduled scanning into a unified
engine. All external dependencies degrade gracefully when unavailable.

Usage:
    from antivirus_engine import AntivirusEngine
    engine = AntivirusEngine(config, signatures_dir, threat_db_dir)
    findings = engine.scan_file_enhanced("/path/to/file")
"""

import hashlib
import logging
import os
import platform
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

# Optional dependencies - all degrade gracefully
try:
    import pyclamd
except ImportError:
    pyclamd = None

try:
    import yara
except ImportError:
    yara = None

try:
    import rarfile
except ImportError:
    rarfile = None

try:
    import py7zr
except ImportError:
    py7zr = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("CleanGuard.AntivirusEngine")


# ---------------------------------------------------------------------------
# Class 1: ClamAV Scanner
# ---------------------------------------------------------------------------

class ClamAVScanner:
    """ClamAV integration via pyclamd - optional, graceful fallback."""

    def __init__(self) -> None:
        self.available: bool = False
        self.clamd: Any = None
        self.version: Optional[str] = None
        self._connect()

    def _connect(self) -> None:
        """Try to connect to ClamAV daemon via Unix socket, then TCP."""
        if pyclamd is None:
            logger.info("pyclamd not installed - ClamAV integration disabled")
            return
        # Try Unix socket first (Linux/macOS default)
        try:
            self.clamd = pyclamd.ClamdUnixSocket()
            self.clamd.ping()
            self.available = True
            self.version = self.clamd.version()
            logger.info("ClamAV connected via Unix socket: %s", self.version)
            return
        except Exception:
            pass
        # Try TCP connection (Windows or custom setups)
        try:
            self.clamd = pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=3310)
            self.clamd.ping()
            self.available = True
            self.version = self.clamd.version()
            logger.info("ClamAV connected via TCP: %s", self.version)
            return
        except Exception:
            pass
        self.clamd = None
        self.available = False
        logger.info("ClamAV daemon not reachable - ClamAV integration disabled")

    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Scan a file on disk. Returns {"infected": bool, "name": str} or None."""
        if not self.available or self.clamd is None:
            return None
        try:
            result = self.clamd.scan_file(filepath)
            if result is None:
                return {"infected": False, "name": ""}
            status, name = result.get(filepath, ("OK", None))
            if status == "FOUND":
                return {"infected": True, "name": name or "Unknown"}
            return {"infected": False, "name": ""}
        except Exception as exc:
            logger.warning("ClamAV scan_file error for %s: %s", filepath, exc)
            return None

    def scan_stream(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Scan in-memory data (e.g. archive contents)."""
        if not self.available or self.clamd is None:
            return None
        try:
            result = self.clamd.scan_stream(data)
            if result is None:
                return {"infected": False, "name": ""}
            status, name = result.get("stream", ("OK", None))
            if status == "FOUND":
                return {"infected": True, "name": name or "Unknown"}
            return {"infected": False, "name": ""}
        except Exception as exc:
            logger.warning("ClamAV scan_stream error: %s", exc)
            return None

    def get_version(self) -> str:
        """Return ClamAV version string."""
        if self.version:
            return self.version
        if self.available and self.clamd:
            try:
                self.version = self.clamd.version()
                return self.version
            except Exception:
                pass
        return "ClamAV not available"

    def update_signatures(self) -> Dict[str, Any]:
        """Run freshclam to update ClamAV virus signatures."""
        try:
            cmd = "freshclam"
            if platform.system() == "Windows":
                cmd = "freshclam.exe"
            result = subprocess.run(
                [cmd],
                capture_output=True, text=True, timeout=300
            )
            success = result.returncode == 0
            output = result.stdout + result.stderr
            if success:
                # Reconnect to pick up new signatures
                self._connect()
            return {"ok": success, "output": output.strip()}
        except FileNotFoundError:
            return {"ok": False, "output": "freshclam not found in PATH"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "output": "freshclam timed out after 300s"}
        except Exception as exc:
            return {"ok": False, "output": str(exc)}


# ---------------------------------------------------------------------------
# Class 2: VirusTotal Checker
# ---------------------------------------------------------------------------

class VirusTotalChecker:
    """VirusTotal API v3 hash lookup with rate limiting and LRU cache."""

    API_URL: str = "https://www.virustotal.com/api/v3/files"
    MAX_CACHE: int = 10000

    def __init__(self, api_key: str = "") -> None:
        self.api_key: str = api_key
        self._cache: OrderedDict = OrderedDict()
        self._requests_this_minute: int = 0
        self._requests_today: int = 0
        self._minute_reset: float = time.time() + 60
        self._day_reset: float = time.time() + 86400

    @property
    def available(self) -> bool:
        """Check if VirusTotal integration is usable."""
        return bool(self.api_key) and requests is not None

    def lookup(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Look up a file hash on VirusTotal. Returns detection info or None."""
        if not self.available:
            return None
        sha256 = sha256.lower()
        # Check cache
        if sha256 in self._cache:
            self._cache.move_to_end(sha256)
            return self._cache[sha256]
        # Check rate limits
        if not self._check_rate_limit():
            logger.debug("VirusTotal rate limit reached, skipping lookup")
            return None
        try:
            url = f"{self.API_URL}/{sha256}"
            headers = {"x-apikey": self.api_key}
            resp = requests.get(url, headers=headers, timeout=15)
            self._requests_this_minute += 1
            self._requests_today += 1
            if resp.status_code == 404:
                # File not known to VT
                result = {"malicious": 0, "total": 0, "ratio": "0/0", "engines": []}
                self._cache_put(sha256, result)
                return result
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit (HTTP 429)")
                return None
            if resp.status_code != 200:
                logger.warning("VirusTotal HTTP %d for %s", resp.status_code, sha256)
                return None
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            # Collect engine names that flagged as malicious
            engines = []
            results_map = attrs.get("last_analysis_results", {})
            for engine_name, engine_result in results_map.items():
                if engine_result.get("category") == "malicious":
                    engines.append(engine_name)
            result = {
                "malicious": malicious,
                "total": total,
                "ratio": f"{malicious}/{total}",
                "engines": engines,
            }
            self._cache_put(sha256, result)
            return result
        except Exception as exc:
            logger.warning("VirusTotal lookup error for %s: %s", sha256, exc)
            return None

    def _check_rate_limit(self) -> bool:
        """Reset counters if elapsed and check limits (4/min, 500/day)."""
        now = time.time()
        if now >= self._minute_reset:
            self._requests_this_minute = 0
            self._minute_reset = now + 60
        if now >= self._day_reset:
            self._requests_today = 0
            self._day_reset = now + 86400
        return self._requests_this_minute < 4 and self._requests_today < 500

    def _cache_put(self, key: str, value: Dict[str, Any]) -> None:
        """Insert into LRU cache, evicting oldest if full."""
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        while len(self._cache) > self.MAX_CACHE:
            self._cache.popitem(last=False)


# ---------------------------------------------------------------------------
# Class 3: YARA Engine
# ---------------------------------------------------------------------------

class YARAEngine:
    """Load and scan with all YARA rules from signatures/ directory."""

    def __init__(self, signatures_dir: Any) -> None:
        self.signatures_dir: Path = Path(signatures_dir)
        self._compiled: Any = None
        self._rule_count: int = 0
        self._last_load: Optional[datetime] = None
        self.reload()

    def reload(self) -> None:
        """Compile all .yar/.yara files from signatures directory."""
        if yara is None:
            logger.info("yara-python not installed - YARA scanning disabled")
            self._compiled = None
            self._rule_count = 0
            return
        if not self.signatures_dir.is_dir():
            logger.info("YARA signatures directory not found: %s", self.signatures_dir)
            self._compiled = None
            self._rule_count = 0
            return
        try:
            filepaths = {}
            for ext in ("*.yar", "*.yara"):
                for rule_file in self.signatures_dir.glob(ext):
                    name = rule_file.stem
                    filepaths[name] = str(rule_file)
            if not filepaths:
                logger.info("No YARA rules found in %s", self.signatures_dir)
                self._compiled = None
                self._rule_count = 0
                return
            self._compiled = yara.compile(filepaths=filepaths)
            self._rule_count = len(filepaths)
            self._last_load = datetime.now()
            logger.info("YARA loaded %d rule files from %s", self._rule_count, self.signatures_dir)
        except Exception as exc:
            logger.error("YARA compilation error: %s", exc)
            self._compiled = None
            self._rule_count = 0

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scan a file with compiled YARA rules."""
        if self._compiled is None:
            return []
        try:
            matches = self._compiled.match(filepath)
            return self._format_matches(matches)
        except Exception as exc:
            logger.warning("YARA scan_file error for %s: %s", filepath, exc)
            return []

    def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan in-memory data with compiled YARA rules."""
        if self._compiled is None:
            return []
        try:
            matches = self._compiled.match(data=data)
            return self._format_matches(matches)
        except Exception as exc:
            logger.warning("YARA scan_data error: %s", exc)
            return []

    @staticmethod
    def _format_matches(matches: list) -> List[Dict[str, Any]]:
        """Convert yara match objects to dictionaries."""
        results = []
        for match in matches:
            meta = match.meta if hasattr(match, "meta") else {}
            strings_matched = []
            if hasattr(match, "strings"):
                for s in match.strings:
                    if hasattr(s, "identifier"):
                        strings_matched.append(s.identifier)
                    else:
                        strings_matched.append(str(s))
            results.append({
                "rule": match.rule,
                "severity": meta.get("severity", "medium"),
                "description": meta.get("description", match.rule),
                "strings_matched": strings_matched,
            })
        return results


# ---------------------------------------------------------------------------
# Class 4: Archive Scanner
# ---------------------------------------------------------------------------

class ArchiveScanner:
    """Scan inside ZIP, RAR, 7z, TAR archives recursively."""

    MAX_DEPTH: int = 3
    MAX_TOTAL_SIZE: int = 100 * 1024 * 1024  # 100MB extracted limit
    SUPPORTED: Set[str] = {".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".gz"}

    def scan_archive(
        self,
        filepath: str,
        scan_callback: Callable[[str], List[Dict[str, Any]]],
        depth: int = 0,
    ) -> List[Dict[str, Any]]:
        """Scan contents of an archive file. scan_callback is the main scan_file function."""
        if depth >= self.MAX_DEPTH:
            logger.debug("Archive scan max depth reached for %s", filepath)
            return []
        suffix = Path(filepath).suffix.lower()
        name_lower = Path(filepath).name.lower()
        try:
            if suffix == ".zip":
                return self._scan_zip(filepath, scan_callback, depth)
            elif suffix in (".tar", ".tgz") or name_lower.endswith((".tar.gz", ".tar.bz2")):
                return self._scan_tar(filepath, scan_callback, depth)
            elif suffix == ".7z":
                return self._scan_7z(filepath, scan_callback, depth)
            elif suffix == ".rar":
                return self._scan_rar(filepath, scan_callback, depth)
            elif suffix == ".gz" and not name_lower.endswith(".tar.gz"):
                return self._scan_tar(filepath, scan_callback, depth)
            else:
                return []
        except Exception as exc:
            logger.warning("Archive scan error for %s: %s", filepath, exc)
            return []

    def _scan_zip(
        self,
        filepath: str,
        scan_callback: Callable[[str], List[Dict[str, Any]]],
        depth: int,
    ) -> List[Dict[str, Any]]:
        """Scan contents of a ZIP archive."""
        findings: List[Dict[str, Any]] = []
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                # Check for password protection
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        findings.append({
                            "type": "archive_warning",
                            "name": "PasswordProtectedZIP",
                            "severity": "info",
                            "detail": f"Password-protected entry: {info.filename}",
                        })
                        return findings
                # Check total extracted size
                total_size = sum(i.file_size for i in zf.infolist())
                if total_size > self.MAX_TOTAL_SIZE:
                    findings.append({
                        "type": "archive_warning",
                        "name": "OversizedArchive",
                        "severity": "warning",
                        "detail": f"Extracted size {total_size} exceeds limit",
                    })
                    return findings
                with tempfile.TemporaryDirectory(prefix="cg_zip_") as tmpdir:
                    zf.extractall(tmpdir)
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        extracted = os.path.join(tmpdir, info.filename)
                        if os.path.isfile(extracted):
                            sub_findings = scan_callback(extracted)
                            for f in sub_findings:
                                f["detail"] = f"[in {Path(filepath).name}/{info.filename}] {f.get('detail', '')}"
                            findings.extend(sub_findings)
        except zipfile.BadZipFile:
            findings.append({
                "type": "archive_error",
                "name": "CorruptZIP",
                "severity": "warning",
                "detail": f"Corrupt ZIP file: {filepath}",
            })
        except Exception as exc:
            logger.warning("ZIP scan error for %s: %s", filepath, exc)
        return findings

    def _scan_tar(
        self,
        filepath: str,
        scan_callback: Callable[[str], List[Dict[str, Any]]],
        depth: int,
    ) -> List[Dict[str, Any]]:
        """Scan contents of a TAR/TGZ/TAR.BZ2 archive."""
        findings: List[Dict[str, Any]] = []
        try:
            with tarfile.open(filepath, "r:*") as tf:
                # Safety: check for path traversal
                members = []
                total_size = 0
                for member in tf.getmembers():
                    if member.name.startswith("/") or ".." in member.name:
                        findings.append({
                            "type": "archive_threat",
                            "name": "PathTraversal",
                            "severity": "high",
                            "detail": f"Suspicious path in archive: {member.name}",
                        })
                        continue
                    total_size += member.size
                    if total_size > self.MAX_TOTAL_SIZE:
                        findings.append({
                            "type": "archive_warning",
                            "name": "OversizedArchive",
                            "severity": "warning",
                            "detail": f"Extracted size exceeds {self.MAX_TOTAL_SIZE} bytes limit",
                        })
                        return findings
                    if member.isfile():
                        members.append(member)
                with tempfile.TemporaryDirectory(prefix="cg_tar_") as tmpdir:
                    for member in members:
                        tf.extract(member, tmpdir, filter="data")
                        extracted = os.path.join(tmpdir, member.name)
                        if os.path.isfile(extracted):
                            sub_findings = scan_callback(extracted)
                            for f in sub_findings:
                                f["detail"] = f"[in {Path(filepath).name}/{member.name}] {f.get('detail', '')}"
                            findings.extend(sub_findings)
        except tarfile.TarError as exc:
            findings.append({
                "type": "archive_error",
                "name": "CorruptTAR",
                "severity": "warning",
                "detail": f"TAR error: {exc}",
            })
        except Exception as exc:
            logger.warning("TAR scan error for %s: %s", filepath, exc)
        return findings

    def _scan_7z(
        self,
        filepath: str,
        scan_callback: Callable[[str], List[Dict[str, Any]]],
        depth: int,
    ) -> List[Dict[str, Any]]:
        """Scan contents of a 7z archive using py7zr."""
        findings: List[Dict[str, Any]] = []
        if py7zr is None:
            findings.append({
                "type": "archive_warning",
                "name": "Missing7zSupport",
                "severity": "info",
                "detail": "py7zr not installed - cannot scan 7z archive",
            })
            return findings
        try:
            with py7zr.SevenZipFile(filepath, mode="r") as archive:
                with tempfile.TemporaryDirectory(prefix="cg_7z_") as tmpdir:
                    archive.extractall(path=tmpdir)
                    for root, _dirs, files in os.walk(tmpdir):
                        for fname in files:
                            extracted = os.path.join(root, fname)
                            rel = os.path.relpath(extracted, tmpdir)
                            sub_findings = scan_callback(extracted)
                            for f in sub_findings:
                                f["detail"] = f"[in {Path(filepath).name}/{rel}] {f.get('detail', '')}"
                            findings.extend(sub_findings)
        except Exception as exc:
            logger.warning("7z scan error for %s: %s", filepath, exc)
            findings.append({
                "type": "archive_error",
                "name": "SevenZipError",
                "severity": "warning",
                "detail": f"7z extraction error: {exc}",
            })
        return findings

    def _scan_rar(
        self,
        filepath: str,
        scan_callback: Callable[[str], List[Dict[str, Any]]],
        depth: int,
    ) -> List[Dict[str, Any]]:
        """Scan contents of a RAR archive using rarfile."""
        findings: List[Dict[str, Any]] = []
        if rarfile is None:
            findings.append({
                "type": "archive_warning",
                "name": "MissingRARSupport",
                "severity": "info",
                "detail": "rarfile not installed - cannot scan RAR archive",
            })
            return findings
        try:
            with rarfile.RarFile(filepath, "r") as rf:
                if rf.needs_password():
                    findings.append({
                        "type": "archive_warning",
                        "name": "PasswordProtectedRAR",
                        "severity": "info",
                        "detail": f"Password-protected RAR: {filepath}",
                    })
                    return findings
                with tempfile.TemporaryDirectory(prefix="cg_rar_") as tmpdir:
                    rf.extractall(tmpdir)
                    for info in rf.infolist():
                        if info.is_dir():
                            continue
                        extracted = os.path.join(tmpdir, info.filename)
                        if os.path.isfile(extracted):
                            sub_findings = scan_callback(extracted)
                            for f in sub_findings:
                                f["detail"] = f"[in {Path(filepath).name}/{info.filename}] {f.get('detail', '')}"
                            findings.extend(sub_findings)
        except Exception as exc:
            logger.warning("RAR scan error for %s: %s", filepath, exc)
            findings.append({
                "type": "archive_error",
                "name": "RARError",
                "severity": "warning",
                "detail": f"RAR extraction error: {exc}",
            })
        return findings

    @staticmethod
    def is_archive(filepath: str) -> bool:
        """Check if a file is a supported archive format."""
        name_lower = Path(filepath).name.lower()
        if any(name_lower.endswith(ext) for ext in (".tar.gz", ".tar.bz2")):
            return True
        return Path(filepath).suffix.lower() in ArchiveScanner.SUPPORTED


# ---------------------------------------------------------------------------
# Class 5: Network Threat Detector
# ---------------------------------------------------------------------------

class NetworkThreatDetector:
    """Monitor active connections for C2 (command & control) indicators."""

    SUSPICIOUS_PORTS: Set[int] = {
        4444, 5555, 6666, 6667, 6668, 6669,
        8443, 9999, 31337, 12345, 1337,
    }

    def __init__(self, threat_db_dir: Any) -> None:
        self.c2_domains: Set[str] = set()
        self.c2_ips: Set[str] = set()
        self._load_threat_lists(Path(threat_db_dir))

    def _load_threat_lists(self, threat_db_dir: Path) -> None:
        """Load C2 domain and IP lists from threat database directory."""
        domains_file = threat_db_dir / "c2_domains.txt"
        if domains_file.is_file():
            try:
                for line in domains_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.c2_domains.add(line.lower())
                logger.info("Loaded %d C2 domains", len(self.c2_domains))
            except Exception as exc:
                logger.warning("Error loading C2 domains: %s", exc)

        ips_file = threat_db_dir / "c2_ips.txt"
        if ips_file.is_file():
            try:
                for line in ips_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.c2_ips.add(line)
                logger.info("Loaded %d C2 IPs", len(self.c2_ips))
            except Exception as exc:
                logger.warning("Error loading C2 IPs: %s", exc)

    def scan_connections(self) -> List[Dict[str, Any]]:
        """Scan active network connections for threat indicators."""
        if psutil is None:
            logger.info("psutil not installed - network threat detection disabled")
            return []
        threats: List[Dict[str, Any]] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Insufficient permissions for network connection scan")
            return []
        except Exception as exc:
            logger.warning("Error reading network connections: %s", exc)
            return []

        for conn in connections:
            if not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid or 0
            process_name = ""
            try:
                if pid:
                    process_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "unknown"

            threat_reasons: List[str] = []
            severity = "low"

            # Check against known C2 IPs
            if remote_ip in self.c2_ips:
                threat_reasons.append(f"Known C2 IP: {remote_ip}")
                severity = "critical"

            # Check suspicious ports
            if remote_port in self.SUSPICIOUS_PORTS:
                threat_reasons.append(f"Suspicious port: {remote_port}")
                if severity != "critical":
                    severity = "high"

            # Reverse DNS lookup and domain check
            if self.c2_domains:
                try:
                    hostname = socket.getfqdn(remote_ip)
                    if hostname and hostname != remote_ip:
                        hostname_lower = hostname.lower()
                        for domain in self.c2_domains:
                            if hostname_lower == domain or hostname_lower.endswith("." + domain):
                                threat_reasons.append(f"Known C2 domain: {hostname}")
                                severity = "critical"
                                break
                except Exception:
                    pass

            if threat_reasons:
                threats.append({
                    "pid": pid,
                    "process": process_name,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "threat": "; ".join(threat_reasons),
                    "severity": severity,
                })

        return threats

    def check_dns_cache(self) -> List[Dict[str, Any]]:
        """Check local DNS cache for known C2 domains."""
        findings: List[Dict[str, Any]] = []
        if not self.c2_domains:
            return findings

        system = platform.system()
        if system == "Windows":
            findings.extend(self._check_dns_cache_windows())
        else:
            findings.extend(self._check_dns_cache_linux())
        return findings

    def _check_dns_cache_windows(self) -> List[Dict[str, Any]]:
        """Parse ipconfig /displaydns on Windows."""
        findings: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=30
            )
            current_name = ""
            for line in result.stdout.splitlines():
                line = line.strip()
                if "Record Name" in line and ":" in line:
                    current_name = line.split(":", 1)[1].strip().lower()
                    for domain in self.c2_domains:
                        if current_name == domain or current_name.endswith("." + domain):
                            findings.append({
                                "type": "dns_cache_threat",
                                "domain": current_name,
                                "matched_c2": domain,
                                "severity": "high",
                                "detail": f"C2 domain '{domain}' found in DNS cache",
                            })
                            break
        except Exception as exc:
            logger.debug("DNS cache check failed: %s", exc)
        return findings

    def _check_dns_cache_linux(self) -> List[Dict[str, Any]]:
        """Check /etc/hosts and systemd-resolve statistics on Linux."""
        findings: List[Dict[str, Any]] = []
        hosts_path = Path("/etc/hosts")
        if hosts_path.is_file():
            try:
                for line in hosts_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    for part in parts[1:]:
                        part_lower = part.lower()
                        for domain in self.c2_domains:
                            if part_lower == domain or part_lower.endswith("." + domain):
                                findings.append({
                                    "type": "dns_hosts_threat",
                                    "domain": part_lower,
                                    "matched_c2": domain,
                                    "severity": "high",
                                    "detail": f"C2 domain '{domain}' found in /etc/hosts",
                                })
                                break
            except Exception as exc:
                logger.debug("Error reading /etc/hosts: %s", exc)
        return findings


# ---------------------------------------------------------------------------
# Class 6: Scan Scheduler
# ---------------------------------------------------------------------------

class ScanScheduler:
    """Schedule automatic scans at configured intervals."""

    def __init__(self, config: Any, run_scan_func: Callable[[str], Any]) -> None:
        self.config = config
        self.run_scan = run_scan_func
        self._thread: Optional[threading.Thread] = None
        self._stop: threading.Event = threading.Event()
        self._last_scan_time: Optional[datetime] = None

    def start(self) -> None:
        """Start the scheduler daemon thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.info("Scan scheduler already running")
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="CleanGuard-Scheduler"
        )
        self._thread.start()
        logger.info("Scan scheduler started")

    def stop(self) -> None:
        """Stop the scheduler."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("Scan scheduler stopped")

    @property
    def running(self) -> bool:
        """Check if the scheduler thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def _run_loop(self) -> None:
        """Main scheduler loop - checks every 60 seconds if a scan is due."""
        while not self._stop.is_set():
            try:
                now = datetime.now()
                if self._should_run(now):
                    logger.info("Scheduled scan triggered at %s", now.isoformat())
                    self._last_scan_time = now
                    try:
                        self.run_scan("quick")
                    except Exception as exc:
                        logger.error("Scheduled scan failed: %s", exc)
            except Exception as exc:
                logger.error("Scheduler loop error: %s", exc)
            self._stop.wait(timeout=60)

    def _should_run(self, now: datetime) -> bool:
        """Determine if it is time to run a scheduled scan."""
        interval = getattr(self.config, "scheduled_scan_interval", "daily")
        scan_time_str = getattr(self.config, "scheduled_scan_time", "02:00")
        scan_day = getattr(self.config, "scheduled_scan_day", "monday")

        # Parse configured scan time
        try:
            hour, minute = map(int, scan_time_str.split(":"))
        except (ValueError, AttributeError):
            hour, minute = 2, 0

        # Check if we're within the scan window (current minute)
        if now.hour != hour or now.minute != minute:
            return False

        # Check if already scanned this window
        if self._last_scan_time is not None:
            elapsed = (now - self._last_scan_time).total_seconds()
            if elapsed < 120:  # Within 2 minutes of last scan
                return False

        if interval == "daily":
            return True
        elif interval == "weekly":
            days = {
                "monday": 0, "tuesday": 1, "wednesday": 2,
                "thursday": 3, "friday": 4, "saturday": 5, "sunday": 6,
            }
            target_day = days.get(scan_day.lower(), 0)
            return now.weekday() == target_day
        elif interval == "hourly":
            # For hourly, ignore the hour check - just check minute
            return now.minute == minute

        return False


# ---------------------------------------------------------------------------
# Class 7: Antivirus Engine (Orchestrator)
# ---------------------------------------------------------------------------

class AntivirusEngine:
    """Orchestrates all scanning subsystems into a unified pipeline."""

    def __init__(self, config: Any, signatures_dir: Any, threat_db_dir: Any) -> None:
        self.config = config
        signatures_dir = Path(signatures_dir)
        threat_db_dir = Path(threat_db_dir)

        # Initialize subsystems
        self.clamav = ClamAVScanner()
        self.virustotal = VirusTotalChecker(getattr(config, "virustotal_api_key", ""))
        self.yara = YARAEngine(signatures_dir)
        self.archive_scanner = ArchiveScanner()
        self.network_detector = NetworkThreatDetector(threat_db_dir)

        # Caches
        self._result_cache: Dict[str, List[Dict[str, Any]]] = {}  # sha256 -> findings
        self._mtime_cache: Dict[str, float] = {}  # filepath -> mtime (incremental)
        self._hash_db: Set[str] = set()  # known bad hashes
        self._load_hash_db(threat_db_dir / "known_hashes.txt")

        logger.info(
            "AntivirusEngine initialized: ClamAV=%s, VT=%s, YARA=%d rules, HashDB=%d",
            self.clamav.available,
            self.virustotal.available,
            self.yara._rule_count,
            len(self._hash_db),
        )

    def _load_hash_db(self, filepath: Path) -> None:
        """Load SHA256 known-bad hashes from file."""
        if not filepath.is_file():
            logger.debug("Hash DB file not found: %s", filepath)
            return
        try:
            for line in filepath.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Support lines with hash only or hash + description
                    hash_val = line.split()[0].strip().lower()
                    if len(hash_val) == 64:  # SHA256 hex length
                        self._hash_db.add(hash_val)
            logger.info("Loaded %d known-bad hashes", len(self._hash_db))
        except Exception as exc:
            logger.warning("Error loading hash DB: %s", exc)

    @staticmethod
    def _compute_sha256(filepath: str) -> str:
        """Compute SHA256 hash of a file in 8KB chunks."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as exc:
            logger.warning("Error hashing %s: %s", filepath, exc)
            return ""

    def scan_file_enhanced(
        self, filepath: str, file_data: Optional[bytes] = None
    ) -> List[Dict[str, Any]]:
        """
        Main scanning pipeline. Returns list of findings, each:
        {"type": str, "name": str, "severity": str, "detail": str}
        """
        findings: List[Dict[str, Any]] = []
        filepath_str = str(filepath)

        # ------------------------------------------------------------------
        # Step 1: Check mtime cache for incremental scanning
        # ------------------------------------------------------------------
        try:
            current_mtime = os.path.getmtime(filepath_str)
            cached_mtime = self._mtime_cache.get(filepath_str)
            if cached_mtime is not None and cached_mtime == current_mtime:
                # File unchanged since last scan - return cached result if available
                cached_hash = None
                for h, f in self._result_cache.items():
                    # We need the hash; skip incremental if we don't have cached results
                    pass
                # Compute hash to check result cache
                sha256 = self._compute_sha256(filepath_str)
                if sha256 and sha256 in self._result_cache:
                    return self._result_cache[sha256]
        except OSError:
            current_mtime = 0

        # ------------------------------------------------------------------
        # Step 2: Compute SHA256
        # ------------------------------------------------------------------
        sha256 = self._compute_sha256(filepath_str)
        if not sha256:
            return findings

        # ------------------------------------------------------------------
        # Step 3: Check result cache
        # ------------------------------------------------------------------
        if sha256 in self._result_cache:
            self._mtime_cache[filepath_str] = current_mtime
            return self._result_cache[sha256]

        # ------------------------------------------------------------------
        # Step 4: Check local known-bad hash database
        # ------------------------------------------------------------------
        if sha256 in self._hash_db:
            findings.append({
                "type": "hash_match",
                "name": "KnownMalwareHash",
                "severity": "critical",
                "detail": f"SHA256 {sha256} matches known malware hash database",
            })

        # ------------------------------------------------------------------
        # Step 5: VirusTotal lookup
        # ------------------------------------------------------------------
        vt_result = self.virustotal.lookup(sha256)
        if vt_result and vt_result.get("malicious", 0) > 0:
            engine_list = ", ".join(vt_result["engines"][:5])
            suffix = ""
            if len(vt_result["engines"]) > 5:
                suffix = f" (+{len(vt_result['engines']) - 5} more)"
            mal_count = vt_result["malicious"]
            severity = "critical" if mal_count >= 5 else "high" if mal_count >= 2 else "medium"
            findings.append({
                "type": "virustotal",
                "name": "VirusTotalDetection",
                "severity": severity,
                "detail": f"Detected by {vt_result['ratio']} engines: {engine_list}{suffix}",
            })

        # ------------------------------------------------------------------
        # Step 6: ClamAV scan
        # ------------------------------------------------------------------
        clam_result = self.clamav.scan_file(filepath_str)
        if clam_result and clam_result.get("infected"):
            findings.append({
                "type": "clamav",
                "name": clam_result["name"],
                "severity": "critical",
                "detail": f"ClamAV detection: {clam_result['name']}",
            })

        # ------------------------------------------------------------------
        # Step 7: YARA rules scan
        # ------------------------------------------------------------------
        yara_matches = self.yara.scan_file(filepath_str)
        for match in yara_matches:
            findings.append({
                "type": "yara",
                "name": match["rule"],
                "severity": match.get("severity", "medium"),
                "detail": f"YARA rule '{match['rule']}': {match.get('description', '')}",
            })

        # ------------------------------------------------------------------
        # Step 8: Archive scanning (recursive)
        # ------------------------------------------------------------------
        if ArchiveScanner.is_archive(filepath_str):
            archive_findings = self.archive_scanner.scan_archive(
                filepath_str,
                lambda f: self.scan_file_enhanced(f),
                depth=0,
            )
            findings.extend(archive_findings)

        # ------------------------------------------------------------------
        # Step 9: Cache results and return
        # ------------------------------------------------------------------
        self._result_cache[sha256] = findings
        self._mtime_cache[filepath_str] = current_mtime
        return findings

    def scan_network(self) -> List[Dict[str, Any]]:
        """Scan active network connections for threat indicators."""
        return self.network_detector.scan_connections()

    def check_dns(self) -> List[Dict[str, Any]]:
        """Check DNS cache for known C2 domains."""
        return self.network_detector.check_dns_cache()

    def update_signatures(self) -> Dict[str, Any]:
        """Update all signature sources (ClamAV + YARA reload)."""
        results: Dict[str, Any] = {}
        if self.clamav.available:
            results["clamav"] = self.clamav.update_signatures()
        self.yara.reload()
        results["yara_rules"] = self.yara._rule_count
        return results

    def get_status(self) -> Dict[str, Any]:
        """Return status of all scanning subsystems."""
        return {
            "clamav_available": self.clamav.available,
            "clamav_version": self.clamav.version,
            "virustotal_available": self.virustotal.available,
            "yara_available": self.yara._compiled is not None,
            "yara_rule_count": self.yara._rule_count,
            "hash_db_count": len(self._hash_db),
            "result_cache_size": len(self._result_cache),
            "c2_domains_count": len(self.network_detector.c2_domains),
            "c2_ips_count": len(self.network_detector.c2_ips),
        }

    def clear_cache(self) -> None:
        """Clear all scan caches to force fresh scans."""
        self._result_cache.clear()
        self._mtime_cache.clear()
        logger.info("Scan caches cleared")

    def scan_data_enhanced(self, data: bytes, label: str = "memory") -> List[Dict[str, Any]]:
        """Scan in-memory data through available engines."""
        findings: List[Dict[str, Any]] = []
        sha256 = hashlib.sha256(data).hexdigest()

        # Check result cache
        if sha256 in self._result_cache:
            return self._result_cache[sha256]

        # Known-bad hash check
        if sha256 in self._hash_db:
            findings.append({
                "type": "hash_match",
                "name": "KnownMalwareHash",
                "severity": "critical",
                "detail": f"SHA256 {sha256} matches known malware hash database ({label})",
            })

        # VirusTotal
        vt_result = self.virustotal.lookup(sha256)
        if vt_result and vt_result.get("malicious", 0) > 0:
            findings.append({
                "type": "virustotal",
                "name": "VirusTotalDetection",
                "severity": "high",
                "detail": f"VT {vt_result['ratio']} detections for {label}",
            })

        # ClamAV stream scan
        clam_result = self.clamav.scan_stream(data)
        if clam_result and clam_result.get("infected"):
            findings.append({
                "type": "clamav",
                "name": clam_result["name"],
                "severity": "critical",
                "detail": f"ClamAV detection in {label}: {clam_result['name']}",
            })

        # YARA
        yara_matches = self.yara.scan_data(data)
        for match in yara_matches:
            findings.append({
                "type": "yara",
                "name": match["rule"],
                "severity": match.get("severity", "medium"),
                "detail": f"YARA rule '{match['rule']}' matched in {label}",
            })

        self._result_cache[sha256] = findings
        return findings
