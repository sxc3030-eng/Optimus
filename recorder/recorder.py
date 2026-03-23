"""
SentinelOS — RecordAgent v1.0.0 (Forensic Recorder)
Records EVERYTHING during security incidents for forensic analysis.
Monitors system activity and creates detailed incident reports.

Port: 8860
Architecture:
    RecordAgent (port 8860)
        ├── SessionRecorder    — records all network sessions/connections
        ├── ProcessMonitor     — tracks process creation/termination
        ├── FileWatcher        — monitors file system changes in real-time
        ├── NetworkLogger      — captures connection metadata (not payload)
        ├── IncidentTimeline   — unified timeline of all recorded events
        ├── ReportGenerator    — generates incident reports (JSON format)
        ├── WebSocket Server   — serves state to Cortex
        └── Storage Manager    — manages recording storage/rotation

Usage: python recorder.py [--headless] [--port 8860]
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
import uuid
import shutil
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[WARN] websockets not installed. Install with: pip install websockets")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("[WARN] psutil not installed. Install with: pip install psutil")

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

# ── Shared modules ──────────────────────────────────────────
try:
    from permissions import PermissionManager
    HAS_PERMISSIONS = True
except ImportError:
    HAS_PERMISSIONS = False

try:
    from toast_notifications import toast_event
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
WS_PORT = 8860
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

RECORDER_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(RECORDER_DIR)
LOG_DIR = os.path.join(RECORDER_DIR, "logs")
RECORDINGS_DIR = os.path.join(RECORDER_DIR, "recordings")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(RECORDINGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RecordAgent] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "recorder.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.RecordAgent")

# Storage limits
MAX_STORAGE_MB = 500
MAX_TIMELINE_EVENTS = 5000
MAX_RECENT_EVENTS = 30
MAX_TIMELINE_RESPONSE = 50

# Watched directories per platform
if IS_WINDOWS:
    _home = os.path.expanduser("~")
    WATCHED_DIRS = [
        os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32"),
        os.path.join(_home, "Desktop"),
        os.path.join(_home, "Downloads"),
        os.environ.get("TEMP", os.path.join(_home, "AppData", "Local", "Temp")),
    ]
elif IS_LINUX:
    _home = os.path.expanduser("~")
    WATCHED_DIRS = [
        "/etc",
        "/tmp",
        "/var/log",
        _home,
    ]
else:
    _home = os.path.expanduser("~")
    WATCHED_DIRS = ["/tmp", _home]

# Filter watched dirs to only those that exist
WATCHED_DIRS = [d for d in WATCHED_DIRS if os.path.isdir(d)]


# ═══════════════════════════════════════════════════════════════════════════
# SESSION RECORDER — records all network sessions/connections
# ═══════════════════════════════════════════════════════════════════════════

class SessionRecorder:
    """Records network connection sessions using psutil."""

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()
        self.sessions: deque = deque(maxlen=2000)
        self._known_conns: dict = {}  # (laddr, raddr) -> start_time
        self.total_logged = 0

    def start(self):
        self._running = True
        t = threading.Thread(target=self._record_loop, daemon=True)
        t.start()
        logger.info("[SessionRecorder] Started")

    def stop(self):
        self._running = False

    def _record_loop(self):
        while self._running:
            try:
                self._snapshot_connections()
            except Exception as e:
                logger.error(f"[SessionRecorder] Error: {e}")
            time.sleep(3 if _engine.mode == "normal" else 1)

    def _snapshot_connections(self):
        if not HAS_PSUTIL:
            return
        now = time.time()
        current = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []

        for c in conns:
            if not c.laddr or not c.raddr:
                continue
            key = (c.laddr, c.raddr)
            proto = "TCP" if c.type == 1 else "UDP"
            current[key] = {
                "src_ip": c.laddr.ip,
                "src_port": c.laddr.port,
                "dst_ip": c.raddr.ip,
                "dst_port": c.raddr.port,
                "protocol": proto,
                "status": c.status if hasattr(c, "status") else "UNKNOWN",
                "pid": c.pid,
            }

        # Detect new connections
        with self._lock:
            for key, info in current.items():
                if key not in self._known_conns:
                    self._known_conns[key] = now
                    session = {
                        "id": f"SESS-{self.total_logged:06d}",
                        "src_ip": info["src_ip"],
                        "src_port": info["src_port"],
                        "dst_ip": info["dst_ip"],
                        "dst_port": info["dst_port"],
                        "protocol": info["protocol"],
                        "status": info["status"],
                        "pid": info["pid"],
                        "started": now,
                        "ended": None,
                        "duration": 0,
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                    }
                    # Try to get process name
                    try:
                        if info["pid"]:
                            proc = psutil.Process(info["pid"])
                            session["process_name"] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        session["process_name"] = "unknown"

                    self.sessions.append(session)
                    self.total_logged += 1

            # Detect ended connections
            ended_keys = set(self._known_conns.keys()) - set(current.keys())
            for key in ended_keys:
                start_time = self._known_conns.pop(key, now)
                # Update last matching session's end time
                for s in reversed(self.sessions):
                    laddr_match = (s["src_ip"], s["src_port"]) == (key[0].ip if hasattr(key[0], "ip") else key[0][0],
                                                                    key[0].port if hasattr(key[0], "port") else key[0][1])
                    if laddr_match and s["ended"] is None:
                        s["ended"] = now
                        s["duration"] = round(now - s["started"], 2)
                        break

    def get_recent(self, limit: int = 20) -> list:
        with self._lock:
            return list(self.sessions)[-limit:]

    def get_stats(self) -> dict:
        return {
            "active": self._running,
            "total_logged": self.total_logged,
        }


# ═══════════════════════════════════════════════════════════════════════════
# PROCESS MONITOR — tracks process creation/termination
# ═══════════════════════════════════════════════════════════════════════════

class ProcessMonitor:
    """Monitors process creation and termination using psutil."""

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()
        self._known_pids: dict = {}  # pid -> info
        self.events: deque = deque(maxlen=2000)
        self.current_count = 0
        self.new_last_min = 0
        self._new_last_min_ts: list = []

    def start(self):
        self._running = True
        self._initial_snapshot()
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()
        logger.info("[ProcessMonitor] Started")

    def stop(self):
        self._running = False

    def _initial_snapshot(self):
        if not HAS_PSUTIL:
            return
        for proc in psutil.process_iter(["pid", "name", "username", "create_time"]):
            try:
                info = proc.info
                self._known_pids[info["pid"]] = {
                    "pid": info["pid"],
                    "name": info.get("name", "unknown"),
                    "username": info.get("username", ""),
                    "create_time": info.get("create_time", 0),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self.current_count = len(self._known_pids)

    def _monitor_loop(self):
        while self._running:
            try:
                self._check_processes()
            except Exception as e:
                logger.error(f"[ProcessMonitor] Error: {e}")
            time.sleep(2 if _engine.mode == "normal" else 0.5)

    def _check_processes(self):
        if not HAS_PSUTIL:
            return
        now = time.time()
        current_pids = {}

        for proc in psutil.process_iter(["pid", "name", "username", "create_time", "ppid", "cmdline"]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids[pid] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        with self._lock:
            # Detect new processes
            for pid, info in current_pids.items():
                if pid not in self._known_pids:
                    cmdline = ""
                    try:
                        cl = info.get("cmdline")
                        if cl:
                            cmdline = " ".join(cl)[:200]
                    except Exception:
                        pass
                    event = {
                        "type": "process_created",
                        "ts": now,
                        "pid": pid,
                        "name": info.get("name", "unknown"),
                        "username": info.get("username", ""),
                        "ppid": info.get("ppid", 0),
                        "cmdline": cmdline,
                        "severity": "info",
                    }
                    # Flag suspicious processes
                    name_lower = (info.get("name") or "").lower()
                    suspicious_names = [
                        "nc", "ncat", "netcat", "nmap", "mimikatz", "powershell",
                        "cmd.exe", "certutil", "bitsadmin", "wscript", "cscript",
                        "mshta", "regsvr32", "rundll32",
                    ]
                    if any(s in name_lower for s in suspicious_names):
                        event["severity"] = "warning"
                        event["suspicious"] = True

                    self.events.append(event)
                    self._new_last_min_ts.append(now)

            # Detect terminated processes
            for pid, info in self._known_pids.items():
                if pid not in current_pids:
                    self.events.append({
                        "type": "process_terminated",
                        "ts": now,
                        "pid": pid,
                        "name": info.get("name", "unknown"),
                        "severity": "info",
                    })

            self._known_pids = {pid: {
                "pid": pid,
                "name": info.get("name", "unknown"),
                "username": info.get("username", ""),
                "create_time": info.get("create_time", 0),
            } for pid, info in current_pids.items()}
            self.current_count = len(self._known_pids)

            # Count new processes in last 60s
            cutoff = now - 60
            self._new_last_min_ts = [t for t in self._new_last_min_ts if t > cutoff]
            self.new_last_min = len(self._new_last_min_ts)

    def get_processes(self) -> list:
        """Return current process list with stats."""
        if not HAS_PSUTIL:
            return []
        result = []
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "create_time"]):
            try:
                info = proc.info
                result.append({
                    "pid": info["pid"],
                    "name": info.get("name", "unknown"),
                    "username": info.get("username", ""),
                    "cpu_percent": info.get("cpu_percent", 0),
                    "memory_percent": round(info.get("memory_percent", 0), 2),
                    "create_time": info.get("create_time", 0),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return result

    def get_stats(self) -> dict:
        return {
            "active": self._running,
            "current_count": self.current_count,
            "new_last_min": self.new_last_min,
        }


# ═══════════════════════════════════════════════════════════════════════════
# FILE WATCHER — monitors file system changes in real-time
# ═══════════════════════════════════════════════════════════════════════════

class FileWatcher:
    """Monitors key directories for file changes using polling with os.scandir()."""

    def __init__(self, watched_dirs: list):
        self._running = False
        self._lock = threading.Lock()
        self.watched_dirs = watched_dirs
        self._snapshots: dict = {}  # dir -> {path: (mtime, size)}
        self.events: deque = deque(maxlen=2000)
        self.changes_detected = 0

    def start(self):
        self._running = True
        self._take_initial_snapshots()
        t = threading.Thread(target=self._watch_loop, daemon=True)
        t.start()
        logger.info(f"[FileWatcher] Started — watching {len(self.watched_dirs)} directories")

    def stop(self):
        self._running = False

    def _scan_dir(self, directory: str, max_depth: int = 1) -> dict:
        """Scan directory and return {path: (mtime, size)} dict. Limited depth for performance."""
        result = {}
        try:
            for entry in os.scandir(directory):
                try:
                    stat = entry.stat(follow_symlinks=False)
                    result[entry.path] = (stat.st_mtime, stat.st_size)
                    # Recurse one level for subdirectories
                    if entry.is_dir(follow_symlinks=False) and max_depth > 0:
                        # Limit: skip very large dirs
                        try:
                            sub_count = 0
                            for sub_entry in os.scandir(entry.path):
                                try:
                                    sub_stat = sub_entry.stat(follow_symlinks=False)
                                    result[sub_entry.path] = (sub_stat.st_mtime, sub_stat.st_size)
                                    sub_count += 1
                                    if sub_count > 200:
                                        break
                                except (OSError, PermissionError):
                                    pass
                        except (OSError, PermissionError):
                            pass
                except (OSError, PermissionError):
                    pass
        except (OSError, PermissionError):
            pass
        return result

    def _take_initial_snapshots(self):
        for d in self.watched_dirs:
            self._snapshots[d] = self._scan_dir(d)
            logger.info(f"[FileWatcher] Baseline snapshot: {d} ({len(self._snapshots[d])} entries)")

    def _watch_loop(self):
        while self._running:
            try:
                self._check_changes()
            except Exception as e:
                logger.error(f"[FileWatcher] Error: {e}")
            time.sleep(10 if _engine.mode == "normal" else 3)

    def _check_changes(self):
        now = time.time()
        for d in self.watched_dirs:
            current = self._scan_dir(d)
            old = self._snapshots.get(d, {})

            with self._lock:
                # New files
                for path in set(current.keys()) - set(old.keys()):
                    self.events.append({
                        "type": "file_created",
                        "ts": now,
                        "path": path,
                        "dir": d,
                        "size": current[path][1],
                        "severity": "info",
                    })
                    self.changes_detected += 1

                # Deleted files
                for path in set(old.keys()) - set(current.keys()):
                    self.events.append({
                        "type": "file_deleted",
                        "ts": now,
                        "path": path,
                        "dir": d,
                        "severity": "warning",
                    })
                    self.changes_detected += 1

                # Modified files
                for path in set(current.keys()) & set(old.keys()):
                    if current[path][0] != old[path][0]:
                        self.events.append({
                            "type": "file_modified",
                            "ts": now,
                            "path": path,
                            "dir": d,
                            "old_size": old[path][1],
                            "new_size": current[path][1],
                            "severity": "info",
                        })
                        self.changes_detected += 1

            self._snapshots[d] = current

    def get_stats(self) -> dict:
        return {
            "active": self._running,
            "changes_detected": self.changes_detected,
            "dirs_watched": len(self.watched_dirs),
        }


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK LOGGER — captures connection metadata (not payload)
# ═══════════════════════════════════════════════════════════════════════════

class NetworkLogger:
    """Captures network connection metadata using psutil net_io_counters."""

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()
        self.snapshots: deque = deque(maxlen=500)
        self._last_io = None

    def start(self):
        self._running = True
        if HAS_PSUTIL:
            self._last_io = psutil.net_io_counters()
        t = threading.Thread(target=self._log_loop, daemon=True)
        t.start()
        logger.info("[NetworkLogger] Started")

    def stop(self):
        self._running = False

    def _log_loop(self):
        while self._running:
            try:
                self._capture_snapshot()
            except Exception as e:
                logger.error(f"[NetworkLogger] Error: {e}")
            time.sleep(5 if _engine.mode == "normal" else 2)

    def _capture_snapshot(self):
        if not HAS_PSUTIL:
            return
        now = time.time()
        io = psutil.net_io_counters()
        delta_sent = io.bytes_sent - (self._last_io.bytes_sent if self._last_io else 0)
        delta_recv = io.bytes_recv - (self._last_io.bytes_recv if self._last_io else 0)

        snapshot = {
            "ts": now,
            "bytes_sent": io.bytes_sent,
            "bytes_recv": io.bytes_recv,
            "packets_sent": io.packets_sent,
            "packets_recv": io.packets_recv,
            "delta_sent": delta_sent,
            "delta_recv": delta_recv,
            "errin": io.errin,
            "errout": io.errout,
            "dropin": io.dropin,
            "dropout": io.dropout,
        }
        with self._lock:
            self.snapshots.append(snapshot)
        self._last_io = io

    def get_current_connections(self) -> list:
        """Get current network connections with metadata."""
        if not HAS_PSUTIL:
            return []
        result = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []

        for c in conns:
            entry = {
                "fd": c.fd,
                "family": "IPv4" if c.family.value == 2 else "IPv6",
                "type": "TCP" if c.type.value == 1 else "UDP",
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status if hasattr(c, "status") else "",
                "pid": c.pid,
            }
            # Try to get process name
            if c.pid:
                try:
                    proc = psutil.Process(c.pid)
                    entry["process"] = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    entry["process"] = "unknown"
            result.append(entry)
        return result

    def get_stats(self) -> dict:
        if self.snapshots:
            last = self.snapshots[-1]
            return {
                "bytes_sent": last["bytes_sent"],
                "bytes_recv": last["bytes_recv"],
                "delta_sent": last["delta_sent"],
                "delta_recv": last["delta_recv"],
            }
        return {"bytes_sent": 0, "bytes_recv": 0, "delta_sent": 0, "delta_recv": 0}


# ═══════════════════════════════════════════════════════════════════════════
# INCIDENT TIMELINE — unified chronological timeline
# ═══════════════════════════════════════════════════════════════════════════

class IncidentTimeline:
    """Unified chronological timeline of all recorded events with severity levels."""

    def __init__(self):
        self._lock = threading.Lock()
        self.events: deque = deque(maxlen=MAX_TIMELINE_EVENTS)
        self.total_events = 0

    def add(self, source: str, event_type: str, severity: str, data: dict):
        with self._lock:
            entry = {
                "id": f"EVT-{self.total_events:08d}",
                "ts": time.time(),
                "source": source,
                "type": event_type,
                "severity": severity,
                "data": data,
            }
            self.events.append(entry)
            self.total_events += 1
            return entry

    def get_events(self, limit: int = 50, severity: Optional[str] = None,
                   source: Optional[str] = None, since: Optional[float] = None) -> list:
        with self._lock:
            filtered = list(self.events)
        if severity:
            filtered = [e for e in filtered if e["severity"] == severity]
        if source:
            filtered = [e for e in filtered if e["source"] == source]
        if since:
            filtered = [e for e in filtered if e["ts"] >= since]
        return filtered[-limit:]

    def get_recent(self, limit: int = MAX_RECENT_EVENTS) -> list:
        with self._lock:
            return list(self.events)[-limit:]


# ═══════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR — generates incident reports (JSON format)
# ═══════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generates JSON incident reports from recorded data."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reports: list = []
        self._report_counter = 0

    def generate(self, engine, minutes: int = 30) -> dict:
        """Generate an incident report covering the last N minutes."""
        now = time.time()
        since = now - (minutes * 60)

        timeline_events = engine.timeline.get_events(limit=5000, since=since)

        # Gather session data
        sessions = [s for s in engine.session_recorder.sessions if s["started"] >= since]

        # Gather process events
        process_events = [e for e in engine.process_monitor.events if e["ts"] >= since]

        # Gather file events
        file_events = [e for e in engine.file_watcher.events if e["ts"] >= since]

        # Network stats
        net_snapshots = [s for s in engine.network_logger.snapshots if s["ts"] >= since]

        # Severity counts
        severity_counts = {"info": 0, "warning": 0, "critical": 0}
        for evt in timeline_events:
            sev = evt.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        self._report_counter += 1
        report_id = f"RPT-{self._report_counter:03d}"

        report = {
            "id": report_id,
            "created": now,
            "created_iso": datetime.now().isoformat(),
            "time_window": {
                "from": since,
                "to": now,
                "minutes": minutes,
            },
            "summary": {
                "total_events": len(timeline_events),
                "severity_counts": severity_counts,
                "sessions_recorded": len(sessions),
                "process_events": len(process_events),
                "file_changes": len(file_events),
                "network_snapshots": len(net_snapshots),
            },
            "incident": None,
            "sessions": sessions[-100:],  # cap at 100
            "process_events": process_events[-200:],
            "file_events": file_events[-200:],
            "network_stats": net_snapshots[-50:],
            "timeline": timeline_events[-500:],
        }

        # Add incident info if active
        if engine.current_incident:
            report["incident"] = engine.current_incident.copy()

        # Save to disk
        filename = f"report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(RECORDINGS_DIR, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
            size_kb = os.path.getsize(filepath) / 1024
            logger.info(f"[ReportGenerator] Report saved: {filepath} ({size_kb:.1f} KB)")
        except Exception as e:
            logger.error(f"[ReportGenerator] Failed to save report: {e}")
            size_kb = 0

        report_meta = {
            "id": report_id,
            "created": now,
            "events_count": len(timeline_events),
            "size_kb": round(size_kb, 1),
            "filepath": filepath,
            "filename": filename,
        }
        with self._lock:
            self.reports.append(report_meta)

        return report

    def get_report(self, report_id: str) -> Optional[dict]:
        """Load a report from disk by ID."""
        with self._lock:
            meta = None
            for r in self.reports:
                if r["id"] == report_id:
                    meta = r
                    break
        if not meta:
            return None
        try:
            with open(meta["filepath"], "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"[ReportGenerator] Failed to load report {report_id}: {e}")
            return None

    def get_reports_list(self) -> list:
        with self._lock:
            return [
                {"id": r["id"], "created": r["created"], "events_count": r["events_count"], "size_kb": r["size_kb"]}
                for r in self.reports
            ]


# ═══════════════════════════════════════════════════════════════════════════
# STORAGE MANAGER — manages recording storage/rotation
# ═══════════════════════════════════════════════════════════════════════════

class StorageManager:
    """Manages recording storage and log rotation."""

    def __init__(self, recordings_dir: str, max_mb: float = MAX_STORAGE_MB):
        self.recordings_dir = recordings_dir
        self.max_mb = max_mb
        self._running = False

    def start(self):
        self._running = True
        t = threading.Thread(target=self._rotation_loop, daemon=True)
        t.start()
        logger.info(f"[StorageManager] Started — max storage: {self.max_mb} MB")

    def stop(self):
        self._running = False

    def _rotation_loop(self):
        while self._running:
            try:
                self._check_and_rotate()
            except Exception as e:
                logger.error(f"[StorageManager] Error: {e}")
            time.sleep(60)

    def _check_and_rotate(self):
        used = self.get_storage_used_mb()
        if used > self.max_mb:
            logger.warning(f"[StorageManager] Storage {used:.1f} MB exceeds limit {self.max_mb} MB — rotating")
            self._rotate()

    def _rotate(self):
        """Delete oldest recordings until under limit."""
        files = []
        for f in os.listdir(self.recordings_dir):
            fp = os.path.join(self.recordings_dir, f)
            if os.path.isfile(fp):
                files.append((os.path.getmtime(fp), fp))
        files.sort()  # oldest first

        while self.get_storage_used_mb() > self.max_mb * 0.8 and files:
            _, oldest = files.pop(0)
            try:
                os.remove(oldest)
                logger.info(f"[StorageManager] Rotated (deleted): {oldest}")
            except OSError as e:
                logger.error(f"[StorageManager] Failed to delete {oldest}: {e}")

    def get_storage_used_mb(self) -> float:
        total = 0
        try:
            for f in os.listdir(self.recordings_dir):
                fp = os.path.join(self.recordings_dir, f)
                if os.path.isfile(fp):
                    total += os.path.getsize(fp)
        except OSError:
            pass
        return total / (1024 * 1024)


# ═══════════════════════════════════════════════════════════════════════════
# RECORD ENGINE — main orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class RecordEngine:
    """Main forensic recording engine. Orchestrates all monitors."""

    def __init__(self):
        self.mode = "normal"  # "normal" or "incident"
        self.started_at = time.time()
        self._running = False

        # Sub-components
        self.session_recorder = SessionRecorder()
        self.process_monitor = ProcessMonitor()
        self.file_watcher = FileWatcher(WATCHED_DIRS)
        self.network_logger = NetworkLogger()
        self.timeline = IncidentTimeline()
        self.report_generator = ReportGenerator()
        self.storage_manager = StorageManager(RECORDINGS_DIR, MAX_STORAGE_MB)

        # Permissions & notifications
        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

        # Incident tracking
        self.current_incident: Optional[dict] = None
        self._incident_counter = 0
        self.total_incidents = 0

    def _check_perm(self, perm_type="execute"):
        if not self._perm or not self._perm.is_enabled():
            return True
        if self._perm.locked and not self._auth_user:
            return False
        return self._perm.check(self._auth_user, "recorder", perm_type)

    def start(self):
        self._running = True
        self.started_at = time.time()

        self.session_recorder.start()
        self.process_monitor.start()
        self.file_watcher.start()
        self.network_logger.start()
        self.storage_manager.start()

        # Start the event collector thread
        t = threading.Thread(target=self._event_collector, daemon=True)
        t.start()

        self.timeline.add("system", "recorder_started", "info", {
            "message": "RecordAgent started",
            "mode": self.mode,
            "watched_dirs": WATCHED_DIRS,
        })

        logger.info("[RecordEngine] All monitors started")

    def stop(self):
        self._running = False
        self.session_recorder.stop()
        self.process_monitor.stop()
        self.file_watcher.stop()
        self.network_logger.stop()
        self.storage_manager.stop()
        logger.info("[RecordEngine] All monitors stopped")

    def _event_collector(self):
        """Periodically collects events from all monitors and feeds them into the timeline."""
        processed_session = 0
        processed_process = 0
        processed_file = 0

        while self._running:
            try:
                # Collect session events
                sessions = list(self.session_recorder.sessions)
                for s in sessions[processed_session:]:
                    self.timeline.add("session", "new_connection", "info", {
                        "id": s["id"],
                        "src": f"{s['src_ip']}:{s['src_port']}",
                        "dst": f"{s['dst_ip']}:{s['dst_port']}",
                        "protocol": s["protocol"],
                        "process": s.get("process_name", "unknown"),
                    })
                processed_session = len(sessions)

                # Collect process events
                proc_events = list(self.process_monitor.events)
                for e in proc_events[processed_process:]:
                    self.timeline.add("process", e["type"], e.get("severity", "info"), {
                        "pid": e["pid"],
                        "name": e["name"],
                        "cmdline": e.get("cmdline", ""),
                    })
                processed_process = len(proc_events)

                # Collect file events
                file_events = list(self.file_watcher.events)
                for e in file_events[processed_file:]:
                    self.timeline.add("file", e["type"], e.get("severity", "info"), {
                        "path": e["path"],
                        "dir": e.get("dir", ""),
                    })
                processed_file = len(file_events)

            except Exception as e:
                logger.error(f"[EventCollector] Error: {e}")

            time.sleep(2)

    def start_incident(self) -> dict:
        """Switch to intensive recording mode and start a new incident."""
        self._incident_counter += 1
        self.total_incidents += 1
        self.mode = "incident"

        self.current_incident = {
            "id": f"INC-{self._incident_counter:03d}",
            "started": time.time(),
            "started_iso": datetime.now().isoformat(),
            "events": 0,
            "status": "active",
        }

        self.timeline.add("system", "incident_started", "critical", {
            "incident_id": self.current_incident["id"],
            "message": f"Incident {self.current_incident['id']} started — intensive recording mode active",
        })

        logger.warning(f"[RecordEngine] INCIDENT STARTED: {self.current_incident['id']} — mode=incident")
        if HAS_TOAST:
            toast_event("Recorder", "Recording started — incident mode active")
        return self.current_incident

    def stop_incident(self) -> Optional[dict]:
        """Stop intensive recording and return to normal mode."""
        if not self.current_incident:
            return None

        self.current_incident["ended"] = time.time()
        self.current_incident["ended_iso"] = datetime.now().isoformat()
        self.current_incident["status"] = "closed"
        self.current_incident["duration"] = round(
            self.current_incident["ended"] - self.current_incident["started"], 2
        )

        # Count events during incident
        incident_events = self.timeline.get_events(
            limit=99999, since=self.current_incident["started"]
        )
        self.current_incident["events"] = len(incident_events)

        self.timeline.add("system", "incident_stopped", "warning", {
            "incident_id": self.current_incident["id"],
            "duration": self.current_incident["duration"],
            "events": self.current_incident["events"],
            "message": f"Incident {self.current_incident['id']} closed",
        })

        closed = self.current_incident.copy()
        self.mode = "normal"
        self.current_incident = None

        logger.info(f"[RecordEngine] Incident closed — returning to normal mode")
        if HAS_TOAST:
            toast_event("Recorder", "Recording stopped")
        return closed

    def get_state(self) -> dict:
        """Build full state for WebSocket broadcast."""
        now = time.time()

        # Update incident event count
        if self.current_incident:
            inc_events = self.timeline.get_events(
                limit=99999, since=self.current_incident["started"]
            )
            self.current_incident["events"] = len(inc_events)

        return {
            "type": "state",
            "version": VERSION,
            "ts": now,
            "mode": self.mode,
            "recording": {
                "active": self._running,
                "started_at": self.started_at,
                "events_recorded": self.timeline.total_events,
                "storage_used_mb": round(self.storage_manager.get_storage_used_mb(), 2),
                "storage_max_mb": MAX_STORAGE_MB,
            },
            "monitors": {
                "sessions": self.session_recorder.get_stats(),
                "processes": self.process_monitor.get_stats(),
                "files": self.file_watcher.get_stats(),
            },
            "current_incident": self.current_incident,
            "recent_events": self.timeline.get_recent(MAX_RECENT_EVENTS),
            "timeline": self.timeline.get_recent(MAX_TIMELINE_RESPONSE),
            "reports": self.report_generator.get_reports_list(),
            "network": self.network_logger.get_stats(),
            "stats": {
                "total_events": self.timeline.total_events,
                "total_incidents": self.total_incidents,
                "total_reports": len(self.report_generator.reports),
                "uptime": round(now - self.started_at, 1),
            },
        }


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER
# ═══════════════════════════════════════════════════════════════════════════

_engine = RecordEngine()
_ws_clients: set = set()


async def handle_ws(websocket, path=None):
    """Handle incoming WebSocket connections and commands."""
    _ws_clients.add(websocket)
    logger.info(f"[WS] Client connected ({len(_ws_clients)} total)")
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                cmd = msg.get("cmd", "")
                response = None

                if cmd == "get_state":
                    response = _engine.get_state()

                elif cmd == "start_incident":
                    if not _engine._check_perm("execute"):
                        response = {"type": "error", "message": "Permission denied: start_incident"}
                    else:
                        incident = _engine.start_incident()
                        response = {"type": "incident_started", "incident": incident}

                elif cmd == "stop_incident":
                    if not _engine._check_perm("execute"):
                        response = {"type": "error", "message": "Permission denied: stop_incident"}
                    else:
                        closed = _engine.stop_incident()
                        response = {"type": "incident_stopped", "incident": closed}

                elif cmd == "get_timeline":
                    limit = msg.get("limit", 50)
                    severity = msg.get("severity")
                    source = msg.get("source")
                    since = msg.get("since")
                    events = _engine.timeline.get_events(
                        limit=limit, severity=severity, source=source, since=since
                    )
                    response = {"type": "timeline", "events": events, "count": len(events)}

                elif cmd == "generate_report":
                    if not _engine._check_perm("execute"):
                        response = {"type": "error", "message": "Permission denied: generate_report"}
                    else:
                        minutes = msg.get("minutes", 30)
                        report = _engine.report_generator.generate(_engine, minutes=minutes)
                        report_id = report["id"]
                        if HAS_TOAST:
                            toast_event("Recorder", f"Incident report generated: {report_id}")
                        response = {
                            "type": "report_generated",
                            "report_id": report_id,
                            "summary": report["summary"],
                        }

                elif cmd == "get_report":
                    report_id = msg.get("report_id", "")
                    report = _engine.report_generator.get_report(report_id)
                    if report:
                        response = {"type": "report", "report": report}
                    else:
                        response = {"type": "error", "message": f"Report {report_id} not found"}

                elif cmd == "get_processes":
                    processes = _engine.process_monitor.get_processes()
                    response = {"type": "processes", "processes": processes, "count": len(processes)}

                elif cmd == "get_connections":
                    conns = _engine.network_logger.get_current_connections()
                    response = {"type": "connections", "connections": conns, "count": len(conns)}

                # ── Permission management commands ──────────────────────
                elif cmd == "perm_get_status":
                    if _engine._perm:
                        response = {
                            "type": "perm_status",
                            "enabled": _engine._perm.is_enabled(),
                            "locked": getattr(_engine._perm, "locked", False),
                            "auth_user": _engine._auth_user,
                        }
                    else:
                        response = {"type": "perm_status", "enabled": False, "locked": False, "auth_user": None}

                elif cmd == "perm_enable":
                    if _engine._perm:
                        _engine._perm.enable()
                        response = {"type": "perm_enabled", "success": True}
                    else:
                        response = {"type": "error", "message": "Permissions module not available"}

                elif cmd == "perm_authenticate":
                    username = msg.get("username", "")
                    password = msg.get("password", "")
                    if _engine._perm and hasattr(_engine._perm, "authenticate"):
                        if _engine._perm.authenticate(username, password):
                            _engine._auth_user = username
                            response = {"type": "perm_authenticated", "success": True, "user": username}
                        else:
                            response = {"type": "perm_authenticated", "success": False}
                    else:
                        response = {"type": "error", "message": "Permissions module not available"}

                elif cmd == "perm_lock":
                    if _engine._perm:
                        _engine._perm.locked = True
                        response = {"type": "perm_locked", "success": True}
                    else:
                        response = {"type": "error", "message": "Permissions module not available"}

                elif cmd == "perm_unlock":
                    if _engine._perm:
                        _engine._perm.locked = False
                        response = {"type": "perm_unlock", "success": True}
                    else:
                        response = {"type": "error", "message": "Permissions module not available"}

                else:
                    response = {"type": "error", "message": f"Unknown command: {cmd}"}

                if response:
                    await websocket.send(json.dumps(response, default=str))

            except json.JSONDecodeError:
                await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        _ws_clients.discard(websocket)
        logger.info(f"[WS] Client disconnected ({len(_ws_clients)} remaining)")


async def broadcast_loop():
    """Broadcast state to all connected clients every 5 seconds."""
    while True:
        if _ws_clients:
            try:
                state = json.dumps(_engine.get_state(), default=str)
                await asyncio.gather(
                    *[c.send(state) for c in _ws_clients.copy()],
                    return_exceptions=True,
                )
            except Exception:
                pass
        await asyncio.sleep(5)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    headless = "--headless" in sys.argv

    # Parse port override
    port = WS_PORT
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            try:
                port = int(sys.argv[i + 1])
            except ValueError:
                pass

    logger.info("=" * 60)
    logger.info(f"  SentinelOS RecordAgent v{VERSION} (Forensic Recorder)")
    logger.info(f"  WebSocket port: {port}")
    logger.info(f"  Mode: {'headless' if headless else 'GUI'}")
    logger.info(f"  Platform: {'Windows' if IS_WINDOWS else 'Linux' if IS_LINUX else sys.platform}")
    logger.info(f"  Watched dirs: {WATCHED_DIRS}")
    logger.info(f"  Storage dir: {RECORDINGS_DIR}")
    logger.info(f"  Max storage: {MAX_STORAGE_MB} MB")
    logger.info("=" * 60)

    _engine.start()

    if headless or not HAS_WEBVIEW:
        # Headless mode: just run WebSocket server
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run():
            server = await websockets.serve(handle_ws, "localhost", port)
            logger.info(f"[RecordAgent] WebSocket server on ws://localhost:{port}")
            asyncio.create_task(broadcast_loop())
            await asyncio.Future()  # Run forever

        try:
            loop.run_until_complete(run())
        except KeyboardInterrupt:
            pass
        finally:
            _engine.stop()
            logger.info("[RecordAgent] Shutdown.")
    else:
        # GUI mode with pywebview
        loop = asyncio.new_event_loop()

        def ws_thread():
            asyncio.set_event_loop(loop)

            async def run():
                server = await websockets.serve(handle_ws, "localhost", port)
                logger.info(f"[RecordAgent] WebSocket server on ws://localhost:{port}")
                asyncio.create_task(broadcast_loop())
                await asyncio.Future()

            loop.run_until_complete(run())

        t = threading.Thread(target=ws_thread, daemon=True)
        t.start()

        try:
            webview.create_window(
                f"Recorder — Optimus Suite",
                f"http://localhost:{port}",
                width=1100,
                height=750,
            )
            webview.start()
        except Exception as e:
            logger.error(f"[RecordAgent] pywebview error: {e}")
            # Fallback to headless
            logger.info("[RecordAgent] Falling back to headless mode")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        finally:
            _engine.stop()
            logger.info("[RecordAgent] Shutdown.")


if __name__ == "__main__":
    main()
