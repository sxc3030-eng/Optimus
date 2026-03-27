#!/usr/bin/env python3
"""
OPTIMUS Desktop Environment v1.0
Cybersecurity Command Desktop — Main graphical interface
Launches and monitors all Optimus suite agents from a unified desktop.
"""

import webview
import json
import os
import sys
import time
import socket
import struct
import threading
import subprocess
import platform
import signal
import psutil

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
LAUNCHERS_DIR = os.path.join(PROJECT_DIR, "launchers")
SETTINGS_DIR = os.path.expanduser("~/.optimus")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "desktop_settings.json")
THEMES_DIR = os.path.join(BASE_DIR, "themes")
HTML_FILE = os.path.join(BASE_DIR, "desktop.html")
CORTEX_WS_PORT = 8900

# Ensure settings directory exists
os.makedirs(SETTINGS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Program registry — all 14 Optimus programs
# ---------------------------------------------------------------------------
PROGRAMS = [
    {
        "id": "netguard",
        "name": "NetGuard Pro",
        "desc": "Network IDS / Packet Capture / Firewall",
        "icon": "fa-shield-halved",
        "emoji": "\U0001f6e1\ufe0f",
        "port": 8765,
        "launcher": "lancer_netguard.sh",
        "color": "#00ff88",
    },
    {
        "id": "sentinel",
        "name": "SentinelOS",
        "desc": "Cybersecurity Command Center / Cortex",
        "icon": "fa-satellite-dish",
        "emoji": "\U0001f4e1",
        "port": 8900,
        "launcher": "lancer_sentinel.sh",
        "color": "#ff6b35",
    },
    {
        "id": "cleanguard",
        "name": "CleanGuard Pro",
        "desc": "System Cleanup & Hardening",
        "icon": "fa-broom",
        "emoji": "\U0001f9f9",
        "port": 8810,
        "launcher": "lancer_cleanguard.sh",
        "color": "#36d1dc",
    },
    {
        "id": "mailshield",
        "name": "MailShield Pro",
        "desc": "Secure Email Client & Phishing Filter",
        "icon": "fa-envelope-open-text",
        "emoji": "\U0001f4e7",
        "port": 8801,
        "launcher": "lancer_mailshield.sh",
        "color": "#f7b731",
    },
    {
        "id": "vpnguard",
        "name": "VPN Guard Pro",
        "desc": "WireGuard VPN Manager",
        "icon": "fa-lock",
        "emoji": "\U0001f510",
        "port": 8820,
        "launcher": "lancer_vpnguard.sh",
        "color": "#a55eea",
    },
    {
        "id": "honeypot",
        "name": "Honeypot",
        "desc": "Decoy Services & Attacker Trap",
        "icon": "fa-spider",
        "emoji": "\U0001f36f",
        "port": 8830,
        "launcher": "lancer_honeypot.sh",
        "color": "#eb3b5a",
    },
    {
        "id": "fim",
        "name": "File Integrity Monitor",
        "desc": "Hash-based File Change Detection",
        "icon": "fa-file-shield",
        "emoji": "\U0001f4c4",
        "port": 8840,
        "launcher": "lancer_fim.sh",
        "color": "#20bf6b",
    },
    {
        "id": "strikeback",
        "name": "StrikeBack",
        "desc": "Active Defense & Counter-Attack",
        "icon": "fa-crosshairs",
        "emoji": "\U0001f3af",
        "port": 8850,
        "launcher": "lancer_strikeback.sh",
        "color": "#fc5c65",
    },
    {
        "id": "recorder",
        "name": "Recorder",
        "desc": "Session Recording & Forensics",
        "icon": "fa-video",
        "emoji": "\U0001f4f9",
        "port": 8860,
        "launcher": "lancer_recorder.sh",
        "color": "#45aaf2",
    },
    {
        "id": "redteam",
        "name": "RedTeam Simulator",
        "desc": "Penetration Testing & Defense Validation",
        "icon": "fa-skull-crossbones",
        "emoji": "\u2620\ufe0f",
        "port": 8870,
        "launcher": "lancer_redteam.sh",
        "color": "#ff4757",
    },
    {
        "id": "siem",
        "name": "SIEM / SOAR",
        "desc": "Security Information & Event Management",
        "icon": "fa-chart-line",
        "emoji": "\U0001f4ca",
        "port": 8880,
        "launcher": "lancer_siem.sh",
        "color": "#2ed573",
    },
    {
        "id": "sandbox",
        "name": "Sandbox",
        "desc": "Automated Malware Analysis",
        "icon": "fa-flask",
        "emoji": "\U0001f9ea",
        "port": 8890,
        "launcher": "lancer_sandbox.sh",
        "color": "#ffa502",
    },
    {
        "id": "mobile_gw",
        "name": "Mobile Gateway",
        "desc": "Mobile Device Protection Relay",
        "icon": "fa-mobile-screen-button",
        "emoji": "\U0001f4f1",
        "port": 8895,
        "launcher": "lancer_mobile_gateway.sh",
        "color": "#1e90ff",
    },
    {
        "id": "helpagent",
        "name": "Help Agent",
        "desc": "AI Cybersecurity Assistant & Docs",
        "icon": "fa-robot",
        "emoji": "\U0001f916",
        "port": 8899,
        "launcher": "lancer_helpagent.sh",
        "color": "#dfe6e9",
    },
]


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
def port_is_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    """Check if a TCP port is listening."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def get_local_ip() -> str:
    """Get the primary LAN IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def uptime_str() -> str:
    """Human-readable system uptime."""
    try:
        boot = psutil.boot_time()
        delta = int(time.time() - boot)
        hours, remainder = divmod(delta, 3600)
        minutes, _ = divmod(remainder, 60)
        return f"{hours}h {minutes}m"
    except Exception:
        return "N/A"


# ---------------------------------------------------------------------------
# JS API — exposed to the webview JavaScript layer
# ---------------------------------------------------------------------------
class DesktopAPI:
    """Python <-> JavaScript bridge for the Optimus Desktop."""

    def __init__(self):
        self._processes: dict[str, subprocess.Popen] = {}
        self._notifications: list[dict] = []
        self._max_notifications = 50

    # ---- Program launch / stop -----------------------------------------
    def launch_program(self, name: str) -> dict:
        """Launch a program by its id.  Returns status dict."""
        prog = next((p for p in PROGRAMS if p["id"] == name), None)
        if prog is None:
            return {"ok": False, "error": f"Unknown program: {name}"}

        launcher_path = os.path.join(LAUNCHERS_DIR, prog["launcher"])
        if not os.path.isfile(launcher_path):
            return {"ok": False, "error": f"Launcher not found: {prog['launcher']}"}

        # If already running (port open), skip
        if port_is_open(prog["port"]):
            return {"ok": True, "msg": f"{prog['name']} is already running."}

        try:
            # Programs needing root: netguard, sentinel, vpnguard, honeypot, strikeback
            needs_root = name in ("netguard", "sentinel", "vpnguard", "honeypot", "strikeback")
            cmd = ["sudo", "bash", launcher_path] if needs_root and os.geteuid() != 0 else ["bash", launcher_path]
            proc = subprocess.Popen(
                cmd,
                cwd=PROJECT_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
            self._processes[name] = proc
            self._push_notification(
                "launch", f"{prog['name']} launched (PID {proc.pid})", prog["color"]
            )
            return {"ok": True, "pid": proc.pid}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def stop_program(self, name: str) -> dict:
        """Attempt to stop a running program."""
        prog = next((p for p in PROGRAMS if p["id"] == name), None)
        if prog is None:
            return {"ok": False, "error": f"Unknown program: {name}"}

        # Try to kill via stored Popen
        proc = self._processes.get(name)
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()
            self._push_notification(
                "stop", f"{prog['name']} stopped.", "#ff4757"
            )
            return {"ok": True}

        # Fallback: kill by port
        killed = self._kill_port(prog["port"])
        if killed:
            self._push_notification(
                "stop", f"{prog['name']} stopped (port {prog['port']}).", "#ff4757"
            )
        return {"ok": killed}

    def shutdown_all(self) -> dict:
        """Stop every running program."""
        stopped = []
        for prog in PROGRAMS:
            if port_is_open(prog["port"]):
                self.stop_program(prog["id"])
                stopped.append(prog["name"])
        return {"ok": True, "stopped": stopped}

    # ---- Status --------------------------------------------------------
    def get_status(self) -> list[dict]:
        """Return status of all 14 programs."""
        result = []
        for prog in PROGRAMS:
            running = port_is_open(prog["port"])
            result.append(
                {
                    "id": prog["id"],
                    "name": prog["name"],
                    "desc": prog["desc"],
                    "icon": prog["icon"],
                    "emoji": prog["emoji"],
                    "port": prog["port"],
                    "color": prog["color"],
                    "running": running,
                }
            )
        return result

    # ---- System info ---------------------------------------------------
    def get_system_info(self) -> dict:
        """CPU, RAM, disk, network and OS information."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.4)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net = psutil.net_io_counters()

            return {
                "hostname": platform.node(),
                "os": f"{platform.system()} {platform.release()}",
                "ip": get_local_ip(),
                "uptime": uptime_str(),
                "cpu_percent": round(cpu_percent, 1),
                "ram_total_gb": round(mem.total / (1024 ** 3), 1),
                "ram_used_gb": round(mem.used / (1024 ** 3), 1),
                "ram_percent": mem.percent,
                "disk_total_gb": round(disk.total / (1024 ** 3), 1),
                "disk_used_gb": round(disk.used / (1024 ** 3), 1),
                "disk_percent": disk.percent,
                "net_sent_mb": round(net.bytes_sent / (1024 ** 2), 1),
                "net_recv_mb": round(net.bytes_recv / (1024 ** 2), 1),
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ---- Settings persistence ------------------------------------------
    def save_settings(self, settings_json: str) -> dict:
        """Persist desktop customisation to ~/.optimus/desktop_settings.json."""
        try:
            data = json.loads(settings_json) if isinstance(settings_json, str) else settings_json
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w") as fh:
                json.dump(data, fh, indent=2)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def load_settings(self) -> dict:
        """Load desktop customisation from disk."""
        if not os.path.isfile(SETTINGS_FILE):
            return self._default_settings()
        try:
            with open(SETTINGS_FILE) as fh:
                return json.load(fh)
        except Exception:
            return self._default_settings()

    def load_theme(self, name: str = "default") -> dict:
        """Load a named theme from the themes/ directory."""
        theme_file = os.path.join(THEMES_DIR, f"{name}.json")
        if not os.path.isfile(theme_file):
            theme_file = os.path.join(THEMES_DIR, "default.json")
        try:
            with open(theme_file) as fh:
                return json.load(fh)
        except Exception:
            return {
                "name": "Optimus Dark",
                "background": "#0a0a0f",
                "accent": "#00ff88",
                "text": "#e0e0e0",
                "card_bg": "#1a1a2e",
                "card_hover": "#252545",
                "dock_bg": "rgba(10,10,15,0.95)",
                "border": "#333355",
            }

    # ---- Notifications -------------------------------------------------
    def get_notifications(self) -> list[dict]:
        """Return the latest desktop notifications."""
        return list(reversed(self._notifications[-self._max_notifications :]))

    def clear_notifications(self) -> dict:
        """Clear all notifications."""
        self._notifications.clear()
        return {"ok": True}

    # ---- Security score ------------------------------------------------
    def get_security_score(self) -> dict:
        """
        Compute a rough security posture score.
        +10 for each running defensive agent, penalties for missing ones.
        Attempts to pull from SIEM (port 8880) if available.
        """
        running_count = sum(1 for p in PROGRAMS if port_is_open(p["port"]))
        total = len(PROGRAMS)
        score = int((running_count / total) * 100)

        critical_ids = ["netguard", "sentinel", "fim", "vpnguard", "mailshield"]
        critical_running = sum(
            1 for cid in critical_ids
            if port_is_open(next(p["port"] for p in PROGRAMS if p["id"] == cid))
        )
        critical_total = len(critical_ids)

        grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F"

        return {
            "score": score,
            "grade": grade,
            "running": running_count,
            "total": total,
            "critical_running": critical_running,
            "critical_total": critical_total,
            "siem_connected": port_is_open(8880),
        }

    # ---- Private helpers -----------------------------------------------
    def _push_notification(self, ntype: str, message: str, color: str = "#00ff88"):
        self._notifications.append(
            {
                "type": ntype,
                "message": message,
                "color": color,
                "time": time.strftime("%H:%M:%S"),
            }
        )

    @staticmethod
    def _default_settings() -> dict:
        return {
            "wallpaper": "#0a0a0f",
            "accent": "#00ff88",
            "icon_size": "medium",
            "layout": "grid",
            "theme": "default",
        }

    @staticmethod
    def _kill_port(port: int) -> bool:
        """Kill all processes listening on *port*."""
        killed = False
        for conn in psutil.net_connections(kind="tcp"):
            if conn.laddr.port == port and conn.pid:
                try:
                    psutil.Process(conn.pid).terminate()
                    killed = True
                except Exception:
                    pass
        return killed


# ---------------------------------------------------------------------------
# Background poller — pushes status updates to the window
# ---------------------------------------------------------------------------
class StatusPoller(threading.Thread):
    """Periodically pushes program status + system info into the webview."""

    daemon = True

    def __init__(self, api: DesktopAPI, window):
        super().__init__()
        self.api = api
        self.window = window
        self._stop_event = threading.Event()

    def run(self):
        # Wait for DOM to be ready
        time.sleep(2)
        while not self._stop_event.is_set():
            try:
                status = json.dumps(self.api.get_status())
                sysinfo = json.dumps(self.api.get_system_info())
                score = json.dumps(self.api.get_security_score())
                notifs = json.dumps(self.api.get_notifications()[:10])
                js = (
                    f"if(window._optimus){{window._optimus.onStatusUpdate({status});"
                    f"window._optimus.onSysInfoUpdate({sysinfo});"
                    f"window._optimus.onScoreUpdate({score});"
                    f"window._optimus.onNotifUpdate({notifs});}}"
                )
                self.window.evaluate_js(js)
            except Exception:
                pass
            self._stop_event.wait(3)

    def stop(self):
        self._stop_event.set()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main():
    api = DesktopAPI()

    # Resolve HTML path
    if not os.path.isfile(HTML_FILE):
        print(f"[!] desktop.html not found at {HTML_FILE}")
        sys.exit(1)

    window = webview.create_window(
        "OPTIMUS  --  Cybersecurity Desktop",
        url=HTML_FILE,
        js_api=api,
        width=1440,
        height=900,
        min_size=(1024, 600),
        frameless=False,
        easy_drag=False,
        text_select=False,
        background_color="#0a0a0f",
    )

    # Start background status poller once webview is loaded
    def on_loaded():
        poller = StatusPoller(api, window)
        poller.start()

    window.events.loaded += on_loaded

    print("[*] Starting OPTIMUS Desktop Environment ...")
    print(f"    HTML: {HTML_FILE}")
    print(f"    Settings: {SETTINGS_FILE}")

    webview.start(debug=("--debug" in sys.argv))


if __name__ == "__main__":
    main()
