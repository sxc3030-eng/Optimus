#!/usr/bin/env python3
"""
netguardpro_installer.py — Optimus Suite Linux Installer
==============================================================
Selective installer for Linux. Copies selected programs,
installs pip dependencies, creates .desktop shortcuts.

Launch: python3 netguardpro_installer.py
"""

import json
import os
import sys
import shutil
import subprocess
import webview

INSTALLER_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.dirname(INSTALLER_DIR)
HTML_FILE = os.path.join(INSTALLER_DIR, "installer_ui.html")

PROGRAMS = [
    {"id": "netguard", "name": "NetGuard Pro", "icon": "🛡️",
     "description": "Network IDS, packet capture, deep packet inspection, firewall",
     "files": ["netguard.py", "netguard_dashboard.html", "netguard_help.html",
               "netguard_login.html", "netguard_map.html", "netguard_network.html",
               "netguard_analyze.html", "netguard_history.html", "netguard_panels.html",
               "netguard_service.html", "netguard_vitrine.html", "netguard_settings.json",
               "netguard_icon.ico", "netguard_icon.png", "netguard_logo.svg"],
     "shared": ["startup_utils.py", "netguard_tray.py", "permissions.py",
                "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "scapy", "requests", "psutil", "pystray", "Pillow"],
     "launcher": "lancer_netguard.sh", "size_mb": 1.2, "admin": False},

    {"id": "cleanguard", "name": "CleanGuard Pro", "icon": "🧹",
     "description": "System cleaner, malware scanner, YARA rules, quarantine",
     "files": ["cleanguard/"],
     "shared": ["startup_utils.py", "permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "watchdog", "pystray", "Pillow"],
     "launcher": "lancer_cleanguard.sh", "size_mb": 0.8, "admin": False},

    {"id": "mailshield", "name": "MailShield Pro", "icon": "📧",
     "description": "Secure email with phishing detection and SPF/DKIM",
     "files": ["mailshield/"],
     "shared": ["startup_utils.py", "permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "requests", "cryptography", "dnspython", "bleach", "pystray", "Pillow"],
     "launcher": "lancer_mailshield.sh", "size_mb": 0.9, "admin": False},

    {"id": "vpnguard", "name": "VPN Guard Pro", "icon": "🔐",
     "description": "WireGuard VPN client with kill switch",
     "files": ["vpnguard/", "wireguard/"],
     "shared": ["startup_utils.py", "permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests", "cryptography", "pystray", "Pillow"],
     "launcher": "lancer_vpnguard.sh", "size_mb": 0.6, "admin": True},

    {"id": "sentinel_mapper", "name": "SentinelOS Mapper", "icon": "🗺️",
     "description": "Network map, iptables firewall, multi-interface scanning",
     "files": ["sentinel/sentinel_mapper.py", "sentinel/sentinel_map.html",
               "sentinel/sentinel_settings.json", "sentinel/SentinelOS.ico", "sentinel/icons/"],
     "shared": ["startup_utils.py", "permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests"],
     "launcher": "lancer_sentinel_mapper.sh", "size_mb": 0.5, "admin": True},

    {"id": "cortex", "name": "SentinelOS Cortex", "icon": "🧠",
     "description": "Central orchestrator — manages all agents",
     "files": ["sentinel/cortex.py", "sentinel/agent_bus.py", "sentinel/playbook_engine.py",
               "sentinel/threat_intel.py", "sentinel/alert_manager.py",
               "sentinel/sentinel_dashboard.html", "sentinel/sentinel_settings.json",
               "sentinel/SentinelOS.ico", "sentinel/icons/", "sentinel/threat_data/"],
     "shared": ["startup_utils.py", "permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests", "aiohttp", "websockets", "scapy",
              "cryptography", "pystray", "Pillow"],
     "launcher": "lancer_sentinel.sh", "size_mb": 1.5, "admin": True},

    {"id": "fim", "name": "File Integrity Monitor", "icon": "📁",
     "description": "SHA-256 file integrity monitoring",
     "files": ["fim/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil"],
     "launcher": None, "size_mb": 0.2, "admin": False},

    {"id": "honeypot", "name": "Honeypot", "icon": "🍯",
     "description": "Deception traps for intruder detection",
     "files": ["honeypot/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil"],
     "launcher": None, "size_mb": 0.2, "admin": True},

    {"id": "strikeback", "name": "StrikeBack", "icon": "⚔️",
     "description": "Active defense with automated counter-measures",
     "files": ["strikeback/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil"],
     "launcher": None, "size_mb": 0.3, "admin": True},

    {"id": "recorder", "name": "Recorder", "icon": "🎙️",
     "description": "Forensic recording of security events",
     "files": ["recorder/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil"],
     "launcher": None, "size_mb": 0.3, "admin": False},

    {"id": "redteam", "name": "RedTeam Agent", "icon": "🎯",
     "description": "Penetration testing toolkit with automated vulnerability scanning",
     "files": ["redteam/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests", "scapy"],
     "launcher": None, "size_mb": 0.4, "admin": True},

    {"id": "siem", "name": "SIEM Agent", "icon": "🧠",
     "description": "Security information and event management — log collection and correlation",
     "files": ["siem/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests"],
     "launcher": None, "size_mb": 0.4, "admin": False},

    {"id": "sandbox", "name": "Sandbox Agent", "icon": "📦",
     "description": "Dynamic file analysis in isolated environment for malware detection",
     "files": ["sandbox/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests"],
     "launcher": None, "size_mb": 0.5, "admin": True},

    {"id": "mobile_gateway", "name": "Mobile Gateway", "icon": "📱",
     "description": "Mobile device gateway for remote monitoring and push notifications",
     "files": ["mobile_gateway/"],
     "shared": ["permissions.py", "toast_notifications.py", "permissions_state.json"],
     "deps": ["pywebview[gtk]", "psutil", "requests", "aiohttp"],
     "launcher": None, "size_mb": 0.3, "admin": False},

    {"id": "help_agent", "name": "Help Agent", "icon": "🤖",
     "description": "Interactive guide for all programs",
     "files": ["help_agent/"],
     "shared": [],
     "deps": ["pywebview[gtk]"],
     "launcher": "lancer_helpagent.sh", "size_mb": 0.1, "admin": False},
]


class InstallerAPI:
    def get_programs(self) -> str:
        return json.dumps(PROGRAMS)

    def check_dependencies(self) -> str:
        results = {"python": False, "python_version": "", "npcap": False,
                   "wireguard": False, "pip": False, "admin": False}
        import platform
        results["python"] = True
        results["python_version"] = platform.python_version()

        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"],
                          capture_output=True, timeout=10)
            results["pip"] = True
        except Exception:
            pass

        # libpcap (Linux equivalent of Npcap)
        results["npcap"] = shutil.which("tcpdump") is not None or \
                           os.path.exists("/usr/lib/libpcap.so")

        results["wireguard"] = shutil.which("wg") is not None
        results["admin"] = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

        return json.dumps(results)

    def install(self, selected_ids: list, install_path: str) -> str:
        if not selected_ids:
            return json.dumps({"error": "No programs selected"})

        install_path = install_path.strip() or os.path.expanduser("~/Optimus")
        os.makedirs(install_path, exist_ok=True)

        installed = []
        errors = []
        all_deps = set()

        for prog in PROGRAMS:
            if prog["id"] not in selected_ids:
                continue
            try:
                for f in prog["files"]:
                    src = os.path.join(SOURCE_DIR, f)
                    dst = os.path.join(install_path, f)
                    if f.endswith("/"):
                        src = src.rstrip("/")
                        dst = dst.rstrip("/")
                        if os.path.isdir(src):
                            if os.path.exists(dst):
                                shutil.rmtree(dst)
                            shutil.copytree(src, dst)
                    else:
                        os.makedirs(os.path.dirname(dst) or install_path, exist_ok=True)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)

                for sf in prog.get("shared", []):
                    src = os.path.join(SOURCE_DIR, sf)
                    dst = os.path.join(install_path, sf)
                    if os.path.isfile(src) and not os.path.exists(dst):
                        shutil.copy2(src, dst)

                if prog.get("launcher"):
                    src = os.path.join(SOURCE_DIR, "launchers", prog["launcher"])
                    dst_dir = os.path.join(install_path, "launchers")
                    os.makedirs(dst_dir, exist_ok=True)
                    if os.path.isfile(src):
                        dst_file = os.path.join(dst_dir, prog["launcher"])
                        shutil.copy2(src, dst_file)
                        os.chmod(dst_file, 0o755)

                all_deps.update(prog.get("deps", []))
                installed.append(prog["id"])
            except Exception as e:
                errors.append(f"{prog['name']}: {str(e)}")

        pip_errors = []
        if all_deps:
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install"] + list(all_deps),
                    capture_output=True, timeout=120
                )
            except Exception as e:
                pip_errors.append(str(e))

        req_src = os.path.join(SOURCE_DIR, "requirements.txt")
        if os.path.isfile(req_src):
            shutil.copy2(req_src, os.path.join(install_path, "requirements.txt"))

        return json.dumps({"ok": True, "installed": installed, "install_path": install_path,
                           "errors": errors, "pip_errors": pip_errors, "deps_installed": list(all_deps)})

    def create_shortcuts(self, install_path: str, selected_ids: list) -> str:
        apps_dir = os.path.expanduser("~/.local/share/applications")
        os.makedirs(apps_dir, exist_ok=True)
        created = []

        for prog in PROGRAMS:
            if prog["id"] not in selected_ids or not prog.get("launcher"):
                continue
            launcher_path = os.path.join(install_path, "launchers", prog["launcher"])
            if not os.path.exists(launcher_path):
                continue

            safe_name = prog["id"].replace("_", "-")
            desktop_file = os.path.join(apps_dir, f"netguardpro-{safe_name}.desktop")
            content = f"""[Desktop Entry]
Type=Application
Name={prog['name']} — Optimus Suite
Comment={prog['description']}
Exec=bash {launcher_path}
Icon={os.path.join(install_path, 'netguard_icon.png')}
Terminal=false
Categories=Security;Network;
StartupNotify=true
"""
            try:
                with open(desktop_file, "w") as f:
                    f.write(content)
                os.chmod(desktop_file, 0o755)
                created.append(prog["name"])
            except Exception:
                pass

        return json.dumps({"ok": True, "shortcuts": created})

    def browse_folder(self) -> str:
        try:
            result = webview.windows[0].create_file_dialog(
                webview.FOLDER_DIALOG, directory=os.path.expanduser("~"))
            if result and len(result) > 0:
                return json.dumps({"path": result[0]})
        except Exception:
            pass
        return json.dumps({"path": ""})


def main():
    api = InstallerAPI()
    if not os.path.exists(HTML_FILE):
        print(f"[!] Installer UI not found: {HTML_FILE}")
        sys.exit(1)
    window = webview.create_window(
        "Optimus Installer — Cybersecurity Suite",
        HTML_FILE, js_api=api,
        width=900, height=700, min_size=(800, 600),
        background_color="#0f0f13", text_select=True
    )
    webview.start(debug=False, gui="gtk")


if __name__ == "__main__":
    main()
