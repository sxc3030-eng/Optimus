#!/usr/bin/env python3
"""
startup_utils.py — Optimus Suite Linux Startup & Tray Utilities
====================================================================
Handles XDG autostart, .desktop file creation, and system tray integration
for Linux desktop environments (GNOME, KDE, XFCE, etc.).

Replaces the Windows version that uses registry + .lnk shortcuts.
"""

import os
import sys
import subprocess
import logging
import shutil

logger = logging.getLogger("Optimus.Startup")

SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
XDG_AUTOSTART = os.path.expanduser("~/.config/autostart")
XDG_APPS = os.path.expanduser("~/.local/share/applications")


def is_admin() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def get_python() -> str:
    """Get the Python executable path."""
    return sys.executable or shutil.which("python3") or "python3"


# ─── Desktop Entry (.desktop files) ─────────────────────────────────────

def _desktop_entry(name: str, comment: str, exec_cmd: str,
                   icon: str = "", terminal: bool = False,
                   categories: str = "Security;Network;") -> str:
    """Generate a .desktop entry string."""
    lines = [
        "[Desktop Entry]",
        "Type=Application",
        f"Name={name}",
        f"Comment={comment}",
        f"Exec={exec_cmd}",
        f"Icon={icon}" if icon else "",
        f"Terminal={'true' if terminal else 'false'}",
        f"Categories={categories}",
        "StartupNotify=true",
    ]
    return "\n".join(line for line in lines if line) + "\n"


def create_desktop_shortcut(program_name: str, script_path: str,
                            comment: str = "", icon_path: str = "") -> bool:
    """
    Create a .desktop file in ~/.local/share/applications/.
    Returns True on success.
    """
    os.makedirs(XDG_APPS, exist_ok=True)
    safe_name = program_name.lower().replace(" ", "-").replace("—", "")
    desktop_file = os.path.join(XDG_APPS, f"netguardpro-{safe_name}.desktop")

    python = get_python()
    exec_cmd = f"{python} {os.path.abspath(script_path)}"

    entry = _desktop_entry(
        name=f"{program_name} — Optimus Suite",
        comment=comment or f"Optimus {program_name}",
        exec_cmd=exec_cmd,
        icon=icon_path,
    )

    try:
        with open(desktop_file, "w") as f:
            f.write(entry)
        os.chmod(desktop_file, 0o755)
        logger.info(f"Desktop shortcut created: {desktop_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to create desktop shortcut: {e}")
        return False


def remove_desktop_shortcut(program_name: str) -> bool:
    """Remove a .desktop file."""
    safe_name = program_name.lower().replace(" ", "-").replace("—", "")
    desktop_file = os.path.join(XDG_APPS, f"netguardpro-{safe_name}.desktop")
    try:
        if os.path.exists(desktop_file):
            os.remove(desktop_file)
            return True
    except Exception:
        pass
    return False


# ─── Autostart ───────────────────────────────────────────────────────────

def register_autostart(program_name: str, script_path: str,
                       icon_path: str = "") -> bool:
    """
    Register a program to start automatically on login via XDG autostart.
    Creates a .desktop file in ~/.config/autostart/.
    """
    os.makedirs(XDG_AUTOSTART, exist_ok=True)
    safe_name = program_name.lower().replace(" ", "-")
    autostart_file = os.path.join(XDG_AUTOSTART, f"netguardpro-{safe_name}.desktop")

    python = get_python()
    exec_cmd = f"{python} {os.path.abspath(script_path)}"

    entry = _desktop_entry(
        name=f"{program_name} — Optimus",
        comment=f"Auto-start {program_name}",
        exec_cmd=exec_cmd,
        icon=icon_path,
    )
    # Add autostart-specific keys
    entry += "X-GNOME-Autostart-enabled=true\n"

    try:
        with open(autostart_file, "w") as f:
            f.write(entry)
        os.chmod(autostart_file, 0o755)
        logger.info(f"Autostart registered: {autostart_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to register autostart: {e}")
        return False


def unregister_autostart(program_name: str) -> bool:
    """Remove program from XDG autostart."""
    safe_name = program_name.lower().replace(" ", "-")
    autostart_file = os.path.join(XDG_AUTOSTART, f"netguardpro-{safe_name}.desktop")
    try:
        if os.path.exists(autostart_file):
            os.remove(autostart_file)
            return True
    except Exception:
        pass
    return False


def is_autostart_registered(program_name: str) -> bool:
    """Check if program is registered for autostart."""
    safe_name = program_name.lower().replace(" ", "-")
    return os.path.exists(os.path.join(XDG_AUTOSTART, f"netguardpro-{safe_name}.desktop"))


# ─── Systemd Service (for root/system-level) ────────────────────────────

def create_systemd_service(service_name: str, script_path: str,
                           description: str = "", user: str = None) -> bool:
    """
    Create a systemd service file. Requires root.
    For user-level services, set user parameter.
    """
    if not is_admin():
        logger.error("Root required to create systemd services")
        return False

    python = get_python()
    unit_content = f"""[Unit]
Description={description or f'Optimus {service_name}'}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {os.path.abspath(script_path)}
WorkingDirectory={os.path.dirname(os.path.abspath(script_path))}
Restart=on-failure
RestartSec=5
{f'User={user}' if user else ''}

[Install]
WantedBy=multi-user.target
"""
    service_file = f"/etc/systemd/system/netguardpro-{service_name}.service"
    try:
        with open(service_file, "w") as f:
            f.write(unit_content)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        logger.info(f"Systemd service created: {service_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to create systemd service: {e}")
        return False


def enable_systemd_service(service_name: str) -> bool:
    """Enable and start a systemd service."""
    try:
        svc = f"netguardpro-{service_name}.service"
        subprocess.run(["systemctl", "enable", svc], check=True)
        subprocess.run(["systemctl", "start", svc], check=True)
        return True
    except Exception:
        return False


def disable_systemd_service(service_name: str) -> bool:
    """Stop and disable a systemd service."""
    try:
        svc = f"netguardpro-{service_name}.service"
        subprocess.run(["systemctl", "stop", svc], check=True)
        subprocess.run(["systemctl", "disable", svc], check=True)
        return True
    except Exception:
        return False


# ─── System Tray (pystray) ──────────────────────────────────────────────
# pystray works on Linux with AppIndicator3 or GTK backend.
# The tray code itself is mostly portable — just ensure the backend is installed:
#   apt install gir1.2-appindicator3-0.1  (Ubuntu/Debian)
#   dnf install libappindicator-gtk3      (Fedora)

def check_tray_support() -> dict:
    """Check if system tray is supported."""
    result = {"pystray": False, "appindicator": False, "gtk": False}
    try:
        import pystray
        result["pystray"] = True
    except ImportError:
        pass

    try:
        import gi
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3
        result["appindicator"] = True
    except Exception:
        pass

    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
        result["gtk"] = True
    except Exception:
        pass

    return result
