#!/usr/bin/env python3
"""
toast_notifications.py — Optimus Suite Linux Desktop Notifications
=======================================================================
Sends native Linux desktop notifications via notify-send (libnotify)
or dbus directly. Graceful fallback if neither available.

Usage:
    from toast_notifications import toast_threat, toast_block, toast_scan, toast_event

    toast_threat("NetGuard Pro", "Port Scan", "high", "Source: 192.168.1.50")
    toast_block("SentinelOS", "10.0.0.42", "Suspicious activity")
"""

import os
import subprocess
import logging
import shutil

logger = logging.getLogger("Optimus.Toast")

# ─── Detect notification backend ────────────────────────────────────────
HAS_NOTIFY_SEND = shutil.which("notify-send") is not None

# Try dbus as fallback
HAS_DBUS = False
try:
    import dbus
    HAS_DBUS = True
except ImportError:
    pass

if not HAS_NOTIFY_SEND and not HAS_DBUS:
    logger.info("No notification backend (notify-send or dbus) — notifications disabled")

# ─── Icon paths ─────────────────────────────────────────────────────────
SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_DIR = os.path.join(SUITE_DIR, "sentinel", "icons")
DEFAULT_ICON = os.path.join(SUITE_DIR, "netguard_icon.png")

PROGRAM_ICONS = {
    "NetGuard Pro":    os.path.join(ICON_DIR, "netguard.ico"),
    "CleanGuard Pro":  os.path.join(ICON_DIR, "cleanguard.ico"),
    "MailShield Pro":  os.path.join(ICON_DIR, "mailshield.ico"),
    "VPN Guard Pro":   os.path.join(ICON_DIR, "vpnguard.ico"),
    "SentinelOS":      os.path.join(ICON_DIR, "sentinel.ico"),
    "Sentinel Mapper": os.path.join(ICON_DIR, "sentinel.ico"),
    "Cortex":          os.path.join(ICON_DIR, "sentinel.ico"),
    "FIM":             os.path.join(ICON_DIR, "fim.ico"),
    "Honeypot":        os.path.join(ICON_DIR, "honeypot.ico"),
    "StrikeBack":      os.path.join(ICON_DIR, "strikeback.ico"),
    "Recorder":        os.path.join(ICON_DIR, "recorder.ico"),
}

SEVERITY_PREFIX = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
    "info":     "ℹ️ INFO",
}

URGENCY_MAP = {
    "critical": "critical",
    "high": "critical",
    "medium": "normal",
    "low": "low",
    "info": "low",
}


def _get_icon(program: str) -> str:
    icon = PROGRAM_ICONS.get(program, DEFAULT_ICON)
    return icon if os.path.exists(icon) else DEFAULT_ICON if os.path.exists(DEFAULT_ICON) else ""


# ─── Core send function ─────────────────────────────────────────────────

def send_toast(title: str, message: str, icon_path: str = None,
               app_id: str = "Optimus Suite", duration: str = "short",
               urgency: str = "normal"):
    """
    Send a Linux desktop notification.
    Tries notify-send first, then dbus. Silent no-op if neither available.

    Args:
        title:    Notification title
        message:  Notification body text
        icon_path: Path to icon file (optional)
        app_id:   Application name
        duration: "short" or "long"
        urgency:  "low", "normal", or "critical"
    """
    timeout_ms = "5000" if duration == "short" else "25000"

    if HAS_NOTIFY_SEND:
        try:
            cmd = ["notify-send", "--app-name", app_id,
                   "--urgency", urgency, "-t", timeout_ms]
            if icon_path and os.path.exists(icon_path):
                cmd.extend(["-i", icon_path])
            cmd.extend([title, message])
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception as e:
            logger.warning(f"notify-send failed: {e}")

    if HAS_DBUS:
        try:
            bus = dbus.SessionBus()
            notif_obj = bus.get_object("org.freedesktop.Notifications",
                                       "/org/freedesktop/Notifications")
            notif_iface = dbus.Interface(notif_obj, "org.freedesktop.Notifications")
            notif_iface.Notify(app_id, 0, icon_path or "", title, message,
                              [], {}, int(timeout_ms))
            return
        except Exception as e:
            logger.warning(f"dbus notification failed: {e}")


# ─── Specialized toast functions ─────────────────────────────────────────

def toast_threat(program: str, threat_type: str, severity: str, details: str = ""):
    prefix = SEVERITY_PREFIX.get(severity.lower(), "⚠️")
    title = f"{prefix} — {program}"
    msg = f"Threat detected: {threat_type}"
    if details:
        msg += f"\n{details}"
    urg = URGENCY_MAP.get(severity.lower(), "normal")
    send_toast(title, msg, _get_icon(program),
               duration="long" if severity in ("critical", "high") else "short",
               urgency=urg)


def toast_block(program: str, ip: str, reason: str = ""):
    title = f"🛡️ Blocked — {program}"
    msg = f"Device blocked: {ip}"
    if reason:
        msg += f"\nReason: {reason}"
    send_toast(title, msg, _get_icon(program))


def toast_unblock(program: str, ip: str):
    send_toast(f"✅ Unblocked — {program}", f"Device unblocked: {ip}", _get_icon(program))


def toast_scan(program: str, summary: str):
    send_toast(f"🔍 Scan Complete — {program}", summary, _get_icon(program))


def toast_event(program: str, message: str):
    send_toast(f"📢 {program}", message, _get_icon(program))


def toast_connection(program: str, status: str, details: str = ""):
    icon_map = {"connected": "🟢", "disconnected": "🔴", "error": "⚠️"}
    emoji = icon_map.get(status.lower(), "📡")
    send_toast(f"{emoji} {status.title()} — {program}", details or status, _get_icon(program))


def toast_quarantine(program: str, filename: str, threat: str = ""):
    msg = f"File quarantined: {filename}"
    if threat:
        msg += f"\nThreat: {threat}"
    send_toast(f"🔒 Quarantined — {program}", msg, _get_icon(program))


def toast_integrity(program: str, filepath: str, change_type: str = "modified"):
    send_toast(f"📁 File {change_type.title()} — {program}", filepath,
               _get_icon(program), duration="long")


def toast_honeypot(program: str, trap_type: str, source_ip: str):
    send_toast(f"🍯 Trap Triggered — {program}",
               f"Type: {trap_type}\nSource: {source_ip}",
               _get_icon(program), duration="long", urgency="critical")
