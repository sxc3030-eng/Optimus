#!/usr/bin/env python3
"""
SentinelOS -- StrikeBack Agent v1.0.0
Active Defense: counter-attack and trap threats.

Port: 8850
Architecture:
    StrikeBack Agent (port 8850)
        +-- TarpitEngine      -- slow down attackers with delayed responses
        +-- DecoyDeployer     -- deploy dynamic decoys / fake services
        +-- ThreatTracker     -- track attacker IPs, fingerprint them
        +-- CounterIntel      -- gather info about attackers (reverse DNS, geolocation, reputation)
        +-- IsolationManager  -- auto-isolate compromised network segments
        +-- WebSocket Server  -- serves state to Cortex
        +-- Timeline Events   -- visual timeline of all counter-actions
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
from datetime import datetime
from pathlib import Path
from collections import defaultdict

import websockets

# ── Shared modules ──────────────────────────────────────────
try:
    from permissions import PermissionManager
    HAS_PERMISSIONS = True
except ImportError:
    HAS_PERMISSIONS = False

try:
    from toast_notifications import toast_block, toast_event, toast_threat
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════════════════

STRIKEBACK_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(STRIKEBACK_DIR)
sys.path.insert(0, BASE_DIR)

VERSION = "1.0.0"
WS_PORT = 8850
IS_WINDOWS = sys.platform == "win32"
HEADLESS = "--headless" in sys.argv

LOG_DIR = os.path.join(STRIKEBACK_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [StrikeBack] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "strikeback.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.StrikeBack")


# ═══════════════════════════════════════════════════════════════════════════
# TARPIT ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class TarpitEngine:
    """Slow down attackers with artificial delays (TCP tarpit).
    When an attacker connects to a tarpitted port, responses are deliberately
    delayed to waste their time and resources."""

    def __init__(self, timeline_callback):
        self.active = True
        self.connections_slowed = 0
        self.total_delay_ms = 0
        self.avg_delay_ms = 0
        self._running = True
        self._timeline_cb = timeline_callback
        self._tarpit_port = 9999
        self._patience_map: dict[str, dict] = {}  # ip -> patience/behavior data

    def start(self):
        t = threading.Thread(target=self._tarpit_listener, daemon=True)
        t.start()
        logger.info(f"[Tarpit] Engine started on port {self._tarpit_port}")
        self._timeline_cb("tarpit", "info", "Tarpit engine activated",
                          {"port": self._tarpit_port})

    def _tarpit_listener(self):
        """Listen on the tarpit port and slow down any connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            sock.bind(("0.0.0.0", self._tarpit_port))
            sock.listen(5)
            logger.info(f"[Tarpit] Listening on port {self._tarpit_port}")

            while self._running:
                try:
                    conn, addr = sock.accept()
                    ip, src_port = addr
                    t = threading.Thread(
                        target=self._handle_tarpit_connection,
                        args=(conn, ip, src_port),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"[Tarpit] Accept error: {e}")
        except OSError as e:
            logger.warning(f"[Tarpit] Cannot bind port {self._tarpit_port}: {e}")
        except Exception as e:
            logger.error(f"[Tarpit] Listener error: {e}")

    def _handle_tarpit_connection(self, conn: socket.socket, ip: str, src_port: int):
        """Handle a single tarpitted connection -- drip-feed data slowly."""
        delay_ms = random.randint(2000, 5000)
        delay_s = delay_ms / 1000.0
        logger.warning(f"[Tarpit] Tarpitting {ip}:{src_port} with {delay_ms}ms delay")

        self.connections_slowed += 1
        self.total_delay_ms += delay_ms
        self.avg_delay_ms = self.total_delay_ms // max(self.connections_slowed, 1)

        # Track patience
        if ip not in self._patience_map:
            self._patience_map[ip] = {
                "first_seen": time.time(), "attempts": 0,
                "total_time_wasted_s": 0, "gave_up": False,
            }
        self._patience_map[ip]["attempts"] += 1

        self._timeline_cb("tarpit", "warning",
                          f"Tarpitting connection from {ip}:{src_port}",
                          {"ip": ip, "delay_ms": delay_ms})

        try:
            # Drip-feed a fake banner one byte at a time
            banner = "SSH-2.0-OpenSSH_9.1 StrikeBack-Tarpit\r\n"
            for ch in banner:
                time.sleep(delay_s / len(banner))
                try:
                    conn.send(ch.encode())
                except Exception:
                    break

            # Keep the connection alive as long as possible
            conn.settimeout(30)
            start = time.time()
            try:
                while self._running and (time.time() - start) < 120:
                    data = conn.recv(64)
                    if not data:
                        break
                    # Send back garbage slowly
                    time.sleep(random.uniform(1, 3))
                    conn.send(b"\xff" * random.randint(1, 4))
            except Exception:
                pass

            wasted = time.time() - start
            self._patience_map[ip]["total_time_wasted_s"] += wasted
            if wasted < 5:
                self._patience_map[ip]["gave_up"] = True

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def get_state(self) -> dict:
        return {
            "active": self.active,
            "connections_slowed": self.connections_slowed,
            "avg_delay_ms": self.avg_delay_ms,
            "tarpit_port": self._tarpit_port,
            "patience_data": dict(list(self._patience_map.items())[-10:]),
        }

    def stop(self):
        self._running = False
        self.active = False


# ═══════════════════════════════════════════════════════════════════════════
# DECOY DEPLOYER
# ═══════════════════════════════════════════════════════════════════════════

# Banners that mimic real services
SERVICE_BANNERS = {
    "MySQL": b"\x4a\x00\x00\x00\x0a" + b"5.7.42-StrikeBack\x00",
    "Redis": b"-ERR unknown command\r\n",
    "Telnet": b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03" +
              b"StrikeBack Telnet v1.0\r\nlogin: ",
    "SMTP": b"220 mail.strikeback.local ESMTP Postfix\r\n",
    "FTP": b"220 FTP StrikeBack Server ready.\r\n",
    "HTTP": (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n"
             b"Content-Type: text/html\r\n\r\n"
             b"<html><head><title>Internal Portal</title></head>"
             b"<body><h1>Welcome</h1></body></html>"),
    "PostgreSQL": b"E\x00\x00\x00\x2dSFATAL\x00C28000\x00"
                  b"Mpassword authentication failed\x00\x00",
    "MSSQL": b"\x04\x01\x00\x25\x00\x00\x01\x00",
    "MongoDB": b"MongoDB shell version v6.0.0\n> ",
    "Elasticsearch": (b'{"name":"strikeback-node","cluster_name":"sentinel",'
                      b'"version":{"number":"8.10.0"}}\n'),
}

DEFAULT_DECOYS = [
    {"port": 3307, "service": "MySQL"},
    {"port": 6380, "service": "Redis"},
    {"port": 2323, "service": "Telnet"},
]


class DecoyDeployer:
    """Deploy dynamic decoy/fake services to attract and log attackers."""

    def __init__(self, timeline_callback):
        self.decoys: list[dict] = []
        self._running = True
        self._timeline_cb = timeline_callback
        self._listeners: dict[int, threading.Thread] = {}

    def deploy(self, port: int, service: str) -> dict:
        """Deploy a decoy on a given port mimicking a service."""
        # Check for duplicate
        for d in self.decoys:
            if d["port"] == port:
                return {"error": f"Port {port} already has a decoy"}

        banner = SERVICE_BANNERS.get(service, f"Welcome to {service}\r\n".encode())

        decoy = {
            "port": port,
            "service": service,
            "connections": 0,
            "deployed_at": time.time(),
            "last_connection": None,
            "attacker_ips": [],
            "payloads_captured": [],
        }
        self.decoys.append(decoy)

        t = threading.Thread(
            target=self._decoy_listener,
            args=(decoy, banner),
            daemon=True,
        )
        t.start()
        self._listeners[port] = t

        logger.info(f"[Decoy] Deployed fake {service} on port {port}")
        self._timeline_cb("decoy", "info",
                          f"Deployed decoy: {service} on port {port}",
                          {"port": port, "service": service})
        return decoy

    def remove(self, port: int) -> bool:
        """Remove a decoy from the given port."""
        for i, d in enumerate(self.decoys):
            if d["port"] == port:
                d["_stop"] = True
                self.decoys.pop(i)
                self._listeners.pop(port, None)
                logger.info(f"[Decoy] Removed decoy on port {port}")
                self._timeline_cb("decoy", "info",
                                  f"Removed decoy on port {port}",
                                  {"port": port})
                return True
        return False

    def _decoy_listener(self, decoy: dict, banner: bytes):
        """Listen on a decoy port."""
        port = decoy["port"]
        service = decoy["service"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)

            while self._running and not decoy.get("_stop"):
                try:
                    conn, addr = sock.accept()
                    ip, src_port = addr
                    decoy["connections"] += 1
                    decoy["last_connection"] = time.time()

                    if ip not in decoy["attacker_ips"]:
                        decoy["attacker_ips"].append(ip)

                    logger.warning(f"[Decoy] {service}:{port} probed by {ip}:{src_port}")
                    self._timeline_cb("decoy", "warning",
                                      f"Decoy {service}:{port} probed by {ip}",
                                      {"ip": ip, "port": port, "service": service})
                    if HAS_TOAST:
                        toast_event("StrikeBack", f"Decoy {service}:{port} probed by {ip}")

                    # Send banner
                    try:
                        conn.send(banner)
                    except Exception:
                        pass

                    # Capture payload
                    try:
                        conn.settimeout(5)
                        data = conn.recv(4096)
                        payload = data.decode("utf-8", errors="replace")[:500]
                        if payload:
                            decoy["payloads_captured"].append({
                                "ts": time.time(), "ip": ip, "data": payload,
                            })
                            # Keep last 50 payloads
                            if len(decoy["payloads_captured"]) > 50:
                                decoy["payloads_captured"] = decoy["payloads_captured"][-50:]
                    except Exception:
                        pass

                    try:
                        conn.close()
                    except Exception:
                        pass

                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"[Decoy] Accept error on {port}: {e}")

            sock.close()
        except OSError as e:
            logger.warning(f"[Decoy] Cannot bind port {port} ({service}): {e}")
        except Exception as e:
            logger.error(f"[Decoy] Error on {port}: {e}")

    def get_decoys(self) -> list:
        return [
            {
                "port": d["port"],
                "service": d["service"],
                "connections": d["connections"],
                "deployed_at": d["deployed_at"],
                "last_connection": d["last_connection"],
                "unique_attackers": len(d["attacker_ips"]),
            }
            for d in self.decoys
        ]

    def stop(self):
        self._running = False
        for d in self.decoys:
            d["_stop"] = True


# ═══════════════════════════════════════════════════════════════════════════
# THREAT TRACKER
# ═══════════════════════════════════════════════════════════════════════════

ATTACK_TYPES = ["scanner", "brute-force", "exploit", "recon", "data-exfil", "c2", "unknown"]


class ThreatTracker:
    """Track attacker IPs, fingerprint them, and assign danger scores."""

    def __init__(self, timeline_callback):
        self.attackers: dict[str, dict] = {}
        self._timeline_cb = timeline_callback

    def track(self, ip: str, source: str = "decoy", details: str = "") -> dict:
        """Start or update tracking for an IP."""
        if ip in self.attackers:
            att = self.attackers[ip]
            att["attacks"] += 1
            att["last_seen"] = time.time()
            att["sources"].add(source)
            att["danger_score"] = self._calculate_score(att)
            return att

        # New attacker
        att = {
            "ip": ip,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "attacks": 1,
            "type": "unknown",
            "danger_score": 10,
            "reverse_dns": "",
            "country": "",
            "org": "",
            "isolated": False,
            "sources": {source},
            "notes": details,
        }
        self.attackers[ip] = att

        # Do reverse DNS in background
        t = threading.Thread(target=self._resolve_ip, args=(ip,), daemon=True)
        t.start()

        logger.info(f"[Tracker] New attacker tracked: {ip} (source: {source})")
        self._timeline_cb("tracker", "warning",
                          f"New attacker tracked: {ip}",
                          {"ip": ip, "source": source})
        if HAS_TOAST:
            toast_threat("StrikeBack", "New Attacker", "high", f"IP: {ip} (source: {source})")
        return att

    def _resolve_ip(self, ip: str):
        """Reverse DNS and basic intelligence for an IP."""
        if ip not in self.attackers:
            return
        att = self.attackers[ip]

        # Reverse DNS
        try:
            hostname = socket.getfqdn(ip)
            if hostname and hostname != ip:
                att["reverse_dns"] = hostname
                # Classify based on hostname
                hn = hostname.lower()
                if any(x in hn for x in ["scan", "crawl", "bot", "spider"]):
                    att["type"] = "scanner"
                elif any(x in hn for x in ["tor", "vpn", "proxy", "anon"]):
                    att["type"] = "recon"
                elif any(x in hn for x in ["dynamic", "pool", "dhcp", "ppp"]):
                    att["type"] = "unknown"
        except Exception:
            pass

        # Country heuristic from reverse DNS TLD
        try:
            if att["reverse_dns"]:
                parts = att["reverse_dns"].split(".")
                tld = parts[-1].upper() if parts else ""
                country_map = {
                    "RU": "Russia", "CN": "China", "KR": "South Korea",
                    "BR": "Brazil", "IN": "India", "DE": "Germany",
                    "FR": "France", "UK": "United Kingdom", "US": "United States",
                    "JP": "Japan", "NL": "Netherlands", "UA": "Ukraine",
                    "COM": "", "NET": "", "ORG": "", "IO": "",
                }
                att["country"] = country_map.get(tld, "")
        except Exception:
            pass

        att["danger_score"] = self._calculate_score(att)

    def _calculate_score(self, att: dict) -> int:
        """Calculate danger score 0-100 based on behavior."""
        score = 10
        # More attacks = higher score
        score += min(att["attacks"] * 5, 40)
        # Multiple sources = higher score
        score += min(len(att.get("sources", set())) * 10, 20)
        # Type bonus
        type_scores = {
            "exploit": 20, "brute-force": 15, "c2": 25,
            "data-exfil": 20, "scanner": 5, "recon": 10,
        }
        score += type_scores.get(att["type"], 0)
        # Time factor -- persistent attackers are more dangerous
        duration = time.time() - att["first_seen"]
        if duration > 3600:
            score += 10
        return min(score, 100)

    def classify_attacker(self, ip: str, attack_type: str):
        """Manually classify an attacker's behavior type."""
        if ip in self.attackers and attack_type in ATTACK_TYPES:
            self.attackers[ip]["type"] = attack_type
            self.attackers[ip]["danger_score"] = self._calculate_score(self.attackers[ip])

    def get_attackers(self, limit: int = 50) -> list:
        """Get list of all profiled attackers sorted by danger score."""
        sorted_atts = sorted(
            self.attackers.values(),
            key=lambda a: a["danger_score"],
            reverse=True,
        )[:limit]
        # Convert sets to lists for JSON serialization
        result = []
        for a in sorted_atts:
            entry = dict(a)
            entry["sources"] = list(entry.get("sources", set()))
            result.append(entry)
        return result

    def get_attacker(self, ip: str) -> dict | None:
        if ip in self.attackers:
            entry = dict(self.attackers[ip])
            entry["sources"] = list(entry.get("sources", set()))
            return entry
        return None


# ═══════════════════════════════════════════════════════════════════════════
# COUNTER INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

class CounterIntel:
    """Gather intelligence about attacker infrastructure."""

    def __init__(self, timeline_callback):
        self._timeline_cb = timeline_callback
        self.intel_cache: dict[str, dict] = {}

    def investigate(self, ip: str) -> dict:
        """Gather all available intelligence about an IP."""
        if ip in self.intel_cache:
            cached = self.intel_cache[ip]
            if time.time() - cached.get("_ts", 0) < 600:
                return cached

        intel = {
            "ip": ip,
            "reverse_dns": "",
            "open_ports_checked": [],
            "dns_records": [],
            "reputation": "unknown",
            "first_investigated": time.time(),
            "_ts": time.time(),
        }

        # Reverse DNS
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                intel["reverse_dns"] = hostname
        except Exception:
            pass

        # Forward DNS verification (if we got a hostname)
        if intel["reverse_dns"]:
            try:
                addrs = socket.getaddrinfo(intel["reverse_dns"], None)
                intel["dns_records"] = list(set(a[4][0] for a in addrs))
                # Check if forward and reverse match
                intel["dns_verified"] = ip in intel["dns_records"]
            except Exception:
                intel["dns_verified"] = False

        # Quick port scan on common attacker infrastructure ports
        common_ports = [22, 80, 443, 8080, 8443]
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    intel["open_ports_checked"].append(port)
                s.close()
            except Exception:
                pass

        # Reputation heuristic
        if len(intel["open_ports_checked"]) == 0:
            intel["reputation"] = "stealth"
        elif len(intel["open_ports_checked"]) >= 4:
            intel["reputation"] = "suspicious-infra"
        elif 8080 in intel["open_ports_checked"] or 8443 in intel["open_ports_checked"]:
            intel["reputation"] = "proxy-likely"
        else:
            intel["reputation"] = "standard"

        self.intel_cache[ip] = intel

        self._timeline_cb("counter-intel", "info",
                          f"Investigation complete: {ip}",
                          {"ip": ip, "reputation": intel["reputation"],
                           "reverse_dns": intel["reverse_dns"]})

        logger.info(f"[CounterIntel] Investigated {ip}: reputation={intel['reputation']}")
        return intel

    def get_intel(self, ip: str) -> dict | None:
        return self.intel_cache.get(ip)


# ═══════════════════════════════════════════════════════════════════════════
# ISOLATION MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class IsolationManager:
    """Mark IPs for blocking and track isolation events."""

    def __init__(self, timeline_callback):
        self.isolated_ips: dict[str, dict] = {}
        self._timeline_cb = timeline_callback

    def isolate(self, ip: str, reason: str = "manual") -> dict:
        """Mark an IP for isolation/blocking."""
        if ip in self.isolated_ips:
            self.isolated_ips[ip]["block_count"] += 1
            return self.isolated_ips[ip]

        entry = {
            "ip": ip,
            "isolated_at": time.time(),
            "reason": reason,
            "block_count": 1,
            "active": True,
        }
        self.isolated_ips[ip] = entry

        logger.warning(f"[Isolation] IP isolated: {ip} (reason: {reason})")
        self._timeline_cb("isolation", "critical",
                          f"IP ISOLATED: {ip}",
                          {"ip": ip, "reason": reason})
        if HAS_TOAST:
            toast_block("StrikeBack", ip, f"Isolated: {reason}")

        # Write to blocklist file for integration with firewall tools
        blocklist_path = os.path.join(STRIKEBACK_DIR, "blocklist.txt")
        try:
            with open(blocklist_path, "a", encoding="utf-8") as f:
                f.write(f"{ip}  # {reason} @ {datetime.now().isoformat()}\n")
        except Exception as e:
            logger.error(f"[Isolation] Error writing blocklist: {e}")

        return entry

    def release(self, ip: str) -> bool:
        if ip in self.isolated_ips:
            self.isolated_ips[ip]["active"] = False
            self._timeline_cb("isolation", "info",
                              f"IP released from isolation: {ip}",
                              {"ip": ip})
            return True
        return False

    def is_isolated(self, ip: str) -> bool:
        entry = self.isolated_ips.get(ip)
        return entry is not None and entry["active"]

    def get_isolated(self) -> list:
        return [v for v in self.isolated_ips.values() if v["active"]]

    @property
    def count(self) -> int:
        return sum(1 for v in self.isolated_ips.values() if v["active"])


# ═══════════════════════════════════════════════════════════════════════════
# STRIKEBACK ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class StrikeBackEngine:
    """Main engine combining all active defense components."""

    def __init__(self):
        self.timeline: list[dict] = []
        self._max_timeline = 200
        self._running = True

        # Initialize components with timeline callback
        self.tarpit = TarpitEngine(self._add_timeline_event)
        self.decoys = DecoyDeployer(self._add_timeline_event)
        self.tracker = ThreatTracker(self._add_timeline_event)
        self.intel = CounterIntel(self._add_timeline_event)
        self.isolation = IsolationManager(self._add_timeline_event)

        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

    def _check_perm(self, perm_type="execute"):
        """Check if the current user has permission for a StrikeBack operation."""
        if not self._perm or not self._perm.is_enabled():
            return True
        if self._perm.locked and not self._auth_user:
            return False
        return self._perm.check(self._auth_user, "strikeback", perm_type)

    def _add_timeline_event(self, source: str, severity: str,
                            description: str, details: dict | None = None):
        """Add an event to the visual timeline."""
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

    def start(self):
        """Start all StrikeBack components."""
        logger.info("[StrikeBack] Starting all components...")

        # Start tarpit
        self.tarpit.start()

        # Deploy default decoys
        for decoy in DEFAULT_DECOYS:
            self.decoys.deploy(decoy["port"], decoy["service"])

        # Start the integration monitor (watches decoys for new attackers)
        t = threading.Thread(target=self._integration_loop, daemon=True)
        t.start()

        self._add_timeline_event("system", "info",
                                 "StrikeBack Agent activated",
                                 {"version": VERSION, "port": WS_PORT})
        logger.info("[StrikeBack] All components started")

    def _integration_loop(self):
        """Monitor decoys and tarpit for new attacker IPs, auto-track them."""
        seen_connections = 0
        while self._running:
            # Check decoys for new attacker IPs
            for decoy in self.decoys.decoys:
                for ip in decoy.get("attacker_ips", []):
                    if ip not in self.tracker.attackers:
                        self.tracker.track(ip, source=f"decoy-{decoy['service']}")

                    # Auto-classify based on decoy type
                    att = self.tracker.attackers.get(ip)
                    if att and att["type"] == "unknown":
                        svc = decoy["service"].lower()
                        if svc in ("mysql", "redis", "postgresql", "mssql", "mongodb"):
                            self.tracker.classify_attacker(ip, "exploit")
                        elif svc in ("telnet", "ssh", "ftp"):
                            self.tracker.classify_attacker(ip, "brute-force")
                        elif svc in ("smtp",):
                            self.tracker.classify_attacker(ip, "scanner")

                    # Auto-isolate high-danger attackers
                    if att and att["danger_score"] >= 80 and not att["isolated"]:
                        self.isolation.isolate(ip, reason="high-danger-auto")
                        att["isolated"] = True

            # Check tarpit for new IPs
            for ip in list(self.tarpit._patience_map.keys()):
                if ip not in self.tracker.attackers:
                    self.tracker.track(ip, source="tarpit")

            time.sleep(3)

    def get_state(self) -> dict:
        """Build the full state for WebSocket broadcast."""
        return {
            "type": "state",
            "version": VERSION,
            "ts": time.time(),
            "tarpit": self.tarpit.get_state(),
            "decoys": self.decoys.get_decoys(),
            "tracked_attackers": self.tracker.get_attackers(30),
            "isolation_count": self.isolation.count,
            "isolated_ips": self.isolation.get_isolated(),
            "timeline": self.timeline[-50:],
            "stats": {
                "total_attackers": len(self.tracker.attackers),
                "total_decoy_hits": sum(d["connections"] for d in self.decoys.decoys),
                "total_isolated": self.isolation.count,
                "tarpit_slowed": self.tarpit.connections_slowed,
                "decoys_active": len(self.decoys.decoys),
                "intel_investigations": len(self.intel.intel_cache),
            },
        }

    def stop(self):
        self._running = False
        self.tarpit.stop()
        self.decoys.stop()
        logger.info("[StrikeBack] Engine stopped")


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER
# ═══════════════════════════════════════════════════════════════════════════

_engine = StrikeBackEngine()
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
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        logger.error(f"[WS] Handler error: {e}")
    finally:
        _ws_clients.discard(websocket)
        logger.info(f"[WS] Client disconnected ({len(_ws_clients)} total)")


def _handle_command(cmd: str, msg: dict) -> dict:
    """Process a WebSocket command and return response."""
    if cmd == "get_state":
        return _engine.get_state()

    elif cmd == "deploy_decoy":
        if not _engine._check_perm("execute"):
            return {"error": "Permission denied: deploy_decoy requires execute permission"}
        port = msg.get("port")
        service = msg.get("service", "HTTP")
        if not port or not isinstance(port, int):
            return {"error": "port (int) is required"}
        return _engine.decoys.deploy(port, service)

    elif cmd == "remove_decoy":
        if not _engine._check_perm("execute"):
            return {"error": "Permission denied: remove_decoy requires execute permission"}
        port = msg.get("port")
        if not port:
            return {"error": "port is required"}
        ok = _engine.decoys.remove(port)
        return {"success": ok, "port": port}

    elif cmd == "track_ip":
        ip = msg.get("ip", "")
        if not ip:
            return {"error": "ip is required"}
        att = _engine.tracker.track(ip, source="manual")
        result = dict(att)
        result["sources"] = list(result.get("sources", set()))
        return {"type": "attacker", **result}

    elif cmd == "isolate_ip":
        if not _engine._check_perm("execute"):
            return {"error": "Permission denied: isolate_ip requires execute permission"}
        ip = msg.get("ip", "")
        reason = msg.get("reason", "manual")
        if not ip:
            return {"error": "ip is required"}
        entry = _engine.isolation.isolate(ip, reason=reason)
        # Also mark in tracker
        if ip in _engine.tracker.attackers:
            _engine.tracker.attackers[ip]["isolated"] = True
        return {"type": "isolation", **entry}

    elif cmd == "release_ip":
        if not _engine._check_perm("execute"):
            return {"error": "Permission denied: release_ip requires execute permission"}
        ip = msg.get("ip", "")
        if not ip:
            return {"error": "ip is required"}
        ok = _engine.isolation.release(ip)
        if ip in _engine.tracker.attackers:
            _engine.tracker.attackers[ip]["isolated"] = False
        return {"success": ok, "ip": ip}

    elif cmd == "get_attackers":
        limit = msg.get("limit", 50)
        return {
            "type": "attackers",
            "attackers": _engine.tracker.get_attackers(limit),
        }

    elif cmd == "investigate_ip":
        ip = msg.get("ip", "")
        if not ip:
            return {"error": "ip is required"}
        intel = _engine.intel.investigate(ip)
        return {"type": "intel", **intel}

    elif cmd == "get_timeline":
        limit = msg.get("limit", 50)
        return {
            "type": "timeline",
            "events": _engine.timeline[-limit:],
        }

    # ── Permission management commands ──────────────────────────
    elif cmd == "perm_get_status":
        if _engine._perm:
            return {"type": "perm_status", "enabled": _engine._perm.is_enabled(),
                    "locked": _engine._perm.locked, "auth_user": _engine._auth_user}
        return {"type": "perm_status", "enabled": False, "locked": False,
                "auth_user": None, "note": "permissions module not loaded"}

    elif cmd == "perm_enable":
        if _engine._perm:
            _engine._perm.enable()
            return {"success": True, "enabled": True}
        return {"error": "permissions module not loaded"}

    elif cmd == "perm_authenticate":
        user = msg.get("user", "")
        password = msg.get("password", "")
        if not _engine._perm:
            return {"error": "permissions module not loaded"}
        if _engine._perm.authenticate(user, password):
            _engine._auth_user = user
            return {"success": True, "user": user}
        return {"error": "Authentication failed"}

    elif cmd == "perm_lock":
        if _engine._perm:
            _engine._perm.locked = True
            _engine._auth_user = None
            return {"success": True, "locked": True}
        return {"error": "permissions module not loaded"}

    elif cmd == "perm_unlock":
        user = msg.get("user", "")
        password = msg.get("password", "")
        if not _engine._perm:
            return {"error": "permissions module not loaded"}
        if _engine._perm.authenticate(user, password):
            _engine._perm.locked = False
            _engine._auth_user = user
            return {"success": True, "locked": False, "user": user}
        return {"error": "Authentication failed"}

    else:
        return {"error": f"Unknown command: {cmd}"}


async def broadcast_loop():
    """Broadcast state to all connected WebSocket clients every 5 seconds."""
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
    logger.info("=" * 60)
    logger.info("  SentinelOS StrikeBack Agent v%s", VERSION)
    logger.info("  Active Defense -- Counter-Attack & Trap Threats")
    logger.info("  WebSocket port: %d", WS_PORT)
    logger.info("  Headless: %s", HEADLESS)
    logger.info("=" * 60)

    _engine.start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run():
        server = await websockets.serve(handle_ws, "localhost", WS_PORT)
        logger.info("[StrikeBack] WebSocket server on ws://localhost:%d", WS_PORT)
        asyncio.create_task(broadcast_loop())
        await asyncio.Future()  # Run forever

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        pass
    finally:
        _engine.stop()
        logger.info("[StrikeBack] Shutdown complete.")


if __name__ == "__main__":
    main()
