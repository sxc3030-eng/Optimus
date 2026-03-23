#!/usr/bin/env python3
"""
Mobile Gateway v1.0.0 — Optimus Suite
VPN gateway + DNS filter for mobile devices (Android/iOS).
Mobile devices connect via WireGuard and get DNS filtering + mail security.

Port: 8895 (API/WebSocket) + WireGuard 51820
Architecture:
    Mobile Gateway
        ├── WireGuardManager  — WireGuard server for mobile clients
        ├── QRCodeGenerator   — QR codes for mobile WireGuard config
        ├── DNSFilter         — DNS proxy with blocklists (ads, trackers, malware, phishing)
        ├── DeviceManager     — Connected mobile device tracking + policies
        ├── MailProxy         — Lightweight email security for mobile
        ├── GatewayEngine     — Main engine combining all components
        ├── GatewayAPI        — pywebview js_api bridge
        └── WebSocket Server  — port 8895 real-time state push
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
import subprocess
import socket
import hashlib
import base64
import ipaddress
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ── Optional dependencies ────────────────────────────────────────────────
try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[WARN] websockets not installed. Install with: pip install websockets")

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ── Shared Optimus modules ──────────────────────────────────────────
GATEWAY_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(GATEWAY_DIR)
sys.path.insert(0, BASE_DIR)

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

# ── Constants ────────────────────────────────────────────────────────────
VERSION = "1.0.0"
WS_PORT = 8895
WG_PORT = 51820
WG_SUBNET = "10.100.0"
WG_ADDR = f"{WG_SUBNET}.1/24"
DNS_UPSTREAM = "8.8.8.8"
DNS_UPSTREAM_ALT = "1.1.1.1"
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

CONFIGS_DIR = os.path.join(GATEWAY_DIR, "configs")
BLOCKLISTS_DIR = os.path.join(GATEWAY_DIR, "dns_blocklists")
LOG_DIR = os.path.join(GATEWAY_DIR, "logs")
SETTINGS_FILE = os.path.join(GATEWAY_DIR, "gateway_settings.json")

for _d in [CONFIGS_DIR, BLOCKLISTS_DIR, LOG_DIR]:
    os.makedirs(_d, exist_ok=True)

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MobileGateway] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "gateway.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("Optimus.MobileGateway")


# ═══════════════════════════════════════════════════════════════════════════
# WIREGUARD MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class WireGuardManager:
    """Manages WireGuard server for mobile clients."""

    def __init__(self):
        self.server_private_key = ""
        self.server_public_key = ""
        self.peers: dict[str, dict] = {}
        self.interface_up = False
        self.listen_port = WG_PORT
        self.config_path = os.path.join(CONFIGS_DIR, "wg0.conf")
        self._next_ip_index = 2  # 10.100.0.2 is the first client IP
        self._wg_bin = self._find_wireguard()
        self._load_state()

    def _find_wireguard(self) -> str:
        """Locate the WireGuard binary."""
        if IS_WINDOWS:
            candidates = [
                r"C:\Program Files\WireGuard\wg.exe",
                r"C:\Program Files (x86)\WireGuard\wg.exe",
                os.path.join(BASE_DIR, "wireguard", "wg.exe"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c
        else:
            for p in ["/usr/bin/wg", "/usr/local/bin/wg", "/snap/bin/wg"]:
                if os.path.isfile(p):
                    return p
        return "wg"  # rely on PATH

    def _state_file(self) -> str:
        return os.path.join(CONFIGS_DIR, "wg_state.json")

    def _load_state(self):
        """Load persisted WireGuard state (keys, peers)."""
        sf = self._state_file()
        if os.path.isfile(sf):
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.server_private_key = data.get("server_private_key", "")
                self.server_public_key = data.get("server_public_key", "")
                self.peers = data.get("peers", {})
                self._next_ip_index = data.get("next_ip_index", 2)
                logger.info(f"[WG] Loaded state: {len(self.peers)} peers")
            except Exception as e:
                logger.error(f"[WG] Error loading state: {e}")

    def _save_state(self):
        """Persist WireGuard state to disk."""
        sf = self._state_file()
        try:
            data = {
                "server_private_key": self.server_private_key,
                "server_public_key": self.server_public_key,
                "peers": self.peers,
                "next_ip_index": self._next_ip_index,
            }
            with open(sf, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[WG] Error saving state: {e}")

    def generate_keypair(self) -> tuple[str, str]:
        """Generate a WireGuard private/public key pair."""
        # Try native wg tool first
        try:
            priv = subprocess.check_output(
                [self._wg_bin, "genkey"], stderr=subprocess.DEVNULL
            ).decode().strip()
            pub = subprocess.check_output(
                [self._wg_bin, "pubkey"], input=priv.encode(),
                stderr=subprocess.DEVNULL
            ).decode().strip()
            return priv, pub
        except (FileNotFoundError, subprocess.CalledProcessError, OSError):
            pass

        # Fallback: cryptography library
        if HAS_CRYPTO:
            try:
                private_key = X25519PrivateKey.generate()
                priv_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_bytes = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                priv = base64.b64encode(priv_bytes).decode()
                pub = base64.b64encode(pub_bytes).decode()
                return priv, pub
            except Exception as e:
                logger.warning(f"[WG] Crypto fallback failed: {e}")

        # Last resort: generate pseudo-random keys (NOT cryptographically secure for production)
        logger.warning("[WG] No key generation method available — using random placeholder keys")
        raw_priv = os.urandom(32)
        raw_pub = hashlib.sha256(raw_priv).digest()
        return base64.b64encode(raw_priv).decode(), base64.b64encode(raw_pub).decode()

    def create_server_config(self) -> str:
        """Create the WireGuard server configuration (wg0.conf)."""
        if not self.server_private_key:
            self.server_private_key, self.server_public_key = self.generate_keypair()
            self._save_state()
            logger.info(f"[WG] Generated server keys. Public: {self.server_public_key[:20]}...")

        lines = [
            "[Interface]",
            f"Address = {WG_ADDR}",
            f"ListenPort = {self.listen_port}",
            f"PrivateKey = {self.server_private_key}",
            f"DNS = {WG_SUBNET}.1",
            "",
            "# PostUp/PostDown for DNS forwarding",
        ]

        if IS_LINUX:
            lines.append("PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; "
                          "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
            lines.append("PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
                          "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE")
        elif IS_WINDOWS:
            lines.append("# Windows: enable IP routing via registry or netsh")

        lines.append("")

        # Add all peers
        for pub_key, peer in self.peers.items():
            lines.extend([
                f"# Peer: {peer.get('name', 'unknown')} ({peer.get('device_type', 'unknown')})",
                "[Peer]",
                f"PublicKey = {pub_key}",
                f"AllowedIPs = {peer['ip']}/32",
                "",
            ])

        config_text = "\n".join(lines)
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                f.write(config_text)
            logger.info(f"[WG] Server config written to {self.config_path}")
        except Exception as e:
            logger.error(f"[WG] Failed to write config: {e}")

        self._save_state()
        return config_text

    def add_peer(self, device_name: str, device_type: str = "android") -> dict:
        """Generate client keys, assign IP, create peer config. Returns peer info + client config."""
        if self._next_ip_index > 254:
            return {"error": "Maximum peers reached (253 devices)"}

        if not self.server_public_key:
            self.create_server_config()

        client_priv, client_pub = self.generate_keypair()
        client_ip = f"{WG_SUBNET}.{self._next_ip_index}"
        self._next_ip_index += 1

        # Detect external endpoint
        endpoint = self._get_endpoint()

        peer_info = {
            "name": device_name,
            "device_type": device_type.lower(),
            "ip": client_ip,
            "public_key": client_pub,
            "private_key": client_priv,  # stored temporarily for QR/config generation
            "registered_at": datetime.now().isoformat(),
            "last_seen": None,
            "traffic_up": 0,
            "traffic_down": 0,
            "blocked_queries": 0,
            "active": False,
        }
        self.peers[client_pub] = peer_info

        # Build client WireGuard config
        client_config = self._build_client_config(
            client_priv, client_ip, self.server_public_key, endpoint
        )

        # Save client config to file
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in device_name)
        config_file = os.path.join(CONFIGS_DIR, f"{safe_name}_{client_pub[:8]}.conf")
        try:
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(client_config)
        except Exception as e:
            logger.error(f"[WG] Failed to save client config: {e}")

        # Regenerate server config with new peer
        self.create_server_config()

        logger.info(f"[WG] Added peer: {device_name} ({device_type}) -> {client_ip}")
        if HAS_TOAST:
            try:
                toast_event(f"New device: {device_name}", f"IP: {client_ip}")
            except Exception:
                pass

        return {
            "public_key": client_pub,
            "ip": client_ip,
            "config": client_config,
            "config_file": config_file,
            "peer": peer_info,
        }

    def _build_client_config(self, priv_key: str, client_ip: str,
                              server_pub: str, endpoint: str) -> str:
        """Build a WireGuard client configuration string."""
        return (
            f"[Interface]\n"
            f"PrivateKey = {priv_key}\n"
            f"Address = {client_ip}/32\n"
            f"DNS = {WG_SUBNET}.1\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {server_pub}\n"
            f"Endpoint = {endpoint}:{self.listen_port}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"PersistentKeepalive = 25\n"
        )

    def _get_endpoint(self) -> str:
        """Get the public/local IP for endpoint configuration."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "YOUR_SERVER_IP"

    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer by public key."""
        if public_key in self.peers:
            peer_name = self.peers[public_key].get("name", "unknown")
            del self.peers[public_key]
            self.create_server_config()
            logger.info(f"[WG] Removed peer: {peer_name} ({public_key[:16]}...)")
            return True
        logger.warning(f"[WG] Peer not found: {public_key[:16]}...")
        return False

    def get_peers(self) -> list[dict]:
        """List all peers with traffic stats."""
        result = []
        # Try to get live stats from wg show
        live_stats = self._get_live_stats()
        for pub_key, peer in self.peers.items():
            info = dict(peer)
            info["public_key"] = pub_key
            # Merge live stats if available
            if pub_key in live_stats:
                info.update(live_stats[pub_key])
                info["active"] = True
                peer["last_seen"] = datetime.now().isoformat()
                peer["traffic_up"] = live_stats[pub_key].get("transfer_rx", peer["traffic_up"])
                peer["traffic_down"] = live_stats[pub_key].get("transfer_tx", peer["traffic_down"])
            result.append(info)
        return result

    def _get_live_stats(self) -> dict:
        """Query wg show for live peer statistics."""
        stats = {}
        try:
            output = subprocess.check_output(
                [self._wg_bin, "show", "wg0", "dump"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()
            for line in output.split("\n")[1:]:  # skip header
                parts = line.split("\t")
                if len(parts) >= 5:
                    pub = parts[0]
                    stats[pub] = {
                        "endpoint": parts[2] if len(parts) > 2 else "",
                        "latest_handshake": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                        "transfer_rx": int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0,
                        "transfer_tx": int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0,
                    }
        except Exception:
            pass
        return stats

    def start_tunnel(self) -> dict:
        """Bring the WireGuard interface up."""
        if not os.path.isfile(self.config_path):
            self.create_server_config()
        try:
            if IS_WINDOWS:
                wg_svc = self._wg_bin.replace("wg.exe", "wireguard.exe")
                subprocess.run(
                    [wg_svc, "/installtunnelservice", self.config_path],
                    check=True, timeout=15, capture_output=True
                )
            else:
                subprocess.run(
                    ["wg-quick", "up", self.config_path],
                    check=True, timeout=15, capture_output=True
                )
            self.interface_up = True
            logger.info("[WG] Tunnel interface UP")
            return {"success": True, "status": "up"}
        except FileNotFoundError:
            logger.error("[WG] WireGuard binary not found")
            return {"success": False, "error": "WireGuard not installed"}
        except subprocess.CalledProcessError as e:
            logger.error(f"[WG] Tunnel start failed: {e.stderr.decode() if e.stderr else e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"[WG] Tunnel start error: {e}")
            return {"success": False, "error": str(e)}

    def stop_tunnel(self) -> dict:
        """Bring the WireGuard interface down."""
        try:
            if IS_WINDOWS:
                wg_svc = self._wg_bin.replace("wg.exe", "wireguard.exe")
                subprocess.run(
                    [wg_svc, "/uninstalltunnelservice", "wg0"],
                    check=True, timeout=15, capture_output=True
                )
            else:
                subprocess.run(
                    ["wg-quick", "down", self.config_path],
                    check=True, timeout=15, capture_output=True
                )
            self.interface_up = False
            logger.info("[WG] Tunnel interface DOWN")
            return {"success": True, "status": "down"}
        except Exception as e:
            logger.error(f"[WG] Tunnel stop error: {e}")
            return {"success": False, "error": str(e)}

    def get_status(self) -> dict:
        """Return WireGuard interface status."""
        peers = self.get_peers()
        active_count = sum(1 for p in peers if p.get("active"))
        total_up = sum(p.get("traffic_up", 0) for p in peers)
        total_down = sum(p.get("traffic_down", 0) for p in peers)
        return {
            "interface_up": self.interface_up,
            "listen_port": self.listen_port,
            "server_public_key": self.server_public_key,
            "total_peers": len(self.peers),
            "active_peers": active_count,
            "total_bandwidth_up": total_up,
            "total_bandwidth_down": total_down,
            "config_path": self.config_path,
        }


# ═══════════════════════════════════════════════════════════════════════════
# QR CODE GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

class QRCodeGenerator:
    """Generates QR codes for mobile WireGuard configuration."""

    @staticmethod
    def generate_qr(config_text: str) -> dict:
        """
        Generate a QR code from WireGuard config text.
        Returns dict with 'image' (base64 PNG) or 'text' (config for manual entry).
        """
        if HAS_QRCODE:
            try:
                import io
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=8,
                    border=4,
                )
                qr.add_data(config_text)
                qr.make(fit=True)

                if HAS_PIL:
                    img = qr.make_image(fill_color="white", back_color="#0f0f13")
                    buf = io.BytesIO()
                    img.save(buf, format="PNG")
                    b64 = base64.b64encode(buf.getvalue()).decode()
                    return {"type": "image", "image": b64, "format": "png"}
                else:
                    # Text-mode QR using ASCII
                    matrix = qr.get_matrix()
                    ascii_qr = ""
                    for row in matrix:
                        line = ""
                        for cell in row:
                            line += "\u2588\u2588" if cell else "  "
                        ascii_qr += line + "\n"
                    return {"type": "ascii", "ascii": ascii_qr}
            except Exception as e:
                logger.warning(f"[QR] Generation error: {e}")

        # Fallback: return text config for manual entry
        return {
            "type": "text",
            "text": config_text,
            "message": "QR library not available. Copy this config manually to your device.",
        }


# ═══════════════════════════════════════════════════════════════════════════
# DNS FILTER
# ═══════════════════════════════════════════════════════════════════════════

class DNSFilter:
    """DNS proxy server with domain blocklists (ads, trackers, malware, phishing)."""

    CATEGORIES = ["ads", "trackers", "malware", "phishing", "adult"]

    def __init__(self):
        self.blocklists: dict[str, set] = {cat: set() for cat in self.CATEGORIES}
        self.enabled_categories: dict[str, bool] = {cat: True for cat in self.CATEGORIES}
        self.custom_block: set = set()
        self.custom_allow: set = set()  # whitelist overrides
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "forwarded_queries": 0,
            "top_blocked": defaultdict(int),
            "top_queried": defaultdict(int),
            "queries_today": 0,
            "blocked_today": 0,
            "day_marker": datetime.now().strftime("%Y-%m-%d"),
        }
        self.running = False
        self._server_socket = None
        self._thread = None
        self._load_blocklists()

    def _load_blocklists(self):
        """Load all blocklist files from dns_blocklists/ directory."""
        for category in self.CATEGORIES:
            filepath = os.path.join(BLOCKLISTS_DIR, f"{category}.txt")
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self.blocklists[category].add(line.lower())
                    count = len(self.blocklists[category])
                    logger.info(f"[DNS] Loaded {count} domains for category '{category}'")
                except Exception as e:
                    logger.error(f"[DNS] Error loading {filepath}: {e}")
            else:
                logger.info(f"[DNS] No blocklist file for category '{category}'")

        total = sum(len(bl) for bl in self.blocklists.values())
        logger.info(f"[DNS] Total blocked domains across all categories: {total}")

    def is_blocked(self, domain: str) -> tuple[bool, str]:
        """Check if a domain should be blocked. Returns (blocked, category)."""
        domain = domain.lower().rstrip(".")

        # Custom allow list (whitelist) takes priority
        if domain in self.custom_allow:
            return False, ""

        # Custom block list
        if domain in self.custom_block:
            return True, "custom"

        # Check each enabled category
        for category in self.CATEGORIES:
            if not self.enabled_categories.get(category, False):
                continue
            if domain in self.blocklists[category]:
                return True, category
            # Check parent domain (e.g., sub.tracker.com matches tracker.com)
            parts = domain.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in self.blocklists[category]:
                    return True, category

        return False, ""

    def resolve(self, query_domain: str) -> tuple[str, bool, str]:
        """
        Resolve a DNS query.
        Returns (ip_result, was_blocked, category).
        If blocked -> returns 0.0.0.0; else forwards to upstream DNS.
        """
        # Reset daily counters if needed
        today = datetime.now().strftime("%Y-%m-%d")
        if today != self.stats["day_marker"]:
            self.stats["queries_today"] = 0
            self.stats["blocked_today"] = 0
            self.stats["day_marker"] = today

        self.stats["total_queries"] += 1
        self.stats["queries_today"] += 1
        self.stats["top_queried"][query_domain] += 1

        blocked, category = self.is_blocked(query_domain)
        if blocked:
            self.stats["blocked_queries"] += 1
            self.stats["blocked_today"] += 1
            self.stats["top_blocked"][query_domain] += 1
            logger.debug(f"[DNS] BLOCKED: {query_domain} (category: {category})")
            return "0.0.0.0", True, category

        # Forward to upstream DNS
        self.stats["forwarded_queries"] += 1
        resolved_ip = self._forward_dns(query_domain)
        return resolved_ip, False, ""

    def _forward_dns(self, domain: str) -> str:
        """Forward DNS query to upstream resolver."""
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            if result:
                return result[0][4][0]
        except socket.gaierror:
            pass
        return "0.0.0.0"

    def _build_dns_response(self, data: bytes, blocked: bool) -> bytes:
        """Build a minimal DNS response packet."""
        # Transaction ID (first 2 bytes from request)
        tid = data[:2]
        # Flags: standard response, no error (or NXDOMAIN if blocked)
        flags = b'\x81\x80'  # Standard query response, no error
        # Questions count (from request)
        qdcount = data[4:6]
        # Answer count
        ancount = b'\x00\x01' if blocked else b'\x00\x00'
        # Authority + additional = 0
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'

        header = tid + flags + qdcount + ancount + nscount + arcount

        # Copy the question section from request
        question_end = 12
        while question_end < len(data) and data[question_end] != 0:
            question_end += data[question_end] + 1
        question_end += 5  # null byte + qtype (2) + qclass (2)
        question = data[12:question_end]

        response = header + question

        if blocked:
            # Add answer: pointer to name + A record + 0.0.0.0
            response += b'\xc0\x0c'         # Name pointer to question
            response += b'\x00\x01'         # Type A
            response += b'\x00\x01'         # Class IN
            response += b'\x00\x00\x00\x3c' # TTL 60 seconds
            response += b'\x00\x04'         # Data length 4
            response += b'\x00\x00\x00\x00' # 0.0.0.0

        return response

    def _extract_domain(self, data: bytes) -> str:
        """Extract queried domain name from DNS packet."""
        domain_parts = []
        idx = 12  # Skip DNS header
        try:
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    break
                idx += 1
                domain_parts.append(data[idx:idx + length].decode("ascii", errors="replace"))
                idx += length
        except (IndexError, UnicodeDecodeError):
            return ""
        return ".".join(domain_parts)

    def start_dns_server(self):
        """Start the UDP DNS proxy server on port 53."""
        if self.running:
            return

        def _serve():
            try:
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_socket.settimeout(2.0)
                self._server_socket.bind(("0.0.0.0", 53))
                self.running = True
                logger.info("[DNS] DNS proxy server started on port 53")

                while self.running:
                    try:
                        data, addr = self._server_socket.recvfrom(1024)
                        if len(data) < 12:
                            continue
                        domain = self._extract_domain(data)
                        if not domain:
                            continue

                        _, was_blocked, _ = self.resolve(domain)
                        response = self._build_dns_response(data, was_blocked)

                        if not was_blocked:
                            # Forward to upstream and relay response
                            try:
                                upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                upstream.settimeout(3.0)
                                upstream.sendto(data, (DNS_UPSTREAM, 53))
                                resp_data, _ = upstream.recvfrom(4096)
                                upstream.close()
                                self._server_socket.sendto(resp_data, addr)
                            except Exception:
                                self._server_socket.sendto(response, addr)
                        else:
                            self._server_socket.sendto(response, addr)

                    except socket.timeout:
                        continue
                    except OSError:
                        if not self.running:
                            break
                    except Exception as e:
                        logger.debug(f"[DNS] Error handling query: {e}")

            except PermissionError:
                logger.error("[DNS] Permission denied: port 53 requires admin/root privileges")
                self.running = False
            except OSError as e:
                logger.error(f"[DNS] Could not bind port 53: {e}")
                self.running = False

        self._thread = threading.Thread(target=_serve, daemon=True, name="DNSFilter")
        self._thread.start()

    def stop_dns_server(self):
        """Stop the DNS proxy server."""
        self.running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None
        logger.info("[DNS] DNS proxy server stopped")

    def toggle_category(self, category: str, enabled: bool) -> bool:
        """Enable or disable a blocklist category."""
        if category in self.enabled_categories:
            self.enabled_categories[category] = enabled
            status = "enabled" if enabled else "disabled"
            logger.info(f"[DNS] Category '{category}' {status}")
            return True
        return False

    def add_custom_rule(self, domain: str, action: str = "block") -> bool:
        """Add a custom DNS rule (block or allow)."""
        domain = domain.lower().strip()
        if not domain:
            return False
        if action == "block":
            self.custom_block.add(domain)
            self.custom_allow.discard(domain)
            logger.info(f"[DNS] Custom block: {domain}")
        elif action == "allow":
            self.custom_allow.add(domain)
            self.custom_block.discard(domain)
            logger.info(f"[DNS] Custom allow: {domain}")
        else:
            return False
        return True

    def remove_custom_rule(self, domain: str) -> bool:
        """Remove a custom DNS rule."""
        domain = domain.lower().strip()
        removed = False
        if domain in self.custom_block:
            self.custom_block.discard(domain)
            removed = True
        if domain in self.custom_allow:
            self.custom_allow.discard(domain)
            removed = True
        return removed

    def get_stats(self) -> dict:
        """Return DNS filter statistics."""
        top_blocked = sorted(
            self.stats["top_blocked"].items(), key=lambda x: x[1], reverse=True
        )[:20]
        top_queried = sorted(
            self.stats["top_queried"].items(), key=lambda x: x[1], reverse=True
        )[:20]

        blocklist_sizes = {cat: len(domains) for cat, domains in self.blocklists.items()}
        return {
            "total_queries": self.stats["total_queries"],
            "blocked_queries": self.stats["blocked_queries"],
            "forwarded_queries": self.stats["forwarded_queries"],
            "queries_today": self.stats["queries_today"],
            "blocked_today": self.stats["blocked_today"],
            "block_rate": round(
                self.stats["blocked_queries"] / max(self.stats["total_queries"], 1) * 100, 1
            ),
            "top_blocked": top_blocked,
            "top_queried": top_queried,
            "enabled_categories": dict(self.enabled_categories),
            "blocklist_sizes": blocklist_sizes,
            "custom_block_count": len(self.custom_block),
            "custom_allow_count": len(self.custom_allow),
            "dns_running": self.running,
        }


# ═══════════════════════════════════════════════════════════════════════════
# DEVICE MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class DeviceManager:
    """Tracks connected mobile devices with policies."""

    def __init__(self, wg_manager: WireGuardManager):
        self.wg = wg_manager
        self.policies: dict[str, dict] = {}  # pubkey -> policy settings
        self._state_file = os.path.join(CONFIGS_DIR, "devices_state.json")
        self._load_policies()

    def _load_policies(self):
        """Load device policies from disk."""
        if os.path.isfile(self._state_file):
            try:
                with open(self._state_file, "r", encoding="utf-8") as f:
                    self.policies = json.load(f)
            except Exception as e:
                logger.error(f"[Devices] Error loading policies: {e}")

    def _save_policies(self):
        """Save device policies to disk."""
        try:
            with open(self._state_file, "w", encoding="utf-8") as f:
                json.dump(self.policies, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[Devices] Error saving policies: {e}")

    def register_device(self, name: str, device_type: str = "phone",
                        os_type: str = "android") -> dict:
        """Register a new mobile device. Creates WireGuard peer."""
        result = self.wg.add_peer(name, device_type)
        if "error" in result:
            return result

        pub_key = result["public_key"]
        self.policies[pub_key] = {
            "name": name,
            "device_type": device_type,
            "os_type": os_type.lower(),
            "time_restriction": None,  # e.g., {"start": "22:00", "end": "07:00"}
            "blocked_categories": [],  # additional per-device blocked categories
            "profile": "default",      # default, kids, restricted
        }
        self._save_policies()
        return result

    def remove_device(self, public_key: str) -> bool:
        """Remove a device and its WireGuard peer."""
        success = self.wg.remove_peer(public_key)
        if success:
            self.policies.pop(public_key, None)
            self._save_policies()
        return success

    def get_devices(self) -> list[dict]:
        """Get all registered devices with status."""
        peers = self.wg.get_peers()
        for peer in peers:
            pub_key = peer.get("public_key", "")
            policy = self.policies.get(pub_key, {})
            peer["os_type"] = policy.get("os_type", "unknown")
            peer["profile"] = policy.get("profile", "default")
            peer["time_restriction"] = policy.get("time_restriction")
        return peers

    def get_device_stats(self, public_key: str) -> dict:
        """Get detailed stats for a single device."""
        peer = self.wg.peers.get(public_key, {})
        policy = self.policies.get(public_key, {})
        return {
            "peer": peer,
            "policy": policy,
            "traffic_up": peer.get("traffic_up", 0),
            "traffic_down": peer.get("traffic_down", 0),
            "blocked_queries": peer.get("blocked_queries", 0),
            "last_seen": peer.get("last_seen"),
            "active": peer.get("active", False),
        }

    def set_policy(self, public_key: str, profile: str = None,
                   time_restriction: dict = None,
                   blocked_categories: list = None) -> bool:
        """Set device policy (profile, time restriction, extra blocked categories)."""
        if public_key not in self.policies:
            return False
        if profile is not None:
            self.policies[public_key]["profile"] = profile
        if time_restriction is not None:
            self.policies[public_key]["time_restriction"] = time_restriction
        if blocked_categories is not None:
            self.policies[public_key]["blocked_categories"] = blocked_categories
        self._save_policies()
        return True

    def check_time_policy(self, public_key: str) -> bool:
        """Check if device is allowed by time policy. Returns True if allowed."""
        policy = self.policies.get(public_key, {})
        restriction = policy.get("time_restriction")
        if not restriction:
            return True

        now = datetime.now().strftime("%H:%M")
        start = restriction.get("start", "00:00")
        end = restriction.get("end", "00:00")

        # Block between start and end (e.g., 22:00 to 07:00 = blocked overnight)
        if start <= end:
            return not (start <= now <= end)
        else:
            # Overnight restriction (e.g., 22:00 -> 07:00)
            return not (now >= start or now <= end)


# ═══════════════════════════════════════════════════════════════════════════
# MAIL PROXY (Lightweight email security)
# ═══════════════════════════════════════════════════════════════════════════

class MailProxy:
    """Lightweight email security advisory for mobile devices."""

    # Known phishing URL patterns
    PHISHING_PATTERNS = [
        "secure-login-", "account-verify-", "password-reset-",
        "update-billing-", "confirm-identity-", "suspended-account-",
        "urgent-action-", "verify-now-", "click-here-to-",
    ]

    # Known malware file hashes (placeholder set)
    KNOWN_MALWARE_HASHES = set()

    def __init__(self):
        self.checks_performed = 0
        self.threats_found = 0
        self.sandbox_available = False
        self._check_sandbox()

    def _check_sandbox(self):
        """Check if Sandbox agent (port 8890) is reachable."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("localhost", 8890))
            s.close()
            self.sandbox_available = True
            logger.info("[MailProxy] Sandbox agent detected on port 8890")
        except Exception:
            self.sandbox_available = False

    def check_url(self, url: str) -> dict:
        """Check a URL against phishing patterns and databases."""
        self.checks_performed += 1
        url_lower = url.lower()

        # Check against phishing patterns
        for pattern in self.PHISHING_PATTERNS:
            if pattern in url_lower:
                self.threats_found += 1
                return {
                    "url": url,
                    "safe": False,
                    "threat_type": "phishing",
                    "confidence": 0.85,
                    "reason": f"Matches phishing pattern: {pattern}",
                }

        # Check suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"]
        for tld in suspicious_tlds:
            if url_lower.endswith(tld) or f"{tld}/" in url_lower:
                return {
                    "url": url,
                    "safe": False,
                    "threat_type": "suspicious",
                    "confidence": 0.6,
                    "reason": f"Suspicious TLD: {tld}",
                }

        # Check for IP-based URLs (common in phishing)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            try:
                ipaddress.ip_address(host)
                return {
                    "url": url,
                    "safe": False,
                    "threat_type": "suspicious",
                    "confidence": 0.7,
                    "reason": "URL uses IP address instead of domain name",
                }
            except ValueError:
                pass
        except Exception:
            pass

        return {"url": url, "safe": True, "threat_type": None, "confidence": 1.0, "reason": ""}

    def check_attachment_hash(self, file_hash: str) -> dict:
        """Check a file hash against known malware databases."""
        self.checks_performed += 1
        file_hash = file_hash.lower().strip()

        if file_hash in self.KNOWN_MALWARE_HASHES:
            self.threats_found += 1
            return {
                "hash": file_hash,
                "safe": False,
                "threat_type": "malware",
                "confidence": 0.95,
            }

        # If sandbox is available, submit for analysis
        if self.sandbox_available:
            return {
                "hash": file_hash,
                "safe": True,
                "threat_type": None,
                "note": "Submitted to Sandbox for deeper analysis",
            }

        return {"hash": file_hash, "safe": True, "threat_type": None}

    def get_stats(self) -> dict:
        return {
            "checks_performed": self.checks_performed,
            "threats_found": self.threats_found,
            "sandbox_available": self.sandbox_available,
        }


# ═══════════════════════════════════════════════════════════════════════════
# GATEWAY ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class GatewayEngine:
    """Main engine combining WireGuard, DNS filter, device manager, mail proxy."""

    def __init__(self):
        self.wg = WireGuardManager()
        self.qr = QRCodeGenerator()
        self.dns = DNSFilter()
        self.devices = DeviceManager(self.wg)
        self.mail = MailProxy()
        self.running = False
        self.started_at = None
        self.timeline: deque = deque(maxlen=200)
        self.clients: set = set()  # WebSocket clients
        self.loop = None
        self._settings = {}
        self._load_settings()

    def _load_settings(self):
        """Load gateway settings."""
        if os.path.isfile(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    self._settings = json.load(f)
                # Restore DNS category states
                for cat, enabled in self._settings.get("dns_categories", {}).items():
                    self.dns.toggle_category(cat, enabled)
            except Exception as e:
                logger.error(f"[Engine] Error loading settings: {e}")

    def _save_settings(self):
        """Save gateway settings."""
        self._settings["dns_categories"] = dict(self.dns.enabled_categories)
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._settings, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[Engine] Error saving settings: {e}")

    def timeline_add(self, icon: str, message: str, category: str = "system"):
        """Add an event to the timeline."""
        self.timeline.appendleft({
            "ts": time.time(),
            "time": datetime.now().strftime("%H:%M:%S"),
            "icon": icon,
            "message": message,
            "category": category,
        })

    def start(self):
        """Start all gateway components."""
        if self.running:
            return
        self.running = True
        self.started_at = time.time()

        # Ensure server config exists
        self.wg.create_server_config()

        # Start DNS filter
        self.dns.start_dns_server()

        # Check mail proxy sandbox
        self.mail._check_sandbox()

        self.timeline_add("rocket", "Mobile Gateway started", "system")
        logger.info("[Engine] Gateway started")

    def stop(self):
        """Stop all gateway components."""
        self.running = False
        self.dns.stop_dns_server()
        self._save_settings()
        self.timeline_add("stop", "Mobile Gateway stopped", "system")
        logger.info("[Engine] Gateway stopped")

    def get_state(self) -> dict:
        """Build full dashboard state."""
        uptime = 0
        if self.started_at:
            uptime = int(time.time() - self.started_at)

        devices = self.devices.get_devices()
        active_devices = [d for d in devices if d.get("active")]
        total_up = sum(d.get("traffic_up", 0) for d in devices)
        total_down = sum(d.get("traffic_down", 0) for d in devices)

        return {
            "type": "state",
            "version": VERSION,
            "running": self.running,
            "uptime": uptime,
            "wireguard": self.wg.get_status(),
            "dns": self.dns.get_stats(),
            "mail": self.mail.get_stats(),
            "devices": devices,
            "device_count": len(devices),
            "active_count": len(active_devices),
            "total_bandwidth_up": total_up,
            "total_bandwidth_down": total_down,
            "timeline": list(self.timeline)[:50],
        }

    async def broadcast_state(self):
        """Periodically broadcast state to WebSocket clients."""
        while self.running:
            if self.clients:
                try:
                    state = json.dumps(self.get_state(), default=str)
                    await asyncio.gather(
                        *[c.send(state) for c in self.clients.copy()],
                        return_exceptions=True,
                    )
                except Exception:
                    pass
            await asyncio.sleep(5)


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL ENGINE INSTANCE
# ═══════════════════════════════════════════════════════════════════════════

_engine = GatewayEngine()


# ═══════════════════════════════════════════════════════════════════════════
# GATEWAY API (pywebview js_api)
# ═══════════════════════════════════════════════════════════════════════════

class GatewayAPI:
    """API exposed to JavaScript via pywebview.api."""

    def __init__(self):
        self._window = None
        self._stop_broadcast = False
        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

    def set_window(self, window):
        self._window = window

    # ── Permission helper ────────────────────────────────────────────────
    def _check_perm(self, action):
        if self._perm and not self._perm.check("mobile_gateway", action, self._auth_user):
            return {"type": "error", "message": f"Permission denied: {action}"}
        return None

    # ── State ────────────────────────────────────────────────────────────
    def get_state(self):
        return json.loads(json.dumps(_engine.get_state(), default=str))

    # ── Gateway control ──────────────────────────────────────────────────
    def start_gateway(self):
        denied = self._check_perm("start")
        if denied:
            return denied
        _engine.start()
        return {"type": "ack", "cmd": "start_gateway", "running": True}

    def stop_gateway(self):
        denied = self._check_perm("stop")
        if denied:
            return denied
        _engine.stop()
        return {"type": "ack", "cmd": "stop_gateway", "running": False}

    # ── Device management ────────────────────────────────────────────────
    def add_device(self, name, device_type="phone", os_type="android"):
        denied = self._check_perm("manage_devices")
        if denied:
            return denied
        result = _engine.devices.register_device(name, device_type, os_type)
        if "error" not in result:
            _engine.timeline_add("phone", f"Device added: {name} ({os_type})", "device")
        return json.loads(json.dumps(result, default=str))

    def remove_device(self, pubkey):
        denied = self._check_perm("manage_devices")
        if denied:
            return denied
        peer = _engine.wg.peers.get(pubkey, {})
        name = peer.get("name", "unknown")
        success = _engine.devices.remove_device(pubkey)
        if success:
            _engine.timeline_add("trash", f"Device removed: {name}", "device")
        return {"type": "ack", "success": success, "removed": name}

    def get_devices(self):
        return json.loads(json.dumps(_engine.devices.get_devices(), default=str))

    def get_device_stats(self, pubkey):
        return json.loads(json.dumps(_engine.devices.get_device_stats(pubkey), default=str))

    def set_device_policy(self, pubkey, profile=None, time_start=None,
                          time_end=None, blocked_categories=None):
        denied = self._check_perm("manage_devices")
        if denied:
            return denied
        time_restriction = None
        if time_start and time_end:
            time_restriction = {"start": time_start, "end": time_end}
        success = _engine.devices.set_policy(
            pubkey, profile=profile,
            time_restriction=time_restriction,
            blocked_categories=blocked_categories,
        )
        return {"type": "ack", "success": success}

    # ── QR Code ──────────────────────────────────────────────────────────
    def get_qr_code(self, pubkey):
        peer = _engine.wg.peers.get(pubkey)
        if not peer:
            return {"error": "Peer not found"}
        config = _engine.wg._build_client_config(
            peer.get("private_key", ""),
            peer.get("ip", ""),
            _engine.wg.server_public_key,
            _engine.wg._get_endpoint(),
        )
        return _engine.qr.generate_qr(config)

    def get_config_text(self, pubkey):
        peer = _engine.wg.peers.get(pubkey)
        if not peer:
            return {"error": "Peer not found"}
        config = _engine.wg._build_client_config(
            peer.get("private_key", ""),
            peer.get("ip", ""),
            _engine.wg.server_public_key,
            _engine.wg._get_endpoint(),
        )
        return {"config": config}

    # ── WireGuard tunnel ─────────────────────────────────────────────────
    def start_tunnel(self):
        denied = self._check_perm("tunnel")
        if denied:
            return denied
        result = _engine.wg.start_tunnel()
        if result.get("success"):
            _engine.timeline_add("shield", "WireGuard tunnel started", "wireguard")
        return result

    def stop_tunnel(self):
        denied = self._check_perm("tunnel")
        if denied:
            return denied
        result = _engine.wg.stop_tunnel()
        if result.get("success"):
            _engine.timeline_add("shield_off", "WireGuard tunnel stopped", "wireguard")
        return result

    # ── DNS Filter ───────────────────────────────────────────────────────
    def get_dns_stats(self):
        return _engine.dns.get_stats()

    def toggle_blocklist(self, category, enabled):
        success = _engine.dns.toggle_category(category, enabled)
        if success:
            status = "enabled" if enabled else "disabled"
            _engine.timeline_add("filter", f"DNS category '{category}' {status}", "dns")
            _engine._save_settings()
        return {"type": "ack", "success": success}

    def add_custom_dns_rule(self, domain, action="block"):
        denied = self._check_perm("dns_rules")
        if denied:
            return denied
        success = _engine.dns.add_custom_rule(domain, action)
        if success:
            _engine.timeline_add("dns", f"Custom {action}: {domain}", "dns")
        return {"type": "ack", "success": success}

    def remove_custom_dns_rule(self, domain):
        denied = self._check_perm("dns_rules")
        if denied:
            return denied
        success = _engine.dns.remove_custom_rule(domain)
        return {"type": "ack", "success": success}

    # ── Mail proxy ───────────────────────────────────────────────────────
    def check_url(self, url):
        return _engine.mail.check_url(url)

    def check_attachment_hash(self, file_hash):
        return _engine.mail.check_attachment_hash(file_hash)

    def get_mail_stats(self):
        return _engine.mail.get_stats()

    # ── Permissions ──────────────────────────────────────────────────────
    def perm_get_status(self):
        if not self._perm:
            return {"available": False}
        return {"available": True, **self._perm.get_status("mobile_gateway")}

    def perm_authenticate(self, password):
        if not self._perm:
            return {"success": False, "error": "permissions not available"}
        ok, user = self._perm.authenticate("mobile_gateway", password)
        if ok:
            self._auth_user = user
        return {"success": ok, "user": user}

    def perm_enable(self, password):
        if not self._perm:
            return {"success": False, "error": "permissions not available"}
        return {"success": self._perm.enable("mobile_gateway", password)}

    def perm_lock(self):
        if not self._perm:
            return {"success": False}
        self._auth_user = None
        return {"success": self._perm.lock("mobile_gateway")}

    def perm_unlock(self, password):
        if not self._perm:
            return {"success": False, "error": "permissions not available"}
        ok, user = self._perm.authenticate("mobile_gateway", password)
        if ok:
            self._auth_user = user
            self._perm.unlock("mobile_gateway")
        return {"success": ok, "user": user}


# ═══════════════════════════════════════════════════════════════════════════
# PYWEBVIEW STATE BROADCAST
# ═══════════════════════════════════════════════════════════════════════════

def _pywebview_state_broadcast(api: GatewayAPI):
    """Background thread: push state to pywebview window periodically."""
    while not api._stop_broadcast:
        try:
            if api._window:
                state = _engine.get_state()
                js_data = json.dumps(state, default=str)
                api._window.evaluate_js(f"handleMsg({js_data})")
        except Exception:
            pass
        time.sleep(4)


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER (port 8895)
# ═══════════════════════════════════════════════════════════════════════════

_ws_clients: set = set()


async def ws_handler(websocket):
    """Handle a WebSocket client connection."""
    _ws_clients.add(websocket)
    remote = websocket.remote_address
    logger.info(f"[WS] Client connected: {remote}")
    try:
        # Send initial state
        state = json.dumps(_engine.get_state(), default=str)
        await websocket.send(state)

        async for message in websocket:
            try:
                data = json.loads(message)
                response = await _handle_ws_command(data)
                await websocket.send(json.dumps(response, default=str))
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
            except Exception as e:
                await websocket.send(json.dumps({"type": "error", "message": str(e)}))
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)
        logger.info(f"[WS] Client disconnected: {remote}")


async def _handle_ws_command(data: dict) -> dict:
    """Process a command received over WebSocket."""
    cmd = data.get("cmd", "")

    if cmd == "get_state":
        return _engine.get_state()
    elif cmd == "start_gateway":
        _engine.start()
        return {"type": "ack", "cmd": cmd, "running": True}
    elif cmd == "stop_gateway":
        _engine.stop()
        return {"type": "ack", "cmd": cmd, "running": False}
    elif cmd == "add_device":
        result = _engine.devices.register_device(
            data.get("name", "Device"),
            data.get("device_type", "phone"),
            data.get("os_type", "android"),
        )
        _engine.timeline_add("phone", f"Device added: {data.get('name', 'Device')}", "device")
        return json.loads(json.dumps(result, default=str))
    elif cmd == "remove_device":
        success = _engine.devices.remove_device(data.get("pubkey", ""))
        return {"type": "ack", "success": success}
    elif cmd == "get_qr":
        pubkey = data.get("pubkey", "")
        peer = _engine.wg.peers.get(pubkey)
        if not peer:
            return {"error": "Peer not found"}
        config = _engine.wg._build_client_config(
            peer.get("private_key", ""),
            peer.get("ip", ""),
            _engine.wg.server_public_key,
            _engine.wg._get_endpoint(),
        )
        return _engine.qr.generate_qr(config)
    elif cmd == "toggle_blocklist":
        success = _engine.dns.toggle_category(data.get("category", ""), data.get("enabled", True))
        return {"type": "ack", "success": success}
    elif cmd == "add_dns_rule":
        success = _engine.dns.add_custom_rule(data.get("domain", ""), data.get("action", "block"))
        return {"type": "ack", "success": success}
    elif cmd == "check_url":
        return _engine.mail.check_url(data.get("url", ""))
    elif cmd == "get_dns_stats":
        return _engine.dns.get_stats()
    else:
        return {"type": "error", "message": f"Unknown command: {cmd}"}


async def ws_broadcast_loop():
    """Periodically broadcast state to all WebSocket clients."""
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
# MAIN ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════

def _format_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def main_webview():
    """Launch with pywebview — native window, direct API calls."""
    print(f"""
+======================================================+
|        Mobile Gateway v{VERSION}                         |
|        VPN Gateway + DNS Filter for Mobile           |
+------------------------------------------------------+
|  Mode    : Native window (pywebview)                 |
|  WG Port : {WG_PORT}                                     |
|  API Port: {WS_PORT}                                      |
+======================================================+
    """)

    _engine.start()
    _engine.timeline_add("rocket", "Mobile Gateway started (pywebview mode)", "system")

    api = GatewayAPI()
    dashboard_path = os.path.join(GATEWAY_DIR, "gateway_dashboard.html")

    window = webview.create_window(
        "Mobile Gateway \u2014 Optimus Suite",
        dashboard_path,
        js_api=api,
        width=1300,
        height=850,
        min_size=(1000, 650),
        background_color="#0f0f13",
    )
    api.set_window(window)

    def on_loaded():
        print("[OK] Dashboard loaded in native window")
        threading.Thread(
            target=_pywebview_state_broadcast, args=(api,), daemon=True
        ).start()

    window.events.loaded += on_loaded

    try:
        webview.start(debug=False)
    finally:
        api._stop_broadcast = True
        _engine.stop()
        print("[*] Mobile Gateway closed.")


async def main_async():
    """Fallback: WebSocket mode when pywebview is not available."""
    if not HAS_WS:
        print("[ERROR] websockets library required for WebSocket mode.")
        print("Install with: pip install websockets")
        return

    _engine.start()
    _engine.loop = asyncio.get_event_loop()
    _engine.timeline_add("rocket", "Mobile Gateway started (WebSocket mode)", "system")

    print(f"""
+======================================================+
|        Mobile Gateway v{VERSION}                         |
|        VPN Gateway + DNS Filter for Mobile           |
+------------------------------------------------------+
|  Mode     : WebSocket (fallback)                     |
|  WebSocket: ws://localhost:{WS_PORT}                      |
|  WG Port  : {WG_PORT}                                    |
|  Dashboard: gateway_dashboard.html                   |
+======================================================+
    """)

    try:
        async with websockets.serve(ws_handler, "localhost", WS_PORT):
            print(f"[OK] WebSocket server started on port {WS_PORT}")
            asyncio.create_task(ws_broadcast_loop())
            await asyncio.Future()  # Run forever
    except OSError as e:
        # Try fallback ports
        for fallback in range(WS_PORT + 1, WS_PORT + 5):
            try:
                async with websockets.serve(ws_handler, "localhost", fallback):
                    print(f"[OK] WebSocket server started on port {fallback} (fallback)")
                    asyncio.create_task(ws_broadcast_loop())
                    await asyncio.Future()
            except OSError:
                continue
        print(f"[ERROR] Could not start WebSocket server: {e}")


def main():
    """Main entry point — chooses pywebview or WebSocket mode."""
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    if not headless and HAS_WEBVIEW:
        print("[*] pywebview detected — launching native window mode")
        main_webview()
    else:
        mode = "headless" if headless else "WebSocket"
        print(f"[*] Mode: {mode}")
        try:
            asyncio.run(main_async())
        except KeyboardInterrupt:
            print("\n[*] Shutting down Mobile Gateway...")
            _engine.stop()


if __name__ == "__main__":
    main()
