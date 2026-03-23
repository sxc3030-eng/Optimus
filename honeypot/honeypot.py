"""
SentinelOS — HoneyPot Agent v1.0
Deception-based intrusion detection.
Creates fake services and trap files to detect attackers.

Port: 8830
Architecture:
    HoneyPot Agent
        ├── Trap Files — monitored bait files (passwords.txt, etc.)
        ├── Fake Services — fake SSH/HTTP/FTP listeners
        ├── Interaction Logger — logs all attacker activity
        ├── WebSocket Server — serves state to Cortex
        └── Agent Bus integration — publishes honeypot.* events
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
import hashlib
import socket
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
    from toast_notifications import toast_honeypot, toast_event
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False

# Setup
HONEYPOT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(HONEYPOT_DIR)
sys.path.insert(0, BASE_DIR)

VERSION = "1.0.0"
WS_PORT = 8830
IS_WINDOWS = sys.platform == "win32"

LOG_DIR = os.path.join(HONEYPOT_DIR, "logs")
TRAP_DIR = os.path.join(HONEYPOT_DIR, "traps")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(TRAP_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HoneyPot] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "honeypot.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.HoneyPot")

# ═══════════════════════════════════════════════════════════════════════════
# TRAP FILE MANAGER
# ═══════════════════════════════════════════════════════════════════════════

# Bait files that attract attackers
TRAP_FILES = [
    {"name": "passwords.txt", "content": "# Fake credentials - SentinelOS Honeypot\nadmin:P@ssw0rd123\nroot:toor\nuser:password\nbackup:backup2024\n"},
    {"name": "config_backup.sql", "content": "-- SentinelOS Honeypot DB Dump\n-- DO NOT MODIFY\nINSERT INTO users VALUES (1, 'admin', 'hash_placeholder');\n"},
    {"name": "id_rsa_backup.key", "content": "-----BEGIN FAKE RSA PRIVATE KEY-----\nTHIS IS A HONEYPOT TRAP FILE\nAny access to this file is logged and reported.\n-----END FAKE RSA PRIVATE KEY-----\n"},
    {"name": "wallet_seed.txt", "content": "# Crypto Wallet Recovery Seed - HONEYPOT\nabandon ability able about above absent absorb abstract absurd abuse access\n"},
    {"name": ".env.backup", "content": "# Honeypot Environment File\nDB_PASSWORD=SuperSecret123\nAPI_KEY=sk-fake-honeypot-key-sentinel\nAWS_SECRET=AKIAFAKEKEY12345\n"},
]


class TrapFileManager:
    """Creates and monitors bait/trap files."""

    def __init__(self):
        self.traps: dict[str, dict] = {}
        self._create_traps()

    def _create_traps(self):
        """Create trap files and record their hashes."""
        for trap in TRAP_FILES:
            filepath = os.path.join(TRAP_DIR, trap["name"])
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(trap["content"])
                # On Linux, set restrictive permissions so access is more detectable
                if not IS_WINDOWS:
                    try:
                        os.chmod(filepath, 0o644)
                    except OSError:
                        pass
                file_hash = hashlib.sha256(trap["content"].encode()).hexdigest()
                mtime = os.path.getmtime(filepath)
                self.traps[filepath] = {
                    "name": trap["name"],
                    "path": filepath,
                    "hash": file_hash,
                    "original_mtime": mtime,
                    "size": len(trap["content"]),
                    "accessed": False,
                    "modified": False,
                    "access_count": 0,
                    "last_access": 0,
                }
                logger.info(f"[Trap] Created: {trap['name']}")
            except Exception as e:
                logger.error(f"[Trap] Error creating {trap['name']}: {e}")

    def check_traps(self) -> list:
        """Check all trap files for access or modification. Returns list of alerts."""
        alerts = []
        for filepath, info in self.traps.items():
            try:
                if not os.path.exists(filepath):
                    # File was DELETED — definitely suspicious
                    alerts.append({
                        "type": "trap_deleted",
                        "file": info["name"],
                        "path": filepath,
                        "severity": "critical",
                        "ts": time.time(),
                        "message": f"Trap file DELETED: {info['name']}",
                    })
                    info["modified"] = True
                    continue

                # Check modification time
                current_mtime = os.path.getmtime(filepath)
                if current_mtime != info["original_mtime"]:
                    # File was accessed or modified
                    with open(filepath, "r", encoding="utf-8") as f:
                        current_content = f.read()
                    current_hash = hashlib.sha256(current_content.encode()).hexdigest()

                    if current_hash != info["hash"]:
                        # Content was MODIFIED
                        alerts.append({
                            "type": "trap_modified",
                            "file": info["name"],
                            "path": filepath,
                            "severity": "critical",
                            "ts": time.time(),
                            "message": f"Trap file MODIFIED: {info['name']}",
                        })
                        info["modified"] = True
                    else:
                        # Only accessed (mtime changed but content same)
                        alerts.append({
                            "type": "trap_accessed",
                            "file": info["name"],
                            "path": filepath,
                            "severity": "warning",
                            "ts": time.time(),
                            "message": f"Trap file ACCESSED: {info['name']}",
                        })

                    info["accessed"] = True
                    info["access_count"] += 1
                    info["last_access"] = time.time()
                    info["original_mtime"] = current_mtime

            except Exception as e:
                logger.error(f"[Trap] Check error for {filepath}: {e}")

        return alerts

    def get_status(self) -> list:
        """Get status of all trap files."""
        return [
            {
                "name": info["name"],
                "path": info["path"],
                "accessed": info["accessed"],
                "modified": info["modified"],
                "access_count": info["access_count"],
                "last_access": info["last_access"],
            }
            for info in self.traps.values()
        ]


# ═══════════════════════════════════════════════════════════════════════════
# FAKE SERVICE LISTENER
# ═══════════════════════════════════════════════════════════════════════════

class FakeServiceListener:
    """Listens on common ports to detect scanning/intrusion attempts."""

    FAKE_PORTS = [
        {"port": 2222, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9\r\n"},
        {"port": 8888, "service": "HTTP", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n<html><body>It works!</body></html>"},
        {"port": 2121, "service": "FTP", "banner": "220 FTP Server ready.\r\n"},
    ]

    def __init__(self):
        self.connections: list[dict] = []
        self._max_connections = 500
        self._servers: list = []
        self._running = True

    def start(self):
        """Start fake service listeners in background threads."""
        for svc in self.FAKE_PORTS:
            t = threading.Thread(
                target=self._listen,
                args=(svc["port"], svc["service"], svc["banner"]),
                daemon=True,
            )
            t.start()
            self._servers.append(t)

    def _listen(self, port: int, service: str, banner: str):
        """Listen on a port and log connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            logger.info(f"[FakeService] Listening on port {port} ({service})")

            while self._running:
                try:
                    conn, addr = sock.accept()
                    ip, src_port = addr
                    logger.warning(f"[FakeService] Connection on {service}:{port} from {ip}:{src_port}")

                    # Send banner
                    try:
                        conn.send(banner.encode())
                    except Exception:
                        pass

                    # Read whatever they send (limited)
                    try:
                        conn.settimeout(3)
                        data = conn.recv(1024)
                        payload = data.decode("utf-8", errors="replace")[:200]
                    except Exception:
                        payload = ""

                    conn.close()

                    # Log the connection
                    entry = {
                        "ts": time.time(),
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "src_port": src_port,
                        "payload": payload,
                        "severity": "warning",
                    }
                    self.connections.append(entry)
                    if len(self.connections) > self._max_connections:
                        self.connections = self.connections[-self._max_connections:]

                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"[FakeService] Accept error on {port}: {e}")

        except PermissionError:
            logger.warning(f"[FakeService] Permission denied for port {port} ({service}). "
                           f"Run with sudo/root to bind low ports.")
        except OSError as e:
            logger.warning(f"[FakeService] Cannot bind port {port} ({service}): {e}")
        except Exception as e:
            logger.error(f"[FakeService] Error on {port}: {e}")

    def get_recent_connections(self, limit: int = 50) -> list:
        return self.connections[-limit:]

    def get_stats(self) -> dict:
        return {
            "total_connections": len(self.connections),
            "unique_ips": len(set(c["ip"] for c in self.connections)),
            "services": {svc["service"]: svc["port"] for svc in self.FAKE_PORTS},
        }

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════
# HONEYPOT ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class HoneyPotEngine:
    """Main honeypot engine combining traps + fake services."""

    def __init__(self):
        self.traps = TrapFileManager()
        self.services = FakeServiceListener()
        self.alerts: list[dict] = []
        self._max_alerts = 500
        self._running = True
        self.timeline: list[dict] = []
        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

    def start(self):
        """Start all honeypot components."""
        self.services.start()
        # Start monitoring loop
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()
        logger.info("[HoneyPot] Engine started")

    def _monitor_loop(self):
        """Periodically check traps and fake service connections."""
        while self._running:
            # Check trap files
            trap_alerts = self.traps.check_traps()
            for alert in trap_alerts:
                self.alerts.append(alert)
                self.timeline.append({
                    "ts": alert["ts"],
                    "source": "honeypot",
                    "channel": f"honeypot.{alert['type']}",
                    "severity": alert["severity"],
                    "data": {"message": alert["message"], "file": alert.get("file", "")},
                })
                if HAS_TOAST:
                    toast_honeypot("HoneyPot", alert.get("file", ""), alert.get("type", ""), alert.get("message", ""))

            # Check fake service connections
            for conn in self.services.connections:
                if conn.get("_processed"):
                    continue
                conn["_processed"] = True
                self.alerts.append({
                    "type": "service_probe",
                    "ip": conn["ip"],
                    "port": conn["port"],
                    "service": conn["service"],
                    "payload": conn.get("payload", ""),
                    "severity": "warning",
                    "ts": conn["ts"],
                    "message": f"Probe on {conn['service']}:{conn['port']} from {conn['ip']}",
                })
                self.timeline.append({
                    "ts": conn["ts"],
                    "source": "honeypot",
                    "channel": "honeypot.service_probe",
                    "severity": "warning",
                    "data": {"ip": conn["ip"], "service": conn["service"], "port": conn["port"]},
                })
                if HAS_TOAST:
                    toast_event("HoneyPot", f"Probe on {conn['service']}:{conn['port']} from {conn['ip']}")

            # Trim
            if len(self.alerts) > self._max_alerts:
                self.alerts = self.alerts[-self._max_alerts:]
            if len(self.timeline) > 200:
                self.timeline = self.timeline[-200:]

            time.sleep(5)

    def get_state(self) -> dict:
        return {
            "type": "state",
            "version": VERSION,
            "ts": time.time(),
            "traps": self.traps.get_status(),
            "traps_triggered": sum(1 for t in self.traps.traps.values() if t["accessed"]),
            "service_stats": self.services.get_stats(),
            "recent_connections": self.services.get_recent_connections(20),
            "alerts_count": len(self.alerts),
            "recent_alerts": self.alerts[-20:],
            "timeline": self.timeline[-30:],
        }

    def stop(self):
        self._running = False
        self.services.stop()


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER
# ═══════════════════════════════════════════════════════════════════════════

_engine = HoneyPotEngine()
_ws_clients = set()


async def handle_ws(websocket, path=None):
    _ws_clients.add(websocket)
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                cmd = msg.get("cmd", "")
                if cmd == "get_state":
                    await websocket.send(json.dumps(_engine.get_state(), default=str))
                elif cmd == "get_alerts":
                    limit = msg.get("limit", 50)
                    await websocket.send(json.dumps({
                        "type": "alerts",
                        "alerts": _engine.alerts[-limit:],
                    }, default=str))

                # ── Permission commands ─────────────────────────
                elif cmd == "perm_get_status":
                    if _engine._perm:
                        await websocket.send(json.dumps({
                            "type": "perm_status",
                            "permissions": _engine._perm.get_status(),
                        }, default=str))
                    else:
                        await websocket.send(json.dumps({
                            "type": "perm_status",
                            "error": "permissions module not available",
                        }))

                elif cmd == "perm_enable":
                    module = msg.get("module", "")
                    if _engine._perm:
                        result = _engine._perm.enable(module)
                        await websocket.send(json.dumps({
                            "type": "perm_enable",
                            "module": module,
                            "result": result,
                        }, default=str))
                    else:
                        await websocket.send(json.dumps({
                            "type": "perm_enable",
                            "error": "permissions module not available",
                        }))

                elif cmd == "perm_authenticate":
                    user = msg.get("user", "")
                    token = msg.get("token", "")
                    if _engine._perm:
                        ok = _engine._perm.authenticate(user, token)
                        if ok:
                            _engine._auth_user = user
                        await websocket.send(json.dumps({
                            "type": "perm_authenticate",
                            "authenticated": ok,
                            "user": user,
                        }, default=str))
                    else:
                        await websocket.send(json.dumps({
                            "type": "perm_authenticate",
                            "error": "permissions module not available",
                        }))

                elif cmd == "perm_lock":
                    module = msg.get("module", "")
                    if _engine._perm:
                        result = _engine._perm.lock(module)
                        await websocket.send(json.dumps({
                            "type": "perm_lock",
                            "module": module,
                            "result": result,
                        }, default=str))
                    else:
                        await websocket.send(json.dumps({
                            "type": "perm_lock",
                            "error": "permissions module not available",
                        }))

                elif cmd == "perm_unlock":
                    module = msg.get("module", "")
                    if _engine._perm:
                        result = _engine._perm.unlock(module)
                        await websocket.send(json.dumps({
                            "type": "perm_unlock",
                            "module": module,
                            "result": result,
                        }, default=str))
                    else:
                        await websocket.send(json.dumps({
                            "type": "perm_unlock",
                            "error": "permissions module not available",
                        }))
            except json.JSONDecodeError:
                pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        _ws_clients.discard(websocket)


async def broadcast_loop():
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


def main():
    logger.info("=" * 50)
    logger.info(f"  SentinelOS HoneyPot Agent v{VERSION}")
    logger.info(f"  WebSocket port: {WS_PORT}")
    logger.info("=" * 50)

    _engine.start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run():
        server = await websockets.serve(handle_ws, "localhost", WS_PORT)
        logger.info(f"[HoneyPot] WebSocket server on ws://localhost:{WS_PORT}")
        asyncio.create_task(broadcast_loop())
        await asyncio.Future()  # Run forever

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        pass
    finally:
        _engine.stop()
        logger.info("[HoneyPot] Shutdown.")


if __name__ == "__main__":
    main()
