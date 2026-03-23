#!/usr/bin/env python3
"""
SentinelOS — SIEM/SOAR Engine v1.0.0
Security Information and Event Management / Security Orchestration, Automation & Response.
Aggregates events from ALL agents, correlates threats, and automates responses.

Port: 8880
Architecture:
    SIEM/SOAR Engine (port 8880)
        +-- EventCollector     -- connects to all agents via WebSocket, normalizes events
        +-- CorrelationEngine  -- pattern matching, kill chain mapping, IP correlation
        +-- SOARPlaybook       -- automated response playbooks
        +-- LogManager         -- persistent storage, rotation, search, export
        +-- RiskScoreCalculator-- global risk scoring with trend analysis
        +-- SIEMEngine         -- main orchestrator combining all components
        +-- SIEMAPI            -- pywebview js_api for dashboard interaction
        +-- WebSocket server   -- serves state on port 8880

Usage: python siem.py [--headless] [--port 8880]
"""

import os
import sys

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
import time
import asyncio
import logging
import threading
import collections
import hashlib
import gzip
import shutil
import csv
import io
from datetime import datetime
from pathlib import Path
from collections import deque, defaultdict
from typing import Optional

# ── Optional dependencies ─────────────────────────────────────────────────

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

# ── Shared modules ──────────────────────────────────────────

SIEM_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SIEM_DIR)
sys.path.insert(0, BASE_DIR)

try:
    from permissions import PermissionManager
    HAS_PERMISSIONS = True
except ImportError:
    HAS_PERMISSIONS = False

try:
    from toast_notifications import toast_threat, toast_event, toast_block
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
WS_PORT = 8880
IS_WINDOWS = sys.platform == "win32"
HEADLESS = "--headless" in sys.argv

LOG_DIR = os.path.join(SIEM_DIR, "logs")
PLAYBOOK_DIR = os.path.join(SIEM_DIR, "playbooks")
RULES_FILE = os.path.join(SIEM_DIR, "correlation_rules.json")
PLAYBOOKS_FILE = os.path.join(SIEM_DIR, "playbooks.json")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PLAYBOOK_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIEM] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "siem.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.SIEM")

MAX_EVENTS = 10000
MAX_TIMELINE = 200
MAX_LOG_SIZE_MB = 10
LOG_ROTATION_CHECK_INTERVAL = 60

# Agent WebSocket endpoints
AGENT_ENDPOINTS = {
    "netguard":   {"host": "localhost", "port": 8765, "label": "NetGuard Pro"},
    "honeypot":   {"host": "localhost", "port": 8830, "label": "HoneyPot Agent"},
    "strikeback": {"host": "localhost", "port": 8850, "label": "StrikeBack Agent"},
    "fim":        {"host": "localhost", "port": 8840, "label": "FIM Agent"},
    "recorder":   {"host": "localhost", "port": 8860, "label": "Forensic Recorder"},
    "redteam":    {"host": "localhost", "port": 8870, "label": "RedTeam Agent"},
}

# Kill Chain stages
KILL_CHAIN_STAGES = [
    {"id": "recon",      "label": "Reconnaissance", "order": 1},
    {"id": "weaponize",  "label": "Weaponization",  "order": 2},
    {"id": "deliver",    "label": "Delivery",        "order": 3},
    {"id": "exploit",    "label": "Exploitation",    "order": 4},
    {"id": "c2",         "label": "Command & Control","order": 5},
    {"id": "exfil",      "label": "Exfiltration",    "order": 6},
]

# Event-to-kill-chain mapping
EVENT_KILL_CHAIN_MAP = {
    "port_scan":       "recon",
    "network_scan":    "recon",
    "dns_query":       "recon",
    "service_enum":    "recon",
    "brute_force":     "exploit",
    "exploit_attempt": "exploit",
    "honeypot_probe":  "deliver",
    "trap_access":     "deliver",
    "malware_drop":    "weaponize",
    "payload_exec":    "weaponize",
    "c2_beacon":       "c2",
    "dns_tunnel":      "c2",
    "reverse_shell":   "c2",
    "data_exfil":      "exfil",
    "entropy_alert":   "exfil",
    "fim_change":      "exploit",
    "lateral_move":    "exploit",
}

# Default correlation rules
DEFAULT_CORRELATION_RULES = [
    {
        "name": "APT Detected",
        "severity": "critical",
        "conditions": ["port_scan", "brute_force", "honeypot_probe"],
        "window": 300,
        "min_matches": 3,
        "action": "auto_block_and_alert",
        "description": "Advanced Persistent Threat: multi-stage attack from same IP within 5 minutes",
    },
    {
        "name": "Data Exfiltration",
        "severity": "critical",
        "conditions": ["dns_tunnel", "entropy_alert"],
        "window": 120,
        "min_matches": 2,
        "action": "isolate_and_record",
        "description": "Suspected data exfiltration via DNS tunneling with high entropy traffic",
    },
    {
        "name": "Lateral Movement",
        "severity": "high",
        "conditions": ["port_scan", "fim_change", "trap_access"],
        "window": 120,
        "min_matches": 2,
        "action": "alert_and_record",
        "description": "Attacker moving laterally across network segments",
    },
    {
        "name": "Brute Force Campaign",
        "severity": "high",
        "conditions": ["brute_force"],
        "window": 60,
        "min_matches": 3,
        "action": "auto_block",
        "description": "Multiple brute force attempts from same IP within 1 minute",
    },
    {
        "name": "Reconnaissance Activity",
        "severity": "medium",
        "conditions": ["port_scan", "network_scan"],
        "window": 60,
        "min_matches": 2,
        "action": "alert",
        "description": "Active network reconnaissance detected",
    },
    {
        "name": "Kill Chain Progression",
        "severity": "critical",
        "conditions": ["port_scan", "exploit_attempt", "c2_beacon"],
        "window": 600,
        "min_matches": 3,
        "action": "auto_block_and_alert",
        "description": "Full kill chain progression: Recon to C2 within 10 minutes",
    },
    {
        "name": "Honeypot Interaction",
        "severity": "medium",
        "conditions": ["honeypot_probe", "trap_access"],
        "window": 60,
        "min_matches": 1,
        "action": "alert_and_record",
        "description": "Attacker interacting with honeypot services or trap files",
    },
    {
        "name": "Multi-Agent Alert",
        "severity": "high",
        "conditions": ["port_scan", "brute_force", "fim_change"],
        "window": 180,
        "min_matches": 2,
        "action": "alert_and_record",
        "description": "Same IP triggering alerts across 3+ different agents",
    },
]

# Default playbooks
DEFAULT_PLAYBOOKS = [
    {
        "name": "auto_block_and_alert",
        "label": "Auto-Block + Alert",
        "description": "Block threatening IP and escalate alert",
        "actions": [
            {"type": "auto_block", "target": "sentinel_mapper"},
            {"type": "alert_escalation", "level": "critical"},
            {"type": "start_recording", "target": "recorder"},
        ],
        "enabled": True,
    },
    {
        "name": "isolate_and_record",
        "label": "Isolate + Record",
        "description": "Isolate compromised host and start forensic recording",
        "actions": [
            {"type": "auto_isolate", "target": "strikeback"},
            {"type": "start_recording", "target": "recorder"},
            {"type": "alert_escalation", "level": "critical"},
        ],
        "enabled": True,
    },
    {
        "name": "alert_and_record",
        "label": "Alert + Record",
        "description": "Send alert and begin incident recording",
        "actions": [
            {"type": "alert_escalation", "level": "high"},
            {"type": "start_recording", "target": "recorder"},
        ],
        "enabled": True,
    },
    {
        "name": "auto_block",
        "label": "Auto-Block",
        "description": "Automatically block offending IP",
        "actions": [
            {"type": "auto_block", "target": "sentinel_mapper"},
            {"type": "alert_escalation", "level": "high"},
        ],
        "enabled": True,
    },
    {
        "name": "alert",
        "label": "Alert Only",
        "description": "Send notification alert without automated response",
        "actions": [
            {"type": "alert_escalation", "level": "medium"},
        ],
        "enabled": True,
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# EVENT COLLECTOR — connects to all agents via WebSocket
# ═══════════════════════════════════════════════════════════════════════════

class EventCollector:
    """Connects to all agent WebSocket endpoints, fetches state, and normalizes events."""

    def __init__(self):
        self.events = deque(maxlen=MAX_EVENTS)
        self.agent_states = {}
        self.agent_health = {}
        self._running = False
        self._lock = threading.Lock()
        self._connections = {}
        self._last_event_counts = defaultdict(int)
        self.total_collected = 0

    def start(self):
        self._running = True
        for agent_key in AGENT_ENDPOINTS:
            self.agent_health[agent_key] = {
                "status": "unknown",
                "last_seen": 0,
                "events_count": 0,
                "errors": 0,
                "label": AGENT_ENDPOINTS[agent_key]["label"],
            }
        t = threading.Thread(target=self._collector_loop, daemon=True)
        t.start()
        logger.info("[EventCollector] Started — monitoring %d agents", len(AGENT_ENDPOINTS))

    def stop(self):
        self._running = False

    def _collector_loop(self):
        """Main loop: poll each agent periodically."""
        while self._running:
            for agent_key, endpoint in AGENT_ENDPOINTS.items():
                try:
                    self._poll_agent(agent_key, endpoint)
                except Exception as e:
                    with self._lock:
                        self.agent_health[agent_key]["status"] = "error"
                        self.agent_health[agent_key]["errors"] += 1
                    logger.debug("[EventCollector] Error polling %s: %s", agent_key, e)
            time.sleep(5)

    def _poll_agent(self, agent_key: str, endpoint: dict):
        """Poll a single agent for its state via synchronous WebSocket."""
        if not HAS_WS:
            return

        uri = f"ws://{endpoint['host']}:{endpoint['port']}"
        try:
            # Use a short-lived synchronous connection
            import asyncio as _aio
            loop = _aio.new_event_loop()
            state = loop.run_until_complete(self._async_poll(uri, agent_key))
            loop.close()

            if state:
                with self._lock:
                    self.agent_states[agent_key] = state
                    self.agent_health[agent_key]["status"] = "online"
                    self.agent_health[agent_key]["last_seen"] = time.time()

                # Extract and normalize events from the state
                self._extract_events(agent_key, state)

        except Exception:
            with self._lock:
                self.agent_health[agent_key]["status"] = "offline"

    async def _async_poll(self, uri: str, agent_key: str) -> Optional[dict]:
        """Async WebSocket poll with timeout."""
        try:
            async with websockets.connect(uri, open_timeout=3, close_timeout=2) as ws:
                await ws.send(json.dumps({"cmd": "get_state"}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                return json.loads(response)
        except Exception:
            return None

    def _extract_events(self, agent_key: str, state: dict):
        """Extract events from agent state and normalize into unified format."""
        new_events = []

        # Extract from timeline / recent_events depending on agent format
        raw_events = []
        if "timeline" in state and isinstance(state["timeline"], list):
            raw_events.extend(state["timeline"])
        if "recent_events" in state and isinstance(state["recent_events"], list):
            raw_events.extend(state["recent_events"])
        if "alerts" in state and isinstance(state["alerts"], list):
            raw_events.extend(state["alerts"])
        if "interactions" in state and isinstance(state["interactions"], list):
            raw_events.extend(state["interactions"])
        if "detections" in state and isinstance(state["detections"], list):
            raw_events.extend(state["detections"])

        # Deduplicate by creating a hash of each event
        seen_hashes = set()
        with self._lock:
            for ev in self.events:
                seen_hashes.add(ev.get("_hash", ""))

        for raw in raw_events:
            normalized = self._normalize_event(agent_key, raw)
            if normalized and normalized["_hash"] not in seen_hashes:
                new_events.append(normalized)
                seen_hashes.add(normalized["_hash"])

        if new_events:
            with self._lock:
                for ev in new_events:
                    self.events.append(ev)
                    self.total_collected += 1
                self.agent_health[agent_key]["events_count"] += len(new_events)

    def _normalize_event(self, agent_key: str, raw: dict) -> Optional[dict]:
        """Normalize a raw agent event into the unified SIEM format."""
        if not isinstance(raw, dict):
            return None

        ts = raw.get("ts") or raw.get("timestamp") or raw.get("time") or time.time()
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts).timestamp()
            except Exception:
                ts = time.time()

        event_type = (
            raw.get("event_type") or raw.get("type") or
            raw.get("category") or raw.get("action") or "unknown"
        )

        severity = raw.get("severity") or raw.get("level") or "info"
        ip = raw.get("ip") or raw.get("src_ip") or raw.get("source_ip") or raw.get("attacker_ip") or ""

        details = {}
        for key in ("message", "description", "details", "path", "port", "protocol",
                     "service", "pid", "name", "cmdline", "dst_ip", "dst_port",
                     "src_port", "process_name", "file_path", "trap_name"):
            if key in raw:
                details[key] = raw[key]

        # Build hash for deduplication
        hash_input = f"{agent_key}:{ts}:{event_type}:{ip}:{json.dumps(details, sort_keys=True, default=str)}"
        event_hash = hashlib.md5(hash_input.encode()).hexdigest()[:16]

        return {
            "ts": ts,
            "ts_iso": datetime.fromtimestamp(ts).isoformat() if isinstance(ts, (int, float)) else str(ts),
            "source_agent": agent_key,
            "event_type": event_type,
            "severity": severity,
            "ip": ip,
            "details": details,
            "_hash": event_hash,
            "kill_chain": EVENT_KILL_CHAIN_MAP.get(event_type, ""),
        }

    def get_events(self, limit: int = 100, agent: str = None,
                   severity: str = None, since: float = None) -> list:
        """Return filtered events."""
        with self._lock:
            events = list(self.events)

        if agent:
            events = [e for e in events if e["source_agent"] == agent]
        if severity:
            events = [e for e in events if e["severity"] == severity]
        if since:
            events = [e for e in events if e["ts"] >= since]

        events.sort(key=lambda e: e["ts"], reverse=True)
        return events[:limit]

    def get_agent_health(self) -> dict:
        with self._lock:
            return dict(self.agent_health)

    def get_agent_states(self) -> dict:
        with self._lock:
            return dict(self.agent_states)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_events": self.total_collected,
                "buffer_size": len(self.events),
                "agents_online": sum(1 for h in self.agent_health.values() if h["status"] == "online"),
                "agents_total": len(AGENT_ENDPOINTS),
            }


# ═══════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE — pattern matching and kill chain mapping
# ═══════════════════════════════════════════════════════════════════════════

class CorrelationEngine:
    """Loads correlation rules and detects multi-event threat patterns."""

    def __init__(self):
        self.rules = list(DEFAULT_CORRELATION_RULES)
        self.correlations = deque(maxlen=500)
        self.ip_activity = defaultdict(list)  # ip -> list of (ts, event_type, agent)
        self.kill_chain_active = defaultdict(set)  # ip -> set of active stages
        self._lock = threading.Lock()
        self.total_correlations = 0
        self._load_rules()

    def _load_rules(self):
        """Load custom rules from correlation_rules.json if present."""
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    custom_rules = json.load(f)
                if isinstance(custom_rules, list):
                    self.rules.extend(custom_rules)
                    logger.info("[CorrelationEngine] Loaded %d custom rules from %s",
                                len(custom_rules), RULES_FILE)
            except Exception as e:
                logger.error("[CorrelationEngine] Failed to load rules: %s", e)

    def _save_rules(self):
        """Save custom rules to disk."""
        custom = [r for r in self.rules if r not in DEFAULT_CORRELATION_RULES]
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(custom, f, indent=2, default=str)
        except Exception as e:
            logger.error("[CorrelationEngine] Failed to save rules: %s", e)

    def add_rule(self, rule: dict) -> dict:
        """Add a new correlation rule."""
        required_fields = ["name", "severity", "conditions", "window"]
        for field in required_fields:
            if field not in rule:
                return {"error": f"Missing required field: {field}"}

        rule.setdefault("min_matches", len(rule["conditions"]))
        rule.setdefault("action", "alert")
        rule.setdefault("description", "")

        with self._lock:
            self.rules.append(rule)
        self._save_rules()
        logger.info("[CorrelationEngine] Added rule: %s", rule["name"])
        return {"success": True, "rule": rule}

    def process_event(self, event: dict) -> list:
        """Process a new event and check for correlation matches."""
        ip = event.get("ip", "")
        event_type = event.get("event_type", "")
        ts = event.get("ts", time.time())
        agent = event.get("source_agent", "")

        triggered = []

        if ip:
            with self._lock:
                self.ip_activity[ip].append({
                    "ts": ts,
                    "event_type": event_type,
                    "agent": agent,
                    "severity": event.get("severity", "info"),
                })

                # Prune old entries (keep last 10 minutes)
                cutoff = time.time() - 600
                self.ip_activity[ip] = [
                    a for a in self.ip_activity[ip] if a["ts"] > cutoff
                ]

                # Update kill chain stages
                kc_stage = EVENT_KILL_CHAIN_MAP.get(event_type, "")
                if kc_stage:
                    self.kill_chain_active[ip].add(kc_stage)

                # Check each rule against this IP's activity
                for rule in self.rules:
                    if self._check_rule(ip, rule, ts):
                        correlation = self._create_correlation(ip, rule, ts)
                        self.correlations.append(correlation)
                        self.total_correlations += 1
                        triggered.append(correlation)
                        logger.warning("[Correlation] TRIGGERED: %s — IP=%s",
                                       rule["name"], ip)

                # Check multi-agent correlation (same IP on 3+ agents)
                agents_seen = set(a["agent"] for a in self.ip_activity[ip])
                if len(agents_seen) >= 3:
                    multi_agent_key = f"multi_agent_{ip}"
                    already_triggered = any(
                        c["rule_name"] == "Multi-Agent Correlation" and c["ip"] == ip
                        and time.time() - c["ts"] < 300
                        for c in self.correlations
                    )
                    if not already_triggered:
                        correlation = {
                            "id": hashlib.md5(f"{multi_agent_key}:{ts}".encode()).hexdigest()[:12],
                            "ts": ts,
                            "ts_iso": datetime.fromtimestamp(ts).isoformat(),
                            "rule_name": "Multi-Agent Correlation",
                            "severity": "high",
                            "ip": ip,
                            "agents": list(agents_seen),
                            "action": "alert_and_record",
                            "description": f"IP {ip} seen on {len(agents_seen)} agents: {', '.join(agents_seen)}",
                            "kill_chain": list(self.kill_chain_active.get(ip, set())),
                        }
                        self.correlations.append(correlation)
                        self.total_correlations += 1
                        triggered.append(correlation)

        return triggered

    def _check_rule(self, ip: str, rule: dict, current_ts: float) -> bool:
        """Check if a correlation rule is triggered for a given IP."""
        window = rule.get("window", 300)
        conditions = rule.get("conditions", [])
        min_matches = rule.get("min_matches", len(conditions))

        cutoff = current_ts - window
        recent = [a for a in self.ip_activity.get(ip, []) if a["ts"] > cutoff]

        if not recent:
            return False

        # Count how many distinct conditions are matched
        matched_conditions = set()
        for activity in recent:
            for cond in conditions:
                if activity["event_type"] == cond:
                    matched_conditions.add(cond)

        # For brute_force with min_matches > 1, also check count
        if len(conditions) == 1 and min_matches > 1:
            count = sum(1 for a in recent if a["event_type"] == conditions[0])
            if count >= min_matches:
                # Prevent re-triggering within the same window
                already_triggered = any(
                    c["rule_name"] == rule["name"] and c["ip"] == ip
                    and current_ts - c["ts"] < window
                    for c in self.correlations
                )
                return not already_triggered
            return False

        if len(matched_conditions) >= min_matches:
            # Prevent duplicate triggers within the same window
            already_triggered = any(
                c["rule_name"] == rule["name"] and c["ip"] == ip
                and current_ts - c["ts"] < window
                for c in self.correlations
            )
            return not already_triggered

        return False

    def _create_correlation(self, ip: str, rule: dict, ts: float) -> dict:
        """Create a correlation alert record."""
        return {
            "id": hashlib.md5(f"{rule['name']}:{ip}:{ts}".encode()).hexdigest()[:12],
            "ts": ts,
            "ts_iso": datetime.fromtimestamp(ts).isoformat(),
            "rule_name": rule["name"],
            "severity": rule.get("severity", "medium"),
            "ip": ip,
            "action": rule.get("action", "alert"),
            "description": rule.get("description", ""),
            "conditions_matched": rule.get("conditions", []),
            "kill_chain": list(self.kill_chain_active.get(ip, set())),
        }

    def get_correlations(self, limit: int = 50) -> list:
        with self._lock:
            corrs = list(self.correlations)
        corrs.sort(key=lambda c: c["ts"], reverse=True)
        return corrs[:limit]

    def get_kill_chain_status(self) -> dict:
        """Get all active kill chain stages across all IPs."""
        with self._lock:
            active_stages = set()
            per_ip = {}
            for ip, stages in self.kill_chain_active.items():
                if stages:
                    active_stages.update(stages)
                    per_ip[ip] = list(stages)

        return {
            "stages": [
                {**stage, "active": stage["id"] in active_stages}
                for stage in KILL_CHAIN_STAGES
            ],
            "per_ip": per_ip,
            "active_count": len(active_stages),
        }

    def get_top_threat_ips(self, limit: int = 10) -> list:
        """Get IPs with the most activity."""
        with self._lock:
            ip_scores = []
            for ip, activities in self.ip_activity.items():
                if not activities:
                    continue
                severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
                score = sum(severity_weights.get(a["severity"], 0) for a in activities)
                agents = set(a["agent"] for a in activities)
                stages = self.kill_chain_active.get(ip, set())
                ip_scores.append({
                    "ip": ip,
                    "score": score,
                    "event_count": len(activities),
                    "agents": list(agents),
                    "kill_chain_stages": list(stages),
                    "last_seen": max(a["ts"] for a in activities),
                })

        ip_scores.sort(key=lambda x: x["score"], reverse=True)
        return ip_scores[:limit]

    def get_rules(self) -> list:
        with self._lock:
            return list(self.rules)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_correlations": self.total_correlations,
                "active_rules": len(self.rules),
                "tracked_ips": len(self.ip_activity),
                "active_kill_chain_ips": sum(1 for s in self.kill_chain_active.values() if s),
            }


# ═══════════════════════════════════════════════════════════════════════════
# SOAR PLAYBOOK — automated response engine
# ═══════════════════════════════════════════════════════════════════════════

class SOARPlaybook:
    """Automated incident response playbooks. Loads from playbooks.json and executes actions."""

    def __init__(self):
        self.playbooks = list(DEFAULT_PLAYBOOKS)
        self.execution_log = deque(maxlen=500)
        self._lock = threading.Lock()
        self.total_executions = 0
        self.active_playbooks = {}  # name -> status
        self._load_playbooks()

    def _load_playbooks(self):
        """Load custom playbooks from playbooks.json if present."""
        if os.path.exists(PLAYBOOKS_FILE):
            try:
                with open(PLAYBOOKS_FILE, "r", encoding="utf-8") as f:
                    custom = json.load(f)
                if isinstance(custom, list):
                    # Merge: update existing or add new
                    existing_names = {p["name"] for p in self.playbooks}
                    for pb in custom:
                        if pb.get("name") in existing_names:
                            for i, existing in enumerate(self.playbooks):
                                if existing["name"] == pb["name"]:
                                    self.playbooks[i] = pb
                                    break
                        else:
                            self.playbooks.append(pb)
                    logger.info("[SOARPlaybook] Loaded playbooks from %s", PLAYBOOKS_FILE)
            except Exception as e:
                logger.error("[SOARPlaybook] Failed to load playbooks: %s", e)

    def execute(self, playbook_name: str, context: dict) -> dict:
        """Execute a playbook with given context (ip, correlation, etc.)."""
        playbook = None
        for pb in self.playbooks:
            if pb["name"] == playbook_name:
                playbook = pb
                break

        if not playbook:
            return {"error": f"Playbook not found: {playbook_name}"}

        if not playbook.get("enabled", True):
            return {"error": f"Playbook disabled: {playbook_name}"}

        execution = {
            "id": hashlib.md5(f"{playbook_name}:{time.time()}".encode()).hexdigest()[:10],
            "playbook": playbook_name,
            "started": time.time(),
            "started_iso": datetime.now().isoformat(),
            "context": context,
            "actions": [],
            "status": "running",
        }

        with self._lock:
            self.active_playbooks[playbook_name] = "running"

        ip = context.get("ip", "")
        correlation_id = context.get("correlation_id", "")

        for action_def in playbook.get("actions", []):
            action_result = self._execute_action(action_def, ip, context)
            execution["actions"].append(action_result)

        execution["completed"] = time.time()
        execution["completed_iso"] = datetime.now().isoformat()
        execution["duration"] = round(execution["completed"] - execution["started"], 3)
        execution["status"] = "completed"

        with self._lock:
            self.execution_log.append(execution)
            self.total_executions += 1
            self.active_playbooks[playbook_name] = "idle"

        logger.info("[SOARPlaybook] Executed: %s — %d actions, %.3fs",
                     playbook_name, len(execution["actions"]), execution["duration"])
        return execution

    def _execute_action(self, action_def: dict, ip: str, context: dict) -> dict:
        """Execute a single playbook action."""
        action_type = action_def.get("type", "unknown")
        target = action_def.get("target", "")
        result = {
            "type": action_type,
            "target": target,
            "ts": time.time(),
            "ts_iso": datetime.now().isoformat(),
            "status": "pending",
            "message": "",
        }

        try:
            if action_type == "auto_block":
                result["message"] = f"Block command sent for IP {ip} to {target}"
                result["status"] = "sent"
                self._send_agent_command(target, {"cmd": "block_ip", "ip": ip})
                logger.info("[SOAR] auto_block: IP=%s target=%s", ip, target)

            elif action_type == "auto_isolate":
                result["message"] = f"Isolate command sent for IP {ip} to {target}"
                result["status"] = "sent"
                self._send_agent_command(target, {"cmd": "isolate", "ip": ip})
                logger.info("[SOAR] auto_isolate: IP=%s target=%s", ip, target)

            elif action_type == "start_recording":
                result["message"] = "Start recording command sent to Recorder"
                result["status"] = "sent"
                self._send_agent_command("recorder", {"cmd": "start_incident"})
                logger.info("[SOAR] start_recording: triggered on recorder")

            elif action_type == "alert_escalation":
                level = action_def.get("level", "high")
                result["message"] = f"Alert escalated at level: {level}"
                result["status"] = "completed"
                if HAS_TOAST:
                    rule_name = context.get("rule_name", "SIEM Alert")
                    toast_threat("SIEM/SOAR", rule_name, level, f"IP: {ip}")
                logger.warning("[SOAR] ALERT ESCALATION: level=%s, ip=%s, rule=%s",
                               level, ip, context.get("rule_name", ""))

            else:
                result["message"] = f"Unknown action type: {action_type}"
                result["status"] = "skipped"

        except Exception as e:
            result["status"] = "error"
            result["message"] = f"Action failed: {e}"
            logger.error("[SOAR] Action error: %s — %s", action_type, e)

        return result

    def _send_agent_command(self, agent_key: str, command: dict):
        """Send a command to an agent via WebSocket (fire-and-forget)."""
        if not HAS_WS:
            return

        # Map target names to endpoint keys
        endpoint_map = {
            "sentinel_mapper": ("localhost", 8800),
            "strikeback": ("localhost", 8850),
            "recorder": ("localhost", 8860),
            "netguard": ("localhost", 8765),
            "honeypot": ("localhost", 8830),
        }
        target = endpoint_map.get(agent_key)
        if not target:
            return

        def _send():
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._async_send(target, command))
                loop.close()
            except Exception as e:
                logger.debug("[SOAR] Failed to send command to %s: %s", agent_key, e)

        t = threading.Thread(target=_send, daemon=True)
        t.start()

    async def _async_send(self, target: tuple, command: dict):
        """Async send command to agent."""
        uri = f"ws://{target[0]}:{target[1]}"
        async with websockets.connect(uri, open_timeout=3, close_timeout=2) as ws:
            await ws.send(json.dumps(command))
            # Wait briefly for ack
            try:
                await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                pass

    def get_playbooks(self) -> list:
        with self._lock:
            return [
                {
                    "name": pb["name"],
                    "label": pb.get("label", pb["name"]),
                    "description": pb.get("description", ""),
                    "enabled": pb.get("enabled", True),
                    "actions_count": len(pb.get("actions", [])),
                    "status": self.active_playbooks.get(pb["name"], "idle"),
                }
                for pb in self.playbooks
            ]

    def get_execution_log(self, limit: int = 50) -> list:
        with self._lock:
            log = list(self.execution_log)
        log.sort(key=lambda e: e["started"], reverse=True)
        return log[:limit]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_playbooks": len(self.playbooks),
                "enabled_playbooks": sum(1 for pb in self.playbooks if pb.get("enabled", True)),
                "total_executions": self.total_executions,
                "active": sum(1 for s in self.active_playbooks.values() if s == "running"),
            }


# ═══════════════════════════════════════════════════════════════════════════
# LOG MANAGER — persistent storage, rotation, search, export
# ═══════════════════════════════════════════════════════════════════════════

class LogManager:
    """Stores all events in JSON files with rotation, search, and export."""

    def __init__(self):
        self._lock = threading.Lock()
        self._current_log_file = None
        self._running = False
        self._buffer = []
        self.total_stored = 0
        self._init_log_file()

    def _init_log_file(self):
        """Create or find the current log file."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        self._current_log_file = os.path.join(LOG_DIR, f"siem_events_{date_str}.json")
        if not os.path.exists(self._current_log_file):
            with open(self._current_log_file, "w", encoding="utf-8") as f:
                json.dump([], f)

    def start(self):
        self._running = True
        t = threading.Thread(target=self._flush_loop, daemon=True)
        t.start()
        t2 = threading.Thread(target=self._rotation_loop, daemon=True)
        t2.start()
        logger.info("[LogManager] Started — log dir: %s", LOG_DIR)

    def stop(self):
        self._running = False
        self._flush()

    def store(self, event: dict):
        """Buffer an event for writing."""
        with self._lock:
            clean = {k: v for k, v in event.items() if k != "_hash"}
            self._buffer.append(clean)

    def _flush_loop(self):
        """Periodically flush buffered events to disk."""
        while self._running:
            self._flush()
            time.sleep(5)

    def _flush(self):
        """Write buffered events to the current log file."""
        with self._lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()

        # Check if date rolled over
        date_str = datetime.now().strftime("%Y-%m-%d")
        expected = os.path.join(LOG_DIR, f"siem_events_{date_str}.json")
        if expected != self._current_log_file:
            self._current_log_file = expected
            if not os.path.exists(self._current_log_file):
                with open(self._current_log_file, "w", encoding="utf-8") as f:
                    json.dump([], f)

        try:
            # Read existing
            existing = []
            if os.path.exists(self._current_log_file):
                try:
                    with open(self._current_log_file, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, IOError):
                    existing = []

            existing.extend(batch)
            with open(self._current_log_file, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=1, default=str)

            self.total_stored += len(batch)

        except Exception as e:
            logger.error("[LogManager] Flush error: %s", e)

    def _rotation_loop(self):
        """Periodically check log files and compress large ones."""
        while self._running:
            try:
                self._rotate_logs()
            except Exception as e:
                logger.error("[LogManager] Rotation error: %s", e)
            time.sleep(LOG_ROTATION_CHECK_INTERVAL)

    def _rotate_logs(self):
        """Compress log files larger than MAX_LOG_SIZE_MB."""
        for filename in os.listdir(LOG_DIR):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(LOG_DIR, filename)
            if filepath == self._current_log_file:
                continue  # Don't rotate the active file
            try:
                size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if size_mb > MAX_LOG_SIZE_MB:
                    gz_path = filepath + ".gz"
                    with open(filepath, "rb") as f_in:
                        with gzip.open(gz_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(filepath)
                    logger.info("[LogManager] Rotated: %s -> %s (%.1f MB)",
                                filename, filename + ".gz", size_mb)
            except Exception as e:
                logger.error("[LogManager] Rotation failed for %s: %s", filename, e)

    def search(self, query: str, limit: int = 100) -> list:
        """Full-text search across all log files."""
        results = []
        query_lower = query.lower()

        for filename in sorted(os.listdir(LOG_DIR), reverse=True):
            if len(results) >= limit:
                break

            filepath = os.path.join(LOG_DIR, filename)

            if filename.endswith(".json"):
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        events = json.load(f)
                    for ev in events:
                        if query_lower in json.dumps(ev, default=str).lower():
                            results.append(ev)
                            if len(results) >= limit:
                                break
                except Exception:
                    pass

            elif filename.endswith(".json.gz"):
                try:
                    with gzip.open(filepath, "rt", encoding="utf-8") as f:
                        events = json.load(f)
                    for ev in events:
                        if query_lower in json.dumps(ev, default=str).lower():
                            results.append(ev)
                            if len(results) >= limit:
                                break
                except Exception:
                    pass

        return results

    def export_csv(self, events: list) -> str:
        """Export events as CSV string."""
        if not events:
            return ""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "ts_iso", "source_agent", "event_type", "severity", "ip", "details"
        ])
        writer.writeheader()
        for ev in events:
            row = {
                "ts_iso": ev.get("ts_iso", ""),
                "source_agent": ev.get("source_agent", ""),
                "event_type": ev.get("event_type", ""),
                "severity": ev.get("severity", ""),
                "ip": ev.get("ip", ""),
                "details": json.dumps(ev.get("details", {}), default=str),
            }
            writer.writerow(row)
        return output.getvalue()

    def export_json(self, events: list) -> str:
        """Export events as JSON string."""
        clean = [{k: v for k, v in ev.items() if k != "_hash"} for ev in events]
        return json.dumps(clean, indent=2, default=str)

    def export_syslog(self, events: list) -> str:
        """Export events in syslog format."""
        lines = []
        severity_map = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
        for ev in events:
            pri = severity_map.get(ev.get("severity", "info"), 6)
            ts_str = ev.get("ts_iso", datetime.now().isoformat())
            agent = ev.get("source_agent", "siem")
            etype = ev.get("event_type", "unknown")
            ip = ev.get("ip", "-")
            msg = json.dumps(ev.get("details", {}), default=str)
            lines.append(f"<{pri}>{ts_str} {agent} SIEM[{etype}]: ip={ip} {msg}")
        return "\n".join(lines)

    def get_stats(self) -> dict:
        log_files = [f for f in os.listdir(LOG_DIR) if f.startswith("siem_events")]
        total_size = 0
        for f in log_files:
            try:
                total_size += os.path.getsize(os.path.join(LOG_DIR, f))
            except OSError:
                pass
        return {
            "total_stored": self.total_stored,
            "log_files": len(log_files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "current_file": os.path.basename(self._current_log_file),
        }


# ═══════════════════════════════════════════════════════════════════════════
# RISK SCORE CALCULATOR — global risk scoring with trend analysis
# ═══════════════════════════════════════════════════════════════════════════

class RiskScoreCalculator:
    """Calculates a global risk score (0-100) with trend analysis."""

    def __init__(self):
        self.current_score = 0
        self.history = deque(maxlen=120)  # Last 120 samples (~10 min at 5s interval)
        self._lock = threading.Lock()

    def calculate(self, collector: EventCollector, correlator: CorrelationEngine) -> dict:
        """Calculate global risk score based on multiple factors."""
        now = time.time()
        score = 0

        # Factor 1: Active threats (correlations in last 10 min) — max 35 pts
        recent_corrs = [c for c in correlator.get_correlations(100) if now - c["ts"] < 600]
        severity_weights = {"critical": 15, "high": 8, "medium": 4, "low": 1}
        corr_score = sum(severity_weights.get(c.get("severity", "medium"), 2) for c in recent_corrs)
        score += min(35, corr_score)

        # Factor 2: Alert frequency (events per minute) — max 25 pts
        recent_events = collector.get_events(limit=500, since=now - 300)
        high_sev_events = [e for e in recent_events if e.get("severity") in ("critical", "high")]
        freq_score = min(25, len(high_sev_events) * 2)
        score += freq_score

        # Factor 3: Agent health — max 20 pts
        health = collector.get_agent_health()
        total_agents = len(health)
        offline_agents = sum(1 for h in health.values() if h["status"] != "online")
        error_agents = sum(1 for h in health.values() if h["status"] == "error")
        if total_agents > 0:
            health_penalty = (offline_agents * 5) + (error_agents * 10)
            score += min(20, health_penalty)

        # Factor 4: Kill chain progression — max 20 pts
        kc = correlator.get_kill_chain_status()
        active_stages = kc.get("active_count", 0)
        score += min(20, active_stages * 4)

        score = min(100, max(0, score))

        with self._lock:
            self.current_score = score
            self.history.append({"ts": now, "score": score})

        return self.get_risk_data()

    def get_risk_data(self) -> dict:
        """Get current risk score, level, and trend."""
        with self._lock:
            score = self.current_score
            history = list(self.history)

        # Determine level
        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 35:
            level = "medium"
        elif score >= 15:
            level = "low"
        else:
            level = "minimal"

        # Calculate trend
        trend = "stable"
        if len(history) >= 6:
            recent_avg = sum(h["score"] for h in history[-3:]) / 3
            older_avg = sum(h["score"] for h in history[-6:-3]) / 3
            diff = recent_avg - older_avg
            if diff > 5:
                trend = "rising"
            elif diff < -5:
                trend = "falling"

        return {
            "score": score,
            "level": level,
            "trend": trend,
            "history": [{"ts": h["ts"], "score": h["score"]} for h in history[-60:]],
        }


# ═══════════════════════════════════════════════════════════════════════════
# SIEM ENGINE — main orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class SIEMEngine:
    """Main SIEM/SOAR engine combining all components."""

    def __init__(self):
        self.collector = EventCollector()
        self.correlator = CorrelationEngine()
        self.playbook = SOARPlaybook()
        self.log_manager = LogManager()
        self.risk_calc = RiskScoreCalculator()

        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._auth_user = None

        self.started_at = time.time()
        self._running = False
        self.alerts = deque(maxlen=200)
        self.total_alerts = 0

    def _check_perm(self, perm_type="execute"):
        if not self._perm or not self._perm.is_enabled():
            return True
        if getattr(self._perm, "locked", False) and not self._auth_user:
            return False
        return self._perm.check(self._auth_user, "siem", perm_type)

    def start(self):
        self._running = True
        self.started_at = time.time()

        self.collector.start()
        self.log_manager.start()

        # Start the correlation processing loop
        t = threading.Thread(target=self._correlation_loop, daemon=True)
        t.start()

        # Start risk score calculation loop
        t2 = threading.Thread(target=self._risk_loop, daemon=True)
        t2.start()

        logger.info("[SIEMEngine] All components started")

    def stop(self):
        self._running = False
        self.collector.stop()
        self.log_manager.stop()
        logger.info("[SIEMEngine] All components stopped")

    def _correlation_loop(self):
        """Process new events through the correlation engine."""
        processed_count = 0
        while self._running:
            try:
                events = self.collector.get_events(limit=500)
                # Process only new events
                for ev in events[processed_count:]:
                    # Store in log
                    self.log_manager.store(ev)

                    # Run through correlation engine
                    triggered = self.correlator.process_event(ev)

                    # Execute playbooks for triggered correlations
                    for corr in triggered:
                        action = corr.get("action", "alert")
                        self._create_alert(corr)

                        if action != "alert":
                            context = {
                                "ip": corr.get("ip", ""),
                                "correlation_id": corr.get("id", ""),
                                "rule_name": corr.get("rule_name", ""),
                                "severity": corr.get("severity", "medium"),
                            }
                            self.playbook.execute(action, context)

                new_count = len(events)
                if new_count > processed_count:
                    processed_count = new_count

            except Exception as e:
                logger.error("[SIEMEngine] Correlation loop error: %s", e)

            time.sleep(3)

    def _risk_loop(self):
        """Periodically recalculate risk score."""
        while self._running:
            try:
                self.risk_calc.calculate(self.collector, self.correlator)
            except Exception as e:
                logger.error("[SIEMEngine] Risk calc error: %s", e)
            time.sleep(5)

    def _create_alert(self, correlation: dict):
        """Create an alert from a correlation."""
        alert = {
            "id": correlation.get("id", ""),
            "ts": correlation.get("ts", time.time()),
            "ts_iso": correlation.get("ts_iso", datetime.now().isoformat()),
            "rule_name": correlation.get("rule_name", ""),
            "severity": correlation.get("severity", "medium"),
            "ip": correlation.get("ip", ""),
            "description": correlation.get("description", ""),
            "action": correlation.get("action", "alert"),
            "acknowledged": False,
        }
        self.alerts.append(alert)
        self.total_alerts += 1
        logger.warning("[ALERT] %s — IP=%s severity=%s",
                        alert["rule_name"], alert["ip"], alert["severity"])

    def get_state(self) -> dict:
        """Build full state for dashboard / WebSocket broadcast."""
        now = time.time()
        risk = self.risk_calc.get_risk_data()
        collector_stats = self.collector.get_stats()
        correlation_stats = self.correlator.get_stats()
        playbook_stats = self.playbook.get_stats()
        log_stats = self.log_manager.get_stats()

        return {
            "type": "siem_state",
            "version": VERSION,
            "ts": now,
            "uptime": round(now - self.started_at, 1),
            "risk": risk,
            "events": {
                "recent": self.collector.get_events(limit=MAX_TIMELINE),
                "stats": collector_stats,
            },
            "correlations": {
                "recent": self.correlator.get_correlations(limit=50),
                "stats": correlation_stats,
            },
            "kill_chain": self.correlator.get_kill_chain_status(),
            "top_threats": self.correlator.get_top_threat_ips(limit=10),
            "agents": self.collector.get_agent_health(),
            "alerts": {
                "recent": list(self.alerts)[-50:],
                "total": self.total_alerts,
            },
            "playbooks": {
                "list": self.playbook.get_playbooks(),
                "stats": playbook_stats,
                "recent_executions": self.playbook.get_execution_log(limit=10),
            },
            "logs": log_stats,
        }


# ═══════════════════════════════════════════════════════════════════════════
# SIEM API — pywebview js_api for dashboard interaction
# ═══════════════════════════════════════════════════════════════════════════

class SIEMAPI:
    """API exposed to the SIEM dashboard via pywebview."""

    def __init__(self, engine: SIEMEngine):
        self.engine = engine

    # ─── State ────────────────────────────────────────────────────────

    def get_state(self) -> str:
        """Get complete SIEM state."""
        return json.dumps(self.engine.get_state(), default=str)

    def get_events(self, limit: int = 100, agent: str = None,
                   severity: str = None) -> str:
        """Get filtered events."""
        events = self.engine.collector.get_events(
            limit=limit, agent=agent or None, severity=severity or None
        )
        return json.dumps({"events": events, "count": len(events)}, default=str)

    def get_correlations(self, limit: int = 50) -> str:
        """Get recent correlations."""
        corrs = self.engine.correlator.get_correlations(limit=limit)
        return json.dumps({"correlations": corrs, "count": len(corrs)}, default=str)

    def get_risk_score(self) -> str:
        """Get current risk score and trend."""
        return json.dumps(self.engine.risk_calc.get_risk_data(), default=str)

    def get_agent_health(self) -> str:
        """Get health status of all agents."""
        return json.dumps(self.engine.collector.get_agent_health(), default=str)

    def get_kill_chain(self) -> str:
        """Get kill chain status."""
        return json.dumps(self.engine.correlator.get_kill_chain_status(), default=str)

    def get_top_threats(self, limit: int = 10) -> str:
        """Get top threat IPs."""
        threats = self.engine.correlator.get_top_threat_ips(limit=limit)
        return json.dumps({"threats": threats}, default=str)

    # ─── Playbook Controls ────────────────────────────────────────────

    def get_playbooks(self) -> str:
        """Get all playbooks and their status."""
        return json.dumps({"playbooks": self.engine.playbook.get_playbooks()}, default=str)

    def run_playbook(self, name: str, ip: str = "") -> str:
        """Manually trigger a playbook."""
        if not self.engine._check_perm("execute"):
            return json.dumps({"error": "Permission denied"})
        context = {"ip": ip, "manual": True, "triggered_by": "dashboard"}
        result = self.engine.playbook.execute(name, context)
        return json.dumps(result, default=str)

    def get_execution_log(self, limit: int = 50) -> str:
        """Get playbook execution history."""
        log = self.engine.playbook.get_execution_log(limit=limit)
        return json.dumps({"executions": log, "count": len(log)}, default=str)

    # ─── Log Search & Export ──────────────────────────────────────────

    def search_logs(self, query: str, limit: int = 100) -> str:
        """Search across all stored logs."""
        if not query:
            return json.dumps({"results": [], "count": 0})
        results = self.engine.log_manager.search(query, limit=limit)
        return json.dumps({"results": results, "count": len(results), "query": query}, default=str)

    def export_logs(self, fmt: str = "json", limit: int = 500) -> str:
        """Export recent events in the specified format (csv, json, syslog)."""
        events = self.engine.collector.get_events(limit=limit)
        if fmt == "csv":
            data = self.engine.log_manager.export_csv(events)
        elif fmt == "syslog":
            data = self.engine.log_manager.export_syslog(events)
        else:
            data = self.engine.log_manager.export_json(events)
        return json.dumps({"format": fmt, "data": data, "count": len(events)}, default=str)

    # ─── Correlation Rules ────────────────────────────────────────────

    def get_rules(self) -> str:
        """Get all correlation rules."""
        return json.dumps({"rules": self.engine.correlator.get_rules()}, default=str)

    def add_correlation_rule(self, rule_json: str) -> str:
        """Add a new correlation rule."""
        if not self.engine._check_perm("modify"):
            return json.dumps({"error": "Permission denied"})
        try:
            rule = json.loads(rule_json)
            result = self.engine.correlator.add_rule(rule)
            return json.dumps(result, default=str)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})

    # ─── Alerts ───────────────────────────────────────────────────────

    def acknowledge_alert(self, alert_id: str) -> str:
        """Acknowledge an alert."""
        for alert in self.engine.alerts:
            if alert.get("id") == alert_id:
                alert["acknowledged"] = True
                return json.dumps({"success": True, "alert_id": alert_id})
        return json.dumps({"error": f"Alert not found: {alert_id}"})

    # ─── Permission management ────────────────────────────────────────

    def perm_get_status(self) -> str:
        if self.engine._perm:
            return json.dumps({
                "enabled": self.engine._perm.is_enabled(),
                "locked": getattr(self.engine._perm, "locked", False),
                "auth_user": self.engine._auth_user,
            })
        return json.dumps({"enabled": False, "locked": False, "auth_user": None})

    def perm_enable(self) -> str:
        if self.engine._perm:
            self.engine._perm.enable()
            return json.dumps({"success": True})
        return json.dumps({"error": "Permissions module not available"})

    def perm_authenticate(self, username: str, password: str) -> str:
        if self.engine._perm and hasattr(self.engine._perm, "authenticate"):
            if self.engine._perm.authenticate(username, password):
                self.engine._auth_user = username
                return json.dumps({"success": True, "user": username})
            return json.dumps({"success": False})
        return json.dumps({"error": "Permissions module not available"})

    def perm_lock(self) -> str:
        if self.engine._perm:
            self.engine._perm.locked = True
            return json.dumps({"success": True})
        return json.dumps({"error": "Permissions module not available"})

    def perm_unlock(self) -> str:
        if self.engine._perm:
            self.engine._perm.locked = False
            return json.dumps({"success": True})
        return json.dumps({"error": "Permissions module not available"})


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SERVER
# ═══════════════════════════════════════════════════════════════════════════

_engine = SIEMEngine()
_ws_clients: set = set()


async def handle_ws(websocket, path=None):
    """Handle incoming WebSocket connections and commands."""
    _ws_clients.add(websocket)
    logger.info("[WS] Client connected (%d total)", len(_ws_clients))
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                cmd = msg.get("cmd", "")
                response = None

                if cmd == "get_state":
                    response = _engine.get_state()

                elif cmd == "get_events":
                    limit = msg.get("limit", 100)
                    agent = msg.get("agent")
                    severity = msg.get("severity")
                    events = _engine.collector.get_events(limit=limit, agent=agent, severity=severity)
                    response = {"type": "events", "events": events, "count": len(events)}

                elif cmd == "get_correlations":
                    limit = msg.get("limit", 50)
                    corrs = _engine.correlator.get_correlations(limit=limit)
                    response = {"type": "correlations", "correlations": corrs, "count": len(corrs)}

                elif cmd == "get_risk":
                    response = {"type": "risk", **_engine.risk_calc.get_risk_data()}

                elif cmd == "get_kill_chain":
                    response = {"type": "kill_chain", **_engine.correlator.get_kill_chain_status()}

                elif cmd == "run_playbook":
                    name = msg.get("name", "")
                    ip = msg.get("ip", "")
                    if not _engine._check_perm("execute"):
                        response = {"type": "error", "message": "Permission denied"}
                    else:
                        context = {"ip": ip, "manual": True}
                        result = _engine.playbook.execute(name, context)
                        response = {"type": "playbook_result", "result": result}

                elif cmd == "search_logs":
                    query = msg.get("query", "")
                    limit = msg.get("limit", 100)
                    results = _engine.log_manager.search(query, limit=limit)
                    response = {"type": "search_results", "results": results, "count": len(results)}

                elif cmd == "export_logs":
                    fmt = msg.get("format", "json")
                    limit = msg.get("limit", 500)
                    events = _engine.collector.get_events(limit=limit)
                    if fmt == "csv":
                        data = _engine.log_manager.export_csv(events)
                    elif fmt == "syslog":
                        data = _engine.log_manager.export_syslog(events)
                    else:
                        data = _engine.log_manager.export_json(events)
                    response = {"type": "export", "format": fmt, "data": data, "count": len(events)}

                elif cmd == "acknowledge_alert":
                    alert_id = msg.get("alert_id", "")
                    for alert in _engine.alerts:
                        if alert.get("id") == alert_id:
                            alert["acknowledged"] = True
                    response = {"type": "alert_ack", "alert_id": alert_id}

                # ── Permission management commands ─────────────────────
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
        logger.info("[WS] Client disconnected (%d remaining)", len(_ws_clients))


async def broadcast_loop():
    """Broadcast SIEM state to all connected WebSocket clients every 5 seconds."""
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
    logger.info("  SIEM/SOAR Engine v%s — Optimus Suite", VERSION)
    logger.info("  WebSocket port: %d", port)
    logger.info("  Mode: %s", "headless" if headless else "GUI")
    logger.info("  Platform: %s", "Windows" if IS_WINDOWS else sys.platform)
    logger.info("  Log dir: %s", LOG_DIR)
    logger.info("  Agents monitored: %d", len(AGENT_ENDPOINTS))
    logger.info("  Correlation rules: %d", len(_engine.correlator.rules))
    logger.info("  Playbooks: %d", len(_engine.playbook.playbooks))
    logger.info("=" * 60)

    _engine.start()

    if headless or not HAS_WEBVIEW:
        # Headless mode: just run WebSocket server
        if not HAS_WS:
            logger.error("[SIEM] websockets not installed — cannot start server")
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run():
            server = await websockets.serve(handle_ws, "localhost", port)
            logger.info("[SIEM] WebSocket server on ws://localhost:%d", port)
            asyncio.create_task(broadcast_loop())
            await asyncio.Future()  # Run forever

        try:
            loop.run_until_complete(run())
        except KeyboardInterrupt:
            pass
        finally:
            _engine.stop()
            logger.info("[SIEM] Shutdown.")
    else:
        # GUI mode with pywebview
        loop = asyncio.new_event_loop()

        def ws_thread():
            asyncio.set_event_loop(loop)

            async def run():
                if HAS_WS:
                    server = await websockets.serve(handle_ws, "localhost", port)
                    logger.info("[SIEM] WebSocket server on ws://localhost:%d", port)
                    asyncio.create_task(broadcast_loop())
                await asyncio.Future()

            loop.run_until_complete(run())

        t = threading.Thread(target=ws_thread, daemon=True)
        t.start()

        # Give WebSocket server time to start
        time.sleep(1)

        dashboard_path = os.path.join(SIEM_DIR, "siem_dashboard.html")
        api = SIEMAPI(_engine)

        if not os.path.exists(dashboard_path):
            logger.error("[SIEM] Dashboard not found: %s", dashboard_path)
            logger.info("[SIEM] Falling back to headless mode")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            try:
                window = webview.create_window(
                    "SIEM/SOAR — Optimus Suite",
                    dashboard_path,
                    js_api=api,
                    width=1400,
                    height=900,
                    min_size=(1100, 700),
                    background_color="#0f0f13",
                )
                logger.info("[SIEM] Opening SIEM dashboard...")
                webview.start(debug=False)
            except ImportError:
                logger.warning("[SIEM] pywebview not installed, opening in browser")
                import webbrowser
                webbrowser.open(Path(dashboard_path).as_uri())
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
            except Exception as e:
                logger.error("[SIEM] Dashboard error: %s", e)
                import webbrowser
                webbrowser.open(Path(dashboard_path).as_uri())
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass

    # Cleanup
    _engine.stop()
    logger.info("[SIEM] Goodbye.")


if __name__ == "__main__":
    main()
