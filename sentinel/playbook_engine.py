"""
SentinelOS — SOAR Playbook Engine v1.0
Security Orchestration, Automated Response.
Defines playbooks that trigger automated responses when threats are detected.

Architecture:
    PlaybookEngine
        ├── Subscribes to AgentBus events
        ├── Evaluates playbook conditions against agent states
        ├── Executes response actions (cross-agent commands)
        └── Logs all executions for audit trail
"""

import time
import json
import logging
import threading
from collections import defaultdict

logger = logging.getLogger("SentinelOS.Playbook")


# ═══════════════════════════════════════════════════════════════════════════
# PLAYBOOK DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

# Each playbook has:
#   name, description (fr/en), trigger (channel pattern),
#   condition (function taking event+states), actions (list of commands),
#   cooldown (seconds), enabled (bool)

DEFAULT_PLAYBOOKS = [
    {
        "id": "pb_network_threat_high",
        "name": {"fr": "Menace reseau critique", "en": "Critical network threat"},
        "description": {
            "fr": "Quand NetGuard detecte plus de 10 menaces, activer DPI + Suricata + VPN auto-connect",
            "en": "When NetGuard detects 10+ threats, enable DPI + Suricata + auto-connect VPN",
        },
        "trigger": "network.*",
        "severity_min": "warning",
        "condition": "netguard.threats_count > 10",
        "actions": [
            {"agent": "netguard", "cmd": "toggle_dpi", "params": {}},
            {"agent": "vpnguard", "cmd": "quick_connect", "params": {}},
        ],
        "cooldown": 300,
        "enabled": True,
    },
    {
        "id": "pb_malware_found",
        "name": {"fr": "Malware detecte", "en": "Malware detected"},
        "description": {
            "fr": "Quand CleanGuard trouve des menaces, activer la protection temps reel + alerter",
            "en": "When CleanGuard finds threats, enable real-time protection + alert",
        },
        "trigger": "clean.*",
        "severity_min": "warning",
        "condition": "cleanguard.scan_threats_count > 0",
        "actions": [
            {"agent": "cleanguard", "cmd": "toggle_realtime", "params": {}},
        ],
        "cooldown": 600,
        "enabled": True,
    },
    {
        "id": "pb_vpn_disconnect_killswitch",
        "name": {"fr": "VPN deconnecte - Kill Switch", "en": "VPN disconnected - Kill Switch"},
        "description": {
            "fr": "Si le VPN se deconnecte inopinement, activer le Kill Switch immediatement",
            "en": "If VPN disconnects unexpectedly, activate Kill Switch immediately",
        },
        "trigger": "vpn.*",
        "severity_min": "info",
        "condition": "vpnguard.connected == False and vpnguard.kill_switch_enabled == False",
        "actions": [
            {"agent": "vpnguard", "cmd": "toggle_kill_switch", "params": {}},
        ],
        "cooldown": 60,
        "enabled": True,
    },
    {
        "id": "pb_attack_chain_response",
        "name": {"fr": "Chaine d'attaque detectee", "en": "Attack chain detected"},
        "description": {
            "fr": "Quand une chaine d'attaque est detectee, lancer scan complet + connecter VPN",
            "en": "When attack chain is detected, launch full scan + connect VPN",
        },
        "trigger": "threat.*",
        "severity_min": "critical",
        "condition": "netguard.attack_chains_count > 0",
        "actions": [
            {"agent": "cleanguard", "cmd": "quick_scan", "params": {}},
            {"agent": "vpnguard", "cmd": "quick_connect", "params": {}},
        ],
        "cooldown": 600,
        "enabled": True,
    },
    {
        "id": "pb_dns_leak_response",
        "name": {"fr": "Fuite DNS detectee", "en": "DNS leak detected"},
        "description": {
            "fr": "Si la protection DNS est inactive avec VPN actif, activer la protection DNS",
            "en": "If DNS protection is inactive with VPN active, enable DNS protection",
        },
        "trigger": "vpn.*",
        "severity_min": "info",
        "condition": "vpnguard.connected == True and vpnguard.dns_protected == False",
        "actions": [
            {"agent": "vpnguard", "cmd": "toggle_dns_protection", "params": {}},
        ],
        "cooldown": 120,
        "enabled": True,
    },
    {
        "id": "pb_honeypot_triggered",
        "name": {"fr": "Honeypot declenche", "en": "Honeypot triggered"},
        "description": {
            "fr": "Quand le honeypot detecte une intrusion, bloquer l'IP + scanner + alerter",
            "en": "When honeypot detects intrusion, block IP + scan + alert",
        },
        "trigger": "honeypot.*",
        "severity_min": "warning",
        "condition": "always",
        "actions": [
            {"agent": "cleanguard", "cmd": "quick_scan", "params": {}},
        ],
        "cooldown": 300,
        "enabled": True,
    },
    {
        "id": "pb_file_integrity_breach",
        "name": {"fr": "Integrite fichier violee", "en": "File integrity breach"},
        "description": {
            "fr": "Quand le FIM detecte une modification suspecte, scanner + alerter",
            "en": "When FIM detects suspicious modification, scan + alert",
        },
        "trigger": "fim.*",
        "severity_min": "warning",
        "condition": "always",
        "actions": [
            {"agent": "cleanguard", "cmd": "quick_scan", "params": {}},
        ],
        "cooldown": 300,
        "enabled": True,
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# PLAYBOOK ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class PlaybookEngine:
    """SOAR Playbook engine — evaluates conditions and executes automated responses."""

    def __init__(self, bus, connectors, api=None):
        self.bus = bus
        self.connectors = connectors
        self.api = api  # CortexAPI for sending commands
        self.playbooks = list(DEFAULT_PLAYBOOKS)
        self._last_fired: dict[str, float] = {}
        self._execution_log: list[dict] = []
        self._max_log = 200
        self._running = True

        # Subscribe to all events
        self.bus.subscribe("*", self._on_event)
        logger.info(f"[Playbook] Engine initialized with {len(self.playbooks)} playbooks")

    def set_api(self, api):
        """Set the CortexAPI reference (needed for sending commands)."""
        self.api = api

    def _on_event(self, event):
        """Called for every bus event — check if any playbook should trigger."""
        if not self._running:
            return
        for pb in self.playbooks:
            if not pb.get("enabled", True):
                continue
            try:
                self._evaluate_playbook(pb, event)
            except Exception as e:
                logger.error(f"[Playbook] Error evaluating {pb['id']}: {e}")

    def _evaluate_playbook(self, pb: dict, event):
        """Check if a playbook should fire for this event."""
        pb_id = pb["id"]

        # Check trigger channel match
        trigger = pb.get("trigger", "")
        if not self._channel_matches(trigger, event.channel):
            return

        # Check severity minimum
        sev_min = pb.get("severity_min", "info")
        if not self._severity_ge(event.severity, sev_min):
            return

        # Check cooldown
        last = self._last_fired.get(pb_id, 0)
        cooldown = pb.get("cooldown", 60)
        if time.time() - last < cooldown:
            return

        # Evaluate condition
        condition = pb.get("condition", "always")
        if condition != "always" and not self._eval_condition(condition):
            return

        # FIRE — execute actions
        logger.info(f"[Playbook] FIRING: {pb_id} (trigger: {event.channel})")
        self._last_fired[pb_id] = time.time()
        self._execute_actions(pb, event)

    def _execute_actions(self, pb: dict, event):
        """Execute all actions in a playbook."""
        actions = pb.get("actions", [])
        results = []

        for action in actions:
            agent = action.get("agent", "")
            cmd = action.get("cmd", "")
            params = action.get("params", {})

            try:
                if self.api:
                    result = self.api.send_agent_command(agent, cmd, json.dumps(params))
                    results.append({"agent": agent, "cmd": cmd, "result": result})
                    logger.info(f"[Playbook] Action: {agent}.{cmd} -> {result}")
                else:
                    logger.warning(f"[Playbook] No API available to execute {agent}.{cmd}")
                    results.append({"agent": agent, "cmd": cmd, "result": "no_api"})
            except Exception as e:
                logger.error(f"[Playbook] Action error {agent}.{cmd}: {e}")
                results.append({"agent": agent, "cmd": cmd, "result": f"error: {e}"})

        # Log execution
        log_entry = {
            "playbook_id": pb["id"],
            "playbook_name": pb["name"],
            "trigger_event": event.channel,
            "trigger_source": event.source,
            "trigger_severity": event.severity,
            "actions": results,
            "ts": time.time(),
        }
        self._execution_log.append(log_entry)
        if len(self._execution_log) > self._max_log:
            self._execution_log = self._execution_log[-self._max_log:]

        # Publish execution event on bus
        self.bus.publish("cortex.playbook_fired", "playbook_engine", {
            "playbook": pb["id"],
            "actions_count": len(actions),
        }, severity="info")

    def _eval_condition(self, condition: str) -> bool:
        """Evaluate a simple condition string against agent states."""
        # Build variables from all agent states
        variables = {}
        for key, conn in self.connectors.items():
            s = conn.state or {}
            # Flatten state keys with agent prefix
            for k, v in s.items():
                variables[f"{key}.{k}"] = v
            # Special computed values
            if key == "netguard":
                chains = s.get("attack_chains", {})
                variables["netguard.attack_chains_count"] = len(chains) if isinstance(chains, dict) else 0

        # Simple expression evaluator (safe — no exec/eval of arbitrary code)
        try:
            # Handle comparisons: "agent.key > value", "agent.key == value"
            for op in [" > ", " >= ", " < ", " <= ", " == ", " != "]:
                if op in condition:
                    parts = condition.split(op, 1)
                    if len(parts) == 2:
                        left_key = parts[0].strip()
                        right_val = parts[1].strip()
                        left_val = variables.get(left_key, 0)

                        # Parse right value
                        if right_val == "True":
                            right_parsed = True
                        elif right_val == "False":
                            right_parsed = False
                        else:
                            try:
                                right_parsed = float(right_val)
                            except ValueError:
                                right_parsed = right_val

                        # Compare
                        if op.strip() == ">":
                            return float(left_val or 0) > float(right_parsed)
                        elif op.strip() == ">=":
                            return float(left_val or 0) >= float(right_parsed)
                        elif op.strip() == "<":
                            return float(left_val or 0) < float(right_parsed)
                        elif op.strip() == "<=":
                            return float(left_val or 0) <= float(right_parsed)
                        elif op.strip() == "==":
                            return left_val == right_parsed
                        elif op.strip() == "!=":
                            return left_val != right_parsed

            # Handle "and" compound conditions
            if " and " in condition:
                parts = condition.split(" and ")
                return all(self._eval_condition(p.strip()) for p in parts)

        except Exception as e:
            logger.debug(f"[Playbook] Condition eval error: {condition} -> {e}")
            return False

        return False

    @staticmethod
    def _channel_matches(pattern: str, channel: str) -> bool:
        if pattern == "*":
            return True
        if pattern == channel:
            return True
        if pattern.endswith(".*"):
            return channel.startswith(pattern[:-2] + ".")
        return False

    @staticmethod
    def _severity_ge(severity: str, minimum: str) -> bool:
        levels = {"info": 0, "warning": 1, "critical": 2}
        return levels.get(severity, 0) >= levels.get(minimum, 0)

    # ─── API Methods ──────────────────────────────────────────────────

    def get_playbooks(self, lang: str = "fr") -> list:
        """Get all playbooks with localized names."""
        result = []
        for pb in self.playbooks:
            result.append({
                "id": pb["id"],
                "name": pb["name"].get(lang, pb["name"].get("fr", pb["id"])),
                "description": pb["description"].get(lang, pb["description"].get("fr", "")),
                "trigger": pb.get("trigger", ""),
                "condition": pb.get("condition", ""),
                "actions": pb.get("actions", []),
                "cooldown": pb.get("cooldown", 60),
                "enabled": pb.get("enabled", True),
                "last_fired": self._last_fired.get(pb["id"], 0),
            })
        return result

    def toggle_playbook(self, pb_id: str) -> bool:
        """Toggle a playbook on/off. Returns new state."""
        for pb in self.playbooks:
            if pb["id"] == pb_id:
                pb["enabled"] = not pb.get("enabled", True)
                logger.info(f"[Playbook] {pb_id} {'enabled' if pb['enabled'] else 'disabled'}")
                return pb["enabled"]
        return False

    def get_execution_log(self, limit: int = 50) -> list:
        """Get recent playbook execution history."""
        return self._execution_log[-limit:]

    def stop(self):
        self._running = False
