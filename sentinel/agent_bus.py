"""
SentinelOS — Agent Bus
Inter-agent pub/sub communication system.
Allows agents and the Cortex brain to publish/subscribe to events.
"""

import time
import threading
import logging
from collections import defaultdict
from typing import Callable, Any, Optional

logger = logging.getLogger("SentinelOS.AgentBus")

# ═══════════════════════════════════════════════════════════════════════════
# EVENT
# ═══════════════════════════════════════════════════════════════════════════

class BusEvent:
    """An event that flows through the Agent Bus."""
    __slots__ = ("channel", "source", "data", "ts", "severity")

    def __init__(self, channel: str, source: str, data: dict, severity: str = "info"):
        self.channel = channel
        self.source = source
        self.data = data
        self.ts = time.time()
        self.severity = severity  # info, warning, critical

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "source": self.source,
            "data": self.data,
            "ts": self.ts,
            "severity": self.severity,
        }

    def __repr__(self):
        return f"<BusEvent {self.channel} from={self.source} sev={self.severity}>"


# ═══════════════════════════════════════════════════════════════════════════
# AGENT BUS
# ═══════════════════════════════════════════════════════════════════════════

class AgentBus:
    """
    In-process pub/sub message bus for inter-agent communication.

    Channels use dot-notation with wildcard support:
        "threat.*"      — all threat events
        "network.scan"  — specific event
        "*"             — everything

    Usage:
        bus = AgentBus()
        bus.subscribe("threat.*", my_callback)
        bus.publish("threat.detected", "NetGuard", {"ip": "1.2.3.4", "type": "portscan"})
    """

    # Predefined channel categories
    CHANNELS = {
        "threat":   "Security threats and alerts",
        "network":  "Network events (connections, scans, blocks)",
        "system":   "System events (disk, CPU, processes)",
        "vpn":      "VPN events (connect, disconnect, peer changes)",
        "email":    "Email events (phishing, spam, analysis)",
        "clean":    "Cleanup events (scan, quarantine, delete)",
        "agent":    "Agent lifecycle (started, stopped, error)",
        "cortex":   "Cortex brain decisions and actions",
        "action":   "Inter-agent commands and requests",
    }

    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._history: list[BusEvent] = []
        self._max_history = 500
        self._lock = threading.Lock()
        self._stats = defaultdict(int)
        logger.info("[AgentBus] Initialized")

    # ───────────────────────────────────────────────────────────────────
    # SUBSCRIBE / UNSUBSCRIBE
    # ───────────────────────────────────────────────────────────────────

    def subscribe(self, pattern: str, callback: Callable[[BusEvent], Any]) -> str:
        """
        Subscribe to events matching a channel pattern.
        Returns a subscription ID for unsubscribe.

        Patterns:
            "threat.*"         — any sub-channel of threat
            "threat.detected"  — exact match
            "*"                — everything
        """
        sub_id = f"{pattern}:{id(callback)}:{time.time()}"
        with self._lock:
            self._subscribers[pattern].append((sub_id, callback))
        logger.debug(f"[AgentBus] Subscribed: {pattern} -> {sub_id}")
        return sub_id

    def unsubscribe(self, sub_id: str):
        """Remove a subscription by its ID."""
        with self._lock:
            for pattern, subs in self._subscribers.items():
                self._subscribers[pattern] = [
                    (sid, cb) for sid, cb in subs if sid != sub_id
                ]

    # ───────────────────────────────────────────────────────────────────
    # PUBLISH
    # ───────────────────────────────────────────────────────────────────

    def publish(self, channel: str, source: str, data: dict,
                severity: str = "info") -> BusEvent:
        """
        Publish an event to a channel.
        All matching subscribers will be called asynchronously.
        """
        event = BusEvent(channel, source, data, severity)

        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            self._stats[channel] += 1

        # Find matching subscribers
        matching = []
        with self._lock:
            for pattern, subs in self._subscribers.items():
                if self._matches(pattern, channel):
                    matching.extend(subs)

        # Call subscribers in threads to avoid blocking
        for sub_id, callback in matching:
            threading.Thread(
                target=self._safe_call,
                args=(callback, event, sub_id),
                daemon=True,
            ).start()

        return event

    def _safe_call(self, callback: Callable, event: BusEvent, sub_id: str):
        """Call a subscriber safely, catching exceptions."""
        try:
            callback(event)
        except Exception as e:
            logger.error(f"[AgentBus] Subscriber error {sub_id}: {e}")

    # ───────────────────────────────────────────────────────────────────
    # PATTERN MATCHING
    # ───────────────────────────────────────────────────────────────────

    @staticmethod
    def _matches(pattern: str, channel: str) -> bool:
        """Check if a channel matches a subscription pattern."""
        if pattern == "*":
            return True
        if pattern == channel:
            return True
        # Wildcard: "threat.*" matches "threat.detected", "threat.blocked"
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return channel.startswith(prefix + ".")
        return False

    # ───────────────────────────────────────────────────────────────────
    # HISTORY & STATS
    # ───────────────────────────────────────────────────────────────────

    def get_history(self, channel_filter: Optional[str] = None,
                    source_filter: Optional[str] = None,
                    severity_filter: Optional[str] = None,
                    limit: int = 50) -> list[dict]:
        """Get recent events, optionally filtered."""
        with self._lock:
            events = list(self._history)

        if channel_filter:
            events = [e for e in events if self._matches(channel_filter, e.channel)]
        if source_filter:
            events = [e for e in events if e.source == source_filter]
        if severity_filter:
            events = [e for e in events if e.severity == severity_filter]

        return [e.to_dict() for e in events[-limit:]]

    def get_stats(self) -> dict:
        """Get publish statistics per channel."""
        with self._lock:
            return dict(self._stats)

    def get_timeline(self, limit: int = 100) -> list[dict]:
        """Get a unified timeline of all events."""
        with self._lock:
            return [e.to_dict() for e in self._history[-limit:]]

    def clear_history(self):
        """Clear event history."""
        with self._lock:
            self._history.clear()
            self._stats.clear()
