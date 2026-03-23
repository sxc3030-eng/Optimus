"""
SentinelOS — Alert Manager v1.0
Centralized alert routing to Telegram, Discord, and other channels.
Subscribes to AgentBus events and sends notifications based on severity.

Features:
    - Telegram Bot alerts
    - Discord Webhook alerts
    - Alert throttling & batching
    - Severity-based routing
    - Bilingual messages (FR/EN)
"""

import time
import json
import logging
import threading
from collections import defaultdict

logger = logging.getLogger("SentinelOS.AlertManager")


# ═══════════════════════════════════════════════════════════════════════════
# ALERT MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class AlertManager:
    """Centralized alert routing and notification system."""

    def __init__(self, bus, settings: dict = None):
        self.bus = bus
        self.settings = settings or {}
        self._cooldowns: dict[str, float] = {}  # key -> last_sent timestamp
        self._cooldown_seconds = 60  # Min seconds between same alert type
        self._alert_queue: list[dict] = []
        self._batch_interval = 30  # Batch alerts every 30s
        self._running = True
        self._log: list[dict] = []
        self._max_log = 200

        # Subscribe to bus events
        bus.subscribe("threat.*", self._on_event)
        bus.subscribe("honeypot.*", self._on_event)
        bus.subscribe("fim.*", self._on_event)
        bus.subscribe("cortex.playbook_fired", self._on_event)
        bus.subscribe("agent.*", self._on_agent_event)

        # Start batch sender
        t = threading.Thread(target=self._batch_loop, daemon=True)
        t.start()

        logger.info("[AlertManager] Initialized")

    def _on_event(self, event):
        """Handle bus events — queue for alerting if severity >= warning."""
        if event.severity in ("warning", "critical"):
            self._queue_alert(event)

    def _on_agent_event(self, event):
        """Handle agent lifecycle events."""
        # Only alert on agent errors/stops
        if "error" in event.channel or "stopped" in event.channel:
            self._queue_alert(event)

    def _queue_alert(self, event):
        """Add event to alert queue (with cooldown check)."""
        key = f"{event.channel}:{event.source}"
        now = time.time()

        # Check cooldown
        last = self._cooldowns.get(key, 0)
        if now - last < self._cooldown_seconds:
            return

        self._cooldowns[key] = now
        self._alert_queue.append({
            "channel": event.channel,
            "source": event.source,
            "severity": event.severity,
            "data": event.data,
            "ts": event.ts,
        })

    def _batch_loop(self):
        """Periodically send batched alerts."""
        while self._running:
            time.sleep(self._batch_interval)
            if self._alert_queue:
                alerts = list(self._alert_queue)
                self._alert_queue.clear()
                self._send_batch(alerts)

    def _send_batch(self, alerts: list):
        """Send a batch of alerts to all configured channels."""
        if not alerts:
            return

        lang = self.settings.get("language", "fr")

        # Send to Telegram
        telegram_token = self.settings.get("telegram_bot_token", "")
        telegram_chat = self.settings.get("telegram_chat_id", "")
        if telegram_token and telegram_chat:
            self._send_telegram(alerts, telegram_token, telegram_chat, lang)

        # Send to Discord
        discord_webhook = self.settings.get("discord_webhook_url", "")
        if discord_webhook:
            self._send_discord(alerts, discord_webhook, lang)

        # Log
        for a in alerts:
            self._log.append({**a, "sent": True, "sent_ts": time.time()})
        if len(self._log) > self._max_log:
            self._log = self._log[-self._max_log:]

    def _send_telegram(self, alerts: list, token: str, chat_id: str, lang: str):
        """Send alerts via Telegram Bot API."""
        try:
            import requests
        except ImportError:
            logger.warning("[AlertManager] requests not installed, cannot send Telegram")
            return

        # Build message
        severity_emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
        header = "🛡️ *SentinelOS Alert*\n\n" if lang == "en" else "🛡️ *Alerte SentinelOS*\n\n"
        lines = [header]

        for a in alerts[:10]:  # Max 10 per message
            emoji = severity_emoji.get(a["severity"], "ℹ️")
            source = a["source"]
            channel = a["channel"]
            data = a["data"] or {}
            msg = data.get("message", channel)
            lines.append(f"{emoji} *{source}* — {msg}\n")

        if len(alerts) > 10:
            remaining = len(alerts) - 10
            lines.append(f"\n_+{remaining} {'more alerts' if lang=='en' else 'alertes supplementaires'}..._")

        text = "".join(lines)

        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            resp = requests.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }, timeout=10)
            if resp.status_code == 200:
                logger.info(f"[AlertManager] Telegram: sent {len(alerts)} alerts")
            else:
                logger.error(f"[AlertManager] Telegram error: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            logger.error(f"[AlertManager] Telegram send error: {e}")

    def _send_discord(self, alerts: list, webhook_url: str, lang: str):
        """Send alerts via Discord Webhook."""
        try:
            import requests
        except ImportError:
            logger.warning("[AlertManager] requests not installed, cannot send Discord")
            return

        severity_colors = {"info": 0x3498db, "warning": 0xf39c12, "critical": 0xe74c3c}

        # Group by severity
        critical = [a for a in alerts if a["severity"] == "critical"]
        warnings = [a for a in alerts if a["severity"] == "warning"]

        # Build embed
        title = "SentinelOS Alert" if lang == "en" else "Alerte SentinelOS"
        color = 0xe74c3c if critical else 0xf39c12 if warnings else 0x3498db

        fields = []
        for a in alerts[:8]:  # Max 8 fields
            data = a["data"] or {}
            msg = data.get("message", a["channel"])
            sev = a["severity"].upper()
            fields.append({
                "name": f"{'🚨' if a['severity']=='critical' else '⚠️'} {a['source']}",
                "value": f"{msg}\n`{a['channel']}` — {sev}",
                "inline": False,
            })

        embed = {
            "title": f"🛡️ {title}",
            "color": color,
            "fields": fields,
            "footer": {"text": f"SentinelOS v1.0 — {len(alerts)} alert(s)"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        try:
            resp = requests.post(webhook_url, json={"embeds": [embed]}, timeout=10)
            if resp.status_code in (200, 204):
                logger.info(f"[AlertManager] Discord: sent {len(alerts)} alerts")
            else:
                logger.error(f"[AlertManager] Discord error: {resp.status_code}")
        except Exception as e:
            logger.error(f"[AlertManager] Discord send error: {e}")

    # ─── API Methods ──────────────────────────────────────────────────

    def get_config(self) -> dict:
        """Get alert configuration (safe — no tokens exposed)."""
        return {
            "telegram_configured": bool(self.settings.get("telegram_bot_token")),
            "telegram_chat_id": self.settings.get("telegram_chat_id", "")[:4] + "..." if self.settings.get("telegram_chat_id") else "",
            "discord_configured": bool(self.settings.get("discord_webhook_url")),
            "cooldown_seconds": self._cooldown_seconds,
            "batch_interval": self._batch_interval,
        }

    def update_config(self, config: dict):
        """Update alert configuration."""
        if "telegram_bot_token" in config:
            self.settings["telegram_bot_token"] = config["telegram_bot_token"]
        if "telegram_chat_id" in config:
            self.settings["telegram_chat_id"] = config["telegram_chat_id"]
        if "discord_webhook_url" in config:
            self.settings["discord_webhook_url"] = config["discord_webhook_url"]
        if "cooldown_seconds" in config:
            self._cooldown_seconds = int(config["cooldown_seconds"])
        if "batch_interval" in config:
            self._batch_interval = int(config["batch_interval"])
        logger.info("[AlertManager] Configuration updated")

    def test_telegram(self) -> bool:
        """Send a test message to Telegram."""
        token = self.settings.get("telegram_bot_token", "")
        chat_id = self.settings.get("telegram_chat_id", "")
        if not token or not chat_id:
            return False
        try:
            import requests
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": "🛡️ SentinelOS — Test alert OK!"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def test_discord(self) -> bool:
        """Send a test message to Discord."""
        url = self.settings.get("discord_webhook_url", "")
        if not url:
            return False
        try:
            import requests
            resp = requests.post(
                url,
                json={"content": "🛡️ SentinelOS — Test alert OK!"},
                timeout=10,
            )
            return resp.status_code in (200, 204)
        except Exception:
            return False

    def get_log(self, limit: int = 50) -> list:
        """Get recent alert log."""
        return self._log[-limit:]

    def stop(self):
        self._running = False
