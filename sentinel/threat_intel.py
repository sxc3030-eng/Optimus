"""
SentinelOS — Threat Intelligence Feed v1.0
Fetches and aggregates threat data from public sources.
Provides IP reputation, known malware hashes, and threat indicators.

Sources:
    - AbuseIPDB (free API)
    - OTX AlienVault (free API)
    - Emerging Threats (free ruleset)
    - Custom blocklists
"""

import os
import json
import time
import logging
import threading
from pathlib import Path

logger = logging.getLogger("SentinelOS.ThreatIntel")

SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))
INTEL_DIR = os.path.join(SENTINEL_DIR, "threat_data")
os.makedirs(INTEL_DIR, exist_ok=True)

# Free public blocklists (no API key needed)
PUBLIC_FEEDS = [
    {
        "name": "Feodo Tracker (Botnet C&C)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip_list",
        "category": "botnet",
    },
    {
        "name": "URLhaus (Malware URLs)",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "url_list",
        "category": "malware",
    },
    {
        "name": "SSLBL (SSL Blacklist)",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip_list",
        "category": "ssl_abuse",
    },
    {
        "name": "Blocklist.de (All Attackers)",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip_list",
        "category": "attacker",
    },
    {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "cidr_list",
        "category": "spam",
    },
]


class ThreatIntelFeed:
    """Fetches and manages threat intelligence data."""

    def __init__(self, bus=None):
        self.bus = bus
        self._malicious_ips: set = set()
        self._malicious_urls: set = set()
        self._malicious_hashes: set = set()
        self._cidr_blocks: list = []
        self._feed_stats: dict = {}
        self._last_update: float = 0
        self._update_interval: int = 3600  # 1 hour
        self._lock = threading.Lock()
        self._running = True

        # Load cached data
        self._load_cache()

    def _load_cache(self):
        """Load cached threat data from disk."""
        cache_file = os.path.join(INTEL_DIR, "intel_cache.json")
        try:
            if os.path.exists(cache_file):
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._malicious_ips = set(data.get("ips", []))
                self._malicious_urls = set(data.get("urls", []))
                self._malicious_hashes = set(data.get("hashes", []))
                self._cidr_blocks = data.get("cidrs", [])
                self._feed_stats = data.get("stats", {})
                self._last_update = data.get("last_update", 0)
                logger.info(f"[ThreatIntel] Loaded cache: {len(self._malicious_ips)} IPs, "
                            f"{len(self._malicious_urls)} URLs")
        except Exception as e:
            logger.warning(f"[ThreatIntel] Cache load error: {e}")

    def _save_cache(self):
        """Save threat data to disk."""
        cache_file = os.path.join(INTEL_DIR, "intel_cache.json")
        try:
            data = {
                "ips": list(self._malicious_ips)[:50000],  # Limit cache size
                "urls": list(self._malicious_urls)[:20000],
                "hashes": list(self._malicious_hashes)[:10000],
                "cidrs": self._cidr_blocks[:5000],
                "stats": self._feed_stats,
                "last_update": self._last_update,
            }
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f)
            logger.info("[ThreatIntel] Cache saved")
        except Exception as e:
            logger.error(f"[ThreatIntel] Cache save error: {e}")

    def update_feeds(self):
        """Fetch all public threat feeds."""
        try:
            import requests
        except ImportError:
            logger.warning("[ThreatIntel] requests not installed, skipping feed update")
            return

        logger.info("[ThreatIntel] Updating threat feeds...")
        total_new = 0

        for feed in PUBLIC_FEEDS:
            try:
                resp = requests.get(feed["url"], timeout=30,
                                    headers={"User-Agent": "SentinelOS-ThreatIntel/1.0"})
                if resp.status_code != 200:
                    logger.warning(f"[ThreatIntel] Feed {feed['name']} returned {resp.status_code}")
                    continue

                lines = resp.text.strip().split("\n")
                count = 0

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue

                    if feed["type"] == "ip_list":
                        # Extract IP (may have port or other info)
                        ip = line.split("|")[0].split(":")[0].split(",")[0].strip()
                        if self._is_valid_ip(ip):
                            with self._lock:
                                self._malicious_ips.add(ip)
                            count += 1

                    elif feed["type"] == "url_list":
                        if line.startswith("http"):
                            with self._lock:
                                self._malicious_urls.add(line)
                            count += 1

                    elif feed["type"] == "cidr_list":
                        parts = line.split(";")[0].strip()
                        if "/" in parts:
                            with self._lock:
                                self._cidr_blocks.append(parts)
                            count += 1

                self._feed_stats[feed["name"]] = {
                    "count": count,
                    "category": feed["category"],
                    "last_update": time.time(),
                }
                total_new += count
                logger.info(f"[ThreatIntel] {feed['name']}: {count} indicators loaded")

            except Exception as e:
                logger.error(f"[ThreatIntel] Feed {feed['name']} error: {e}")
                self._feed_stats[feed["name"]] = {
                    "count": 0,
                    "category": feed["category"],
                    "error": str(e),
                    "last_update": time.time(),
                }

        self._last_update = time.time()
        self._save_cache()

        if self.bus:
            self.bus.publish("cortex.threat_intel_updated", "threat_intel", {
                "total_ips": len(self._malicious_ips),
                "total_urls": len(self._malicious_urls),
                "new_indicators": total_new,
            })

        logger.info(f"[ThreatIntel] Update complete: {len(self._malicious_ips)} IPs, "
                    f"{len(self._malicious_urls)} URLs total")

    def start_auto_update(self):
        """Start background thread that updates feeds periodically."""
        def _loop():
            while self._running:
                if time.time() - self._last_update > self._update_interval:
                    self.update_feeds()
                time.sleep(60)  # Check every minute

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        logger.info("[ThreatIntel] Auto-update started")

    # ─── Lookup Methods ───────────────────────────────────────────────

    def is_malicious_ip(self, ip: str) -> bool:
        """Check if an IP is in the threat database."""
        with self._lock:
            return ip in self._malicious_ips

    def is_malicious_url(self, url: str) -> bool:
        """Check if a URL is in the threat database."""
        with self._lock:
            return url in self._malicious_urls

    def check_ip(self, ip: str) -> dict:
        """Full check on an IP — returns threat info."""
        is_bad = self.is_malicious_ip(ip)
        # Check which feeds flagged this IP
        sources = []
        for feed_name, stats in self._feed_stats.items():
            if stats.get("count", 0) > 0:
                sources.append(feed_name)

        return {
            "ip": ip,
            "malicious": is_bad,
            "risk_score": 90 if is_bad else 0,
            "feeds_checked": len(self._feed_stats),
            "total_known_threats": len(self._malicious_ips),
        }

    # ─── Stats ────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "total_malicious_ips": len(self._malicious_ips),
            "total_malicious_urls": len(self._malicious_urls),
            "total_malicious_hashes": len(self._malicious_hashes),
            "total_cidr_blocks": len(self._cidr_blocks),
            "feeds": self._feed_stats,
            "last_update": self._last_update,
            "update_interval": self._update_interval,
        }

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def stop(self):
        self._running = False
