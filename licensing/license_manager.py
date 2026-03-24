#!/usr/bin/env python3
"""
Optimus Cybersecurity Defense Suite — License Manager
======================================================
Handles license key generation, validation, activation, and tier enforcement.

License key format: OPTMS-TXXXX-XXXXX-XXXXX-XXXXX
  - T = Tier prefix (C=Community, P=Pro, E=EarlyBird, X=Enterprise)
  - X = Base32-encoded HMAC signature segments

Usage (CLI):
    python license_manager.py --generate --tier earlybird --email user@example.com
    python license_manager.py --validate --key OPTMS-EABCD-EFGHI-JKLMN-OPQRS
    python license_manager.py --info
    python license_manager.py --activate --key OPTMS-EABCD-EFGHI-JKLMN-OPQRS

Copyright (c) 2026 sxc3030-eng. All rights reserved.
"""

import os
import sys
import json
import hmac
import hashlib
import base64
import string
import time
import argparse
import platform
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

# HMAC secret — in production, store this server-side only.
# This is used for key generation (admin) and validation (client).
_HMAC_SECRET = b"Optimus-2026-S3cur3-K3y-S1gn1ng-S3cr3t"

# Key prefix
_KEY_PREFIX = "OPTMS"

# Tier code mapping
_TIER_CODES = {
    "community":  "C",
    "pro":        "P",
    "earlybird":  "E",
    "enterprise": "X",
}
_CODE_TO_TIER = {v: k for k, v in _TIER_CODES.items()}

# Base32 alphabet (RFC 4648, no padding)
_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Suite root — two levels up from licensing/
_SUITE_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
#  License Tier Definitions
# ---------------------------------------------------------------------------

TIERS = {
    "community": {
        "name": "Community",
        "price": "Free",
        "programs": [
            "netguard", "cleanguard", "mailshield", "vpnguard", "fim",
        ],
        "max_devices": 1,
        "commercial": False,
        "lifetime": False,
        "duration_days": 0,  # no expiry for free tier
    },
    "pro": {
        "name": "Pro",
        "price": "$29/year",
        "programs": "__all__",
        "max_devices": 5,
        "commercial": True,
        "lifetime": False,
        "duration_days": 365,
    },
    "earlybird": {
        "name": "Early Bird",
        "price": "$14.99 — Lifetime",
        "programs": "__all__",
        "max_devices": 10,
        "commercial": True,
        "lifetime": True,
        "duration_days": 0,  # lifetime
    },
    "enterprise": {
        "name": "Enterprise",
        "price": "$99/year",
        "programs": "__all__",
        "max_devices": -1,  # unlimited
        "commercial": True,
        "lifetime": False,
        "duration_days": 365,
    },
}

# All programs in the suite
ALL_PROGRAMS = [
    "netguard", "cleanguard", "mailshield", "vpnguard", "fim",
    "sentinel", "honeypot", "recorder", "strikeback", "helpagent",
    "installer", "dashboard", "mapper", "tray",
]


# ---------------------------------------------------------------------------
#  Utility helpers
# ---------------------------------------------------------------------------

def _get_machine_id() -> str:
    """Generate a stable machine identifier for device tracking."""
    raw = ""
    try:
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line and line.upper() != "UUID":
                    raw = line
                    break
        else:
            # Linux / macOS — read machine-id
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                if os.path.isfile(path):
                    with open(path) as f:
                        raw = f.read().strip()
                    break
    except Exception:
        pass

    if not raw:
        raw = str(uuid.getnode())  # fallback to MAC-based id

    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _hmac_sign(data: str) -> bytes:
    """Compute HMAC-SHA256 over the given data string."""
    return hmac.new(_HMAC_SECRET, data.encode("utf-8"), hashlib.sha256).digest()


def _b32_encode_segment(data: bytes, length: int = 5) -> str:
    """Encode bytes to a base32 string of fixed length."""
    encoded = base64.b32encode(data).decode("ascii").rstrip("=")
    # Pad or truncate to requested length
    return (encoded + "A" * length)[:length]


def _format_key(tier_code: str, segments: list) -> str:
    """Format segments into the OPTMS-TXXXX-XXXXX-XXXXX-XXXXX pattern."""
    parts = [f"{_KEY_PREFIX}"]
    parts.append(f"{tier_code}{segments[0]}")
    parts.extend(segments[1:])
    return "-".join(parts)


def _parse_key(key: str) -> Optional[dict]:
    """
    Parse a license key string into components.

    Returns dict with 'tier_code', 'segments', 'raw_payload' or None if invalid.
    """
    key = key.strip().upper()
    parts = key.split("-")

    if len(parts) != 5:
        return None
    if parts[0] != _KEY_PREFIX:
        return None
    if len(parts[1]) < 5:
        return None

    tier_code = parts[1][0]
    if tier_code not in _CODE_TO_TIER:
        return None

    segment0 = parts[1][1:]  # first segment minus the tier code
    segments = [segment0, parts[2], parts[3], parts[4]]

    return {
        "tier_code": tier_code,
        "tier": _CODE_TO_TIER[tier_code],
        "segments": segments,
        "raw": key,
    }


# ---------------------------------------------------------------------------
#  License Manager Class
# ---------------------------------------------------------------------------

class LicenseManager:
    """
    License validation and management for Optimus Cybersecurity Defense Suite.

    License key format: OPTMS-TXXXX-XXXXX-XXXXX-XXXXX
      T = Tier code (C/P/E/X)

    Stores activation data in <suite_root>/license.key as JSON.
    """

    LICENSE_FILE = "license.key"
    SUITE_NAME = "Optimus"

    def __init__(self, suite_root: Optional[Path] = None):
        self.suite_root = Path(suite_root) if suite_root else _SUITE_ROOT
        self.license_path = self.suite_root / self.LICENSE_FILE
        self._license_data = None
        self._load()

    # ------------------------------------------------------------------
    #  Internal persistence
    # ------------------------------------------------------------------

    def _load(self):
        """Load license data from disk."""
        self._license_data = None
        if self.license_path.is_file():
            try:
                with open(self.license_path, "r", encoding="utf-8") as f:
                    self._license_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._license_data = None

    def _save(self, data: dict):
        """Save license data to disk."""
        self.license_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self._license_data = data

    # ------------------------------------------------------------------
    #  Key generation (admin / server-side)
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key(tier: str, email: str) -> str:
        """
        Generate a license key for the given tier and email.

        The key encodes:
          - Tier code
          - Email hash (for binding)
          - Timestamp
          - HMAC signature (tamper protection)

        Args:
            tier:  One of 'community', 'pro', 'earlybird', 'enterprise'
            email: Licensee email address

        Returns:
            Formatted license key string
        """
        tier = tier.lower().strip()
        if tier not in _TIER_CODES:
            raise ValueError(
                f"Invalid tier '{tier}'. Must be one of: "
                f"{', '.join(_TIER_CODES.keys())}"
            )

        email = email.strip().lower()
        if not email or "@" not in email:
            raise ValueError("A valid email address is required.")

        tier_code = _TIER_CODES[tier]

        # Build the payload to sign
        timestamp = int(time.time())
        email_hash = hashlib.sha256(email.encode()).hexdigest()[:8]
        payload = f"{tier_code}:{email_hash}:{timestamp}"

        # HMAC signature
        signature = _hmac_sign(payload)

        # Split signature into segments for the key
        seg0 = _b32_encode_segment(signature[0:4], 4)   # 4 chars (tier prefix uses 1)
        seg1 = _b32_encode_segment(signature[4:8], 5)
        seg2 = _b32_encode_segment(signature[8:12], 5)
        seg3 = _b32_encode_segment(signature[12:16], 5)

        key = _format_key(tier_code, [seg0, seg1, seg2, seg3])
        return key

    # ------------------------------------------------------------------
    #  Key validation
    # ------------------------------------------------------------------

    def validate_key(self, key: str) -> dict:
        """
        Validate a license key format and structure.

        Args:
            key: License key string (OPTMS-XXXXX-XXXXX-XXXXX-XXXXX)

        Returns:
            dict with keys:
                'valid'   (bool)  — whether the key is structurally valid
                'tier'    (str)   — tier name if valid
                'tier_info' (dict) — full tier definition if valid
                'error'   (str)   — error message if invalid
        """
        parsed = _parse_key(key)
        if parsed is None:
            return {
                "valid": False,
                "tier": None,
                "tier_info": None,
                "error": "Invalid key format. Expected: OPTMS-XXXXX-XXXXX-XXXXX-XXXXX",
            }

        tier_name = parsed["tier"]

        # Validate each segment contains only Base32 characters
        valid_chars = set(_B32_ALPHABET)
        for seg in parsed["segments"]:
            if not all(c in valid_chars for c in seg):
                return {
                    "valid": False,
                    "tier": None,
                    "tier_info": None,
                    "error": "Key contains invalid characters.",
                }

        tier_info = TIERS.get(tier_name, {})
        return {
            "valid": True,
            "tier": tier_name,
            "tier_info": tier_info,
            "error": None,
        }

    # ------------------------------------------------------------------
    #  Activation
    # ------------------------------------------------------------------

    def activate(self, key: str) -> dict:
        """
        Activate a license key on this machine.

        Args:
            key: License key string

        Returns:
            dict with 'success', 'message', 'license_info'
        """
        validation = self.validate_key(key)
        if not validation["valid"]:
            return {
                "success": False,
                "message": validation["error"],
                "license_info": None,
            }

        tier_name = validation["tier"]
        tier_info = validation["tier_info"]
        machine_id = _get_machine_id()

        # Build activation record
        now = datetime.utcnow()
        expiry = None
        if tier_info.get("duration_days") and tier_info["duration_days"] > 0:
            expiry = (now + timedelta(days=tier_info["duration_days"])).isoformat()

        activation_data = {
            "key": key.strip().upper(),
            "tier": tier_name,
            "tier_name": tier_info["name"],
            "activated_at": now.isoformat(),
            "expires_at": expiry,
            "lifetime": tier_info.get("lifetime", False),
            "machine_id": machine_id,
            "suite": self.SUITE_NAME,
            "version": "1.0.0",
        }

        self._save(activation_data)

        expiry_str = expiry if expiry else "Never (Lifetime)"
        return {
            "success": True,
            "message": (
                f"License activated successfully.\n"
                f"  Tier:    {tier_info['name']}\n"
                f"  Expires: {expiry_str}\n"
                f"  Machine: {machine_id}"
            ),
            "license_info": activation_data,
        }

    # ------------------------------------------------------------------
    #  License info & status
    # ------------------------------------------------------------------

    def get_license_info(self) -> dict:
        """
        Return the current license status.

        Returns:
            dict with 'active', 'tier', 'tier_info', 'expires_at',
            'days_remaining', 'machine_id', 'key'
        """
        if not self._license_data:
            return {
                "active": True,
                "tier": "community",
                "tier_name": "Community",
                "tier_info": TIERS["community"],
                "expires_at": None,
                "days_remaining": None,
                "lifetime": False,
                "machine_id": _get_machine_id(),
                "key": None,
                "message": "No license key activated. Running in Community (Free) mode.",
            }

        data = self._license_data
        tier_name = data.get("tier", "community")
        tier_info = TIERS.get(tier_name, TIERS["community"])

        # Check expiry
        active = True
        days_remaining = None
        message = f"{tier_info['name']} license is active."

        if data.get("lifetime"):
            days_remaining = None
            message = f"{tier_info['name']} license is active (Lifetime)."
        elif data.get("expires_at"):
            try:
                expiry_dt = datetime.fromisoformat(data["expires_at"])
                remaining = expiry_dt - datetime.utcnow()
                days_remaining = max(0, remaining.days)
                if days_remaining <= 0:
                    active = False
                    message = (
                        f"{tier_info['name']} license has EXPIRED. "
                        "Falling back to Community mode."
                    )
                elif days_remaining <= 30:
                    message = (
                        f"{tier_info['name']} license is active. "
                        f"WARNING: Expires in {days_remaining} days."
                    )
            except (ValueError, TypeError):
                pass

        # Machine check
        current_machine = _get_machine_id()
        if data.get("machine_id") and data["machine_id"] != current_machine:
            active = False
            message = "License is bound to a different machine."

        effective_tier = tier_name if active else "community"
        effective_info = TIERS.get(effective_tier, TIERS["community"])

        return {
            "active": active,
            "tier": effective_tier,
            "tier_name": effective_info["name"],
            "tier_info": effective_info,
            "expires_at": data.get("expires_at"),
            "days_remaining": days_remaining,
            "lifetime": data.get("lifetime", False),
            "machine_id": data.get("machine_id"),
            "key": data.get("key"),
            "message": message,
        }

    # ------------------------------------------------------------------
    #  Program access control
    # ------------------------------------------------------------------

    def is_program_allowed(self, program_id: str) -> bool:
        """
        Check whether the current license permits running a program.

        Args:
            program_id: Program identifier (e.g. 'netguard', 'sentinel')

        Returns:
            True if the program is allowed under the active license.
        """
        info = self.get_license_info()
        tier_info = info["tier_info"]
        programs = tier_info.get("programs", [])

        if programs == "__all__":
            return True

        return program_id.lower().strip() in programs

    def get_allowed_programs(self) -> list:
        """Return list of program IDs allowed under the current license."""
        info = self.get_license_info()
        tier_info = info["tier_info"]
        programs = tier_info.get("programs", [])

        if programs == "__all__":
            return ALL_PROGRAMS.copy()

        return list(programs)

    # ------------------------------------------------------------------
    #  Deactivation
    # ------------------------------------------------------------------

    def deactivate(self) -> dict:
        """Remove the current license activation."""
        if self.license_path.is_file():
            os.remove(self.license_path)
            self._license_data = None
            return {"success": True, "message": "License deactivated."}
        return {"success": False, "message": "No active license to deactivate."}


# ---------------------------------------------------------------------------
#  CLI Interface
# ---------------------------------------------------------------------------

def _cli_generate(args):
    """Handle --generate command."""
    key = LicenseManager.generate_key(args.tier, args.email)
    print()
    print("=" * 60)
    print(f"  {LicenseManager.SUITE_NAME} — License Key Generated")
    print("=" * 60)
    print(f"  Tier:    {TIERS[args.tier]['name']}")
    print(f"  Email:   {args.email}")
    print(f"  Key:     {key}")
    print("=" * 60)
    print()


def _cli_validate(args):
    """Handle --validate command."""
    mgr = LicenseManager()
    result = mgr.validate_key(args.key)
    print()
    if result["valid"]:
        print(f"  VALID — Tier: {result['tier_info']['name']}")
    else:
        print(f"  INVALID — {result['error']}")
    print()


def _cli_activate(args):
    """Handle --activate command."""
    mgr = LicenseManager()
    result = mgr.activate(args.key)
    print()
    if result["success"]:
        print("  ACTIVATION SUCCESSFUL")
        print(f"  {result['message']}")
    else:
        print(f"  ACTIVATION FAILED — {result['message']}")
    print()


def _cli_info(args):
    """Handle --info command."""
    mgr = LicenseManager()
    info = mgr.get_license_info()
    print()
    print("=" * 60)
    print(f"  {LicenseManager.SUITE_NAME} — License Status")
    print("=" * 60)
    print(f"  Status:     {'Active' if info['active'] else 'INACTIVE'}")
    print(f"  Tier:       {info['tier_name']}")
    print(f"  Key:        {info['key'] or '(none)'}")
    print(f"  Expires:    {info['expires_at'] or 'N/A'}")
    print(f"  Lifetime:   {'Yes' if info['lifetime'] else 'No'}")
    print(f"  Machine ID: {info['machine_id']}")
    print(f"  Message:    {info['message']}")
    print("=" * 60)

    allowed = mgr.get_allowed_programs()
    print(f"  Programs:   {', '.join(allowed)}")
    print("=" * 60)
    print()


def _cli_deactivate(args):
    """Handle --deactivate command."""
    mgr = LicenseManager()
    result = mgr.deactivate()
    print()
    print(f"  {result['message']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description=f"{LicenseManager.SUITE_NAME} — License Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python license_manager.py --generate --tier earlybird --email user@example.com\n"
            "  python license_manager.py --validate --key OPTMS-EABCD-EFGHI-JKLMN-OPQRS\n"
            "  python license_manager.py --activate --key OPTMS-EABCD-EFGHI-JKLMN-OPQRS\n"
            "  python license_manager.py --info\n"
            "  python license_manager.py --deactivate\n"
        ),
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="Generate a new license key")
    group.add_argument("--validate", action="store_true", help="Validate a license key")
    group.add_argument("--activate", action="store_true", help="Activate a license key")
    group.add_argument("--info", action="store_true", help="Show current license status")
    group.add_argument("--deactivate", action="store_true", help="Remove current license")

    parser.add_argument("--tier", type=str, choices=list(TIERS.keys()),
                        help="License tier (for --generate)")
    parser.add_argument("--email", type=str,
                        help="Licensee email (for --generate)")
    parser.add_argument("--key", type=str,
                        help="License key (for --validate / --activate)")

    args = parser.parse_args()

    if args.generate:
        if not args.tier or not args.email:
            parser.error("--generate requires --tier and --email")
        _cli_generate(args)
    elif args.validate:
        if not args.key:
            parser.error("--validate requires --key")
        _cli_validate(args)
    elif args.activate:
        if not args.key:
            parser.error("--activate requires --key")
        _cli_activate(args)
    elif args.info:
        _cli_info(args)
    elif args.deactivate:
        _cli_deactivate(args)


if __name__ == "__main__":
    main()
