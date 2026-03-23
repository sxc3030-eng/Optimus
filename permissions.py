#!/usr/bin/env python3
"""
permissions.py — Optimus Suite Shared Permission System
============================================================
Provides optional role-based access control across all programs.
By default, permissions are DISABLED — all operations are allowed.
When enabled, users must authenticate and have specific permissions.

Permission types per program:
  - read:    View dashboard, see data
  - write:   Create rules, add entries
  - modify:  Change settings, edit configs
  - execute: Run scans, block IPs, start/stop services

Usage in any program:
    from permissions import PermissionManager
    perm = PermissionManager()

    # Check if gate should apply
    if not perm.check("netguard", "execute"):
        return {"error": "Permission denied / Accès refusé"}
"""

import json
import os
import hashlib
import secrets
import time
from typing import Optional

# ─── paths ──────────────────────────────────────────────────────────────
SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SUITE_DIR, "permissions_state.json")

PROGRAMS = [
    "netguard", "cleanguard", "mailshield", "vpnguard",
    "sentinel_mapper", "cortex", "fim", "honeypot",
    "strikeback", "recorder", "help_agent"
]

PERM_TYPES = ["read", "write", "modify", "execute"]

# ─── helpers ────────────────────────────────────────────────────────────

def _hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with salt using SHA-256. Returns (hash, salt)."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return h, salt


def _load_state() -> dict:
    """Load permissions state from disk."""
    if not os.path.exists(STATE_FILE):
        return {"enabled": False, "locked": False, "master_admin": "",
                "master_hash": "", "master_salt": "", "users": {}}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "locked": False, "master_admin": "",
                "master_hash": "", "master_salt": "", "users": {}}


def _save_state(state: dict):
    """Save permissions state to disk."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# ─── PermissionManager ──────────────────────────────────────────────────

class PermissionManager:
    """
    Shared permission manager for all Optimus programs.
    Thread-safe: reloads state from disk on each call.
    """

    def __init__(self):
        self._state_file = STATE_FILE

    def _state(self) -> dict:
        return _load_state()

    # ── Status ───────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        """Check if permission system is active."""
        return self._state().get("enabled", False)

    def is_locked(self) -> bool:
        """Check if permissions are locked (require auth for changes)."""
        s = self._state()
        return s.get("enabled", False) and s.get("locked", False)

    def get_status(self) -> dict:
        """Return full permission status (safe for API)."""
        s = self._state()
        return {
            "enabled": s.get("enabled", False),
            "locked": s.get("locked", False),
            "master_admin": s.get("master_admin", ""),
            "user_count": len(s.get("users", {})),
            "users": list(s.get("users", {}).keys())
        }

    # ── Enable / Disable ─────────────────────────────────────────────

    def enable(self, master_user: str, master_password: str) -> dict:
        """
        Enable the permission system with a master admin account.
        Returns: {"ok": True} or {"error": "..."}
        """
        s = self._state()
        if s.get("enabled"):
            return {"error": "Permissions already enabled / Permissions déjà activées"}
        if not master_user or not master_password:
            return {"error": "Username and password required / Nom d'utilisateur et mot de passe requis"}
        if len(master_password) < 4:
            return {"error": "Password too short (min 4) / Mot de passe trop court (min 4)"}

        h, salt = _hash_password(master_password)
        s["enabled"] = True
        s["locked"] = False
        s["master_admin"] = master_user
        s["master_hash"] = h
        s["master_salt"] = salt
        # Master gets all permissions on all programs
        s["users"] = {
            master_user: {
                "hash": h,
                "salt": salt,
                "role": "admin",
                "permissions": {prog: list(PERM_TYPES) for prog in PROGRAMS},
                "created": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        _save_state(s)
        return {"ok": True, "message": f"Permissions enabled. Master admin: {master_user}"}

    def disable(self, master_password: str) -> dict:
        """Disable the permission system entirely."""
        s = self._state()
        if not s.get("enabled"):
            return {"error": "Permissions not enabled / Permissions non activées"}
        # Verify master password
        h, _ = _hash_password(master_password, s.get("master_salt", ""))
        if h != s.get("master_hash", ""):
            return {"error": "Invalid master password / Mot de passe maître invalide"}
        s["enabled"] = False
        s["locked"] = False
        _save_state(s)
        return {"ok": True, "message": "Permissions disabled / Permissions désactivées"}

    # ── Lock / Unlock ────────────────────────────────────────────────

    def lock(self, master_password: str) -> dict:
        """Lock permissions (require auth for all operations)."""
        s = self._state()
        if not s.get("enabled"):
            return {"error": "Permissions not enabled"}
        h, _ = _hash_password(master_password, s.get("master_salt", ""))
        if h != s.get("master_hash", ""):
            return {"error": "Invalid master password / Mot de passe maître invalide"}
        s["locked"] = True
        _save_state(s)
        return {"ok": True, "message": "Permissions locked / Permissions verrouillées"}

    def unlock(self, master_password: str) -> dict:
        """Unlock permissions (allow all operations without auth)."""
        s = self._state()
        if not s.get("enabled"):
            return {"error": "Permissions not enabled"}
        h, _ = _hash_password(master_password, s.get("master_salt", ""))
        if h != s.get("master_hash", ""):
            return {"error": "Invalid master password / Mot de passe maître invalide"}
        s["locked"] = False
        _save_state(s)
        return {"ok": True, "message": "Permissions unlocked / Permissions déverrouillées"}

    # ── Authentication ───────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> dict:
        """
        Authenticate user. Returns user info with permissions or error.
        """
        s = self._state()
        if not s.get("enabled"):
            return {"ok": True, "role": "admin", "message": "Permissions not enabled — full access"}
        users = s.get("users", {})
        if username not in users:
            return {"error": "User not found / Utilisateur non trouvé"}
        user = users[username]
        h, _ = _hash_password(password, user.get("salt", ""))
        if h != user.get("hash", ""):
            return {"error": "Invalid password / Mot de passe invalide"}
        return {
            "ok": True,
            "username": username,
            "role": user.get("role", "user"),
            "permissions": user.get("permissions", {})
        }

    # ── Permission Check (main gate) ────────────────────────────────

    def check(self, program: str, perm_type: str, username: str = None) -> bool:
        """
        Check if an operation is allowed.
        - If permissions not enabled → always True
        - If enabled but not locked → always True
        - If locked and no username → False
        - If locked and username provided → check user's permissions
        """
        s = self._state()
        if not s.get("enabled", False):
            return True
        if not s.get("locked", False):
            return True
        if not username:
            return False
        users = s.get("users", {})
        if username not in users:
            return False
        user_perms = users[username].get("permissions", {})
        prog_perms = user_perms.get(program, [])
        return perm_type in prog_perms

    # ── User Management ──────────────────────────────────────────────

    def create_user(self, admin_password: str, username: str, password: str,
                    permissions: dict = None, role: str = "user") -> dict:
        """
        Create a new user. Only master admin can create users.
        permissions: {"netguard": ["read", "execute"], "sentinel_mapper": ["read"]}
        """
        s = self._state()
        if not s.get("enabled"):
            return {"error": "Permissions not enabled"}
        h, _ = _hash_password(admin_password, s.get("master_salt", ""))
        if h != s.get("master_hash", ""):
            return {"error": "Invalid admin password / Mot de passe admin invalide"}
        if not username or not password:
            return {"error": "Username and password required"}
        if username in s.get("users", {}):
            return {"error": f"User '{username}' already exists / L'utilisateur existe déjà"}

        uh, usalt = _hash_password(password)
        if permissions is None:
            permissions = {prog: ["read"] for prog in PROGRAMS}

        s["users"][username] = {
            "hash": uh,
            "salt": usalt,
            "role": role,
            "permissions": permissions,
            "created": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        _save_state(s)
        return {"ok": True, "message": f"User '{username}' created / Utilisateur créé"}

    def delete_user(self, admin_password: str, username: str) -> dict:
        """Delete a user. Cannot delete master admin."""
        s = self._state()
        if not s.get("enabled"):
            return {"error": "Permissions not enabled"}
        h, _ = _hash_password(admin_password, s.get("master_salt", ""))
        if h != s.get("master_hash", ""):
            return {"error": "Invalid admin password"}
        if username == s.get("master_admin"):
            return {"error": "Cannot delete master admin / Impossible de supprimer l'admin maître"}
        if username not in s.get("users", {}):
            return {"error": f"User '{username}' not found"}
        del s["users"][username]
        _save_state(s)
        return {"ok": True, "message": f"User '{username}' deleted / Utilisateur supprimé"}

    def set_user_permissions(self, admin_password: str, username: str,
                             program: str, perms: list) -> dict:
        """Set permissions for a user on a specific program."""
        s = self._state()
        if not s.get("enabled"):
            return {"error": "Permissions not enabled"}
        h, _ = _hash_password(admin_password, s.get("master_salt", ""))
        if h != s.get("master_hash", ""):
            return {"error": "Invalid admin password"}
        if username not in s.get("users", {}):
            return {"error": f"User '{username}' not found"}
        # Validate perm types
        for p in perms:
            if p not in PERM_TYPES:
                return {"error": f"Invalid permission type: {p}"}
        s["users"][username]["permissions"][program] = perms
        _save_state(s)
        return {"ok": True, "message": f"Permissions updated for {username} on {program}"}

    def get_all_permissions(self) -> dict:
        """Return all users and their permissions (no hashes)."""
        s = self._state()
        result = {}
        for uname, udata in s.get("users", {}).items():
            result[uname] = {
                "role": udata.get("role", "user"),
                "permissions": udata.get("permissions", {}),
                "created": udata.get("created", "")
            }
        return result
