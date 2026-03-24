"""
Optimus Suite — Auto-Updater v1.0.0
Checks GitHub Releases for new versions and applies updates.

Flow:
1. Check current version from VERSION file
2. Query GitHub API for latest release
3. Compare semver versions
4. If newer: download .tar.gz/.zip, verify SHA256, backup current, extract, restart

GitHub repo: sxc3030-eng/Optimus
"""

import os
import sys
import json
import shutil
import zipfile
import tarfile
import hashlib
import logging
import threading
import time
import re
import stat
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION_FILE = "VERSION"
GITHUB_REPO = "sxc3030-eng/Optimus"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
BACKUP_DIR = "backups"
UPDATE_DIR = "updates"
LOG_DIR = "logs"

# Files and directories to preserve during updates (never overwritten)
PRESERVE_PATTERNS = [
    "*_settings.json",
    "license.key",
    "LICENSE.key",
]
PRESERVE_DIRS = [
    "logs",
    "backups",
    "updates",
    "__pycache__",
    ".git",
    ".claude",
]

# Directories to exclude from backups
BACKUP_EXCLUDE_DIRS = [
    "backups",
    "updates",
    "logs",
    "__pycache__",
    ".git",
    ".claude",
    "node_modules",
    ".venv",
    "venv",
]

USER_AGENT = "Optimus-Updater/1.0"
CHUNK_SIZE = 8192


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(base_dir: str) -> logging.Logger:
    """Configure updater logging."""
    log_dir = os.path.join(base_dir, LOG_DIR)
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "updater.log")

    logger = logging.getLogger("Optimus.Updater")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

    return logger


# ---------------------------------------------------------------------------
# AutoUpdater
# ---------------------------------------------------------------------------

class AutoUpdater:
    """
    GitHub-based auto-updater for Optimus Suite (Linux).

    States: idle | checking | downloading | installing | complete | error
    """

    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        self.version_file = os.path.join(self.base_dir, VERSION_FILE)
        self.backup_dir = os.path.join(self.base_dir, BACKUP_DIR)
        self.update_dir = os.path.join(self.base_dir, UPDATE_DIR)
        self.current_version = self._read_version()
        self.update_info: dict = None
        self.download_progress: float = 0.0
        self.status: str = "idle"
        self.error: str = None
        self.logger = setup_logging(self.base_dir)

        os.makedirs(self.backup_dir, exist_ok=True)
        os.makedirs(self.update_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Version helpers
    # ------------------------------------------------------------------

    def _read_version(self) -> str:
        """Read current version from VERSION file."""
        try:
            with open(self.version_file, "r", encoding="utf-8") as f:
                ver = f.read().strip()
                if ver:
                    return ver
        except FileNotFoundError:
            pass
        return "1.0.0"

    @staticmethod
    def _parse_semver(version: str) -> tuple:
        """Parse a semver string into (major, minor, patch) integers."""
        version = version.lstrip("vV")
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
        if not match:
            raise ValueError(f"Invalid semver: {version}")
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))

    def _compare_versions(self, current: str, latest: str) -> bool:
        """Return True if latest > current (semver comparison)."""
        try:
            cur = self._parse_semver(current)
            lat = self._parse_semver(latest)
            return lat > cur
        except ValueError as exc:
            self.logger.warning("Version comparison failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # GitHub API
    # ------------------------------------------------------------------

    def _github_request(self, url: str) -> dict:
        """Make a GitHub API request with proper headers."""
        req = urllib.request.Request(url)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "application/vnd.github.v3+json")

        # Optional: use GITHUB_TOKEN env var for higher rate limits
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"token {token}")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RuntimeError("Repository or release not found.") from exc
            if exc.code == 403:
                raise RuntimeError(
                    "GitHub API rate limit exceeded. Set GITHUB_TOKEN env var."
                ) from exc
            raise RuntimeError(f"GitHub API error: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error: {exc.reason}") from exc

    @staticmethod
    def _extract_sha256(body: str) -> str:
        """Try to extract SHA256 hash from release body text."""
        if not body:
            return None
        patterns = [
            r"[Ss][Hh][Aa]256[\s:=]+([a-fA-F0-9]{64})",
            r"`([a-fA-F0-9]{64})`",
        ]
        for pat in patterns:
            m = re.search(pat, body)
            if m:
                return m.group(1).lower()
        return None

    def check_for_updates(self) -> dict:
        """
        Query GitHub API for latest release.

        Returns dict with keys:
            update_available, current_version, latest_version,
            release_name, changelog, download_url, download_size,
            published_at, sha256
        """
        self.status = "checking"
        self.error = None
        self.logger.info("Checking for updates (current: v%s)...", self.current_version)

        try:
            data = self._github_request(GITHUB_API)
        except RuntimeError as exc:
            self.status = "error"
            self.error = str(exc)
            self.logger.error("Update check failed: %s", exc)
            return {
                "update_available": False,
                "current_version": self.current_version,
                "error": str(exc),
            }

        tag = data.get("tag_name", "").lstrip("vV")
        changelog = data.get("body", "") or ""
        release_name = data.get("name", f"v{tag}")
        published = data.get("published_at", "")
        sha256 = self._extract_sha256(changelog)

        # Prefer .tar.gz asset (Linux-native), then .zip, then zipball
        download_url = data.get("zipball_url", "")
        download_size = 0
        for asset in data.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(".tar.gz") or name.endswith(".tgz"):
                download_url = asset["browser_download_url"]
                download_size = asset.get("size", 0)
                break
            elif name.endswith(".zip"):
                download_url = asset["browser_download_url"]
                download_size = asset.get("size", 0)
                # Don't break — keep looking for .tar.gz

        is_newer = self._compare_versions(self.current_version, tag)

        result = {
            "update_available": is_newer,
            "current_version": self.current_version,
            "latest_version": tag,
            "release_name": release_name,
            "changelog": changelog,
            "download_url": download_url,
            "download_size": download_size,
            "published_at": published,
            "sha256": sha256,
        }

        self.update_info = result
        self.status = "idle"

        if is_newer:
            self.logger.info(
                "Update available: v%s -> v%s", self.current_version, tag
            )
        else:
            self.logger.info("Already up to date (v%s).", self.current_version)

        return result

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download_update(self, url: str, expected_sha256: str = None) -> str:
        """
        Download update archive with progress tracking.
        Returns path to downloaded file.
        """
        self.status = "downloading"
        self.download_progress = 0.0
        self.error = None
        self.logger.info("Downloading update from %s", url)

        # Determine extension from URL
        if ".tar.gz" in url or ".tgz" in url:
            ext = ".tar.gz"
        else:
            ext = ".zip"

        filename = f"optimus-update-{int(time.time())}{ext}"
        dest = os.path.join(self.update_dir, filename)

        req = urllib.request.Request(url)
        req.add_header("User-Agent", USER_AGENT)
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"token {token}")

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                sha = hashlib.sha256()

                with open(dest, "wb") as f:
                    while True:
                        chunk = resp.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                        sha.update(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            self.download_progress = round(
                                (downloaded / total) * 100, 1
                            )

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            self.status = "error"
            self.error = f"Download failed: {exc}"
            self.logger.error("Download failed: %s", exc)
            if os.path.exists(dest):
                os.remove(dest)
            raise RuntimeError(self.error) from exc

        # Verify SHA256
        actual_sha = sha.hexdigest()
        if expected_sha256 and actual_sha != expected_sha256.lower():
            self.status = "error"
            self.error = "SHA256 checksum mismatch — download may be corrupted."
            self.logger.error(
                "SHA256 mismatch: expected %s, got %s",
                expected_sha256,
                actual_sha,
            )
            os.remove(dest)
            raise RuntimeError(self.error)

        self.download_progress = 100.0
        self.logger.info(
            "Download complete: %s (%d bytes, SHA256: %s)",
            dest,
            downloaded,
            actual_sha,
        )
        return dest

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    def create_backup(self) -> str:
        """
        Backup current installation before updating.
        Creates timestamped tar.gz in backups/ dir.
        Returns backup path.
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"optimus_v{self.current_version}_{ts}.tar.gz"
        backup_path = os.path.join(self.backup_dir, backup_name)
        self.logger.info("Creating backup: %s", backup_path)

        try:
            with tarfile.open(backup_path, "w:gz") as tf:
                for root, dirs, files in os.walk(self.base_dir):
                    dirs[:] = [
                        d for d in dirs
                        if d not in BACKUP_EXCLUDE_DIRS
                    ]
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        arcname = os.path.relpath(fpath, self.base_dir)
                        try:
                            tf.add(fpath, arcname=arcname)
                        except PermissionError:
                            self.logger.warning(
                                "Skipped (permission denied): %s", fpath
                            )
        except Exception as exc:
            self.logger.error("Backup failed: %s", exc)
            raise RuntimeError(f"Backup failed: {exc}") from exc

        size_mb = os.path.getsize(backup_path) / (1024 * 1024)
        self.logger.info("Backup created: %s (%.1f MB)", backup_path, size_mb)
        return backup_path

    # ------------------------------------------------------------------
    # Install / Apply
    # ------------------------------------------------------------------

    def _should_preserve(self, relpath: str) -> bool:
        """Check if a file should be preserved during update."""
        import fnmatch

        basename = os.path.basename(relpath)
        parts = Path(relpath).parts

        for d in PRESERVE_DIRS:
            if d in parts:
                return True

        for pat in PRESERVE_PATTERNS:
            if fnmatch.fnmatch(basename, pat):
                return True

        return False

    def _extract_archive(self, archive_path: str, dest_dir: str):
        """Extract .zip or .tar.gz archive."""
        if archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                # Security: filter out absolute paths and path traversal
                members = []
                for m in tf.getmembers():
                    if m.name.startswith("/") or ".." in m.name:
                        self.logger.warning("Skipping dangerous path: %s", m.name)
                        continue
                    members.append(m)
                tf.extractall(dest_dir, members=members)
        else:
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest_dir)

    def apply_update(self, archive_path: str) -> bool:
        """
        Extract update archive and replace files.
        Preserves settings, license, logs, and backups.
        """
        self.status = "installing"
        self.error = None
        self.logger.info("Applying update from %s", archive_path)

        temp_dir = os.path.join(self.update_dir, f"_extract_{int(time.time())}")

        try:
            # 1. Extract to temp directory
            os.makedirs(temp_dir, exist_ok=True)
            self._extract_archive(archive_path, temp_dir)

            # GitHub archives have a top-level directory like "repo-tag/"
            entries = os.listdir(temp_dir)
            source_dir = temp_dir
            if len(entries) == 1 and os.path.isdir(
                os.path.join(temp_dir, entries[0])
            ):
                source_dir = os.path.join(temp_dir, entries[0])

            # 2. Walk extracted files and copy to base_dir
            updated = 0
            skipped = 0
            for root, dirs, files in os.walk(source_dir):
                rel_root = os.path.relpath(root, source_dir)
                dest_root = os.path.join(self.base_dir, rel_root)

                dirs[:] = [d for d in dirs if d not in PRESERVE_DIRS]
                os.makedirs(dest_root, exist_ok=True)

                for fname in files:
                    rel_file = os.path.join(rel_root, fname)
                    if rel_file.startswith("."):
                        rel_file = rel_file[2:]

                    if self._should_preserve(rel_file):
                        self.logger.debug("Preserved: %s", rel_file)
                        skipped += 1
                        continue

                    src = os.path.join(root, fname)
                    dst = os.path.join(dest_root, fname)

                    try:
                        shutil.copy2(src, dst)
                        # Preserve executable permissions on Linux
                        src_stat = os.stat(src)
                        if src_stat.st_mode & stat.S_IXUSR:
                            os.chmod(
                                dst,
                                src_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
                            )
                        updated += 1
                    except PermissionError:
                        self.logger.warning(
                            "Could not overwrite (in use?): %s", dst
                        )

            # 3. Update VERSION file from the extracted release
            new_ver_file = os.path.join(source_dir, VERSION_FILE)
            if os.path.exists(new_ver_file):
                shutil.copy2(new_ver_file, self.version_file)
                self.current_version = self._read_version()

            self.logger.info(
                "Update applied: %d files updated, %d preserved.", updated, skipped
            )

        except (zipfile.BadZipFile, tarfile.TarError) as exc:
            self.status = "error"
            self.error = "Corrupt update archive."
            self.logger.error("Bad archive: %s", exc)
            raise RuntimeError(self.error) from exc
        except Exception as exc:
            self.status = "error"
            self.error = f"Install failed: {exc}"
            self.logger.error("Install error: %s", exc)
            raise
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            if os.path.exists(archive_path):
                try:
                    os.remove(archive_path)
                except OSError:
                    pass

        self.status = "complete"
        return True

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self, backup_path: str) -> bool:
        """Restore from backup if update fails."""
        self.logger.info("Rolling back from backup: %s", backup_path)

        if not os.path.exists(backup_path):
            self.logger.error("Backup not found: %s", backup_path)
            return False

        try:
            if backup_path.endswith(".tar.gz") or backup_path.endswith(".tgz"):
                with tarfile.open(backup_path, "r:gz") as tf:
                    for member in tf.getmembers():
                        if self._should_preserve(member.name):
                            continue
                        if member.name.startswith("/") or ".." in member.name:
                            continue
                        dest = os.path.join(self.base_dir, member.name)
                        if member.isdir():
                            os.makedirs(dest, exist_ok=True)
                        else:
                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                            with tf.extractfile(member) as src:
                                if src:
                                    with open(dest, "wb") as dst:
                                        shutil.copyfileobj(src, dst)
            else:
                with zipfile.ZipFile(backup_path, "r") as zf:
                    for member in zf.namelist():
                        if self._should_preserve(member):
                            continue
                        dest = os.path.join(self.base_dir, member)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        if not member.endswith("/"):
                            with zf.open(member) as src, open(dest, "wb") as dst:
                                shutil.copyfileobj(src, dst)

            self.current_version = self._read_version()
            self.logger.info("Rollback complete. Version: v%s", self.current_version)
            self.status = "idle"
            return True

        except Exception as exc:
            self.logger.error("Rollback failed: %s", exc)
            self.status = "error"
            self.error = f"Rollback failed: {exc}"
            return False

    # ------------------------------------------------------------------
    # Full update flow
    # ------------------------------------------------------------------

    def full_update(self) -> dict:
        """
        Complete update flow: check -> download -> backup -> install.
        Returns result dict.
        """
        self.logger.info("=== Starting full update process ===")

        # Step 1: Check
        info = self.check_for_updates()
        if info.get("error"):
            return {"status": "error", "error": info["error"]}
        if not info.get("update_available"):
            return {"status": "up_to_date", "version": self.current_version}

        # Step 2: Download
        try:
            archive_path = self.download_update(
                info["download_url"], info.get("sha256")
            )
        except RuntimeError as exc:
            return {"status": "error", "error": str(exc)}

        # Step 3: Backup
        try:
            backup_path = self.create_backup()
        except RuntimeError as exc:
            return {"status": "error", "error": str(exc)}

        # Step 4: Install
        try:
            self.apply_update(archive_path)
            self.logger.info(
                "=== Update complete: v%s -> v%s ===",
                info["current_version"],
                info["latest_version"],
            )
            return {
                "status": "updated",
                "from_version": info["current_version"],
                "to_version": info["latest_version"],
                "backup": backup_path,
            }
        except Exception as exc:
            self.logger.error("Update failed, rolling back: %s", exc)
            self.rollback(backup_path)
            return {
                "status": "error",
                "error": str(exc),
                "rolled_back": True,
            }

    # ------------------------------------------------------------------
    # State (for UI / js_api)
    # ------------------------------------------------------------------

    def get_state(self) -> dict:
        """For WebSocket / js_api status reporting."""
        return {
            "current_version": self.current_version,
            "status": self.status,
            "download_progress": self.download_progress,
            "update_info": self.update_info,
            "error": self.error,
        }

    def cleanup_old_updates(self, keep_latest: int = 3):
        """Remove old backup and update files, keeping the N most recent."""
        for directory in [self.backup_dir, self.update_dir]:
            try:
                archives = []
                for ext in ("*.zip", "*.tar.gz", "*.tgz"):
                    archives.extend(Path(directory).glob(ext))
                archives.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                for old in archives[keep_latest:]:
                    old.unlink()
                    self.logger.info("Cleaned up: %s", old)
            except Exception as exc:
                self.logger.warning("Cleanup error in %s: %s", directory, exc)


# ---------------------------------------------------------------------------
# UpdaterAPI — pywebview js_api integration for Cortex dashboard
# ---------------------------------------------------------------------------

class UpdaterAPI:
    """
    Exposes updater functions to the Cortex UI via pywebview js_api.

    Usage in Cortex:
        from updater.updater import UpdaterAPI
        updater_api = UpdaterAPI()
    """

    def __init__(self, base_dir: str = None):
        self._updater = AutoUpdater(base_dir=base_dir)
        self._update_thread: threading.Thread = None

    def get_updater_state(self) -> str:
        """Return current updater state as JSON string."""
        return json.dumps(self._updater.get_state())

    def check_for_updates(self) -> str:
        """Check GitHub for updates. Returns JSON result."""
        try:
            result = self._updater.check_for_updates()
            return json.dumps(result)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    def start_update(self) -> str:
        """
        Start full update in background thread.
        Poll get_updater_state() for progress.
        """
        if self._update_thread and self._update_thread.is_alive():
            return json.dumps({"error": "Update already in progress."})

        def _run():
            self._updater.full_update()

        self._update_thread = threading.Thread(target=_run, daemon=True)
        self._update_thread.start()
        return json.dumps({"status": "started"})

    def get_current_version(self) -> str:
        """Return current version string."""
        return self._updater.current_version

    def set_auto_update(self, enabled: bool) -> str:
        """Persist auto-update preference to settings."""
        settings_file = os.path.join(
            self._updater.base_dir, "optimus_settings.json"
        )
        settings = {}
        if os.path.exists(settings_file):
            try:
                with open(settings_file, "r", encoding="utf-8") as f:
                    settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        settings["auto_update"] = enabled
        try:
            with open(settings_file, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
            return json.dumps({"status": "ok", "auto_update": enabled})
        except OSError as exc:
            return json.dumps({"error": str(exc)})

    def get_auto_update(self) -> str:
        """Read auto-update preference."""
        settings_file = os.path.join(
            self._updater.base_dir, "optimus_settings.json"
        )
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                settings = json.load(f)
            return json.dumps({"auto_update": settings.get("auto_update", True)})
        except (FileNotFoundError, json.JSONDecodeError):
            return json.dumps({"auto_update": True})

    def skip_version(self, version: str) -> str:
        """Mark a version as skipped."""
        settings_file = os.path.join(
            self._updater.base_dir, "optimus_settings.json"
        )
        settings = {}
        if os.path.exists(settings_file):
            try:
                with open(settings_file, "r", encoding="utf-8") as f:
                    settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        skipped = settings.get("skipped_versions", [])
        if version not in skipped:
            skipped.append(version)
        settings["skipped_versions"] = skipped

        try:
            with open(settings_file, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
            return json.dumps({"status": "ok", "skipped": version})
        except OSError as exc:
            return json.dumps({"error": str(exc)})

    def cleanup(self) -> str:
        """Remove old backup/update archives."""
        try:
            self._updater.cleanup_old_updates()
            return json.dumps({"status": "ok"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main():
    """Command-line interface for the updater."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Optimus Auto-Updater",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python updater.py --check          Check for available updates
  python updater.py --update         Download and install latest update
  python updater.py --version        Show current version
  python updater.py --rollback FILE  Restore from a backup archive
  python updater.py --cleanup        Remove old update/backup files
        """,
    )
    parser.add_argument(
        "--check", action="store_true", help="Check for updates"
    )
    parser.add_argument(
        "--update", action="store_true", help="Download and install update"
    )
    parser.add_argument(
        "--version", action="store_true", help="Show current version"
    )
    parser.add_argument(
        "--rollback", metavar="BACKUP_FILE", help="Rollback from backup archive"
    )
    parser.add_argument(
        "--cleanup", action="store_true", help="Clean old update files"
    )

    args = parser.parse_args()
    updater = AutoUpdater()

    if args.version:
        print(f"Optimus v{updater.current_version}")
        return

    if args.check:
        info = updater.check_for_updates()
        if info.get("update_available"):
            print(f"\n  Update available: v{info['latest_version']}")
            print(f"  Release: {info['release_name']}")
            if info.get("changelog"):
                print(f"\n  Changelog:\n  {info['changelog'][:500]}")
            print(f"\n  Run with --update to install.")
        else:
            print(f"  Up to date (v{updater.current_version}).")
            if info.get("error"):
                print(f"  Error: {info['error']}")
        return

    if args.update:
        result = updater.full_update()
        if result["status"] == "updated":
            print(
                f"\n  Updated: v{result['from_version']} -> v{result['to_version']}"
            )
            print(f"  Backup: {result['backup']}")
            print("  Restart the application to use the new version.")
        elif result["status"] == "up_to_date":
            print(f"  Already up to date (v{result['version']}).")
        else:
            print(f"  Update failed: {result.get('error', 'Unknown error')}")
            if result.get("rolled_back"):
                print("  Rolled back to previous version.")
        return

    if args.rollback:
        if updater.rollback(args.rollback):
            print(f"  Rollback complete. Version: v{updater.current_version}")
        else:
            print("  Rollback failed. Check logs for details.")
        return

    if args.cleanup:
        updater.cleanup_old_updates()
        print("  Cleanup complete.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
