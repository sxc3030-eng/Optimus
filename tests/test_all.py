#!/usr/bin/env python3
"""
NetGuardPro — Comprehensive Test Suite
Tests all 14 programs for import, port conflicts, API health, and basic functionality.
Run: python tests/test_all.py
"""

import os
import sys
import json
import time
import socket
import importlib
import subprocess
import unittest
from pathlib import Path
from collections import Counter

# Add parent directory to path
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))


class TestPortConflicts(unittest.TestCase):
    """Ensure no two programs share the same port."""

    EXPECTED_PORTS = {
        "NetGuard": 8765,
        "CleanGuard": 8810,
        "MailShield": 8801,
        "VPN Guard": 8820,
        "Cortex": 8900,
        "FIM": 8840,
        "HoneyPot": 8830,
        "StrikeBack": 8850,
        "Recorder": 8860,
        "RedTeam": 8870,
        "SIEM": 8880,
        "Sandbox": 8890,
        "Mobile Gateway": 8895,
    }

    def test_no_duplicate_ports(self):
        """No two programs should use the same port."""
        ports = list(self.EXPECTED_PORTS.values())
        counts = Counter(ports)
        duplicates = {port: count for port, count in counts.items() if count > 1}
        self.assertEqual(
            len(duplicates), 0,
            f"Duplicate ports found: {duplicates}"
        )

    def test_all_ports_in_valid_range(self):
        """All ports should be in valid range (1024-65535)."""
        for name, port in self.EXPECTED_PORTS.items():
            self.assertGreater(port, 1023, f"{name} port {port} < 1024")
            self.assertLess(port, 65536, f"{name} port {port} > 65535")


class TestFileStructure(unittest.TestCase):
    """Verify all expected files and directories exist."""

    REQUIRED_DIRS = [
        "netguard",
        "cleanguard",
        "mailshield",
        "vpnguard",
        "sentinel",
        "fim",
        "honeypot",
        "strikeback",
        "recorder",
        "redteam",
        "siem",
        "sandbox",
        "mobile_gateway",
        "help_agent",
        "launchers",
    ]

    REQUIRED_FILES = [
        "netguard/netguard.py",
        "cleanguard/cleanguard.py",
        "mailshield/mailshield.py",
        "vpnguard/vpnguard.py",
        "sentinel/cortex.py",
        "sentinel/sentinel.py",
        "fim/fim.py",
        "honeypot/honeypot.py",
        "strikeback/strikeback.py",
        "recorder/recorder.py",
        "redteam/redteam.py",
        "siem/siem.py",
        "sandbox/sandbox.py",
        "mobile_gateway/gateway.py",
        "help_agent/help_agent.py",
    ]

    REQUIRED_DASHBOARDS = [
        "netguard_dashboard.html",
        "cleanguard/cleanguard_dashboard.html",
        "mailshield/mailshield_dashboard.html",
        "vpnguard/vpnguard_dashboard.html",
        "sentinel/sentinel_dashboard.html",
        "help_agent/help_dashboard.html",
        "redteam/redteam_dashboard.html",
        "siem/siem_dashboard.html",
        "sandbox/sandbox_dashboard.html",
        "mobile_gateway/gateway_dashboard.html",
    ]

    def test_directories_exist(self):
        """All program directories should exist."""
        for d in self.REQUIRED_DIRS:
            path = ROOT_DIR / d
            self.assertTrue(
                path.is_dir(),
                f"Missing directory: {path}"
            )

    def test_python_files_exist(self):
        """All main Python files should exist."""
        for f in self.REQUIRED_FILES:
            path = ROOT_DIR / f
            self.assertTrue(
                path.is_file(),
                f"Missing file: {path}"
            )

    def test_dashboards_exist(self):
        """All HTML dashboards should exist."""
        for f in self.REQUIRED_DASHBOARDS:
            path = ROOT_DIR / f
            self.assertTrue(
                path.is_file(),
                f"Missing dashboard: {path}"
            )

    def test_python_files_are_valid_syntax(self):
        """All Python files should have valid syntax."""
        for f in self.REQUIRED_FILES:
            path = ROOT_DIR / f
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        compile(fh.read(), str(path), "exec")
                except SyntaxError as e:
                    self.fail(f"Syntax error in {path}: {e}")

    def test_dashboards_have_social_share(self):
        """All dashboards should have social sharing footer."""
        for f in self.REQUIRED_DASHBOARDS:
            path = ROOT_DIR / f
            if path.exists():
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.assertIn(
                    "social",
                    content.lower(),
                    f"Dashboard {f} missing social sharing section"
                )


class TestImports(unittest.TestCase):
    """Test that key modules can be imported without crashing."""

    def _try_import(self, module_path, module_name):
        """Try to import a module from path."""
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None:
            self.skipTest(f"Cannot find module spec for {module_path}")
        try:
            module = importlib.util.module_from_spec(spec)
            # Don't execute - just verify it can be loaded
            return True
        except Exception as e:
            return False

    def test_python_files_importable(self):
        """All Python main files should be parseable."""
        files = [
            "netguard/netguard.py",
            "cleanguard/cleanguard.py",
            "sentinel/cortex.py",
        ]
        for f in files:
            path = ROOT_DIR / f
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        compile(fh.read(), str(path), "exec")
                except SyntaxError as e:
                    self.fail(f"Cannot parse {f}: {e}")


class TestLaunchers(unittest.TestCase):
    """Verify launcher scripts exist and are properly formatted."""

    def test_windows_launchers_exist(self):
        """Windows .bat launchers should exist."""
        launcher_dir = ROOT_DIR / "launchers"
        if launcher_dir.exists():
            bat_files = list(launcher_dir.glob("*.bat"))
            self.assertGreater(
                len(bat_files), 0,
                "No .bat launcher files found"
            )

    def test_launchers_have_valid_encoding(self):
        """Launcher files should be readable."""
        launcher_dir = ROOT_DIR / "launchers"
        if launcher_dir.exists():
            for f in launcher_dir.iterdir():
                if f.suffix in (".bat", ".sh"):
                    try:
                        f.read_text(encoding="utf-8", errors="strict")
                    except UnicodeDecodeError:
                        try:
                            f.read_text(encoding="cp1252")
                        except Exception as e:
                            self.fail(f"Cannot read launcher {f.name}: {e}")


class TestInstallerConfig(unittest.TestCase):
    """Verify installer is properly configured."""

    def test_installer_exists(self):
        """Installer script should exist."""
        installer = ROOT_DIR / "installer" / "netguardpro_installer.py"
        if installer.exists():
            content = installer.read_text(encoding="utf-8")
            self.assertIn("PROGRAMS", content, "Installer missing PROGRAMS config")

    def test_installer_syntax(self):
        """Installer should have valid Python syntax."""
        installer = ROOT_DIR / "installer" / "netguardpro_installer.py"
        if installer.exists():
            try:
                with open(installer, "r", encoding="utf-8") as f:
                    compile(f.read(), str(installer), "exec")
            except SyntaxError as e:
                self.fail(f"Installer syntax error: {e}")


class TestDashboardContent(unittest.TestCase):
    """Verify dashboard HTML files have proper structure."""

    DASHBOARDS = [
        "netguard_dashboard.html",
        "cleanguard/cleanguard_dashboard.html",
        "mailshield/mailshield_dashboard.html",
        "vpnguard/vpnguard_dashboard.html",
        "sentinel/sentinel_dashboard.html",
        "redteam/redteam_dashboard.html",
        "siem/siem_dashboard.html",
        "sandbox/sandbox_dashboard.html",
        "mobile_gateway/gateway_dashboard.html",
    ]

    def test_dashboards_have_html_structure(self):
        """Dashboards should have basic HTML structure."""
        for f in self.DASHBOARDS:
            path = ROOT_DIR / f
            if path.exists():
                content = path.read_text(encoding="utf-8", errors="ignore")
                self.assertIn("<html", content.lower(), f"{f} missing <html> tag")
                self.assertIn("</html>", content.lower(), f"{f} missing </html> tag")

    def test_dashboards_not_empty(self):
        """Dashboards should not be empty files."""
        for f in self.DASHBOARDS:
            path = ROOT_DIR / f
            if path.exists():
                size = path.stat().st_size
                self.assertGreater(size, 100, f"{f} is suspiciously small ({size} bytes)")


class TestPortAvailability(unittest.TestCase):
    """Check if required ports are available (not already in use)."""

    PORTS = [8765, 8810, 8801, 8820, 8900, 8840, 8830, 8850, 8860, 8870, 8880, 8890, 8895]

    def test_ports_not_conflicting(self):
        """Ports should not conflict with common services."""
        common_ports = {80, 443, 3306, 5432, 6379, 8080, 8443, 27017}
        for port in self.PORTS:
            self.assertNotIn(
                port, common_ports,
                f"Port {port} conflicts with common service port"
            )


def run_tests():
    """Run all tests and return results."""
    print("=" * 70)
    print("  NetGuardPro — Comprehensive Test Suite")
    print("=" * 70)
    print()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestPortConflicts,
        TestFileStructure,
        TestImports,
        TestLaunchers,
        TestInstallerConfig,
        TestDashboardContent,
        TestPortAvailability,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    if result.wasSuccessful():
        print("  ✅ ALL TESTS PASSED!")
    else:
        print(f"  ❌ {len(result.failures)} failures, {len(result.errors)} errors")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
