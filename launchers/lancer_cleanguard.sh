#!/bin/bash
# ============================================
#  CleanGuard Pro — Optimus Suite
#  System Cleaner / Antivirus
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  CleanGuard Pro                          ║"
echo "  ║  System Cleaner / Antivirus              ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 is not installed."
    exit 1
fi

echo "[*] Checking dependencies..."
python3 -m pip install pywebview[gtk] psutil watchdog --quiet 2>/dev/null
echo "[OK] Dependencies ready."

echo "[*] Starting CleanGuard Pro..."
cd "$(dirname "$0")/.."
python3 cleanguard/cleanguard.py
