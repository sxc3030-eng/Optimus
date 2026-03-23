#!/bin/bash
# ============================================
#  MailShield Pro — Optimus Suite
#  Secure Email Client
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  MailShield Pro                          ║"
echo "  ║  Secure Email Client                     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 is not installed."
    exit 1
fi

echo "[*] Checking dependencies..."
python3 -m pip install pywebview[gtk] requests cryptography dnspython bleach --quiet 2>/dev/null
echo "[OK] Dependencies ready."

echo "[*] Starting MailShield Pro..."
cd "$(dirname "$0")/.."
python3 mailshield/mailshield.py
