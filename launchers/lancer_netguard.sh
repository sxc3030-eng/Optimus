#!/bin/bash
# ============================================
#  NetGuard Pro — Optimus Suite
#  Network IDS / Packet Capture / Firewall
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  NetGuard Pro v4.0                       ║"
echo "  ║  Network IDS / Packet Capture / Firewall ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 is not installed."
    echo "    Install: sudo apt install python3 python3-pip"
    exit 1
fi
echo "[OK] Python 3 detected: $(python3 --version)"

# Install dependencies
echo "[*] Checking dependencies..."
python3 -m pip install pywebview[gtk] scapy requests psutil --quiet 2>/dev/null
echo "[OK] Dependencies ready."

# Launch
echo "[*] Starting NetGuard Pro..."
cd "$(dirname "$0")/.."
python3 netguard.py
