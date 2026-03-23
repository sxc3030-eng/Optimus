#!/bin/bash
# ============================================
#  SentinelOS Mapper — Optimus Suite
#  Network Map + Firewall (requires root)
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  SentinelOS Network Mapper + Firewall    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "  [!] Root required for firewall (iptables)."
    echo "  [*] Relaunching with sudo..."
    sudo "$0"
    exit $?
fi
echo "  [OK] Root access confirmed."

if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 is not installed."
    exit 1
fi

echo "[*] Checking dependencies..."
python3 -m pip install pywebview[gtk] psutil requests --quiet 2>/dev/null
echo "[OK] Dependencies ready."

echo "[*] Starting SentinelOS Mapper..."
cd "$(dirname "$0")/.."
python3 sentinel/sentinel_mapper.py
