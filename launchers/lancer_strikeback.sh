#!/bin/bash
# ============================================
#  StrikeBack — Optimus Suite
#  Active Defense System
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  StrikeBack v1.0.0                      ║"
echo "  ║  Active Defense System                   ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Root required for iptables
if [ "$EUID" -ne 0 ]; then
    echo "  [!] Root required for active defense."
    echo "  [*] Relaunching with sudo..."
    sudo "$0"
    exit $?
fi
echo "  [OK] Root access confirmed."

python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  [!] Python3 is not installed."
    exit 1
fi
echo "  [OK] Python3 detected."

echo "  [*] Installing dependencies..."
python3 -m pip install pywebview[gtk] psutil requests websockets --quiet 2>/dev/null
echo "  [OK] Dependencies ready."

echo ""
echo "  [*] Starting StrikeBack on port 8850..."
echo ""

cd "$(dirname "$0")/../strikeback"
python3 strikeback.py &
echo "  [OK] StrikeBack started!"
sleep 3
