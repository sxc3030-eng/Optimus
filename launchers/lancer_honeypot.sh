#!/bin/bash
# ============================================
#  HoneyPot — Optimus Suite
#  Honeypot Trap System
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  HoneyPot v1.0.0                        ║"
echo "  ║  Honeypot Trap System                    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Root required for low ports
if [ "$EUID" -ne 0 ]; then
    echo "  [!] Root required for honeypot services."
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
echo "  [*] Starting HoneyPot on port 8830..."
echo ""

cd "$(dirname "$0")/../honeypot"
python3 honeypot.py &
echo "  [OK] HoneyPot started!"
sleep 3
