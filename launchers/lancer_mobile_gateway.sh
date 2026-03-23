#!/bin/bash
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  Mobile Gateway v1.0.0                   ║"
echo "  ║  VPN & DNS Filter for Mobile Devices     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Root required for WireGuard + DNS (port 53)
if [ "$EUID" -ne 0 ]; then
    echo "  [!] Root required for VPN and DNS services."
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
python3 -m pip install pywebview[gtk] psutil requests websockets cryptography qrcode Pillow --quiet 2>/dev/null
echo "  [OK] Dependencies ready."

echo ""
echo "  [*] Starting Mobile Gateway on port 8895..."
echo ""

cd "$(dirname "$0")/../mobile_gateway"
python3 gateway.py &
echo "  [OK] Mobile Gateway started!"
sleep 3
