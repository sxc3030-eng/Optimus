#!/bin/bash
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  RedTeam Simulator v1.0.0                ║"
echo "  ║  Penetration Testing & Defense Validation║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Root required for raw sockets
if [ "$EUID" -ne 0 ]; then
    echo "  [!] Root required for raw socket attacks."
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
python3 -m pip install pywebview[gtk] psutil requests scapy websockets --quiet 2>/dev/null
echo "  [OK] Dependencies ready."

echo ""
echo "  [*] Starting RedTeam Simulator on port 8870..."
echo "  [!] WARNING: This tool attacks your local defenses for testing."
echo ""

cd "$(dirname "$0")/../redteam"
python3 redteam.py &
echo "  [OK] RedTeam Simulator started!"
sleep 3
