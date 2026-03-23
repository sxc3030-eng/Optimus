#!/bin/bash
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  SIEM/SOAR v1.0.0                        ║"
echo "  ║  Security Information & Event Management  ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

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
echo "  [*] Starting SIEM/SOAR on port 8880..."
echo ""

cd "$(dirname "$0")/../siem"
python3 siem.py &
echo "  [OK] SIEM/SOAR started!"
sleep 3
