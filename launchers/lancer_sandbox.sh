#!/bin/bash
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  Sandbox v1.0.0                          ║"
echo "  ║  Automated File Analysis                 ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  [!] Python3 is not installed."
    exit 1
fi
echo "  [OK] Python3 detected."

echo "  [*] Installing dependencies..."
python3 -m pip install pywebview[gtk] psutil requests websockets yara-python --quiet 2>/dev/null
echo "  [OK] Dependencies ready."

echo ""
echo "  [*] Starting Sandbox on port 8890..."
echo ""

cd "$(dirname "$0")/../sandbox"
python3 sandbox.py &
echo "  [OK] Sandbox started!"
sleep 3
