#!/bin/bash
# ============================================
#  Recorder — Optimus Suite
#  Forensic Recorder
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  Recorder v1.0.0                        ║"
echo "  ║  Forensic Recorder                       ║"
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
echo "  [*] Starting Recorder on port 8860..."
echo ""

cd "$(dirname "$0")/../recorder"
python3 recorder.py &
echo "  [OK] Recorder started!"
sleep 3
