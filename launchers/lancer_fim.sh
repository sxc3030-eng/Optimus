#!/bin/bash
# ============================================
#  FIM — Optimus Suite
#  File Integrity Monitor
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  FIM v1.0.0                              ║"
echo "  ║  File Integrity Monitor                  ║"
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
echo "  [*] Starting FIM on port 8840..."
echo ""

cd "$(dirname "$0")/../fim"
python3 file_integrity_monitor.py &
echo "  [OK] FIM started!"
sleep 3
