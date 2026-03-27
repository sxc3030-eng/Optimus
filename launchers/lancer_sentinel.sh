#!/bin/bash
# ============================================
#  SentinelOS — Optimus Suite
#  Cybersecurity Command Center (requires root)
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  SentinelOS v2.0                         ║"
echo "  ║  Cybersecurity Command Center            ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "  [!] Root required for firewall and scanning."
    echo "  [*] Relaunching with sudo..."
    sudo "$0"
    exit $?
fi
echo "  [OK] Root access confirmed."

if ! command -v python3 &>/dev/null; then
    echo "  [!] Python 3 is not installed."
    exit 1
fi
echo "  [OK] Python 3 detected."

# Check WireGuard
if command -v wg &>/dev/null; then
    echo "  [OK] WireGuard detected."
else
    echo "  [INFO] WireGuard not installed — VPN features limited."
fi

echo ""
echo "  [*] Installing Python dependencies..."
python3 -m pip install pywebview[gtk] psutil requests scapy websockets aiohttp cryptography pystray Pillow --quiet 2>/dev/null
echo "  [OK] Dependencies ready."

echo ""
echo "  ============================================"
echo "    Starting SentinelOS Cortex..."
echo "  ============================================"
echo ""
echo "  [*] Cortex will start all agents:"
echo "      - NetGuard Pro           (port 8765)"
echo "      - CleanGuard Pro         (port 8810)"
echo "      - MailShield Pro         (port 8801)"
echo "      - VPN Guard Pro          (port 8820)"
echo "      - Honeypot               (port 8830)"
echo "      - File Integrity Monitor (port 8840)"
echo "      - StrikeBack             (port 8850)"
echo "      - Recorder               (port 8860)"
echo ""
echo "  [*] Cortex dashboard on port 8900"
echo ""

cd "$(dirname "$0")/../sentinel"
python3 cortex.py
echo "  [OK] SentinelOS Cortex exited."
