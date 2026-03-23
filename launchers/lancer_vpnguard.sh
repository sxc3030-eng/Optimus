#!/bin/bash
# ============================================
#  VPN Guard Pro — Optimus Suite
#  WireGuard VPN Client (requires root)
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  VPN Guard Pro                           ║"
echo "  ║  WireGuard VPN Client                    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Root required for VPN operations."
    echo "[*] Relaunching with sudo..."
    sudo "$0"
    exit $?
fi
echo "[OK] Root access confirmed."

if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 is not installed."
    exit 1
fi

# Check WireGuard
if command -v wg &>/dev/null; then
    echo "[OK] WireGuard detected."
else
    echo "[!] WireGuard not installed."
    echo "[*] Install: sudo apt install wireguard  (Debian/Ubuntu)"
    echo "             sudo dnf install wireguard-tools  (Fedora)"
    echo "             sudo pacman -S wireguard-tools  (Arch)"
fi

echo "[*] Checking dependencies..."
python3 -m pip install pywebview[gtk] psutil requests cryptography --quiet 2>/dev/null
echo "[OK] Dependencies ready."

echo "[*] Starting VPN Guard Pro..."
cd "$(dirname "$0")/.."
python3 vpnguard/vpnguard.py
