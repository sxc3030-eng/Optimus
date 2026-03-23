#!/bin/bash
# ═══════════════════════════════════════════════════════
#  Optimus Suite — Linux Quick Install Script
# ═══════════════════════════════════════════════════════
#
# Usage:
#   chmod +x install.sh && ./install.sh
#
# This installs system dependencies and pip packages.
# For selective installation, use the GUI installer:
#   python3 installer/netguardpro_installer.py

set -e

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   Optimus Suite v3.0 — Linux Setup    ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# ── Detect distro ─────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi
echo "[*] Detected distro: $DISTRO"

# ── Install system dependencies ───────────────────────
echo ""
echo "[*] Installing system dependencies..."

case $DISTRO in
    ubuntu|debian|linuxmint|pop)
        sudo apt update -qq
        sudo apt install -y python3 python3-pip python3-venv \
            python3-gi gir1.2-webkit2-4.1 gir1.2-appindicator3-0.1 \
            libnotify-bin wireguard-tools tcpdump
        ;;
    fedora|rhel|centos)
        sudo dnf install -y python3 python3-pip \
            python3-gobject webkit2gtk4.1 libappindicator-gtk3 \
            libnotify wireguard-tools tcpdump
        ;;
    arch|manjaro|endeavouros)
        sudo pacman -Sy --noconfirm python python-pip \
            python-gobject webkit2gtk-4.1 libappindicator-gtk3 \
            libnotify wireguard-tools tcpdump
        ;;
    opensuse*|suse*)
        sudo zypper install -y python3 python3-pip \
            python3-gobject typelib-1_0-WebKit2-4_1 \
            libnotify wireguard-tools tcpdump
        ;;
    *)
        echo "[!] Unknown distro: $DISTRO"
        echo "    Please install manually: python3, pip, GTK WebKit2, libnotify, wireguard-tools"
        ;;
esac

echo "[OK] System dependencies installed."

# ── Install pip packages ──────────────────────────────
echo ""
echo "[*] Installing Python packages..."
python3 -m pip install --upgrade pip 2>/dev/null
python3 -m pip install -r requirements.txt 2>/dev/null
echo "[OK] Python packages installed."

# ── Make launchers executable ─────────────────────────
echo ""
echo "[*] Making launchers executable..."
chmod +x launchers/*.sh 2>/dev/null
chmod +x install.sh 2>/dev/null
echo "[OK] Launchers ready."

# ── Summary ───────────────────────────────────────────
echo ""
echo "  ============================================"
echo "    Installation Complete!"
echo "  ============================================"
echo ""
echo "  Launch individual programs:"
echo "    ./launchers/lancer_netguard.sh"
echo "    ./launchers/lancer_cleanguard.sh"
echo "    ./launchers/lancer_mailshield.sh"
echo "    ./launchers/lancer_vpnguard.sh"
echo "    ./launchers/lancer_sentinel_mapper.sh"
echo "    ./launchers/lancer_helpagent.sh"
echo ""
echo "  Launch all via Cortex:"
echo "    sudo ./launchers/lancer_sentinel.sh"
echo ""
echo "  GUI Installer (selective):"
echo "    python3 installer/netguardpro_installer.py"
echo ""
