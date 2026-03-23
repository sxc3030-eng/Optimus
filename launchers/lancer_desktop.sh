#!/bin/bash
# ============================================
#  OPTIMUS Desktop Environment v1.0
#  Cybersecurity Command Desktop
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Desktop Environment        ║"
echo "  ║  Cybersecurity Command Desktop v1.0      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# --------------------------------------------------
# Check Python 3
# --------------------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "  [!] Python 3 is not installed."
    echo "      Install:  sudo apt install python3 python3-pip"
    exit 1
fi
echo "  [OK] Python 3 detected: $(python3 --version 2>&1)"

# --------------------------------------------------
# Check / install dependencies
# --------------------------------------------------
echo "  [*] Checking dependencies..."

DEPS="pywebview[gtk] psutil requests websockets"

# Detect GTK backend availability
if python3 -c "import gi" 2>/dev/null; then
    echo "  [OK] GTK backend available."
else
    echo "  [INFO] GTK not found — trying QT backend..."
    DEPS="pywebview[qt] psutil requests websockets"
fi

python3 -m pip install $DEPS --quiet 2>/dev/null
if [ $? -ne 0 ]; then
    echo "  [!] Failed to install some dependencies."
    echo "      Try:  pip3 install pywebview psutil requests websockets"
    echo "      GTK:  sudo apt install python3-gi python3-gi-cairo gir1.2-webkit2-4.0"
    echo "      QT:   pip3 install PyQt5 PyQtWebEngine"
    exit 1
fi
echo "  [OK] Dependencies ready."

# --------------------------------------------------
# Ensure settings directory
# --------------------------------------------------
mkdir -p ~/.optimus
echo "  [OK] Settings directory: ~/.optimus/"

# --------------------------------------------------
# Launch
# --------------------------------------------------
echo ""
echo "  ============================================"
echo "    Starting OPTIMUS Desktop..."
echo "  ============================================"
echo ""
echo "  Programs available on the desktop:"
echo "      NetGuard Pro           :8765"
echo "      SentinelOS / Cortex    :8900"
echo "      CleanGuard Pro         :8810"
echo "      MailShield Pro         :8801"
echo "      VPN Guard Pro          :8820"
echo "      Honeypot               :8830"
echo "      File Integrity Monitor :8840"
echo "      StrikeBack             :8850"
echo "      Recorder               :8860"
echo "      RedTeam Simulator      :8870"
echo "      SIEM / SOAR            :8880"
echo "      Sandbox                :8890"
echo "      Mobile Gateway         :8895"
echo "      Help Agent             :8899"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$SCRIPT_DIR/../optimus_desktop"

if [ ! -f "$DESKTOP_DIR/desktop.py" ]; then
    echo "  [!] desktop.py not found at $DESKTOP_DIR"
    exit 1
fi

cd "$DESKTOP_DIR"
python3 desktop.py "$@"
