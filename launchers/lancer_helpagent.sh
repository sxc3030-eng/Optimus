#!/bin/bash
# ============================================
#  Help Agent — Optimus Suite
#  Interactive Guide for All Programs
# ============================================

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  ⚡ OPTIMUS — Cybersecurity Suite        ║"
echo "  ║  Optimus Help Agent                  ║"
echo "  ║  Interactive Guide for All Programs      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 is not installed."
    exit 1
fi

echo "[*] Checking dependencies..."
python3 -m pip install pywebview[gtk] --quiet 2>/dev/null
echo "[OK] Dependencies ready."

echo "[*] Starting Help Agent..."
cd "$(dirname "$0")/.."
python3 help_agent/help_agent.py
