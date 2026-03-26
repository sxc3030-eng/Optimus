#!/bin/bash
# ═══════════════════════════════════════════
#  Optimus — Comprehensive Test Suite
# ═══════════════════════════════════════════

echo "================================================================"
echo "  Optimus Suite — Comprehensive Test Suite"
echo "================================================================"
echo ""

cd "$(dirname "$0")/.."

echo "[1/3] Running Python tests..."
python3 tests/test_all.py
if [ $? -ne 0 ]; then
    echo ""
    echo "[FAIL] Python tests failed!"
else
    echo ""
    echo "[PASS] Python tests passed!"
fi

echo ""
echo "[2/3] Checking Python syntax..."
for f in \
    netguard/netguard.py \
    cleanguard/cleanguard.py \
    mailshield/mailshield.py \
    vpnguard/vpnguard.py \
    sentinel/cortex.py \
    sentinel/sentinel.py \
    fim/fim.py \
    honeypot/honeypot.py \
    strikeback/strikeback.py \
    recorder/recorder.py \
    redteam/redteam.py \
    siem/siem.py \
    sandbox/sandbox.py \
    mobile_gateway/gateway.py \
    help_agent/help_agent.py; do
    if [ -f "$f" ]; then
        python3 -c "import py_compile; py_compile.compile('$f', doraise=True)" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "  [OK]   $f"
        else
            echo "  [FAIL] $f"
        fi
    else
        echo "  [MISS] $f"
    fi
done

echo ""
echo "[3/3] Checking HTML dashboards..."
for f in \
    netguard_dashboard.html \
    cleanguard/cleanguard_dashboard.html \
    mailshield/mailshield_dashboard.html \
    vpnguard/vpnguard_dashboard.html \
    sentinel/sentinel_dashboard.html \
    redteam/redteam_dashboard.html \
    siem/siem_dashboard.html \
    sandbox/sandbox_dashboard.html \
    mobile_gateway/gateway_dashboard.html; do
    if [ -f "$f" ]; then
        echo "  [OK]   $f"
    else
        echo "  [MISS] $f"
    fi
done

echo ""
echo "================================================================"
echo "  Test Suite Complete"
echo "================================================================"
