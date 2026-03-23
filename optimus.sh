#!/bin/bash
# ============================================================================
#  OPTIMUS — Master Launcher for the Cybersecurity Defense Suite
#  Version : 1.0.0
#  Platform: Linux
# ============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHERS="$SCRIPT_DIR/launchers"

# ── ANSI Colors ─────────────────────────────────────────────────────────────
R='\033[0;31m'   G='\033[0;32m'   C='\033[0;36m'   Y='\033[1;33m'
B='\033[1;34m'   M='\033[0;35m'   W='\033[1;37m'   D='\033[0;90m'
BOLD='\033[1m'   RST='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────────────────
ok()   { echo -e "  ${G}[OK]${RST}  $1"; }
warn() { echo -e "  ${Y}[!!]${RST}  $1"; }
err()  { echo -e "  ${R}[ERR]${RST} $1"; }
line() { echo -e "${D}  $(printf '─%.0s' {1..52})${RST}"; }

banner() {
    clear
    echo -e "${C}"
    cat << 'ART'

       ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗
      ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝
      ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗
      ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║
      ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║
       ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝
ART
    echo -e "${W}${BOLD}          Cybersecurity Defense Suite v1.0.0${RST}"
    echo -e "${D}          ── Protect. Detect. Respond. ──${RST}"
    echo ""
}

# ── Pre-flight checks ──────────────────────────────────────────────────────
preflight() {
    line
    # Root check
    if [ "$(id -u)" -eq 0 ]; then
        ok "Running as root"
    else
        warn "Not running as root — some tools may need ${W}sudo${RST}"
    fi

    # Python3 check
    if command -v python3 &>/dev/null; then
        local pyver
        pyver=$(python3 --version 2>&1)
        ok "Python3 found  ($pyver)"
    else
        err "Python3 not found — install it before using Python-based tools"
    fi
    line
    echo ""
}

# ── Launch a single program ────────────────────────────────────────────────
launch() {
    local script="$LAUNCHERS/$1"
    if [ -f "$script" ]; then
        echo -e "\n  ${G}>>>  Launching ${W}${BOLD}$2${RST}${G} ...${RST}\n"
        bash "$script"
    else
        err "Launcher not found: $script"
    fi
}

# ── Menu ────────────────────────────────────────────────────────────────────
show_menu() {
    echo -e "  ${C}╔══════════════════════════════════════════════════╗${RST}"
    echo -e "  ${C}║${W}  1.  NetGuard Pro      ${D}— Firewall & IDS          ${C}║${RST}"
    echo -e "  ${C}║${W}  2.  CleanGuard Pro    ${D}— Antivirus & Cleaner     ${C}║${RST}"
    echo -e "  ${C}║${W}  3.  MailShield Pro    ${D}— Email Protection        ${C}║${RST}"
    echo -e "  ${C}║${W}  4.  VPN Guard Pro     ${D}— VPN Manager             ${C}║${RST}"
    echo -e "  ${C}║${W}  5.  SentinelOS Mapper ${D}— Network Mapper          ${C}║${RST}"
    echo -e "  ${C}║${W}  6.  SentinelOS Cortex ${D}— Command Center          ${C}║${RST}"
    echo -e "  ${C}║${W}  7.  FIM               ${D}— File Integrity          ${C}║${RST}"
    echo -e "  ${C}║${W}  8.  HoneyPot          ${D}— Honeypot Traps          ${C}║${RST}"
    echo -e "  ${C}║${W}  9.  StrikeBack        ${D}— Active Defense          ${C}║${RST}"
    echo -e "  ${C}║${W} 10.  Recorder          ${D}— Forensic Recorder       ${C}║${RST}"
    echo -e "  ${C}║${W} 11.  RedTeam Simulator ${D}— Attack Testing          ${C}║${RST}"
    echo -e "  ${C}║${W} 12.  SIEM/SOAR         ${D}— Security Brain          ${C}║${RST}"
    echo -e "  ${C}║${W} 13.  Sandbox           ${D}— File Analysis           ${C}║${RST}"
    echo -e "  ${C}║${W} 14.  Mobile Gateway    ${D}— Mobile VPN+DNS          ${C}║${RST}"
    echo -e "  ${C}║                                                  ║${RST}"
    echo -e "  ${C}║${G}  A.  Launch ALL programs                         ${C}║${RST}"
    echo -e "  ${C}║${Y}  H.  Help Agent                                  ${C}║${RST}"
    echo -e "  ${C}║${M}  I.  Install / Update                            ${C}║${RST}"
    echo -e "  ${C}║${R}  Q.  Quit                                        ${C}║${RST}"
    echo -e "  ${C}╚══════════════════════════════════════════════════╝${RST}"
    echo ""
}

# ── Launcher map ────────────────────────────────────────────────────────────
SCRIPTS=(
    [1]="lancer_netguard.sh|NetGuard Pro"
    [2]="lancer_cleanguard.sh|CleanGuard Pro"
    [3]="lancer_mailshield.sh|MailShield Pro"
    [4]="lancer_vpnguard.sh|VPN Guard Pro"
    [5]="lancer_sentinel_mapper.sh|SentinelOS Mapper"
    [6]="lancer_sentinel.sh|SentinelOS Cortex"
    [7]="lancer_fim.sh|FIM"
    [8]="lancer_honeypot.sh|HoneyPot"
    [9]="lancer_strikeback.sh|StrikeBack"
    [10]="lancer_recorder.sh|Recorder"
    [11]="lancer_redteam.sh|RedTeam Simulator"
    [12]="lancer_siem.sh|SIEM/SOAR"
    [13]="lancer_sandbox.sh|Sandbox"
    [14]="lancer_mobile_gateway.sh|Mobile Gateway"
)

launch_by_id() {
    local entry="${SCRIPTS[$1]}"
    local script="${entry%%|*}"
    local label="${entry##*|}"
    launch "$script" "$label"
}

launch_all() {
    echo -e "\n  ${G}${BOLD}>>> Launching ALL programs sequentially ...${RST}\n"
    for i in $(seq 1 14); do
        launch_by_id "$i"
    done
    echo -e "\n  ${G}[OK]${RST}  All programs launched."
}

# ── Main loop ───────────────────────────────────────────────────────────────
main() {
    banner
    preflight

    while true; do
        show_menu
        echo -ne "  ${W}${BOLD}Select [1-14, A, H, I, Q]: ${RST}"
        read -r choice

        case "${choice,,}" in
            [1-9]|1[0-4])
                launch_by_id "$choice"
                ;;
            a)
                launch_all
                ;;
            h)
                launch "lancer_helpagent.sh" "Help Agent"
                ;;
            i)
                echo -e "\n  ${M}>>>  Running installer ...${RST}\n"
                bash "$SCRIPT_DIR/install.sh"
                ;;
            q)
                echo -e "\n  ${C}Goodbye. Stay secure.${RST}\n"
                exit 0
                ;;
            *)
                err "Invalid choice — please try again"
                ;;
        esac

        echo ""
        echo -ne "  ${D}Press Enter to return to menu...${RST}"
        read -r
        banner
    done
}

main "$@"
