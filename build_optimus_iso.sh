#!/bin/bash
# ============================================================================
#  OPTIMUS ISO BUILDER
#  Build a bootable Debian-based Linux distribution with the full Optimus
#  cybersecurity suite pre-installed.
#
#  Usage:  sudo bash build_optimus_iso.sh
#
#  This script performs the following high-level steps:
#    1. Validates prerequisites (root, required packages)
#    2. Bootstraps a minimal Debian (Bookworm) root filesystem
#    3. Enters a chroot to install packages, configure the desktop,
#       and embed the Optimus suite under /opt/optimus
#    4. Compresses the filesystem into a SquashFS image
#    5. Assembles a bootable ISO (BIOS + UEFI) with GRUB
#
#  The output ISO can be written to a USB stick with:
#    sudo dd if=optimus-v1.0.0-amd64.iso of=/dev/sdX bs=4M status=progress
#
#  Author : NetGuard Pro Team
#  License: See LICENSE in the project root
# ============================================================================

set -euo pipefail

# ── ANSI Colors ─────────────────────────────────────────────────────────────
R='\033[0;31m'   G='\033[0;32m'   C='\033[0;36m'   Y='\033[1;33m'
B='\033[1;34m'   W='\033[1;37m'   D='\033[0;90m'
BOLD='\033[1m'   RST='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────────────────
info()  { echo -e "  ${C}[*]${RST} $1"; }
ok()    { echo -e "  ${G}[+]${RST} $1"; }
warn()  { echo -e "  ${Y}[!]${RST} $1"; }
fail()  { echo -e "  ${R}[X]${RST} $1"; exit 1; }
line()  { echo -e "${D}  $(printf '─%.0s' {1..60})${RST}"; }
step()  { echo -e "\n${B}${BOLD}  ── Step $1: $2 ──${RST}"; }

# ════════════════════════════════════════════════════════════════════════════
#  BANNER
# ════════════════════════════════════════════════════════════════════════════
banner() {
    echo -e "${C}"
    cat << 'ART'

       ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗
      ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝
      ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗
      ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║
      ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║
       ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝

ART
    echo -e "${W}${BOLD}           ISO Builder — Cybersecurity Defense Suite${RST}"
    echo -e "${D}           ── Protect. Detect. Respond. ──${RST}"
    echo ""
}

# ════════════════════════════════════════════════════════════════════════════
#  BUILD CONFIGURATION
#  Edit these variables to customise the output ISO.
# ════════════════════════════════════════════════════════════════════════════
DISTRO_NAME="Optimus"
VERSION="1.0.0"
BASE="bookworm"                           # Debian 12 codename
ARCH="amd64"
WORK_DIR="/tmp/optimus-build"             # Temporary build tree (needs ~6 GB)
CHROOT_DIR="${WORK_DIR}/chroot"           # The root filesystem we assemble
ISO_DIR="${WORK_DIR}/iso"                 # Staging area for the ISO layout
ISO_OUTPUT="$HOME/optimus-v${VERSION}-${ARCH}.iso"

# Path to the Optimus suite source tree (the repo this script lives in).
SUITE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ════════════════════════════════════════════════════════════════════════════
#  CLEANUP TRAP
#  If the build fails at any point, this function unmounts bind-mounts and
#  removes the working directory so we don't leave stale mounts behind.
# ════════════════════════════════════════════════════════════════════════════
cleanup() {
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo ""
        warn "Build failed (exit code $rc). Cleaning up..."
    fi

    # Unmount chroot bind mounts in reverse order (ignore errors)
    for mp in "${CHROOT_DIR}/dev/pts" "${CHROOT_DIR}/dev" \
              "${CHROOT_DIR}/proc" "${CHROOT_DIR}/sys" \
              "${CHROOT_DIR}/run"; do
        mountpoint -q "$mp" 2>/dev/null && umount -lf "$mp" 2>/dev/null || true
    done

    if [ $rc -ne 0 ]; then
        warn "Working directory preserved at ${WORK_DIR} for inspection."
        warn "Remove it manually with:  sudo rm -rf ${WORK_DIR}"
    fi
}
trap cleanup EXIT

# ════════════════════════════════════════════════════════════════════════════
#  STEP 1 — CHECK PREREQUISITES
#  We need root privileges and several Debian packaging/ISO tools.
# ════════════════════════════════════════════════════════════════════════════
step "1/8" "Checking prerequisites"

# 1a. Root check
if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root.  Try:  sudo bash $0"
fi
ok "Running as root"

# 1b. Required host packages
REQUIRED_PKGS=(
    debootstrap          # Bootstrap a minimal Debian root filesystem
    squashfs-tools       # mksquashfs — compress rootfs into a SquashFS image
    xorriso              # Build the hybrid BIOS/UEFI ISO image
    grub-pc-bin          # GRUB modules for BIOS boot
    grub-efi-amd64-bin   # GRUB modules for UEFI boot
    mtools               # Manipulate FAT images (needed by grub-mkimage for EFI)
)

MISSING=()
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING+=("$pkg")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    warn "Missing packages: ${MISSING[*]}"
    info "Installing missing packages via apt..."
    apt-get update -qq
    apt-get install -y -qq "${MISSING[@]}"
    ok "All missing packages installed"
else
    ok "All required packages are present"
fi

# ════════════════════════════════════════════════════════════════════════════
#  STEP 2 — PREPARE WORKING DIRECTORY
# ════════════════════════════════════════════════════════════════════════════
step "2/8" "Preparing working directory"

if [ -d "$WORK_DIR" ]; then
    warn "Previous build directory found — removing it"
    # Make sure nothing is mounted from a previous failed build
    for mp in "${CHROOT_DIR}/dev/pts" "${CHROOT_DIR}/dev" \
              "${CHROOT_DIR}/proc" "${CHROOT_DIR}/sys" \
              "${CHROOT_DIR}/run"; do
        mountpoint -q "$mp" 2>/dev/null && umount -lf "$mp" 2>/dev/null || true
    done
    rm -rf "$WORK_DIR"
fi

mkdir -p "$CHROOT_DIR" "$ISO_DIR"
ok "Work directory created at ${WORK_DIR}"

# ════════════════════════════════════════════════════════════════════════════
#  STEP 3 — BOOTSTRAP DEBIAN BASE SYSTEM
#  debootstrap downloads and unpacks the core Debian packages into our
#  chroot directory.  This gives us a minimal but functional system.
# ════════════════════════════════════════════════════════════════════════════
step "3/8" "Bootstrapping Debian ${BASE} (${ARCH})"

debootstrap --arch="$ARCH" "$BASE" "$CHROOT_DIR" http://deb.debian.org/debian
ok "Debootstrap complete"

# ════════════════════════════════════════════════════════════════════════════
#  STEP 4 — MOUNT VIRTUAL FILESYSTEMS & PREPARE CHROOT
#  The chroot needs /proc, /sys, /dev, and DNS resolution to install
#  packages and run post-install scripts.
# ════════════════════════════════════════════════════════════════════════════
step "4/8" "Mounting virtual filesystems for chroot"

mount --bind /proc  "${CHROOT_DIR}/proc"
mount --bind /sys   "${CHROOT_DIR}/sys"
mount --bind /dev   "${CHROOT_DIR}/dev"
mount --bind /dev/pts "${CHROOT_DIR}/dev/pts"
mkdir -p "${CHROOT_DIR}/run"
mount --bind /run   "${CHROOT_DIR}/run"

# Copy the host's DNS config so apt and pip can resolve hostnames
cp /etc/resolv.conf "${CHROOT_DIR}/etc/resolv.conf"
ok "Chroot environment ready"

# ════════════════════════════════════════════════════════════════════════════
#  STEP 5 — COPY OPTIMUS SUITE INTO CHROOT
#  We copy the entire source tree to /opt/optimus inside the chroot before
#  entering it, so the chroot scripts can reference the files.
# ════════════════════════════════════════════════════════════════════════════
step "5/8" "Copying Optimus suite into chroot"

mkdir -p "${CHROOT_DIR}/opt/optimus"
# Copy everything except .git, __pycache__, and the build script itself
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='build_optimus_iso.sh' \
    "${SUITE_SRC}/" "${CHROOT_DIR}/opt/optimus/"
ok "Optimus suite copied to /opt/optimus"

# ════════════════════════════════════════════════════════════════════════════
#  STEP 6 — CONFIGURE SYSTEM INSIDE CHROOT
#  Everything inside the heredoc runs as root within the chroot.  This is
#  the core of the build — we install all packages, configure the desktop,
#  create the optimus user, and set up launcher shortcuts.
# ════════════════════════════════════════════════════════════════════════════
step "6/8" "Configuring system inside chroot (this will take a while)"

chroot "$CHROOT_DIR" /bin/bash << 'ENDCHROOT'
set -e
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

# ── 6a. Basic system identity ──────────────────────────────────────────────
echo "optimus" > /etc/hostname
echo "127.0.0.1  localhost optimus" > /etc/hosts
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# ── 6b. Enable contrib and non-free repos for security tools ───────────────
cat > /etc/apt/sources.list << 'APT'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
APT
apt-get update -qq

# ── 6c. Install Linux kernel and boot infrastructure ──────────────────────
apt-get install -y -qq linux-image-amd64 live-boot systemd-sysv

# ── 6d. Install desktop environment (XFCE — lightweight) ──────────────────
apt-get install -y -qq \
    xfce4 xfce4-goodies xfce4-terminal \
    lightdm lightdm-gtk-greeter \
    dbus-x11 xorg

# ── 6e. Install Python ecosystem ──────────────────────────────────────────
apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    python3-setuptools python3-wheel

# ── 6f. Install networking and security tools ─────────────────────────────
apt-get install -y -qq \
    wireshark-common tshark nmap tcpdump \
    net-tools iptables iptables-persistent \
    wireguard wireguard-tools \
    clamav clamav-daemon clamav-freshclam \
    yara john hydra \
    traceroute whois dnsutils iproute2 ethtool

# ── 6g. Install system utilities ──────────────────────────────────────────
apt-get install -y -qq \
    git curl wget vim nano htop tmux \
    unzip p7zip-full rsync sudo \
    build-essential libffi-dev libssl-dev \
    libpcap-dev

# ── 6h. Install GUI dependencies (pywebview needs webkit) ─────────────────
apt-get install -y -qq \
    libwebkit2gtk-4.0-37 gir1.2-webkit2-4.0 \
    python3-gi python3-gi-cairo gir1.2-gtk-3.0 \
    libgirepository1.0-dev

# ── 6i. Install Python dependencies for the Optimus suite ────────────────
# We install globally so all users can run the tools without venv activation.
pip3 install --break-system-packages \
    pywebview scapy psutil requests websockets \
    cryptography qrcode Pillow yara-python \
    flask netifaces

# ── 6j. Create the optimus user ──────────────────────────────────────────
# Default password "optimus" — users should change this after first boot.
useradd -m -s /bin/bash -G sudo,wireshark,adm optimus
echo "optimus:optimus" | chpasswd
echo "optimus ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/optimus
chmod 440 /etc/sudoers.d/optimus

# ── 6k. Install optimus launcher to PATH ──────────────────────────────────
# This lets users type "optimus" anywhere to launch the master menu.
cat > /usr/local/bin/optimus << 'LAUNCHER'
#!/bin/bash
cd /opt/optimus && bash optimus.sh "$@"
LAUNCHER
chmod +x /usr/local/bin/optimus

# ── 6l. Configure LightDM autologin ──────────────────────────────────────
# The live ISO boots straight to the optimus desktop — no login prompt.
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf << 'LDM'
[Seat:*]
autologin-user=optimus
autologin-user-timeout=0
user-session=xfce
LDM

# ── 6m. Configure XFCE dark theme and wallpaper ──────────────────────────
XFCE_CONF="/home/optimus/.config/xfce4/xfconf/xfce-perchannel-xml"
mkdir -p "$XFCE_CONF"

# Set dark GTK theme (Adwaita-dark ships with XFCE)
cat > "$XFCE_CONF/xsettings.xml" << 'XSET'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xsettings" version="1.0">
  <property name="Net" type="empty">
    <property name="ThemeName" type="string" value="Adwaita-dark"/>
    <property name="IconThemeName" type="string" value="Adwaita"/>
  </property>
</channel>
XSET

# Set solid dark wallpaper (#0a0a0f) — XFCE desktop background
cat > "$XFCE_CONF/xfce4-desktop.xml" << 'XDESK'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-desktop" version="1.0">
  <property name="backdrop" type="empty">
    <property name="screen0" type="empty">
      <property name="monitorVirtual-1" type="empty">
        <property name="workspace0" type="empty">
          <property name="color-style" type="int" value="0"/>
          <property name="rgba1" type="array">
            <value type="double" value="0.039216"/>
            <value type="double" value="0.039216"/>
            <value type="double" value="0.058824"/>
            <value type="double" value="1.000000"/>
          </property>
          <property name="image-style" type="int" value="0"/>
        </property>
      </property>
    </property>
  </property>
</channel>
XDESK

# Set dark window manager theme
cat > "$XFCE_CONF/xfwm4.xml" << 'XWM'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0">
  <property name="general" type="empty">
    <property name="theme" type="string" value="Default-hdpi"/>
  </property>
</channel>
XWM

# ── 6n. Create .desktop files for all 14 Optimus programs ────────────────
# These appear in the XFCE application menu and can be placed on the desktop.
APPS_DIR="/usr/share/applications"

declare -A PROGRAMS=(
    ["netguard-pro"]="NetGuard Pro|Firewall and Intrusion Detection System|lancer_netguard.sh|security-high"
    ["cleanguard-pro"]="CleanGuard Pro|Antivirus Scanner and System Cleaner|lancer_cleanguard.sh|security-medium"
    ["mailshield-pro"]="MailShield Pro|Secure Email Client with Filtering|lancer_mailshield.sh|mail-send"
    ["vpnguard-pro"]="VPN Guard Pro|VPN Manager and WireGuard Frontend|lancer_vpnguard.sh|network-vpn"
    ["sentinel-mapper"]="SentinelOS Mapper|Network Topology Mapper|lancer_sentinel_mapper.sh|network-workgroup"
    ["sentinel-cortex"]="SentinelOS Cortex|Security Command Center|lancer_sentinel.sh|preferences-system"
    ["fim"]="FIM|File Integrity Monitor|lancer_fim.sh|document-properties"
    ["honeypot"]="HoneyPot|Honeypot Trap Deployment|lancer_honeypot.sh|network-server"
    ["strikeback"]="StrikeBack|Active Defense and Response|lancer_strikeback.sh|security-high"
    ["recorder"]="Recorder|Forensic Session Recorder|lancer_recorder.sh|media-record"
    ["redteam"]="RedTeam Simulator|Attack Simulation and Pen Testing|lancer_redteam.sh|dialog-warning"
    ["siem-soar"]="SIEM/SOAR|Security Information and Event Management|lancer_siem.sh|utilities-system-monitor"
    ["sandbox"]="Sandbox|Malware Analysis Sandbox|lancer_sandbox.sh|system-run"
    ["mobile-gateway"]="Mobile Gateway|Mobile VPN and DNS Gateway|lancer_mobile_gateway.sh|phone"
)

for id in "${!PROGRAMS[@]}"; do
    IFS='|' read -r name comment launcher icon <<< "${PROGRAMS[$id]}"
    cat > "${APPS_DIR}/optimus-${id}.desktop" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=${name}
Comment=${comment}
Exec=bash /opt/optimus/launchers/${launcher}
Icon=${icon}
Terminal=true
Categories=System;Security;
StartupNotify=false
DESKTOP
done

# Master launcher desktop entry
cat > "${APPS_DIR}/optimus-suite.desktop" << 'MASTER'
[Desktop Entry]
Version=1.0
Type=Application
Name=Optimus Suite
Comment=Cybersecurity Defense Suite — Master Launcher
Exec=/usr/local/bin/optimus
Icon=security-high
Terminal=true
Categories=System;Security;
StartupNotify=false
MASTER

# ── 6o. Place shortcuts on the XFCE desktop ──────────────────────────────
DESKTOP_DIR="/home/optimus/Desktop"
mkdir -p "$DESKTOP_DIR"

# Copy the master launcher shortcut to the desktop
cp "${APPS_DIR}/optimus-suite.desktop" "${DESKTOP_DIR}/"
chmod +x "${DESKTOP_DIR}/optimus-suite.desktop"

# Also add a terminal shortcut
cat > "${DESKTOP_DIR}/terminal.desktop" << 'TERM'
[Desktop Entry]
Version=1.0
Type=Application
Name=Terminal
Comment=Open a terminal
Exec=xfce4-terminal
Icon=utilities-terminal
Terminal=false
Categories=System;TerminalEmulator;
TERM
chmod +x "${DESKTOP_DIR}/terminal.desktop"

# ── 6p. Set MOTD banner ──────────────────────────────────────────────────
cat > /etc/motd << 'MOTD'

   ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗
  ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝
  ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗
  ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║
  ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║
   ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝

  Optimus v1.0.0 — Cybersecurity Defense Suite
  Type "optimus" to launch the suite.

MOTD

# ── 6q. Fix ownership ────────────────────────────────────────────────────
chown -R optimus:optimus /home/optimus
chown -R root:root /opt/optimus
chmod -R +x /opt/optimus/launchers/ 2>/dev/null || true
chmod +x /opt/optimus/optimus.sh

# ── 6r. Clean up apt caches inside chroot ─────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENDCHROOT

ok "Chroot configuration complete"

# ════════════════════════════════════════════════════════════════════════════
#  STEP 7 — UNMOUNT CHROOT & CREATE SQUASHFS
#  SquashFS is a compressed read-only filesystem.  The live boot system
#  mounts it as an overlay so the user can write to RAM while the base
#  image stays on the ISO.
# ════════════════════════════════════════════════════════════════════════════
step "7/8" "Building SquashFS image"

# Unmount virtual filesystems (order matters — most nested first)
umount "${CHROOT_DIR}/dev/pts" 2>/dev/null || true
umount "${CHROOT_DIR}/dev"     2>/dev/null || true
umount "${CHROOT_DIR}/proc"    2>/dev/null || true
umount "${CHROOT_DIR}/sys"     2>/dev/null || true
umount "${CHROOT_DIR}/run"     2>/dev/null || true
ok "Virtual filesystems unmounted"

# Create the live filesystem directory structure
mkdir -p "${ISO_DIR}/live"
mkdir -p "${ISO_DIR}/boot/grub"

info "Compressing root filesystem (this may take 10-20 minutes)..."
mksquashfs "$CHROOT_DIR" "${ISO_DIR}/live/filesystem.squashfs" \
    -comp xz -Xbcj x86 -b 1M -no-duplicates -no-recovery
ok "SquashFS image created"

# ════════════════════════════════════════════════════════════════════════════
#  STEP 8 — BUILD THE ISO IMAGE
#  We create a hybrid ISO that boots on both BIOS (via MBR) and UEFI
#  systems.  GRUB is embedded for both boot modes.
# ════════════════════════════════════════════════════════════════════════════
step "8/8" "Assembling bootable ISO"

# 8a. Copy kernel and initramfs from the chroot into the ISO
VMLINUZ=$(ls "${CHROOT_DIR}"/boot/vmlinuz-* 2>/dev/null | sort -V | tail -1)
INITRD=$(ls "${CHROOT_DIR}"/boot/initrd.img-* 2>/dev/null | sort -V | tail -1)

if [ -z "$VMLINUZ" ] || [ -z "$INITRD" ]; then
    fail "Kernel or initrd not found in chroot. Bootstrap may have failed."
fi

cp "$VMLINUZ" "${ISO_DIR}/live/vmlinuz"
cp "$INITRD"  "${ISO_DIR}/live/initrd.img"
ok "Kernel and initramfs copied"

# 8b. Create GRUB configuration
# This config handles both BIOS and UEFI boot paths.
cat > "${ISO_DIR}/boot/grub/grub.cfg" << 'GRUB'
set timeout=5
set default=0

# Detect if we booted via EFI
if [ "${grub_platform}" = "efi" ]; then
    insmod efi_gop
    insmod efi_uga
else
    insmod vbe
    insmod vga
fi

insmod gfxterm
terminal_output gfxterm
set gfxmode=auto

# ── Menu Colors ──────────────────────────────────────────────────────────
set menu_color_normal=cyan/black
set menu_color_highlight=white/dark-gray

menuentry "Optimus v1.0.0 — Live (Default)" {
    linux /live/vmlinuz boot=live quiet splash
    initrd /live/initrd.img
}

menuentry "Optimus v1.0.0 — Live (Safe Mode)" {
    linux /live/vmlinuz boot=live nomodeset
    initrd /live/initrd.img
}

menuentry "Optimus v1.0.0 — Live (Debug / Verbose)" {
    linux /live/vmlinuz boot=live debug verbose
    initrd /live/initrd.img
}

menuentry "Memory Test (memtest86+)" {
    linux16 /live/vmlinuz memtest
}
GRUB

# 8c. Create the EFI boot image
# GRUB needs a small FAT image for UEFI booting.
mkdir -p "${ISO_DIR}/EFI/boot"

grub-mkstandalone \
    --format=x86_64-efi \
    --output="${ISO_DIR}/EFI/boot/bootx64.efi" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=${ISO_DIR}/boot/grub/grub.cfg"

# Create the EFI System Partition image (FAT12/16)
EFI_IMG="${ISO_DIR}/boot/grub/efi.img"
dd if=/dev/zero of="$EFI_IMG" bs=1M count=4
mkfs.vfat "$EFI_IMG"
mmd -i "$EFI_IMG" ::/EFI ::/EFI/boot
mcopy -i "$EFI_IMG" "${ISO_DIR}/EFI/boot/bootx64.efi" ::/EFI/boot/

# 8d. Create the BIOS boot image
grub-mkstandalone \
    --format=i386-pc \
    --output="${WORK_DIR}/core.img" \
    --install-modules="linux normal iso9660 biosdisk memdisk search tar ls" \
    --modules="linux normal iso9660 biosdisk search" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=${ISO_DIR}/boot/grub/grub.cfg"

# Concatenate the BIOS boot image with the cdboot module
cat /usr/lib/grub/i386-pc/cdboot.img "${WORK_DIR}/core.img" \
    > "${ISO_DIR}/boot/grub/bios.img"

# 8e. Build the final hybrid ISO with xorriso
# -eltorito-boot   = BIOS boot image
# -eltorito-alt-boot + efi.img = UEFI boot image
# --mbr-force-bootable = write a protective MBR for USB boot
info "Running xorriso to create ISO..."
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "OPTIMUS_LIVE" \
    -output "$ISO_OUTPUT" \
    -eltorito-boot boot/grub/bios.img \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        --grub2-boot-info \
        --grub2-mbr /usr/lib/grub/i386-pc/boot_hybrid.img \
    -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
    -append_partition 2 0xef "${EFI_IMG}" \
    -graft-points \
        "${ISO_DIR}"

ok "ISO image created successfully"

# ════════════════════════════════════════════════════════════════════════════
#  DONE — Print summary
# ════════════════════════════════════════════════════════════════════════════
echo ""
line
echo -e "  ${G}${BOLD}BUILD COMPLETE${RST}"
line
echo ""

ISO_SIZE=$(du -h "$ISO_OUTPUT" | cut -f1)
ISO_MD5=$(md5sum "$ISO_OUTPUT" | awk '{print $1}')

echo -e "  ${W}ISO Path :${RST}  $ISO_OUTPUT"
echo -e "  ${W}ISO Size :${RST}  $ISO_SIZE"
echo -e "  ${W}MD5      :${RST}  $ISO_MD5"
echo ""
echo -e "  ${D}Write to USB:${RST}"
echo -e "  ${C}  sudo dd if=${ISO_OUTPUT} of=/dev/sdX bs=4M status=progress && sync${RST}"
echo ""
echo -e "  ${D}Test in QEMU:${RST}"
echo -e "  ${C}  qemu-system-x86_64 -m 2048 -cdrom ${ISO_OUTPUT} -boot d${RST}"
echo ""
line

# Clean up the build directory (optional — comment out to inspect)
info "Cleaning up build directory..."
rm -rf "$WORK_DIR"
ok "Build directory removed. All done."
