# Building the Optimus ISO

This document explains how to build a bootable Optimus Linux ISO from the source tree.

The build script (`build_optimus_iso.sh`) creates a Debian 12 (Bookworm) based live
distribution with all 14 Optimus cybersecurity tools pre-installed, a dark XFCE desktop,
and the `optimus` command available system-wide.

---

## Prerequisites

### Host System

You need a **Debian-based Linux system** (Debian 12, Ubuntu 22.04+, or similar) to run
the build. The script will not work on macOS, Windows, or non-Debian distributions
without significant modification.

Minimum requirements:
- **8 GB RAM** (4 GB may work but will be slow)
- **20 GB free disk space** in `/tmp` (or change `WORK_DIR` in the script)
- **Root access** (the script uses debootstrap, chroot, and mount)
- **Internet connection** (to download Debian packages and Python dependencies)

### Required Packages

The script auto-installs these if missing, but you can install them in advance:

```bash
sudo apt-get install debootstrap squashfs-tools xorriso \
    grub-pc-bin grub-efi-amd64-bin mtools rsync
```

---

## Building the ISO

### 1. Clone or copy the repository to a Linux machine

If you are working on Windows, copy the `NetGuardPro-Linux` directory to a Debian/Ubuntu
machine (physical or VM):

```bash
scp -r /path/to/NetGuardPro-Linux user@linux-host:~/NetGuardPro-Linux
```

### 2. Run the build script

```bash
cd ~/NetGuardPro-Linux
sudo bash build_optimus_iso.sh
```

The build takes **30-60 minutes** depending on your internet speed and disk I/O.

### 3. Find the output

When the build completes, the ISO is written to your home directory:

```
~/optimus-v1.0.0-amd64.iso
```

The script prints the file path, size, and MD5 checksum at the end.

---

## Testing the ISO

### With QEMU (quick test, no USB needed)

```bash
# Basic test (BIOS boot)
qemu-system-x86_64 -m 2048 -cdrom ~/optimus-v1.0.0-amd64.iso -boot d

# With KVM acceleration (much faster, requires KVM support)
qemu-system-x86_64 -m 4096 -enable-kvm -cdrom ~/optimus-v1.0.0-amd64.iso -boot d

# Test UEFI boot (requires OVMF)
sudo apt-get install ovmf
qemu-system-x86_64 -m 4096 -enable-kvm \
    -bios /usr/share/OVMF/OVMF_CODE.fd \
    -cdrom ~/optimus-v1.0.0-amd64.iso -boot d
```

### With VirtualBox

1. Create a new VM (Type: Linux, Version: Debian 64-bit)
2. Allocate at least 2048 MB RAM
3. Skip the virtual hard disk (live mode does not need one)
4. Settings > Storage > Add optical drive > Choose the ISO
5. Start the VM

---

## Writing to USB

Use `dd` to write the ISO to a USB drive. **This erases all data on the drive.**

```bash
# Identify your USB device (usually /dev/sdb or /dev/sdc)
lsblk

# Write the ISO (replace /dev/sdX with your actual device)
sudo dd if=~/optimus-v1.0.0-amd64.iso of=/dev/sdX bs=4M status=progress
sync
```

Alternatively, use a graphical tool:
- **Etcher** (https://etcher.balena.io)
- **Ventoy** (https://ventoy.net) — supports booting multiple ISOs from one USB

---

## What is Included in the ISO

### Desktop Environment

- **XFCE 4** with dark Adwaita theme
- Solid dark wallpaper (#0a0a0f)
- LightDM with autologin (user: `optimus`, password: `optimus`)
- Desktop shortcut for the Optimus Suite launcher

### Optimus Suite (14 programs)

All tools are installed under `/opt/optimus` and accessible from the XFCE application
menu under the "Security" category:

| # | Tool | Description |
|---|------|-------------|
| 1 | NetGuard Pro | Firewall and Intrusion Detection System |
| 2 | CleanGuard Pro | Antivirus Scanner and System Cleaner |
| 3 | MailShield Pro | Secure Email Client with Intelligent Filtering |
| 4 | VPN Guard Pro | VPN Manager and WireGuard Frontend |
| 5 | SentinelOS Mapper | Network Topology Mapper |
| 6 | SentinelOS Cortex | Security Command Center |
| 7 | FIM | File Integrity Monitor |
| 8 | HoneyPot | Honeypot Trap Deployment |
| 9 | StrikeBack | Active Defense and Response |
| 10 | Recorder | Forensic Session Recorder |
| 11 | RedTeam Simulator | Attack Simulation and Pen Testing |
| 12 | SIEM/SOAR | Security Information and Event Management |
| 13 | Sandbox | Malware Analysis Sandbox |
| 14 | Mobile Gateway | Mobile VPN and DNS Gateway |

Launch all tools from the terminal with:

```bash
optimus
```

### Pre-installed Security Tools

- **Network**: Wireshark, Nmap, tcpdump, WireGuard, traceroute, whois
- **Offensive**: John the Ripper, Hydra
- **Defensive**: ClamAV, YARA
- **Python**: Scapy, pywebview, psutil, cryptography, and more

---

## Customization

### Changing the version or output path

Edit the configuration block near the top of `build_optimus_iso.sh`:

```bash
DISTRO_NAME="Optimus"
VERSION="1.0.0"          # Change this for new releases
BASE="bookworm"          # Debian codename (bookworm = Debian 12)
ARCH="amd64"             # Architecture (amd64 only for now)
WORK_DIR="/tmp/optimus-build"
ISO_OUTPUT="$HOME/optimus-v${VERSION}-${ARCH}.iso"
```

### Changing the default user password

Find the `chpasswd` line inside the chroot heredoc and change the password:

```bash
echo "optimus:YOUR_NEW_PASSWORD" | chpasswd
```

### Adding more packages

Add packages to the relevant `apt-get install` block inside the chroot section.
Group them logically (network tools, security tools, system utilities, etc.).

### Changing the desktop theme or wallpaper

The XFCE configuration is written as XML inside the chroot heredoc (section 6m).
Modify the `xsettings.xml` to change the GTK theme, or update the RGBA values in
`xfce4-desktop.xml` to change the wallpaper color.

---

## Troubleshooting

### Build fails during debootstrap

- Check your internet connection
- Make sure the Debian mirror is reachable: `curl -I http://deb.debian.org/debian`
- Try a different mirror by editing the debootstrap URL in the script

### Build fails during chroot package installation

- The chroot needs DNS. Check that `/etc/resolv.conf` exists on the host
- If behind a proxy, set `http_proxy` and `https_proxy` before running the script

### "No space left on device"

- The build needs ~15-20 GB in `/tmp`. Change `WORK_DIR` to a directory with more space
- You can also mount a larger partition at `/tmp` before building

### ISO does not boot

- Test with QEMU first to rule out USB writing issues
- For UEFI boot issues, ensure `grub-efi-amd64-bin` was installed on the host
- Check the GRUB config in `${ISO_DIR}/boot/grub/grub.cfg`

### Stale mounts from a previous failed build

If a previous build failed and left mounts behind:

```bash
sudo umount /tmp/optimus-build/chroot/dev/pts
sudo umount /tmp/optimus-build/chroot/dev
sudo umount /tmp/optimus-build/chroot/proc
sudo umount /tmp/optimus-build/chroot/sys
sudo umount /tmp/optimus-build/chroot/run
sudo rm -rf /tmp/optimus-build
```

---

## Architecture Notes

The ISO uses the **Debian Live** boot system:

1. GRUB loads the kernel (`vmlinuz`) and initial ramdisk (`initrd.img`)
2. The `live-boot` package in the initrd finds `filesystem.squashfs` on the ISO
3. It mounts the SquashFS as a read-only lower layer
4. A tmpfs (RAM) overlay is mounted on top, making the system writable
5. Changes are lost on reboot (this is a live system, not an installer)

The ISO is a **hybrid image** — it works both as a CD/DVD ISO and as a raw USB image.
Both BIOS (MBR/El Torito) and UEFI boot paths are supported via GRUB.
