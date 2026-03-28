# Installation Guide

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11+ / Ubuntu 22.04+ / Fedora 38+ / Arch | Debian 12 / Ubuntu 24.04 |
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 4 GB |
| Disk | 2 GB free | 10 GB free |
| Python | 3.8+ | 3.11+ |
| Network | Ethernet or Wi-Fi | Ethernet (for packet capture) |

## Quick Install (2 minutes)

```bash
git clone https://github.com/sxc3030-eng/Optimus.git
cd Optimus
chmod +x install.sh
sudo ./install.sh
```

The installer automatically detects your distribution and installs all dependencies.

## Supported Distributions

| Distribution | Version | Status |
|---|---|---|
| Ubuntu | 22.04, 24.04 | Fully supported |
| Debian | 11, 12 | Fully supported |
| Fedora | 38, 39, 40 | Supported |
| Arch Linux | Rolling | Supported |
| Linux Mint | 21+ | Supported |
| Pop!_OS | 22.04+ | Supported |
| openSUSE | Tumbleweed | Community tested |
| Kali Linux | 2024+ | Community tested |

## Step-by-Step Installation

### 1. Install system dependencies

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    python3-gi gir1.2-webkit2-4.1 gir1.2-appindicator3-0.1 \
    libnotify-bin wireguard-tools tcpdump nmap
```

**Fedora:**
```bash
sudo dnf install -y python3 python3-pip \
    python3-gobject webkit2gtk4.1 libappindicator-gtk3 \
    libnotify wireguard-tools tcpdump nmap
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip \
    python-gobject webkit2gtk-4.1 libappindicator-gtk3 \
    libnotify wireguard-tools tcpdump nmap
```

### 2. Install Python dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Verify installation

```bash
python3 -c "import scapy; print('scapy OK')"
python3 -c "import websockets; print('websockets OK')"
python3 -c "import psutil; print('psutil OK')"
python3 -c "import webview; print('pywebview OK')"
```

### 4. Launch

```bash
# Interactive menu
./optimus.sh

# Or launch individual programs
sudo ./launchers/lancer_netguard.sh      # NetGuard Pro (needs root)
./launchers/lancer_cleanguard.sh          # CleanGuard Pro
sudo ./launchers/lancer_sentinel.sh       # SentinelOS Cortex (needs root)
```

## Bootable ISO (Live USB)

Build a complete bootable Linux distribution with Optimus pre-installed:

```bash
sudo ./build_optimus_iso.sh
```

### Requirements for ISO build
- 6 GB free disk space (temporary)
- Root access
- Internet connection
- Packages: `debootstrap`, `squashfs-tools`, `xorriso`, `grub-pc-bin`, `grub-efi-amd64-bin`

### Write to USB

```bash
sudo dd if=~/optimus-v1.0.0-amd64.iso of=/dev/sdX bs=4M status=progress && sync
```

Or use [Rufus](https://rufus.ie) on Windows (DD mode).

### Boot credentials
- **User:** `optimus`
- **Password:** `optimus`
- Auto-login is enabled by default

## WSL (Windows Subsystem for Linux)

Optimus works in WSL2 on Windows 10/11:

```powershell
# Install WSL if not already
wsl --install

# In WSL Ubuntu terminal:
git clone https://github.com/sxc3030-eng/Optimus.git
cd Optimus
sudo ./install.sh
sudo ./launchers/lancer_netguard.sh
```

Open `netguard_dashboard.html` in your Windows browser — it connects to the WebSocket server running in WSL.

## Docker (Experimental)

```bash
docker build -t optimus .
docker run -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN optimus
```

## Troubleshooting

### "Permission denied" on packet capture
NetGuard and VPN Guard need root for raw socket access:
```bash
sudo ./launchers/lancer_netguard.sh
```

### "WebKit2 not found"
Install the GTK WebKit2 binding:
```bash
# Ubuntu/Debian
sudo apt install gir1.2-webkit2-4.1 python3-gi

# Fedora
sudo dnf install webkit2gtk4.1 python3-gobject
```

### "Port already in use"
Kill the process using the port:
```bash
sudo kill $(sudo lsof -t -i:8765)
```

### WSL: No GUI windows
WSL2 on Windows 11 supports GUI apps natively (WSLg). On Windows 10:
```bash
export DISPLAY=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):0
```

## Uninstall

```bash
# Remove installed files
sudo rm -rf /opt/optimus /usr/local/bin/optimus
sudo rm -f /usr/share/applications/optimus-*.desktop

# Remove Python packages (optional)
pip3 uninstall scapy websockets psutil pywebview
```

## Next Steps

- Read the [README](README.md) for an overview of all 14 programs
- Check the [SECURITY](SECURITY.md) policy for responsible disclosure
- See the [ROADMAP](ROADMAP.md) for upcoming features
- Join the community — [open an issue](https://github.com/sxc3030-eng/Optimus/issues) or submit a PR
