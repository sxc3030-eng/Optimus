<div align="center">

# ⚡ Optimus

### Cybersecurity Defense Suite for Linux

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/sxc3030-eng/Optimus/actions/workflows/ci.yml/badge.svg)](https://github.com/sxc3030-eng/Optimus/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624.svg)]()
[![Programs](https://img.shields.io/badge/Programs-14-ff6600.svg)]()
[![Bootable ISO](https://img.shields.io/badge/Bootable-ISO-red.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Like Kali, but yours. Protect. Detect. Respond.*

[Quick Start](#-quick-start) | [Programs](#-programs) | [ISO Builder](#-bootable-iso-builder) | [Desktop](#-optimus-desktop-environment) | [Roadmap](ROADMAP.md) | [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md)

</div>

---

## 🚀 Overview

**Optimus** is a full cybersecurity defense suite for Linux, featuring **14 integrated security programs**, an interactive terminal launcher, a custom desktop environment, and a **bootable ISO builder** that packages everything into a live Linux distribution.

Think of it as your own private security-focused OS — like Kali Linux, but built around your tools and your workflows.

---

## ⚡ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/sxc3030-eng/Optimus.git
cd Optimus
chmod +x install.sh
./install.sh
```

### 2. Launch the Interactive Menu

```bash
chmod +x optimus.sh
./optimus.sh
```

This opens the Optimus terminal menu — a full-featured TUI with ASCII art banner, preflight checks, and one-key launching for all 14 programs.

### 3. Launch Individual Programs

```bash
./launchers/lancer_netguard.sh        # NetGuard Pro
./launchers/lancer_cleanguard.sh      # CleanGuard Pro
./launchers/lancer_mailshield.sh      # MailShield Pro
./launchers/lancer_vpnguard.sh        # VPN Guard Pro
./launchers/lancer_sentinel.sh        # SentinelOS Cortex (all agents)
./launchers/lancer_sentinel_mapper.sh # SentinelOS Mapper
./launchers/lancer_helpagent.sh       # Help Agent
```

### 4. Launch via Cortex (Full Suite)

```bash
sudo ./launchers/lancer_sentinel.sh
```

Cortex starts all agents automatically and provides a unified dashboard on port **8900**.

---

## 📦 Programs

| # | Program | Port | Description |
|---|---------|------|-------------|
| 1 | 🛡️ **NetGuard Pro** | 8765 | Network Firewall & Intrusion Detection System |
| 2 | 🧹 **CleanGuard Pro** | 8810 | Antivirus, Malware Scanner & System Cleaner |
| 3 | 📧 **MailShield Pro** | 8801 | Secure Email Client with Phishing Detection |
| 4 | 🔐 **VPN Guard Pro** | 8820 | WireGuard VPN with Kill Switch & DNS Leak Protection |
| 5 | 🗺️ **SentinelOS Mapper** | — | Interactive Network Map & iptables Firewall |
| 6 | 🧠 **SentinelOS Cortex** | 8900 | Central Orchestrator, Playbooks & Threat Intelligence |
| 7 | 📁 **File Integrity Monitor** | 8840 | SHA-256 File Integrity Monitoring |
| 8 | 🍯 **Honeypot** | 8830 | Deception Traps (SSH, FTP, HTTP) |
| 9 | ⚔️ **StrikeBack** | 8850 | Active Defense & Automated Counter-Measures |
| 10 | 🎙️ **Recorder** | 8860 | Forensic Security Event Recording |
| 11 | 🔴 **RedTeam** | — | Offensive Security & Penetration Testing Tools |
| 12 | 🧪 **Sandbox** | — | Isolated Malware Analysis Environment |
| 13 | 📱 **Mobile Gateway** | — | Mobile Device Security Bridge |
| 14 | 📊 **SIEM** | — | Security Information & Event Management |
| + | 🤖 **Help Agent** | — | Interactive Guide for All Programs |

---

## 🖥️ Optimus Desktop Environment

Optimus ships with a lightweight custom desktop environment built with Python and WebKit2/GTK:

```
optimus_desktop/
├── desktop.py      # Desktop compositor & window manager
├── desktop.html    # Desktop interface (taskbar, app launcher)
└── themes/         # Visual themes for the desktop
```

The Optimus Desktop provides:
- **Application launcher** with one-click access to all 14 security tools
- **System tray** integration with real-time security notifications
- **Theme support** — switch between light, dark, and cyberpunk themes
- **Lightweight footprint** — runs smoothly on minimal hardware

Launch it with:
```bash
python3 optimus_desktop/desktop.py
```

---

## 🖲️ Interactive Terminal Menu

The `optimus.sh` script provides a full-featured terminal interface:

```
   ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗   ██╗███████╗
  ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║   ██║██╔════╝
  ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║   ██║███████╗
  ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║   ██║╚════██║
  ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║╚██████╔╝███████║
   ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝
          Cybersecurity Defense Suite v1.0.0
```

Features:
- **Preflight checks** — verifies root access, Python version, and dependencies
- **Color-coded output** — ANSI colors for status indicators
- **One-key launching** — select a program by number and it starts immediately
- **Dependency validation** — warns about missing packages before launch

---

## 💿 Bootable ISO Builder

Build your own live Linux distribution with all Optimus tools pre-installed:

```bash
chmod +x build_optimus_iso.sh
sudo ./build_optimus_iso.sh
```

### What the ISO Builder Does

1. Creates a minimal Debian/Ubuntu-based live system
2. Installs all Python dependencies and system packages
3. Bundles all 14 Optimus security programs
4. Configures the Optimus Desktop as the default session
5. Sets up auto-login with the security dashboard on boot
6. Outputs a bootable `.iso` file ready for USB or VM

### Burning to USB

```bash
sudo dd if=optimus-live.iso of=/dev/sdX bs=4M status=progress
```

### Running in a VM

```bash
qemu-system-x86_64 -m 4096 -cdrom optimus-live.iso -boot d
```

> See [BUILDING.md](BUILDING.md) for detailed build instructions and customization options.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    SentinelOS Cortex (:8900)                     │
│               Central Orchestrator / Agent Bus                   │
│                    SIEM / SOAR Engine                             │
├────────┬────────┬────────┬────────┬────────┬────────┬────────────┤
│        │        │        │        │        │        │            │
▼        ▼        ▼        ▼        ▼        ▼        ▼            ▼
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐┌────────┐
│ Net  ││Clean ││Mail  ││ VPN  ││Honey ││ FIM  ││Strk  ││Recorder│
│Guard ││Guard ││Shld  ││Guard ││ pot  ││      ││Back  ││        │
│:8765 ││:8810 ││:8801 ││:8820 ││:8830 ││:8840 ││:8850 ││:8860   │
└──────┘└──────┘└──────┘└──────┘└──────┘└──────┘└──────┘└────────┘

  Shared Modules:
  ├── permissions.py         (role-based access control)
  ├── startup_utils.py       (system tray + auto-start)
  └── toast_notifications.py (libnotify / notify-send)
```

- All programs communicate via **WebSocket** on localhost
- Firewall rules managed via **iptables/nftables** (not Windows Firewall)
- Notifications via **libnotify** (`notify-send`) instead of Windows toast
- GUI powered by **pywebview** with GTK/WebKit2 backend

---

## 🔧 Linux vs Windows

| Feature | Windows (NetGuardPro) | Linux (Optimus) |
|---------|----------------------|-----------------|
| **Firewall** | `netsh advfirewall` | `iptables` / `nftables` |
| **Network Scan** | `Get-NetNeighbor` | `ip neigh show` |
| **Interface Detection** | `Get-NetIPAddress` | `ip -4 addr show` |
| **Admin Check** | `ctypes.windll` | `os.geteuid() == 0` |
| **Notifications** | `winotify` | `notify-send` (libnotify) |
| **Launchers** | `.bat` files | `.sh` scripts |
| **Desktop** | Windows native | Optimus Desktop (GTK/WebKit2) |
| **Distribution** | Installer | Bootable ISO |

---

## 📦 System Dependencies

### Ubuntu / Debian
```bash
sudo apt install python3 python3-pip python3-venv \
    python3-gi gir1.2-webkit2-4.1 gir1.2-appindicator3-0.1 \
    libnotify-bin wireguard-tools tcpdump nmap
```

### Fedora
```bash
sudo dnf install python3 python3-pip \
    python3-gobject webkit2gtk4.1 libappindicator-gtk3 \
    libnotify wireguard-tools tcpdump nmap
```

### Arch Linux
```bash
sudo pacman -S python python-pip \
    python-gobject webkit2gtk-4.1 libappindicator-gtk3 \
    libnotify wireguard-tools tcpdump nmap
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 💰 Licensing

**Optimus Linux is FREE and Open Source (GPLv3).**

All 14 programs, bootable ISO, desktop environment — 100% free for everyone.

Want the **Windows version** with professional installer and premium support? See [NetGuardPro](https://github.com/sxc3030-eng/NetGuardPro).

---

## 📁 Project Structure

```
Optimus/
├── optimus.sh                  # Interactive terminal launcher
├── install.sh                  # System installer
├── build_optimus_iso.sh        # Bootable ISO builder
├── netguard.py                 # NetGuard Pro (main firewall/IDS)
├── permissions.py              # Shared: role-based access control
├── toast_notifications.py      # Shared: libnotify notifications
├── startup_utils.py            # Shared: tray + auto-start
├── requirements.txt            # Python dependencies
│
├── optimus_desktop/            # Custom desktop environment
│   ├── desktop.py
│   ├── desktop.html
│   └── themes/
│
├── cleanguard/                 # CleanGuard Pro
├── mailshield/                 # MailShield Pro
├── vpnguard/                   # VPN Guard Pro
├── sentinel/                   # SentinelOS (Mapper + Cortex)
├── siem/                       # SIEM / SOAR Engine
├── fim/                        # File Integrity Monitor
├── honeypot/                   # Honeypot Deception Traps
├── strikeback/                 # StrikeBack Active Defense
├── recorder/                   # Forensic Recorder
├── redteam/                    # RedTeam Offensive Tools
├── sandbox/                    # Malware Sandbox
├── mobile_gateway/             # Mobile Device Gateway
├── help_agent/                 # Interactive Help Agent
├── installer/                  # Selective Installer
├── launchers/                  # Shell launchers (.sh)
├── wireguard/                  # WireGuard VPN configs
├── captures/                   # Packet capture files
└── reports/                    # Generated security reports
```

---

## 🔑 GPG Verification

All commits are signed with GPG key **`5C99E502B17F16D5`**.

```bash
git log --show-signature -1
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -S -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

All contributions must include GPG-signed commits.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0** — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

## 🪟 Windows Version

Looking for Windows? Check out **[NetGuardPro](https://github.com/sxc3030-eng/NetGuardPro)** — the same 14-program cybersecurity suite built natively for Windows 10/11!

---

<div align="center">

**Optimus** — Your cybersecurity OS. Built with Python.

*Like Kali, but yours.*

Made by [@sxc3030-eng](https://github.com/sxc3030-eng)

</div>

---

### Method

Architecture-first, AI-paired. Built over a focused **5-day sprint in March 2026** with **Claude (Opus 4.6)** as paired implementation and audit partner. Linux-port of the NetGuardPro suite: 14 integrated defense tools, custom desktop environment, bootable ISO builder. Each commit is cross-audited (code review, dependency scan, threat-model check on the iptables/nftables layer).

---
