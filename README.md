# 🛡️ Optimus Suite v3.0 — Linux Edition

**A modular cybersecurity platform for Linux** — 10 programs covering network defense, malware scanning, VPN, email security, and more.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%20|%20Fedora%20|%20Arch-FCC624?logo=linux)
![License](https://img.shields.io/badge/License-GPL%20v3-green)
![Programs](https://img.shields.io/badge/Programs-10-orange)

---

## 🚀 Quick Start

### 1. Install Everything

```bash
chmod +x install.sh
./install.sh
```

### 2. Launch Programs

```bash
# Individual programs
./launchers/lancer_netguard.sh
./launchers/lancer_sentinel_mapper.sh
./launchers/lancer_helpagent.sh

# All agents via Cortex (requires root)
sudo ./launchers/lancer_sentinel.sh
```

### 3. GUI Installer (Selective)

```bash
python3 installer/netguardpro_installer.py
```

---

## 🧩 Programs

| # | Program | Port | Description |
|---|---------|------|-------------|
| 1 | **NetGuard Pro** 🛡️ | 8765 | Network IDS, packet capture, DPI, firewall |
| 2 | **CleanGuard Pro** 🧹 | 8810 | System cleaner, malware scanner, YARA |
| 3 | **MailShield Pro** 📧 | 8801 | Secure email, phishing detection, SPF/DKIM |
| 4 | **VPN Guard Pro** 🔐 | 8820 | WireGuard VPN, kill switch |
| 5 | **SentinelOS Mapper** 🗺️ | — | Network map + iptables firewall |
| 6 | **SentinelOS Cortex** 🧠 | 8900 | Central orchestrator |
| 7 | **FIM** 📁 | 8840 | SHA-256 file integrity monitor |
| 8 | **Honeypot** 🍯 | 8830 | Deception traps |
| 9 | **StrikeBack** ⚔️ | 8850 | Active defense |
| 10 | **Recorder** 🎙️ | 8860 | Forensic recording |

---

## 🔧 Linux-Specific Differences

| Feature | Windows | Linux |
|---------|---------|-------|
| **Firewall** | `netsh advfirewall` | `iptables` / `nftables` |
| **Network Scan** | `Get-NetNeighbor` | `ip neigh show` |
| **Interface Detection** | `Get-NetIPAddress` | `ip -4 addr show` |
| **Gateway Detection** | `Get-NetRoute` | `ip route show default` |
| **Admin Check** | `ctypes.windll` | `os.geteuid() == 0` |
| **Notifications** | `winotify` | `notify-send` (libnotify) |
| **Launchers** | `.bat` files | `.sh` scripts |
| **Autostart** | Registry | XDG autostart / systemd |
| **Desktop Shortcuts** | `.lnk` | `.desktop` files |
| **GUI Backend** | pywebview (MSHTML/Edge) | pywebview (GTK/WebKit2) |

---

## 📦 System Dependencies

### Ubuntu / Debian
```bash
sudo apt install python3 python3-pip python3-venv \
    python3-gi gir1.2-webkit2-4.1 gir1.2-appindicator3-0.1 \
    libnotify-bin wireguard-tools tcpdump
```

### Fedora
```bash
sudo dnf install python3 python3-pip \
    python3-gobject webkit2gtk4.1 libappindicator-gtk3 \
    libnotify wireguard-tools tcpdump
```

### Arch Linux
```bash
sudo pacman -S python python-pip \
    python-gobject webkit2gtk-4.1 libappindicator-gtk3 \
    libnotify wireguard-tools tcpdump
```

---

## 🔑 Permission System

Same as Windows version — shared `permissions.py` module (pure Python, fully portable).

```python
from permissions import PermissionManager
pm = PermissionManager()
pm.enable("admin", "password")
pm.lock("password")
```

---

## 📜 License

GNU General Public License v3.0 — see [LICENSE](LICENSE)

---

<div align="center">

**Optimus Suite — Linux Edition** 🐧

</div>
