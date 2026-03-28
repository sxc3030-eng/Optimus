# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-27

### Added
- **14 integrated security programs** — NetGuard Pro, CleanGuard Pro, MailShield Pro, VPN Guard Pro, SentinelOS Cortex, SentinelOS Mapper, FIM, Honeypot, StrikeBack, Recorder, RedTeam, SIEM/SOAR, Sandbox, Mobile Gateway
- **Interactive terminal launcher** (`optimus.sh`) with ASCII art, preflight checks, and one-key launching
- **Custom desktop environment** (Optimus Desktop) with pywebview/GTK backend
- **Bootable ISO builder** — creates a live Debian-based Linux distribution
- **Multi-distro installer** — supports Ubuntu, Debian, Fedora, Arch, openSUSE
- **WSL2 support** — runs natively in Windows Subsystem for Linux
- **NetGuard Pro v4.0** — full network firewall with IDS, DPI, geo-blocking, Suricata rules
- **Dashboard** — 34-tab web interface with Wireshark-style packet filtering
- **4-language support** — French, English, Spanish, German
- **Threat intelligence** — live feeds from Feodo Tracker and Emerging Threats (669+ IPs)
- **WireGuard VPN** integration with kill switch
- **Session recording** and forensic analysis
- **XFCE dark theme** with auto-generated Optimus wallpaper
- **Desktop shortcuts** for all 14 programs + Firefox dashboard + terminal

### Fixed
- ISO kernel installation (removed silent mode, added verification)
- Wireshark group creation order (pre-create before package install)
- Scapy installation verification with retry
- NetGuard launcher auto-escalates to root for packet capture
- Sentinel Cortex no longer exits prematurely (removed background mode)
- Desktop.py launcher references corrected (honeypot, FIM, strikeback, recorder)

### Security
- WebSocket authentication with PBKDF2 password hashing
- Session token validation
- Input validation on all WebSocket commands
- Default admin password: `admin` (must change on first login)

### Changed
- License changed from Commercial to GPLv3 (Linux version is free and open source)
- Added 20 SEO topics to GitHub repository
