# Roadmap

## Current Release: v1.0.0 (March 2026)

### Completed
- [x] 14 integrated security programs
- [x] Interactive terminal launcher (`optimus.sh`)
- [x] Custom desktop environment (Optimus Desktop)
- [x] Bootable ISO builder
- [x] Multi-distro installer (Ubuntu, Debian, Fedora, Arch)
- [x] WSL2 support
- [x] WebSocket-based agent communication
- [x] 4-language dashboard (FR/EN/ES/DE)
- [x] Threat intelligence feeds (Feodo, Emerging Threats)
- [x] Wireshark-style packet filtering
- [x] WireGuard VPN integration
- [x] Suricata IDS rule support
- [x] Session recording and forensics
- [x] GPLv3 open source license

---

## v1.1.0 — Stability & Polish (Q2 2026)

**Focus:** Make everything bulletproof for first-time users.

- [ ] Automated test suite (pytest) for all 14 programs
- [ ] Health check command: `optimus --check`
- [ ] Graceful error handling for missing dependencies
- [ ] Improved ISO boot reliability (UEFI + Legacy BIOS)
- [ ] Auto-updater via `git pull` with version check
- [ ] Systemd service files for all agents
- [ ] Man pages for CLI commands
- [ ] Offline threat intelligence (bundled in ISO)

## v1.2.0 — Security Hardening (Q3 2026)

**Focus:** Make Optimus audit-ready.

- [ ] Rate limiting on all WebSocket endpoints
- [ ] Role-based access control (RBAC) enforcement
- [ ] TLS/SSL for agent-to-agent communication
- [ ] Automated security scanning in CI/CD
- [ ] SBOM (Software Bill of Materials) generation
- [ ] CVE monitoring for dependencies
- [ ] SELinux/AppArmor profiles

## v1.3.0 — Community Features (Q4 2026)

**Focus:** Make it easy to contribute and extend.

- [ ] Plugin system for third-party security tools
- [ ] Community threat intelligence sharing
- [ ] Dashboard theme marketplace
- [ ] Rule sharing (Suricata, YARA)
- [ ] Localization: add Arabic, Chinese, Portuguese, Japanese
- [ ] Public API documentation (OpenAPI/Swagger)

## v2.0.0 — Enterprise & Certification (2027)

**Focus:** Enterprise readiness.

- [ ] Multi-node deployment (central management)
- [ ] LDAP/Active Directory integration
- [ ] Compliance reporting (PCI-DSS, SOC2, ISO 27001)
- [ ] Encrypted log shipping (Syslog + TLS)
- [ ] High availability / failover
- [ ] Professional support tier
- [ ] Security certification preparation

---

## Long-term Vision

Optimus aims to be the **#1 open-source defensive cybersecurity suite for Linux** — an alternative to commercial solutions like CrowdStrike, SentinelOne, or Sophos, accessible to everyone from home users to small businesses.

### Positioning

| Tool | Focus | License |
|------|-------|---------|
| Kali Linux | Offensive (pentesting) | Open source |
| Security Onion | Network monitoring | Open source |
| **Optimus** | **Complete defense** | **Open source (GPLv3)** |
| CrowdStrike | Enterprise EDR | Commercial ($$$) |

---

## How to Influence the Roadmap

1. **Vote on features** — React with a thumbs-up on [feature request issues](https://github.com/sxc3030-eng/Optimus/issues?q=is%3Aissue+label%3Aenhancement)
2. **Submit ideas** — Open a feature request issue
3. **Contribute code** — See [CONTRIBUTING.md](CONTRIBUTING.md)
4. **Sponsor development** — Support the project financially

The roadmap is community-driven. The most requested features get prioritized.
