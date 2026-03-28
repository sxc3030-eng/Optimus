# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security issues via:

1. **Email:** security@netguardpro.com
2. **GitHub Security Advisories:** [Report a vulnerability](https://github.com/sxc3030-eng/Optimus/security/advisories/new)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Patch release | Within 30 days for critical issues |

## Security Architecture

### Network Security
- All inter-agent communication uses **localhost WebSocket** (never exposed externally)
- Default ports: 8765 (NetGuard), 8801-8900 (agents)
- No data leaves the machine unless explicitly configured (VPN, email alerts)

### Authentication
- Password hashing: PBKDF2 with SHA-256 + salt
- Session tokens: cryptographically random, time-limited
- Default credentials: `admin` / `admin` — **change immediately after first login**

### Permissions
- Packet capture requires `CAP_NET_RAW` or root
- Firewall rules require root (`iptables`)
- File integrity monitoring runs as the current user
- WireGuard VPN requires root

### Data Storage
- All data stored locally in `/opt/optimus/` or `~/.optimus/`
- No telemetry, no analytics, no phone-home
- Threat intelligence feeds fetched from public sources (Feodo Tracker, Emerging Threats)

## Security Audit Status

| Component | Last Audit | Status |
|-----------|-----------|--------|
| WebSocket handler (netguard.py) | 2026-03-27 | Reviewed |
| Dashboard (netguard_dashboard.html) | 2026-03-27 | 239 handlers verified |
| Authentication system | 2026-03-27 | PBKDF2 + session tokens |
| Input validation | 2026-03-27 | WebSocket commands validated |
| Dependencies | 2026-03-27 | All pinned in requirements.txt |

## Security Best Practices for Users

1. **Change default passwords** immediately after installation
2. **Run with minimal privileges** — only use `sudo` for programs that need it
3. **Keep updated** — `git pull && pip install -r requirements.txt`
4. **Review firewall rules** regularly in the NetGuard dashboard
5. **Enable VPN** (WireGuard) on untrusted networks
6. **Monitor logs** — check `/opt/optimus/netguard.log` for suspicious activity

## Dependency Security

We use only well-known, actively maintained Python packages:

| Package | Purpose | Security track record |
|---------|---------|----------------------|
| scapy | Packet analysis | Widely used in security tools |
| websockets | Agent communication | IETF RFC 6455 compliant |
| cryptography | Encryption | OpenSSL bindings, FIPS capable |
| psutil | System monitoring | Read-only system info |
| pywebview | GUI | Sandboxed WebKit2/GTK |

## GPG Verification

Releases and commits are signed. Verify with:

```bash
git log --show-signature -1
```
