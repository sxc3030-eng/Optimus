# Support

## Getting Help

| Channel | Best for | Response time |
|---------|----------|---------------|
| [GitHub Issues](https://github.com/sxc3030-eng/Optimus/issues) | Bug reports, feature requests | 1-3 days |
| [GitHub Discussions](https://github.com/sxc3030-eng/Optimus/discussions) | Questions, ideas, community help | Community-driven |
| [INSTALL.md](INSTALL.md) | Installation problems | Self-service |
| [Security advisories](SECURITY.md) | Vulnerabilities | 48 hours |

## Before Opening an Issue

1. **Search existing issues** — your problem may already be reported
2. **Check the install guide** — [INSTALL.md](INSTALL.md) covers common problems
3. **Include your environment:**
   ```
   OS: Ubuntu 24.04
   Python: 3.12.3
   Optimus version: 1.0.0
   Install method: git clone / ISO / WSL
   ```

## Frequently Asked Questions

### "NetGuard shows no packets"
Run with root: `sudo ./launchers/lancer_netguard.sh`

### "Dashboard won't connect"
Check if NetGuard is running: `ss -tlnp | grep 8765`

### "ISO won't boot"
Try Safe Mode in the GRUB menu. If that fails, rebuild with the latest `build_optimus_iso.sh`.

### "Can I use Optimus commercially?"
Yes. GPLv3 allows commercial use. You must keep the source code open if you distribute modifications.

## Windows Version

For the Windows version with professional installer and premium support, see [NetGuardPro](https://github.com/sxc3030-eng/NetGuardPro).
