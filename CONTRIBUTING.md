# Contributing to Optimus

Thank you for your interest in contributing to Optimus! This guide will help you get started.

## How to Contribute

### Reporting Bugs

1. Search [existing issues](https://github.com/sxc3030-eng/Optimus/issues) first
2. Use the **Bug Report** template
3. Include: OS, Python version, steps to reproduce, expected vs actual behavior
4. Attach logs if relevant (`netguard.log`)

### Suggesting Features

1. Open an issue with the **Feature Request** template
2. Describe the use case, not just the solution
3. Explain why this benefits the community

### Submitting Code

1. **Fork** the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `python3 -m pytest tests/`
5. Commit: `git commit -m "Add: description of change"`
6. Push: `git push origin feature/my-feature`
7. Open a **Pull Request**

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/Optimus.git
cd Optimus
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest flake8  # dev dependencies
```

## Code Standards

### Python
- Follow PEP 8
- Use type hints for function signatures
- Document public functions with docstrings
- Maximum line length: 120 characters

### Shell scripts
- Use `#!/bin/bash` shebang
- Use `set -euo pipefail` for safety
- Quote all variables: `"$VAR"` not `$VAR`

### Commit messages
Format: `Type: Short description`

Types:
- `Add:` — New feature
- `Fix:` — Bug fix
- `Update:` — Enhancement to existing feature
- `Remove:` — Removed feature or code
- `Refactor:` — Code restructuring (no behavior change)
- `Docs:` — Documentation only
- `Test:` — Test additions or fixes
- `Security:` — Security-related changes

### Examples
```
Add: geo-blocking for 12 additional countries
Fix: WebSocket reconnection loop on network change
Update: threat feed to include Emerging Threats ET Pro
Security: rate-limit authentication attempts
```

## Project Structure

```
Optimus/
├── netguard.py              # Core firewall/IDS engine
├── optimus.sh               # Interactive terminal menu
├── install.sh               # Auto-installer
├── build_optimus_iso.sh     # ISO builder
├── requirements.txt         # Python dependencies
├── launchers/               # Shell launchers for each program
├── optimus_desktop/         # Custom desktop environment
├── sentinel/                # SentinelOS Cortex (orchestrator)
├── cleanguard/              # Antivirus engine
├── mailshield/              # Email protection
├── vpnguard/                # WireGuard VPN manager
├── fim/                     # File integrity monitor
├── honeypot/                # Deception traps
├── strikeback/              # Active defense
├── recorder/                # Session recorder
├── redteam/                 # Pen testing tools
├── sandbox/                 # Malware sandbox
├── siem/                    # SIEM/SOAR engine
├── mobile_gateway/          # Mobile device bridge
├── help_agent/              # AI help assistant
├── tests/                   # Test suite
└── docs/                    # Documentation & website
```

## Adding a New Program

1. Create a directory: `my_program/`
2. Add main Python file: `my_program/my_program.py`
3. Create a launcher: `launchers/lancer_my_program.sh`
4. Register in `optimus.sh` (add menu entry + launcher mapping)
5. Register in `optimus_desktop/desktop.py` (add to PROGRAMS list)
6. Add `.desktop` entry in `build_optimus_iso.sh`
7. Update `README.md` programs table
8. Add tests in `tests/`

## Security Contributions

For security-related fixes, see [SECURITY.md](SECURITY.md). Do **not** open public issues for vulnerabilities — use private disclosure instead.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the **GPLv3** license.
