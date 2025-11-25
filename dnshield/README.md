# DNShield

A macOS DNS filtering solution.

## Features

- System-level DNS filtering using Network Extension
- Blocks ads, trackers, and malicious domains
- Enterprise deployment support (LaunchDaemon)
- Menu bar UI for user control
- WebSocket server for browser extension integration
- SQLite database for rule storage at `/var/db/dnshield/rules.db`
- Manifest-based rule distribution with automatic updates
- Configurable blocklists and whitelists
- Optional watchdog LaunchDaemon that monitors `/etc/hosts` for bypass attempts

## Deployment Options

### 1. Standalone Mode

Traditional macOS app that users install in `/Applications`:

- Menu bar interface
- User manages extension lifecycle
- Settings stored in user preferences

### 2. Enterprise Mode

Daemon-based deployment for managed environments:

- Runs as LaunchDaemon
- No UI required for operation
- Centralized configuration
- Remote management capabilities

## Quick Start

### Standalone Installation

1. Download DNShield.app
2. Move to `/Applications`
3. Launch and approve system extension
4. Configure via menu bar

### Enterprise Installation

```bash
# Build
make enterprise

# Or build directly
../resources/package/build_enterprise.sh

# Install the generated package
sudo installer -pkg build/enterprise/DNShield-Enterprise.pkg -target /

# Manage
sudo dnshield-ctl status
```

## Architecture

```
DNShield.app (Menu Bar UI)
    ↓
SQLite Database (/var/db/dnshield/rules.db)
    ↑
System Extension (Network Filter)
    ↓
DNS Proxy Provider
    ↓
Manifest Server (Rule Updates)
```

## Watchdog Daemon

- Optional LaunchDaemon (`com.dnshield.watchdog`) delivers monitoring of `/etc/hosts`
- Disabled by default; enable with `sudo launchctl enable system/com.dnshield.watchdog`
- Respects the `RemoveBlockBypassEntries` boolean in the `com.dnshield.watchdog` preference domain
  - `false` (default): log detected bypass entries to `/var/log/dnshield/watchdog.log`
  - `true`: remove offending host entries and leave an audit comment in the file
- Requires the DNShield rule database (`/var/db/dnshield/rules.db`) to resolve blocked domains
- Ships alongside the main package; symlinked to `/usr/local/bin/dnshield-watchdog`
- See [DNShield Watchdog](../docs/security/watchdog.md) for architecture, deployment, and operations guidance.

## Documentation

- [Enterprise Deployment Guide](../docs/deployment/enterprise.md)
- [Troubleshooting Guide](../docs/troubleshooting/)
- [Manifest System Guide](../docs/manifests/manifest-guide.md)
- [Chrome Extension Setup](../chrome_extension/ENTERPRISE_SETUP.md)

## Requirements

- macOS 11.0 (Big Sur) or later
- Admin privileges for system extension
- Code signing certificate for distribution

## Security

DNShield implements multiple security measures:

- Code signature validation for XPC
- Privileged helper separation
- Secure configuration storage
- No external network connections (except DNS)

## Support

For issues, see the [Troubleshooting Documentation](../docs/troubleshooting/) or file an issue in the repository.

## Testing

- Unit and integration tests build without extra dependencies, but some mocks rely on OCMock.
- The OCMock binary is intentionally not checked in; install it locally via `dnshield/DNShieldTests/vendors/install_ocmock.sh`.
- Alternative manual setup instructions live in `dnshield/DNShieldTests/vendors/README.md`.

# Project Structure (After Cleanup)

The DNShield macOS app has been reorganized for better maintainability:

```
dnshield/
├── App/                        # Main application source
├── Extension/                  # Network extension source
├── Daemon/                     # LaunchDaemon source
├── Common/                     # Shared code and utilities
├── Tests/                      # Test suite
├── CTL/                        # dnshield-ctl source
├── XPC/                        # XPC helper source
│   └── dnshield-xpc.m          # XPC helper (compiled during build)
└── Makefile                   # Build configuration

../resources/                   # Build and deployment resources
├── package/                    # PKG installer components
│   ├── Scripts/               # Installer scripts (preinstall, postinstall)
│   ├── LaunchDaemons/         # System service configuration
│   └── Component/             # PKG component configuration
└── scripts/                   # Development and deployment scripts
    ├── sync/                  # Version synchronization
    └── chrome/                # Chrome extension scripts
```
