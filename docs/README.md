# DNShield Documentation

Welcome to the DNShield documentation. This guide will help you install, configure, and use DNShield to protect your macOS system from ads, trackers, and malicious domains.

## Documentation Structure

### Architecture

System design and technical implementation details.

- [Manifest System Guide](architecture/manifest-guide.md) - Rule distribution pipeline
- [Preferences Reference](architecture/preferences.md) - Complete managed preference list
- [DNS Chain Preservation](architecture/dns-chain-preservation.md) - VPN compatibility
- [Network State Detection](architecture/network-state-detection.md) - Interface awareness
- [Filesystem vs SQLite](architecture/filesystem-vs-sqlite.md) - Storage design rationale
- [Command Processing](architecture/command-processing.md) - Filesystem command bridge
- [DNS Response Parsing](architecture/dns-response-parsing.md) - Packet inspection workflow
- [Telemetry System](architecture/telemetry.md) - Opt-in event export
- [Log Viewer Architecture](architecture/log-viewer.md) - Modern log pipeline

### Deployment

Enterprise and production deployment guides.

- [Configuration Files](deployment/configuration-files.md) - File-based configuration
- [Chrome Extension WebSocket](deployment/chrome-ext-websocket.md) - Browser integration setup

### Guides

Step-by-step walkthroughs for operators and end users.

- [macOS App Guide](guides/apple-developer.md) - Setting up the identifiers and provisioning profiles for the macOS app signing process.

### Tools

Management and administrative tools.

- [Manifest Editor](tools/manifest-editor.md) - Web-based manifest management tool
- [Watchdog](tools/watchdog.md) - Health monitoring agent
- [Command-line Utilities](tools/command-line-utilities.md) - Packaging and diagnostics

### Troubleshooting

Diagnostic and problem resolution guides.

- [Cache and Network Configuration](troubleshooting/cache-and-network-configuration.md) - Performance tuning
- [Log Analysis](troubleshooting/logs.md) - Understanding DNShield logs

## Quick Links

### For Administrators

- [Preferences Reference](architecture/preferences.md)
- [Configuration Files](deployment/configuration-files.md)

### For Management

- [Manifest Editor Tool](tools/manifest-editor.md)

### For Troubleshooting

- [Cache & Network Config](troubleshooting/cache-and-network-configuration.md)
- [Log Analysis](troubleshooting/logs.md)

### For Support Teams

- [macOS App Guide](guides/apple-developer.md)

---

Last updated: November 2025
