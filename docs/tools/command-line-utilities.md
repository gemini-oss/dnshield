# DNShield Command-Line Utilities

DNShield provides several command-line utilities bundled within the application at `/Applications/DNShield.app/Contents/MacOS/`. These tools are also accessible via symlinks in `/usr/local/bin/` for convenient command-line access.

## Available Tools

### DNShield (Main Application)

**Path:** `/Applications/DNShield.app/Contents/MacOS/DNShield`

The main macOS application that provides:

- Menu bar interface for user interaction
- System extension activation and management
- GUI for viewing logs and status
- Preference management UI
- WebSocket server for Chrome extension communication

**Special Flags:**

- `--load-system-extension` - Activates the system extension and exits (used during installation)

### dnshield-daemon

**Path:** `/Applications/DNShield.app/Contents/MacOS/dnshield-daemon`  
**Symlink:** `/usr/local/bin/dnshield-daemon`

The background daemon keeps the Network Extension installed, configured, and enabled:

- Runs headless without requiring user login.
- Installs/activates the DNS proxy via `OSSystemExtensionRequest` and `NEDNSProxyManager`.
- Applies `/Library/Application Support/DNShield/config.json` to the system proxy configuration and
  recreates it if it goes missing.
- Exposes the privileged XPC service (`com.dnshield.daemon.xpc`) used by `dnshield-ctl` and
  `dnshield-xpc`.
- Publishes daemon/extension state via the `status`, `enable`, `disable`, `reload`, `shutdown`, and
  `security-status` XPC commands.

The filesystem command queue under `/Library/Application Support/DNShield/Commands/` is processed by
`DNSCommandProcessor` inside the network extension, not by the daemon.

**Key Features:**

- Launched via LaunchDaemon (`/Library/LaunchDaemons/com.dnshield.daemon.plist`).
- Reads and validates `/Library/Application Support/DNShield/config.json`.
- Creates a PID/lock file at `/var/run/dnshield.pid` to prevent duplicate instances.
- Handles `SIGTERM`, `SIGINT`, and `SIGQUIT` so it can tear down the XPC listener and remove the PID
  file cleanly.

### dnshield-ctl

**Path:** `/Applications/DNShield.app/Contents/MacOS/dnshield-ctl`  
**Symlink:** `/usr/local/bin/dnshield-ctl`

The primary command-line control utility for managing DNShield:

**Commands:**

```bash
DNShield Control Utility

Usage: dnshield-ctl [command] [options]

Commands:
  status          Show daemon and extension status
  start           Start the DNShield daemon
  stop            Stop the DNShield daemon
  restart         Restart the DNShield daemon
  enable          Enable DNS filtering
  disable         Disable DNS filtering
  config          Show or set configuration values
  logs            Show or follow logs via unified logging
  logs subsystems List DNShield subsystems/categories from logs
  logs categories  List unique categories across DNShield logs
  version         Show version information
  help            Show this help message

Output formatting (where applicable):
  Append:  format <plist|json|yaml>
  Examples: dnshield-ctl config format json
            dnshield-ctl status format yaml
```

**Example Usage:**

```bash
# Check system status
dnshield-ctl status

# Configure manifest URL
sudo dnshield-ctl config set ManifestURL "https://example.com/manifests"

# Watch logs in real-time
dnshield-ctl logs -f

# Enable DNS filtering
sudo dnshield-ctl enable
```

### dnshield-xpc

**Path:** `/Applications/DNShield.app/Contents/MacOS/dnshield-xpc`  
**Symlink:** `/usr/local/bin/dnshield-xpc`

A lightweight XPC (inter-process communication) client for communicating with the daemon:

**Commands:**

```bash
dnshield-xpc status    # Query daemon status and get process information
dnshield-xpc enable    # Enable DNS filtering via XPC
dnshield-xpc disable   # Disable DNS filtering via XPC
```

**Purpose:**

- Provides programmatic access to daemon functionality
- Used internally by `dnshield-ctl` for privileged operations
- Communicates with daemon via `com.dnshield.daemon.xpc` Mach service
- More reliable than signal-based communication
- Returns structured responses for automation

**Response Examples:**

```bash
$ dnshield-xpc status
Daemon: Running (PID: 12345)
Extension: Installed
Filter: Enabled

$ dnshield-xpc enable
Command 'enable' executed successfully
```

## Installation and Symlinks

During installation, the postinstall script creates symbolic links from `/usr/local/bin/` to the binaries in the application bundle:

```bash
/usr/local/bin/dnshield-daemon -> /Applications/DNShield.app/Contents/MacOS/dnshield-daemon
/usr/local/bin/dnshield-ctl    -> /Applications/DNShield.app/Contents/MacOS/dnshield-ctl
/usr/local/bin/dnshield-xpc    -> /Applications/DNShield.app/Contents/MacOS/dnshield-xpc
```

- Single source of truth for binaries
- Simplified code signing and notarization
- Clean uninstallation (removing the app removes everything)
- Convenient command-line access via PATH

## Architecture Notes

### Universal Binaries

All command-line tools are built as universal binaries supporting both:

- Apple Silicon (arm64)
- Intel (x86_64)

### Code Signing

All binaries are signed with:

- Developer ID for distribution outside the App Store
- Hardened runtime for enhanced security
- Notarization for Gatekeeper approval

### Privilege Requirements

- `dnshield-daemon`: Runs as root via LaunchDaemon
- `dnshield-ctl`: Some commands require sudo (start, stop, enable, config set)
- `dnshield-xpc`: Communicates with privileged daemon service
- Main app: Runs as user, requests admin privileges for system extension

## Troubleshooting

### Check if tools are accessible:

```bash
which dnshield-ctl
ls -la /usr/local/bin/dnshield-*
ls -la /Applications/DNShield.app/Contents/MacOS/
```

### Verify daemon status:

```bash
sudo dnshield-ctl status
ps aux | grep dnshield-daemon
launchctl list | grep dnshield
```

### View daemon logs:

```bash
dnshield-ctl logs -f
tail -f /Library/Logs/DNShield/daemon.stderr.log
```

### Test XPC communication:

```bash
dnshield-xpc status
```

## See Also

- [Enterprise Deployment Guide](../deployment/enterprise.md)
- [Configuration Files](../deployment/configuration-files.md)
- [Troubleshooting Logs](../troubleshooting/logs.md)
- [Architecture Overview](../architecture/network-extension-components.md)
