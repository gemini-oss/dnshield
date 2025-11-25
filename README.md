# DNShield

DNShield is a macOS DNS filtering stack that consists of:

- A notarized menu-bar application (`dnshield/App`) that owns user interaction, health monitoring, and preference management.
- A Network Extension target (`dnshield/Extension`, bundle identifier `com.dnshield.extension`) that proxies DNS traffic, enforces manifests, records telemetry, and exposes a WebSocket server for the Chrome extension.
- An enterprise daemon (`dnshield/Daemon`, bundle identifier `com.dnshield.daemon`) that executes privileged commands from `dnshield-ctl` and keeps managed deployments running without the UI.
- Tooling under `tools/` (Objective-C CLI, Go watchdog, manifest editor, Network Extension Status Inspector) and packaging assets in `resources/`.
- A Manifest V3 Chrome extension located at `chrome_extension/` that consumes the WebSocket bridge for notifications and whitelist operations.

All code shares the `com.dnshield.app` preference domain (see `dnshield/Common/DNShieldPreferences.{h,m}` for the resolver and default table).

## Documentation Entry Points

- `docs/Overview.md` – project summary and operator guide.
- `docs/guides/mac-app.md`, `docs/guides/mac_app_user_guide.md` – UI workflows.
- `docs/architecture/` – design documents (preferences, log viewer, DNS chain preservation, manifest guide, etc.).
- `docs/deployment/chrome-ext-websocket.md` – Chrome extension setup.
- `docs/tools/command-line-utilities.md` – `dnshield-ctl` reference.
- `docs/troubleshooting/` – log collection, issue checklists, CLI snippets.

## Repository Layout

```tree
dnshield-dev/
├── dnshield/                        # Xcode workspace (App, Extension, Daemon, Tests)
│   └── CTL/                         # Objective-C CLI source (`dnshield-ctl`)
├── chrome_extension/                # Manifest V3 browser extension
├── manifests/                       # Sample include manifests + machine manifests
├── resources/
│   ├── package/                     # Installer scripts, launchd plists, profiles
│   └── scripts/                     # Version/chrome helpers
├── tools/
│   ├── cmd/manifest-editor/         # Go web server + embedded frontend
│   ├── cmd/watchdog/                # Hosts-file watchdog (Go)
│   └── nesi/                        # Network Extension Status Inspector (ObjC) + Munki helper
└── docs/                            # Documentation tree
```

## Build Targets

| Command                   | Description                                                        |
| ------------------------- | ------------------------------------------------------------------ |
| `make mac-app`            | Build DNShield.app + system extension in Release mode.             |
| `make mac-app-enterprise` | Build the enterprise payloads (app, daemon, watchdog, staged pkg). |
| `make chrome-extension`   | Update the Chrome extension version and zip it to `build/`.        |
| `make tools`              | Build the Go/Objective-C tools declared in `tools/Makefile`.       |
| `make ctl`                | Compile `dnshield-ctl` as a universal binary under `build/`.       |
| `make install`            | Copy DNShield.app from DerivedData to `/Applications` (macOS).     |
| `make clean`              | Remove `build/` / `dist/` and clean the Xcode project.             |

### Signing identities

- `make identity IDENTITY=default` renders `dnshield/Configurations/Identity.xcconfig` and `dnshield/Common/DNIdentity.h` from `config/identities/<name>.json`. The target runs automatically before `make mac-app` / `make mac-app-enterprise`, ensuring bundle identifiers, provisioning profiles, and certificate names stay in sync before each build.

Requirements: Xcode with Command Line Tools installed. Go 1.21+ is required for `tools/cmd/manifest-editor` and `tools/cmd/watchdog`.

## CLI Overview (`dnshield-ctl`)

`dnshield-ctl` lives in the app bundle at `DNShield.app/Contents/MacOS/dnshield-ctl` and is symlinked to `/usr/local/bin/dnshield-ctl` by the installer. Source code is in `dnshield/CTL/dnshield-ctl.m`.

Typical commands:

```bash
sudo dnshield-ctl status              # Daemon/extension health, configuration sources
sudo dnshield-ctl enable / disable
dnshield-ctl logs -f                  # Follow com.dnshield.* unified logging
dnshield-ctl logs --last 1h
dnshield-ctl config                   # Show managed/system/user preference dictionaries
sudo dnshield-ctl config set ManifestURL "https://example.com/manifest.json"
```

See `docs/tools/command-line-utilities.md` for the full command reference, log subcommands, and config examples.

## Tooling Highlights

- **Manifest Editor (`tools/cmd/manifest-editor/`)** – Go server with embedded frontend (`frontend/`) that loads manifest JSON files, lets operators search user/machine/group assignments, and opens pull requests via GitHub APIs.
- **Watchdog (`tools/cmd/watchdog/`)** – Optional LaunchDaemon that watches `/etc/hosts` and enforces the DNShield block database. Configuration lives in the `com.dnshield.watchdog` domain (see `docs/tools/watchdog.md`).
- **Network Extension Status Inspector (`tools/nesi/`)** – Objective-C utility used by support tooling and Munki conditionals; the Munki script `tools/nesi/munki/nesi-status.go` emits `dnshield_proxy=` keys for Conditional Items.
- **Chrome Extension (`chrome_extension/`)** – Manifest V3 extension that subscribes to the WebSocket server inside the Network Extension. Packaging and Web Store uploads are scripted in `resources/scripts/chrome/`.

## Development Notes

- **Versions:** The root `VERSION` file feeds Info.plist values via `resources/scripts/sync/sync_version.sh`. Use `make version-up`, `make version-minor`, or `make version-major` to bump versions consistently.
- **Testing:** `make test` invokes the runners under `resources/tests/runners/`, which in turn call the XCTest bundle defined in `dnshield/DNShieldTests/`.
- **Formatting:** `make lint` runs clang-format over `.m/.mm/.h/.c` files (see `.clang-format`). `make format` will run `shfmt` on shell scripts if the formatter is installed.
- **Preferences:** `DNSharedDefaults` mirrors values to the app group (`group.C6F9Y6M584.com.gemini.dnshield`). Managed preferences under `/Library/Managed Preferences/com.dnshield.app.plist` override system/user values; refer to `docs/architecture/preferences.md`.
- **Docs:** Keep architecture and troubleshooting guides synchronized with code changes; doc files live under version control so edits should be made through pull requests.

For detailed information on a specific tool consult the README or guide located within the relevant `docs/` or `tools/` subdirectory.
