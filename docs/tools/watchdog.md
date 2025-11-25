# DNShield Watchdog

## Purpose

The DNShield watchdog is an optional LaunchDaemon (`com.dnshield.watchdog`) that monitors `/etc/hosts` for attempts to bypass DNShield’s DNS enforcement. When it detects a record that targets a blocked domain, the watchdog logs an alert and, if configured, automatically removes the offending entries. It uses the same rule database as the DNS proxy so the evaluation logic exactly mirrors what the daemon enforces.

## Packaging & Service Layout

- **Binary** – Built as part of the enterprise artifacts and shipped inside `DNShield.app` (`Contents/MacOS/watchdog`). The installer copies it to `/Applications/DNShield.app/Contents/MacOS/watchdog`.
- **LaunchDaemon** – `resources/package/LaunchDaemons/com.dnshield.watchdog.plist` installs to `/Library/LaunchDaemons/`, disabled by default.
- **Preferences** – Uses the standalone domain `com.dnshield.watchdog`.
- **Logs** – Default file is `/var/log/dnshield/watchdog.log`, owned by `root:wheel`. Output is plaintext unless JSON logging is enabled.

Enable the service after installing DNShield:

```bash
sudo launchctl enable system/com.dnshield.watchdog
sudo launchctl start com.dnshield.watchdog
```

To stop or disable:

```bash
sudo launchctl stop com.dnshield.watchdog
sudo launchctl disable system/com.dnshield.watchdog
```

## How It Works

1. **Rule ingestion** – On start the watchdog reads `/var/db/dnshield/rules.db` (or the overridden `RulesDBPath`) with `sqlite3` to build in-memory exact, wildcard, and regex rule sets. If the database is missing the service logs a warning and continues with an empty set.
2. **File monitoring** – `/etc/hosts` is watched via `kqueue`. If `kqueue` is unavailable, the service falls back to polling at the configured `PollInterval`.
3. **Detection** – Each time the hosts file changes, every hostname is checked against the blocked set. Offending lines are reported with line numbers, IP addresses, and offending domains.
4. **Remediation** – When `RemoveBlockBypassEntries` is true, offending domains are removed from the hosts entry or replaced with a comment such as `# Removed by DNShield Watchdog <timestamp>: <domain list>`.
5. **Structured telemetry** – Events are emitted through `zerolog`. JSON output and optional Splunk HEC telemetry can be enabled via preferences (see below).

## Preference Reference (`com.dnshield.watchdog`)

### Core Behaviour

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `RemoveBlockBypassEntries` | Boolean | `false` | When true the watchdog edits `/etc/hosts` to remove blocked domains; otherwise it only logs detections. |
| `RulesDBPath` | String | `/var/db/dnshield/rules.db` | Alternate path to the DNShield rule database. |
| `PollInterval` | Integer (seconds) | `3` | Interval for the polling fallback when `kqueue` is unavailable. |
| `RemovalComment` | String | `# Removed by DNShield Watchdog %s: %s` | Format string used when a full line is replaced with a comment (`%s` placeholders are timestamp and domain list). |
| `LoggerPrefix` | String | `[dnshield-watchdog]` | Prepended to plaintext log lines when JSON logging is disabled. |

### Logging

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `UseJSONLogging` | Boolean | `false` | Enables zerolog’s JSON output. Needed for structured log forwarding and database monitoring. |
| `LogFilePath` | String | `/var/log/dnshield/watchdog.log` | File to write logs. Set to `-` to keep stdout/stderr only. |

When JSON logging is enabled the watchdog also starts a lightweight database monitor that records create/delete events for the rule database.

### Telemetry

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `TelemetryEnabled` | Boolean | `false` | Master toggle for Splunk HEC forwarding. |
| `TelemetryServerURL` | String | — | HTTPS endpoint of the HEC collector (e.g., `https://splunk.example.com:8088`). Required when telemetry is enabled. |
| `TelemetryHECToken` | String | — | Splunk HEC token. Required when telemetry is enabled. |

Telemetry is only activated when both the URL and token are provided. Events include bypass attempts, rule loads, database availability changes, and shutdown notices.

### Example Configuration

```bash
# Enable automatic remediation with JSON logging
sudo defaults write com.dnshield.watchdog RemoveBlockBypassEntries -bool true
sudo defaults write com.dnshield.watchdog UseJSONLogging -bool true
sudo defaults write com.dnshield.watchdog LogFilePath -string "/var/log/dnshield/watchdog.json"

# Send structured events to Splunk
sudo defaults write com.dnshield.watchdog TelemetryEnabled -bool true
sudo defaults write com.dnshield.watchdog TelemetryServerURL -string "https://splunk.example.com:8088"
sudo defaults write com.dnshield.watchdog TelemetryHECToken -string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

After changing preferences, restart the daemon:

```bash
sudo launchctl kickstart -k system/com.dnshield.watchdog
```

## Observability

- **Log tailing**: `sudo tail -f /var/log/dnshield/watchdog.log`
- **JSON parsing**: `sudo tail -f /var/log/dnshield/watchdog.log | jq '.'`
- **Telemetry health**: errors are written to stderr; check `sudo log stream --predicate 'process == "watchdog"'` for transmission failures.

Example log entry (JSON mode):

```json
{
  "timestamp": "2025-11-24T15:04:11Z",
  "level": "warn",
  "event_type": "bypass_attempt",
  "line_number": 19,
  "ip_address": "127.0.0.1",
  "domains": ["facebook.com"],
  "removed": true,
  "message": "removed blocked-domain override on line 19: facebook.com"
}
```

## Troubleshooting

- **“rule database not found”** – Ensure the main DNShield daemon has populated `/var/db/dnshield/rules.db`. The watchdog uses this database to understand which domains are blocked.
- **No remediation happening** – Confirm `RemoveBlockBypassEntries` is set to `true` and that the daemon has permission to write `/etc/hosts`.
- **No telemetry despite being enabled** – Both `TelemetryServerURL` and `TelemetryHECToken` must be present. Inspect stderr output via `sudo log show --last 5m --predicate 'process == "watchdog"'`.
- **Still seeing bypass entries after edits** – Some configuration-management systems restore `/etc/hosts`. Pair the watchdog with those tools or deploy policies preventing unauthorized edits.

For a deeper architectural overview see `docs/security/watchdog.md`, which covers threat models, build integration, and packaging details.
