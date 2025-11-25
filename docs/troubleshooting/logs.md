# DNShield Log Collection

`dnshield-ctl` is the canonical way to pull logs from every DNShield component. It wraps the
macOS unified logging system with sane predicates, JSON export, and helpers for discovering
subsystems/categories. Use the menu bar app’s **Open Log Viewer…** for GUI workflows and this guide
for command-line collection.

## Quick Reference

| Goal | Command |
| ---- | ------- |
| Live stream (all components) | `dnshield-ctl logs -f` |
| Live stream + JSON lines | `dnshield-ctl logs -f format json` |
| Last 4 hours to Desktop | `dnshield-ctl logs --last 4h > ~/Desktop/dnshield.log` |
| Structured bundle for support | `dnshield-ctl logs --last 12h format json > ~/Desktop/dnshield-logs.json` |
| Extension-only stream | `dnshield-ctl logs subsystems --include subsystem:com.dnshield.extension --show-logs -f` |
| Summary of subsystems seen | `dnshield-ctl logs subsystems --summary --last 6h` |
| List categories mentioning Telemetry | `dnshield-ctl logs categories --last 2h --filter Telemetry` |
| Enable verbose logging | `sudo dnshield-ctl config set logLevel debug` |
| Raw `log show` fallback | `log show --predicate 'subsystem == "com.dnshield.extension"' --last 1h --style compact` |

All durations accept the `log` syntax (`10m`, `1h`, `2d`). When streaming (`-f`) the CLI switches to
`log stream`.

## Live Streaming

```sh
# Entire stack (app + extension + daemon) in compact text
dnshield-ctl logs -f

# JSON lines suitable for piping into jq or tee
dnshield-ctl logs -f format json | jq '.eventMessage'
```

### Component-Specific Streams

`logs subsystems` lets you limit output to the subsystem(s) you care about. Combine `--include` /
`--exclude` selectors with `subsystem:<name>` or `process:<name>` tokens:

```sh
# Extension-only stream
dnshield-ctl logs subsystems \
  --include subsystem:com.dnshield.extension \
  --show-logs -f

# App UI events only
dnshield-ctl logs subsystems \
  --include subsystem:com.dnshield.app --show-logs --last 30m

# Stream everything except the daemon
dnshield-ctl logs subsystems \
  --exclude subsystem:com.dnshield.daemon --show-logs -f
```

Add `--summary` to view a rolling table of subsystems, categories, and event counters instead of the
raw log lines.

## Historical Snapshots

`dnshield-ctl logs` defaults to the last hour. Adjust with `--last` and choose a format:

```sh
# 24 hours of text logs
dnshield-ctl logs --last 1d > ~/Desktop/dnshield-last-day.log

# JSON blob for tickets (best for automation and filtering)
dnshield-ctl logs --last 12h format json > ~/Desktop/dnshield-logs.json

# YAML export (handy for quick perusal)
dnshield-ctl logs --last 2h format yaml
```

To ship a bundle to support, capture JSON and compress it:

```sh
dnshield-ctl logs --last 12h format json > ~/Desktop/dnshield-logs.json
gzip ~/Desktop/dnshield-logs.json
```

## Filtering & Pattern Searches

Once you have the base output you can filter with standard tools:

```sh
# Block decisions
dnshield-ctl logs --last 2h | grep -i "BLOCKED"

# DNS telemetry lines
dnshield-ctl logs -f | grep -i '"messageType":"dns"'

# WebSocket bridge issues
dnshield-ctl logs --last 30m | grep -i websocket
```

For structured searches, keep everything in JSON and pipe through `jq`:

```sh
dnshield-ctl logs --last 4h format json \
  | jq 'select(.subsystem=="com.dnshield.extension" and .category=="Telemetry")'
```

## Subsystem & Category Discovery

Use the helper subcommands whenever you are unsure which subsystems/categories are present in the
time window you care about.

```sh
# Snapshot (JSON) of subsystems seen in the last 2 hours
dnshield-ctl logs subsystems --last 2h --summary format json

# Stream new subsystems as they appear (text)
dnshield-ctl logs subsystems -f --summary

# Categories that contain "Telemetry"
dnshield-ctl logs categories --last 2h --filter Telemetry

# Stream only Telemetry categories
dnshield-ctl logs categories -f --filter Telemetry --show-logs
```

Selectors (`--include` / `--exclude`) use the same `subsystem:` or `process:` syntax as above, which
is helpful when you only care about `com.dnshield.extension`.

## System Extension & Daemon Health

These commands are still useful when triaging install/activation problems:

```sh
# System extension inventory
systemextensionsctl list | grep dnshield

# Creation / approval issues
log stream --predicate 'subsystem == "com.apple.sysextd"' --info

# LaunchDaemon status
sudo launchctl list | grep com.dnshield.daemon

# Verify the daemon binary shipped with the app
ls -l /Applications/DNShield.app/Contents/MacOS/dnshield-daemon
```

## Debug / Verbose Logging

Switch DNShield into debug mode when asked by support (resets automatically on reinstall):

```sh
sudo dnshield-ctl config set logLevel debug
dnshield-ctl logs -f --last 5m | grep -i debug
```

Use `dnshield-ctl config` (without arguments) to confirm the effective level. Remember to revert to
`info` once the investigation is complete:

```sh
sudo dnshield-ctl config set logLevel info
```

## Performance & Telemetry Examples

```sh
# Cache churn in the last hour
log show --predicate 'subsystem == "com.dnshield.extension" AND eventMessage CONTAINS "Cache"' \
  --last 1h --info

# DNS latency samples as they stream in
log stream --predicate 'subsystem == "com.dnshield.extension" AND category == "Telemetry" AND eventMessage CONTAINS[c] "latency"' \
  --info

# Count queries per domain
dnshield-ctl logs --last 1h format json \
  | jq -r 'select(.eventMessage | test("Query:")) | .eventMessage' \
  | sed -E 's/.*Query: ([^ ]+).*/\1/' \
  | sort | uniq -c | sort -rn | head

# Unique blocked domains today
dnshield-ctl logs --last 1d format json \
  | jq -r 'select(.eventMessage | test("BLOCKED")) | .eventMessage' \
  | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u
```

## Error-Focused Queries

```sh
# Any DNShield error
dnshield-ctl logs --last 2h | grep -i "error"

# Extension-specific failures
dnshield-ctl logs subsystems \
  --include subsystem:com.dnshield.extension \
  --show-logs --last 2h | grep -i error

# Database corruption hints
dnshield-ctl logs --last 4h | grep -i database
```

## Raw `log` Commands (When dnshield-ctl Is Missing)

If the CLI cannot be launched, fall back to macOS primitives. The predicates below match the ones
`dnshield-ctl logs` uses internally.

```sh
log stream --predicate 'process == "DNShield" OR subsystem == "com.dnshield" OR subsystem == "com.dnshield.app" OR process == "com.dnshield.extension" OR process == "dnshield-daemon"' --info --style compact
  
log show --predicate 'subsystem == "com.dnshield.extension"' --last 1h --info --style compact
```

These fallbacks are rarely necessary but are handy on recovery media or heavily locked-down systems.
