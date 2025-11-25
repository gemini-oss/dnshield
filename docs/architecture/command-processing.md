# DNShield Command Processing Architecture

`dnshield/Extension/DNSCommandProcessor.m` implements the file-based channel the macOS menu bar app uses to reach the network extension. The menu bar UI (`StatusMenuController`) creates JSON commands, `DNShieldDaemonService` writes them into `/Library/Application Support/DNShield/Commands/incoming`, and the network extension processes them on a dedicated serial queue.

## Components

### Menu Bar Application

- Runs as the logged-in user.
- Uses `DNShieldDaemonService` to atomically write JSON command files named `command_<epoch>_<UUID>.json`.
- Requires write access to `/Library/Application Support/DNShield/Commands/incoming`.
- Records the last requested command under the shared defaults key `DNSProxyCommand` when the directory cannot be written (diagnostic only; the extension still needs the filesystem watcher).

### Network Extension

- Creates `/Library/Application Support/DNShield/Commands/{incoming,responses}` on startup if the installer script has not already done so.
- Watches the `incoming` directory via FSEvents, deduplicates commands by `commandId`, and dispatches each command to `ProxyProvider (DNSCommandProcessorDelegate)`.
- Removes each command file immediately after it is parsed.
- Optionally writes a JSON response into `/Library/Application Support/DNShield/Commands/responses`.

## Directory Layout and Permissions

```tree
/Library/Application Support/DNShield/Commands/
|-- incoming/   # Menu bar app writes commands here
`-- responses/  # Network extension writes structured responses here
```

The installer sets `incoming` to `chmod 1777` (world-writable with sticky bit) and `responses` to `chmod 755`. The extension recreates both directories with `root:wheel` ownership and `0755` if they disappear; follow the installer permissions if you repair the directories manually:

```bash
sudo install -d -m 1777 "/Library/Application Support/DNShield/Commands/incoming"
sudo install -d -m 0755 "/Library/Application Support/DNShield/Commands/responses"
```

## Command File Format

Each command is a single JSON object. `commandId` is required; it drives the duplicate filter and is copied into response files.

```jsonc
{
  "commandId": "manual-1732658452",
  "type": "syncRules",
  "timestamp": 1732658452,
  "source": "menu_bar_app",
  "payload": {
    "reason": "user_click"
  }
}
```

`payload` is optional and currently unused by the built-in commands, but it is preserved so the delegate can extend the schema later.

## Processing Pipeline

1. **Detection** - `DNSCommandProcessor` sets up an FSEvent stream (100 ms latency) on the `incoming` directory.
2. **Deduplication** - The filename (without `.json`) becomes the `commandId`. A bounded `NSMutableSet` (100 entries) prevents reprocessing if the file toggles between "created" and "modified".
3. **Parsing** - Files are read on a serial queue and parsed with `NSJSONSerialization`. Invalid JSON is logged and deleted.
4. **Dispatch** - Valid commands are sent to `ProxyProvider (processCommand:)` on the main queue. The network extension deletes each file before invoking the delegate to avoid replay loops.
5. **Responses** - The delegate may call `writeResponse:forCommand:error:` to drop a JSON response (permissions forced to `0644`). These files currently serve automated tests and manual troubleshooting; the shipping app does not poll them.
6. **Cleanup** - A timer deletes command and response files older than 1 hour to keep the directories tidy.

## Supported Command Types

Command handling lives in `dnshield/Extension/ProxyProvider/Delegates.m` and is limited to the following identifiers:

| Command               | Effect                                                                                        |
| --------------------- | --------------------------------------------------------------------------------------------- |
| `syncRules`           | Loads the manifest via `RuleManager loadManifestAsync:` and immediately calls `forceUpdate`.  |
| `updateRules`         | Calls `RuleManager forceUpdate` without fetching a new manifest (useful after local edits).   |
| `clearCache`          | Flushes the DNS cache and the rule cache, then emits telemetry (`cache_cleared`).             |
| `reloadConfiguration` | Reloads the current configuration profile, clears caches, and restarts rule updates.          |
| `getStatus`           | Returns cache statistics, database size, and permitted/blocked counters in the response JSON. |

Unknown `type` values are logged and reported as failures in the response file.

## Responses

`DNSCommandProcessor` writes responses to `<commandId>_response.json`; a successful `clearCache` looks like:

```json
{
  "commandId": "fa3f6b4c-3dc5-4d6b-bb12-09bd4d3e1f95",
  "timestamp": "2025-01-12T02:14:18.004Z",
  "success": true,
  "message": "All caches cleared"
}
```

`getStatus` adds a `status` dictionary containing `blockedDomainCount`, cache hit rates, and flow counters. These files are optional but useful when writing automated health checks.

## Diagnostics

- **Unified logging** (Info level):

  ```bash
  log show --predicate 'subsystem == "com.dnshield.extension" && category == "CommandProcessor"' \
           --style syslog --last 5m --info
  ```

- **Manual command injection** (requires root because of the sticky-bit directory):

```bash
sudo tee "/Library/Application Support/DNShield/Commands/incoming/manual-$(date +%s).json" >/dev/null <<EOF
{
  "commandId": "manual-$(date +%s)",
  "type": "clearCache",
  "timestamp": $(date +%s),
  "source": "terminal-test"
}
EOF
```

- **Permission audit**:

  ```bash
  ls -ld "/Library/Application Support/DNShield/Commands"/*
  ```

If the log stream shows `Failed to create command directory` errors from `DNShieldDaemonService`, fix the permissions and rerun the installer script; the shared-defaults fallback only records the attempted command and does **not** trigger an action inside the extension.

## Error Handling

- Malformed JSON and missing keys are logged via `os_log_error` and the offending files are removed.
- The deduplication set is pruned continuously so long-running sessions do not leak memory.
- Files older than one hour are purged from both `incoming` and `responses`.
- Disk and permission errors bubble up so the UI can surface a failure to the user.

## Security Notes

- Commands run inside the system extension sandbox; only the extension writes responses.
- Sticky-bit directories prevent unprivileged users from deleting somebody else's command files.
- All logging goes through the `com.dnshield.extension` subsystem, making it easy to filter via `dnshield-ctl logs`.
- Because filesystem commands are the only active control plane, ensure `/Library/Application Support/DNShield/Commands/incoming` remains writable and owned by `root:wheel`.
