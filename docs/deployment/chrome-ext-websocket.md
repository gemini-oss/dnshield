# DNShield Chrome Extension WebSocket Guide

## Overview

The DNShield Monitor Chrome extension receives real-time DNS blocking notifications from the
network extension over a localhost-only WebSocket. This document explains how the macOS component
authenticates browser clients, which message types are supported today, and how to configure the
managed policies that tie everything together.

At runtime the WebSocket server lives **inside the DNS proxy network extension**, not the menu bar
process. The proxy starts the server when `EnableWebSocketServer` is true (managed preference) and
listens on TCP port **8876** by default. The listener accepts only localhost connections and
enforces an allow-list of Chrome extension origins built from `DNSShieldChromeExtensionIDs` (bundled
in the app’s Info.plist or `/Library/Application Support/DNShield/websocket_config.json`).

## Authentication

Tokens can be provided in three ways, in descending priority:

1. `WebSocketAuthToken` from `com.dnshield.app` managed preferences (recommended for MDM)
2. A token supplied when the proxy provider launches (rare; used by automation/testing)
3. A Keychain-stored token that the extension generates for local, unmanaged installs  
   (`com.dnshield.websocket` service, account `auth-token`)

The server validates each handshake using one of two mechanisms:

- **Browser clients** (Chrome extension) send the token via the WebSocket subprotocol. The extension
  URL-encodes the token and connects with `new WebSocket(url, ["auth.<token>"])`.
- **CLI tools** send an `Authorization: Bearer <token>` header when upgrading the HTTP connection.

Every handshake is rate limited (10 attempts per minute per client). Five failed attempts block the
client for five minutes, and each rejection is logged under the `WebSocketAuth` category.

## Message Types

The current protocol is intentionally small and focused on notifications.

### Server → Extension

```jsonc
{
  "type": "blocked_site",
  "data": {
    "domain": "malicious.example.com",
    "process": "com.apple.Safari",
    "timestamp": "2025-01-15T10:30:00.000Z"
  }
}
```

Broadcast whenever the proxy blocks a domain. The `process` field comes from the Network Extension
metadata, and the timestamp is UTC in ISO 8601 format.

```jsonc
{
  "type": "blocked_domains_list",
  "data": [
    "ads.example.com",
    "*.tracker.example.net"
  ]
}
```

Returned only to the requesting client (not broadcast) after it asks for a synced list of blocked
domains.

### Extension → Server

```json
{
  "type": "get_blocked_domains"
}
```

Requests the current blocked-domain snapshot. Other request types are ignored; the server does not
yet support whitelisting or bypass commands from the browser.

## Enterprise Configuration

### Managed Preferences (MDM)

Deploy these keys under the `com.dnshield.app` payload to enable and secure the listener:

```xml
<dict>
  <key>EnableWebSocketServer</key>
  <true/>
  <key>WebSocketPort</key>
  <integer>8876</integer>
  <key>WebSocketAuthToken</key>
  <string>YOUR-GENERATED-TOKEN</string>
</dict>
```

Rotate the token by updating the profile and restarting the proxy (`sudo dnshield-ctl restart`) so
the network extension can reload the managed preferences.

### Chrome Managed Storage

Configure the extension in Google Admin Console (Devices → Chrome → Apps & extensions) with this
policy JSON:

```json
{
  "authToken": {
    "Value": "YOUR-GENERATED-TOKEN"
  },
  "websocketUrl": {
    "Value": "ws://localhost:8876/ws"
  },
  "debug": {
    "Value": false
  }
}
```

Only the keys above are supported (`authToken`, `websocketUrl`, `debug`). Because the server accepts
connections solely from `localhost`, TLS is unnecessary and not currently implemented.

## Development and Testing

1. Start DNShield and ensure the server is running:
   ```bash
   sudo lsof -nP -iTCP:8876 | grep LISTEN
   ```
2. Test connectivity with `wscat` (or any WebSocket client) by sending the bearer token header:
   ```bash
   wscat -c ws://localhost:8876/ws -H "Authorization: Bearer <token>"
   ```
3. Send a `{"type":"get_blocked_domains"}` request to receive the current list.

## Monitoring and Troubleshooting

- **Logs**  

  ```bash
  log show --predicate 'subsystem == "com.dnshield.app" && category == "WebSocket"' --last 30m
  log show --predicate 'subsystem == "com.dnshield.app" && category == "WebSocketAuth"' --last 30m
  ```
  
- **Handshake Failures**  
  Usually indicate mismatched tokens or an unapproved Chrome extension ID. Check `websocket_config.json`
  and the Info.plist to confirm the extension ID matches the one enforced in Google Admin.
- **Rate-Limit Blocks**  
  Five consecutive failures block the client for five minutes. The log entry includes the offending
  client identifier.
- **Policy Drift**  
  Verify managed storage via `chrome://policy` and check `chrome://extensions` → *Service worker* for
  console errors.

Keep this document handy when onboarding Chrome clients to ensure the browser, managed preferences,
and the network extension stay in lockstep.
