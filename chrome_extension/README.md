# DNShield Chrome Extension

DNShield Monitor is a Manifest V3 Chrome extension that surfaces real-time DNS block activity from
the DNShield macOS network extension. It listens on a localhost-only WebSocket, mirrors the block
decisions that originated from the browser, and gives end users a dedicated "blocked" experience,
notification badge, and searchable history view.

- **Real-time telemetry** via the Network Extension WebSocket (`ws://localhost:8876/ws` by default)
- **Automatic redirect** to `blocked.html` whenever a banned domain is requested in Chrome
- **Popup dashboard** (`popup.html`) with live connectivity state, counts, and per-domain actions
- **History console** (`history.html`) with CSV export and bulk clearing
- **Enterprise-ready config** through Chrome managed storage backed by `schema.json`

For the end-to-end transport and policy model refer to `docs/deployment/chrome-ext-websocket.md`.

## Requirements

- Google Chrome
- DNShield macOS network extension running on the same host with the WebSocket bridge enabled
- A bearer token shared between DNShield and the browser (managed preference or native messaging)
- For enterprise deployments: Google Admin Console access to push managed storage policies

## Repository Layout

| Path                 | Description                                                                   |
| -------------------- | ----------------------------------------------------------------------------- |
| `manifest.json`      | Manifest V3 definition (permissions, icons, background worker, block pages)   |
| `js/background.js`   | Service worker: WebSocket client, badge counts, domain cache & redirects      |
| `js/popup.js`        | Logic for `popup.html` (status indicator, clearing history, unblock requests) |
| `js/history.js`      | Standalone history view with search/export                                    |
| `js/blocked.js`      | Controller for the end-user blocked page                                      |
| `js/secure_token.js` | Helper for session-scoped auth tokens (used by background worker)             |
| `css/`               | Styling for the popup, history, and blocked templates                         |
| `images/`            | Extension icons used for the action badge and Chrome Web Store                |
| `schema.json`        | Managed storage schema consumed by Google Admin Console                       |
| `CHANGELOG.md`       | Extension-specific release notes                                              |

## Runtime Architecture

1. The DNShield proxy starts a localhost WebSocket server when the managed preference
   `EnableWebSocketServer` is `true`. It exposes events such as `blocked_site`, `blocked_domains_list`
   and `domain_unblocked`.
2. `background.js` retrieves an auth token from (in this order) Chrome managed storage, session-only
   storage, or a one-time local-storage migration. The token is URL-encoded and sent as a WebSocket
   subprotocol (`auth.<token>`).
3. After connecting, the service worker:
   - Keeps Chrome’s service worker alive via alarms/pings.
   - Requests an initial block list and keeps it synced every 30 seconds.
   - Sanitizes everything before persisting (`chrome.storage.local`) so counters stay accurate.
   - Listens to `chrome.webNavigation` events to redirect blocked navigations to `blocked.html`.
4. `popup.js` / `history.js` request cached data through runtime messages (`getBlockedDomains`,
   `clearHistory`, `unblockDomain`, `checkConnection`). This keeps UI logic simple and testable.

Only browser-originated blocks are surfaced: non-browser processes are filtered out using process
metadata delivered by DNShield.

## Configuring DNShield and Chrome

### 1. Enable the WebSocket Bridge on macOS

Provision these keys (MDM profile or `/Library/Preferences/com.dnshield.app.plist`) before
launching the proxy:

```xml
<dict>
  <key>EnableWebSocketServer</key><true/>
  <key>WebSocketPort</key><integer>8876</integer>
  <key>WebSocketAuthToken</key><string>GENERATED-TOKEN</string>
</dict>
```

Restart the proxy (`sudo dnshield-ctl restart`) whenever the token rotates. Only localhost clients
are accepted and they must present the same token.

### 2. Deploy Chrome Managed Storage (recommended)

Under Google Admin Console → Devices → Chrome → Apps & Extensions → _DNShield Monitor_, paste a
policy blob that matches `chrome_extension/schema.json`:

```json
{
  "authToken": { "Value": "GENERATED-TOKEN" },
  "websocketUrl": { "Value": "ws://localhost:8876/ws" },
  "debug": { "Value": false }
}
```

The service worker reads these keys through `chrome.storage.managed` on every reconnect, so updates
take effect as soon as policy refresh completes (`chrome://policy`).

### 3. Local or Ad-hoc Testing Without Policy

1. Build or run DNShield locally so that the WebSocket server is listening on `localhost:8876`.
2. Load the extension unpacked: `chrome://extensions` → **Load unpacked** → `chrome_extension/`.
3. Open the service-worker console, then seed a session token (cleared when Chrome quits):

   ```js
   await chrome.storage.session.set({
     auth_token: "GENERATED-TOKEN",
     expires_at: Date.now() + 3600 * 1000,
   });
   ```

4. Confirm the popup shows **Connected** and that `background.js` logs the connection.
5. Trigger a block (or tail DNShield logs) to see the redirect to `blocked.html` and the popup
   counters increment.

The legacy `chrome.storage.local` token field (`dnshield_auth_token`) is migrated automatically the
first time the worker runs, so run the snippet above only if no policy exists.

## Development & Testing Workflow

1. **Versioning**
   - The Chrome extension version is always `root VERSION.major + 1`. `make chrome-extension` applies
     that rule automatically and restores `manifest.json` afterwards.
   - To bump the extension independently, use
     `make chrome-ext-version TYPE=patch|minor|major` (wraps
     `resources/scripts/chrome/update-chrome-extension-version.sh`).
2. **Build artifacts**
   - Run `make chrome-extension` from the repo root. It produces
     `build/dnshield-chrome-extension-<version>.zip`.
   - Assets excluded from the zip: `CHANGELOG.md`, backup files, etc.
3. **Web Store uploads**
   - Either call `make chrome-ext-publish` or invoke
     `resources/scripts/chrome/chrome-web-store-upload.sh <zip> <version>`.
   - Required env vars: `CHROME_EXTENSION_ID`, `GOOGLE_CLIENT_ID`,
     `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`.
4. **Manual tests**
   - `resources/scripts/chrome/test_websocket.html` and `test_ws_server.js` contain a minimal echo
     server to validate WebSocket traffic before touching DNShield.
   - Use `chrome://extensions` → **Service worker** to inspect logs and force reloads.
   - Visit `chrome-extension://<EXT_ID>/history.html` for the full history view outside the popup.

## Customization Notes

- `blocked.html` contains the support link users see after a block. Update the `<a>` target if your
  help desk URL differs.
- Add or resize icons via `resources/scripts/chrome/icons/` and `resources/scripts/chrome/resize.sh`.
- `js/background.js` exposes optional message types (`whitelist_domain`, `request_bypass`) that are
  sent upstream when users click corresponding UI elements—extend the DNShield WebSocket server to
  handle these if your deployment supports user-driven overrides.

## Troubleshooting Checklist

- **Missing badge updates** – Open the service worker console and ensure `blockedDomains` is being
  synced (`syncBlockedDomains` logs the counts). The popup shows only browser-originated entries,
  so system-level blocks will be filtered out intentionally.
- **Auth failures** – Inspect `chrome://policy` for `authToken` and look for
  `WebSocketAuth` failures in macOS logs:  
  `log show --predicate 'subsystem == "com.dnshield.app" && category == "WebSocketAuth"' --last 30m`
- **Service worker sleeps** – Verify `chrome.alarms` are firing. Chrome 116+ still terminates idle
  workers if the WebSocket dies, so ensure DNShield is running locally.
- **Blocked page not shown** – Confirm `chrome.webNavigation` events fire for frameId `0`. Using
  other Chromium-based browsers may require enabling equivalent APIs.

Keep this README next to `docs/deployment/chrome-ext-websocket.md` when onboarding customers so the
browser extension, DNShield preferences, and release packaging remain in sync.
