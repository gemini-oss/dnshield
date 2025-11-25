# DNShield Chrome Extension Enterprise Setup

This guide explains how to configure the DNShield Monitor Chrome extension for enterprise deployment using Google Admin Console.

## Prerequisites

- Google Workspace or Chrome Enterprise license
- Admin access to Google Admin Console
- Chrome extension ID: `nblcmkkfcjelgdlhjpfifjmdlnmfdlin`
- DNShield auth token from the macOS app

## Configuration Steps

### 1. Get the Auth Token

On a machine with DNShield installed, retrieve the auth token:

```bash
security find-generic-password -s "com.dnshield.websocket" -a "auth-token" -w
```

### 2. Configure in Google Admin Console

1. Sign in to [Google Admin Console](https://admin.google.com)
2. Navigate to **Devices → Chrome → Apps & extensions → Users & browsers**
3. Click **Add** → **Add Chrome app or extension by ID**
4. Enter the extension ID: `nblcmkkfcjelgdlhjpfifjmdlnmfdlin`
5. Click **Save**

### 3. Configure Extension Policies

1. Click on the DNShield Monitor extension you just added
2. Under **Policy for extensions**, configure the following JSON:

```json
{
  "authToken": {
    "Value": "YOUR_AUTH_TOKEN_HERE"
  },
  "websocketUrl": {
    "Value": "ws://localhost:8876/ws"
  },
  "debug": {
    "Value": false
  }
}
```

Replace `YOUR_AUTH_TOKEN_HERE` with the token retrieved in step 1.

### 4. Force Installation (Optional)

To automatically install the extension for all users:

1. In the extension settings, change **Installation policy** to **Force install**
2. Click **Save**

## Alternative: Local Configuration

For testing or non-enterprise environments, you can manually set the auth token:

1. Open Chrome and navigate to the extension's service worker console:
   - Go to `chrome://extensions/`
   - Click "service worker" link under DNShield Monitor
2. In the console, run:

```javascript
chrome.storage.local.set({ dnshield_auth_token: "YOUR_AUTH_TOKEN_HERE" });
```

## Policy Schema Reference

The extension accepts the following managed storage properties:

| Property       | Type    | Description                               | Default                  |
| -------------- | ------- | ----------------------------------------- | ------------------------ |
| `authToken`    | string  | Bearer token for WebSocket authentication | (none)                   |
| `websocketUrl` | string  | URL of the DNShield WebSocket server      | `ws://localhost:8876/ws` |
| `debug`        | boolean | Enable debug logging                      | `false`                  |

## Troubleshooting

### Extension Not Connecting

1. Verify DNShield is running: `ps aux | grep -i dnshield`
2. Check WebSocket server is listening: `sudo lsof -i :8876`
3. Verify auth token is correct
4. Check Chrome console for errors

### Policy Not Applied

1. Navigate to `chrome://policy` to view active policies
2. Ensure the device is enrolled in Chrome Enterprise
3. Force sync policies: **Admin Console → Devices → Chrome → Sync Chrome browser**

## Security Notes

- Rotate tokens periodically through managed preferences and redeploy the Chrome policy.
- The WebSocket server only binds to `localhost` and does not support TLS—keep it that way by distributing the extension exclusively through managed channels.
