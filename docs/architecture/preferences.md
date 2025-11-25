# DNShield Preference Reference

This document describes the active preference keys consumed by the DNShield app, daemon, and Network Extension. The authoritative definitions live in `dnshield/Common/DNShieldPreferences.h` and `DNShieldPreferences.m`; update this page whenever that file changes.

## Domains and Resolution Order

- **Preference domain**: `com.dnshield.app` (also used by configuration profiles and `defaults`).
- **Managed overrides**: When a key is forced by MDM (`/Library/Managed Preferences/com.dnshield.app.plist`) the forced value wins.

Resolution order for every read:

1. Managed/forced preference (MDM profile or `/Library/Managed Preferences`).
2. Mirrored value in the app group container.
3. Legacy value from `~/Library/Preferences/com.dnshield.app.plist` or `/Library/Preferences/com.dnshield.app.plist` (automatically mirrored forward).
4. Hard-coded defaults from `DNShieldPreferences defaultPreferences`.

### Inspecting and Editing

- Per-user values:

  ```bash
  defaults read ~/Library/Preferences/com.dnshield.app <Key>
  ```

- System-level or privileged values:

  ```bash
  sudo defaults read /Library/Preferences/com.dnshield.app <Key>
  ```

## Preference Key Reference

### Manifest & Distribution

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `ManifestURL` | String | `https://dnshield-manifests.example.com` | Primary manifest feed consumed by the extension and daemon. |
| `ManifestFormat` | String | `json` | Manifest serialization format (`json`, `yaml`, etc.). |
| `ManifestUpdateInterval` | Integer (seconds) | `300` | Poll cadence for manifest refreshes. |
| `DefaultManifestIdentifier` | String | `global-allowlist` | Identifier selected if a resolved manifest does not specify one. |
| `RuleSources` | Array<Dictionary> | `[]` | Legacy/custom rule source definitions. Each dictionary follows `RuleSource` schema (`identifier`, `type`, `url`/`bucket`, `format`, `updateInterval`, etc.). |
| `SoftwareRepoURL` | String | `https://dnshield-rules.example.com` | Base URL used by legacy HTTP/S3 rule fetchers. |
| `UpdateInterval` | Integer (seconds) | `300` | Fallback polling interval for non-manifest sources. |
| `AdditionalHttpHeaders` | Dictionary | `nil` | Extra headers sent with manifest and rule requests (e.g., auth tokens). |
| `Configuration` (`kDNShieldConfigurationArchiveKey`) | Data | `nil` | NSKeyedArchive of the full `DNSConfiguration` document. Prefer editing via the configuration UI/CLI instead of writing binary blobs directly. |

### Cache, Domain Overrides & Rule Behavior

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `BlockedDomains` | Array<String> | `[]` | Always-deny host list merged into the SQLite database. |
| `WhitelistedDomains` | Array<String> | `[]` | Always-allow list evaluated before manifest rules. |
| `CacheDirectory` | String | `/Library/Application Support/DNShield/Cache` | On-disk cache path for resolver state. |
| `EnableDNSCache` | Boolean | `nil` (unset) | Managed toggle that forces caching on/off for every user. Only respected when set via system or MDM domains. |
| `UserCanAdjustCache` | Boolean | `false` | Enables the UI toggle controlling cache usage when the managed key is unset. |
| `UserCanAdjustCacheTTL` | Boolean | `false` | Allows menu-bar controls to alter cache TTL. |
| `DomainCacheRules` | Dictionary | `{}` | JSON-style rules that override caching per-domain (e.g., `{ "*.okta.com": {"action":"never"} }`). |
| `CacheBypassDomains` | Array<String> | `[]` | Hostnames that bypass the cache entirely (used for sensitive IDPs). |

### DNS Chain, Interface & Reliability

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `EnableDNSChainPreservation` | Boolean | `true` | Keeps upstream resolver order intact for VPN compatibility. |
| `EnableDNSInterfaceBinding` | Boolean | `false` | Enables the experimental interface binding engine. |
| `BindInterfaceStrategy` | String | `resolver_cidr` | One of `resolver_cidr`, `original_path`, or `active_resolver`. |
| `StickyInterfacePerTransaction` | Boolean | `true` | Forces request/response pairs to use the same network path. |
| `VPNResolvers` | Array<String> (CIDRs) | `[]` | Optional resolver CIDR list; when unset the binding engine injects the CGNAT range `100.64.0.0/10`, so add your VPN's ranges explicitly. |
| `MaxRetries` | Integer | `3` | Maximum DNS retry attempts per transaction. |
| `InitialBackoffMs` | Integer (ms) | `250` | Delay before the first retry; subsequent delays follow retry policy. |

### Browser / WebSocket Integration

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `EnableWebSocketServer` | Boolean | `true` | Toggles the WebSocket bridge used by browser extensions. |
| `WebSocketPort` | Integer | `8876` | Listening port inside the user session. |
| `WebSocketAuthToken` | String | `nil` | Optional shared secret browsers must present when connecting. |
| `WebSocketRetryBackoff` | Boolean | `true` | Enables exponential backoff when reconnecting to browsers. |
| `WebSocketRetryInterval` | Number (seconds) | `10` | Base reconnect delay (`kDNShieldWebSocketRetryIntervalKey`). Values ≤0 revert to the default. |
| `ChromeExtensionIDs` | Array<String> | `[]` | Allowed Chrome extension IDs. Moving this into preferences removed the Info.plist fallback; configure via managed prefs for enterprise deployments. |

### Telemetry & Logging

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `TelemetryEnabled` | Boolean | `true` | Master toggle for all telemetry emitters. |
| `TelemetryServerURL` | String | `nil` | HTTPS endpoint for Telemetry uploads or Splunk collectors. |
| `TelemetryHECToken` | String | `nil` | Splunk HEC token attached to uploads. |
| `TelemetryPrivacyLevel` | Integer | `1` | `0 = none`, `1 = hash IPs`, `2 = anonymize` before transport. |
| `VerboseTelemetry` | Boolean | `false` | Emits debug logs for every payload. |
| `LogLevel` | Integer | `1` | `0 = error`, `1 = info`, `2 = debug`. Applies to the daemon, extension, and app logs. |

### Security, Identity & Secrets

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `BypassPassword` | String | `nil` | Deprecated emergency bypass password. Clearing the key disables the UI entry point entirely. |
| `ClientIdentifier` | String | `""` | Optional host identifier presented to remote services. |
| `S3AccessKeyId` | String | `nil` | Legacy S3 credential used by `RuleSources` entries that point at buckets. |
| `S3SecretAccessKey` | String | `nil` | Companion secret for the access key; prefer temporary credentials distributed via manifests. |

### Miscellaneous & Legacy Keys

- `SoftwareRepoURL`, `RuleSources`, and `UpdateInterval` remain for older deployments that do not use manifests; new installations should prefer manifest-driven configuration.
- `Configuration` (NSKeyedArchive) is written by `ConfigurationManager` when the UI or CLI saves a profile. Use the Configuration window or `dnshield-ctl config`/`dnshield-ctl config set` instead of editing this blob manually.
- `AdditionalHttpHeaders`, `BlockedDomains`, `WhitelistedDomains`, and other list-type keys accept arrays/dictionaries encoded by `defaults` or configuration profiles. When editing with `defaults`, wrap JSON objects in single quotes so the shell does not strip braces.

## Scope Summary

- **User domain** (`~/Library/Preferences/com.dnshield.app`): menu-bar app writes here; best for experimentation or single-user overrides.
- **System domain** (`/Library/Preferences/com.dnshield.app`): requires sudo; affects every user unless overridden by MDM.
- **Managed domain** (`/Library/Managed Preferences/com.dnshield.app.plist`): highest priority; use configuration profiles/MDM.

Whenever you add or change a preference key in code, update this document to match.