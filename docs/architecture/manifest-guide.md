# DNShield Manifest System Guide

This guide documents how the Network Extension discovers, downloads, and evaluates manifests. It is
based on the current Objective-C implementation (`DNSManifestResolver`, `DNSManifest`, and
`RuleManager+Manifest`) rather than historical plans.

## Overview

A manifest is a JSON/YAML/plist document that defines:

- Which **rule sources** to synchronize (remote JSON lists, local files, etc.).
- Inline **managed rules** that are always applied.
- Optional **conditional items** that include other manifests, toggle rule sources, or add rules
  when a predicate evaluates to `true`.

The resolver performs the following steps each time a manifest refresh is requested:

1. Determine the initial **client identifier** (tries `ClientIdentifier`, then legacy
   `ManifestIdentifier`, then serial number, and finally literal `default`).
2. Build a fallback list `[initialIdentifier, serial (if different), "default"]`.
3. Download the manifest for the first identifier that succeeds, using the preferred file extension.
4. Cache each manifest under `/Library/Application Support/DNShield/manifest_cache/`.
5. Parse the manifest (format auto-detected), validate it, and recursively fetch included manifests.
6. Evaluate `conditional_items` using the current `DNSEvaluationContext`.
7. Merge `managed_rules` and `rule_sources` into a single resolved manifest and hand it to the
   `RuleManager`.

If the device is offline the resolver serves the most recent cached manifest.

## Resolution Pipeline

### Identifier Selection

1. `ClientIdentifier` preference (`defaults write /Library/Preferences/com.dnshield.app ClientIdentifier "finance-lab-01"`).
2. Legacy `ManifestIdentifier` preference.
3. Device serial number (`IOPlatformSerialNumber`).
4. Literal `default`.

The selected identifier is also written into the fallback chain so the resolver never gets stuck on a
missing manifest-if `finance/mbp-01` is missing, the resolver automatically tries
`C02XXXXXXX` and then `default`. There is a `DefaultManifestIdentifier` preference defined in
`DNShieldPreferences`, but the resolver currently ignores it and always falls back to the literal
string `"default"`.

### Manifest Base URL and Format

- `ManifestURL` (preferred) or `SoftwareRepoURL` define the HTTP base URL.
- The extension appends `/identifier.<ext>` where `<ext>` is:
  - `.json` by default.
  - `.plist` or `.yml` when `ManifestFormat` is set to `plist` or `yml`.

If an HTTP base URL is not configured the resolver searches locally in:

```text
/Library/Application Support/DNShield/manifests/
~/Library/Application Support/DNShield/manifests/
<BundleResources>/manifests/
```

### Authentication Headers

`AdditionalHttpHeaders` (array of `"Header: Value"` strings in `com.dnshield.app`) is applied to
every download. The HTTP fetcher also supports `authType` and `authCredentials` inside a rule
source's `configuration`, but most deployments rely on the global header array.

### Caching

- Cache root: `/Library/Application Support/DNShield/manifest_cache/`
- Each identifier creates a folder; nested identifiers such as `includes/team/mac` are stored in
  subdirectories.
- Entries expire 5 minutes after download (`_cacheTimeout = 300` seconds). Expired entries are removed automatically.
- The manifest viewer in the macOS app reads directly from this cache.

## Configuring Delivery

| Preference Key              | Purpose                                            | Default            |
| --------------------------- | -------------------------------------------------- | ------------------ |
| `ManifestURL`               | HTTPS base URL for manifests                       | `nil`              |
| `ManifestFormat`            | `json`, `plist`, or `yml` for the file extension   | `json`             |
| `ManifestUpdateInterval`    | Seconds between automatic refreshes                | `300` (5 minutes)  |
| `ClientIdentifier`          | Overrides the identifier lookup                    | unset              |
| `DefaultManifestIdentifier` | Reserved (not read; resolver falls back to `default`) | `global-allowlist` |
| `AdditionalHttpHeaders`     | Array of `Header: Value` strings for every request | unset              |

Example profile snippet:

```xml
<key>ManifestURL</key>
<string>https://manifests.company.com/</string>
<key>ManifestFormat</key>
<string>json</string>
<key>AdditionalHttpHeaders</key>
<array>
  <string>Authorization: Bearer ${DNShieldManifestToken}</string>
  <string>X-Org-ID: company-prod</string>
</array>
<key>ManifestUpdateInterval</key>
<integer>600</integer>
<key>ClientIdentifier</key>
<string>%SerialNumber%</string>
```

To test quickly without MDM:

```bash
sudo defaults write /Library/Preferences/com.dnshield.app ManifestURL "https://manifests.company.com/"
sudo defaults write /Library/Preferences/com.dnshield.app AdditionalHttpHeaders -array \
  "Authorization: Basic $(printf 'user:pass' | base64)"
sudo dnshield-ctl restart
```

## Manifest Schema

Supported top-level keys:

| Key                  | Type                | Notes                                                        |
| -------------------- | ------------------- | ------------------------------------------------------------ |
| `manifest_version`   | String              | Currently `1.0`. Required.                                   |
| `identifier`         | String              | Used in logs/cache. Required.                                |
| `display_name`       | String              | Optional human-friendly label.                               |
| `included_manifests` | `[String]`          | Relative identifiers such as `includes/global/base`.         |
| `rule_sources`       | `[RuleSource]`      | See the next section for the exact structure.                |
| `managed_rules`      | Dictionary          | Keys `block` and `allow`, each an array of domains.          |
| `conditional_items`  | `[ConditionalItem]` | Optional; applies rule sources/includes based on predicates. |
| `metadata`           | Dictionary          | Arbitrary data (author, description, last_modified, etc.).   |

### Example (JSON)

```json
{
  "manifest_version": "1.0",
  "identifier": "includes/team/infra",
  "display_name": "Infrastructure Team",
  "included_manifests": ["includes/global/base", "includes/security/baseline"],
  "managed_rules": {
    "block": ["*.coin-miner.tld", "rogue.example.com"],
    "allow": ["*.trusted-partner.com"]
  },
  "conditional_items": [
    {
      "condition": "network_location == 'office' AND vpn_connected == NO",
      "included_manifests": ["includes/policy/on-prem"]
    }
  ],
  "metadata": {
    "author": "Security Team",
    "last_modified": "2025-10-01T12:30:00Z"
  }
}
```

## Rule Sources

Only two types are currently supported:

| `type`  | Required Fields | Notes                                                              |
| ------- | --------------- | ------------------------------------------------------------------ |
| `https` | `url`           | Uses `HTTPRuleFetcher`; inherits `customHeaders`, `authType`, etc. |
| `file`  | `path`          | Reads a local file-useful for development or baked-in manifests.   |

Common properties:

- `id` / `identifier`: Stable identifier used in logs and the macOS UI.
- `format`: `json`, `yaml`/`yml`, or `plist`. Determines which parser `DNSRuleParser` uses.
- `priority`: Higher numbers override lower ones during rule merging (default `100`).
- `updateInterval`: Seconds between refreshes for this source (default `300`).
- `enabled`: Boolean toggle.
- `configuration`: Passed verbatim to the fetcher. Supported keys include:
  - `authType`: `basic`, `bearer`, or `apikey`.
  - `authCredentials`: `username/password`, `token`, or `apiKey`.
  - `headers`: dictionary of request headers.
  - `validateSSL`, `pinnedCertificates`, `followRedirects`, etc. (see `HTTPRuleFetcher`).

## Conditional Items and Predicate Context

Each entry inside `conditional_items` contains:

- `condition` (required): NSPredicate-format string evaluated against `DNSEvaluationContext`.
- `managed_rules`, `rule_sources`, and/or `included_manifests`: at least one action must be present.
- Optional metadata such as `priority`.

Predicate context variables populated by the extension:

| Category | Variables                                                                           |
| -------- | ----------------------------------------------------------------------------------- |
| Time     | `time_of_day` (`HH:mm`), `day_of_week`, `is_weekend`, `current_date` (`YYYY-MM-DD`) |
| System   | `os_version`, `device_type` (laptop/desktop/unknown), `device_model`                |
| Network  | `network_location`, `network_ssid`, `vpn_connected`, `vpn_identifier`               |
| User     | `user_group`, `device_identifier`, `security_score`                                 |
| Custom   | Any key/value injected via `updateManifestContext:`                                 |

Helper functions are translated before evaluation:

- `is_business_hours()` -> `(time_of_day >= "09:00" AND time_of_day <= "17:00" AND is_weekend == NO)`
- `is_weekday()` -> `is_weekend == NO`

Example conditional item:

```json
{
  "condition": "vpn_connected == YES AND network_location == 'twingate'",
  "managed_rules": {
    "allow": ["*.corp.local"]
  }
}
```

`managed_rules` currently supports the `allow` and `block` keys. Entries are deduplicated as they are
merged.

## Operations and Troubleshooting

### Forcing a Refresh

- Use the menu bar action **Rules -> Sync Rules**.
- Or restart the daemon from Terminal to force the resolver to re-download manifests:

  ```bash
  sudo dnshield-ctl restart
  tail -f /Library/Logs/DNShield/daemon.stdout.log
  ```

### Inspecting the Cache

```bash
ls "/Library/Application Support/DNShield/manifest_cache"
plutil -p "/Library/Application Support/DNShield/manifest_cache/<identifier>.json"
```

### Watching Logs

```text
log show --predicate '(subsystem == "com.dnshield.extension") AND (category == "RuleFetching" OR category == "RuleParsing")' --info --last 10m
```

### Validating Headers

```bash
defaults read /Library/Preferences/com.dnshield.app AdditionalHttpHeaders
```
