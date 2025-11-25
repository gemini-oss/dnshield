# DNShield Cache Rules and Advanced Network Configuration

This document provides comprehensive guidance for configuring DNShield's caching system and advanced network settings for optimal performance and enterprise deployment.

## Table of Contents

- [Cache Configuration](#cache-configuration)
- [Advanced Network Settings](#advanced-network-settings)
- [Enterprise Configuration](#enterprise-configuration)

## Cache Configuration

### Overview

DNShield implements a three-tier caching system:

1. **Memory Cache**: Fast in-memory cache using NSCache
2. **Disk Cache**: Persistent disk-based cache for rule sets
3. **DNS Cache**: TTL-aware DNS response cache

### DNS Cache Settings

#### Basic Configuration

All DNS cache settings use the preference domain `com.dnshield.app`:

```bash
# Enable DNS caching (disabled by default for security)
defaults write ~/Library/Preferences/com.dnshield.app UserCanAdjustCache -bool YES

# Allow users to adjust cache TTL settings
defaults write ~/Library/Preferences/com.dnshield.app UserCanAdjustCacheTTL -bool YES
```

#### TTL Configuration

DNS cache Time-To-Live settings control how long responses are cached:

- **Default TTL**: 300 seconds (5 minutes)
- **Minimum TTL**: 30 seconds (cannot be set lower)
- **Maximum TTL**: 300 seconds (cannot be set higher for security)

```bash
# View current DNS cache settings
defaults read com.dnshield.app | grep -i cache
```

### Domain-Specific Cache Rules

Configure per-domain cache behavior using the `DomainCacheRules` preference:

#### Rule Format

```json
{
  "domain_pattern": {
    "action": "cache_action",
    "ttl": custom_ttl_seconds
  }
}
```

#### Available Cache Actions

- `"default"`: Uses standard 300-second TTL
- `"never"`: 0 seconds TTL (no caching) - recommended for authentication domains
- `"always"`: Maximum TTL (300 seconds)
- `"custom"`: Use specified TTL value

#### Example Configuration

```bash
# Configure domain-specific cache rules
defaults write ~/Library/Preferences/com.dnshield.app DomainCacheRules -dict \
  "*.okta.com" '{"action": "never"}' \
  "*.twingate.com" '{"action": "never"}' \
  "*.github.com" '{"action": "never"}' \
  "*.internal.company.com" '{"action": "always"}' \
  "*.cdn.example.com" '{"action": "custom", "ttl": 600}'
```

### Memory Cache Configuration

The DNS response cache size (10,000 entries) and TTL clamp (30–300 seconds) are hard-coded in the
extension. Instead of resizing the cache, tune `DomainCacheRules` for sensitive domains and disable
`EnableDNSCache` via managed preferences when caching must be off entirely.

```bash
# Override cache directory for enterprise deployments
defaults write ~/Library/Preferences/com.dnshield.app CacheDirectory -string "/var/cache/dnshield"
```

### Cache Bypass Configuration

Configure domains that should completely bypass all caching:

```bash
# Set domains to never cache (array of domain patterns)
defaults write ~/Library/Preferences/com.dnshield.app CacheBypassDomains -array \
  "*.okta.com" \
  "*.oktapreview.com" \
  "*.auth.company.com" \
  "login.microsoftonline.com"
```

## Advanced Network Settings

### DNS Server Configuration

#### Basic DNS Settings

```bash
# Set custom DNS servers (as array stored in the DNShield shared defaults)
sudo defaults write /Library/Preferences/com.dnshield.app DNSServers -array "1.1.1.1" "8.8.8.8"
```

Adjust per-flow timeouts through `/Library/Application Support/DNShield/config.json`:

```json
{
  "dnsServers": ["1.1.1.1", "8.8.8.8"],
  "dnsTimeout": 5.0
}
```

### Network Interface Binding

Control how DNShield selects network interfaces for DNS queries:

```bash
# Enable interface binding
defaults write ~/Library/Preferences/com.dnshield.app EnableDNSInterfaceBinding -bool YES

# Set binding strategy
defaults write ~/Library/Preferences/com.dnshield.app BindInterfaceStrategy -string "resolver_cidr"
```

#### Available Binding Strategies

- `"default"`: System's automatic interface selection
- `"resolver_cidr"`: Choose interface based on resolver IP range (recommended)
- `"interface_index"`: Use specific interface by system index
- `"adaptive"`: Dynamically select optimal interface

```bash
# Enable sticky interface per DNS transaction
defaults write ~/Library/Preferences/com.dnshield.app StickyInterfacePerTransaction -bool YES
```

### VPN and Network Compatibility

Configure VPN resolver ranges for proper routing:

```bash
# Configure VPN resolver IP ranges
defaults write ~/Library/Preferences/com.dnshield.app VPNResolvers -array \
  "100.64.0.0/10" \
  "fc00::/7" \
  "fd00::/8" \
  "fe80::/10"

# Enable DNS chain preservation for VPN compatibility
defaults write ~/Library/Preferences/com.dnshield.app EnableDNSChainPreservation -bool YES
```

### Connection Retry and Timeout Settings

Configure connection reliability settings:

```bash
# Set maximum DNS query retries (0-10)
defaults write ~/Library/Preferences/com.dnshield.app MaxRetries -int 3

# Set initial backoff delay in milliseconds (50-5000)
defaults write ~/Library/Preferences/com.dnshield.app InitialBackoffMs -int 250
```

### WebSocket Server Configuration

Configure the Chrome extension WebSocket server:

```bash
# Enable WebSocket server for Chrome extension
defaults write ~/Library/Preferences/com.dnshield.app EnableWebSocketServer -bool YES

# Set WebSocket server port (default: 8876)
sudo defaults write /Library/Preferences/com.dnshield.app WebSocketPort -int 8876
```

## Enterprise Configuration

### Manifest System Configuration

Configure centralized rule distribution:

```bash
# Set manifest server URL
sudo defaults write /Library/Preferences/com.dnshield.app ManifestURL -string "https://dns-rules.company.com/manifest"

# Set manifest update interval (seconds)
defaults write ~/Library/Preferences/com.dnshield.app ManifestUpdateInterval -int 300

# Configure authentication headers for manifest server
sudo defaults write /Library/Preferences/com.dnshield.app AdditionalHttpHeaders -dict \
  "Authorization" "Bearer your-api-token-here" \
  "X-Company-ID" "your-company-id"
```

### Update Strategy Configuration

Control how and when rules are updated:

```bash
# Set update strategy
sudo defaults write /Library/Preferences/com.dnshield.app updateStrategy -string "UpdateStrategyInterval"
```

#### Available Update Strategies

- `"UpdateStrategyInterval"`: Fixed intervals (default)
- `"UpdateStrategyScheduled"`: Specific times
- `"UpdateStrategyManual"`: On-demand only
- `"UpdateStrategyPush"`: Push notifications

### Enterprise Mode Configuration

Enable managed/enterprise mode:

```bash
# Enable managed mode (disables user control)
sudo defaults write /Library/Preferences/com.dnshield.app ManagedMode -bool YES

# Note: Enterprise configuration uses /Library/Application Support/DNShield/config.json
# This path is hardcoded and not configurable via preferences
```

### Telemetry Configuration

Configure telemetry and logging for enterprise monitoring:

```bash
# Enable telemetry
defaults write ~/Library/Preferences/com.dnshield.app TelemetryEnabled -bool YES

# Set telemetry server URL
defaults write ~/Library/Preferences/com.dnshield.app TelemetryServerURL -string "https://telemetry.company.com/dnshield"

# Set privacy level (0=None, 1=Hash IPs, 2=Full anonymization)
defaults write ~/Library/Preferences/com.dnshield.app TelemetryPrivacyLevel -int 1

# Set HEC token for Splunk integration
defaults write ~/Library/Preferences/com.dnshield.app TelemetryHECToken -string "your-hec-token"

# Enable verbose telemetry (for debugging)
defaults write ~/Library/Preferences/com.dnshield.app VerboseTelemetry -bool NO
```

### Network Performance

```bash
# Increase retries for unreliable networks
defaults write ~/Library/Preferences/com.dnshield.app MaxRetries -int 5

# Reduce initial backoff for faster retry
defaults write ~/Library/Preferences/com.dnshield.app InitialBackoffMs -int 100
```
