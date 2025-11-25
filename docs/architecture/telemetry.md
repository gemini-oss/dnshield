# DNShield Telemetry Integration

DNShield includes telemetry support for sending DNS filtering events and health metrics to Splunk via HTTP Event Collector (HEC). The Network Extension queues events, batches them every 60 seconds, and streams them directly to the configured HEC endpoint.

## Architecture

### Components

1. **DNSShieldTelemetry** - Core telemetry client that handles:

   - Event batching and transmission to Splunk HEC
   - Privacy controls for PII anonymization
   - Automatic retry with exponential backoff and disk buffering
   - Performance optimization with 60-second flush intervals using dispatch timers

2. **Event Types** - Event logging for:

   - DNS query events (blocked/allowed/failed)
   - Cache performance metrics
   - Rule update notifications
   - Extension lifecycle events
   - Security violations

3. **Privacy Controls** - Three levels of privacy:
   - Level 0: No anonymization (full data)
   - Level 1: Hash IP addresses (default)
   - Level 2: Full anonymization (redact all PII)

## Configuration

### Preference Keys

Configure telemetry via managed preferences or defaults:

```bash
# Enable telemetry
sudo defaults write /Library/Preferences/com.dnshield.app TelemetryEnabled -bool YES

# Set Splunk HEC endpoint URL
sudo defaults write /Library/Preferences/com.dnshield.app TelemetryServerURL -string "https://splunk.example.com:8088/services/collector/raw"

# Set privacy level (0-2)
sudo defaults write /Library/Preferences/com.dnshield.app TelemetryPrivacyLevel -int 1
```

### MDM Configuration Profile

For enterprise deployment via MDM:

```xml
<dict>
    <key>PayloadType</key>
    <string>com.dnshield.app</string>
    <key>PayloadContent</key>
    <dict>
        <key>TelemetryEnabled</key>
        <true/>
        <key>TelemetryServerURL</key>
        <string>https://splunk.example.com:8088/services/collector/raw</string>
        <key>TelemetryPrivacyLevel</key>
        <integer>1</integer>
    </dict>
</dict>
```

## Event Schema

### DNS Query Event

```jsonc
{
  "sourcetype": "macos:dnshield",
  "event": {
    "dnshield_data": {
      "timestamp": "2024-01-15T10:30:45.123Z",
      "event_type": "dns_query",
      "hostname": "tracker.example.com",
      "action": "blocked",
      "rule_id": "rule_12345",
      "rule_source": "manifest",
      "threat_category": "tracker",
      "client_app": "com.apple.Safari",
      "process_name": "Safari",
      "query_type": "A",
      "cache_hit": false,
      "response_time_ms": 2.5,
      "dns_response_code": "NOERROR",
      "source_ip": "a1b2c3d4", // Hashed
      "serial_number": "C02XX1234567",
      "extension_version": "1.1.94",
      "device_hostname": "mac-01",
      "manifest_url": "https://manifests.company.com/main.plist"
    }
  }
}
```

### Cache Performance Event

```jsonc
{
  "sourcetype": "macos:dnshield",
  "event": {
    "dnshield_data": {
      "timestamp": "2024-01-15T10:30:45.123Z",
      "event_type": "cache_performance",
      "cache_type": "dns_response_cache",
      "hit_rate": 0.85,
      "eviction_count": 0,
      "memory_usage_mb": 45,
      "total_queries": 15678,
      "queries_per_second": 25,
      "avg_lookup_time_ms": 0.5,
      "fastest_lookup_ms": 0.1,
      "slowest_lookup_ms": 10.2,
      "slow_query_count": 3
    }
  }
}
```

### Rule Update Event

```jsonc
{
  "sourcetype": "macos:dnshield",
  "event": {
    "dnshield_data": {
      "timestamp": "2024-01-15T10:30:45.123Z",
      "event_type": "rule_update",
      "manifest_id": "default",
      "rules_added": 5000,
      "rules_removed": 4800,
      "total_rules": 50000,
      "update_source": "manifest",
      "cache_cleared": true
    }
  }
}
```

## Splunk Queries

### Top Blocked Domains

```spl
index=endpoint_telemetry sourcetype="macos:dnshield" event_type="dns_query" action="blocked"
| stats count by hostname
| sort -count
| head 20
```

### Security Threats by Category

```spl
index=endpoint_telemetry sourcetype="macos:dnshield" threat_category=*
| timechart span=1h count by threat_category
```

### Cache Performance Over Time

```spl
index=endpoint_telemetry sourcetype="macos:dnshield" event_type="cache_performance"
| timechart span=5m avg(hit_rate) as "Hit Rate", avg(queries_per_second) as QPS
```

### DNS Query Volume by Application

```spl
index=endpoint_telemetry sourcetype="macos:dnshield" event_type="dns_query"
| stats count by client_app
| sort -count
```

### Extension Health Monitoring

```spl
index=endpoint_telemetry sourcetype="macos:dnshield" event_type="extension_lifecycle"
| stats latest(timestamp) as last_seen by serial_number
| eval minutes_ago=round((now()-strptime(last_seen,"%Y-%m-%dT%H:%M:%S.%3NZ"))/60,2)
| where minutes_ago > 10
```

## Testing

To validate your configuration without production traffic, temporarily enable telemetry and trigger
events locally (for example, block a known domain or force a rule sync). Monitor `FlowTelemetry` and
`Telemetry` log categories while watching the Splunk index.

## Implementation Details

### Timer Management

- Uses dispatch_source timers instead of NSTimer for reliable background operation
- Timer runs on dedicated serial queue to avoid blocking DNS operations
- 60-second flush interval with 10-second leeway for power efficiency

### Retry Logic

- Failed events are buffered to disk for persistence across restarts
- Exponential backoff with jitter (2s, 4s, 8s, 16s, 32s) up to 5 attempts
- Maximum 5-minute retry delay to prevent excessive resource usage
- Buffer limited to 1000 events to prevent disk overflow

### Server URL Resolution

- Managed or system preferences (`com.dnshield.app`) provide `TelemetryServerURL` and `TelemetryHECToken`.
- Defaults are empty, so telemetry stays disabled until both values are configured.
