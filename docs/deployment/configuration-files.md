# Configuration File Examples

## MDM Configuration Profile

Create a configuration profile for MDM deployment:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.company.dnshield.config</string>
            <key>PayloadDisplayName</key>
            <string>DNShield Configuration</string>
            <key>PayloadDescription</key>
            <string>Enterprise DNShield Configuration</string>
            <key>PayloadUUID</key>
            <string>12345678-1234-1234-1234-123456789012</string>
            <key>PayloadEnabled</key>
            <true/>
            <key>PayloadOrganization</key>
            <string>Company Name</string>
            <key>com.dnshield.app</key>
            <dict>
                <key>Forced</key>
                <array>
                    <dict>
                        <key>mcx_preference_settings</key>
                        <dict>
                            <key>ManagedMode</key>
                            <true/>
                            <key>ManifestURL</key>
                            <string>https://dns-rules.company.com/manifest</string>
                            <key>EnableDNSCache</key>
                            <false/>
                            <key>EnableDNSInterfaceBinding</key>
                            <true/>
                        </dict>
                    </dict>
                </array>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

## Local Config JSON

Create `/Library/Application Support/DNShield/config.json` with the small set of fields that the
daemon consumes before reading managed preferences:

```json
{
  "dnsServers": ["1.1.1.1", "8.8.8.8"],
  "dnsTimeout": 5.0,
  "autoStart": true,
  "updateInterval": 3600,
  "logLevel": "info",
  "allowRuleEditing": false
}
```

All other knobs (manifest URL, telemetry, cache options, Chrome WebSocket credentials, etc.) belong
in the `com.dnshield.app` preference domain so the network extension, daemon, and menu bar app stay
in sync.
