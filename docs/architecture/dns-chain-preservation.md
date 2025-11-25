# DNS Chain Preservation

When the DNS proxy network extension intercepts queries it normally forwards them to the configured
public resolvers (for example, `1.1.1.1`). That breaks corporate/VPN DNS chains because replies that
should have come from the original resolver never reach the proxy. The result is consistent
`NXDOMAIN` or timeouts for internal domains.

DNShield ships with **DNS chain preservation** enabled by default so that queries originating from a
DNS server continue along their original path. The logic is implemented in
`dnshield/Extension/ProxyProvider/FlowManagement.m` (`forwardDNSQuery:`) and controlled by the
preferences `EnableDNSChainPreservation` and `VPNResolvers` (declared in
`dnshield/Common/DNShieldPreferences.m`).

## How the Extension Detects DNS Servers

1. The proxy inspects the **source endpoint** of every flow. If the source port is `53`, the flow is
   treated as a DNS server and DNShield forwards the query back to that IP.
2. If the source port is not `53`, DNShield compares the source IP against the configured
   `VPNResolvers` CIDR list. When the IP falls inside one of those ranges (for example
   `100.64.0.0/10`), the proxy still forwards the query back to that resolver to keep the chain
   intact.
3. When no match occurs, the proxy continues to use the standard upstream DNS list (`DNSServers`).

| Preference Key               | Purpose                                               | Default                             |
| ---------------------------- | ----------------------------------------------------- | ----------------------------------- |
| `EnableDNSChainPreservation` | Master toggle read from `PreferenceManager`           | `true`                              |
| `VPNResolvers`               | Array of CIDR strings used when the source port != 53 | `["100.64.0.0/10","fc00::/7", ...]` |

## Configuration

All settings live under `com.dnshield.app` and can be managed via MDM or `defaults`.

```bash
# Ensure chain preservation stays enabled (default)
sudo defaults write /Library/Preferences/com.dnshield.app EnableDNSChainPreservation -bool YES

# Override the VPN resolver ranges (optional)
sudo defaults write /Library/Preferences/com.dnshield.app VPNResolvers -array \
  "100.95.0.0/16" \
  "10.10.0.0/16"
```

Restart the proxy to apply changes:

```bash
sudo dnshield-ctl restart
```

## Decision Flow

```text
1. Receive DNS query
2. Extract source endpoint (IP + port)
3. If source port == 53 -> forward to that IP
4. Else if IP is in VPNResolvers -> forward to that IP
5. Else -> use configured upstream DNS list
```

Forwarded queries set `enforceOriginalResolver = YES`, which prevents failover to public DNS if the
VPN resolver is briefly unavailable; the proxy retries the original resolver instead. This mirrors
the code path in `FlowManagement.m` that calls `getOrCreateUpstreamConnectionForServer:` with the
captured resolver.

## Observability

Chain-preservation messages log under the `network` category. The extension appends its build
version to the subsystem (for example `com.dnshield.extension:187`), so use `BEGINSWITH` to match the
prefix instead of equality:

```bash
log show --predicate 'subsystem BEGINSWITH "com.dnshield.extension" && category == "network"' \
        --last 5m --info | grep "DNS chain preservation"
```

Example log:

```text
DNShield[Extension] DNS chain preservation: Query from DNS server 100.95.0.251, forwarding back to preserve chain
```

## Verification Workflow

1. Enable verbose logging temporarily:

   ```bash
   sudo defaults write /Library/Preferences/com.dnshield.app LogLevel -int 2
   sudo dnshield-ctl restart
   ```

2. Trigger DNS lookups from your VPN by resolving an internal hostname.
3. Confirm that the log output shows `forwarding back to preserve chain` and that the lookup succeeds.
4. Restore the previous log level when finished:

   ```bash
   sudo defaults delete /Library/Preferences/com.dnshield.app LogLevel
   sudo dnshield-ctl restart
   ```

## Troubleshooting

- **Still getting NXDOMAIN**  
  Verify that the VPN resolver IP is included in `VPNResolvers`. If not, add the CIDR and restart.

- **Chain preservation disabled**  
  Managed preferences can override the toggle. Run
  `defaults read /Library/Managed\ Preferences/com.dnshield.app EnableDNSChainPreservation` to check.

- **No logs**  
  Make sure you include `--info` in the `log show` command; chain-preservation messages are Info
  level.

Chain preservation is on by default because it protects the most fragile DNS topologies with no additional configuration. Only override the defaults if your environment requires a tighter IP list for VPN resolvers.
