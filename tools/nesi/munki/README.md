# DNShield Munki Conditional Script

`nesi-status.go` wraps the Network Extension Status Inspector (`/opt/dnshield/nesi`) and prints JSON Munki can consume from a Conditional Item script. Build it (`go build -o /usr/local/bin/nesi-status ./nesi-status.go`), deploy the binary, and then call it inside `ConditionalItems` to emit a key named `dnshield_proxy` with one of `enabled`, `disabled`, or `nesi_not_installed`.

## Example Conditional Items snippet

```bash
#!/bin/bash
/usr/local/bin/nesi-status | /usr/bin/awk -F'"' '/dnshield_proxy/ {print "dnshield_proxy=" $4}'
```

That key can gate Munki manifests so certain payloads only install when DNShield’s DNS proxy is active.
