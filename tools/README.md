# DNShield Tools

Unified tools for DNShield management, including manifest generation and migration utilities.

## Structure

```
tools/
├── cmd/                      # Go utilities
│   ├── manifest-editor/      # Web manifest editor (Go + static assets)
│   └── watchdog/             # /etc/hosts watchdog (Go)
├── internal/                 # Shared Go libs for generators/migrations
├── nesi/                     # Network Extension Status Inspector (Objective-C)
└── README.md                 # This guide
```

> `dnshield-ctl` now lives under `dnshield/CTL/` alongside the Xcode sources. Build it with
> `make ctl` from the repository root.

## Manifest Generator

The manifest generator creates device-specific DNS filtering manifests based on machine information from Jamf and department memberships from Okta.

### Usage

```bash
cd tools/cmd/manifests
go run . [options]

Options:
  -manifests-dir string
        Directory to output machine manifests (e.g., "manifests/machines")
  -jamf-url string
        Jamf Pro server URL
  -jamf-client-id string
        Jamf Pro OAuth2 Client ID
  -jamf-client-secret string
        Jamf Pro OAuth2 Client Secret
  -okta-domain string
        Okta domain (e.g., example.okta.com)
  -okta-client-id string
        Okta OAuth2 Client ID
  -okta-client-secret string
        Okta OAuth2 Client Secret
  -okta-private-key string
        Okta OAuth2 Private Key (PEM format)
  -okta-private-key-id string
        Okta OAuth2 Private Key ID
  -verbose
        Enable verbose logging
  -dry-run
        Show what would be done without making changes
```

### Environment Variables

The tool supports environment variables as alternatives to command-line flags:

- `JAMF_URL` - Jamf Pro server URL (also supports `JAMF_PRO_URL` for compatibility)
- `JAMF_CLIENT_ID` - Jamf Pro OAuth2 Client ID (also supports `JAMF_PRO_CLIENT_ID` and `JAMF_PRO_API_USER` for compatibility)
- `JAMF_CLIENT_SECRET` - Jamf Pro OAuth2 Client Secret (also supports `JAMF_PRO_CLIENT_SECRET` and `JAMF_PRO_API_PASSWORD` for compatibility)
- `OKTA_DOMAIN` - Okta domain, e.g., `example.okta.com`
- `OKTA_CLIENT_ID` - Okta OAuth2 Client ID
- `OKTA_CLIENT_SECRET` - Okta OAuth2 Client Secret
- `OKTA_PRIVATE_KEY` - Okta OAuth2 Private Key in PEM format (optional, can also be loaded from `priv.pem` file)
- `OKTA_PRIVATE_KEY_ID` - Okta OAuth2 Private Key ID (also supports `OKTA_KID` for compatibility)

### Generated Manifests

Each manifest includes:

- Global allowlist and blocklist rules
- Department-specific rules (if applicable)
- Company-wide base rules
- Combined phishing protection rules

Example manifest paths:

- `includes/global/allowlist`
- `includes/global/blocklist`
- `includes/team/[department]`
- `includes/company/base`
- `includes/phishing/combined`

## API Clients

### Jamf Client

- Supports OAuth2 authentication (recommended)
- Retrieves computer information including serial numbers, hostnames, and usernames
- Located in `tools/jamf/`

### Okta Client  

- Supports API token authentication
- Retrieves group memberships and user information
- Maps users to departments based on group membership
- Located in `tools/okta/`

## Building

### Using Make

```bash
# Build all tools
make build

# Build specific tool
make build-manifests

# Install to /usr/local/bin
make install
```

### Manual Build

```bash
# Build manifest generator
cd tools/cmd/manifests
go build -o dnshield-manifests
```

## Running

### Using Make

```bash
# Run manifest generator
make run-manifests

# Run with arguments
make run-manifests ARGS="-dry-run -verbose"

# Quick dry-run test
make dry-run

# Check environment variables
make check-env
```

### Direct Execution

```bash
# Run in dry-run mode to test without making changes
cd tools/cmd/manifests
go run . -dry-run -verbose

# Test with specific credentials
go run . \
  -jamf-url="https://your-instance.jamfcloud.com" \
  -jamf-client-id="your-jamf-oauth2-client-id" \
  -jamf-client-secret="your-jamf-oauth2-client-secret" \
  -okta-domain="your-org.okta.com" \
  -okta-client-id="your-okta-oauth2-client-id" \
  -okta-client-secret="your-okta-oauth2-client-secret" \
  -dry-run

# Or using environment variables
export JAMF_URL="https://your-instance.jamfcloud.com"
export JAMF_CLIENT_ID="your-jamf-oauth2-client-id"
export JAMF_CLIENT_SECRET="your-jamf-oauth2-client-secret"
export OKTA_DOMAIN="your-org.okta.com"
export OKTA_CLIENT_ID="your-okta-oauth2-client-id"
export OKTA_CLIENT_SECRET="your-okta-oauth2-client-secret"
go run . -dry-run
```

## Development

```bash
# Setup development environment
make setup

# Format code
make fmt

# Run tests
make test

# Run tests with coverage
make test-coverage

# Tidy dependencies
make tidy

# Run linter
make lint

# Clean build artifacts
make clean
```

## Make Targets

Run `make help` to see all available targets:

- `build` - Build all binaries
- `run-manifests` - Run manifest generator
- `run-migration` - Run migration tool
- `dry-run` - Quick dry-run test
- `test` - Run tests
- `fmt` - Format code
- `lint` - Run linter
- `install` - Install to system
- `clean` - Clean artifacts
- `help` - Show help

## Exclusions

The following machine types are automatically excluded from manifest generation:

- Template machines
- Configuration workstations
- System/service machines
- Any machine with "template" in the serial number

Additional exclusions can be configured in the `shouldExclude` function in `generator.go`.
