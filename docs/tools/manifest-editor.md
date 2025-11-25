# DNShield Manifest Editor

The DNShield Manifest Editor is a web-based tool for managing DNS filtering manifests and rule assignments. It provides an intuitive interface for searching users, machines, and groups, editing their manifest assignments, and creating pull requests for changes.

## Overview

The manifest editor operates on the principle of centralized DNS rule management through JSON manifest files. Each machine, user, or group can have specific DNS filtering rules assigned through these manifests, which are then distributed to DNShield clients.

### Key Concepts

- **Manifests**: JSON files containing DNS rule assignments
- **Entities**: Users, machines, or groups that can have manifests assigned
- **Rule Categories**: Organized collections of DNS rules (team, group, global, domain, phishing)
- **Inheritance**: Manifests can include other manifests, creating hierarchical rule structures

## Installation and Setup

### Download

The manifest-editor tool is available as a signed binary in DNShield releases:

```bash
# Download from GitHub releases
curl -L -o manifest-editor.zip https://github.com/your-org/dnshield/releases/latest/download/manifest-editor.zip

# Extract the binary
unzip manifest-editor.zip

# Verify the signature (macOS)
codesign --verify --verbose manifest-editor
```

### Running the Tool

```bash
# Start the server
./manifest-editor

# The server will output:
# DNShield Manifest Editor Server
# Base directory: /path/to/your/repo
# Manifests directory: /path/to/your/repo/manifests
# Server running at: http://localhost:7777
# Open http://localhost:7777/index.html in your browser
```

### Authentication (GitHub App On Behalf Of User)

To create PRs as the signed-in user, the Manifest Editor uses the GitHub App web application flow:

- Configure your GitHub App with a User authorization callback URL of:
  - `http://localhost:7777/api/auth/callback`
- Provide the App OAuth client credentials via environment variables:
  - `GH_APP_CLIENT_ID` (or `GH_CLIENT_ID`)
  - `GH_APP_CLIENT_SECRET` (or `GH_CLIENT_SECRET`)

When you click “Sign in with GitHub” in the UI, you’ll be redirected to GitHub to authorize the app. After signing in, the tool uses your user access token to create branches, commits, and pull requests on your behalf.

Notes:
- The app must have the appropriate repository permissions (e.g., contents: write, pull_requests: write) and be installed in the target org/repo.
- For GitHub Enterprise, set `GITHUB_API_BASE` if needed (e.g., `https://github.company.com/api/v3`).

### Repository Structure

The tool expects to be run from a repository with this structure:

```
your-repo/
├── manifests/
│   ├── includes/
│   │   ├── team/
│   │   │   ├── fte-security.json
│   │   │   └── fte-engineering.json
│   │   ├── group/
│   │   │   └── social-media-allow.json
│   │   ├── global/
│   │   │   ├── global-allowlist.json
│   │   │   └── global-blocklist.json
│   │   ├── domain/
│   │   │   ├── okta-allowlist.json
│   │   │   └── twingate-allowlist.json
│   │   └── phishing/
│   │       └── phishing-domains.json
│   ├── MACHINE123.json
│   ├── MACHINE456.json
│   └── default.json
└── tools/
    └── cmd/
        └── manifest-editor/
            └── manifest-editor
```

## Features

### Entity Search

The tool provides comprehensive search capabilities:

#### User Search

- Search by username or email address
- Supports partial matching
- Returns associated machine serial numbers
- Handles users with multiple machines

#### Machine Search

- Search by machine serial number
- Direct manifest file lookup
- Shows machine-specific configurations

#### Group Search

- Search team manifests (e.g., "fte-security")
- Search group manifests (e.g., "social-media-allow")
- Browse available rule categories

### Manifest Management

#### Viewing Manifests

- Load and display current manifest assignments
- Show inherited manifests (rules from included manifests)
- Real-time validation of manifest structure
- Visual indication of rule inheritance hierarchy

#### Editing Manifests

- Add/remove manifest assignments
- Drag-and-drop interface for rule management
- Auto-completion for available manifests
- Prevents assignment of already-inherited rules

#### Available Rule Categories

The tool organizes rules into categories:

- **Team**: Organization-specific rules (e.g., `fte-security`, `fte-engineering`)
- **Group**: Department or role-based rules (e.g., `social-media-allow`)
- **Global**: System-wide rules (`global-allowlist`, `global-blocklist`)
- **Domain**: Service-specific allowlists (`okta-allowlist`, `twingate-allowlist`)
- **Phishing**: Security-focused blocking rules

### Pull Request Integration

The tool integrates with GitHub for change management:

#### Prerequisites

- GitHub CLI (`gh`) must be installed
- Repository must be a Git repository with GitHub remote
- User must be authenticated with GitHub (`gh auth login`)

#### Creating Pull Requests

1. Make changes to manifests using the web interface
2. Fill in pull request details:
   - Branch name (auto-generated or custom)
   - Title describing the changes
   - Description with rationale
3. Tool automatically:
   - Creates a new branch
   - Commits the changes
   - Creates a GitHub pull request
   - Links back to the PR for review

## Web Interface Guide

### Main Dashboard

The web interface provides:

- **Search Bar**: Enter usernames, emails, machine serials, or group names
- **Entity Type Selector**: Choose between user, machine, or group search
- **Search Results**: Display matching entities with quick access to manifests

### Manifest Editor

When editing a manifest:

1. **Current Assignments**: Shows directly assigned manifests
2. **Available Manifests**: Filtered list of assignable rules
3. **Inherited Rules**: Read-only display of rules from included manifests
4. **Add/Remove Buttons**: Modify manifest assignments
5. **Save Changes**: Persist changes to the manifest file

### Pull Request Creation

The PR creation dialog includes:

- **Branch Name**: Auto-generated or customizable
- **Title**: Descriptive title for the change
- **Description**: Detailed explanation of the changes
- **File Preview**: Shows which manifest file will be modified

## API Reference

The tool exposes a REST API for programmatic access:

### Search Endpoint

```http
POST /api/search
Content-Type: application/json

{
  "type": "user|machine|group",
  "query": "search-term"
}
```

### Manifest Endpoint

```http
GET /api/manifests/{file-path}
PUT /api/manifests/{file-path}
Content-Type: application/json

{
  "manifests": ["rule1", "rule2", "rule3"]
}
```

### Available Manifests

```http
GET /api/manifests/available?entity={file-path}
```

### Pull Request Creation

```http
POST /api/pull-request
Content-Type: application/json

{
  "branch": "branch-name",
  "title": "PR Title",
  "description": "PR Description",
  "file": "manifest-file.json"
}
```

### Health Check

```http
GET /api/health
```

## Configuration

The tool automatically detects the repository structure and manifest directory. Configuration is minimal:

### Environment Variables

- **PORT**: Server port (default: 7777)
- **MANIFESTS_DIR**: Override manifest directory path

### Repository Detection

The tool walks up the directory tree from the current working directory to find:

1. A directory containing a `manifests/` subdirectory
2. Falls back to the current working directory

## Troubleshooting

### Common Issues

#### Tool Won't Start

```bash
# Check if port is already in use
lsof -i :7777

# Run with different port
PORT=8888 ./manifest-editor
```

#### Repository Not Found

```bash
# Ensure you're in a directory with manifests/ folder
ls manifests/

# Or run from the repository root
cd /path/to/your/repo
./path/to/manifest-editor
```

#### GitHub Integration Issues

##### Authentication Error

```bash
# Authenticate with GitHub CLI
gh auth login

# Verify authentication
gh auth status
```

##### Branch Already Exists

- Use a different branch name in the PR creation dialog
- Or delete the existing branch: `git branch -D branch-name`

##### No Changes Detected

- Ensure you've saved changes in the web interface
- Check that the manifest file has been modified: `git status`

### Debug Mode

Enable verbose logging:

```bash
# Run with debug output
./manifest-editor 2>&1 | tee manifest-editor.log
```

### Network Issues

#### Can't Access Web Interface

- Check firewall settings for port 7777
- Verify the tool is running: `ps aux | grep manifest-editor`
- Try accessing via IP: `http://127.0.0.1:7777`

#### CORS Errors

- The tool sets permissive CORS headers for development
- For production use, consider reverse proxy with proper CORS configuration

## Security Considerations

### Code Signing

The binary is code-signed with Apple's Developer ID for macOS distribution.

### Network Security

- Tool runs on localhost by default
- No external network access required (except for GitHub integration)
- All manifest operations are local file system operations

### Git Integration

- Uses system `git` and `gh` commands
- Inherits user's Git configuration and credentials
- No credential storage in the tool itself

## Development

### Building from Source

```bash
cd tools/cmd/manifest-editor
go build -o manifest-editor server.go
```

### Dependencies

- Go 1.21+
- Embedded static files (HTML, CSS, JS)
- Standard library only (no external dependencies)

### Testing

```bash
# Run the test server
go run server.go

# Test API endpoints
curl -X POST http://localhost:7777/api/search \
  -H "Content-Type: application/json" \
  -d '{"type":"user","query":"john"}'
```
