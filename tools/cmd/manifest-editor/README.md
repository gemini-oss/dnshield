# DNShield Manifest Editor

A web server tool for managing DNShield manifest assignments and creating pull requests. This tool provides a web interface to manage manifest assignments.

## Features

- **Search Functionality**: Search for users, machines, or groups by name/serial
- **Visual Management**: Drag-and-drop interface for managing manifest assignments
- **Current Assignments**: View currently assigned manifests with optional rule expansion
- **Available Manifests**: Browse available manifests filtered by user scope (excludes team manifests user isn't scoped to)
- **Staging Area**: Preview changes before saving
- **Pull Request Creation**: Generate pull requests directly from the interface

## Building

### Build Commands

```bash
# Build the binary
make build

# Build and code sign (requires DEVELOPER_ID)
make sign

# Build and run
make run

# Development mode (with auto-reload)
make dev

# Run tests
make test

# Install to /usr/local/bin
make install

# Clean build artifacts
make clean
```

## Usage

1. Start the server:

```bash
./manifest-editor-assignment
```

2. Open your browser and navigate to:

```
http://localhost:7777
```

The server will serve the web interface and handle API requests for manifest management.

## How to Use

### Searching

1. Select search type: User, Machine, or Group
2. Enter the search term:
   - **User**: Username like "john.peterson"
   - **Machine**: Serial number like "C02ABC1234"
   - **Group**: Group name like "foo-bar"
3. Click Search or press Enter

### Managing Assignments

1. **View Current**: See manifests currently assigned to the entity
2. **Drag to Remove**: Drag manifests from "Current Assignments" to "Staging Area" to remove
3. **Drag to Add**: Drag manifests from "Available Manifests" to "Staging Area" to add
4. **Preview Changes**: Review changes in the "Staging Area" before saving

## Development

The main components are:

- `server.go`: Go web server with HTTP handlers and business logic
- Static web assets under `frontend/`: HTML/CSS/JavaScript served by the Go server

### Repository Layout

```
manifest-editor/
├── frontend/          # Static assets embedded into the server binary
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── server.go          # Backend handlers, GitHub integration, manifest management
├── Makefile           # Build/run/sign helpers
├── README.md
└── tool-scope.json    # vscode devcontainer/tooling scope
```

## Environment Variables

- `DEVELOPER_ID`: Apple Developer ID for code signing (auto-detected if not set)
- `PORT`: Server port (defaults to 7777)
