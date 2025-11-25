# Makefile for DNShield Manifest Editor

GO_BINARY=manifest-editor-assignment
GO_SOURCE=server.go
DEVELOPER_ID ?= $(shell security find-identity -v -p codesigning | grep "Developer ID Application" | head -1 | awk -F'"' '{print $$2}')

.PHONY: all build clean run sign

# Default target
all: build

# Build targets
build:
	@echo "Building Go server: $(GO_BINARY)..."
	go build -o $(GO_BINARY) $(GO_SOURCE)
	@echo "Go server build complete: $(GO_BINARY)"

sign: build
	@echo "Code signing $(GO_BINARY)..."
	@if [ -z "$(DEVELOPER_ID)" ]; then \
		echo "Error: DEVELOPER_ID not set and no Developer ID Application certificate found"; \
		echo "Set DEVELOPER_ID environment variable or install a Developer ID certificate"; \
		exit 1; \
	fi
	codesign --force --sign "$(DEVELOPER_ID)" \
		--options runtime \
		--timestamp \
		--verbose \
		$(GO_BINARY)
	@echo "Code signing complete"
	@echo "Verifying signature..."
	codesign --verify --verbose $(GO_BINARY)
	@echo "Signature verified"

run: build
	@echo "Starting DNShield Manifest Editor..."
	./$(GO_BINARY)

clean:
	@echo "Cleaning..."
	rm -f $(GO_BINARY)
	@echo "Clean complete"

install: sign
	@echo "Installing to /usr/local/bin..."
	sudo cp $(GO_BINARY) /usr/local/bin/
	@echo "Installation complete: /usr/local/bin/$(GO_BINARY)"

uninstall:
	@echo "Uninstalling..."
	sudo rm -f "/usr/local/bin/$(GO_BINARY)"
	@echo "Uninstall complete"

# Development targets
dev:
	@echo "Running in development mode..."
	go run $(GO_SOURCE)

test:
	@echo "Running tests..."
	go test ./...

help:
	@echo "DNShield Manifest Editor - Makefile targets:"
	@echo ""
	@echo "  make build      - Build Go binary"
	@echo "  make sign       - Build and codesign the binary"
	@echo "  make run        - Build and run the server"
	@echo "  make install    - Sign and install to /usr/local/bin"
	@echo "  make clean      - Remove built binary"
	@echo "  make dev        - Run in development mode"
	@echo "  make test       - Run tests"
	@echo ""
	@echo "Environment variables:"
	@echo "  DEVELOPER_ID - Developer ID for code signing (auto-detected if not set)"