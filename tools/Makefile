# DNShield Tools Makefile

# Variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
EDITOR_BINARY=manifest-editor
NESI_BINARY=nesi
NESI_STATUS_BINARY=nesi-status

# Directories
EDITOR_DIR=cmd/manifest-editor
NESI_DIR=nesi
NESI_STATUS_DIR=nesi/munki
BUILD_DIR=build
BIN_DIR=bin

# Build flags
LDFLAGS=-ldflags "-s -w"

# Universal build flags for Apple Silicon and Intel
UNIVERSAL_FLAGS=CGO_ENABLED=1 GOOS=darwin

# Code signing
DEVELOPER_ID ?= $(shell echo "$$DEVELOPER_ID")
DEVELOPER_ID_INSTALLER ?= $(shell echo "$$DEVELOPER_ID_INSTALLER")

# Default target
.PHONY: all
all: clean build

# Build all binaries
.PHONY: build
build: build-manifests build-editor nesi nesi-status

# Build manifest generator
.PHONY: build-manifests
build-manifests:
	@echo "Building manifest generator..."
	@mkdir -p $(BUILD_DIR)
	cd $(MANIFEST_DIR) && $(GOBUILD) $(LDFLAGS) -o ../../$(BUILD_DIR)/$(MANIFEST_BINARY) .
	@# Code sign if DEVELOPER_ID is set
	@if [ ! -z "$(DEVELOPER_ID)" ]; then \
		echo "Signing manifest generator with: $(DEVELOPER_ID)"; \
		codesign --force --sign "$(DEVELOPER_ID)" \
			--options runtime \
			--timestamp \
			$(BUILD_DIR)/$(MANIFEST_BINARY); \
		echo " Signed manifest generator binary"; \
	else \
		echo "  DEVELOPER_ID not set, manifest generator will not be signed"; \
	fi
	@echo " Built $(BUILD_DIR)/$(MANIFEST_BINARY)"

# Build manifest editor
.PHONY: build-editor
build-editor:
	@echo "Building manifest editor (universal binary)..."
	@mkdir -p $(BUILD_DIR)
	@# Build for arm64 (Apple Silicon)
	cd $(EDITOR_DIR) && $(UNIVERSAL_FLAGS) GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o ../../$(BUILD_DIR)/$(EDITOR_BINARY)-arm64 .
	@# Build for amd64 (Intel)
	cd $(EDITOR_DIR) && $(UNIVERSAL_FLAGS) GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o ../../$(BUILD_DIR)/$(EDITOR_BINARY)-amd64 .
	@# Create universal binary
	lipo -create $(BUILD_DIR)/$(EDITOR_BINARY)-arm64 $(BUILD_DIR)/$(EDITOR_BINARY)-amd64 -output $(BUILD_DIR)/$(EDITOR_BINARY)
	@# Clean up architecture-specific binaries
	rm $(BUILD_DIR)/$(EDITOR_BINARY)-arm64 $(BUILD_DIR)/$(EDITOR_BINARY)-amd64
	@# Code sign if DEVELOPER_ID is set
	@if [ ! -z "$(DEVELOPER_ID)" ]; then \
		echo "Signing manifest editor with: $(DEVELOPER_ID)"; \
		codesign --force --sign "$(DEVELOPER_ID)" \
			--options runtime \
			--entitlements ../resources/entitlements/manifest-editor.entitlements \
			$(BUILD_DIR)/$(EDITOR_BINARY) || \
		codesign --force --sign "$(DEVELOPER_ID)" \
			--options runtime \
			$(BUILD_DIR)/$(EDITOR_BINARY); \
	else \
		echo "  DEVELOPER_ID not set, manifest editor will not be signed"; \
	fi
	@echo " Built universal $(BUILD_DIR)/$(EDITOR_BINARY)"

# Run manifest editor
.PHONY: run-editor
run-editor:
	@echo "Running manifest editor..."
	cd $(EDITOR_DIR) && $(GOCMD) run . $(ARGS)

# Build nesi tool as universal binary
.PHONY: nesi
nesi:
	@echo "Building nesi tool (universal binary)..."
	@mkdir -p $(BUILD_DIR)
	@# Build for arm64 (Apple Silicon)
	cd $(NESI_DIR) && clang -arch arm64 -framework Foundation -framework NetworkExtension -o ../$(BUILD_DIR)/$(NESI_BINARY)-arm64 main.m
	@# Build for x86_64 (Intel)
	cd $(NESI_DIR) && clang -arch x86_64 -framework Foundation -framework NetworkExtension -o ../$(BUILD_DIR)/$(NESI_BINARY)-x86_64 main.m
	@# Create universal binary
	lipo -create $(BUILD_DIR)/$(NESI_BINARY)-arm64 $(BUILD_DIR)/$(NESI_BINARY)-x86_64 -output $(BUILD_DIR)/$(NESI_BINARY)
	@# Clean up architecture-specific binaries
	rm $(BUILD_DIR)/$(NESI_BINARY)-arm64 $(BUILD_DIR)/$(NESI_BINARY)-x86_64
	@# Code sign if DEVELOPER_ID is set
	@if [ ! -z "$(DEVELOPER_ID)" ]; then \
		echo "Signing nesi tool with: $(DEVELOPER_ID)"; \
		codesign --force --sign "$(DEVELOPER_ID)" \
			--options runtime \
			--timestamp \
			$(BUILD_DIR)/$(NESI_BINARY); \
		echo " Signed nesi tool binary"; \
	else \
		echo "  DEVELOPER_ID not set, nesi tool will not be signed"; \
	fi
	@echo " Built universal $(BUILD_DIR)/$(NESI_BINARY)"

# Build nesi-status tool for Munki as universal binary
.PHONY: nesi-status
nesi-status:
	@echo "Building nesi-status tool (universal binary)..."
	@mkdir -p $(BUILD_DIR)
	@# Build for arm64 (Apple Silicon)
	cd $(NESI_STATUS_DIR) && GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o ../../$(BUILD_DIR)/$(NESI_STATUS_BINARY)-arm64 nesi-status.go
	@# Build for amd64 (Intel)
	cd $(NESI_STATUS_DIR) && GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o ../../$(BUILD_DIR)/$(NESI_STATUS_BINARY)-amd64 nesi-status.go
	@# Create universal binary
	lipo -create $(BUILD_DIR)/$(NESI_STATUS_BINARY)-arm64 $(BUILD_DIR)/$(NESI_STATUS_BINARY)-amd64 -output $(BUILD_DIR)/$(NESI_STATUS_BINARY)
	@# Clean up architecture-specific binaries
	rm $(BUILD_DIR)/$(NESI_STATUS_BINARY)-arm64 $(BUILD_DIR)/$(NESI_STATUS_BINARY)-amd64
	@# Code sign if DEVELOPER_ID is set
	@if [ ! -z "$(DEVELOPER_ID)" ]; then \
		echo "Signing nesi-status tool with: $(DEVELOPER_ID)"; \
		codesign --force --sign "$(DEVELOPER_ID)" \
			--options runtime \
			--timestamp \
			$(BUILD_DIR)/$(NESI_STATUS_BINARY); \
		echo " Signed nesi-status tool binary"; \
	else \
		echo "  DEVELOPER_ID not set, nesi-status tool will not be signed"; \
	fi
	@echo " Built universal $(BUILD_DIR)/$(NESI_STATUS_BINARY)"

# Test all packages
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Test with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -cover -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo " Coverage report generated: coverage.html"

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...
	@echo " Code formatted"

# Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	@if ! command -v golangci-lint >/dev/null 2>&1 || ! golangci-lint version 2>/dev/null | grep -q "version 2"; then \
		echo "Installing golangci-lint v2..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
	fi
	golangci-lint run ./...

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy
	@echo " Dependencies tidied"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo " Cleaned"

.PHONY: package-nesi
package-nesi: nesi
	@echo "Creating nesi package..."
	@mkdir -p $(BUILD_DIR)/pkg/usr/local/bin
	@cp $(BUILD_DIR)/$(NESI_BINARY) $(BUILD_DIR)/pkg/usr/local/bin/
	@pkgbuild --root $(BUILD_DIR)/pkg \
		--identifier com.dnshield.nesi \
		--version 1.0.0 \
		--install-location / \
		$(BUILD_DIR)/nesi-unsigned.pkg
	@# Sign the package if DEVELOPER_ID is set
	@if [ ! -z "$(DEVELOPER_ID)" ]; then \
		INSTALLER_IDENTITY="$$(echo "$(DEVELOPER_ID)" | sed 's/Developer ID Application:/Developer ID Installer:/')"; \
		if echo "$(DEVELOPER_ID)" | grep -q "Developer ID Installer:"; then \
			INSTALLER_IDENTITY="$(DEVELOPER_ID)"; \
		fi; \
		echo "Signing package with: $$INSTALLER_IDENTITY"; \
		if productsign --sign "$$INSTALLER_IDENTITY" \
			$(BUILD_DIR)/nesi-unsigned.pkg \
			$(BUILD_DIR)/nesi.pkg 2>/dev/null; then \
			rm $(BUILD_DIR)/nesi-unsigned.pkg; \
			echo "Created signed package: $(BUILD_DIR)/nesi.pkg"; \
		else \
			echo "Could not sign package, creating unsigned version"; \
			mv $(BUILD_DIR)/nesi-unsigned.pkg $(BUILD_DIR)/nesi.pkg; \
			echo " Created unsigned package: $(BUILD_DIR)/nesi.pkg"; \
		fi; \
	else \
		mv $(BUILD_DIR)/nesi-unsigned.pkg $(BUILD_DIR)/nesi.pkg; \
		echo "DEVELOPER_ID not set, package will not be signed"; \
		echo "Created unsigned package: $(BUILD_DIR)/nesi.pkg"; \
	fi
	@rm -rf $(BUILD_DIR)/pkg

# Package nesi-status for Munki as a .pkg installer (includes both nesi and nesi-status binaries)
.PHONY: package-nesi-status
package-nesi-status: nesi nesi-status
	@echo "Creating nesi-status package for Munki..."
	@mkdir -p $(BUILD_DIR)/pkg/usr/local/munki/conditions/facts
	@mkdir -p $(BUILD_DIR)/pkg/opt/gemini/dnshield
	@cp $(BUILD_DIR)/$(NESI_STATUS_BINARY) $(BUILD_DIR)/pkg/usr/local/munki/conditions/facts/
	@cp $(BUILD_DIR)/$(NESI_BINARY) $(BUILD_DIR)/pkg/opt/gemini/dnshield/
	@pkgbuild --root $(BUILD_DIR)/pkg \
		--identifier com.dnshield.nesi-status \
		--version 1.0.0 \
		--install-location / \
		$(BUILD_DIR)/nesi-status-unsigned.pkg
	@# Sign the package with DEVELOPER_ID_INSTALLER if set, or try to derive it from DEVELOPER_ID
	@if [ ! -z "$(DEVELOPER_ID_INSTALLER)" ]; then \
		echo "Signing package with: $(DEVELOPER_ID_INSTALLER)"; \
		if productsign --sign "$(DEVELOPER_ID_INSTALLER)" \
			$(BUILD_DIR)/nesi-status-unsigned.pkg \
			$(BUILD_DIR)/nesi-status.pkg 2>/dev/null; then \
			rm $(BUILD_DIR)/nesi-status-unsigned.pkg; \
			echo " Created signed package: $(BUILD_DIR)/nesi-status.pkg"; \
		else \
			echo "  Could not sign package, creating unsigned version"; \
			mv $(BUILD_DIR)/nesi-status-unsigned.pkg $(BUILD_DIR)/nesi-status.pkg; \
			echo " Created unsigned package: $(BUILD_DIR)/nesi-status.pkg"; \
		fi; \
	elif [ ! -z "$(DEVELOPER_ID)" ]; then \
		INSTALLER_IDENTITY="$$(echo "$(DEVELOPER_ID)" | sed 's/Developer ID Application:/Developer ID Installer:/')"; \
		if echo "$(DEVELOPER_ID)" | grep -q "Developer ID Installer:"; then \
			INSTALLER_IDENTITY="$(DEVELOPER_ID)"; \
		fi; \
		echo "Signing package with: $$INSTALLER_IDENTITY"; \
		if productsign --sign "$$INSTALLER_IDENTITY" \
			$(BUILD_DIR)/nesi-status-unsigned.pkg \
			$(BUILD_DIR)/nesi-status.pkg 2>/dev/null; then \
			rm $(BUILD_DIR)/nesi-status-unsigned.pkg; \
			echo " Created signed package: $(BUILD_DIR)/nesi-status.pkg"; \
		else \
			echo "  Could not sign package, creating unsigned version"; \
			mv $(BUILD_DIR)/nesi-status-unsigned.pkg $(BUILD_DIR)/nesi-status.pkg; \
			echo " Created unsigned package: $(BUILD_DIR)/nesi-status.pkg"; \
		fi; \
	else \
		mv $(BUILD_DIR)/nesi-status-unsigned.pkg $(BUILD_DIR)/nesi-status.pkg; \
		echo "  DEVELOPER_ID not set, package will not be signed"; \
		echo " Created unsigned package: $(BUILD_DIR)/nesi-status.pkg"; \
	fi
	@rm -rf $(BUILD_DIR)/pkg

# Notarize nesi package
.PHONY: notarize-nesi
notarize-nesi:
	@if [ ! -f "$(BUILD_DIR)/nesi.pkg" ]; then \
		echo " Error: $(BUILD_DIR)/nesi.pkg not found. Run 'make package-nesi' first."; \
		exit 1; \
	fi
	@if [ -z "$(APPLE_ID)" ]; then \
		echo " Error: APPLE_ID environment variable not set"; \
		echo "Usage: APPLE_ID=your@email.com APPLE_PASSWORD=app-specific-password TEAM_ID=ABC123 make notarize-nesi"; \
		exit 1; \
	fi
	@if [ -z "$(APPLE_PASSWORD)" ]; then \
		echo " Error: APPLE_PASSWORD environment variable not set"; \
		echo "Usage: APPLE_ID=your@email.com APPLE_PASSWORD=app-specific-password TEAM_ID=ABC123 make notarize-nesi"; \
		exit 1; \
	fi
	@if [ -z "$(TEAM_ID)" ]; then \
		echo " Error: TEAM_ID environment variable not set"; \
		echo "Usage: APPLE_ID=your@email.com APPLE_PASSWORD=app-specific-password TEAM_ID=C6F9Y6M584 make notarize-nesi"; \
		exit 1; \
	fi
	@echo " Submitting nesi.pkg for notarization..."
	@xcrun notarytool submit $(BUILD_DIR)/nesi.pkg \
		--apple-id "$(APPLE_ID)" \
		--password "$(APPLE_PASSWORD)" \
		--team-id "$(TEAM_ID)" \
		--wait \
		--output-format json > $(BUILD_DIR)/notarization-result.json
	@if grep -q '"status":"Accepted"' $(BUILD_DIR)/notarization-result.json; then \
		echo " Notarization successful!"; \
		echo " Stapling notarization ticket to package..."; \
		xcrun stapler staple $(BUILD_DIR)/nesi.pkg; \
		echo " Package notarized and stapled: $(BUILD_DIR)/nesi.pkg"; \
	else \
		echo " Notarization failed. Check $(BUILD_DIR)/notarization-result.json for details"; \
		cat $(BUILD_DIR)/notarization-result.json | jq .; \
		exit 1; \
	fi