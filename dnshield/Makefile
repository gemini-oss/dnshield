# DNShield Makefile

# Configuration
# Version is now managed at the root level
VERSION ?= $(shell cat ../VERSION)
VERSION_MAJOR_MINOR := $(shell echo $(VERSION) | cut -d. -f1-2)
BUILD_NUMBER := $(shell echo $(VERSION) | cut -d. -f3)

# Scripts
BUILD_ENTERPRISE := ../resources/package/build_enterprise.sh
RELEASE_XPC := ./release_xpc.sh

# Default target
.PHONY: all
all: enterprise

# Build targets
.PHONY: enterprise
enterprise: update-version
	@echo "Building DNShield Enterprise (Version $(VERSION))..."
	@$(BUILD_ENTERPRISE)

.PHONY: release
release:
	@echo "Building XPC Release (Version $(VERSION))..."
	@$(RELEASE_XPC)

# Version management
.PHONY: update-version
update-version:
	@echo "Updating version to $(VERSION_MAJOR_MINOR) ($(BUILD_NUMBER))..."
	@# Update App Info.plist
	@/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(VERSION_MAJOR_MINOR)" App/Info.plist
	@/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $(BUILD_NUMBER)" App/Info.plist
	@# Update Extension Info.plist
	@/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(VERSION_MAJOR_MINOR)" Extension/Info.plist
	@/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $(BUILD_NUMBER)" Extension/Info.plist
	@# Update daemon version
	@sed -i '' 's/^#define DAEMON_VERSION.*/#define DAEMON_VERSION "$(VERSION_MAJOR_MINOR)"/' Daemon/main.m
	@sed -i '' 's/^#define DAEMON_BUILD.*/#define DAEMON_BUILD "$(BUILD_NUMBER)"/' Daemon/main.m

.PHONY: version-up
version-up:
	@echo "Version management has moved to the root Makefile"
	@echo "Run 'make version-up' from the project root instead"

.PHONY: version-minor
version-minor:
	@echo "Version management has moved to the root Makefile"
	@echo "Run 'make version-minor' from the project root instead"

.PHONY: version-major
version-major:
	@echo "Version management has moved to the root Makefile"
	@echo "Run 'make version-major' from the project root instead"

# Daemon operations
.PHONY: daemon-version
daemon-version:
	@if [ -f build/enterprise/daemon/dnshield-daemon ]; then \
		./build/enterprise/daemon/dnshield-daemon --version; \
	else \
		echo "Daemon not built. Run 'make enterprise' first."; \
	fi

# Clean targets
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf DerivedData/
	@find . -name "*.xcuserstate" -delete
	@find . -name ".DS_Store" -delete

.PHONY: clean-all
clean-all: clean
	@echo "Cleaning all generated files..."
	@rm -rf ~/Library/Developer/Xcode/DerivedData/DNShield-*

# Chrome extension operations
.PHONY: chrome-test
chrome-test:
	@echo "Testing Chrome extension connection..."
	@cd ../chrome_extension && npm test 2>/dev/null || echo "Install npm dependencies first: cd ../chrome_extension && npm install"

# Installation targets (requires sudo)
.PHONY: install-daemon
install-daemon:
	@echo "Installing DNShield daemon..."
	@if [ -f build/enterprise/daemon/dnshield-daemon ]; then \
		sudo cp build/enterprise/daemon/dnshield-daemon /usr/local/bin/; \
		sudo chmod 755 /usr/local/bin/dnshield-daemon; \
		echo "Daemon installed to /usr/local/bin/dnshield-daemon"; \
	else \
		echo "Daemon not built. Run 'make enterprise' first."; \
	fi

.PHONY: install-app
install-app:
	@echo "Installing DNShield app..."
	@if [ -d build/enterprise/app/DerivedData/Build/Products/Release/DNShield.app ]; then \
		cp -R build/enterprise/app/DerivedData/Build/Products/Release/DNShield.app /Applications/; \
		echo "App installed to /Applications/DNShield.app"; \
	else \
		echo "App not built. Run 'make enterprise' first."; \
	fi

# Helper targets
.PHONY: help
help:
	@echo "DNShield Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  make                        - Build enterprise version (default)"
	@echo "  make simple                 - Build simple version"
	@echo "  make enterprise             - Build enterprise version"
	@echo "  make release                - Build XPC release"
	@echo ""
	@echo "Version management:"
	@echo "  make version-up     - Increment build number (1.1.3 -> 1.1.4)"
	@echo "  make version-minor  - Increment minor version (1.1.3 -> 1.2.0)"
	@echo "  make version-major  - Increment major version (1.1.3 -> 2.0.0)"
	@echo "  make daemon-version - Show daemon version"
	@echo ""
	@echo "Installation:"
	@echo "  make install-daemon - Install daemon to /usr/local/bin (requires sudo)"
	@echo "  make install-app    - Install app to /Applications"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make clean-all      - Clean all generated files"
	@echo "  make chrome-test    - Test Chrome extension connection"
	@echo ""
	@echo "Current version: $(VERSION)"

# Development shortcuts
.PHONY: dev
dev: clean enterprise install-app
	@echo "Development build complete!"
	@open /Applications/DNShield.app

# Export variables for scripts
export VERSION
export VERSION_MAJOR_MINOR
export BUILD_NUMBER
