# DNShield

# Version management
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%d %H:%M:%S")

# Build directories
BUILD_DIR := build
DIST_DIR := dist
TOP_LEVEL := $(shell git rev-parse --show-toplevel)
# Components
dnshield_DIR := dnshield
CHROME_EXT_DIR := chrome_extension
IDENTITY ?= default

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Default target
.DEFAULT_GOAL := help

# Help target
.PHONY: help
help: ## Show this help message
	@echo "DNShield v$(VERSION) - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\033[36m  %-20s\033[0m %s\n", "Target", "Description"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Version Management

.PHONY: version
version: ## Display current version
	@echo "DNShield version: $(VERSION)"
	@echo "Git commit: $(COMMIT)"
	@echo "Build date: $(BUILD_DATE)"

.PHONY: version-up
version-up: ## Increment patch version (1.1.10 -> 1.1.11)
	@echo "Current version: $(VERSION)"
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(VERSION) | cut -d. -f2); \
	PATCH=$$(echo $(VERSION) | cut -d. -f3); \
	PATCH_LEN=$${#PATCH}; \
	PATCH_NUM=$$((10#$$PATCH)); \
	NEW_PATCH_NUM=$$(($$PATCH_NUM + 1)); \
	NEW_PATCH=$$(printf "%0$${PATCH_LEN}d" $$NEW_PATCH_NUM); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo "New version: $$NEW_VERSION"; \
	echo "$$NEW_VERSION" > VERSION
	@echo "Syncing version to Info.plist files..."
	@resources/scripts/sync/sync_version.sh
	@echo "Version updated. Don't forget to commit!"

.PHONY: version-minor
version-minor: ## Increment minor version (1.1.10 -> 1.2.0)
	@echo "Current version: $(VERSION)"
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(VERSION) | cut -d. -f2); \
	PATCH=$$(echo $(VERSION) | cut -d. -f3); \
	PATCH_LEN=$${#PATCH}; \
	NEW_MINOR=$$((10#$$MINOR + 1)); \
	NEW_PATCH=$$(printf "%0$${PATCH_LEN}d" 0); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.$$NEW_PATCH"; \
	echo "New version: $$NEW_VERSION"; \
	echo "$$NEW_VERSION" > VERSION
	@echo "Syncing version to Info.plist files..."
	@resources/scripts/sync/sync_version.sh
	@echo "Version updated. Don't forget to commit!"

.PHONY: version-major
version-major: ## Increment major version (1.1.10 -> 2.0.0)
	@echo "Current version: $(VERSION)"
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	PATCH=$$(echo $(VERSION) | cut -d. -f3); \
	PATCH_LEN=$${#PATCH}; \
	NEW_MAJOR=$$((10#$$MAJOR + 1)); \
	NEW_PATCH=$$(printf "%0$${PATCH_LEN}d" 0); \
	NEW_VERSION="$$NEW_MAJOR.0.$$NEW_PATCH"; \
	echo "New version: $$NEW_VERSION"; \
	echo "$$NEW_VERSION" > VERSION
	@echo "Syncing version to Info.plist files..."
	@resources/scripts/sync/sync_version.sh
	@echo "Version updated. Don't forget to commit!"

##@ Build Targets

.PHONY: all
all: mac-app chrome-extension tools ## Build all components

.PHONY: identity
identity: ## Apply signing identity (set IDENTITY=name)
	@echo "Applying signing identity '$(IDENTITY)'"
	@./tools/signing/apply_identity.py --identity "$(IDENTITY)"

.PHONY: mac-app
mac-app: identity ## Build macOS application
	@echo "Building macOS app v$(VERSION)..."
	@$(MAKE) -C $(dnshield_DIR) VERSION=$(VERSION)

.PHONY: mac-app-enterprise
mac-app-enterprise: identity ## Build macOS app (enterprise version) with watchdog
	@echo "Building macOS enterprise app v$(VERSION)..."
	@# Build watchdog first if Go is available
	@if command -v go >/dev/null 2>&1; then \
		echo "[INFO] Building watchdog for enterprise app..."; \
		$(MAKE) watchdog; \
	else \
		echo "[INFO] Go not found, skipping watchdog build"; \
	fi
	@$(MAKE) -C $(dnshield_DIR) enterprise VERSION=$(VERSION)

.PHONY: tools
tools: ## Build management tools 
	@echo "Building management tools..."
	@$(MAKE) -C tools build

##@ CLI

CTL_SOURCES := $(wildcard dnshield/CTL/*.m) dnshield/Common/Defaults.m

.PHONY: ctl
ctl: ## Build dnshield-ctl CLI as universal binary (optionally sign with DEVELOPER_ID)
	@echo "[INFO] Building dnshield-ctl universal binary..."
	@mkdir -p $(BUILD_DIR)
	@# Build for arm64 (Apple Silicon)
	@xcrun clang -fobjc-arc -framework Foundation -mmacosx-version-min=11.0 -O2 -I dnshield \
		-target arm64-apple-macos11.0 \
		-o "$(BUILD_DIR)/dnshield-ctl-arm64" $(CTL_SOURCES)
	@# Build for x86_64 (Intel)
	@xcrun clang -fobjc-arc -framework Foundation -mmacosx-version-min=11.0 -O2 -I dnshield \
		-target x86_64-apple-macos11.0 \
		-o "$(BUILD_DIR)/dnshield-ctl-x86_64" $(CTL_SOURCES)
	@# Create universal binary
	@lipo -create "$(BUILD_DIR)/dnshield-ctl-arm64" "$(BUILD_DIR)/dnshield-ctl-x86_64" \
		-output "$(BUILD_DIR)/dnshield-ctl"
	@# Clean up architecture-specific binaries
	@rm -f "$(BUILD_DIR)/dnshield-ctl-arm64" "$(BUILD_DIR)/dnshield-ctl-x86_64"
	@chmod 755 "$(BUILD_DIR)/dnshield-ctl"
	@if [ -n "$(DEVELOPER_ID)" ]; then \
		echo "[INFO] Signing dnshield-ctl with: $(DEVELOPER_ID)"; \
		codesign --force --sign "$(DEVELOPER_ID)" --options runtime --timestamp "$(BUILD_DIR)/dnshield-ctl"; \
	else \
		echo "[INFO] Not signing dnshield-ctl (set DEVELOPER_ID=\"Developer ID Application: Your Name (TEAMID)\" to sign)"; \
	fi
	@echo "[INFO] Built universal dnshield-ctl binary: $(BUILD_DIR)/dnshield-ctl"

.PHONY: watchdog
watchdog: ## Build watchdog as universal signed binary
	@echo "[INFO] Building watchdog universal binary..."
	@mkdir -p $(BUILD_DIR)
	@# Build for arm64 (Apple Silicon)
	@cd tools/cmd/watchdog && \
		CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o ../../../$(BUILD_DIR)/watchdog-arm64 .
	@# Build for amd64 (Intel)
	@cd tools/cmd/watchdog && \
		CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o ../../../$(BUILD_DIR)/watchdog-amd64 .
	@# Create universal binary
	@lipo -create $(BUILD_DIR)/watchdog-arm64 $(BUILD_DIR)/watchdog-amd64 -output $(BUILD_DIR)/watchdog
	@# Clean up architecture-specific binaries
	@rm -f $(BUILD_DIR)/watchdog-arm64 $(BUILD_DIR)/watchdog-amd64
	@# Code sign if DEVELOPER_ID is set
	@if [ -n "$(DEVELOPER_ID)" ]; then \
		echo "[INFO] Signing watchdog with: $(DEVELOPER_ID)"; \
		codesign --force --sign "$(DEVELOPER_ID)" --options runtime --timestamp "$(BUILD_DIR)/watchdog"; \
		echo "[INFO] Signed watchdog binary"; \
	else \
		echo "[INFO] DEVELOPER_ID not set, watchdog will not be signed"; \
	fi
	@echo "[INFO] Built universal watchdog binary: $(BUILD_DIR)/watchdog"

.PHONY: watchdog-install
watchdog-install: watchdog ## Copy watchdog binary to DNShield.app
	@echo "[INFO] Installing watchdog to DNShield.app..."
	@if [ -d "/Applications/DNShield.app/Contents/MacOS" ]; then \
		cp "$(BUILD_DIR)/watchdog" "/Applications/DNShield.app/Contents/MacOS/watchdog"; \
		chmod 755 "/Applications/DNShield.app/Contents/MacOS/watchdog"; \
		echo "[INFO] Installed watchdog to /Applications/DNShield.app/Contents/MacOS/watchdog"; \
	else \
		echo "[ERROR] DNShield.app not found at /Applications/DNShield.app"; \
		exit 1; \
	fi

.PHONY: watchdog-package
watchdog-package: ## Package watchdog LaunchDaemon plist
	@echo "[INFO] Packaging watchdog LaunchDaemon..."
	@mkdir -p $(BUILD_DIR)/watchdog-pkg/Library/LaunchDaemons
	@mkdir -p $(BUILD_DIR)/watchdog-pkg/Applications/DNShield.app/Contents/MacOS
	@# Copy LaunchDaemon plist
	@cp resources/package/LaunchDaemons/com.dnshield.watchdog.plist \
		$(BUILD_DIR)/watchdog-pkg/Library/LaunchDaemons/
	@# Copy watchdog binary if it exists
	@if [ -f "$(BUILD_DIR)/watchdog" ]; then \
		cp "$(BUILD_DIR)/watchdog" $(BUILD_DIR)/watchdog-pkg/Applications/DNShield.app/Contents/MacOS/; \
		chmod 755 $(BUILD_DIR)/watchdog-pkg/Applications/DNShield.app/Contents/MacOS/watchdog; \
	else \
		echo "[WARNING] Watchdog binary not found, run 'make watchdog' first"; \
	fi
	@# Create package
	@pkgbuild --root $(BUILD_DIR)/watchdog-pkg \
		--identifier com.dnshield.watchdog \
		--version $(VERSION) \
		--install-location / \
		$(BUILD_DIR)/watchdog-unsigned.pkg
	@# Sign the package if DEVELOPER_ID is set
	@if [ -n "$(DEVELOPER_ID)" ]; then \
		INSTALLER_IDENTITY="$$(echo "$(DEVELOPER_ID)" | sed 's/Developer ID Application:/Developer ID Installer:/')"; \
		if echo "$(DEVELOPER_ID)" | grep -q "Developer ID Installer:"; then \
			INSTALLER_IDENTITY="$(DEVELOPER_ID)"; \
		fi; \
		echo "[INFO] Signing package with: $$INSTALLER_IDENTITY"; \
		if productsign --sign "$$INSTALLER_IDENTITY" \
			$(BUILD_DIR)/watchdog-unsigned.pkg \
			$(BUILD_DIR)/watchdog.pkg 2>/dev/null; then \
			rm $(BUILD_DIR)/watchdog-unsigned.pkg; \
			echo "[INFO] Created signed package: $(BUILD_DIR)/watchdog.pkg"; \
		else \
			echo "[WARNING] Could not sign package, creating unsigned version"; \
			mv $(BUILD_DIR)/watchdog-unsigned.pkg $(BUILD_DIR)/watchdog.pkg; \
			echo "[INFO] Created unsigned package: $(BUILD_DIR)/watchdog.pkg"; \
		fi; \
	else \
		mv $(BUILD_DIR)/watchdog-unsigned.pkg $(BUILD_DIR)/watchdog.pkg; \
		echo "[INFO] DEVELOPER_ID not set, package will not be signed"; \
		echo "[INFO] Created unsigned package: $(BUILD_DIR)/watchdog.pkg"; \
	fi
	@rm -rf $(BUILD_DIR)/watchdog-pkg

.PHONY: ctl-install
ctl-install: ## Install dnshield-ctl to /usr/local/bin (requires sudo)
	@if [ -f "$(BUILD_DIR)/dnshield-ctl" ]; then \
		sudo cp "$(BUILD_DIR)/dnshield-ctl" /usr/local/bin/; \
		sudo chmod 755 /usr/local/bin/dnshield-ctl; \
		echo "Installed /usr/local/bin/dnshield-ctl"; \
	else \
		echo "dnshield-ctl not built. Run 'make ctl' first."; exit 1; \
	fi

.PHONY: manifests
manifests: ## Run manifest generator
	@$(MAKE) -C tools run-manifests

.PHONY: manifests-dry-run
manifests-dry-run: ## Run manifest generator in dry-run mode
	@$(MAKE) -C tools dry-run


.PHONY: chrome-extension
chrome-extension: ## Package Chrome extension
	@# Calculate Chrome extension version (major version + 1)
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(VERSION) | cut -d. -f2); \
	PATCH=$$(echo $(VERSION) | cut -d. -f3); \
	CHROME_MAJOR=$$(($$MAJOR + 1)); \
	CHROME_VERSION="$$CHROME_MAJOR.$$MINOR.$$PATCH"; \
	echo "Packaging Chrome extension v$$CHROME_VERSION..."; \
	mkdir -p $(BUILD_DIR); \
	cd $(CHROME_EXT_DIR) && \
		sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$$CHROME_VERSION\"/" manifest.json && \
		zip -r ../$(BUILD_DIR)/dnshield-chrome-extension-$$CHROME_VERSION.zip . -x "CHANGELOG.md" "*.bak" && \
		mv manifest.json.bak manifest.json

.PHONY: chrome-ext-version
chrome-ext-version: ## Update Chrome extension version (usage: make chrome-ext-version TYPE=patch|minor|major)
	@if [ -z "$(TYPE)" ]; then \
		echo "Error: TYPE not specified. Use TYPE=patch|minor|major"; \
		exit 1; \
	fi
	@resources/scripts/chrome/update-chrome-extension-version.sh $(TYPE)

.PHONY: chrome-ext-publish
chrome-ext-publish: ## Publish Chrome extension to Web Store (requires environment variables)
	@# Calculate Chrome extension version (major version + 1)
	@VERSION_PARTS=($(shell echo $(VERSION) | tr '.' ' ')); \
	MAJOR=$${VERSION_PARTS[0]}; \
	CHROME_MAJOR=$$(($$MAJOR + 1)); \
	CHROME_VERSION="$$CHROME_MAJOR.$${VERSION_PARTS[1]}.$${VERSION_PARTS[2]}"; \
	if [ ! -f "$(BUILD_DIR)/dnshield-chrome-extension-$$CHROME_VERSION.zip" ]; then \
		echo "Error: Extension not built. Run 'make chrome-extension' first"; \
		exit 1; \
	fi; \
	resources/scripts/chrome/chrome-web-store-upload.sh "$(BUILD_DIR)/dnshield-chrome-extension-$$CHROME_VERSION.zip" "$$CHROME_VERSION"

##@ Installation

.PHONY: install
install: ## Install DNShield (macOS app to /Applications)
ifeq ($(UNAME_S),Darwin)
	@$(MAKE) -C $(dnshield_DIR) install
else
	@echo "Install target only supported on macOS. Use 'make install-server' for other platforms."
endif


.PHONY: uninstall
uninstall: ## Uninstall DNShield
ifeq ($(UNAME_S),Darwin)
	@$(MAKE) -C $(dnshield_DIR) uninstall
endif

##@ Development

.PHONY: dev
dev: ## Build development version (no code signing)
	@$(MAKE) -C $(dnshield_DIR) dev VERSION=$(VERSION)

.PHONY: test
test: test-simple test-unit test-direct ## Run all modern test suites
	@echo ""
	@echo "All test suites completed successfully!"


.PHONY: test-simple
test-simple: ## Run simple tests (fastest, basic validation)
	@echo "Running DNShield simple tests..."
	@if [ -f resources/tests/runners/run_simple_tests.sh ]; then \
		resources/tests/runners/run_simple_tests.sh; \
	else \
		echo "Simple test runner not found at resources/tests/runners/run_simple_tests.sh"; \
		exit 1; \
	fi

.PHONY: test-unit
test-unit: ## Run unit tests following Apple XCTest best practices
	@echo "Running DNShield unit tests..."
	@if [ -f resources/tests/runners/run_unit_tests.sh ]; then \
		resources/tests/runners/run_unit_tests.sh; \
	else \
		echo "Unit test runner not found at resources/tests/runners/run_unit_tests.sh"; \
		exit 1; \
	fi

.PHONY: test-direct
test-direct: ## Run direct tests (standalone, no dependencies)
	@echo "Running DNShield direct tests..."
	@if [ -f resources/tests/runners/run_direct_tests.sh ]; then \
		resources/tests/runners/run_direct_tests.sh; \
	else \
		echo "Direct test runner not found at resources/tests/runners/run_direct_tests.sh"; \
		exit 1; \
	fi

.PHONY: test-signed
test-signed: ## Run tests with code signing (may trigger security warnings)
	@echo "Running DNShield tests with signing..."
	@if [ -f resources/tests/runners/run_tests.sh ]; then \
		cd $(dnshield_DIR) && ../resources/tests/runners/run_tests.sh; \
	else \
		echo "Test runner not found at resources/tests/runners/run_tests.sh"; \
		exit 1; \
	fi

.PHONY: test-setup
test-setup: ## Set up test environment
	@echo "Setting up test environment..."
	@cd $(dnshield_DIR) && \
	if [ ! -f run_unit_tests.sh ]; then \
		echo "Test runner already exists"; \
	fi
	@echo "To add tests to Xcode project:"
	@echo "  1. Open $(dnshield_DIR)/DNShield.xcodeproj in Xcode"
	@echo "  2. File → New → Target → macOS Unit Testing Bundle"
	@echo "  3. Name it 'DNShieldTests'"
	@echo "  4. Add test files from Tests/ directory"
	@echo "  5. Run with Cmd+U or 'make test'"

.PHONY: lint
lint: ## Run clang-format on C/C++/Objective-C code
	@echo "Running clang-format..."
	@find . -type f \( -name '*.m' -o -name '*.mm' -o -name '*.h' -o -name '*.c' -o -name '*.cpp' \) \
		-not -path './build/*' \
		-not -path './chrome_extension/node_modules/*' \
		-not -path './resources/node_modules/*' \
		-print0 | xargs -0 clang-format -i
	@echo "Code formatting complete."

.PHONY: lint-manifests
lint-manifests: ## Validate manifest JSON files
	@echo "Linting manifest files..."
	@python3 resources/scripts/lint-manifests.py manifests --check-only

.PHONY: fix-manifests
fix-manifests: ## Fix manifest JSON issues
	@echo "Fixing manifest files..."
	@python3 resources/scripts/lint-manifests.py manifests --fix

.PHONY: format
format: ## Format code
	@echo "Formatting code..."
	@if command -v shfmt >/dev/null 2>&1; then \
		find . -name "*.sh" -type f -exec shfmt -w {} \; ; \
	fi

##@ Release

.PHONY: release
release: clean all ## Build release artifacts
	@echo "Building release v$(VERSION)..."
	@mkdir -p $(DIST_DIR)
	# macOS app
	@$(MAKE) -C $(dnshield_DIR) release VERSION=$(VERSION)
	@if [ -d $(dnshield_DIR)/dist ]; then \
		cp -r $(dnshield_DIR)/dist/* $(DIST_DIR)/; \
	fi
	# Chrome extension
	@VERSION_PARTS=($(shell echo $(VERSION) | tr '.' ' ')); \
	MAJOR=$${VERSION_PARTS[0]}; \
	CHROME_MAJOR=$$(($$MAJOR + 1)); \
	CHROME_VERSION="$$CHROME_MAJOR.$${VERSION_PARTS[1]}.$${VERSION_PARTS[2]}"; \
	cp $(BUILD_DIR)/dnshield-chrome-extension-$$CHROME_VERSION.zip $(DIST_DIR)/
	# Generate checksums
	@cd $(DIST_DIR) && shasum -a 256 * > checksums.txt
	@echo "Release artifacts created in $(DIST_DIR)/"

.PHONY: tag
tag: ## Create git tag for current version
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Tag v$(VERSION) already exists"; \
	else \
		echo "Creating tag v$(VERSION)..."; \
		git tag -a "v$(VERSION)" -m "Release v$(VERSION)"; \
		echo "Tag created. Run 'git push origin v$(VERSION)' to push."; \
	fi

##@ Utility

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@$(MAKE) -C $(dnshield_DIR) clean

.PHONY: deps
deps: ## Install dependencies
	@echo "Installing dependencies..."
	@if [ -f $(dnshield_DIR)/install_deps.sh ]; then \
		cd $(dnshield_DIR) && ./install_deps.sh; \
	fi

.PHONY: update-deps
update-deps: ## Update dependencies
	@echo "Updating dependencies..."

##@ Documentation

.PHONY: docs
docs: ## Serve documentation locally from docs/ at http://localhost:8000
	@cd docs && python3 -m http.server 8000

.PHONY: check-env
check-env: ## Check build environment
	@echo "Build Environment Check"
	@echo "======================"
	@echo "OS: $(UNAME_S)"
	@echo "Arch: $(UNAME_M)"
	@echo "Version: $(VERSION)"
	@echo ""
	@echo "Tools:"
	@echo -n "  Xcode: "; if command -v xcodebuild >/dev/null 2>&1; then xcodebuild -version | head -1; else echo "Not found"; fi
	@echo -n "  Go: "; if command -v go >/dev/null 2>&1; then go version; else echo "Not found"; fi
	@echo -n "  Git: "; if command -v git >/dev/null 2>&1; then git --version; else echo "Not found"; fi
	@echo -n "  Make: "; make --version | head -1
	@echo ""
	@echo "macOS Signing:"
	@if [ -n "$$DEVELOPER_ID" ]; then echo "  DEVELOPER_ID: Set"; else echo "  DEVELOPER_ID: Not set"; fi
	@if [ -n "$$TEAM_ID" ]; then echo "  TEAM_ID: Set"; else echo "  TEAM_ID: Not set"; fi

# Include component makefiles if they exist
-include $(dnshield_DIR)/Makefile.include
