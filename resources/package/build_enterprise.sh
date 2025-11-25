#!/bin/bash
#
# DNShield Enterprise Build Script
# Builds all components for enterprise deployment
#

set -e

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P )"
PROJECT_DIR="$( cd "${SCRIPT_DIR}/../../dnshield" && pwd -P )"
BUILD_DIR="${PROJECT_DIR}/build/enterprise"
DAEMON_BUILD_DIR="${BUILD_DIR}/daemon"
WATCHDOG_BUILD_DIR="${BUILD_DIR}/watchdog"
APP_BUILD_DIR="${BUILD_DIR}/app"
DIST_DIR="${PROJECT_DIR}/dist/enterprise"

# Shared helpers
if [ -f "${SCRIPT_DIR}/lib/build_common.sh" ]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/lib/build_common.sh"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

fetch_notary_log() {
    local submission_id="$1"
    local artifact_label="$2"
    if [ -z "$submission_id" ]; then
        return
    fi

    log_info "Fetching notarization log for ${artifact_label:-submission} ($submission_id)..."
    if xcrun notarytool log "$submission_id" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APP_PASSWORD" | tee "${BUILD_DIR}/notary-${submission_id}.log"; then
        log_info "Notarization log saved to ${BUILD_DIR}/notary-${submission_id}.log"
    else
        log_warning "Unable to retrieve notarization log for $submission_id"
    fi
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous builds..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${DIST_DIR}"
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${DAEMON_BUILD_DIR}"
    mkdir -p "${WATCHDOG_BUILD_DIR}"
    mkdir -p "${APP_BUILD_DIR}"
    mkdir -p "${DIST_DIR}"
}

# Build the daemon
build_daemon() {
    log_info "Building DNShield daemon..."
    if [ ! -f "${PROJECT_DIR}/Daemon/main.m" ]; then
        log_error "Daemon source not found at ${PROJECT_DIR}/Daemon/main.m"
        exit 1
    fi
    dns_build_daemon
    log_info "Daemon build successful"
}

# Build the optional watchdog
build_watchdog() {
    log_info "Building DNShield watchdog (optional)..."
    WATCHDOG_OUTPUT=""
    dns_build_watchdog
    if [ -n "${WATCHDOG_OUTPUT}" ] && [ -f "${WATCHDOG_OUTPUT}" ]; then
        log_info "Watchdog binary created at ${WATCHDOG_OUTPUT}"
    else
        log_warning "Watchdog binary not produced; Go toolchain may be unavailable. Continuing without watchdog."
    fi
}

# Build the main app and extension
build_app() {
    log_info "Building DNShield app and extension..."
    dns_build_app
    log_info "App build successful"
}

# Create the distribution package
create_distribution() {
    log_info "Creating distribution package..."
    
    # Copy built components
    cp "${DAEMON_BUILD_DIR}/dnshield-daemon" "${DIST_DIR}/"
    if [ -n "${WATCHDOG_OUTPUT}" ] && [ -f "${WATCHDOG_OUTPUT}" ]; then
        cp "${WATCHDOG_OUTPUT}" "${DIST_DIR}/"
    fi
    # Find the built app in DerivedData
    APP_ACTUAL_PATH="${APP_BUILD_DIR}/DerivedData/Build/Products/Release/DNShield.app"
    if [ -d "$APP_ACTUAL_PATH" ]; then
        cp -R "$APP_ACTUAL_PATH" "${DIST_DIR}/"
    else
        log_error "Built app not found at $APP_ACTUAL_PATH"
        exit 1
    fi
    
    # Copy LaunchDaemon plist
    mkdir -p "${DIST_DIR}/LaunchDaemons"
    cp "${SCRIPT_DIR}/LaunchDaemons/com.dnshield.daemon.plist" "${DIST_DIR}/LaunchDaemons/"
    if [ -f "${SCRIPT_DIR}/LaunchDaemons/com.dnshield.watchdog.plist" ]; then
        cp "${SCRIPT_DIR}/LaunchDaemons/com.dnshield.watchdog.plist" "${DIST_DIR}/LaunchDaemons/"
    fi
    
    # Copy documentation if it exists
    if [ -f "${PROJECT_DIR}/ENTERPRISE_DEPLOYMENT.md" ]; then
        cp "${PROJECT_DIR}/ENTERPRISE_DEPLOYMENT.md" "${DIST_DIR}/"
    fi
    
    # Create directories structure
    mkdir -p "${DIST_DIR}/Scripts"
    mkdir -p "${DIST_DIR}/Config"
    
    # Create default configuration
    cat > "${DIST_DIR}/Config/default-config.json" << 'EOF'
{
    "dnsServers": ["1.1.1.1", "8.8.8.8"],
    "autoStart": true,
    "updateInterval": 3600,
    "logLevel": "info",
    "blockedDomains": [
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com"
    ]
}
EOF
    
    log_info "Distribution package created at ${DIST_DIR}"
}

# Create installer package
create_installer() {
    log_info "Creating installer package..."
    
    # Clean up any existing app in build directory to prevent relocation issues
    log_info "Cleaning up build directory to prevent package relocation..."
    rm -rf "${APP_BUILD_DIR}/DerivedData/Build/Products/Release/DNShield.app" 2>/dev/null || true
    
    # Create pkg structure
    PKG_ROOT="${BUILD_DIR}/pkg_root"
    PKG_SCRIPTS="${SCRIPT_DIR}/Scripts"
    
    mkdir -p "${PKG_ROOT}/Applications"
    mkdir -p "${PKG_ROOT}/Library/LaunchDaemons"
    mkdir -p "${PKG_ROOT}/Library/Preferences"
    mkdir -p "${PKG_ROOT}/Library/Application Support/DNShield/Commands/incoming"
    mkdir -p "${PKG_ROOT}/Library/Application Support/DNShield/Commands/responses"

    # Copy files to pkg root
    cp -R "${DIST_DIR}/DNShield.app" "${PKG_ROOT}/Applications/"
    cp "${DIST_DIR}/LaunchDaemons/com.dnshield.daemon.plist" "${PKG_ROOT}/Library/LaunchDaemons/"
    if [ -f "${DIST_DIR}/LaunchDaemons/com.dnshield.watchdog.plist" ]; then
        cp "${DIST_DIR}/LaunchDaemons/com.dnshield.watchdog.plist" "${PKG_ROOT}/Library/LaunchDaemons/"
    fi

    # Ensure macOS bundle directory exists for helper binaries
    APP_MACOS_DIR="${PKG_ROOT}/Applications/DNShield.app/Contents/MacOS"
    mkdir -p "${APP_MACOS_DIR}"

    # Copy daemon into app bundle
    cp "${DIST_DIR}/dnshield-daemon" "${APP_MACOS_DIR}/"
    if [ -f "${DIST_DIR}/watchdog" ]; then
        cp "${DIST_DIR}/watchdog" "${APP_MACOS_DIR}/"
    elif [ -f "${WATCHDOG_BUILD_DIR}/watchdog" ]; then
        cp "${WATCHDOG_BUILD_DIR}/watchdog" "${APP_MACOS_DIR}/"
    fi

    # Build dnshield-ctl utility as universal binary
    if command -v xcrun &> /dev/null; then
        log_info "Building dnshield-ctl utility (universal binary)..."
        DNCTL_ROOT="${SCRIPT_DIR}/../../dnshield"
        DNCTL_SOURCES=()
        while IFS= read -r src; do
            DNCTL_SOURCES+=("$src")
        done < <(find "${DNCTL_ROOT}/CTL" -name '*.m' -print)
        DNCTL_SOURCES+=("${DNCTL_ROOT}/Common/Defaults.m")
        # Build for arm64
        xcrun clang -fobjc-arc -framework Foundation -mmacosx-version-min=11.0 -O2 \
            -I "${DNCTL_ROOT}" \
            -target arm64-apple-macos11.0 \
            -o "${BUILD_DIR}/dnshield-ctl-arm64" "${DNCTL_SOURCES[@]}"
        # Build for x86_64
        xcrun clang -fobjc-arc -framework Foundation -mmacosx-version-min=11.0 -O2 \
            -I "${DNCTL_ROOT}" \
            -target x86_64-apple-macos11.0 \
            -o "${BUILD_DIR}/dnshield-ctl-x86_64" "${DNCTL_SOURCES[@]}"
        # Create universal binary
        lipo -create "${BUILD_DIR}/dnshield-ctl-arm64" "${BUILD_DIR}/dnshield-ctl-x86_64" \
            -output "${BUILD_DIR}/dnshield-ctl"
        # Clean up architecture-specific binaries
        rm -f "${BUILD_DIR}/dnshield-ctl-arm64" "${BUILD_DIR}/dnshield-ctl-x86_64"
        cp "${BUILD_DIR}/dnshield-ctl" "${APP_MACOS_DIR}/"
    else
        log_warning "clang not available; skipping dnshield-ctl build"
    fi

    # Build and copy XPC helper as universal binary
    log_info "Building XPC helper (universal binary)..."
    if declare -F dns_build_xpc_universal >/dev/null; then
        XPC_OUT_PATH="$(dns_build_xpc_universal)"
    else
        # Fallback: build plainly if helper not available
        clang -framework Foundation \
            -target arm64-apple-macos11.0 \
            -o "${BUILD_DIR}/dnshield-xpc-arm64" \
            "${PROJECT_DIR}/XPC/dnshield-xpc.m"
        clang -framework Foundation \
            -target x86_64-apple-macos11.0 \
            -o "${BUILD_DIR}/dnshield-xpc-x86_64" \
            "${PROJECT_DIR}/XPC/dnshield-xpc.m"
        lipo -create \
            "${BUILD_DIR}/dnshield-xpc-arm64" \
            "${BUILD_DIR}/dnshield-xpc-x86_64" \
            -output "${BUILD_DIR}/dnshield-xpc"
        if [ -n "$DEVELOPER_ID" ]; then
            codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp \
                "${BUILD_DIR}/dnshield-xpc" || true
        fi
        XPC_OUT_PATH="${BUILD_DIR}/dnshield-xpc"
    fi
    cp "$XPC_OUT_PATH" "${APP_MACOS_DIR}/"

    # Set permissions
    chmod 755 "${APP_MACOS_DIR}/dnshield-daemon"
    chmod 755 "${APP_MACOS_DIR}/dnshield-watchdog" 2>/dev/null || true
    chmod 755 "${APP_MACOS_DIR}/dnshield-ctl" 2>/dev/null || true
    chmod 755 "${APP_MACOS_DIR}/dnshield-xpc"

    # Re-sign helper binaries if identity is available (preserving entitlements)
    if [ ! -z "$DEVELOPER_ID" ]; then
        # Use the helper function from build_common.sh to properly sign with entitlements
        dns_sign_helpers_in_app "${APP_MACOS_DIR}" dnshield-daemon dnshield-ctl dnshield-xpc dnshield-watchdog

        log_info "Re-signing DNShield.app bundle..."
        # Re-sign with proper entitlements (not using --deep to preserve nested entitlements)
        if ! codesign --force --sign "$DEVELOPER_ID" --options runtime --timestamp --entitlements "${SCRIPT_DIR}/../../dnshield/App/DNShield.entitlements" "${PKG_ROOT}/Applications/DNShield.app"; then
            log_warning "Failed to re-sign DNShield.app"
        fi
    fi
    chmod 644 "${PKG_ROOT}/Library/LaunchDaemons/com.dnshield.daemon.plist"
    
    # Build the package
    if command -v pkgbuild &> /dev/null; then
        # First create unsigned package
        UNSIGNED_PKG="${BUILD_DIR}/DNShield-Enterprise-unsigned.pkg"
        # Get version from app Info.plist
        APP_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "${DIST_DIR}/DNShield.app/Contents/Info.plist")
        APP_BUILD=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "${DIST_DIR}/DNShield.app/Contents/Info.plist" 2>/dev/null || echo "0")
        if [ -z "$APP_BUILD" ]; then
            APP_BUILD="0"
        fi
        if [[ "$APP_BUILD" == *.* ]]; then
            PKG_VERSION="$APP_BUILD"
        else
            PKG_VERSION="${APP_VERSION}.${APP_BUILD}"
        fi
        
        pkgbuild \
            --root "${PKG_ROOT}" \
            --scripts "${PKG_SCRIPTS}" \
            --component-plist "${SCRIPT_DIR}/Component/component.plist" \
            --identifier "com.dnshield.enterprise" \
            --version "$PKG_VERSION" \
            --install-location "/" \
            --ownership recommended \
            "$UNSIGNED_PKG"
        
        # Sign the package if we have installer identity
        FINAL_PKG_NAME="DNShield-${PKG_VERSION}.pkg"
        if [ ! -z "$INSTALLER_IDENTITY" ]; then
            log_info "Signing installer package with: $INSTALLER_IDENTITY"
            productsign --sign "$INSTALLER_IDENTITY" \
                --timestamp \
                "$UNSIGNED_PKG" \
                "${DIST_DIR}/${FINAL_PKG_NAME}"
            rm -f "$UNSIGNED_PKG"
        else
            log_warning "INSTALLER_IDENTITY not set, package will not be signed"
            mv "$UNSIGNED_PKG" "${DIST_DIR}/${FINAL_PKG_NAME}"
        fi
        
        log_info "Installer package created: ${DIST_DIR}/${FINAL_PKG_NAME}"
    else
        log_warning "pkgbuild not found, skipping installer package creation"
    fi
}

# Notarize the built app and package
notarize_app() {
    if [ -z "$APPLE_ID" ] || [ -z "$TEAM_ID" ] || [ -z "$APP_PASSWORD" ]; then
        log_warning "Skipping notarization - credentials not set"
        return
    fi
    
    # Notarize the app
    log_info "Notarizing DNShield app..."
    
    # Create ZIP for app notarization
    log_info "Creating ZIP for app notarization..."
    APP_ZIP_PATH="${BUILD_DIR}/DNShield-App.zip"
    ditto -c -k --keepParent "${DIST_DIR}/DNShield.app" "$APP_ZIP_PATH"
    
    # Submit app for notarization
    log_info "Submitting app to Apple (this may take several minutes)..."
    APP_NOTARIZATION_OUTPUT=$(xcrun notarytool submit "$APP_ZIP_PATH" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APP_PASSWORD" \
        --wait 2>&1)
    
    echo "$APP_NOTARIZATION_OUTPUT"
    
    # Check if app notarization was successful
    if echo "$APP_NOTARIZATION_OUTPUT" | grep -q "status: Accepted"; then
        log_info "App notarization successful!"
        
        log_info "Stapling notarization ticket to app..."
        if declare -F dns_staple_with_retry >/dev/null; then
            dns_staple_with_retry "${DIST_DIR}/DNShield.app" || true
        else
            xcrun stapler staple "${DIST_DIR}/DNShield.app" || true
        fi
    else
        log_error "App notarization failed or incomplete"
        
        # Try to extract submission ID for log retrieval
        SUBMISSION_ID=$(echo "$APP_NOTARIZATION_OUTPUT" | grep "id:" | head -1 | awk '{print $2}')
        if [ ! -z "$SUBMISSION_ID" ]; then
            fetch_notary_log "$SUBMISSION_ID" "app"
        fi
    fi
    
    # Clean up app zip
    rm -f "$APP_ZIP_PATH"
    
    # Notarize the installer package if it exists
    # Find the package with version in filename
    FINAL_PKG=$(ls "${DIST_DIR}"/DNShield-*.pkg 2>/dev/null | head -1)
    if [ -f "$FINAL_PKG" ]; then
        log_info "Notarizing installer package: $(basename "$FINAL_PKG")"
        
        # Submit package for notarization
        log_info "Submitting package to Apple (this may take several minutes)..."
        PKG_NOTARIZATION_OUTPUT=$(xcrun notarytool submit "$FINAL_PKG" \
            --apple-id "$APPLE_ID" \
            --team-id "$TEAM_ID" \
            --password "$APP_PASSWORD" \
            --wait 2>&1)
        
        echo "$PKG_NOTARIZATION_OUTPUT"
        
        # Check if package notarization was successful
        if echo "$PKG_NOTARIZATION_OUTPUT" | grep -q "status: Accepted"; then
            log_info "Package notarization successful!"
            
            log_info "Stapling notarization ticket to package..."
            if declare -F dns_staple_with_retry >/dev/null; then
                dns_staple_with_retry "$FINAL_PKG"
            else
                xcrun stapler staple "$FINAL_PKG"
            fi
            
            log_info "All notarization complete!"
        else
            log_error "Package notarization failed or incomplete"
            
            # Try to extract submission ID for log retrieval
            PKG_SUBMISSION_ID=$(echo "$PKG_NOTARIZATION_OUTPUT" | grep "id:" | head -1 | awk '{print $2}')
            if [ ! -z "$PKG_SUBMISSION_ID" ]; then
                fetch_notary_log "$PKG_SUBMISSION_ID" "package"
            fi
        fi
    fi
}

# Main build process
main() {
    log_info "Starting DNShield Enterprise build..."
    
    # Create Daemon directory if it doesn't exist
    if [ ! -d "${PROJECT_DIR}/Daemon" ]; then
        log_warning "Daemon directory not found, creating it..."
        mkdir -p "${PROJECT_DIR}/Daemon"
        
        # Check if daemon source was already created
        if [ ! -f "${PROJECT_DIR}/Daemon/main.m" ]; then
            log_error "Daemon source (Daemon/main.m) not found!"
            log_error "Please ensure the daemon implementation is in place"
            exit 1
        fi
    fi
    
    # Check for required environment variables
    if [ -z "$DEVELOPER_ID" ]; then
        log_warning "DEVELOPER_ID not set - daemon will not be signed"
        log_info "  export DEVELOPER_ID='Developer ID Application: Your Name (TEAMID)'"
    fi
    
    if [ -z "$INSTALLER_IDENTITY" ]; then
        log_warning "INSTALLER_IDENTITY not set - installer package will not be signed"
        log_info "  export INSTALLER_IDENTITY='Developer ID Installer: Your Name (TEAMID)'"
    fi
    
    if [ -z "$APPLE_ID" ] || [ -z "$TEAM_ID" ] || [ -z "$APP_PASSWORD" ]; then
        log_warning "APPLE_ID, TEAM_ID, or APP_PASSWORD not set"
        log_warning "Build will continue but notarization will not be available"
        log_info "Set these environment variables for notarization:"
        log_info "  export APPLE_ID='your-email@example.com'"
        log_info "  export TEAM_ID='C6F9Y6M584'"
        log_info "  export APP_PASSWORD='xxxx-xxxx-xxxx-xxxx'"
    fi
    
    # Sync version from VERSION file before build
    log_info "Syncing version from VERSION file..."
    SYNC_SCRIPT="${SCRIPT_DIR}/../scripts/sync/sync_version.sh"
    if [ -f "$SYNC_SCRIPT" ]; then
        "$SYNC_SCRIPT"
    else
        log_error "sync_version.sh not found at $SYNC_SCRIPT"
        exit 1
    fi
    
    # Execute build steps
    clean_build
    build_daemon
    build_watchdog
    build_app
    create_distribution
    create_installer
    notarize_app
    
    log_info "Enterprise build completed successfully!"
    log_info "Distribution files available at: ${DIST_DIR}"
}

# Run main function
main "$@"
