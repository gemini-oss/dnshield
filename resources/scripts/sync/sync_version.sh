#!/bin/bash
#
# Sync version from root VERSION file to all Info.plist files
#

set -e

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Navigate from resources/scripts/sync/ to project root
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
dnshield_DIR="$ROOT_DIR/dnshield"

# Read version from VERSION file
if [ ! -f "$ROOT_DIR/VERSION" ]; then
    echo "ERROR: VERSION file not found at $ROOT_DIR/VERSION"
    exit 1
fi

VERSION=$(cat "$ROOT_DIR/VERSION" | tr -d '\n')
echo "Syncing version $VERSION to Info.plist files..."

# Extract version components
VERSION_PARTS=(${VERSION//./ })
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

# Full version string for CFBundleVersion (e.g., 1.1.74)
FULL_VERSION="${VERSION}"

# Short version string for CFBundleShortVersionString (e.g., 1.1)
SHORT_VERSION="${MAJOR}.${MINOR}"

# Update App Info.plist
APP_PLIST="$dnshield_DIR/App/Info.plist"
if [ -f "$APP_PLIST" ]; then
    echo "Updating $APP_PLIST..."
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $SHORT_VERSION" "$APP_PLIST"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $FULL_VERSION" "$APP_PLIST"
else
    echo "WARNING: App Info.plist not found at $APP_PLIST"
fi

# Update Extension Info.plist
EXT_PLIST="$dnshield_DIR/Extension/Info.plist"
if [ -f "$EXT_PLIST" ]; then
    echo "Updating $EXT_PLIST..."
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $SHORT_VERSION" "$EXT_PLIST"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $FULL_VERSION" "$EXT_PLIST"
else
    echo "WARNING: Extension Info.plist not found at $EXT_PLIST"
fi

echo "Version sync complete!"
echo "  App version: $SHORT_VERSION (build $FULL_VERSION)"
echo "  Extension version: $SHORT_VERSION (build $FULL_VERSION)"