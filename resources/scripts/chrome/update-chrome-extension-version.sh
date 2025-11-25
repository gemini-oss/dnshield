#!/bin/bash

# Update Chrome Extension Version Script
# Usage: ./update-chrome-extension-version.sh [major|minor|patch]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default to patch if no argument provided
VERSION_TYPE=${1:-patch}

# Validate version type
if [[ ! "$VERSION_TYPE" =~ ^(major|minor|patch)$ ]]; then
    echo -e "${RED}Error: Invalid version type. Use major, minor, or patch${NC}"
    exit 1
fi

# Check if we're in the project root
if [ ! -f "chrome_extension/manifest.json" ]; then
    echo -e "${RED}Error: chrome_extension/manifest.json not found. Run this script from the project root.${NC}"
    exit 1
fi

# Check for required tools
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed. Install it with: brew install jq${NC}"
    exit 1
fi

if ! command -v semver &> /dev/null; then
    echo -e "${YELLOW}Warning: semver not found. Installing via npm...${NC}"
    npm install -g semver
fi

# Get current version
CURRENT_VERSION=$(jq -r '.version' chrome_extension/manifest.json)
echo -e "${GREEN}Current Chrome extension version: ${CURRENT_VERSION}${NC}"

# Calculate new version
NEW_VERSION=$(semver -i "$VERSION_TYPE" "$CURRENT_VERSION")
echo -e "${GREEN}New version will be: ${NEW_VERSION}${NC}"

# Update manifest.json
echo "Updating manifest.json..."
jq ".version = \"$NEW_VERSION\"" chrome_extension/manifest.json > chrome_extension/manifest.tmp && \
    mv chrome_extension/manifest.tmp chrome_extension/manifest.json

# Create a backup of the current extension
if [ -d "chrome_extension" ]; then
    echo "Creating backup of current version..."
    mkdir -p build/backups
    zip -r "build/backups/dnshield-chrome-extension-${CURRENT_VERSION}-backup.zip" chrome_extension \
        -x "*.zip" \
        -x ".DS_Store" \
        -x "*.bak" \
        -x "example-*" \
        -x ".git*" \
        > /dev/null 2>&1
fi

# Build the new version
echo "Building Chrome extension v${NEW_VERSION}..."
mkdir -p build
cd chrome_extension
zip -r "../build/dnshield-chrome-extension-${NEW_VERSION}.zip" . \
    -x "*.zip" \
    -x ".DS_Store" \
    -x "*.bak" \
    -x "example-*" \
    -x ".git*" \
    > /dev/null 2>&1
cd ..

echo -e "${GREEN}✓ Version updated to ${NEW_VERSION}${NC}"
echo -e "${GREEN}✓ Extension packaged at: build/dnshield-chrome-extension-${NEW_VERSION}.zip${NC}"

# Show next steps
echo ""
echo "Next steps:"
echo "1. Test the extension locally"
echo "2. Commit the version change: git add chrome_extension/manifest.json && git commit -m \"chore: bump Chrome extension to v${NEW_VERSION}\""
echo "3. Push to trigger the GitHub Action: git push"
echo "4. Or manually publish to Chrome Web Store: ./resources/scripts/chrome/chrome-web-store-upload.sh build/dnshield-chrome-extension-${NEW_VERSION}.zip ${NEW_VERSION}"