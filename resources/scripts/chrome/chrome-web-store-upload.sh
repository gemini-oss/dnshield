#!/bin/bash

# Chrome Web Store Upload Script
# Usage: ./chrome-web-store-upload.sh <zip_file_path> <version>
#
# Required environment variables:
# - CHROME_EXTENSION_ID
# - GOOGLE_CLIENT_ID
# - GOOGLE_CLIENT_SECRET
# - GOOGLE_REFRESH_TOKEN

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check arguments
if [ $# -ne 2 ]; then
    echo -e "${RED}Error: Missing arguments${NC}"
    echo "Usage: $0 <zip_file_path> <version>"
    exit 1
fi

ZIP_FILE_PATH="$1"
VERSION="$2"

# Validate ZIP_FILE_PATH
if [[ "$ZIP_FILE_PATH" = /* ]]; then
    echo -e "${RED}Error: Absolute paths are not allowed for zip file: $ZIP_FILE_PATH${NC}"
    exit 1
fi
if [[ "$ZIP_FILE_PATH" == *".."* ]]; then
    echo -e "${RED}Error: Directory traversal detected in zip file path: $ZIP_FILE_PATH${NC}"
    exit 1
fi
if [[ ! "$ZIP_FILE_PATH" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
    echo -e "${RED}Error: Zip file path contains invalid characters: $ZIP_FILE_PATH${NC}"
    exit 1
fi
# Check if zip file exists
if [ ! -f "$ZIP_FILE_PATH" ]; then
    echo -e "${RED}Error: Zip file not found: $ZIP_FILE_PATH${NC}"
    exit 1
fi

# Check required environment variables
REQUIRED_VARS=("CHROME_EXTENSION_ID" "GOOGLE_CLIENT_ID" "GOOGLE_CLIENT_SECRET" "GOOGLE_REFRESH_TOKEN")
MISSING_VARS=()

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_VARS+=("$var")
    fi
done

if [ ${#MISSING_VARS[@]} -ne 0 ]; then
    echo -e "${RED}Error: Missing required environment variables:${NC}"
    for var in "${MISSING_VARS[@]}"; do
        echo "  - $var"
    done
    echo ""
    echo "To set up Chrome Web Store credentials:"
    echo "1. Go to https://console.cloud.google.com/"
    echo "2. Create a new project or select existing"
    echo "3. Enable Chrome Web Store API"
    echo "4. Create OAuth 2.0 credentials"
    echo "5. Get refresh token using OAuth playground"
    echo ""
    echo "See: https://developer.chrome.com/docs/webstore/using_webstore_api"
    exit 1
fi

# Function to get access token
get_access_token() {
    local response=$(curl -s -X POST \
        -d "client_id=${GOOGLE_CLIENT_ID}" \
        -d "client_secret=${GOOGLE_CLIENT_SECRET}" \
        -d "refresh_token=${GOOGLE_REFRESH_TOKEN}" \
        -d "grant_type=refresh_token" \
        https://oauth2.googleapis.com/token)
    
    local access_token=$(echo "$response" | jq -r '.access_token // empty')
    
    if [ -z "$access_token" ]; then
        echo -e "${RED}Error: Failed to get access token${NC}"
        echo "Response: $response"
        exit 1
    fi
    
    echo "$access_token"
}

# Function to upload to Chrome Web Store
upload_to_store() {
    local access_token="$1"
    local zip_file="$2"
    
    echo -e "${BLUE}Uploading extension to Chrome Web Store...${NC}"
    
    # Upload the extension
    local upload_response=$(curl -s -X PUT \
        -H "Authorization: Bearer $access_token" \
        -H "x-goog-api-version: 2" \
        -T "$zip_file" \
        "https://www.googleapis.com/upload/chromewebstore/v1.1/items/${CHROME_EXTENSION_ID}")
    
    local upload_status=$(echo "$upload_response" | jq -r '.uploadState // empty')
    
    if [ "$upload_status" != "SUCCESS" ]; then
        echo -e "${RED}Error: Failed to upload extension${NC}"
        echo "Response: $upload_response"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Extension uploaded successfully${NC}"
}

# Function to publish the extension
publish_extension() {
    local access_token="$1"
    
    echo -e "${BLUE}Publishing extension...${NC}"
    
    # Publish the extension
    local publish_response=$(curl -s -X POST \
        -H "Authorization: Bearer $access_token" \
        -H "x-goog-api-version: 2" \
        -H "Content-Length: 0" \
        "https://www.googleapis.com/chromewebstore/v1.1/items/${CHROME_EXTENSION_ID}/publish")
    
    local status=$(echo "$publish_response" | jq -r '.status[0] // empty')
    
    if [ "$status" != "OK" ] && [ "$status" != "PUBLISHED" ]; then
        echo -e "${YELLOW}Warning: Extension may not have been published${NC}"
        echo "Response: $publish_response"
        echo ""
        echo "This could mean:"
        echo "- The extension is already published with this version"
        echo "- The extension is pending review"
        echo "- There was an error (check the Chrome Web Store Developer Dashboard)"
    else
        echo -e "${GREEN}✓ Extension published successfully${NC}"
    fi
}

# Function to check extension status
check_extension_status() {
    local access_token="$1"
    
    echo -e "${BLUE}Checking extension status...${NC}"
    
    local status_response=$(curl -s -X GET \
        -H "Authorization: Bearer $access_token" \
        -H "x-goog-api-version: 2" \
        "https://www.googleapis.com/chromewebstore/v1.1/items/${CHROME_EXTENSION_ID}?projection=DRAFT")
    
    local item_id=$(echo "$status_response" | jq -r '.id // empty')
    
    if [ -z "$item_id" ]; then
        echo -e "${RED}Error: Failed to get extension status${NC}"
        echo "Response: $status_response"
        exit 1
    fi
    
    echo "Extension details:"
    echo "  ID: $(echo "$status_response" | jq -r '.id // "N/A"')"
    echo "  Title: $(echo "$status_response" | jq -r '.title // "N/A"')"
    echo "  Status: $(echo "$status_response" | jq -r '.status // "N/A"')"
    echo "  Version: $(echo "$status_response" | jq -r '.version // "N/A"')"
}

# Main execution
echo -e "${GREEN}Chrome Web Store Upload Script${NC}"
echo "Version: $VERSION"
echo "Extension ID: $CHROME_EXTENSION_ID"
echo "Zip file: $ZIP_FILE_PATH"
echo ""

# Get access token
echo -e "${BLUE}Getting access token...${NC}"
ACCESS_TOKEN=$(get_access_token)
echo -e "${GREEN}✓ Access token obtained${NC}"

# Check current status
check_extension_status "$ACCESS_TOKEN"
echo ""

# Upload extension
upload_to_store "$ACCESS_TOKEN" "$ZIP_FILE_PATH"

# Publish extension
publish_extension "$ACCESS_TOKEN"

# Check final status
echo ""
check_extension_status "$ACCESS_TOKEN"

echo ""
echo -e "${GREEN}Upload process completed!${NC}"
echo ""
echo "Next steps:"
echo "1. Check the Chrome Web Store Developer Dashboard for status"
echo "2. The extension may take some time to be reviewed and published"
echo "3. Monitor email for any review feedback"
echo ""
echo "Dashboard: https://chrome.google.com/webstore/devconsole"