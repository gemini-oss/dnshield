#!/bin/bash
# DNShield Test Runner Script
# Handles cleaning, framework signing, and test execution

# Clean previous test builds
echo "Cleaning test build..."
xcodebuild clean -scheme DNShieldTests -quiet 2>/dev/null || true

# Run tests with simplified approach - let Xcode handle the build and signing
echo "Running tests..."
echo ""

# Use xcodebuild test with minimal overrides
# Only disable code signing requirements since we're testing locally
xcodebuild test \
    -scheme DNShieldTests \
    -destination 'platform=macOS,arch=arm64' \
    -disable-concurrent-testing \
    CODE_SIGNING_ALLOWED=NO \
    ENABLE_HARDENED_RUNTIME=NO \
    2>&1 | \
    grep -E "(Test Suite|Test Case|\[.*\].*passed|\[.*\].*failed|error:|warning:|Testing failed|TEST EXECUTE|tests? passed|tests? failed)" || {
        echo ""
        echo "Tests completed with issues. Run 'xcodebuild test -scheme DNShieldTests' for full output."
        exit 1
    }

echo ""
echo "Test run complete!"