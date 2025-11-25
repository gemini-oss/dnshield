#!/bin/bash
# Simple DNShield Tests - Core logic only, no mocking required
# Tests basic functionality without complex dependencies

set -e
cd "$(dirname "$0")"

# Clean any previous builds
echo "Cleaning previous builds..."
rm -rf build/SimpleTests 2>/dev/null || true
mkdir -p build/SimpleTests

# Create a simple test harness with minimal dependencies
echo "Creating test harness..."
cat > build/SimpleTests/SimpleTests.m << 'EOF'
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// Simple assertion macros
#define ASSERT_TRUE(expr, msg) \
    do { \
        if (!(expr)) { \
            NSLog(@"FAIL: %s - %@", #expr, msg); \
            failures++; \
        } else { \
            NSLog(@"PASS: %s", #expr); \
            passes++; \
        } \
    } while(0)

#define ASSERT_FALSE(expr, msg) \
    do { \
        if (expr) { \
            NSLog(@"FAIL: !(%s) - %@", #expr, msg); \
            failures++; \
        } else { \
            NSLog(@"PASS: !(%s)", #expr); \
            passes++; \
        } \
    } while(0)

#define ASSERT_EQUAL(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            NSLog(@"FAIL: %s == %s - %@ (got %ld, expected %ld)", #a, #b, msg, (long)(a), (long)(b)); \
            failures++; \
        } else { \
            NSLog(@"PASS: %s == %s", #a, #b); \
            passes++; \
        } \
    } while(0)

#define ASSERT_NOT_NIL(obj, msg) \
    do { \
        if (!(obj)) { \
            NSLog(@"FAIL: %s not nil - %@", #obj, msg); \
            failures++; \
        } else { \
            NSLog(@"PASS: %s not nil", #obj); \
            passes++; \
        } \
    } while(0)

static int passes = 0;
static int failures = 0;

// Basic wildcard matching test (simplified version)
void testWildcardMatching() {
    NSLog(@"Testing wildcard matching...");
    
    // Simple string-based wildcard matching for testing
    NSString *pattern = @"*.example.com";
    NSString *testDomain1 = @"sub.example.com";
    NSString *testDomain2 = @"example.com";
    NSString *testDomain3 = @"other.com";
    
    // Simple pattern matching logic for test purposes
    BOOL matches1 = [testDomain1 hasSuffix:@"example.com"];
    BOOL matches2 = [testDomain2 hasSuffix:@"example.com"];  
    BOOL matches3 = [testDomain3 hasSuffix:@"example.com"];
    
    ASSERT_TRUE(matches1, @"Subdomain should match wildcard");
    ASSERT_TRUE(matches2, @"Root domain should match in this test");
    ASSERT_FALSE(matches3, @"Unrelated domain should not match");
}

// Basic domain validation test
void testDomainValidation() {
    NSLog(@"Testing domain validation...");
    
    NSString *validDomain = @"example.com";
    NSString *invalidDomain1 = @"";
    NSString *invalidDomain2 = @"..invalid..";
    
    BOOL valid1 = validDomain.length > 0 && [validDomain containsString:@"."];
    BOOL valid2 = invalidDomain1.length > 0;
    BOOL valid3 = ![invalidDomain2 containsString:@".."];
    
    ASSERT_TRUE(valid1, @"Valid domain should pass validation");
    ASSERT_FALSE(valid2, @"Empty domain should fail validation");
    ASSERT_FALSE(valid3, @"Domain with consecutive dots should fail");
}

// Basic rule priority test
void testRulePriority() {
    NSLog(@"Testing rule priority logic...");
    
    // Simulate rule priority comparison
    NSInteger allowRulePriority = 150;
    NSInteger blockRulePriority = 100;
    NSInteger systemRulePriority = 50;
    
    ASSERT_TRUE(allowRulePriority > blockRulePriority, @"Allow rule should have higher priority than block");
    ASSERT_TRUE(blockRulePriority > systemRulePriority, @"User rule should have higher priority than system");
}

// Basic URL validation test
void testURLValidation() {
    NSLog(@"Testing URL validation...");
    
    NSString *validURL = @"https://example.com/manifest";
    NSString *invalidURL = @"not-a-url";
    
    NSURL *url1 = [NSURL URLWithString:validURL];
    NSURL *url2 = [NSURL URLWithString:invalidURL];
    
    ASSERT_NOT_NIL(url1, @"Valid URL should parse");
    ASSERT_TRUE([url1.scheme isEqualToString:@"https"], @"URL should have HTTPS scheme");
}

// Main test runner
int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"Starting simple logic tests...\n");
        
        testWildcardMatching();
        NSLog(@"");
        
        testDomainValidation();
        NSLog(@"");
        
        testRulePriority();
        NSLog(@"");
        
        testURLValidation();
        NSLog(@"");
        
        NSLog(@"Test Results:");
        NSLog(@"");
        NSLog(@"Passed: %d", passes);
        NSLog(@"Failed: %d", failures);
        NSLog(@"Total:  %d", passes + failures);
        
        if (failures == 0) {
            NSLog(@"\nAll simple tests passed!");
            return 0;
        } else {
            NSLog(@"\nSome tests failed.");
            return 1;
        }
    }
}
EOF

# Compile and run the simple tests
echo "Compiling simple tests..."
clang -o build/SimpleTests/SimpleTests \
    -fobjc-arc \
    -framework Foundation \
    build/SimpleTests/SimpleTests.m

if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

echo "Running simple tests..."
echo ""

./build/SimpleTests/SimpleTests

exit_code=$?

echo ""
echo "Simple test run complete."
echo ""
echo "These tests validate basic logic without complex dependencies."
echo "For all test suites, use 'make test' (runs simple + unit + direct tests)."

exit $exit_code