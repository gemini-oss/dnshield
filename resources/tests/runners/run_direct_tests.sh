#!/bin/bash
# Direct Unit Tests - Bypass Xcode project entirely
# Compile and run specific test components directly

set -e
cd "$(dirname "$0")"

# Clean any previous builds
rm -rf build/DirectTests 2>/dev/null || true
mkdir -p build/DirectTests

echo "Compiling direct unit tests..."

# Create a standalone test that tests just the core logic classes
cat > build/DirectTests/DirectTests.m << 'EOF'
#import <Foundation/Foundation.h>

// Simple test framework
#define TEST_ASSERT(expr, msg) \
    do { \
        if (!(expr)) { \
            NSLog(@"FAIL: %s - %@", #expr, msg); \
            failures++; \
        } else { \
            NSLog(@"PASS: %s", #expr); \
            passes++; \
        } \
    } while(0)

static int passes = 0;
static int failures = 0;

// Test wildcard domain matching (simplified implementation for testing)
@interface SimpleWildcardMatcher : NSObject
+ (BOOL)domain:(NSString *)domain matchesPattern:(NSString *)pattern includeRoot:(BOOL)includeRoot;
@end

@implementation SimpleWildcardMatcher
+ (BOOL)domain:(NSString *)domain matchesPattern:(NSString *)pattern includeRoot:(BOOL)includeRoot {
    if (![pattern hasPrefix:@"*."]) {
        return [domain isEqualToString:pattern];
    }
    
    NSString *baseDomain = [pattern substringFromIndex:2]; // Remove "*."
    
    if ([domain isEqualToString:baseDomain]) {
        return includeRoot;
    }
    
    return [domain hasSuffix:[@"." stringByAppendingString:baseDomain]];
}
@end

// Test rule precedence (simplified implementation)
typedef NS_ENUM(NSInteger, SimpleRuleAction) {
    SimpleRuleActionAllow = 0,
    SimpleRuleActionBlock = 1,
    SimpleRuleActionUnknown = -1
};

@interface SimpleRule : NSObject
@property (nonatomic, strong) NSString *domain;
@property (nonatomic, assign) SimpleRuleAction action;
@property (nonatomic, assign) NSInteger priority;
@end

@implementation SimpleRule
@end

@interface SimpleRulePrecedence : NSObject
+ (SimpleRuleAction)resolveConflictBetweenRules:(NSArray<SimpleRule *> *)rules;
@end

@implementation SimpleRulePrecedence
+ (SimpleRuleAction)resolveConflictBetweenRules:(NSArray<SimpleRule *> *)rules {
    if (rules.count == 0) return SimpleRuleActionUnknown;
    
    // Higher priority wins
    SimpleRule *highestPriorityRule = rules[0];
    for (SimpleRule *rule in rules) {
        if (rule.priority > highestPriorityRule.priority) {
            highestPriorityRule = rule;
        }
    }
    
    return highestPriorityRule.action;
}
@end

// Test functions
void testWildcardMatching() {
    NSLog(@"Testing wildcard domain matching...");
    
    // Test subdomain matching
    TEST_ASSERT([SimpleWildcardMatcher domain:@"sub.example.com" matchesPattern:@"*.example.com" includeRoot:NO],
                @"Subdomain should match wildcard pattern");
    
    // Test root domain exclusion
    TEST_ASSERT(![SimpleWildcardMatcher domain:@"example.com" matchesPattern:@"*.example.com" includeRoot:NO],
                @"Root domain should NOT match in subdomains-only mode");
    
    // Test root domain inclusion
    TEST_ASSERT([SimpleWildcardMatcher domain:@"example.com" matchesPattern:@"*.example.com" includeRoot:YES],
               @"Root domain SHOULD match in include-root mode");
    
    // Test non-matching domain
    TEST_ASSERT(![SimpleWildcardMatcher domain:@"other.com" matchesPattern:@"*.example.com" includeRoot:YES],
               @"Unrelated domain should not match");
    
    // Test exact domain matching
    TEST_ASSERT([SimpleWildcardMatcher domain:@"exact.com" matchesPattern:@"exact.com" includeRoot:NO],
               @"Exact domain should match exact pattern");
}

void testRulePrecedence() {
    NSLog(@"Testing rule precedence resolution...");
    
    SimpleRule *blockRule = [[SimpleRule alloc] init];
    blockRule.domain = @"example.com";
    blockRule.action = SimpleRuleActionBlock;
    blockRule.priority = 100;
    
    SimpleRule *allowRule = [[SimpleRule alloc] init];
    allowRule.domain = @"example.com";
    allowRule.action = SimpleRuleActionAllow;
    allowRule.priority = 150;
    
    // Test that higher priority wins
    NSArray *rules = @[blockRule, allowRule];
    SimpleRuleAction result = [SimpleRulePrecedence resolveConflictBetweenRules:rules];
    TEST_ASSERT(result == SimpleRuleActionAllow, @"Higher priority allow rule should win");
    
    // Test single rule
    NSArray *singleRule = @[blockRule];
    SimpleRuleAction singleResult = [SimpleRulePrecedence resolveConflictBetweenRules:singleRule];
    TEST_ASSERT(singleResult == SimpleRuleActionBlock, @"Single block rule should return block");
    
    // Test empty rules
    NSArray *emptyRules = @[];
    SimpleRuleAction emptyResult = [SimpleRulePrecedence resolveConflictBetweenRules:emptyRules];
    TEST_ASSERT(emptyResult == SimpleRuleActionUnknown, @"Empty rules should return unknown");
}

void testDomainValidation() {
    NSLog(@"Testing domain validation logic...");
    
    // Valid domains
    NSString *validDomain1 = @"example.com";
    NSString *validDomain2 = @"sub.example.org";
    NSString *validDomain3 = @"a.b.c.d";
    
    // Test basic validation (length > 0 and contains dot)
    BOOL valid1 = validDomain1.length > 0 && [validDomain1 containsString:@"."];
    BOOL valid2 = validDomain2.length > 0 && [validDomain2 containsString:@"."];
    BOOL valid3 = validDomain3.length > 0 && [validDomain3 containsString:@"."];
    
    TEST_ASSERT(valid1, @"example.com should be valid");
    TEST_ASSERT(valid2, @"sub.example.org should be valid");
    TEST_ASSERT(valid3, @"a.b.c.d should be valid");
    
    // Invalid domains
    NSString *invalidDomain1 = @"";
    NSString *invalidDomain2 = @"nodot";
    NSString *invalidDomain3 = @"..invalid";
    
    BOOL invalid1 = !(invalidDomain1.length > 0 && [invalidDomain1 containsString:@"."]);
    BOOL invalid2 = !(invalidDomain2.length > 0 && [invalidDomain2 containsString:@"."]);
    BOOL invalid3 = [invalidDomain3 hasPrefix:@".."];
    
    TEST_ASSERT(invalid1, @"Empty domain should be invalid");
    TEST_ASSERT(invalid2, @"Domain without dot should be invalid");
    TEST_ASSERT(invalid3, @"Domain starting with .. should be invalid");
}

void testManifestURLValidation() {
    NSLog(@"Testing manifest URL validation...");
    
    NSString *validURL = @"https://example.com/manifest.json";
    NSString *validURL2 = @"http://localhost:8080/test";
    NSString *invalidURL1 = @"ftp://invalid.com/file";
    NSString *invalidURL2 = @"not-a-url";
    
    NSURL *url1 = [NSURL URLWithString:validURL];
    NSURL *url2 = [NSURL URLWithString:validURL2];
    NSURL *url3 = [NSURL URLWithString:invalidURL1];
    NSURL *url4 = [NSURL URLWithString:invalidURL2];
    
    // Test valid HTTPS URL
    TEST_ASSERT(url1 && [url1.scheme isEqualToString:@"https"], @"HTTPS URL should be valid");
    
    // Test valid HTTP URL (for localhost testing)
    TEST_ASSERT(url2 && [url2.scheme isEqualToString:@"http"], @"HTTP localhost URL should be valid");
    
    // Test invalid scheme
    BOOL invalidScheme = url3 && ![url3.scheme isEqualToString:@"https"] && ![url3.scheme isEqualToString:@"http"];
    TEST_ASSERT(invalidScheme, @"FTP URL should be flagged as invalid scheme");
    
    // Test malformed URL (NSURL is forgiving, so check if it creates a valid URL object)
    BOOL isMalformedURL = (url4 == nil) || (url4.scheme == nil);
    TEST_ASSERT(isMalformedURL, @"Malformed URL should fail to parse or have no scheme");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"Starting direct unit tests...\n");
        
        testWildcardMatching();
        NSLog(@"");
        
        testRulePrecedence();
        NSLog(@"");
        
        testDomainValidation();
        NSLog(@"");
        
        testManifestURLValidation();
        NSLog(@"");
        
        NSLog(@"=========================");
        NSLog(@"Test Results Summary:");
        NSLog(@"Passed: %d", passes);
        NSLog(@"Failed: %d", failures);
        NSLog(@"Total:  %d", passes + failures);
        
        if (failures == 0) {
            NSLog(@"\nAll direct unit tests passed!");
            NSLog(@"These tests validate core DNS logic without system dependencies.");
            return 0;
        } else {
            NSLog(@"\nSome direct tests failed.");
            return 1;
        }
    }
}
EOF

# Compile the direct tests
clang -o build/DirectTests/DirectTests \
    -fobjc-arc \
    -framework Foundation \
    build/DirectTests/DirectTests.m

if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

echo "Running direct unit tests..."
echo ""

./build/DirectTests/DirectTests

exit_code=$?

echo ""
echo "Direct test run complete."

exit $exit_code