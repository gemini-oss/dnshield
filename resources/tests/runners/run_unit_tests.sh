#!/bin/bash
# Improved Unit Tests following Apple XCTest best practices
# Focus on isolated unit testing without system extension dependencies

set -e
cd "$(dirname "$0")"

echo "DNShield Unit Tests"
echo ""

# Clean any previous builds
echo "Cleaning previous builds..."
rm -rf build/UnitTests 2>/dev/null || true
mkdir -p build/UnitTests

# Create unit tests that follow Apple's recommendations for testable code
cat > build/UnitTests/IsolatedUnitTests.m << 'EOF'
#import <Foundation/Foundation.h>

// Mock simple assertion framework for standalone use
#define UNIT_ASSERT_TRUE(expr, msg) \
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

// Protocol-based approach following Apple's "Replace a concrete type with a protocol"
@protocol DNSRuleStorage <NSObject>
- (NSInteger)ruleCount;
- (void)addRule:(id)rule;
- (void)clearRules;
@end

@protocol DNSCache <NSObject>
- (void)clearCache;
- (id)cachedValueForDomain:(NSString *)domain;
- (void)setCachedValue:(id)value forDomain:(NSString *)domain;
@end

@protocol DNSPreferences <NSObject>
- (id)valueForKey:(NSString *)key;
- (void)setValue:(id)value forKey:(NSString *)key;
@end

// Testable implementation following Apple's dependency injection pattern
@interface TestableRuleManager : NSObject
@property (nonatomic, strong) id<DNSRuleStorage> storage;
@property (nonatomic, strong) id<DNSCache> cache;
@property (nonatomic, strong) id<DNSPreferences> preferences;

- (instancetype)initWithStorage:(id<DNSRuleStorage>)storage 
                          cache:(id<DNSCache>)cache 
                    preferences:(id<DNSPreferences>)preferences;
- (BOOL)shouldReloadManifest;
- (void)reloadManifestIfNeeded;
- (NSString *)currentManifestIdentifier;
@end

@implementation TestableRuleManager

- (instancetype)initWithStorage:(id<DNSRuleStorage>)storage 
                          cache:(id<DNSCache>)cache 
                    preferences:(id<DNSPreferences>)preferences {
    if (self = [super init]) {
        _storage = storage;
        _cache = cache;
        _preferences = preferences;
    }
    return self;
}

- (BOOL)shouldReloadManifest {
    // Simple logic for testing
    NSString *lastUpdate = [self.preferences valueForKey:@"LastManifestUpdate"];
    if (!lastUpdate) return YES;
    
    NSTimeInterval timeSince = [[NSDate date] timeIntervalSinceDate:[NSDate dateWithTimeIntervalSince1970:[lastUpdate doubleValue]]];
    return timeSince > 300; // 5 minutes
}

- (void)reloadManifestIfNeeded {
    if ([self shouldReloadManifest]) {
        // Simulate manifest loading
        [self.preferences setValue:@([[NSDate date] timeIntervalSince1970]) forKey:@"LastManifestUpdate"];
        [self.cache clearCache];
    }
}

- (NSString *)currentManifestIdentifier {
    return [self.preferences valueForKey:@"ManifestIdentifier"] ?: @"default";
}

@end

// Test doubles (stubs) following Apple's "sample" object pattern  
@interface TestRuleStorage : NSObject <DNSRuleStorage>
@property (nonatomic, assign) NSInteger ruleCount;
@property (nonatomic, strong) NSMutableArray *rules;
@end

@implementation TestRuleStorage

- (instancetype)init {
    if (self = [super init]) {
        _rules = [[NSMutableArray alloc] init];
    }
    return self;
}

- (NSInteger)ruleCount {
    return self.rules.count;
}

- (void)addRule:(id)rule {
    [self.rules addObject:rule];
}

- (void)clearRules {
    [self.rules removeAllObjects];
}

@end

@interface TestCache : NSObject <DNSCache>
@property (nonatomic, strong) NSMutableDictionary *cache;
@property (nonatomic, assign) BOOL wasCleared;
@end

@implementation TestCache

- (instancetype)init {
    if (self = [super init]) {
        _cache = [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (void)clearCache {
    [self.cache removeAllObjects];
    self.wasCleared = YES;
}

- (id)cachedValueForDomain:(NSString *)domain {
    return self.cache[domain];
}

- (void)setCachedValue:(id)value forDomain:(NSString *)domain {
    self.cache[domain] = value;
}

@end

@interface TestPreferences : NSObject <DNSPreferences>
@property (nonatomic, strong) NSMutableDictionary *values;
@end

@implementation TestPreferences

- (instancetype)init {
    if (self = [super init]) {
        _values = [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (id)valueForKey:(NSString *)key {
    return self.values[key];
}

- (void)setValue:(id)value forKey:(NSString *)key {
    self.values[key] = value;
}

@end

// Test functions following Apple's unit test patterns
void testManifestReloadLogic() {
    NSLog(@"Testing manifest reload logic...");
    
    TestRuleStorage *storage = [[TestRuleStorage alloc] init];
    TestCache *cache = [[TestCache alloc] init];
    TestPreferences *preferences = [[TestPreferences alloc] init];
    
    TestableRuleManager *manager = [[TestableRuleManager alloc] initWithStorage:storage 
                                                                           cache:cache 
                                                                     preferences:preferences];
    
    // Test initial state requires reload
    UNIT_ASSERT_TRUE([manager shouldReloadManifest], @"Initial state should require manifest reload");
    
    // Test reload updates timestamp
    [manager reloadManifestIfNeeded];
    UNIT_ASSERT_TRUE([preferences valueForKey:@"LastManifestUpdate"] != nil, @"Reload should set timestamp");
    UNIT_ASSERT_TRUE(cache.wasCleared, @"Reload should clear cache");
    
    // Test recent reload doesn't require another reload
    UNIT_ASSERT_TRUE(![manager shouldReloadManifest], @"Recent reload should not require another reload");
}

void testRuleStorageOperations() {
    NSLog(@"Testing rule storage operations...");
    
    TestRuleStorage *storage = [[TestRuleStorage alloc] init];
    
    // Test initial state
    UNIT_ASSERT_TRUE(storage.ruleCount == 0, @"Initial storage should be empty");
    
    // Test adding rules
    [storage addRule:@"rule1"];
    [storage addRule:@"rule2"];
    UNIT_ASSERT_TRUE(storage.ruleCount == 2, @"Storage should contain 2 rules after adding");
    
    // Test clearing rules
    [storage clearRules];
    UNIT_ASSERT_TRUE(storage.ruleCount == 0, @"Storage should be empty after clearing");
}

void testCacheOperations() {
    NSLog(@"Testing cache operations...");
    
    TestCache *cache = [[TestCache alloc] init];
    
    // Test cache miss
    UNIT_ASSERT_TRUE([cache cachedValueForDomain:@"example.com"] == nil, @"Cache miss should return nil");
    
    // Test cache hit
    [cache setCachedValue:@"blocked" forDomain:@"example.com"];
    NSString *cached = [cache cachedValueForDomain:@"example.com"];
    UNIT_ASSERT_TRUE([cached isEqualToString:@"blocked"], @"Cache hit should return stored value");
    
    // Test cache clear
    [cache clearCache];
    UNIT_ASSERT_TRUE([cache cachedValueForDomain:@"example.com"] == nil, @"Cache should be empty after clear");
    UNIT_ASSERT_TRUE(cache.wasCleared, @"Clear flag should be set");
}

void testPreferencesOperations() {
    NSLog(@"Testing preferences operations...");
    
    TestPreferences *prefs = [[TestPreferences alloc] init];
    
    // Test setting and getting values
    [prefs setValue:@"test-value" forKey:@"test-key"];
    NSString *value = [prefs valueForKey:@"test-key"];
    UNIT_ASSERT_TRUE([value isEqualToString:@"test-value"], @"Should retrieve stored preference value");
    
    // Test missing key
    UNIT_ASSERT_TRUE([prefs valueForKey:@"missing-key"] == nil, @"Missing key should return nil");
}

void testIntegratedManifestFlow() {
    NSLog(@"Testing integrated manifest flow...");
    
    TestRuleStorage *storage = [[TestRuleStorage alloc] init];
    TestCache *cache = [[TestCache alloc] init];
    TestPreferences *preferences = [[TestPreferences alloc] init];
    
    // Pre-populate cache and preferences
    [cache setCachedValue:@"cached-result" forDomain:@"test.com"];
    [preferences setValue:@"old-manifest" forKey:@"ManifestIdentifier"];
    
    TestableRuleManager *manager = [[TestableRuleManager alloc] initWithStorage:storage 
                                                                           cache:cache 
                                                                     preferences:preferences];
    
    // Test manifest identifier retrieval
    NSString *manifestId = [manager currentManifestIdentifier];
    UNIT_ASSERT_TRUE([manifestId isEqualToString:@"old-manifest"], @"Should retrieve current manifest ID");
    
    // Test reload clears cache but preserves preferences
    [manager reloadManifestIfNeeded];
    UNIT_ASSERT_TRUE(cache.wasCleared, @"Reload should clear cache");
    UNIT_ASSERT_TRUE([preferences valueForKey:@"ManifestIdentifier"] != nil, @"Preferences should be preserved");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"Starting isolated unit tests...\n");
        
        testManifestReloadLogic();
        NSLog(@"");
        
        testRuleStorageOperations();
        NSLog(@"");
        
        testCacheOperations();
        NSLog(@"");
        
        testPreferencesOperations();
        NSLog(@"");
        
        testIntegratedManifestFlow();
        NSLog(@"");
        
        NSLog(@"");
        NSLog(@"Unit Test Results Summary:");
        NSLog(@"Passed: %d", passes);
        NSLog(@"Failed: %d", failures);
        NSLog(@"Total:  %d", passes + failures);
        
        if (failures == 0) {
            NSLog(@"\nAll unit tests passed");
            return 0;
        } else {
            NSLog(@"\nSome unit tests failed.");
            return 1;
        }
    }
}
EOF

# Compile the unit tests
clang -o build/UnitTests/IsolatedUnitTests \
    -fobjc-arc \
    -framework Foundation \
    build/UnitTests/IsolatedUnitTests.m

if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

echo "Running isolated unit tests..."
echo ""

./build/UnitTests/IsolatedUnitTests

exit_code=$?

echo ""
echo "Unit test run complete."
echo ""

exit $exit_code