//
//  RuleManagerManifestTests.m
//  DNShield Tests
//
//  Tests for manifest loading logic with fallback behavior
//

#import <XCTest/XCTest.h>
#import <objc/runtime.h>
#import "Testing/DNSTestCase.h"

#import <Extension/Rule/Manager+Manifest.h>

#import "ConfigurationManager.h"
#import "DNSManifest.h"
#import "DNSManifestResolver.h"
#import "DNShieldPreferences.h"
#import "LoggingManager.h"
#import "PreferenceManager.h"
#import "TestHelpers/MockManifestResolver.h"
#import "Testing/DNSManifest+Testing.h"

// Mock classes for testing

@interface MockPreferenceManager : PreferenceManager
@property(nonatomic, strong) NSMutableDictionary* mockPreferences;
@end

@implementation MockPreferenceManager

- (instancetype)init {
  self = [super init];
  if (self) {
    _mockPreferences = [NSMutableDictionary dictionary];
  }
  return self;
}

- (id)preferenceValueForKey:(NSString*)key inDomain:(NSString*)domain {
  return self.mockPreferences[key];
}

@end

@interface MockConfigurationManager : ConfigurationManager
@property(nonatomic, strong) DNSConfiguration* mockConfiguration;
@end

@implementation MockConfigurationManager

- (DNSConfiguration*)configurationFromResolvedManifest:(DNSResolvedManifest*)manifest {
  return self.mockConfiguration ?: [DNSConfiguration defaultConfiguration];
}

@end

// Test case
@interface RuleManagerManifestTests : DNSTestCase
@property(nonatomic, strong) RuleManager* ruleManager;
@property(nonatomic, strong) MockManifestResolver* mockResolver;
@property(nonatomic, strong) MockPreferenceManager* mockPreferenceManager;
@property(nonatomic, strong) MockConfigurationManager* mockConfigurationManager;
@end

@implementation RuleManagerManifestTests

- (void)setUp {
  [super setUp];

  // Setup mock preference manager
  self.mockPreferenceManager = [[MockPreferenceManager alloc] init];
  self.mockPreferenceManager.mockPreferences[kDNShieldManifestUpdateInterval] = @60;  // 1 minute

  // Swizzle PreferenceManager sharedManager
  Method originalMethod = class_getClassMethod([PreferenceManager class], @selector(sharedManager));
  Method swizzledMethod =
      class_getClassMethod([self class], @selector(mockSharedPreferenceManager));
  method_exchangeImplementations(originalMethod, swizzledMethod);

  // Setup mock configuration manager
  self.mockConfigurationManager = [[MockConfigurationManager alloc] init];

  // Swizzle ConfigurationManager sharedManager
  Method originalConfigMethod =
      class_getClassMethod([ConfigurationManager class], @selector(sharedManager));
  Method swizzledConfigMethod =
      class_getClassMethod([self class], @selector(mockSharedConfigurationManager));
  method_exchangeImplementations(originalConfigMethod, swizzledConfigMethod);

  // Setup mock manifest resolver
  self.mockResolver = [[MockManifestResolver alloc] init];

  // Initialize rule manager with manifest
  self.ruleManager = [[RuleManager alloc] initWithManifestIdentifier:@"test-machine"];

  // Replace the resolver with our mock
  // Note: setManifestResolver may not be exposed - use setValue:forKey: if needed
  [self.ruleManager setValue:self.mockResolver forKey:@"manifestResolver"];
}

- (void)tearDown {
  // Stop any timers
  [self.ruleManager stopManifestUpdateTimer];

  // Restore original methods
  Method originalMethod = class_getClassMethod([PreferenceManager class], @selector(sharedManager));
  Method swizzledMethod =
      class_getClassMethod([self class], @selector(mockSharedPreferenceManager));
  method_exchangeImplementations(originalMethod, swizzledMethod);

  Method originalConfigMethod =
      class_getClassMethod([ConfigurationManager class], @selector(sharedManager));
  Method swizzledConfigMethod =
      class_getClassMethod([self class], @selector(mockSharedConfigurationManager));
  method_exchangeImplementations(originalConfigMethod, swizzledConfigMethod);

  [super tearDown];
}

+ (PreferenceManager*)mockSharedPreferenceManager {
  static MockPreferenceManager* manager = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    manager = [[MockPreferenceManager alloc] init];
  });
  return manager;
}

+ (ConfigurationManager*)mockSharedConfigurationManager {
  static MockConfigurationManager* manager = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    manager = [[MockConfigurationManager alloc] init];
  });
  return manager;
}

#pragma mark - Helper Methods

- (DNSResolvedManifest*)createMockManifest:(NSString*)identifier {
  DNSManifest* manifest =
      [DNSManifest dns_manifestWithIdentifier:identifier
                                  displayName:[NSString stringWithFormat:@"Test %@", identifier]
                                        allow:nil
                                        block:@[]];

  DNSResolvedManifest* resolved = [[DNSResolvedManifest alloc] init];
  [resolved setValue:manifest forKey:@"baseManifest"];
  [resolved setValue:@[] forKey:@"resolvedRuleSources"];
  [resolved setValue:@{} forKey:@"resolvedManagedRules"];
  [resolved setValue:@[] forKey:@"warnings"];

  return resolved;
}

- (NSError*)createNotFoundError {
  return [NSError errorWithDomain:DNSManifestErrorDomain
                             code:DNSManifestErrorManifestNotFound
                         userInfo:@{NSLocalizedDescriptionKey : @"Manifest not found"}];
}

- (NSError*)createAuthError {
  return [NSError errorWithDomain:NSURLErrorDomain
                             code:401
                         userInfo:@{NSLocalizedDescriptionKey : @"Authentication failed"}];
}

#pragma mark - Test Cases

- (void)testLoadManifestWithPrimarySuccess {
  // Setup: Primary manifest exists
  DNSResolvedManifest* primaryManifest = [self createMockManifest:@"test-machine"];
  self.mockResolver.mockManifests[@"test-machine"] = primaryManifest;

  // Test
  NSError* error = nil;
  BOOL success = [self.ruleManager loadManifest:@"test-machine" error:&error];

  // Verify
  XCTAssertTrue(success);
  XCTAssertNil(error);
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 1);
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[0], @"test-machine");
  XCTAssertEqualObjects(self.ruleManager.currentManifestIdentifier, @"test-machine");
}

- (void)testLoadManifestFallbackTo404Default {
  // Setup: Primary manifest returns 404, default exists
  self.mockResolver.mockErrors[@"test-machine"] = [self createNotFoundError];
  DNSResolvedManifest* defaultManifest = [self createMockManifest:@"default"];
  self.mockResolver.mockManifests[@"default"] = defaultManifest;

  // Test
  NSError* error = nil;
  BOOL success = [self.ruleManager loadManifest:@"test-machine" error:&error];

  // Verify
  XCTAssertTrue(success);
  XCTAssertNil(error);
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 2);
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[0], @"test-machine");
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[1], @"default");
  XCTAssertEqualObjects(self.ruleManager.currentManifestIdentifier, @"test-machine");
}

- (void)testLoadManifestFallbackOn401AuthError {
  // Setup: Primary manifest returns 401, default exists
  self.mockResolver.mockErrors[@"test-machine"] = [self createAuthError];
  DNSResolvedManifest* defaultManifest = [self createMockManifest:@"default"];
  self.mockResolver.mockManifests[@"default"] = defaultManifest;

  // Test
  NSError* error = nil;
  BOOL success = [self.ruleManager loadManifest:@"test-machine" error:&error];

  // Verify
  XCTAssertTrue(success);
  XCTAssertNil(error);
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 2);
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[0], @"test-machine");
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[1], @"default");
}

- (void)testLoadManifestBothFail {
  // Setup: Both primary and default fail
  self.mockResolver.mockErrors[@"test-machine"] = [self createNotFoundError];
  self.mockResolver.mockErrors[@"default"] = [self createNotFoundError];

  // Test
  NSError* error = nil;
  BOOL success = [self.ruleManager loadManifest:@"test-machine" error:&error];

  // Verify
  XCTAssertFalse(success);
  XCTAssertNotNil(error);
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 2);
}

- (void)testManifestUpdateTimerFunctionality {
  // Setup: Create expectation for timer firing
  XCTestExpectation* timerExpectation = [self expectationWithDescription:@"Timer should fire"];

  // Clear existing history
  [self.mockResolver.resolveCallHistory removeAllObjects];

  // Setup manifests
  DNSResolvedManifest* manifest = [self createMockManifest:@"test-machine"];
  self.mockResolver.mockManifests[@"test-machine"] = manifest;

  // Swizzle loadManifest to notify when called
  __block NSInteger loadCount = 0;
  Method originalMethod = class_getInstanceMethod([RuleManager class], @selector(loadManifest:
                                                                                        error:));
  IMP originalIMP = method_getImplementation(originalMethod);
  IMP newIMP = imp_implementationWithBlock(^BOOL(id self, NSString* identifier, NSError** error) {
    loadCount++;
    if (loadCount > 1) {  // Skip initial load
      [timerExpectation fulfill];
    }
    return ((BOOL (*)(id, SEL, NSString*, NSError**))originalIMP)(
        self, @selector(loadManifest:error:), identifier, error);
  });
  method_setImplementation(originalMethod, newIMP);

  // Set short interval for testing
  ((MockPreferenceManager*)[PreferenceManager sharedManager])
      .mockPreferences[kDNShieldManifestUpdateInterval] = @1;  // 1 second

  // Start timer
  [self.ruleManager startManifestUpdateTimer];

  // Wait for timer
  [self waitForExpectationsWithTimeout:2.0 handler:nil];

  // Restore original implementation
  method_setImplementation(originalMethod, originalIMP);

  // Verify
  XCTAssertGreaterThan(loadCount, 1);
}

- (void)testOriginalManifestIdentifierPreserved {
  // Setup: Primary manifest fails, fallback to default
  self.mockResolver.mockErrors[@"machine-serial"] = [self createNotFoundError];
  DNSResolvedManifest* defaultManifest = [self createMockManifest:@"default"];
  self.mockResolver.mockManifests[@"default"] = defaultManifest;

  // Create rule manager with machine serial
  RuleManager* manager = [[RuleManager alloc] initWithManifestIdentifier:@"machine-serial"];
  // Note: setManifestResolver may not be exposed - use setValue:forKey: if needed
  [manager setValue:self.mockResolver forKey:@"manifestResolver"];

// Verify original identifier is preserved
// Note: OriginalManifestIdentifierKey selector may not exist
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"
  NSString* originalIdentifier =
      objc_getAssociatedObject(manager, @selector(OriginalManifestIdentifierKey));
#pragma clang diagnostic pop
  XCTAssertEqualObjects(originalIdentifier, @"machine-serial");

  // Clear history and setup for second load
  [self.mockResolver.resolveCallHistory removeAllObjects];

  // Load again - should try machine-serial first
  NSError* error = nil;
  [manager loadManifest:originalIdentifier error:&error];

  // Verify it tried machine-serial first
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 2);
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[0], @"machine-serial");
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[1], @"default");
}

- (void)testNoFallbackWhenLoadingDefault {
  // Setup: Loading default directly when it doesn't exist
  self.mockResolver.mockErrors[@"default"] = [self createNotFoundError];

  // Test
  NSError* error = nil;
  BOOL success = [self.ruleManager loadManifest:@"default" error:&error];

  // Verify - should not try fallback since we're already loading default
  XCTAssertFalse(success);
  XCTAssertNotNil(error);
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 1);
  XCTAssertEqualObjects(self.mockResolver.resolveCallHistory[0], @"default");
}

- (void)testNonAuthErrorDoesNotTriggerFallback {
  // Setup: Primary manifest returns generic error (not 404 or 401)
  NSError* genericError = [NSError errorWithDomain:NSURLErrorDomain
                                              code:500
                                          userInfo:@{NSLocalizedDescriptionKey : @"Server error"}];
  self.mockResolver.mockErrors[@"test-machine"] = genericError;

  // Test
  NSError* error = nil;
  BOOL success = [self.ruleManager loadManifest:@"test-machine" error:&error];

  // Verify - should not fallback
  XCTAssertFalse(success);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, 500);
  XCTAssertEqual(self.mockResolver.resolveCallHistory.count, 1);
}

@end
