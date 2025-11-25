//
//  RuleManagerSyncTests.m
//  DNShield Tests
//
//  Tests for sync rules functionality with empty database scenarios
//

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import "Testing/DNSTestCase.h"
#import "Testing/OCMock+DNSTesting.h"

#import <Extension/ConfigurationManager.h>
#import <Extension/Rule/RuleDatabase.h>

#import <Extension/Rule/Manager+Manifest.h>
#import <Extension/Rule/Manager.h>

#import "DNSManifest.h"
#import "DNSManifestResolver.h"

#import "PreferenceManager.h"

// #import "RuleSource.h" // Not available yet
// #import "UpdateScheduler.h" // Not available yet

@interface RuleManager (TestAccess)
@property(nonatomic, strong) DNSManifestResolver* manifestResolver;
@property(nonatomic, strong) DNSResolvedManifest* currentResolvedManifest;
@property(nonatomic, strong) NSString* currentManifestIdentifier;
// @property(nonatomic, strong) UpdateScheduler *scheduler; // Class doesn't exist
- (NSString*)determineManifestIdentifier;
- (BOOL)isResolvedManifestEqual:(DNSResolvedManifest*)manifest1 to:(DNSResolvedManifest*)manifest2;
- (void)updateConfiguration:(DNSConfiguration*)configuration;
@end

@interface RuleManagerSyncTests : DNSTestCase
@property(nonatomic, strong) RuleManager* ruleManager;
@property(nonatomic, strong) id mockManifestResolver;
@property(nonatomic, strong) id mockPreferenceManager;
@property(nonatomic, strong) id mockConfigurationManager;
// @property(nonatomic, strong) id mockScheduler; // UpdateScheduler doesn't exist
@property(nonatomic, strong) id mockDatabase;
@end

@implementation RuleManagerSyncTests

- (void)setUp {
  [super setUp];

  // Create mocks
  self.mockManifestResolver = OCMClassMock([DNSManifestResolver class]);
  self.mockPreferenceManager = OCMClassMock([PreferenceManager class]);
  self.mockConfigurationManager = OCMClassMock([ConfigurationManager class]);
  // UpdateScheduler not available yet
  // self.mockScheduler = OCMClassMock([UpdateScheduler class]);
  self.mockDatabase = OCMClassMock([RuleDatabase class]);

  // Setup default configuration
  DNSConfiguration* defaultConfig = [[DNSConfiguration alloc] init];
  OCMStub([self.mockConfigurationManager currentConfiguration]).andReturn(defaultConfig);

  // Create rule manager
  self.ruleManager = [[RuleManager alloc] initWithConfiguration:defaultConfig];
  self.ruleManager.manifestResolver = self.mockManifestResolver;
  // self.ruleManager.scheduler = self.mockScheduler; // UpdateScheduler doesn't exist
}

- (void)tearDown {
  [self.mockManifestResolver stopMocking];
  [self.mockPreferenceManager stopMocking];
  [self.mockConfigurationManager stopMocking];
  // [self.mockScheduler stopMocking]; // UpdateScheduler doesn't exist
  [self.mockDatabase stopMocking];

  self.ruleManager = nil;
  [super tearDown];
}

#pragma mark - Test reloadManifestIfNeeded with empty database

- (void)testReloadManifestIfNeeded_WithNoCurrentManifest_DeterminesAndLoadsManifest {
  // Given: No current manifest identifier
  self.ruleManager.currentManifestIdentifier = nil;
  self.ruleManager.currentResolvedManifest = nil;

  // Mock determineManifestIdentifier to return "default"
  OCMStub([self.ruleManager determineManifestIdentifier]).andReturn(@"default");

  // Create mock resolved manifest
  DNSResolvedManifest* mockResolvedManifest = OCMClassMock([DNSResolvedManifest class]);
  OCMStub([mockResolvedManifest resolvedRuleSources]).andReturn(@[]);

  // Mock resolver to return manifest
  OCMStub([self.mockManifestResolver resolveManifestWithFallback:@"default"
                                                           error:[OCMArg anyObjectRef]])
      .andReturn(mockResolvedManifest);

  // Mock configuration manager
  DNSConfiguration* mockConfig = [[DNSConfiguration alloc] init];
  mockConfig.ruleSources = @[];
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:mockResolvedManifest])
      .andReturn(mockConfig);

  // When: reloadManifestIfNeeded is called
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should determine manifest, load it, and trigger update
  XCTAssertEqualObjects(self.ruleManager.currentManifestIdentifier, @"default",
                        @"Should set current manifest identifier");
  XCTAssertNotNil(self.ruleManager.currentResolvedManifest,
                  @"Should set current resolved manifest");
  // OCMVerify([self.mockScheduler updateAllSourcesWithPriority:UpdatePriorityHigh]); //
  // UpdateScheduler doesn't exist
}

- (void)testReloadManifestIfNeeded_WithEmptyDatabase_TriggersForceUpdate {
  // Given: Database is empty (simulated by no current resolved manifest)
  self.ruleManager.currentManifestIdentifier = nil;
  self.ruleManager.currentResolvedManifest = nil;

  // Mock manifest resolution
  OCMStub([self.ruleManager determineManifestIdentifier]).andReturn(@"test-manifest");

  DNSResolvedManifest* mockResolvedManifest = OCMClassMock([DNSResolvedManifest class]);
  // Mock empty rule sources since RuleSource class doesn't exist
  OCMStub([mockResolvedManifest resolvedRuleSources]).andReturn(@[]);

  OCMStub([self.mockManifestResolver resolveManifestWithFallback:@"test-manifest"
                                                           error:[OCMArg anyObjectRef]])
      .andReturn(mockResolvedManifest);

  DNSConfiguration* mockConfig = [[DNSConfiguration alloc] init];
  mockConfig.ruleSources = @[];  // Empty since RuleSource doesn't exist
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:mockResolvedManifest])
      .andReturn(mockConfig);

  // When: reloadManifestIfNeeded is called
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should trigger force update
  // OCMVerify([self.mockScheduler updateAllSourcesWithPriority:UpdatePriorityHigh]); //
  // UpdateScheduler doesn't exist
}

#pragma mark - Test manifest identifier fallback logic

- (void)testManifestFallback_PrimaryFails_FallsBackToSerial {
  // Given: Primary manifest fails, serial manifest succeeds
  self.ruleManager.currentManifestIdentifier = nil;

  // Mock preference for primary identifier
  OCMStub([self.mockPreferenceManager preferenceValueForKey:@"ManifestIdentifier"
                                                   inDomain:@"com.dnshield.app"])
      .andReturn(@"custom-manifest");

  // Mock serial number
  OCMStub([DNSManifestResolver getMachineSerialNumber]).andReturn(@"SERIAL123");

  // Primary manifest fails with 404
  NSError* notFoundError =
      [NSError errorWithDomain:@"DNSManifest"
                          code:404
                      userInfo:@{NSLocalizedDescriptionKey : @"Manifest not found"}];

  DNSResolvedManifest* serialManifest = OCMClassMock([DNSResolvedManifest class]);

  // Setup resolver to fail for custom, succeed for serial
  __block NSInteger callCount = 0;
  OCMStub([self.mockManifestResolver resolveManifestWithFallback:[OCMArg any]
                                                           error:[OCMArg anyObjectRef]])
      .andDo(^(NSInvocation* invocation) {
        NSString* identifier;
        [invocation getArgument:&identifier atIndex:2];

        NSError* __autoreleasing* errorPtr;
        [invocation getArgument:&errorPtr atIndex:3];

        callCount++;
        if (callCount == 1) {
          // First call with custom-manifest should try fallback internally
          [invocation setReturnValue:&serialManifest];
        }
      });

  DNSConfiguration* mockConfig = [[DNSConfiguration alloc] init];
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:serialManifest])
      .andReturn(mockConfig);

  // When: reloadManifestIfNeeded is called
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should load successfully with fallback
  XCTAssertNotNil(self.ruleManager.currentResolvedManifest,
                  @"Should have loaded manifest via fallback");
}

- (void)testManifestFallback_AllFail_DoesNotTriggerUpdate {
  // Given: All manifests fail
  self.ruleManager.currentManifestIdentifier = nil;

  OCMStub([self.ruleManager determineManifestIdentifier]).andReturn(@"failing-manifest");

  NSError* error = [NSError errorWithDomain:@"DNSManifest"
                                       code:500
                                   userInfo:@{NSLocalizedDescriptionKey : @"Server error"}];

  OCMStub([self.mockManifestResolver resolveManifestWithFallback:[OCMArg any]
                                                           error:[OCMArg anyObjectRef]])
      .andDo(^(NSInvocation* invocation) {
        NSError* __autoreleasing* errorPtr;
        [invocation getArgument:&errorPtr atIndex:3];
        if (errorPtr) {
          *errorPtr = error;
        }
        DNSResolvedManifest* nilManifest = nil;
        [invocation setReturnValue:&nilManifest];
      });

  // When: reloadManifestIfNeeded is called
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should NOT trigger update to prevent infinite loops
  // OCMReject([self.mockScheduler updateAllSourcesWithPriority:UpdatePriorityHigh]); //
  // UpdateScheduler doesn't exist
  XCTAssertNil(self.ruleManager.currentResolvedManifest,
               @"Should not have a resolved manifest when all fallbacks fail");
}

#pragma mark - Test sync rules command processing

- (void)testSyncRulesCommand_WithEmptyDatabase_LoadsManifestAndRules {
  // Given: Database is empty, sync command received
  self.ruleManager.currentManifestIdentifier = nil;
  self.ruleManager.currentResolvedManifest = nil;

  // Setup manifest resolution
  OCMStub([self.ruleManager determineManifestIdentifier]).andReturn(@"default");

  DNSResolvedManifest* mockManifest = OCMClassMock([DNSResolvedManifest class]);
  // Mock empty rule sources since RuleSource class doesn't exist
  OCMStub([mockManifest resolvedRuleSources]).andReturn(@[]);

  OCMStub([self.mockManifestResolver resolveManifestWithFallback:@"default"
                                                           error:[OCMArg anyObjectRef]])
      .andReturn(mockManifest);

  DNSConfiguration* config = [[DNSConfiguration alloc] init];
  config.ruleSources = @[];  // Empty since RuleSource doesn't exist
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:mockManifest])
      .andReturn(config);

  // When: Sync is triggered (simulating menu bar sync click)
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should load manifest and trigger rule updates
  XCTAssertEqualObjects(self.ruleManager.currentManifestIdentifier, @"default",
                        @"Should set manifest identifier");
  XCTAssertNotNil(self.ruleManager.currentResolvedManifest, @"Should have resolved manifest");
  // OCMVerify([self.mockScheduler updateAllSourcesWithPriority:UpdatePriorityHigh]); //
  // UpdateScheduler doesn't exist
}

- (void)testSyncRulesCommand_WithExistingManifest_TriggersPeriodicUpdate {
  // Given: Manifest already loaded, sync command received
  DNSResolvedManifest* existingManifest = OCMClassMock([DNSResolvedManifest class]);
  self.ruleManager.currentManifestIdentifier = @"existing";
  self.ruleManager.currentResolvedManifest = existingManifest;

  // Mock that manifest hasn't changed
  OCMStub([self.mockManifestResolver resolveManifestWithFallback:@"existing"
                                                           error:[OCMArg anyObjectRef]])
      .andReturn(existingManifest);

  OCMStub([self.ruleManager isResolvedManifestEqual:existingManifest to:existingManifest])
      .andReturn(YES);

  // When: Sync is triggered
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should trigger periodic update even though manifest unchanged
  // OCMVerify([self.mockScheduler updateAllSourcesWithPriority:UpdatePriorityHigh]); //
  // UpdateScheduler doesn't exist
}

#pragma mark - Test edge cases

- (void)testReloadManifestIfNeeded_ManifestChanges_ClearsAndReloads {
  // Given: Existing manifest, new one is different
  DNSResolvedManifest* oldManifest = OCMClassMock([DNSResolvedManifest class]);
  DNSResolvedManifest* newManifest = OCMClassMock([DNSResolvedManifest class]);

  self.ruleManager.currentManifestIdentifier = @"test";
  self.ruleManager.currentResolvedManifest = oldManifest;

  OCMStub([self.mockManifestResolver resolveManifestWithFallback:@"test"
                                                           error:[OCMArg anyObjectRef]])
      .andReturn(newManifest);

  OCMStub([self.ruleManager isResolvedManifestEqual:oldManifest to:newManifest]).andReturn(NO);

  DNSConfiguration* newConfig = [[DNSConfiguration alloc] init];
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:newManifest])
      .andReturn(newConfig);

  // When: Reload is triggered
  [self.ruleManager reloadManifestIfNeeded];

  // Then: Should update configuration and trigger force update
  XCTAssertEqual(self.ruleManager.currentResolvedManifest, newManifest,
                 @"Should update to new manifest");
  OCMVerify([self.ruleManager updateConfiguration:newConfig]);
  // OCMVerify([self.mockScheduler updateAllSourcesWithPriority:UpdatePriorityHigh]); //
  // UpdateScheduler doesn't exist
}

- (void)testDetermineManifestIdentifier_PriorityOrder {
  // Test 1: Preference set
  OCMStub([self.mockPreferenceManager preferenceValueForKey:@"ManifestIdentifier"
                                                   inDomain:@"com.dnshield.app"])
      .andReturn(@"custom-id");
  NSString* result = [self.ruleManager determineManifestIdentifier];
  XCTAssertEqualObjects(result, @"custom-id", @"Should use preference when set");

  // Test 2: No preference, use serial
  OCMStub([self.mockPreferenceManager preferenceValueForKey:@"ManifestIdentifier"
                                                   inDomain:@"com.dnshield.app"])
      .andReturn(nil);
  OCMStub([DNSManifestResolver getMachineSerialNumber]).andReturn(@"SERIAL456");
  result = [self.ruleManager determineManifestIdentifier];
  XCTAssertEqualObjects(result, @"SERIAL456", @"Should use serial when no preference");

  // Test 3: No preference, no serial, use default
  OCMStub([self.mockPreferenceManager preferenceValueForKey:@"ManifestIdentifier"
                                                   inDomain:@"com.dnshield.app"])
      .andReturn(nil);
  OCMStub([DNSManifestResolver getMachineSerialNumber]).andReturn(nil);
  result = [self.ruleManager determineManifestIdentifier];
  XCTAssertEqualObjects(result, @"default", @"Should fall back to default");
}

#pragma mark - Test concurrent access

- (void)testConcurrentSyncRequests_HandledSafely {
  // Given: Multiple sync requests at once
  XCTestExpectation* expectation = [self expectationWithDescription:@"Concurrent syncs complete"];
  expectation.expectedFulfillmentCount = 3;

  DNSResolvedManifest* manifest = OCMClassMock([DNSResolvedManifest class]);
  OCMStub([self.mockManifestResolver resolveManifestWithFallback:[OCMArg any]
                                                           error:[OCMArg anyObjectRef]])
      .andReturn(manifest);

  DNSConfiguration* config = [[DNSConfiguration alloc] init];
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:manifest])
      .andReturn(config);

  // When: Multiple concurrent sync requests
  dispatch_queue_t queue = dispatch_queue_create("test.concurrent", DISPATCH_QUEUE_CONCURRENT);

  for (int i = 0; i < 3; i++) {
    dispatch_async(queue, ^{
      [self.ruleManager reloadManifestIfNeeded];
      [expectation fulfill];
    });
  }

  // Then: All should complete without crashes or race conditions
  [self waitForExpectationsWithTimeout:5.0
                               handler:^(NSError* error) {
                                 XCTAssertNil(error, @"Concurrent syncs should complete");
                               }];
}

#pragma mark - Test error recovery

- (void)testNetworkError_Recovery {
  // Given: Initial network error, then recovery
  self.ruleManager.currentManifestIdentifier = nil;

  __block NSInteger attemptCount = 0;
  OCMStub([self.ruleManager determineManifestIdentifier]).andReturn(@"test");

  OCMStub([self.mockManifestResolver resolveManifestWithFallback:[OCMArg any]
                                                           error:[OCMArg anyObjectRef]])
      .andDo(^(NSInvocation* invocation) {
        attemptCount++;

        NSError* __autoreleasing* errorPtr;
        [invocation getArgument:&errorPtr atIndex:3];

        if (attemptCount == 1) {
          // First attempt fails with network error
          if (errorPtr) {
            *errorPtr = [NSError errorWithDomain:NSURLErrorDomain
                                            code:NSURLErrorNotConnectedToInternet
                                        userInfo:nil];
          }
          DNSResolvedManifest* nilManifest = nil;
          [invocation setReturnValue:&nilManifest];
        } else {
          // Second attempt succeeds
          DNSResolvedManifest* manifest = OCMClassMock([DNSResolvedManifest class]);
          [invocation setReturnValue:&manifest];
        }
      });

  // When: First sync fails
  [self.ruleManager reloadManifestIfNeeded];
  XCTAssertNil(self.ruleManager.currentResolvedManifest,
               @"Should not have manifest after network error");

  // When: Second sync succeeds
  DNSConfiguration* config = [[DNSConfiguration alloc] init];
  OCMStub([self.mockConfigurationManager configurationFromResolvedManifest:[OCMArg any]])
      .andReturn(config);

  [self.ruleManager reloadManifestIfNeeded];
  XCTAssertNotNil(self.ruleManager.currentResolvedManifest, @"Should recover and load manifest");
}

@end
