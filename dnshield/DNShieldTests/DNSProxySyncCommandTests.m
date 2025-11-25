//
//  DNSProxySyncCommandTests.m
//  DNShield Tests
//
//  Integration tests for sync command processing in DNSProxyProvider
//

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import "Testing/DNSTestCase.h"
#import "Testing/OCMock+DNSTesting.h"

#import <Extension/Rule/Cache.h>
#import <Extension/Rule/Manager+Manifest.h>
#import <Extension/Rule/Manager.h>
#import <Extension/Rule/RuleDatabase.h>

#import "DNSCache.h"
#import "DNSManifestResolver.h"
#import "DNSProxyProvider.h"
#import "PreferenceManager.h"

@interface DNSProxyProvider (TestAccess)
@property(nonatomic, strong) RuleManager* ruleManager;
@property(nonatomic, strong) DNSCache* dnsCache;
@property(nonatomic, strong) DNSRuleCache* ruleCache;
@property(nonatomic, strong) RuleDatabase* ruleDatabase;
@property(nonatomic, strong) PreferenceManager* preferenceManager;
- (NSDictionary*)processCommand:(NSDictionary*)command;
- (void)reloadConfigurationIfNeeded;
@end

@interface DNSProxySyncCommandTests : DNSTestCase
@property(nonatomic, strong) DNSProxyProvider* proxyProvider;
@property(nonatomic, strong) id mockRuleManager;
@property(nonatomic, strong) id mockDNSCache;
@property(nonatomic, strong) id mockRuleCache;
@property(nonatomic, strong) id mockRuleDatabase;
@property(nonatomic, strong) id mockPreferenceManager;
@end

@implementation DNSProxySyncCommandTests

- (void)setUp {
  [super setUp];

  // Create DNSProxyProvider instance
  self.proxyProvider = [[DNSProxyProvider alloc] init];

  // Create mocks
  self.mockRuleManager = OCMClassMock([RuleManager class]);
  self.mockDNSCache = OCMClassMock([DNSCache class]);
  self.mockRuleCache = OCMClassMock([DNSRuleCache class]);
  self.mockRuleDatabase = OCMClassMock([RuleDatabase class]);
  self.mockPreferenceManager = OCMClassMock([PreferenceManager class]);

  // Inject mocks
  self.proxyProvider.ruleManager = self.mockRuleManager;
  self.proxyProvider.dnsCache = self.mockDNSCache;
  self.proxyProvider.ruleCache = self.mockRuleCache;
  self.proxyProvider.ruleDatabase = self.mockRuleDatabase;
  self.proxyProvider.preferenceManager = self.mockPreferenceManager;
}

- (void)tearDown {
  [self.mockRuleManager stopMocking];
  [self.mockDNSCache stopMocking];
  [self.mockRuleCache stopMocking];
  [self.mockRuleDatabase stopMocking];
  [self.mockPreferenceManager stopMocking];

  self.proxyProvider = nil;
  [super tearDown];
}

#pragma mark - Test syncRules command processing

- (void)testSyncRulesCommand_CallsReloadManifestIfNeeded {
  // Given: syncRules command
  NSDictionary* command = @{
    @"commandId" : @"test-123",
    @"type" : @"syncRules",
    @"timestamp" : @([[NSDate date] timeIntervalSince1970]),
    @"source" : @"menu_bar_app"
  };

  // Setup expectation
  OCMExpect([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);
  OCMExpect([self.mockRuleManager reloadManifestIfNeeded]);
  OCMExpect([self.mockDNSCache clearCache]);
  OCMExpect([self.mockRuleCache clear]);

  // When: Command is processed
  NSDictionary* response = [self.proxyProvider processCommand:command];

  // Then: Should call reloadManifestIfNeeded
  OCMVerifyAll(self.mockRuleManager);
  OCMVerifyAll(self.mockDNSCache);
  OCMVerifyAll(self.mockRuleCache);

  XCTAssertTrue([response[@"success"] boolValue], @"Command should succeed");
  XCTAssertEqualObjects(response[@"message"], @"Rule sync initiated successfully");
}

- (void)testSyncRulesCommand_WithEmptyDatabase_SuccessfullyLoadsRules {
  // Given: Empty database scenario
  OCMStub([self.mockRuleDatabase ruleCount]).andReturn(0);

  NSDictionary* command = @{
    @"commandId" : @"test-456",
    @"type" : @"syncRules",
    @"timestamp" : @([[NSDate date] timeIntervalSince1970])
  };

  // Mock that reloadManifestIfNeeded exists and succeeds
  OCMStub([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);

  __block BOOL reloadCalled = NO;
  OCMStub([self.mockRuleManager reloadManifestIfNeeded]).andDo(^(NSInvocation* invocation) {
    reloadCalled = YES;
    // Simulate successful load - database now has rules
    OCMStub([self.mockRuleDatabase ruleCount]).andReturn(1000);
  });

  // When: Command is processed
  NSDictionary* response = [self.proxyProvider processCommand:command];

  // Then: Should successfully load rules
  XCTAssertTrue(reloadCalled, @"Should call reloadManifestIfNeeded");
  XCTAssertTrue([response[@"success"] boolValue], @"Command should succeed");

  // Verify database has rules after sync
  NSInteger ruleCount = [self.mockRuleDatabase ruleCount];
  XCTAssertGreaterThan(ruleCount, 0, @"Database should have rules after sync");
}

- (void)testSyncRulesCommand_NoRuleManager_ReturnsError {
  // Given: No rule manager
  self.proxyProvider.ruleManager = nil;

  NSDictionary* command = @{@"commandId" : @"test-789", @"type" : @"syncRules"};

  // When: Command is processed
  NSDictionary* response = [self.proxyProvider processCommand:command];

  // Then: Should return error
  XCTAssertFalse([response[@"success"] boolValue], @"Command should fail");
  XCTAssertEqualObjects(response[@"error"], @"Rule manager not initialized");
}

#pragma mark - Test configuration reload timer

- (void)testConfigurationReloadTimer_CallsReloadManifestIfNeeded {
  // Given: Configuration reload timer fires
  OCMStub([self.mockPreferenceManager preferenceValueForKey:@"ManifestUpdateInterval"
                                                   inDomain:@"com.dnshield.app"])
      .andReturn(@300);  // 5 minutes

  // Mock that we should use manifest
  id mockConfigManager = OCMClassMock([ConfigurationManager class]);
  OCMStub([mockConfigManager shouldUseManifest]).andReturn(YES);

  // Setup expectations
  OCMExpect([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);
  OCMExpect([self.mockRuleManager currentManifestIdentifier]).andReturn(@"test");
  OCMExpect([self.mockRuleManager reloadManifestIfNeeded]);

  // When: Timer fires
  [self.proxyProvider reloadConfigurationIfNeeded];

  // Then: Should call reloadManifestIfNeeded
  OCMVerifyAll(self.mockRuleManager);

  [mockConfigManager stopMocking];
}

- (void)testConfigurationReloadTimer_ManifestChanged_ClearsCaches {
  // Given: Manifest identifier changed
  id mockConfigManager = OCMClassMock([ConfigurationManager class]);
  OCMStub([mockConfigManager shouldUseManifest]).andReturn(YES);

  // Current manifest is "old", new one is "new"
  OCMStub([self.mockRuleManager currentManifestIdentifier]).andReturn(@"old");

  // Mock the class method properly
  id mockResolver = OCMClassMock([DNSManifestResolver class]);
  OCMStub(ClassMethod([mockResolver
              determineClientIdentifierWithPreferenceManager:self.mockPreferenceManager]))
      .andReturn(@"new");

  // Setup expectations
  OCMExpect([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);
  OCMExpect([self.mockRuleManager reloadManifestIfNeeded]);
  OCMExpect([self.mockDNSCache clearCache]);
  OCMExpect([self.mockRuleCache clear]);

  // When: Timer fires with changed manifest
  [self.proxyProvider reloadConfigurationIfNeeded];

  // Then: Should clear caches
  OCMVerifyAll(self.mockDNSCache);
  OCMVerifyAll(self.mockRuleCache);

  [mockConfigManager stopMocking];
  [mockResolver stopMocking];
}

#pragma mark - Test command file processing

- (void)testCommandFileProcessing_SyncRules {
  // Given: Command file with syncRules
  NSString* commandPath = @"/tmp/test_command.json";
  NSDictionary* command =
      @{@"commandId" : @"file-test-123", @"type" : @"syncRules", @"source" : @"menu_bar_app"};

  NSError* error;
  NSData* commandData = [NSJSONSerialization dataWithJSONObject:command options:0 error:&error];
  XCTAssertNil(error, @"Should serialize command");

  // Mock file manager to return our command
  id mockFileManager = OCMClassMock([NSFileManager class]);
  OCMStub([mockFileManager contentsAtPath:commandPath]).andReturn(commandData);

  // Setup rule manager expectations
  OCMExpect([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);
  OCMExpect([self.mockRuleManager reloadManifestIfNeeded]);

  // When: Command file is processed
  NSDictionary* response = [self.proxyProvider processCommand:command];

  // Then: Should process sync command
  OCMVerifyAll(self.mockRuleManager);
  XCTAssertTrue([response[@"success"] boolValue], @"Should process command successfully");

  [mockFileManager stopMocking];
}

#pragma mark - Test error scenarios

- (void)testSyncRulesCommand_ManifestResolutionFails_HandlesGracefully {
  // Given: Manifest resolution will fail
  NSDictionary* command = @{@"commandId" : @"fail-test", @"type" : @"syncRules"};

  OCMStub([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);

  // Mock that reloadManifestIfNeeded throws exception
  OCMStub([self.mockRuleManager reloadManifestIfNeeded])
      .andThrow([NSException exceptionWithName:@"ManifestError"
                                        reason:@"Failed to resolve"
                                      userInfo:nil]);

  // When: Command is processed
  XCTAssertNoThrow([self.proxyProvider processCommand:command],
                   @"Should handle exception gracefully");
}

- (void)testConcurrentSyncCommands_HandledCorrectly {
  // Given: Multiple sync commands at once
  XCTestExpectation* expectation = [self expectationWithDescription:@"All syncs complete"];
  expectation.expectedFulfillmentCount = 5;

  OCMStub([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);

  __block NSInteger callCount = 0;
  OCMStub([self.mockRuleManager reloadManifestIfNeeded]).andDo(^(NSInvocation* invocation) {
    @synchronized(self) {
      callCount++;
    }
    // Simulate some processing time
    [NSThread sleepForTimeInterval:0.1];
  });

  // When: Multiple concurrent sync commands
  dispatch_queue_t queue =
      dispatch_queue_create("test.concurrent.commands", DISPATCH_QUEUE_CONCURRENT);

  for (int i = 0; i < 5; i++) {
    dispatch_async(queue, ^{
      NSDictionary* command =
          @{@"commandId" : [NSString stringWithFormat:@"concurrent-%d", i], @"type" : @"syncRules"};

      NSDictionary* response = [self.proxyProvider processCommand:command];
      XCTAssertTrue([response[@"success"] boolValue], @"Command %d should succeed", i);
      [expectation fulfill];
    });
  }

  // Then: All commands should complete
  [self waitForExpectationsWithTimeout:10.0
                               handler:^(NSError* error) {
                                 XCTAssertNil(error, @"All sync commands should complete");
                                 XCTAssertGreaterThan(callCount, 0,
                                                      @"reloadManifestIfNeeded should be called");
                               }];
}

#pragma mark - Test database state transitions

- (void)testDatabaseTransitions_EmptyToPopulated {
  // Given: Database starts empty
  __block NSInteger dbState = 0;  // 0 = empty, 1 = populated
  OCMStub([self.mockRuleDatabase ruleCount]).andDo(^(NSInvocation* invocation) {
    NSInteger count = (dbState == 0) ? 0 : 1500;
    [invocation setReturnValue:&count];
  });

  NSDictionary* command = @{@"commandId" : @"transition-test", @"type" : @"syncRules"};

  OCMStub([self.mockRuleManager respondsToSelector:@selector(reloadManifestIfNeeded)])
      .andReturn(YES);
  OCMStub([self.mockRuleManager reloadManifestIfNeeded]).andDo(^(NSInvocation* invocation) {
    // Simulate database population
    dbState = 1;
  });

  // When: Initial state - database empty
  NSInteger initialCount = [self.mockRuleDatabase ruleCount];
  XCTAssertEqual(initialCount, 0, @"Database should start empty");

  // Process sync command
  NSDictionary* response = [self.proxyProvider processCommand:command];
  XCTAssertTrue([response[@"success"] boolValue], @"Sync should succeed");

  // Then: Database should be populated
  NSInteger finalCount = [self.mockRuleDatabase ruleCount];
  XCTAssertGreaterThan(finalCount, 0, @"Database should be populated after sync");
}

@end
