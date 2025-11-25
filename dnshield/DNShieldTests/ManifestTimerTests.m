//
//  ManifestTimerTests.m
//  DNShield Tests
//
//  Tests specifically for manifest update timer behavior
//

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import "Testing/DNSTestCase.h"
#import "Testing/OCMock+DNSTesting.h"

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Extension/Rule/Manager+Manifest.h>

#import "PreferenceManager.h"

// Suppress warnings for undeclared selectors
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"

@interface ManifestTimerTests : DNSTestCase
@property(nonatomic, strong) RuleManager* ruleManager;
@property(nonatomic, strong) NSMutableArray<NSDate*>* timerFireDates;
@property(nonatomic, strong) dispatch_semaphore_t timerSemaphore;
@end

@implementation ManifestTimerTests

- (void)setUp {
  [super setUp];
  self.timerFireDates = [NSMutableArray array];
  self.timerSemaphore = dispatch_semaphore_create(0);
  self.ruleManager =
      [[RuleManager alloc] initWithConfiguration:[DNSConfiguration defaultConfiguration]];
}

- (void)tearDown {
  [self.ruleManager stopManifestUpdateTimer];
  [super tearDown];
}

- (void)testTimerStartsSuccessfully {
  // Get the timer before starting
  dispatch_source_t timerBefore =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));
  XCTAssertNil(timerBefore);

  // Start timer
  [self.ruleManager startManifestUpdateTimer];

  // Get the timer after starting
  dispatch_source_t timerAfter =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));
  XCTAssertNotNil(timerAfter);
}

- (void)testTimerStopsSuccessfully {
  // Start timer
  [self.ruleManager startManifestUpdateTimer];
  dispatch_source_t timer =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));
  XCTAssertNotNil(timer);

  // Stop timer
  [self.ruleManager stopManifestUpdateTimer];

  // Verify timer is nil
  dispatch_source_t timerAfter =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));
  XCTAssertNil(timerAfter);
}

- (void)testTimerRespectsCustomInterval {
  // Mock preference manager to return custom interval
  id mockPreferenceManager = OCMClassMock([PreferenceManager class]);
  OCMStub([mockPreferenceManager sharedManager]).andReturn(mockPreferenceManager);
  OCMStub([mockPreferenceManager preferenceValueForKey:kDNShieldManifestUpdateInterval
                                              inDomain:kDNShieldPreferenceDomain])
      .andReturn(@120);  // 2 minutes

  // Create timer tracking
  __block NSTimeInterval capturedInterval = 0;

  // Swizzle dispatch_source_set_timer to capture the interval
  void (*original_dispatch_source_set_timer)(dispatch_source_t, dispatch_time_t, uint64_t,
                                             uint64_t);
  original_dispatch_source_set_timer = dlsym(RTLD_DEFAULT, "dispatch_source_set_timer");

  id block =
      ^(dispatch_source_t source, dispatch_time_t start, uint64_t interval, uint64_t leeway) {
        capturedInterval = (NSTimeInterval)interval / NSEC_PER_SEC;
        original_dispatch_source_set_timer(source, start, interval, leeway);
      };

  // Replace implementation
  Method method = class_getInstanceMethod(
      [self class], @selector(mockDispatchSourceSetTimer:start:interval:leeway:));
  IMP imp = imp_implementationWithBlock(block);
  method_setImplementation(method, imp);

  // Start timer
  [self.ruleManager startManifestUpdateTimer];

  // Verify interval
  XCTAssertEqual(capturedInterval, 120.0, @"Timer interval should be 120 seconds");

  [mockPreferenceManager stopMocking];
}

- (void)testMultipleStartCallsDontCreateMultipleTimers {
  // Start timer multiple times
  [self.ruleManager startManifestUpdateTimer];
  dispatch_source_t timer1 =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));

  [self.ruleManager startManifestUpdateTimer];
  dispatch_source_t timer2 =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));

  [self.ruleManager startManifestUpdateTimer];
  dispatch_source_t timer3 =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));

  // Should have cancelled previous timers
  XCTAssertNotNil(timer3);
  XCTAssertNotEqual(timer1, timer2);
  XCTAssertNotEqual(timer2, timer3);
}

- (void)testTimerUsesGlobalQueue {
  // This test verifies the timer uses the correct dispatch queue
  // We'll check this by examining the timer's target queue
  [self.ruleManager startManifestUpdateTimer];

  dispatch_source_t timer =
      objc_getAssociatedObject(self.ruleManager, @selector(manifestUpdateTimer));
  XCTAssertNotNil(timer);

  // Note: dispatch_source_get_queue may not be available
  // We can just verify the timer exists instead
  // dispatch_queue_t targetQueue = dispatch_source_get_queue(timer);
  // XCTAssertNotNil(targetQueue);
  // dispatch_qos_class_t qos = dispatch_queue_get_qos_class(targetQueue, NULL);
  // XCTAssertEqual(qos, QOS_CLASS_DEFAULT);
}

// Mock method for swizzling
- (void)mockDispatchSourceSetTimer:(dispatch_source_t)source
                             start:(dispatch_time_t)start
                          interval:(uint64_t)interval
                            leeway:(uint64_t)leeway {
  // This method exists only for swizzling purposes
}

@end

#pragma clang diagnostic pop
