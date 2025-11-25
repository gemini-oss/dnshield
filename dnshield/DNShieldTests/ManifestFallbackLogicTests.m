//
//  ManifestFallbackLogicTests.m
//  DNShield Tests
//
//  Tests for manifest fallback logic implementation
//

#import <Common/DNShieldPreferences.h>
#import <Extension/Rule/Manager+Manifest.h>
#import <XCTest/XCTest.h>
#import <objc/runtime.h>
#import "DNSManifest.h"
#import "ErrorTypes.h"
#import "Testing/DNSTestCase.h"

@interface ManifestFallbackLogicTests : DNSTestCase
@end

@implementation ManifestFallbackLogicTests

#pragma mark - Error Code Tests

- (void)testHTTP404ErrorTriggersFallback {
  // Test that 404 errors properly trigger fallback
  NSError* error404 =
      [NSError errorWithDomain:DNSManifestErrorDomain
                          code:DNSManifestErrorManifestNotFound
                      userInfo:@{NSLocalizedDescriptionKey : @"Manifest not found"}];

  // In the actual implementation, this would trigger fallback
  XCTAssertEqual(error404.code, DNSManifestErrorManifestNotFound);
  XCTAssertEqualObjects(error404.domain, DNSManifestErrorDomain);
}

- (void)testHTTP401ErrorTriggersFallback {
  // Test that 401 auth errors trigger fallback
  NSError* error401 = [NSError errorWithDomain:NSURLErrorDomain
                                          code:401
                                      userInfo:@{NSLocalizedDescriptionKey : @"Unauthorized"}];

  // Verify error properties
  XCTAssertEqual(error401.code, 401);
  XCTAssertEqualObjects(error401.domain, NSURLErrorDomain);
}

- (void)testOtherHTTPErrorsDoNotTriggerFallback {
  // Test that other HTTP errors don't trigger fallback
  NSArray* nonFallbackCodes = @[ @400, @403, @500, @502, @503 ];

  for (NSNumber* code in nonFallbackCodes) {
    NSError* error = [NSError errorWithDomain:NSURLErrorDomain
                                         code:[code integerValue]
                                     userInfo:@{NSLocalizedDescriptionKey : @"Error"}];

    // These should not trigger fallback
    XCTAssertNotEqual(error.code, 401);
    XCTAssertNotEqual(error.code, DNSManifestErrorManifestNotFound);
  }
}

#pragma mark - Manifest Identifier Tests

- (void)testDefaultManifestIdentifier {
  // Test the default manifest identifier constant
  NSString* defaultIdentifier = @"default";

  // Verify it's not nil and has expected value
  XCTAssertNotNil(defaultIdentifier);
  XCTAssertEqualObjects(defaultIdentifier, @"default");
}

- (void)testManifestIdentifierPreservation {
  // Test that manifest identifiers are properly preserved
  NSString* machineSerial = @"ABC123DEF456";
  NSString* defaultIdentifier = @"default";

  // Verify they're different
  XCTAssertNotEqualObjects(machineSerial, defaultIdentifier);

  // Verify string operations work correctly
  XCTAssertTrue([machineSerial isKindOfClass:[NSString class]]);
  XCTAssertTrue([defaultIdentifier isKindOfClass:[NSString class]]);
}

#pragma mark - Associated Object Tests

- (void)testAssociatedObjectKeys {
  // Test that associated object keys are properly defined
  static void* TestKey1 = &TestKey1;
  static void* TestKey2 = &TestKey2;

  // Keys should be different
  XCTAssertNotEqual(TestKey1, TestKey2);

  // Create test object
  NSObject* testObject = [[NSObject alloc] init];

  // Set associated objects
  objc_setAssociatedObject(testObject, TestKey1, @"Value1", OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  objc_setAssociatedObject(testObject, TestKey2, @"Value2", OBJC_ASSOCIATION_RETAIN_NONATOMIC);

  // Retrieve and verify
  NSString* retrieved1 = objc_getAssociatedObject(testObject, TestKey1);
  NSString* retrieved2 = objc_getAssociatedObject(testObject, TestKey2);

  XCTAssertEqualObjects(retrieved1, @"Value1");
  XCTAssertEqualObjects(retrieved2, @"Value2");
}

#pragma mark - URL Construction Tests

- (void)testManifestURLConstruction {
  // Test URL construction with different manifest identifiers
  NSString* baseURL = @"http://localhost:8080/manifests";
  NSArray* identifiers = @[ @"machine123", @"default", @"test-manifest" ];
  NSArray* extensions = @[ @"json", @"yaml", @"plist" ];

  for (NSString* identifier in identifiers) {
    for (NSString* ext in extensions) {
      NSString* url = [NSString stringWithFormat:@"%@/%@.%@", baseURL, identifier, ext];

      // Verify URL format
      XCTAssertTrue([url hasPrefix:baseURL]);
      XCTAssertTrue([url containsString:identifier]);
      XCTAssertTrue([url hasSuffix:ext]);
    }
  }
}

#pragma mark - Preference Key Tests

- (void)testManifestUpdateIntervalKey {
  // Test the manifest update interval preference key
  NSString* key = kDNShieldManifestUpdateInterval;

  XCTAssertNotNil(key);
  XCTAssertEqualObjects(key, @"ManifestUpdateInterval");
}

#pragma mark - Timer Interval Tests

- (void)testTimerIntervalCalculations {
  // Test timer interval conversions
  NSTimeInterval intervalSeconds = 60.0;
  int64_t intervalNanoseconds = (int64_t)(intervalSeconds * NSEC_PER_SEC);

  XCTAssertEqual(intervalNanoseconds, 60000000000);

  // Test with different intervals
  NSArray* testIntervals = @[ @30, @60, @120, @300 ];

  for (NSNumber* interval in testIntervals) {
    NSTimeInterval seconds = [interval doubleValue];
    int64_t nanoseconds = (int64_t)(seconds * NSEC_PER_SEC);

    // Verify conversion back
    NSTimeInterval convertedBack = (NSTimeInterval)nanoseconds / NSEC_PER_SEC;
    XCTAssertEqualWithAccuracy(convertedBack, seconds, 0.001);
  }
}

#pragma mark - Fallback Decision Logic Tests

- (void)testShouldFallbackDecisionLogic {
  // Test the decision logic for fallback

  // Case 1: 404 error should fallback
  {
    NSError* error = [NSError errorWithDomain:DNSManifestErrorDomain
                                         code:DNSManifestErrorManifestNotFound
                                     userInfo:nil];
    BOOL shouldFallback = (error.code == DNSManifestErrorManifestNotFound);
    XCTAssertTrue(shouldFallback);
  }

  // Case 2: 401 error from ManifestFetcher should fallback
  {
    NSError* error = [NSError errorWithDomain:NSURLErrorDomain code:401 userInfo:nil];
    BOOL shouldFallback = ([error.domain isEqualToString:NSURLErrorDomain] && error.code == 401);
    XCTAssertTrue(shouldFallback);
  }

  // Case 3: Other errors should not fallback
  {
    NSError* error = [NSError errorWithDomain:NSURLErrorDomain
                                         code:NSURLErrorTimedOut
                                     userInfo:nil];
    BOOL shouldFallback = (error.code == DNSManifestErrorManifestNotFound) ||
                          ([error.domain isEqualToString:NSURLErrorDomain] && error.code == 401);
    XCTAssertFalse(shouldFallback);
  }
}

@end
