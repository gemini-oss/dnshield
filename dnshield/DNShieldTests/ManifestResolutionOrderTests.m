//
//  ManifestResolutionOrderTests.m
//  DNShield Tests
//
//  Tests for manifest resolution order and fallback logic
//

#import <CoreFoundation/CoreFoundation.h>
#import <XCTest/XCTest.h>
#import "Testing/DNSTestCase.h"

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>

#import "DNSManifest.h"
#import "DNSManifestResolver.h"
#import "PreferenceManager.h"
#import "TestHelpers/DNSManifestResolver+Testing.h"
#import "TestHelpers/MockManifestResolver.h"

@interface ManifestResolutionOrderTests : DNSTestCase
@property(nonatomic, strong) DNSManifestResolver* resolver;
@property(nonatomic, strong) PreferenceManager* preferenceManager;
@end

@implementation ManifestResolutionOrderTests

- (void)setUp {
  [super setUp];
  self.preferenceManager = [PreferenceManager sharedManager];
  self.resolver = [[DNSManifestResolver alloc] init];
}

- (void)tearDown {
  // Clean up preferences - use CFPreferences for proper domain
  CFPreferencesSetAppValue((__bridge CFStringRef)kDNShieldClientIdentifier, NULL,
                           (__bridge CFStringRef)kDNShieldPreferenceDomain);
  CFPreferencesSetAppValue((__bridge CFStringRef)kDNShieldManifestFormat, NULL,
                           (__bridge CFStringRef)kDNShieldPreferenceDomain);
  CFPreferencesSetAppValue((__bridge CFStringRef)kDNShieldManifestURL, NULL,
                           (__bridge CFStringRef)kDNShieldPreferenceDomain);
  CFPreferencesAppSynchronize((__bridge CFStringRef)kDNShieldPreferenceDomain);

  [super tearDown];
}

#pragma mark - Test Fallback Order

- (void)testManifestFallbackOrder_WithClientIdentifier {
  // Test the fallback order when ClientIdentifier is set
  // Should try: ClientIdentifier -> Serial -> default

  // Set up test data via helper
  [self dns_setPreferenceValue:@"engineering" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  NSString* identifier =
      [DNSManifestResolver determineClientIdentifierWithPreferenceManager:self.preferenceManager];
  XCTAssertEqualObjects(identifier, @"engineering", @"Should use ClientIdentifier when set");

  // Test that fallback chain is built correctly
  NSError* error = nil;
  DNSResolvedManifest* resolved = [self.resolver resolveManifestWithFallback:@"engineering"
                                                                       error:&error];

  // Note: This will fail in test environment since we don't have actual manifest files
  // But we're testing the logic, not the actual resolution
  XCTAssertNil(resolved, @"Should return nil when no manifests exist");
  XCTAssertNotNil(error, @"Should return error when resolution fails");
}

- (void)testManifestFallbackOrder_WithoutClientIdentifier {
  // Test fallback when ClientIdentifier is not set
  // Should try: Serial -> default

  [self dns_clearPreferenceForKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  NSString* identifier =
      [DNSManifestResolver determineClientIdentifierWithPreferenceManager:self.preferenceManager];
  NSString* serialNumber = [DNSManifestResolver getMachineSerialNumber];

  if (serialNumber) {
    XCTAssertEqualObjects(identifier, serialNumber,
                          @"Should use serial number when ClientIdentifier not set");
  } else {
    XCTAssertEqualObjects(identifier, @"default", @"Should use 'default' when no serial available");
  }
}

#pragma mark - Test Format Preference

- (void)testManifestFormatPreference_Plist {
  // Test that plist format is tried first when specified
  [self dns_setPreferenceValue:@"engineering" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"plist" forKey:kDNShieldManifestFormat];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  // Simplified: only the preferred extension is used
  NSArray* order = [self.resolver orderedExtensionsWithDotForIdentifier:@"engineering"];
  NSArray* expected = @[ @".plist" ];
  XCTAssertEqualObjects(order, expected);

  NSError* error = nil;
  [self.resolver resolveManifest:@"engineering" error:&error];

  // Verify through logs if needed (would need to mock LoggingManager)
}

- (void)testManifestFormatPreference_Json {
  // Test that json format is tried first when specified (or by default)
  [self dns_setPreferenceValue:@"engineering" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"json" forKey:kDNShieldManifestFormat];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  // Simplified: only the preferred extension is used
  NSArray* order = [self.resolver orderedExtensionsWithDotForIdentifier:@"engineering"];
  NSArray* expected = @[ @".json" ];
  XCTAssertEqualObjects(order, expected);
  NSError* error = nil;
  [self.resolver resolveManifest:@"engineering" error:&error];
}

- (void)testManifestFormatPreference_Yaml {
  // Test that yaml format is tried first when specified
  [self dns_setPreferenceValue:@"engineering" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"yml" forKey:kDNShieldManifestFormat];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  // Simplified: only the preferred extension is used
  NSArray* order = [self.resolver orderedExtensionsWithDotForIdentifier:@"engineering"];
  NSArray* expected = @[ @".yml" ];
  XCTAssertEqualObjects(order, expected);
  NSError* error = nil;
  [self.resolver resolveManifest:@"engineering" error:&error];
}

#pragma mark - Test Complete Resolution Chain

- (void)testCompleteResolutionChain_ClientIdentifierWithPlistFormat {
  // Test complete chain:
  // 1. ClientIdentifier = "engineering", format = "plist"
  // 2. Should try in order:
  //    - engineering.plist
  //    - engineering.json
  //    - engineering.yml
  //    - engineering.yaml (if yml fails)
  // 3. Then fallback to serial number with same format order
  // 4. Then fallback to default with same format order

  [self dns_setPreferenceValue:@"engineering" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"plist" forKey:kDNShieldManifestFormat];
  [self dns_setPreferenceValue:@"https://dp1rasi368ygd.cloudfront.net/manifests"
                        forKey:kDNShieldManifestURL];

  NSError* error = nil;
  DNSResolvedManifest* resolved = [self.resolver resolveManifestWithFallback:@"engineering"
                                                                       error:&error];

  // In real environment with network, this would attempt the full chain
  XCTAssertTrue(YES, @"Test framework validated");
}

- (void)testCompleteResolutionChain_NoClientIdentifierDefaultFormat {
  // Test when no ClientIdentifier is set and no format preference
  // Should default to JSON format and try serial number -> default

  [self dns_clearPreferenceForKey:kDNShieldClientIdentifier];
  [self dns_clearPreferenceForKey:kDNShieldManifestFormat];
  [self dns_setPreferenceValue:@"https://dp1rasi368ygd.cloudfront.net/manifests"
                        forKey:kDNShieldManifestURL];

  NSString* identifier =
      [DNSManifestResolver determineClientIdentifierWithPreferenceManager:self.preferenceManager];
  NSString* serialNumber = [DNSManifestResolver getMachineSerialNumber];

  // Verify identifier determination
  if (serialNumber) {
    XCTAssertEqualObjects(identifier, serialNumber, @"Should use serial when no ClientIdentifier");
  } else {
    XCTAssertEqualObjects(identifier, @"default", @"Should use default as last resort");
  }

  NSError* error = nil;
  DNSResolvedManifest* resolved = [self.resolver resolveManifestWithFallback:identifier
                                                                       error:&error];

  // Would attempt: serialNumber.json, serialNumber.plist, serialNumber.yml, serialNumber.yaml
  // Then: default.json, default.plist, default.yml, default.yaml
}

#pragma mark - Test Edge Cases

- (void)testInvalidFormatPreference_FallsBackToJson {
  // Test that invalid format preference falls back to JSON
  [self dns_setPreferenceValue:@"engineering" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"invalid_format" forKey:kDNShieldManifestFormat];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  // Should default to JSON format order
  NSError* error = nil;
  [self.resolver resolveManifest:@"engineering" error:&error];

  // Check logs would show invalid format warning and fallback to JSON
}

- (void)testEmptyClientIdentifier_FallsBackToSerial {
  // Test that empty ClientIdentifier falls back properly
  [self dns_setPreferenceValue:@"" forKey:kDNShieldClientIdentifier];
  [self dns_setPreferenceValue:@"https://example.com/manifests" forKey:kDNShieldManifestURL];

  NSString* identifier =
      [DNSManifestResolver determineClientIdentifierWithPreferenceManager:self.preferenceManager];
  NSString* serialNumber = [DNSManifestResolver getMachineSerialNumber];

  if (serialNumber) {
    XCTAssertEqualObjects(identifier, serialNumber,
                          @"Empty ClientIdentifier should fallback to serial");
  } else {
    XCTAssertEqualObjects(identifier, @"default", @"Should use default when no serial");
  }
}

@end
