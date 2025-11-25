//
//  ManifestCachingSanitizationTests.m
//  DNShieldTests
//
//  Tests for NSNull sanitization in manifest caching
//

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import "DNSManifest.h"
#import "DNSManifestParser.h"
#import "DNSManifestResolver.h"
#import "LoggingManager.h"

@interface DNSManifestResolver (TestPrivate)
- (id)sanitizeDictionaryForPlist:(id)object;
- (void)cacheManifestToDisk:(DNSManifest*)manifest forIdentifier:(NSString*)identifier;
@end

@interface ManifestCachingSanitizationTests : XCTestCase
@property(nonatomic, strong) DNSManifestResolver* resolver;
@property(nonatomic, strong) NSString* testCacheDir;
@property(nonatomic, strong) id mockLoggingManager;
@end

@implementation ManifestCachingSanitizationTests

- (void)setUp {
  [super setUp];

  // Create a test cache directory
  NSString* tempDir = NSTemporaryDirectory();
  self.testCacheDir = [tempDir stringByAppendingPathComponent:@"test_manifest_cache"];
  [[NSFileManager defaultManager] createDirectoryAtPath:self.testCacheDir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:nil];

  // Setup mock logging manager
  self.mockLoggingManager = OCMClassMock([LoggingManager class]);
  OCMStub([self.mockLoggingManager sharedManager]).andReturn(self.mockLoggingManager);
  OCMStub([self.mockLoggingManager logEvent:[OCMArg any]
                                   category:[OCMArg any]
                                      level:[OCMArg any]
                                 attributes:[OCMArg any]]);
  OCMStub([self.mockLoggingManager logError:[OCMArg any]
                                   category:[OCMArg any]
                                    context:[OCMArg any]]);

  // Initialize resolver with test cache directory
  self.resolver = [[DNSManifestResolver alloc] initWithCacheDirectory:self.testCacheDir];
}

- (void)tearDown {
  // Clean up test cache directory
  [[NSFileManager defaultManager] removeItemAtPath:self.testCacheDir error:nil];

  [self.mockLoggingManager stopMocking];

  [super tearDown];
}

#pragma mark - NSNull Sanitization Tests

- (void)testSanitizeDictionaryRemovesNSNull {
  NSDictionary* input = @{
    @"key1" : @"value1",
    @"key2" : [NSNull null],
    @"key3" : @{@"nested1" : @"nestedValue", @"nested2" : [NSNull null]},
    @"key4" : @[ @"item1", [NSNull null], @"item2" ]
  };

  NSDictionary* sanitized = [self.resolver sanitizeDictionaryForPlist:input];

  // Verify NSNull values are removed
  XCTAssertNotNil(sanitized[@"key1"]);
  XCTAssertNil(sanitized[@"key2"]);  // Should be removed

  // Check nested dictionary
  NSDictionary* nestedDict = sanitized[@"key3"];
  XCTAssertNotNil(nestedDict[@"nested1"]);
  XCTAssertNil(nestedDict[@"nested2"]);  // Should be removed

  // Check array
  NSArray* array = sanitized[@"key4"];
  XCTAssertEqual(array.count, 2);  // NSNull should be removed from array
  XCTAssertEqualObjects(array[0], @"item1");
  XCTAssertEqualObjects(array[1], @"item2");
}

- (void)testManifestWithNSNullCanBeCached {
  // Create a manifest with JSON data that includes null values
  NSString* jsonString = @"{"
                         @"\"manifest_version\": \"1.0\","
                         @"\"identifier\": \"test_manifest\","
                         @"\"display_name\": \"Test Manifest\","
                         @"\"metadata\": {"
                         @"  \"author\": \"Test Author\","
                         @"  \"description\": null,"
                         @"  \"version\": \"1.0\""
                         @"},"
                         @"\"rule_sources\": ["
                         @"  {"
                         @"    \"identifier\": \"source1\","
                         @"    \"name\": \"Test Source\","
                         @"    \"type\": \"https\","
                         @"    \"format\": \"json\","
                         @"    \"configuration\": null"
                         @"  }"
                         @"]"
                         @"}";

  NSData* jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
  NSError* parseError = nil;

  DNSManifest* manifest = [DNSManifestParser parseManifestFromData:jsonData error:&parseError];
  XCTAssertNil(parseError, @"Should be able to parse manifest with null values");
  XCTAssertNotNil(manifest, @"Manifest should be created");

  // Try to cache the manifest - this should not throw an exception
  XCTAssertNoThrow([self.resolver cacheManifestToDisk:manifest forIdentifier:@"test_manifest"],
                   @"Should be able to cache manifest with null values");

  // Verify the cached file exists
  NSString* expectedCachePath = [self.testCacheDir stringByAppendingPathComponent:@"test_manifest"];
  BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:expectedCachePath];
  XCTAssertTrue(fileExists, @"Cached manifest file should exist");

  // Verify the cached file can be read back as a property list
  NSData* cachedData = [NSData dataWithContentsOfFile:expectedCachePath];
  XCTAssertNotNil(cachedData, @"Should be able to read cached data");

  NSError* plistError = nil;
  id plistObject = [NSPropertyListSerialization propertyListWithData:cachedData
                                                             options:0
                                                              format:NULL
                                                               error:&plistError];
  XCTAssertNil(plistError, @"Should be able to deserialize cached plist");
  XCTAssertNotNil(plistObject, @"Cached plist should deserialize successfully");

  // Verify no NSNull values exist in the cached data
  [self verifyNoNSNullInObject:plistObject];
}

- (void)verifyNoNSNullInObject:(id)object {
  if ([object isKindOfClass:[NSDictionary class]]) {
    NSDictionary* dict = (NSDictionary*)object;
    [dict enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL* stop) {
      XCTAssertFalse([obj isKindOfClass:[NSNull class]], @"Found NSNull in dictionary at key: %@",
                     key);
      [self verifyNoNSNullInObject:obj];
    }];
  } else if ([object isKindOfClass:[NSArray class]]) {
    NSArray* array = (NSArray*)object;
    for (id obj in array) {
      XCTAssertFalse([obj isKindOfClass:[NSNull class]], @"Found NSNull in array");
      [self verifyNoNSNullInObject:obj];
    }
  }
}

- (void)testEmptyDictionaryHandling {
  NSDictionary* input = @{};
  NSDictionary* sanitized = [self.resolver sanitizeDictionaryForPlist:input];

  XCTAssertNotNil(sanitized);
  XCTAssertEqual(sanitized.count, 0);
}

- (void)testNilHandling {
  id sanitized = [self.resolver sanitizeDictionaryForPlist:nil];
  XCTAssertNil(sanitized);
}

- (void)testPrimitiveTypesPreserved {
  NSString* string = @"test string";
  NSNumber* number = @42;
  NSDate* date = [NSDate date];

  XCTAssertEqualObjects([self.resolver sanitizeDictionaryForPlist:string], string);
  XCTAssertEqualObjects([self.resolver sanitizeDictionaryForPlist:number], number);
  XCTAssertEqualObjects([self.resolver sanitizeDictionaryForPlist:date], date);
}

@end
