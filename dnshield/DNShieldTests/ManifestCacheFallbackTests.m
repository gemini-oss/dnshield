//
//  ManifestCacheFallbackTests.m
//  DNShield Tests
//

#import <XCTest/XCTest.h>

#import "DNSManifest.h"
#import "DNSManifestResolver.h"
#import "ErrorTypes.h"
#import "HTTPRuleFetcher.h"
#import "Testing/DNSManifest+Testing.h"
#import "Testing/DNSTestCase.h"

static NSData* TestFetcherData = nil;
static NSError* TestFetcherError = nil;

@interface DNSManifestResolverTestFetcher : HTTPRuleFetcher
@end

@implementation DNSManifestResolverTestFetcher

- (instancetype)initWithURL:(NSURL*)url configuration:(NSDictionary*)configuration {
  return [super initWithURL:url configuration:configuration];
}

- (void)fetchRulesWithCompletion:(void (^)(NSData*, NSError*))completion {
  if (completion) {
    completion(TestFetcherData, TestFetcherError);
  }
}

- (void)cancelFetch {
  // No-op for tests
}

@end

@interface ManifestCacheFallbackTests : DNSTestCase
@property(nonatomic, strong) DNSManifestResolver* resolver;
@property(nonatomic, strong) NSString* cacheDirectory;
@end

@implementation ManifestCacheFallbackTests

- (void)setUp {
  [super setUp];

  NSURL* cacheURL = [self dns_makeTempSubdirectory:@"manifest-cache"];
  self.cacheDirectory = cacheURL.path;
  self.resolver = [[DNSManifestResolver alloc] initWithCacheDirectory:self.cacheDirectory];

  // Use a predictable base URL so the resolver attempts HTTP fetches.
  [self.resolver setValue:@"https://example.com/manifests" forKey:@"manifestBaseURL"];

  // Seed the resolver with a base HTTPRuleFetcher configuration and override the factory class so
  // tests can control responses without global mocks.
  NSURL* seedURL = [NSURL URLWithString:@"https://example.com/seed.json"];
  HTTPRuleFetcher* seedFetcher = [[HTTPRuleFetcher alloc] initWithURL:seedURL];
  [self.resolver setValue:seedFetcher forKey:@"httpFetcher"];
  [self.resolver setValue:[DNSManifestResolverTestFetcher class] forKey:@"ruleFetcherClass"];
  TestFetcherData = nil;
  TestFetcherError = nil;
}

- (void)tearDown {
  [[NSFileManager defaultManager] removeItemAtPath:self.cacheDirectory error:nil];
  TestFetcherData = nil;
  TestFetcherError = nil;
  self.resolver = nil;
  [super tearDown];
}

#pragma mark - Helpers

- (DNSManifest*)dns_manifestWithIdentifier:(NSString*)identifier {
  return [DNSManifest dns_manifestWithIdentifier:identifier
                                     displayName:@"Test Manifest"
                                           allow:@[ @"example.com" ]
                                           block:@[]];
}

- (void)dns_markManifestExpired:(NSString*)identifier timeout:(NSTimeInterval)timeout {
  DNSManifestCache* cache = [self.resolver valueForKey:@"cache"];
  [cache setValue:@(timeout) forKey:@"timeout"];

  NSString* path = [self.cacheDirectory stringByAppendingPathComponent:identifier];
  NSDictionary* attributes =
      @{NSFileModificationDate : [NSDate dateWithTimeIntervalSinceNow:-(timeout + 60.0)]};
  NSError* attributeError = nil;
  BOOL updated = [[NSFileManager defaultManager] setAttributes:attributes
                                                  ofItemAtPath:path
                                                         error:&attributeError];
  XCTAssertTrue(updated);
  XCTAssertNil(attributeError);
}

#pragma mark - Tests

- (void)testResolverFallsBackToExpiredCachedManifestWhenFetchFails {
  NSString* identifier = @"test_manifest";
  DNSManifest* manifest = [self dns_manifestWithIdentifier:identifier];
  DNSManifestCache* cache = [self.resolver valueForKey:@"cache"];
  [cache cacheManifest:manifest forIdentifier:identifier];

  // Force the cached entry to appear expired so the primary lookup misses.
  [self dns_markManifestExpired:identifier timeout:1.0];

  NSError* simulatedError = [NSError errorWithDomain:NSURLErrorDomain
                                                code:NSURLErrorTimedOut
                                            userInfo:nil];
  TestFetcherData = nil;
  TestFetcherError = simulatedError;

  NSDate* beforeCall = [NSDate date];

  NSError* error = nil;
  DNSManifest* resolved = [self.resolver getManifest:identifier error:&error];

  XCTAssertNotNil(resolved);
  XCTAssertNil(error);
  XCTAssertEqualObjects(resolved.identifier, identifier);

  NSString* cachePath = [self.cacheDirectory stringByAppendingPathComponent:identifier];
  NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:cachePath error:nil];
  NSDate* modDate = attrs[NSFileModificationDate];
  XCTAssertNotNil(modDate);
  XCTAssertTrue([modDate compare:beforeCall] != NSOrderedAscending,
                @"Expected cache refresh to update modification date");

  TestFetcherError = nil;
}

- (void)testResolverReturnsErrorWhenFetchFailsAndNoCacheExists {
  NSString* identifier = @"missing_manifest";

  NSError* simulatedError = [NSError errorWithDomain:NSURLErrorDomain
                                                code:NSURLErrorTimedOut
                                            userInfo:nil];
  TestFetcherData = nil;
  TestFetcherError = simulatedError;

  NSError* error = nil;
  DNSManifest* resolved = [self.resolver getManifest:identifier error:&error];

  XCTAssertNil(resolved);
  XCTAssertNotNil(error);
  XCTAssertEqualObjects(error.domain, DNSManifestErrorDomain);
  XCTAssertEqual(error.code, DNSManifestErrorManifestNotFound);
  TestFetcherError = nil;
}

- (void)testCacheReportsExpirationStatusThroughPublicAPI {
  NSString* identifier = @"stale_manifest";
  DNSManifest* manifest = [self dns_manifestWithIdentifier:identifier];
  DNSManifestCache* cache = [self.resolver valueForKey:@"cache"];
  [cache cacheManifest:manifest forIdentifier:identifier];

  [cache setValue:@(1.0) forKey:@"timeout"];

  NSString* cachePath = [self.cacheDirectory stringByAppendingPathComponent:identifier];
  NSDictionary* attributes =
      @{NSFileModificationDate : [NSDate dateWithTimeIntervalSinceNow:-120.0]};
  [[NSFileManager defaultManager] setAttributes:attributes ofItemAtPath:cachePath error:nil];

  BOOL wasExpired = NO;
  DNSManifest* freshLookup = [cache manifestForIdentifier:identifier
                                             allowExpired:NO
                                               wasExpired:&wasExpired];
  XCTAssertNil(freshLookup);
  XCTAssertTrue(wasExpired);

  wasExpired = NO;
  DNSManifest* expiredLookup = [cache manifestForIdentifier:identifier
                                               allowExpired:YES
                                                 wasExpired:&wasExpired];
  XCTAssertNotNil(expiredLookup);
  XCTAssertTrue(wasExpired);
  XCTAssertEqualObjects(expiredLookup.identifier, identifier);
}

@end
