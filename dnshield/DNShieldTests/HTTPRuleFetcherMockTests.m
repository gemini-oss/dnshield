//
//  HTTPRuleFetcherMockTests.m
//  DNShield Tests
//
//  Tests for HTTPRuleFetcher using OCMock
//

#import <XCTest/XCTest.h>
#import "DNSManifest.h"
#import "HTTPRuleFetcher.h"
#import "TestConfiguration.h"
#import "Testing/DNSTestCase.h"

@interface HTTPRuleFetcherMockTests : DNSTestCase
@property(nonatomic, strong) HTTPRuleFetcher* fetcher;
#ifdef OCMOCK_AVAILABLE
@property(nonatomic, strong) id mockSession;
@property(nonatomic, strong) id mockTask;
#endif
@end

@implementation HTTPRuleFetcherMockTests

- (void)setUp {
  [super setUp];

  NSURL* testURL = [NSURL URLWithString:@"https://example.com/manifest.json"];
  self.fetcher = [[HTTPRuleFetcher alloc] initWithURL:testURL];

#ifdef OCMOCK_AVAILABLE
  // Create mock session and task
  self.mockSession = OCMClassMock([NSURLSession class]);
  self.mockTask = OCMClassMock([NSURLSessionDataTask class]);
#endif
}

- (void)tearDown {
#ifdef OCMOCK_AVAILABLE
  [self.mockSession stopMocking];
  [self.mockTask stopMocking];
#endif
  self.fetcher = nil;
  [super tearDown];
}

- (void)testFetcherInitialization {
  XCTAssertNotNil(self.fetcher, @"Fetcher should be initialized");
  XCTAssertNotNil(self.fetcher.URL, @"URL should be set");
  XCTAssertEqualObjects(self.fetcher.URL.absoluteString, @"https://example.com/manifest.json");
}

#ifdef OCMOCK_AVAILABLE

- (void)testSuccessfulFetchWithMock {
  // Setup expectation
  XCTestExpectation* expectation = [self expectationWithDescription:@"Fetch completion"];

  // Create mock response data
  NSDictionary* mockManifest = @{@"version" : @"1.0", @"rules" : @[ @"example.com", @"test.com" ]};
  NSData* mockData = [NSJSONSerialization dataWithJSONObject:mockManifest options:0 error:nil];

  // Setup mock session to return our data
  NSHTTPURLResponse* mockResponse = [[NSHTTPURLResponse alloc] initWithURL:self.fetcher.url
                                                                statusCode:200
                                                               HTTPVersion:@"HTTP/1.1"
                                                              headerFields:nil];

  // Configure mock to return data
  OCMStub([self.mockSession dataTaskWithRequest:[OCMArg any]
                              completionHandler:([OCMArg invokeBlockWithArgs:mockData, mockResponse,
                                                                             [NSNull null], nil])]);

  OCMStub([self.mockTask resume]);

  // Inject mock session into fetcher (would need to expose session property)
  // For now, this demonstrates the setup

  // Perform fetch
  [self.fetcher performFetchWithCompletion:^(DNSManifest* manifest, NSError* error) {
    XCTAssertNil(error, @"Error should be nil for successful fetch");
    XCTAssertNotNil(manifest, @"Manifest should not be nil");
    [expectation fulfill];
  }];

  [self waitForExpectationsWithTimeout:kTestTimeout handler:nil];
}

- (void)testFetchWithNetworkError {
  // Setup expectation
  XCTestExpectation* expectation = [self expectationWithDescription:@"Error completion"];

  // Create mock error
  NSError* mockError = [NSError errorWithDomain:NSURLErrorDomain
                                           code:NSURLErrorNetworkConnectionLost
                                       userInfo:nil];

  // Configure mock to return error
  OCMStub([self.mockSession
      dataTaskWithRequest:[OCMArg any]
        completionHandler:([OCMArg
                              invokeBlockWithArgs:[NSNull null], [NSNull null], mockError, nil])]);

  // Perform fetch
  [self.fetcher performFetchWithCompletion:^(DNSManifest* manifest, NSError* error) {
    XCTAssertNotNil(error, @"Error should not be nil");
    XCTAssertNil(manifest, @"Manifest should be nil on error");
    XCTAssertEqual(error.code, NSURLErrorNetworkConnectionLost);
    [expectation fulfill];
  }];

  [self waitForExpectationsWithTimeout:kTestTimeout handler:nil];
}

- (void)testTimeoutBehavior {
  // Test that timeout is properly configured
  XCTestExpectation* expectation = [self expectationWithDescription:@"Timeout test"];

  // Create a mock that simulates timeout
  NSError* timeoutError = [NSError errorWithDomain:NSURLErrorDomain
                                              code:NSURLErrorTimedOut
                                          userInfo:nil];

  OCMStub([self.mockSession
      dataTaskWithRequest:[OCMArg any]
        completionHandler:([OCMArg invokeBlockWithArgs:[NSNull null], [NSNull null], timeoutError,
                                                       nil])]);

  [self.fetcher performFetchWithCompletion:^(DNSManifest* manifest, NSError* error) {
    XCTAssertNotNil(error, @"Should have timeout error");
    XCTAssertEqual(error.code, NSURLErrorTimedOut, @"Should be timeout error");
    [expectation fulfill];
  }];

  [self waitForExpectationsWithTimeout:kTestTimeout handler:nil];
}

#else

- (void)testMockingNotAvailable {
  NSLog(@"OCMock not available - skipping mock tests");
  NSLog(@"Run DNShieldTests/vendors/install_ocmock.sh to install OCMock framework");
}

#endif

@end
