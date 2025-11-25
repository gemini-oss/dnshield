//
//  DNSTestCase.h
//  DNShield Tests
//
//  A lightweight base test case inspired by Santa's Testing utilities.
//  Provides temporary directories, resource helpers, and preference utilities.
//

#import <XCTest/XCTest.h>

NS_ASSUME_NONNULL_BEGIN

@interface DNSTestCase : XCTestCase

// Per-test temporary working directory (unique per test method)
@property(nonatomic, readonly) NSURL* dns_tempDirectoryURL;

// Convenience to create a subdirectory under the per-test temp dir
- (NSURL*)dns_makeTempSubdirectory:(NSString*)name;

// Locate a resource in the test bundle (e.g., plist fixtures)
- (nullable NSURL*)dns_URLForResource:(NSString*)name withExtension:(nullable NSString*)ext;
- (nullable NSData*)dns_dataForResource:(NSString*)name withExtension:(nullable NSString*)ext;

// CFPreferences helpers for the DNShield domain
- (void)dns_setPreferenceValue:(nullable id)value forKey:(NSString*)key;
- (void)dns_clearPreferenceForKey:(NSString*)key;
- (void)dns_clearAllTestPreferences;  // clears common keys used in tests

// Async helpers
- (XCTestExpectation*)dns_expectation:(NSString*)description;
- (void)dns_waitForExpectations:(NSTimeInterval)timeout;
- (void)dns_wait:(NSTimeInterval)timeout forExpectation:(XCTestExpectation*)expectation;

// Temp file helpers
- (NSURL*)dns_writeData:(NSData*)data named:(NSString*)filename;
- (NSURL*)dns_writeString:(NSString*)string named:(NSString*)filename;
- (nullable NSURL*)dns_copyResource:(NSString*)name
                      withExtension:(nullable NSString*)ext
                           toSubdir:(nullable NSString*)subdirName;

@end

NS_ASSUME_NONNULL_END
