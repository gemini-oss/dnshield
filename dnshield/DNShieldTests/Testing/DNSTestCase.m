//
//  DNSTestCase.m
//  DNShield Tests
//

#import "DNSTestCase.h"

#import <CoreFoundation/CoreFoundation.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>

#import "NSBundle+DNSTesting.h"

@interface DNSTestCase ()
@property(nonatomic, readwrite) NSURL* dns_tempDirectoryURL;
@end

@implementation DNSTestCase

- (void)setUp {
  [super setUp];

  // Create a unique temporary directory for each test method
  NSString* uuid = [[NSUUID UUID] UUIDString];
  NSURL* base = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
  NSURL* dir =
      [base URLByAppendingPathComponent:[NSString stringWithFormat:@"dnshield-test-%@", uuid]
                            isDirectory:YES];
  NSError* err = nil;
  [[NSFileManager defaultManager] createDirectoryAtURL:dir
                           withIntermediateDirectories:YES
                                            attributes:nil
                                                 error:&err];
  self.dns_tempDirectoryURL = dir;
}

- (void)tearDown {
  // Remove the temporary directory
  if (self.dns_tempDirectoryURL) {
    [[NSFileManager defaultManager] removeItemAtURL:self.dns_tempDirectoryURL error:nil];
    self.dns_tempDirectoryURL = nil;
  }

  // Clear standard DNShield preferences used by tests
  [self dns_clearAllTestPreferences];

  [super tearDown];
}

#pragma mark - Temp directories

- (NSURL*)dns_makeTempSubdirectory:(NSString*)name {
  NSURL* subdir = [self.dns_tempDirectoryURL URLByAppendingPathComponent:name isDirectory:YES];
  [[NSFileManager defaultManager] createDirectoryAtURL:subdir
                           withIntermediateDirectories:YES
                                            attributes:nil
                                                 error:nil];
  return subdir;
}

#pragma mark - Resources

- (NSURL*)dns_URLForResource:(NSString*)name withExtension:(NSString*)ext {
  return [NSBundle dns_testBundleURLForResource:name withExtension:ext];
}

- (NSData*)dns_dataForResource:(NSString*)name withExtension:(NSString*)ext {
  NSURL* url = [self dns_URLForResource:name withExtension:ext];
  if (!url)
    return nil;
  return [NSData dataWithContentsOfURL:url];
}

#pragma mark - Preferences

- (void)dns_setPreferenceValue:(id)value forKey:(NSString*)key {
  CFPreferencesSetAppValue((__bridge CFStringRef)key, (__bridge CFPropertyListRef)value,
                           (__bridge CFStringRef)kDNShieldPreferenceDomain);
  CFPreferencesAppSynchronize((__bridge CFStringRef)kDNShieldPreferenceDomain);
}

- (void)dns_clearPreferenceForKey:(NSString*)key {
  CFPreferencesSetAppValue((__bridge CFStringRef)key, NULL,
                           (__bridge CFStringRef)kDNShieldPreferenceDomain);
  CFPreferencesAppSynchronize((__bridge CFStringRef)kDNShieldPreferenceDomain);
}

- (void)dns_clearAllTestPreferences {
  // A focused set of keys frequently used in tests
  [self dns_clearPreferenceForKey:kDNShieldClientIdentifier];
  [self dns_clearPreferenceForKey:kDNShieldManifestFormat];
  [self dns_clearPreferenceForKey:kDNShieldManifestURL];
}

#pragma mark - Async helpers

- (XCTestExpectation*)dns_expectation:(NSString*)description {
  return [self expectationWithDescription:description];
}

- (void)dns_waitForExpectations:(NSTimeInterval)timeout {
  [self waitForExpectationsWithTimeout:timeout handler:nil];
}

- (void)dns_wait:(NSTimeInterval)timeout forExpectation:(XCTestExpectation*)expectation {
  if (!expectation)
    return;
  [self waitForExpectations:@[ expectation ] timeout:timeout];
}

#pragma mark - Temp file helpers

- (NSURL*)dns_writeData:(NSData*)data named:(NSString*)filename {
  NSURL* dest = [self.dns_tempDirectoryURL URLByAppendingPathComponent:filename];
  [data writeToURL:dest atomically:YES];
  return dest;
}

- (NSURL*)dns_writeString:(NSString*)string named:(NSString*)filename {
  NSData* data = [string dataUsingEncoding:NSUTF8StringEncoding];
  return [self dns_writeData:data named:filename];
}

- (NSURL*)dns_copyResource:(NSString*)name
             withExtension:(NSString*)ext
                  toSubdir:(NSString*)subdirName {
  NSURL* src = [self dns_URLForResource:name withExtension:ext];
  if (!src)
    return nil;
  NSURL* destDir = self.dns_tempDirectoryURL;
  if (subdirName.length > 0) {
    destDir = [self dns_makeTempSubdirectory:subdirName];
  }
  NSURL* dest = [destDir URLByAppendingPathComponent:[src lastPathComponent]];
  [[NSFileManager defaultManager] copyItemAtURL:src toURL:dest error:nil];
  return dest;
}

@end
