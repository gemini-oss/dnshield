//
//  NSBundle+DNSTesting.m
//  DNShield Tests
//

#import "NSBundle+DNSTesting.h"

#import <XCTest/XCTest.h>

@implementation NSBundle (DNSTesting)

+ (NSBundle*)dns_testBundle {
  // Bundle corresponding to the currently running test case class
  return [NSBundle bundleForClass:[XCTestCase class]];
}

+ (NSURL*)dns_testBundleURLForResource:(NSString*)name withExtension:(NSString*)ext {
  return [[self dns_testBundle] URLForResource:name withExtension:ext];
}

@end
