//
//  NSBundle+DNSTesting.h
//  DNShield Tests
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSBundle (DNSTesting)

+ (NSBundle*)dns_testBundle;
+ (nullable NSURL*)dns_testBundleURLForResource:(NSString*)name
                                  withExtension:(nullable NSString*)ext;

@end

NS_ASSUME_NONNULL_END
