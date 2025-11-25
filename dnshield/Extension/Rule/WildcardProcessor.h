//
//  WildcardProcessor.h
//  DNShield Network Extension
//
//  Processes wildcard rules and handles root domain inclusion
//

#import <Foundation/Foundation.h>
#import "RuleDatabase.h"

NS_ASSUME_NONNULL_BEGIN

@interface WildcardProcessor : NSObject

// Process a wildcard rule and optionally add root domain rule
+ (NSArray<DNSRule*>*)processWildcardRule:(DNSRule*)wildcardRule includeRoot:(BOOL)includeRoot;

// Automatically add root domain rules for all wildcards in database
+ (void)enhanceWildcardRulesInDatabase:(RuleDatabase*)database
                        withCompletion:(nullable void (^)(NSUInteger rulesAdded,
                                                          NSError* _Nullable error))completion;

// Check if a rule is a wildcard that needs root domain coverage
+ (BOOL)isWildcardNeedingRootCoverage:(DNSRule*)rule;

// Generate root domain from wildcard domain
+ (nullable NSString*)rootDomainFromWildcard:(NSString*)wildcardDomain;

@end

NS_ASSUME_NONNULL_END
