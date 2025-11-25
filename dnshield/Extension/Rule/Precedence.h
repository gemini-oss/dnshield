//
//  Precedence.h
//  Extension
//
//

#import <Foundation/Foundation.h>
#import "RuleDatabase.h"

NS_ASSUME_NONNULL_BEGIN

@interface RulePrecedence : NSObject

// Resolve rule conflicts between block and allow rules
// Returns the final action to take based on precedence rules
+ (DNSRuleAction)resolveConflictBetweenRules:(NSArray<DNSRule*>*)rules forDomain:(NSString*)domain;

// Check if a domain has an explicit allow rule that overrides wildcard blocks
+ (BOOL)hasExplicitAllowRule:(NSString*)domain inDatabase:(RuleDatabase*)database;

// Get all matching rules for a domain, sorted by precedence
+ (NSArray<DNSRule*>*)allMatchingRulesForDomain:(NSString*)domain
                                     inDatabase:(RuleDatabase*)database;

// Precedence order (highest to lowest):
// 1. Exact domain allow rules
// 2. Exact domain block rules
// 3. Wildcard allow rules (more specific first)
// 4. Wildcard block rules (more specific first)

@end

NS_ASSUME_NONNULL_END
