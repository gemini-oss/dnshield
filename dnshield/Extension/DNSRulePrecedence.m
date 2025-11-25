//
//  DNSRulePrecedence.m
//  DNShield Network Extension
//
//  Rule precedence and conflict resolution implementation
//

#import <os/log.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/Precedence.h>

#import "DNSWildcardConfig.h"

static os_log_t logHandle;

@implementation RulePrecedence

+ (void)initialize {
  if (self == [RulePrecedence class]) {
    logHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"RulePrecedence");
  }
}

+ (DNSRuleAction)resolveConflictBetweenRules:(NSArray<DNSRule*>*)rules forDomain:(NSString*)domain {
  if (rules.count == 0) {
    return DNSRuleActionUnknown;
  }

  // Sort rules by precedence
  NSArray<DNSRule*>* sortedRules = [self sortRulesByPrecedence:rules forDomain:domain];

  // Log conflict resolution
  if (rules.count > 1) {
    os_log_info(logHandle, "Resolving conflict for domain %{public}@ with %lu rules", domain,
                (unsigned long)rules.count);
    for (DNSRule* rule in sortedRules) {
      os_log_debug(logHandle, "  Rule: %{public}@ action=%ld priority=%ld type=%ld", rule.domain,
                   (long)rule.action, (long)rule.priority, (long)rule.type);
    }
  }

  // Return the action of the highest precedence rule
  DNSRule* winningRule = sortedRules.firstObject;
  os_log_info(logHandle, "Domain %{public}@ resolved to action %ld from rule %{public}@", domain,
              (long)winningRule.action, winningRule.domain);

  return winningRule.action;
}

+ (BOOL)hasExplicitAllowRule:(NSString*)domain inDatabase:(RuleDatabase*)database {
  // Check for exact match allow rule
  DNSRule* exactRule = [database ruleForDomain:domain];
  if (exactRule && exactRule.type == DNSRuleTypeExact && exactRule.action == DNSRuleActionAllow) {
    os_log_info(logHandle, "Found explicit allow rule for %{public}@", domain);
    return YES;
  }

  // Check if there's a more specific allow rule that overrides wildcards
  NSArray<DNSRule*>* allRules = [self allMatchingRulesForDomain:domain inDatabase:database];
  for (DNSRule* rule in allRules) {
    if (rule.action == DNSRuleActionAllow) {
      // Check if this is a specific subdomain allow rule
      if ([rule.domain isEqualToString:domain] ||
          (rule.type == DNSRuleTypeWildcard && [self isSpecificSubdomainRule:rule.domain
                                                                   forDomain:domain])) {
        os_log_info(logHandle, "Found overriding allow rule %{public}@ for %{public}@", rule.domain,
                    domain);
        return YES;
      }
    }
  }

  return NO;
}

+ (NSArray<DNSRule*>*)allMatchingRulesForDomain:(NSString*)domain
                                     inDatabase:(RuleDatabase*)database {
  NSMutableArray<DNSRule*>* matchingRules = [NSMutableArray array];

  // Don't load all the things!
  // Instead, use database queries to find matching rules efficiently

  // 1. Check for exact match first (most common case)
  DNSRule* exactRule = [database ruleForDomain:domain];
  if (exactRule) {
    [matchingRules addObject:exactRule];
  }

  // 2. Check parent domains for wildcard rules
  NSArray* domainParts = [domain componentsSeparatedByString:@"."];
  NSUInteger partCount = domainParts.count;

  // Build parent domains: example.com -> *.example.com, *.com
  for (NSUInteger i = 1; i < partCount; i++) {
    NSArray* parentParts = [domainParts subarrayWithRange:NSMakeRange(i, partCount - i)];
    NSString* parentDomain = [parentParts componentsJoinedByString:@"."];

    // Check wildcard version
    NSString* wildcardDomain = [@"*." stringByAppendingString:parentDomain];
    DNSRule* wildcardRule = [database ruleForDomain:wildcardDomain];
    if (wildcardRule) {
      [matchingRules addObject:wildcardRule];
    }
  }

  // 3. Check for root wildcard rules (*.com, *.net, etc)
  if (partCount > 0) {
    NSString* tld = [@"*." stringByAppendingString:domainParts.lastObject];
    DNSRule* tldRule = [database ruleForDomain:tld];
    if (tldRule) {
      [matchingRules addObject:tldRule];
    }
  }

  // Sort by precedence
  return [self sortRulesByPrecedence:matchingRules forDomain:domain];
}

#pragma mark - Private Methods

+ (NSArray<DNSRule*>*)sortRulesByPrecedence:(NSArray<DNSRule*>*)rules forDomain:(NSString*)domain {
  return [rules sortedArrayUsingComparator:^NSComparisonResult(DNSRule* rule1, DNSRule* rule2) {
    // 1. Exact matches have highest precedence
    BOOL isExact1 = [rule1.domain isEqualToString:domain];
    BOOL isExact2 = [rule2.domain isEqualToString:domain];

    if (isExact1 && !isExact2)
      return NSOrderedAscending;
    if (!isExact1 && isExact2)
      return NSOrderedDescending;

    // 2. Within same match type, allow rules have precedence over block rules
    if (rule1.action == DNSRuleActionAllow && rule2.action == DNSRuleActionBlock) {
      return NSOrderedAscending;
    }
    if (rule1.action == DNSRuleActionBlock && rule2.action == DNSRuleActionAllow) {
      return NSOrderedDescending;
    }

    // 3. More specific wildcards have precedence
    NSUInteger specificity1 = [self calculateSpecificity:rule1.domain];
    NSUInteger specificity2 = [self calculateSpecificity:rule2.domain];

    if (specificity1 > specificity2)
      return NSOrderedAscending;
    if (specificity1 < specificity2)
      return NSOrderedDescending;

    // 4. Higher priority value wins
    if (rule1.priority > rule2.priority)
      return NSOrderedAscending;
    if (rule1.priority < rule2.priority)
      return NSOrderedDescending;

    // 5. User rules have precedence over system rules
    if (rule1.source == DNSRuleSourceUser && rule2.source != DNSRuleSourceUser) {
      return NSOrderedAscending;
    }
    if (rule1.source != DNSRuleSourceUser && rule2.source == DNSRuleSourceUser) {
      return NSOrderedDescending;
    }

    return NSOrderedSame;
  }];
}

+ (NSUInteger)calculateSpecificity:(NSString*)domain {
  // More dots = more specific
  // *.foo.bar.com is more specific than *.bar.com
  NSUInteger dotCount = 0;
  for (NSUInteger i = 0; i < domain.length; i++) {
    if ([domain characterAtIndex:i] == '.') {
      dotCount++;
    }
  }

  // Subtract 1 if it's a wildcard to account for the *. prefix
  if ([domain hasPrefix:@"*."]) {
    dotCount = dotCount > 0 ? dotCount - 1 : 0;
  }

  return dotCount;
}

+ (BOOL)isSpecificSubdomainRule:(NSString*)ruleDomain forDomain:(NSString*)queryDomain {
  // Check if ruleDomain is a specific subdomain allow for queryDomain
  // Example: allowed.foo.com is specific for foo.com
  if ([ruleDomain hasPrefix:@"*."]) {
    return NO;  // Wildcards are not specific
  }

  // Check if ruleDomain is a subdomain of queryDomain
  if ([ruleDomain hasSuffix:queryDomain]) {
    NSUInteger prefixLength = ruleDomain.length - queryDomain.length;
    if (prefixLength > 0 && [[ruleDomain substringToIndex:prefixLength] hasSuffix:@"."]) {
      return YES;
    }
  }

  return NO;
}

@end
