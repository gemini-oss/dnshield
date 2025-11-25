//
//  DNSWildcardProcessor.m
//  DNShield Network Extension
//
//  Processes wildcard rules and handles root domain inclusion implementation
//

#import <os/log.h>

#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/Precedence.h>
#import <Rule/WildcardProcessor.h>

#import "DNSWildcardConfig.h"
static os_log_t logHandle;

@implementation WildcardProcessor

+ (void)initialize {
  if (self == [WildcardProcessor class]) {
    logHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"WildcardProcessor");
  }
}

+ (NSArray<DNSRule*>*)processWildcardRule:(DNSRule*)wildcardRule includeRoot:(BOOL)includeRoot {
  NSMutableArray<DNSRule*>* rules = [NSMutableArray arrayWithObject:wildcardRule];

  // Check if we should add root domain rule
  if (includeRoot && [self isWildcardNeedingRootCoverage:wildcardRule]) {
    NSString* rootDomain = [self rootDomainFromWildcard:wildcardRule.domain];
    if (rootDomain) {
      // Create root domain rule with same properties as wildcard
      DNSRule* rootRule = [[DNSRule alloc] init];
      rootRule.domain = rootDomain;
      rootRule.action = wildcardRule.action;
      rootRule.type = DNSRuleTypeExact;  // Root domain is exact match
      rootRule.priority = wildcardRule.priority;
      rootRule.source = wildcardRule.source;
      rootRule.customMessage = wildcardRule.customMessage;
      rootRule.comment =
          [NSString stringWithFormat:@"Auto-generated root for %@", wildcardRule.domain];
      rootRule.updatedAt = [NSDate date];

      [rules addObject:rootRule];

      os_log_info(logHandle, "Generated root domain rule for %{public}@: %{public}@",
                  wildcardRule.domain, rootDomain);
    }
  }

  return [rules copy];
}

+ (void)enhanceWildcardRulesInDatabase:(RuleDatabase*)database
                        withCompletion:(nullable void (^)(NSUInteger rulesAdded,
                                                          NSError* _Nullable error))completion {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    os_log_info(logHandle, "Starting wildcard rule enhancement");

    DNSWildcardConfig* config = [DNSWildcardConfig sharedConfig];
    if (config.mode == DNSWildcardModeSubdomainsOnly) {
      os_log_info(logHandle, "Wildcard mode is subdomains-only, skipping enhancement");
      if (completion) {
        completion(0, nil);
      }
      return;
    }

    NSError* error = nil;
    NSUInteger rulesAdded = 0;

    // Get all wildcard rules
    NSArray<DNSRule*>* allRules = [database allRules];
    NSMutableArray<DNSRule*>* rootRulesToAdd = [NSMutableArray array];
    NSMutableSet<NSString*>* existingDomains = [NSMutableSet set];

    // Build set of existing domains for quick lookup
    for (DNSRule* rule in allRules) {
      [existingDomains addObject:rule.domain];
    }

    // Process each wildcard rule
    for (DNSRule* rule in allRules) {
      if ([self isWildcardNeedingRootCoverage:rule]) {
        NSString* rootDomain = [self rootDomainFromWildcard:rule.domain];

        if (rootDomain && ![existingDomains containsObject:rootDomain]) {
          // Check if there's an explicit allow rule for the root
          BOOL hasExplicitAllow = [RulePrecedence hasExplicitAllowRule:rootDomain
                                                            inDatabase:database];

          if (!hasExplicitAllow || !config.respectAllowlistPrecedence) {
            // Create root domain rule
            DNSRule* rootRule = [[DNSRule alloc] init];
            rootRule.domain = rootDomain;
            rootRule.action = rule.action;
            rootRule.type = DNSRuleTypeExact;
            rootRule.priority = rule.priority - 1;  // Slightly lower priority than wildcard
            rootRule.source = DNSRuleSourceSystem;  // Mark as system-generated
            rootRule.comment =
                [NSString stringWithFormat:@"Auto-generated root for %@", rule.domain];
            rootRule.updatedAt = [NSDate date];

            [rootRulesToAdd addObject:rootRule];
            [existingDomains addObject:rootDomain];  // Prevent duplicates

            os_log_info(logHandle, "Adding root domain rule for %{public}@", rootDomain);
          } else {
            os_log_info(logHandle, "Skipping root %{public}@ - has explicit allow rule",
                        rootDomain);
          }
        }
      }
    }

    // Add all root rules to database
    if (rootRulesToAdd.count > 0) {
      if ([database addRules:rootRulesToAdd error:&error]) {
        rulesAdded = rootRulesToAdd.count;
        os_log_info(logHandle, "Successfully added %lu root domain rules",
                    (unsigned long)rulesAdded);
      } else {
        os_log_error(logHandle, "Failed to add root domain rules: %{public}@", error);
      }
    }

    if (completion) {
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(rulesAdded, error);
      });
    }
  });
}

+ (BOOL)isWildcardNeedingRootCoverage:(DNSRule*)rule {
  // Check if it's a wildcard rule
  if (rule.type != DNSRuleTypeWildcard) {
    return NO;
  }

  // Check if domain starts with *.
  if (![rule.domain hasPrefix:@"*."]) {
    return NO;
  }

  // Check configuration
  DNSWildcardConfig* config = [DNSWildcardConfig sharedConfig];
  return [config wildcardShouldMatchRoot:rule.domain];
}

+ (nullable NSString*)rootDomainFromWildcard:(NSString*)wildcardDomain {
  if (![wildcardDomain hasPrefix:@"*."]) {
    return nil;
  }

  // Extract root domain from wildcard
  // *.example.com -> example.com
  return [wildcardDomain substringFromIndex:2];
}

@end
