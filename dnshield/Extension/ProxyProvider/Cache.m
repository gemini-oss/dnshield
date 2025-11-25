#import <Common/LoggingManager.h>
#import "Provider.h"
#import "ProxyProvider+Cache.h"
#import "ProxyProvider+Private.h"
#import "RuleSet.h"

@implementation ProxyProvider (CacheRules)

#pragma mark - Cache Rule Matching

- (NSDictionary*)findMatchingCacheRule:(NSString*)domain inRules:(NSDictionary*)rules {
  if (!domain || !rules) {
    return nil;
  }

  // First check for exact match
  NSDictionary* exactMatch = rules[domain];
  if (exactMatch) {
    return exactMatch;
  }

  // Then check for wildcard matches
  for (NSString* pattern in rules) {
    if ([pattern hasPrefix:@"*."]) {
      // Wildcard pattern - check suffix match
      NSString* suffix = [pattern substringFromIndex:2];  // Remove "*."
      if ([domain hasSuffix:suffix]) {
        return rules[pattern];
      }

      // Also check if domain equals the suffix without subdomain
      if ([domain isEqualToString:suffix]) {
        return rules[pattern];
      }
    } else if ([pattern hasPrefix:@"*"]) {
      // Pure wildcard - matches any subdomain
      NSString* suffix = [pattern substringFromIndex:1];  // Remove "*"
      if ([domain hasSuffix:suffix]) {
        return rules[pattern];
      }
    }
  }

  return nil;
}

@end
