#import <Common/LoggingManager.h>
#import "Provider.h"
#import "ProxyProvider+Migration.h"
#import "ProxyProvider+Private.h"

@implementation ProxyProvider (Migration)

#pragma mark - Migration

- (void)migrateRulesToDatabase {
  // Check if migration is needed by comparing rule counts
  NSUInteger dbRuleCount = self.ruleDatabase.ruleCount;

  DNSLogInfo(LogCategoryRuleParsing, "Checking rule migration: DB has %lu rules",
             (unsigned long)dbRuleCount);

  if (dbRuleCount == 0) {
    DNSLogInfo(LogCategoryRuleParsing, "Starting migration of rules to SQLite database");

    dispatch_async(self.dnsQueue, ^{
      [self.ruleDatabase beginTransaction];

      // Migrate from shared defaults instead of trie (since trie doesn't expose all domains)
      NSArray* blockedList = [self.preferenceManager.sharedDefaults arrayForKey:@"BlockedDomains"];
      NSArray* whiteList =
          [self.preferenceManager.sharedDefaults arrayForKey:@"WhitelistedDomains"];
      NSMutableArray* rules = [NSMutableArray array];

      // Add blocked domains
      for (NSString* domain in blockedList) {
        DNSRule* rule = [DNSRule ruleWithDomain:domain action:DNSRuleActionBlock];
        rule.source = DNSRuleSourceSystem;
        rule.type = DNSRuleTypeExact;
        [rules addObject:rule];
      }

      // Add whitelisted domains
      for (NSString* domain in whiteList) {
        DNSRule* rule = [DNSRule ruleWithDomain:domain action:DNSRuleActionAllow];
        rule.source = DNSRuleSourceSystem;
        rule.type = DNSRuleTypeExact;
        rule.priority = 200;  // Higher priority for whitelist
        [rules addObject:rule];
      }

      // Batch insert all rules
      NSError* error = nil;
      if ([self.ruleDatabase addRules:rules error:&error]) {
        if ([self.ruleDatabase commitTransaction]) {
          DNSLogInfo(LogCategoryRuleParsing, "Successfully migrated %lu rules to database",
                     (unsigned long)rules.count);
        } else {
          DNSLogError(LogCategoryRuleParsing, "Failed to commit migration transaction");
        }
      } else {
        DNSLogError(LogCategoryRuleParsing, "Failed to migrate rules: %@", error);
        [self.ruleDatabase rollbackTransaction];
      }
    });
  }
}

- (void)warmCache {
  DNSLogInfo(LogCategoryCache, "Warming DNS rule cache...");

  dispatch_async(self.dnsQueue, ^{
    // Get most frequently queried domains
    NSArray<NSString*>* frequentDomains = [self.ruleDatabase mostQueriedDomains:1000];

    NSUInteger warmedCount = 0;
    for (NSString* domain in frequentDomains) {
      DNSRule* rule = [self.ruleDatabase ruleForDomain:domain];
      if (rule) {
        // Use adaptive TTL based on query frequency
        NSUInteger queryCount = [self.ruleDatabase queryCountForDomain:domain];
        NSTimeInterval adaptiveTTL = [self calculateAdaptiveTTL:queryCount];
        [self.ruleCache setAction:rule.action forDomain:domain withTTL:adaptiveTTL];
        warmedCount++;
      }
    }

    DNSLogInfo(LogCategoryCache, "Cache warmed with %lu entries from %lu frequent domains",
               (unsigned long)warmedCount, (unsigned long)frequentDomains.count);
  });
}

- (NSTimeInterval)calculateAdaptiveTTL:(NSUInteger)queryCount {
  // Base TTL is 5 minutes (300 seconds)
  NSTimeInterval baseTTL = 300;

  // Domains accessed frequently get longer TTL
  if (queryCount > 1000) {
    return baseTTL * 8;  // 40 minutes for very frequent domains
  } else if (queryCount > 500) {
    return baseTTL * 4;  // 20 minutes for frequent domains
  } else if (queryCount > 100) {
    return baseTTL * 2;  // 10 minutes for moderately frequent domains
  } else if (queryCount > 50) {
    return baseTTL * 1.5;  // 7.5 minutes
  }

  return baseTTL;  // Default 5 minutes for less frequent domains
}

- (void)startPeriodicMaintenance {
  DNSLogInfo(LogCategoryPerformance, "Starting periodic maintenance tasks");

  // Run cleanup every hour using dispatch timer instead of infinite loop
  static dispatch_source_t maintenanceTimer = nil;
  if (maintenanceTimer) {
    dispatch_source_cancel(maintenanceTimer);
  }

  dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0);
  maintenanceTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

  // First execution after 1 hour, then every hour
  dispatch_source_set_timer(maintenanceTimer, dispatch_time(DISPATCH_TIME_NOW, 3600 * NSEC_PER_SEC),
                            3600 * NSEC_PER_SEC,
                            60 * NSEC_PER_SEC);  // 1 minute leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(maintenanceTimer, ^{
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    dispatch_async(strongSelf.dnsQueue, ^{
      DNSLogInfo(LogCategoryPerformance, "Running periodic maintenance");

      // Clean up expired rules
      NSError* error = nil;
      if ([strongSelf.ruleDatabase removeExpiredRules:&error]) {
        DNSLogInfo(LogCategoryPerformance, "Expired rules cleanup completed");
      } else {
        DNSLogError(LogCategoryPerformance, "Failed to clean up expired rules: %@", error);
      }

      // Clean up old query statistics (older than 7 days)
      [strongSelf.ruleDatabase cleanupOldQueryStats:7 * 24 * 60 * 60];

      // Clear DNS cache to ensure fresh lookups
      [strongSelf.dnsCache clearCache];
      [strongSelf.ruleCache clear];

      // Re-warm cache after cleanup
      [strongSelf warmCache];

      // Vacuum database for optimal performance
      if ([strongSelf.ruleDatabase vacuum]) {
        DNSLogInfo(LogCategoryPerformance, "Database vacuum completed");
      }

      // Log current statistics
      NSDictionary* stats = [[DNSCacheStats sharedStats] snapshot];
      DNSLogInfo(LogCategoryPerformance, "Performance stats: %@", stats);
    });
  });

  dispatch_resume(maintenanceTimer);
}

@end
