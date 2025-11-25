#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import "Provider.h"
#import "ProxyProvider+Private.h"

@implementation ProxyProvider (SharedDefaults)

#pragma mark - Shared Defaults Commands

- (void)writeRuleStatusToSharedDefaults {
  DNSLogInfo(LogCategoryConfiguration,
             "writeRuleStatusToSharedDefaults called - preparing status data");

  NSUInteger totalQueries = self.blockedCount + self.allowedCount;
  double dnsCacheHitRate = self.dnsCache.hitRate;
  double ruleCacheHitRate = self.ruleCache.hitRate;

  NSDictionary* status = @{
    @"lastUpdate" : self.ruleManager.lastUpdateDate ?: [NSNull null],
    @"isUpdating" : @(self.ruleManager.state == RuleManagerStateRunning),

    @"totalRuleCount" : @([self.ruleManager totalRuleCount]),
    @"sourceCount" : @([self.ruleManager allRuleSources].count),
    @"dnsCacheHitRate" : @(dnsCacheHitRate),
    @"ruleCacheHitRate" : @(ruleCacheHitRate),
    @"queriesProcessed" : @(totalQueries),
    @"queriesBlocked" : @(self.blockedCount),
    @"queriesAllowed" : @(self.allowedCount),
    @"dnsCacheSize" : @(self.dnsCache.cacheSize),
    @"dnsCacheEvictions" : @(self.dnsCache.evictionCount),
    @"ruleCacheSize" : @(self.ruleCache.currentSize),
    @"ruleCacheEvictions" : @(self.ruleCache.evictionCount)
  };

  [self.preferenceManager.sharedDefaults setObject:status forKey:@"DNSProxyStatus"];
  [self.preferenceManager.sharedDefaults synchronize];

  // Force CFPreferences sync for better cross-process communication
  DNPreferenceDomainSynchronize(kDNShieldAppGroup);

  DNSLogInfo(LogCategoryConfiguration, "Rule status written to shared defaults with %lu keys",
             (unsigned long)status.count);
}

- (void)triggerManualRuleUpdate {
  DNSLogInfo(LogCategoryRuleFetching, "Manual rule update triggered via shared defaults");

  if (self.ruleManager) {
    // Trigger immediate update of all rule sources
    [self.ruleManager forceUpdate];

    // Write update started status
    NSDateFormatter* isoFormatter = [[NSDateFormatter alloc] init];
    isoFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    isoFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    isoFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];

    [self.preferenceManager.sharedDefaults setObject:@{
      @"updateStarted" : @YES,
      @"timestamp" : [isoFormatter stringFromDate:[NSDate date]]
    }
                                              forKey:@"DNSProxyUpdateStatus"];
    [self.preferenceManager.sharedDefaults synchronize];

    // Force CFPreferences sync
    DNPreferenceDomainSynchronize(kDNShieldAppGroup);
  } else {
    DNSLogError(LogCategoryRuleFetching, "Cannot trigger update - rule manager not initialized");

    // Write error status
    [self.preferenceManager.sharedDefaults setObject:@{@"error" : @"Rule manager not initialized"}
                                              forKey:@"DNSProxyUpdateStatus"];
    [self.preferenceManager.sharedDefaults synchronize];

    // Force CFPreferences sync
    DNPreferenceDomainSynchronize(kDNShieldAppGroup);
  }
}

@end
