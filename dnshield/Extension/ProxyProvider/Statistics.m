#import <Common/LoggingManager.h>
#import "DNSCacheStats.h"
#import "Provider.h"
#import "ProxyProvider+Private.h"
#import "ProxyProvider+Statistics.h"

@implementation ProxyProvider (Statistics)

#pragma mark - Statistics

- (void)setupStatisticsReporting {
  static dispatch_source_t statisticsTimer = nil;
  if (statisticsTimer) {
    dispatch_source_cancel(statisticsTimer);
  }

  dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0);
  statisticsTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

  dispatch_source_set_timer(statisticsTimer, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC),
                            60 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(statisticsTimer, ^{
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (strongSelf) {
      [strongSelf reportStatistics];
    }
  });

  dispatch_resume(statisticsTimer);
}

- (void)reportStatistics {
  dispatch_async(self.dnsQueue, ^{
    [self.preferenceManager.sharedDefaults setInteger:self.blockedCount forKey:@"BlockedCount"];
    [self.preferenceManager.sharedDefaults setInteger:self.allowedCount forKey:@"AllowedCount"];
    [self.preferenceManager.sharedDefaults setDouble:self.dnsCache.hitRate forKey:@"CacheHitRate"];
    [self.preferenceManager.sharedDefaults synchronize];

    DNSLogInfo(LogCategoryPerformance, "Stats - Blocked: %lu, Allowed: %lu, Cache hit rate: %.2f%%",
               (unsigned long)self.blockedCount, (unsigned long)self.allowedCount,
               self.dnsCache.hitRate * 100);

    DNSCacheStats* cacheStats = [DNSCacheStats sharedStats];
    NSDictionary* statsSnapshot = [cacheStats snapshot];

    struct task_basic_info info;
    mach_msg_type_number_t size = TASK_BASIC_INFO_COUNT;
    kern_return_t kerr = task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &size);
    NSUInteger memoryUsageMB = (kerr == KERN_SUCCESS) ? (info.resident_size / 1024 / 1024) : 0;

    [self.telemetry
        logCachePerformanceEvent:@"dns_response_cache"
                         hitRate:self.dnsCache.hitRate
                   evictionCount:self.dnsCache.evictionCount
                     memoryUsage:memoryUsageMB
                        metadata:@{
                          @"total_queries" : @(self.blockedCount + self.allowedCount),
                          @"queries_per_second" : statsSnapshot[@"queriesPerSecond"] ?: @0,
                          @"avg_lookup_time_ms" :
                              @([statsSnapshot[@"avgLookupTime"] doubleValue] * 1000),
                          @"fastest_lookup_ms" :
                              @([statsSnapshot[@"fastestLookup"] doubleValue] * 1000),
                          @"slowest_lookup_ms" :
                              @([statsSnapshot[@"slowestLookup"] doubleValue] * 1000),
                          @"slow_query_count" : statsSnapshot[@"slowQueryCount"] ?: @0
                        }];

    [self.telemetry logCachePerformanceEvent:@"rule_cache"
                                     hitRate:[cacheStats hitRate]
                               evictionCount:[self.ruleCache evictionCount]
                                 memoryUsage:memoryUsageMB
                                    metadata:@{
                                      @"rule_count" : @(self.ruleDatabase.ruleCount),
                                      @"cache_size" : @(self.ruleCache.currentSize)
                                    }];
  });
}

@end
