//
//  DNSCacheStats.m
//  DNShield Network Extension
//
//  Cache statistics tracking for performance monitoring
//

#import <os/log.h>
#import <stdatomic.h>

#import <Common/Defaults.h>
#import <Common/LoggingManager.h>

#import "DNSCacheStats.h"

static os_log_t logHandle;

@interface DNSCacheStats ()
@property(nonatomic, assign) _Atomic(NSUInteger) hitCount;
@property(nonatomic, assign) _Atomic(NSUInteger) missCount;
@property(nonatomic, assign) _Atomic(double) totalLookupTime;
@property(nonatomic, assign) _Atomic(NSUInteger) lookupCount;
@property(nonatomic, assign) _Atomic(double) minLookupTime;
@property(nonatomic, assign) _Atomic(double) maxLookupTime;
@property(nonatomic, assign) _Atomic(NSUInteger) slowQueries;
@property(nonatomic, strong) NSDate* startTime;
@property(nonatomic, strong) dispatch_queue_t statsQueue;
@property(nonatomic, strong) NSMutableArray<NSNumber*>* recentQueryTimes;
@property(nonatomic, strong) NSTimer* qpsTimer;
@property(nonatomic, assign) NSUInteger currentQPS;
@end

@implementation DNSCacheStats

+ (void)initialize {
  if (self == [DNSCacheStats class]) {
    logHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"CacheStats");
  }
}

+ (instancetype)sharedStats {
  static DNSCacheStats* sharedStats = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedStats = [[DNSCacheStats alloc] init];
  });
  return sharedStats;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    [self reset];
    _statsQueue = dispatch_queue_create("com.dnshield.cachestats", DISPATCH_QUEUE_SERIAL);
    _recentQueryTimes = [NSMutableArray array];

    // Start QPS calculation timer
    __weak typeof(self) weakSelf = self;
    _qpsTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                repeats:YES
                                                  block:^(NSTimer* _Nonnull timer) {
                                                    [weakSelf calculateQPS];
                                                  }];
  }
  return self;
}

- (void)dealloc {
  [_qpsTimer invalidate];
}

- (void)reset {
  atomic_store(&_hitCount, 0);
  atomic_store(&_missCount, 0);
  atomic_store(&_totalLookupTime, 0.0);
  atomic_store(&_lookupCount, 0);
  atomic_store(&_minLookupTime, DBL_MAX);
  atomic_store(&_maxLookupTime, 0.0);
  atomic_store(&_slowQueries, 0);
  _startTime = [NSDate date];
  os_log_info(logHandle, "Cache statistics reset");
}

- (void)recordHit:(NSTimeInterval)lookupTime {
  atomic_fetch_add(&_hitCount, 1);
  [self recordLookupTime:lookupTime];
}

- (void)recordMiss:(NSTimeInterval)lookupTime {
  atomic_fetch_add(&_missCount, 1);
  [self recordLookupTime:lookupTime];
}

- (void)recordDatabaseQuery:(NSTimeInterval)queryTime {
  [self recordLookupTime:queryTime];
}

- (void)recordLookupTime:(NSTimeInterval)lookupTime {
  atomic_fetch_add(&_lookupCount, 1);

  // Update total time for average calculation
  double currentTotal = atomic_load(&_totalLookupTime);
  atomic_store(&_totalLookupTime, currentTotal + lookupTime);

  // Update min/max
  double currentMin = atomic_load(&_minLookupTime);
  if (lookupTime < currentMin) {
    atomic_store(&_minLookupTime, lookupTime);
  }

  double currentMax = atomic_load(&_maxLookupTime);
  if (lookupTime > currentMax) {
    atomic_store(&_maxLookupTime, lookupTime);
  }

  // Count slow queries (> 10ms)
  if (lookupTime > 0.010) {
    atomic_fetch_add(&_slowQueries, 1);
    os_log_info(logHandle, "Slow query detected: %.3f ms", lookupTime * 1000);
  }

  // Track recent query times for QPS calculation
  dispatch_async(self.statsQueue, ^{
    [self.recentQueryTimes addObject:@([[NSDate date] timeIntervalSince1970])];

    // Keep only last 5 seconds of data
    NSTimeInterval cutoff = [[NSDate date] timeIntervalSince1970] - 5.0;
    while (self.recentQueryTimes.count > 0 &&
           [self.recentQueryTimes.firstObject doubleValue] < cutoff) {
      [self.recentQueryTimes removeObjectAtIndex:0];
    }
  });
}

- (void)calculateQPS {
  dispatch_async(self.statsQueue, ^{
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval cutoff = now - 1.0;  // Last second

    NSUInteger count = 0;
    for (NSNumber* timestamp in self.recentQueryTimes) {
      if ([timestamp doubleValue] >= cutoff) {
        count++;
      }
    }

    self.currentQPS = count;
  });
}

#pragma mark - Properties

- (NSUInteger)hits {
  return atomic_load(&_hitCount);
}

- (NSUInteger)misses {
  return atomic_load(&_missCount);
}

- (double)hitRate {
  NSUInteger h = atomic_load(&_hitCount);
  NSUInteger m = atomic_load(&_missCount);
  NSUInteger total = h + m;
  return (total > 0) ? (double)h / (double)total : 0.0;
}

- (NSTimeInterval)avgLookupTime {
  NSUInteger count = atomic_load(&_lookupCount);
  if (count == 0)
    return 0.0;

  double total = atomic_load(&_totalLookupTime);
  return total / (double)count;
}

- (NSUInteger)queriesPerSecond {
  return self.currentQPS;
}

- (NSDate*)lastReset {
  return self.startTime;
}

- (NSTimeInterval)uptime {
  return [[NSDate date] timeIntervalSinceDate:self.startTime];
}

- (NSTimeInterval)fastestLookup {
  double min = atomic_load(&_minLookupTime);
  return (min == DBL_MAX) ? 0.0 : min;
}

- (NSTimeInterval)slowestLookup {
  return atomic_load(&_maxLookupTime);
}

- (NSUInteger)slowQueryCount {
  return atomic_load(&_slowQueries);
}

- (NSDictionary*)snapshot {
  return @{
    @"hits" : @(self.hits),
    @"misses" : @(self.misses),
    @"hitRate" : @(self.hitRate),
    @"avgLookupTime" : @(self.avgLookupTime * 1000),  // Convert to ms
    @"queriesPerSecond" : @(self.queriesPerSecond),
    @"uptime" : @(self.uptime),
    @"fastestLookup" : @(self.fastestLookup * 1000),  // Convert to ms
    @"slowestLookup" : @(self.slowestLookup * 1000),  // Convert to ms
    @"slowQueryCount" : @(self.slowQueryCount),
    @"totalQueries" : @(self.hits + self.misses)
  };
}

@end
