//
//  RuleCache.m
//  DNShield Network Extension
//
//  Implementation of the two-tier rule cache system
//

#import "RuleCache.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <objc/runtime.h>
#import "ConfigurationManager.h"
#import "DiskCache.h"
#import "MemoryCache.h"

// Notifications
NSString* const RuleCacheDidUpdateNotification = @"RuleCacheDidUpdateNotification";
NSString* const RuleCacheDidEvictNotification = @"RuleCacheDidEvictNotification";
NSString* const RuleCacheSourceIDKey = @"sourceID";

@interface CacheStatistics ()
@property(nonatomic, assign) NSUInteger memoryCacheHits;
@property(nonatomic, assign) NSUInteger memoryCacheMisses;
@property(nonatomic, assign) NSUInteger diskCacheHits;
@property(nonatomic, assign) NSUInteger diskCacheMisses;
@property(nonatomic, assign) NSUInteger totalRequests;
@property(nonatomic, assign) NSUInteger currentMemoryUsage;
@property(nonatomic, assign) NSUInteger currentDiskUsage;
@property(nonatomic, strong) NSMutableArray<NSNumber*>* loadTimes;
@end

@implementation CacheStatistics

- (instancetype)init {
  self = [super init];
  if (self) {
    _loadTimes = [NSMutableArray array];
  }
  return self;
}

- (double)hitRate {
  if (self.totalRequests == 0)
    return 0.0;
  NSUInteger hits = self.memoryCacheHits + self.diskCacheHits;
  return (double)hits / (double)self.totalRequests;
}

- (NSTimeInterval)averageLoadTime {
  if (self.loadTimes.count == 0)
    return 0.0;

  double sum = 0;
  for (NSNumber* time in self.loadTimes) {
    sum += [time doubleValue];
  }
  return sum / self.loadTimes.count;
}

- (void)recordLoadTime:(NSTimeInterval)time {
  [self.loadTimes addObject:@(time)];

  // Keep only last 100 load times
  if (self.loadTimes.count > 100) {
    [self.loadTimes removeObjectAtIndex:0];
  }
}

- (void)reset {
  self.memoryCacheHits = 0;
  self.memoryCacheMisses = 0;
  self.diskCacheHits = 0;
  self.diskCacheMisses = 0;
  self.totalRequests = 0;
  [self.loadTimes removeAllObjects];
}

@end

@interface RuleCache ()
@property(nonatomic, strong) MemoryCache* memoryCache;
@property(nonatomic, strong) DiskCache* diskCache;
@property(nonatomic, strong) CacheConfiguration* configuration;
@property(nonatomic, strong) dispatch_queue_t cacheQueue;
@property(nonatomic, strong) NSTimer* cleanupTimer;
@property(nonatomic, strong) CacheStatistics* statistics;
@end

@implementation RuleCache

- (instancetype)initWithConfiguration:(CacheConfiguration*)configuration {
  self = [super init];
  if (self) {
    _configuration = [configuration copy] ?: [CacheConfiguration defaultCacheConfiguration];
    _cacheQueue = dispatch_queue_create("com.dnshield.rulecache", DISPATCH_QUEUE_CONCURRENT);
    _statistics = [[CacheStatistics alloc] init];

    [self setupCaches];
    [self startCleanupTimer];

    DNSLogInfo(LogCategoryCache,
               "RuleCache initialized with memory limit: %lu MB, disk limit: %lu MB",
               (unsigned long)(_configuration.maxMemoryCacheSize / (1024 * 1024)),
               (unsigned long)(_configuration.maxCacheSize / (1024 * 1024)));
  }
  return self;
}

- (void)dealloc {
  [self.cleanupTimer invalidate];
}

- (void)setupCaches {
  // Initialize memory cache
  self.memoryCache = [[MemoryCache alloc] initWithMaxSize:self.configuration.maxMemoryCacheSize];

  // Initialize disk cache
  self.diskCache = [[DiskCache alloc] initWithDirectory:self.configuration.cacheDirectory
                                                maxSize:self.configuration.maxCacheSize];
}

- (void)startCleanupTimer {
  if (self.configuration.cleanupInterval > 0) {
    self.cleanupTimer = [NSTimer scheduledTimerWithTimeInterval:self.configuration.cleanupInterval
                                                         target:self
                                                       selector:@selector(invalidateExpiredEntries)
                                                       userInfo:nil
                                                        repeats:YES];
  }
}

#pragma mark - Store Operations

- (void)storeRuleSet:(RuleSet*)ruleSet
           forSource:(NSString*)sourceID
          timeToLive:(NSTimeInterval)ttl {
  if (!ruleSet || !sourceID) {
    DNSLogError(LogCategoryCache, "Cannot store nil ruleSet or sourceID");
    return;
  }

  DNSLogPerformanceStart(@"cache.store");

  dispatch_barrier_async(self.cacheQueue, ^{
    CacheEntry* entry = [[CacheEntry alloc] initWithRuleSet:ruleSet
                                                  fetchDate:[NSDate date]
                                                 timeToLive:ttl
                                           sourceIdentifier:sourceID];

    // Store in memory cache
    [self.memoryCache setObject:entry forKey:sourceID];

    // Store in disk cache if persistence is enabled
    if (self.configuration.persistCache) {
      NSError* error = nil;
      [self.diskCache storeEntry:entry forKey:sourceID error:&error];

      if (error) {
        DNSLogError(LogCategoryCache, "Failed to store in disk cache: %@", error);
      }
    }

    // Update statistics
    self.statistics.currentMemoryUsage = [self.memoryCache currentSize];
    self.statistics.currentDiskUsage = [self.diskCache currentSize];

    DNSLogPerformanceEnd(@"cache.store");
    DNSLogInfo(LogCategoryCache, "Stored rule set for source: %@, TTL: %.0f seconds", sourceID,
               ttl);

    // Post notification
    [[NSNotificationCenter defaultCenter] postNotificationName:RuleCacheDidUpdateNotification
                                                        object:self
                                                      userInfo:@{RuleCacheSourceIDKey : sourceID}];
  });
}

- (void)storeRuleSet:(RuleSet*)ruleSet forSource:(NSString*)sourceID {
  [self storeRuleSet:ruleSet forSource:sourceID timeToLive:self.configuration.defaultTTL];
}

#pragma mark - Retrieve Operations

- (nullable RuleSet*)ruleSetForSource:(NSString*)sourceID maxAge:(NSTimeInterval)maxAge {
  if (!sourceID)
    return nil;

  __block RuleSet* ruleSet = nil;
  NSDate* startTime = [NSDate date];

  dispatch_sync(self.cacheQueue, ^{
    self.statistics.totalRequests++;

    // Check memory cache first
    CacheEntry* entry = [self.memoryCache objectForKey:sourceID];

    if (entry && ![entry isExpired] &&
        [entry timeUntilExpiration] > (self.configuration.defaultTTL - maxAge)) {
      self.statistics.memoryCacheHits++;
      ruleSet = entry.ruleSet;
      DNSLogDebug(LogCategoryCache, "Memory cache hit for source: %@", sourceID);
    } else {
      self.statistics.memoryCacheMisses++;

      // Check disk cache
      if (self.configuration.persistCache) {
        NSError* error = nil;
        entry = [self.diskCache entryForKey:sourceID error:&error];

        if (entry && ![entry isExpired] &&
            [entry timeUntilExpiration] > (self.configuration.defaultTTL - maxAge)) {
          self.statistics.diskCacheHits++;
          ruleSet = entry.ruleSet;

          // Promote to memory cache
          [self.memoryCache setObject:entry forKey:sourceID];
          DNSLogDebug(LogCategoryCache, "Disk cache hit for source: %@", sourceID);
        } else {
          self.statistics.diskCacheMisses++;
          DNSLogDebug(LogCategoryCache, "Cache miss for source: %@", sourceID);
        }

        if (error) {
          DNSLogError(LogCategoryCache, "Disk cache error: %@", error);
        }
      }
    }
  });

  NSTimeInterval loadTime = -[startTime timeIntervalSinceNow];
  [self.statistics recordLoadTime:loadTime];

  return ruleSet;
}

- (nullable RuleSet*)ruleSetForSource:(NSString*)sourceID {
  return [self ruleSetForSource:sourceID maxAge:DBL_MAX];
}

- (void)ruleSetForSource:(NSString*)sourceID
                  maxAge:(NSTimeInterval)maxAge
              completion:(void (^)(RuleSet* _Nullable ruleSet))completion {
  dispatch_async(self.cacheQueue, ^{
    RuleSet* ruleSet = [self ruleSetForSource:sourceID maxAge:maxAge];
    if (completion) {
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(ruleSet);
      });
    }
  });
}

#pragma mark - Cache Management

- (void)invalidateCacheForSource:(NSString*)sourceID {
  if (!sourceID)
    return;

  dispatch_barrier_async(self.cacheQueue, ^{
    [self.memoryCache removeObjectForKey:sourceID];

    if (self.configuration.persistCache) {
      NSError* error = nil;
      [self.diskCache removeEntryForKey:sourceID error:&error];
      if (error) {
        DNSLogError(LogCategoryCache, "Failed to remove from disk cache: %@", error);
      }
    }

    DNSLogInfo(LogCategoryCache, "Invalidated cache for source: %@", sourceID);

    [[NSNotificationCenter defaultCenter] postNotificationName:RuleCacheDidEvictNotification
                                                        object:self
                                                      userInfo:@{RuleCacheSourceIDKey : sourceID}];
  });
}

- (void)invalidateExpiredEntries {
  dispatch_barrier_async(self.cacheQueue, ^{
    DNSLogDebug(LogCategoryCache, "Running cache cleanup...");

    NSUInteger removedFromMemory = [self.memoryCache removeExpiredEntries];
    NSUInteger removedFromDisk = 0;

    if (self.configuration.persistCache) {
      NSError* error = nil;
      removedFromDisk = [self.diskCache removeExpiredEntriesWithError:&error];
      if (error) {
        DNSLogError(LogCategoryCache, "Failed to clean disk cache: %@", error);
      }
    }

    if (removedFromMemory > 0 || removedFromDisk > 0) {
      DNSLogInfo(LogCategoryCache, "Cache cleanup removed %lu from memory, %lu from disk",
                 (unsigned long)removedFromMemory, (unsigned long)removedFromDisk);
    }

    // Update statistics
    self.statistics.currentMemoryUsage = [self.memoryCache currentSize];
    self.statistics.currentDiskUsage = [self.diskCache currentSize];
  });
}

- (void)clearMemoryCache {
  dispatch_barrier_async(self.cacheQueue, ^{
    [self.memoryCache removeAllObjects];
    self.statistics.currentMemoryUsage = 0;
    DNSLogInfo(LogCategoryCache, "Memory cache cleared");
  });
}

- (void)clearDiskCache {
  if (!self.configuration.persistCache)
    return;

  dispatch_barrier_async(self.cacheQueue, ^{
    NSError* error = nil;
    [self.diskCache removeAllEntriesWithError:&error];
    if (error) {
      DNSLogError(LogCategoryCache, "Failed to clear disk cache: %@", error);
    } else {
      self.statistics.currentDiskUsage = 0;
      DNSLogInfo(LogCategoryCache, "Disk cache cleared");
    }
  });
}

- (void)clearAllCaches {
  [self clearMemoryCache];
  [self clearDiskCache];
  [self.statistics reset];
}

#pragma mark - Preloading

- (void)preloadSource:(NSString*)sourceID {
  if (!sourceID || !self.configuration.persistCache)
    return;

  dispatch_async(self.cacheQueue, ^{
    NSError* error = nil;
    CacheEntry* entry = [self.diskCache entryForKey:sourceID error:&error];

    if (entry && ![entry isExpired]) {
      [self.memoryCache setObject:entry forKey:sourceID];
      DNSLogDebug(LogCategoryCache, "Preloaded source: %@", sourceID);
    }
  });
}

- (void)preloadAllSources {
  if (!self.configuration.persistCache)
    return;

  dispatch_async(self.cacheQueue, ^{
    NSError* error = nil;
    NSArray<NSString*>* allKeys = [self.diskCache allKeysWithError:&error];

    if (error) {
      DNSLogError(LogCategoryCache, "Failed to get disk cache keys: %@", error);
      return;
    }

    for (NSString* key in allKeys) {
      [self preloadSource:key];
    }

    DNSLogInfo(LogCategoryCache, "Preloaded %lu sources", (unsigned long)allKeys.count);
  });
}

#pragma mark - Size Management

- (NSUInteger)currentMemoryCacheSize {
  return [self.memoryCache currentSize];
}

- (NSUInteger)currentDiskCacheSize {
  return self.configuration.persistCache ? [self.diskCache currentSize] : 0;
}

- (NSUInteger)totalCacheSize {
  return [self currentMemoryCacheSize] + [self currentDiskCacheSize];
}

#pragma mark - Persistence

- (void)synchronize {
  if (!self.configuration.persistCache)
    return;

  dispatch_barrier_async(self.cacheQueue, ^{
    NSError* error = nil;
    [self.diskCache synchronizeWithError:&error];
    if (error) {
      DNSLogError(LogCategoryCache, "Failed to synchronize disk cache: %@", error);
    }
  });
}

#pragma mark - Testing Support

- (void)injectTestRuleSet:(RuleSet*)ruleSet
                forSource:(NSString*)sourceID
               timeToLive:(NSTimeInterval)ttl {
  // Direct injection for testing, bypasses some validation
  CacheEntry* entry = [[CacheEntry alloc] initWithRuleSet:ruleSet
                                                fetchDate:[NSDate date]
                                               timeToLive:ttl
                                         sourceIdentifier:sourceID];

  [self.memoryCache setObject:entry forKey:sourceID];
  DNSLogDebug(LogCategoryCache, "Injected test rule set for source: %@", sourceID);
}

@end

#pragma mark - CacheEntry Implementation

@implementation CacheEntry

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)initWithRuleSet:(RuleSet*)ruleSet
                      fetchDate:(NSDate*)fetchDate
                     timeToLive:(NSTimeInterval)ttl
               sourceIdentifier:(NSString*)sourceId {
  self = [super init];
  if (self) {
    _ruleSet = ruleSet;
    _fetchDate = fetchDate ?: [NSDate date];
    _timeToLive = ttl;
    _sourceIdentifier = sourceId;
    _dataSize = class_getInstanceSize([CacheEntry class]);  // Simplified size calculation
  }
  return self;
}

- (BOOL)isExpired {
  if (self.timeToLive <= 0) {
    return NO;  // No expiration
  }

  NSTimeInterval age = -[self.fetchDate timeIntervalSinceNow];
  return age > self.timeToLive;
}

- (NSTimeInterval)timeUntilExpiration {
  if (self.timeToLive <= 0) {
    return DBL_MAX;  // Never expires
  }

  NSTimeInterval age = -[self.fetchDate timeIntervalSinceNow];
  NSTimeInterval remaining = self.timeToLive - age;
  return MAX(0, remaining);
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.ruleSet forKey:@"ruleSet"];
  [coder encodeObject:self.fetchDate forKey:@"fetchDate"];
  [coder encodeDouble:self.timeToLive forKey:@"timeToLive"];
  [coder encodeObject:self.sourceIdentifier forKey:@"sourceIdentifier"];
  [coder encodeInteger:self.dataSize forKey:@"dataSize"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _ruleSet = [coder decodeObjectOfClass:[RuleSet class] forKey:@"ruleSet"];
    _fetchDate = [coder decodeObjectOfClass:[NSDate class] forKey:@"fetchDate"];
    _timeToLive = [coder decodeDoubleForKey:@"timeToLive"];
    _sourceIdentifier = [coder decodeObjectOfClass:[NSString class] forKey:@"sourceIdentifier"];
    _dataSize = [coder decodeIntegerForKey:@"dataSize"];
  }
  return self;
}

@end
