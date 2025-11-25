//
//  DNSCache.m
//  DNShield Network Extension
//
//  TTL-aware DNS response cache implementation
//

#import "DNSCache.h"
#import <os/log.h>
#import "DNSPacket.h"

extern os_log_t logHandle;

// Constants
static const NSUInteger kDefaultMaxCacheSize = 10000;
static const NSTimeInterval kMinTTL = 30;   // 30 seconds minimum (reduced from 60)
static const NSTimeInterval kMaxTTL = 300;  // 5 minutes maximum (reduced from 24 hours)

@implementation DNSCacheEntry
@end

@interface DNSCache () <NSCacheDelegate>
@property(nonatomic, strong) NSCache* cache;
@property(nonatomic, strong) NSMutableDictionary<NSString*, NSDate*>* expiryDates;
@property(nonatomic, strong) dispatch_queue_t cacheQueue;
@property(nonatomic, assign) NSUInteger hitCountInternal;
@property(nonatomic, assign) NSUInteger missCountInternal;
@property(nonatomic, assign) NSUInteger evictionCountInternal;
@property(nonatomic, strong) NSTimer* cleanupTimer;
@end

@implementation DNSCache

- (instancetype)init {
  return [self initWithMaxSize:kDefaultMaxCacheSize];
}

- (instancetype)initWithMaxSize:(NSUInteger)maxSize {
  self = [super init];
  if (self) {
    _cache = [[NSCache alloc] init];
    _cache.countLimit = maxSize;
    _cache.delegate = self;

    _expiryDates = [NSMutableDictionary new];
    _cacheQueue = dispatch_queue_create("com.dnshield.dnscache", DISPATCH_QUEUE_SERIAL);
    _hitCountInternal = 0;
    _missCountInternal = 0;
    _evictionCountInternal = 0;

    // Set up periodic cleanup timer (every 5 minutes)
    _cleanupTimer = [NSTimer scheduledTimerWithTimeInterval:300.0
                                                     target:self
                                                   selector:@selector(removeExpiredEntries)
                                                   userInfo:nil
                                                    repeats:YES];

    // Monitor memory pressure on macOS
    dispatch_source_t memoryPressureSource =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
                               DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL,
                               dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));

    dispatch_source_set_event_handler(memoryPressureSource, ^{
      [self handleMemoryWarning:nil];
    });

    dispatch_resume(memoryPressureSource);
  }
  return self;
}

- (void)dealloc {
  [_cleanupTimer invalidate];
}

#pragma mark - Cache Operations

- (void)cacheResponse:(NSData*)response
            forDomain:(NSString*)domain
            queryType:(uint16_t)queryType
                  ttl:(uint32_t)ttl {
  if (!response || !domain) {
    return;
  }

  dispatch_async(self.cacheQueue, ^{
    // Create cache key
    NSString* cacheKey = [self cacheKeyForDomain:domain queryType:queryType];

    // Clamp TTL to reasonable bounds
    NSTimeInterval actualTTL = ttl;
    if (actualTTL < kMinTTL)
      actualTTL = kMinTTL;
    if (actualTTL > kMaxTTL)
      actualTTL = kMaxTTL;

    // Create cache entry
    DNSCacheEntry* entry = [[DNSCacheEntry alloc] init];
    entry.response = response;
    entry.originalTTL = ttl;
    entry.expiryDate = [NSDate dateWithTimeIntervalSinceNow:actualTTL];

    // Store in cache
    [self.cache setObject:entry forKey:cacheKey];
    self.expiryDates[cacheKey] = entry.expiryDate;

    os_log_debug(logHandle, "Cached response for %{public}@ (type %d) with TTL %d", domain,
                 queryType, (int)actualTTL);
  });
}

- (nullable NSData*)getCachedResponseForDomain:(NSString*)domain queryType:(uint16_t)queryType {
  if (!domain) {
    return nil;
  }

  __block NSData* response = nil;

  dispatch_sync(self.cacheQueue, ^{
    NSString* cacheKey = [self cacheKeyForDomain:domain queryType:queryType];
    DNSCacheEntry* entry = [self.cache objectForKey:cacheKey];

    if (entry) {
      // Check if still valid
      if ([entry.expiryDate timeIntervalSinceNow] > 0) {
        response = entry.response;
        self.hitCountInternal++;

        // Update TTL in response
        response = [self updateTTLInResponse:entry.response
                                 originalTTL:entry.originalTTL
                                  expiryDate:entry.expiryDate];

        os_log_debug(logHandle, "Cache hit for %{public}@ (type %d)", domain, queryType);
      } else {
        // Expired, remove it
        [self.cache removeObjectForKey:cacheKey];
        [self.expiryDates removeObjectForKey:cacheKey];
        self.missCountInternal++;
        os_log_debug(logHandle, "Cache miss (expired) for %{public}@ (type %d)", domain, queryType);
      }
    } else {
      self.missCountInternal++;
      os_log_debug(logHandle, "Cache miss for %{public}@ (type %d)", domain, queryType);
    }
  });

  return response;
}

#pragma mark - Cache Management

- (void)clearCache {
  dispatch_async(self.cacheQueue, ^{
    [self.cache removeAllObjects];
    [self.expiryDates removeAllObjects];
    self.hitCountInternal = 0;
    self.missCountInternal = 0;
    os_log_info(logHandle, "DNS cache cleared");
  });
}

- (void)removeExpiredEntries {
  dispatch_async(self.cacheQueue, ^{
    NSDate* now = [NSDate date];
    NSMutableArray* expiredKeys = [NSMutableArray new];

    for (NSString* key in self.expiryDates) {
      NSDate* expiryDate = self.expiryDates[key];
      if ([expiryDate compare:now] == NSOrderedAscending) {
        [expiredKeys addObject:key];
      }
    }

    for (NSString* key in expiredKeys) {
      [self.cache removeObjectForKey:key];
      [self.expiryDates removeObjectForKey:key];
    }

    if (expiredKeys.count > 0) {
      os_log_debug(logHandle, "Removed %lu expired cache entries",
                   (unsigned long)expiredKeys.count);
    }
  });
}

- (void)handleMemoryWarning:(NSNotification*)notification {
  os_log_info(logHandle, "Memory warning received, reducing cache size");
  dispatch_async(self.cacheQueue, ^{
    // Remove 25% of cache entries
    NSUInteger targetSize = self.cache.countLimit * 0.75;
    self.cache.countLimit = targetSize;
  });
}

#pragma mark - Helper Methods

- (NSString*)cacheKeyForDomain:(NSString*)domain queryType:(uint16_t)queryType {
  return [NSString stringWithFormat:@"%@:%hu", [domain lowercaseString], queryType];
}

- (NSData*)updateTTLInResponse:(NSData*)response
                   originalTTL:(uint32_t)originalTTL
                    expiryDate:(NSDate*)expiryDate {
  // Calculate remaining TTL
  NSTimeInterval remainingTime = [expiryDate timeIntervalSinceNow];
  if (remainingTime <= 0) {
    return response;  // Expired
  }

  // Update the TTL fields in the response
  uint32_t newTTL = (uint32_t)remainingTime;
  NSData* updatedResponse = [DNSPacket updateTTLInResponse:response newTTL:newTTL];

  if (updatedResponse) {
    os_log_debug(logHandle, "Updated TTL from %u to %u for cached response", originalTTL, newTTL);
    return updatedResponse;
  }

  // Fall back to original response if update fails
  return response;
}

#pragma mark - NSCacheDelegate

- (void)cache:(NSCache*)cache willEvictObject:(id)obj {
  // Track evictions
  dispatch_async(self.cacheQueue, ^{
    self.evictionCountInternal++;

    // Clean up expiry dates when object is evicted
    for (NSString* key in self.expiryDates.allKeys) {
      if ([self.cache objectForKey:key] == nil) {
        [self.expiryDates removeObjectForKey:key];
      }
    }

    os_log_debug(logHandle, "DNS cache evicted entry, total evictions: %lu",
                 (unsigned long)self.evictionCountInternal);
  });
}

#pragma mark - Properties

- (NSUInteger)cacheSize {
  __block NSUInteger size = 0;
  dispatch_sync(self.cacheQueue, ^{
    size = self.expiryDates.count;
  });
  return size;
}

- (NSUInteger)hitCount {
  __block NSUInteger count = 0;
  dispatch_sync(self.cacheQueue, ^{
    count = self.hitCountInternal;
  });
  return count;
}

- (NSUInteger)missCount {
  __block NSUInteger count = 0;
  dispatch_sync(self.cacheQueue, ^{
    count = self.missCountInternal;
  });
  return count;
}

- (NSUInteger)evictionCount {
  __block NSUInteger count = 0;
  dispatch_sync(self.cacheQueue, ^{
    count = self.evictionCountInternal;
  });
  return count;
}

- (double)hitRate {
  __block double rate = 0.0;
  dispatch_sync(self.cacheQueue, ^{
    NSUInteger total = self.hitCountInternal + self.missCountInternal;
    if (total > 0) {
      rate = (double)self.hitCountInternal / (double)total;
    }
  });
  return rate;
}

@end
