//
//  DNSRuleCache.m
//  DNShield Network Extension
//
//  Simple LRU cache for DNS rule lookups
//

#import <os/log.h>
#import <stdatomic.h>

#import <Rule/Cache.h>

static os_log_t logHandle;

@implementation DNSRuleCacheEntry
@end

@interface DNSRuleCache () <NSCacheDelegate> {
  NSUInteger _maxEntries;
}
@property(nonatomic, strong) NSCache* cache;
@property(nonatomic, strong) NSMutableOrderedSet* lruOrder;
@property(nonatomic, strong) dispatch_queue_t cacheQueue;
@property(nonatomic, assign) _Atomic(NSUInteger) hitCount;
@property(nonatomic, assign) _Atomic(NSUInteger) missCount;
@property(nonatomic, assign) _Atomic(NSUInteger) evictionCount;
@end

@implementation DNSRuleCache

+ (void)initialize {
  if (self == [DNSRuleCache class]) {
    logHandle = os_log_create("com.dnshield.extension", "RuleCache");
  }
}

+ (instancetype)sharedCache {
  static DNSRuleCache* sharedCache = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedCache = [[DNSRuleCache alloc] init];
  });
  return sharedCache;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _cache = [[NSCache alloc] init];
    _cache.countLimit = 10000;  // Default max entries
    _cache.delegate = (id<NSCacheDelegate>)self;

    _lruOrder = [NSMutableOrderedSet orderedSet];
    _cacheQueue = dispatch_queue_create("com.dnshield.rulecache", DISPATCH_QUEUE_CONCURRENT);

    // Set queue-specific context to detect when we're on this queue
    dispatch_queue_set_specific(_cacheQueue, "com.dnshield.rulecache.queue", (void*)1, NULL);

    _maxEntries = 10000;
    _ttl = 300;  // 5 minutes default
    _hitCount = 0;
    _missCount = 0;
    _evictionCount = 0;

    os_log_info(logHandle, "Rule cache initialized with max entries: %lu, TTL: %.0f seconds",
                (unsigned long)_maxEntries, _ttl);
  }
  return self;
}

#pragma mark - Cache Operations

- (nullable DNSRuleCacheEntry*)entryForDomain:(NSString*)domain {
  __block DNSRuleCacheEntry* entry = nil;

  dispatch_sync(self.cacheQueue, ^{
    entry = [self.cache objectForKey:domain];

    if (entry) {
      // Check if entry has expired using its specific TTL
      NSTimeInterval age = [[NSDate date] timeIntervalSinceDate:entry.timestamp];
      NSTimeInterval effectiveTTL = (entry.ttl > 0) ? entry.ttl : self.ttl;

      if (age > effectiveTTL) {
        // Entry expired, remove it
        [self.cache removeObjectForKey:domain];
        [self.lruOrder removeObject:domain];
        entry = nil;
        atomic_fetch_add(&_missCount, 1);
        os_log_debug(logHandle, "Cache miss (expired) for domain: %{public}@", domain);
      } else {
        // Valid hit, update LRU order
        [self.lruOrder removeObject:domain];
        [self.lruOrder addObject:domain];
        atomic_fetch_add(&_hitCount, 1);
        os_log_debug(logHandle, "Cache hit for domain: %{public}@", domain);
      }
    } else {
      atomic_fetch_add(&_missCount, 1);
      os_log_debug(logHandle, "Cache miss for domain: %{public}@", domain);
    }
  });

  return entry;
}

- (DNSRuleAction)actionForDomain:(NSString*)domain {
  DNSRuleCacheEntry* entry = [self entryForDomain:domain];
  if (entry && entry.hasRule) {
    return entry.action;
  }
  return DNSRuleActionUnknown;
}

- (void)setAction:(DNSRuleAction)action forDomain:(NSString*)domain {
  [self setAction:action forDomain:domain withTTL:0];  // Use default TTL
}

- (void)setAction:(DNSRuleAction)action forDomain:(NSString*)domain withTTL:(NSTimeInterval)ttl {
  DNSRuleCacheEntry* entry = [[DNSRuleCacheEntry alloc] init];
  entry.action = action;
  entry.ttl = ttl;  // Store custom TTL
  entry.hasRule = YES;
  entry.timestamp = [NSDate date];

  dispatch_barrier_async(self.cacheQueue, ^{
    [self.cache setObject:entry forKey:domain];

    // Update LRU order
    [self.lruOrder removeObject:domain];
    [self.lruOrder addObject:domain];

    // Enforce max entries limit
    while (self.lruOrder.count > self->_maxEntries) {
      NSString* oldestDomain = self.lruOrder.firstObject;
      [self.lruOrder removeObjectAtIndex:0];
      [self.cache removeObjectForKey:oldestDomain];
    }

    os_log_debug(logHandle, "Cached action %ld for domain: %{public}@", (long)action, domain);
  });
}

- (void)setNoRuleForDomain:(NSString*)domain {
  DNSRuleCacheEntry* entry = [[DNSRuleCacheEntry alloc] init];
  entry.hasRule = NO;
  entry.timestamp = [NSDate date];

  dispatch_barrier_async(self.cacheQueue, ^{
    [self.cache setObject:entry forKey:domain];

    // Update LRU order
    [self.lruOrder removeObject:domain];
    [self.lruOrder addObject:domain];

    // Enforce max entries limit
    while (self.lruOrder.count > self->_maxEntries) {
      NSString* oldestDomain = self.lruOrder.firstObject;
      [self.lruOrder removeObjectAtIndex:0];
      [self.cache removeObjectForKey:oldestDomain];
    }

    os_log_debug(logHandle, "Cached no-rule for domain: %{public}@", domain);
  });
}

- (void)removeDomain:(NSString*)domain {
  dispatch_barrier_async(self.cacheQueue, ^{
    [self.cache removeObjectForKey:domain];
    [self.lruOrder removeObject:domain];
    os_log_debug(logHandle, "Removed cache entry for domain: %{public}@", domain);
  });
}

- (void)clear {
  dispatch_barrier_async(self.cacheQueue, ^{
    [self.cache removeAllObjects];
    [self.lruOrder removeAllObjects];
    os_log_info(logHandle, "Cache cleared");
  });
}

#pragma mark - Properties

- (NSUInteger)maxEntries {
  // Use dispatch_get_specific to check if we're on the cache queue
  // This avoids deadlock when called from within a block on cacheQueue
  if (dispatch_get_specific("com.dnshield.rulecache.queue") != NULL) {
    return _maxEntries;
  }

  __block NSUInteger entries;
  dispatch_sync(self.cacheQueue, ^{
    entries = _maxEntries;
  });
  return entries;
}

- (void)setMaxEntries:(NSUInteger)maxEntries {
  dispatch_barrier_async(self.cacheQueue, ^{
    self->_maxEntries = maxEntries;
    self.cache.countLimit = maxEntries;

    // Remove excess entries if needed
    while (self.lruOrder.count > maxEntries) {
      NSString* oldestDomain = self.lruOrder.firstObject;
      [self.lruOrder removeObjectAtIndex:0];
      [self.cache removeObjectForKey:oldestDomain];
    }

    os_log_info(logHandle, "Cache max entries updated to: %lu", (unsigned long)maxEntries);
  });
}

- (NSUInteger)entryCount {
  __block NSUInteger count = 0;
  dispatch_sync(self.cacheQueue, ^{
    count = self.lruOrder.count;
  });
  return count;
}

- (NSUInteger)hitCount {
  return atomic_load(&_hitCount);
}

- (NSUInteger)missCount {
  return atomic_load(&_missCount);
}

- (NSUInteger)evictionCount {
  return atomic_load(&_evictionCount);
}

- (NSUInteger)currentSize {
  return [self entryCount];
}

- (double)hitRate {
  NSUInteger hits = atomic_load(&_hitCount);
  NSUInteger misses = atomic_load(&_missCount);
  NSUInteger total = hits + misses;

  if (total == 0)
    return 0.0;
  return (double)hits / (double)total;
}

- (void)resetStatistics {
  atomic_store(&_hitCount, 0);
  atomic_store(&_missCount, 0);
  atomic_store(&_evictionCount, 0);
  os_log_info(logHandle, "Cache statistics reset");
}

#pragma mark - NSCacheDelegate

- (void)cache:(NSCache*)cache willEvictObject:(id)obj {
  // This is called when NSCache evicts objects due to memory pressure
  // We don't need to update lruOrder here as it's handled in our own logic
  atomic_fetch_add(&_evictionCount, 1);
  os_log_debug(logHandle, "Cache will evict object due to memory pressure, total evictions: %lu",
               (unsigned long)atomic_load(&_evictionCount));
}

@end
