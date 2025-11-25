//
//  MemoryCache.m
//  DNShield Network Extension
//
//  Implementation of fast in-memory cache
//

#import "MemoryCache.h"
#import <Common/LoggingManager.h>
#import <objc/runtime.h>

@interface MemoryCacheWrapper : NSObject
@property(nonatomic, strong) CacheEntry* entry;
@property(nonatomic, assign) NSUInteger cost;
@end

@implementation MemoryCacheWrapper
@end

@interface MemoryCache () <NSCacheDelegate>
@property(nonatomic, strong) NSCache<NSString*, MemoryCacheWrapper*>* cache;
@property(nonatomic, strong) NSMutableDictionary<NSString*, NSDate*>* accessTimes;
@property(nonatomic, strong) dispatch_queue_t accessQueue;
@property(nonatomic, assign) NSUInteger maxSize;
@property(atomic, assign) NSUInteger currentSize;
@end

@implementation MemoryCache

- (instancetype)initWithMaxSize:(NSUInteger)maxSize {
  self = [super init];
  if (self) {
    _maxSize = maxSize;
    _currentSize = 0;
    _accessQueue = dispatch_queue_create("com.dnshield.memorycache", DISPATCH_QUEUE_CONCURRENT);
    _accessTimes = [NSMutableDictionary dictionary];

    [self setupCache];
  }
  return self;
}

- (void)setupCache {
  self.cache = [[NSCache alloc] init];
  self.cache.delegate = self;
  self.cache.totalCostLimit = self.maxSize;
  self.cache.countLimit = 0;  // No count limit, only size limit
}

#pragma mark - Cache Operations

- (void)setObject:(CacheEntry*)entry forKey:(NSString*)key {
  if (!entry || !key)
    return;

  dispatch_barrier_async(self.accessQueue, ^{
    // Calculate cost (size)
    NSUInteger cost = entry.dataSize;
    if (cost == 0) {
      // Estimate if not provided
      cost = [self estimateSizeForEntry:entry];
    }

    // Wrap entry with cost
    MemoryCacheWrapper* wrapper = [[MemoryCacheWrapper alloc] init];
    wrapper.entry = entry;
    wrapper.cost = cost;

    // Remove old entry if exists
    MemoryCacheWrapper* oldWrapper = [self.cache objectForKey:key];
    if (oldWrapper) {
      self.currentSize -= oldWrapper.cost;
    }

    // Add new entry
    [self.cache setObject:wrapper forKey:key cost:cost];
    self.currentSize += cost;
    self.accessTimes[key] = [NSDate date];

    DNSLogDebug(LogCategoryCache, "Memory cache stored: %@, size: %lu bytes", key,
                (unsigned long)cost);
  });
}

- (nullable CacheEntry*)objectForKey:(NSString*)key {
  if (!key)
    return nil;

  __block CacheEntry* entry = nil;

  dispatch_sync(self.accessQueue, ^{
    MemoryCacheWrapper* wrapper = [self.cache objectForKey:key];
    if (wrapper) {
      entry = wrapper.entry;

      // Check if expired
      if ([entry isExpired]) {
        [self.cache removeObjectForKey:key];
        [self.accessTimes removeObjectForKey:key];
        self.currentSize -= wrapper.cost;
        entry = nil;
        DNSLogDebug(LogCategoryCache, "Memory cache entry expired: %@", key);
      } else {
        // Update access time
        self.accessTimes[key] = [NSDate date];
      }
    }
  });

  return entry;
}

- (void)removeObjectForKey:(NSString*)key {
  if (!key)
    return;

  dispatch_barrier_async(self.accessQueue, ^{
    MemoryCacheWrapper* wrapper = [self.cache objectForKey:key];
    if (wrapper) {
      [self.cache removeObjectForKey:key];
      [self.accessTimes removeObjectForKey:key];
      self.currentSize -= wrapper.cost;
      DNSLogDebug(LogCategoryCache, "Memory cache removed: %@", key);
    }
  });
}

- (void)removeAllObjects {
  dispatch_barrier_async(self.accessQueue, ^{
    [self.cache removeAllObjects];
    [self.accessTimes removeAllObjects];
    self.currentSize = 0;
    DNSLogInfo(LogCategoryCache, "Memory cache cleared");
  });
}

#pragma mark - Expiration Management

- (NSUInteger)removeExpiredEntries {
  __block NSUInteger removedCount = 0;
  __block NSMutableArray<NSString*>* keysToRemove = [NSMutableArray array];

  dispatch_sync(self.accessQueue, ^{
    // Find expired entries
    for (NSString* key in self.accessTimes.allKeys) {
      MemoryCacheWrapper* wrapper = [self.cache objectForKey:key];
      if (wrapper && [wrapper.entry isExpired]) {
        [keysToRemove addObject:key];
      }
    }
  });

  // Remove expired entries
  if (keysToRemove.count > 0) {
    dispatch_barrier_async(self.accessQueue, ^{
      for (NSString* key in keysToRemove) {
        MemoryCacheWrapper* wrapper = [self.cache objectForKey:key];
        if (wrapper) {
          [self.cache removeObjectForKey:key];
          [self.accessTimes removeObjectForKey:key];
          self.currentSize -= wrapper.cost;
          removedCount++;
        }
      }

      if (removedCount > 0) {
        DNSLogInfo(LogCategoryCache, "Removed %lu expired entries from memory cache",
                   (unsigned long)removedCount);
      }
    });
  }

  return removedCount;
}

#pragma mark - Size Management

// currentSize property is synthesized with atomic property, no custom getter needed

- (NSUInteger)entryCount {
  __block NSUInteger count = 0;
  dispatch_sync(self.accessQueue, ^{
    count = self.accessTimes.count;
  });
  return count;
}

- (NSArray<NSString*>*)allKeys {
  __block NSArray<NSString*>* keys = nil;
  dispatch_sync(self.accessQueue, ^{
    keys = [self.accessTimes.allKeys copy];
  });
  return keys ?: @[];
}

#pragma mark - NSCacheDelegate

- (void)cache:(NSCache*)cache willEvictObject:(id)obj {
  if ([obj isKindOfClass:[MemoryCacheWrapper class]]) {
    MemoryCacheWrapper* wrapper = (MemoryCacheWrapper*)obj;

    dispatch_barrier_async(self.accessQueue, ^{
      // Find key for this object
      NSString* keyToRemove = nil;
      for (NSString* key in self.accessTimes.allKeys) {
        if ([self.cache objectForKey:key] == wrapper) {
          keyToRemove = key;
          break;
        }
      }

      if (keyToRemove) {
        [self.accessTimes removeObjectForKey:keyToRemove];
        self.currentSize -= wrapper.cost;
        DNSLogDebug(LogCategoryCache, "Memory cache evicted: %@", keyToRemove);
      }
    });
  }
}

#pragma mark - Private Helpers

- (NSUInteger)estimateSizeForEntry:(CacheEntry*)entry {
  // Basic size estimation - use class_getInstanceSize
  NSUInteger size = class_getInstanceSize([CacheEntry class]);

  // Add RuleSet size estimation
  if (entry.ruleSet) {
    @try {
      NSData* data = [NSKeyedArchiver archivedDataWithRootObject:entry.ruleSet
                                           requiringSecureCoding:YES
                                                           error:nil];
      if (data) {
        size += data.length;
      }
    } @catch (NSException* exception) {
      // Fallback to rough estimation
      size += 1024;  // 1KB default
    }
  }

  return size;
}

@end
