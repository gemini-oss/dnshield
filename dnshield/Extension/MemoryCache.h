//
//  MemoryCache.h
//  DNShield Network Extension
//
//  Fast in-memory cache using NSCache with TTL support
//

#import <Foundation/Foundation.h>
#import "RuleCache.h"

NS_ASSUME_NONNULL_BEGIN

@interface MemoryCache : NSObject

// Initialize with maximum size in bytes
- (instancetype)initWithMaxSize:(NSUInteger)maxSize;

// Cache operations
- (void)setObject:(CacheEntry*)entry forKey:(NSString*)key;
- (nullable CacheEntry*)objectForKey:(NSString*)key;
- (void)removeObjectForKey:(NSString*)key;
- (void)removeAllObjects;

// Expiration management
- (NSUInteger)removeExpiredEntries;

// Size management
- (NSUInteger)currentSize;
- (NSUInteger)entryCount;

// Get all keys (for debugging/testing)
- (NSArray<NSString*>*)allKeys;

@end

NS_ASSUME_NONNULL_END
