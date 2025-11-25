//
//  DiskCache.h
//  DNShield Network Extension
//
//  Persistent disk-based cache for rule sets
//

#import <Foundation/Foundation.h>
#import "RuleCache.h"

NS_ASSUME_NONNULL_BEGIN

@interface DiskCache : NSObject

// Initialize with cache directory and maximum size
- (instancetype)initWithDirectory:(NSString*)directory maxSize:(NSUInteger)maxSize;

// Store operations
- (BOOL)storeEntry:(CacheEntry*)entry forKey:(NSString*)key error:(NSError**)error;

// Retrieve operations
- (nullable CacheEntry*)entryForKey:(NSString*)key error:(NSError**)error;

// Remove operations
- (BOOL)removeEntryForKey:(NSString*)key error:(NSError**)error;
- (NSUInteger)removeExpiredEntriesWithError:(NSError**)error;
- (BOOL)removeAllEntriesWithError:(NSError**)error;

// Query operations
- (NSArray<NSString*>*)allKeysWithError:(NSError**)error;
- (NSUInteger)currentSize;
- (NSUInteger)entryCount;

// Maintenance
- (BOOL)synchronizeWithError:(NSError**)error;
- (BOOL)performMaintenanceWithError:(NSError**)error;

// Migration support
- (BOOL)migrateCacheIfNeededWithError:(NSError**)error;

@end

NS_ASSUME_NONNULL_END
