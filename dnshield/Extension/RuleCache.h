//
//  RuleCache.h
//  DNShield Network Extension
//
//  Main cache interface for rule sets
//  Provides a two-tier caching system with memory and disk storage
//

#import <Foundation/Foundation.h>
#import "RuleSet.h"

NS_ASSUME_NONNULL_BEGIN

// Forward declarations
@class MemoryCache;
@class DiskCache;
@class CacheConfiguration;

// Cache statistics
@interface CacheStatistics : NSObject

@property(nonatomic, readonly) NSUInteger memoryCacheHits;
@property(nonatomic, readonly) NSUInteger memoryCacheMisses;
@property(nonatomic, readonly) NSUInteger diskCacheHits;
@property(nonatomic, readonly) NSUInteger diskCacheMisses;
@property(nonatomic, readonly) NSUInteger totalRequests;
@property(nonatomic, readonly) NSUInteger currentMemoryUsage;
@property(nonatomic, readonly) NSUInteger currentDiskUsage;
@property(nonatomic, readonly) double hitRate;
@property(nonatomic, readonly) NSTimeInterval averageLoadTime;

- (void)reset;

@end

// Cache entry wrapper with metadata
@interface CacheEntry : NSObject <NSCoding, NSSecureCoding>

@property(nonatomic, strong) RuleSet* ruleSet;
@property(nonatomic, strong) NSDate* fetchDate;
@property(nonatomic, assign) NSTimeInterval timeToLive;
@property(nonatomic, strong) NSString* sourceIdentifier;
@property(nonatomic, assign) NSUInteger dataSize;

- (instancetype)initWithRuleSet:(RuleSet*)ruleSet
                      fetchDate:(NSDate*)fetchDate
                     timeToLive:(NSTimeInterval)ttl
               sourceIdentifier:(NSString*)sourceId;

- (BOOL)isExpired;
- (NSTimeInterval)timeUntilExpiration;

@end

// Main cache interface
@interface RuleCache : NSObject

// Statistics
@property(nonatomic, readonly) CacheStatistics* statistics;

// Initialize with configuration
- (instancetype)initWithConfiguration:(CacheConfiguration*)configuration;

// Store operations
- (void)storeRuleSet:(RuleSet*)ruleSet forSource:(NSString*)sourceID timeToLive:(NSTimeInterval)ttl;

- (void)storeRuleSet:(RuleSet*)ruleSet forSource:(NSString*)sourceID;  // Uses default TTL

// Retrieve operations
- (nullable RuleSet*)ruleSetForSource:(NSString*)sourceID maxAge:(NSTimeInterval)maxAge;

- (nullable RuleSet*)ruleSetForSource:(NSString*)sourceID;  // Any age

// Async operations for better performance
- (void)ruleSetForSource:(NSString*)sourceID
                  maxAge:(NSTimeInterval)maxAge
              completion:(void (^)(RuleSet* _Nullable ruleSet))completion;

// Cache management
- (void)invalidateCacheForSource:(NSString*)sourceID;
- (void)invalidateExpiredEntries;
- (void)clearMemoryCache;
- (void)clearDiskCache;
- (void)clearAllCaches;

// Preloading
- (void)preloadSource:(NSString*)sourceID;
- (void)preloadAllSources;

// Size management
- (NSUInteger)currentMemoryCacheSize;
- (NSUInteger)currentDiskCacheSize;
- (NSUInteger)totalCacheSize;

// Persistence
- (void)synchronize;  // Force write to disk

// Testing support
- (void)injectTestRuleSet:(RuleSet*)ruleSet
                forSource:(NSString*)sourceID
               timeToLive:(NSTimeInterval)ttl;

@end

// Notifications
extern NSString* const RuleCacheDidUpdateNotification;
extern NSString* const RuleCacheDidEvictNotification;
extern NSString* const RuleCacheSourceIDKey;

NS_ASSUME_NONNULL_END
