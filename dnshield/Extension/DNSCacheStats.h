//
//  DNSCacheStats.h
//  DNShield Network Extension
//
//  Cache statistics tracking for performance monitoring
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DNSCacheStats : NSObject

// Real-time statistics
@property(atomic, readonly) NSUInteger hits;
@property(atomic, readonly) NSUInteger misses;
@property(atomic, readonly) double hitRate;
@property(atomic, readonly) NSTimeInterval avgLookupTime;
@property(atomic, readonly) NSUInteger queriesPerSecond;

// Time-based metrics
@property(atomic, readonly) NSDate* lastReset;
@property(atomic, readonly) NSTimeInterval uptime;

// Performance metrics
@property(atomic, readonly) NSTimeInterval fastestLookup;
@property(atomic, readonly) NSTimeInterval slowestLookup;
@property(atomic, readonly) NSUInteger slowQueryCount;  // Queries > 10ms

// Singleton instance
+ (instancetype)sharedStats;

// Recording methods
- (void)recordHit:(NSTimeInterval)lookupTime;
- (void)recordMiss:(NSTimeInterval)lookupTime;
- (void)recordDatabaseQuery:(NSTimeInterval)queryTime;

// Management
- (void)reset;
- (NSDictionary*)snapshot;

@end

NS_ASSUME_NONNULL_END
