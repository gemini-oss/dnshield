//
//  Cache.h
//  DNShield Network Extension
//
//  Simple LRU cache for DNS rule lookups
//

#import <Foundation/Foundation.h>
#import "RuleDatabase.h"

NS_ASSUME_NONNULL_BEGIN

@interface DNSRuleCacheEntry : NSObject
@property(nonatomic, assign) DNSRuleAction action;
@property(nonatomic, assign) BOOL hasRule;
@property(nonatomic, strong) NSDate* timestamp;
@property(nonatomic, assign) NSTimeInterval ttl;  // Custom TTL for this entry
@end

@interface DNSRuleCache : NSObject

@property(atomic, assign) NSUInteger maxEntries;  // Default: 10,000
@property(atomic, assign) NSTimeInterval ttl;     // Default: 300 seconds

// Singleton instance
+ (instancetype)sharedCache;

// Cache operations
- (nullable DNSRuleCacheEntry*)entryForDomain:(NSString*)domain;
- (DNSRuleAction)actionForDomain:(NSString*)domain;  // Returns DNSRuleActionUnknown if not cached
- (void)setAction:(DNSRuleAction)action forDomain:(NSString*)domain;
- (void)setAction:(DNSRuleAction)action forDomain:(NSString*)domain withTTL:(NSTimeInterval)ttl;
- (void)setNoRuleForDomain:(NSString*)domain;
- (void)removeDomain:(NSString*)domain;
- (void)clear;

// Statistics
// Statistics (readonly public interface)
- (NSUInteger)hitCount;
- (NSUInteger)missCount;
- (NSUInteger)evictionCount;
@property(atomic, readonly) NSUInteger entryCount;
@property(atomic, readonly) NSUInteger currentSize;  // Alias for entryCount
@property(atomic, readonly) double hitRate;

- (void)resetStatistics;

@end

NS_ASSUME_NONNULL_END
