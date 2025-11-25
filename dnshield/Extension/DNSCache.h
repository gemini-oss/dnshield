//
//  DNSCache.h
//  DNShield Network Extension
//
//  TTL-aware DNS response cache
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DNSCacheEntry : NSObject
@property(nonatomic, strong) NSData* response;
@property(nonatomic, strong) NSDate* expiryDate;
@property(nonatomic, assign) uint32_t originalTTL;
@end

@interface DNSCache : NSObject

// Initialize with maximum cache size
- (instancetype)initWithMaxSize:(NSUInteger)maxSize;

// Cache operations
- (void)cacheResponse:(NSData*)response
            forDomain:(NSString*)domain
            queryType:(uint16_t)queryType
                  ttl:(uint32_t)ttl;

- (nullable NSData*)getCachedResponseForDomain:(NSString*)domain queryType:(uint16_t)queryType;

// Cache management
- (void)clearCache;
- (void)removeExpiredEntries;

// Statistics
@property(nonatomic, readonly) NSUInteger cacheSize;
@property(nonatomic, readonly) NSUInteger hitCount;
@property(nonatomic, readonly) NSUInteger missCount;
@property(nonatomic, readonly) NSUInteger evictionCount;
@property(nonatomic, readonly) double hitRate;

@end

NS_ASSUME_NONNULL_END
