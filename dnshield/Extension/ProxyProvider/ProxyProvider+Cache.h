//
//  ProxyProvider+Cache.h
//  DNShield Network Extension
//
//  Category interface for cache-related helpers
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (CacheRules)

- (nullable NSDictionary*)findMatchingCacheRule:(NSString*)domain inRules:(NSDictionary*)rules;

@end

NS_ASSUME_NONNULL_END
