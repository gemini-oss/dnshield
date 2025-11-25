//
//  ProxyProvider+Migration.h
//  DNShield Network Extension
//
//  Category interface for migration and cache warmup helpers
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (Migration)

- (void)warmCache;
- (void)migrateRulesToDatabase;
- (NSTimeInterval)calculateAdaptiveTTL:(NSUInteger)queryCount;
- (void)startPeriodicMaintenance;

@end

NS_ASSUME_NONNULL_END
