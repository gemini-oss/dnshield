//
//  ProxyProvider+Health.h
//  DNShield Network Extension
//
//  Category header for health monitoring methods
//

#import "Provider.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (HealthMonitoring)

- (BOOL)isProxyHealthy;
- (void)performHealthCheck;

@end

NS_ASSUME_NONNULL_END
