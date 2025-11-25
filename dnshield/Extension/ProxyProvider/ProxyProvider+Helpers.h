//
//  ProxyProvider+Helpers.h
//  DNShield Network Extension
//
//  Category interface for helper utilities used across proxy components
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (NetworkHelpers)

- (nullable nw_endpoint_t)modernEndpointFromLegacy:(NWEndpoint*)legacyEndpoint;
- (NWEndpoint*)createLegacyEndpointWithHostname:(NSString*)hostname port:(NSString*)port;
- (BOOL)isIPAddress:(NSString*)ipAddress inCIDR:(NSString*)cidr;
- (NSString*)extractIPFromEndpoint:(NSString*)endpointStr;
- (void)ensureWebSocketServerRunning;
- (void)resetWebSocketRetryState;
- (NSTimeInterval)resolveWebSocketRetryInterval;
- (void)scheduleWebSocketRetryWithError:(NSError* _Nullable)error;

@end

NS_ASSUME_NONNULL_END
