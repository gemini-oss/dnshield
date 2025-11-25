//
//  ProxyProvider+Delegates.h
//  DNShield Network Extension
//
//  Category interface for delegate conformances
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (Delegates) <DNSUpstreamConnectionDelegate,
                                      WebSocketServerDelegate,
                                      RuleManagerDelegate,
                                      DNSCommandProcessorDelegate,
                                      DNSInterfaceManagerDelegate,
                                      DNSRetryManagerDelegate,
                                      NetworkReachabilityDelegate>

@end

NS_ASSUME_NONNULL_END
