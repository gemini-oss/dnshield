#import <Network/Network.h>
#import <NetworkExtension/NetworkExtension.h>
#import <os/log.h>

#import <Common/XPCProtocol.h>
#import "Cache.h"
#import "Manager.h"
#import "RuleDatabase.h"

#import "ConfigurationManager.h"
#import "DNSCache.h"
#import "DNSCacheStats.h"
#import "DNSCommandProcessor.h"
#import "DNSFlowTelemetry.h"
#import "DNSInterfaceManager.h"
#import "DNSPacket.h"
#import "DNSRetryManager.h"

#import "DNSShieldTelemetry.h"
#import "DNSUpstreamConnection.h"
#import "NetworkReachability.h"
#import "PreferenceManager.h"

#import "RuleSet.h"
#import "WebSocketServer.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider : NEDNSProxyProvider <WebSocketServerDelegate>

- (BOOL)handleNewUDPFlow:(NEAppProxyUDPFlow*)flow
    initialRemoteFlowEndpoint:(nw_endpoint_t)remoteEndpoint;
- (void)continuouslyReadDatagrams:(NEAppProxyUDPFlow*)flow
                     fromEndpoint:(nw_endpoint_t)remoteEndpoint;

@end

NS_ASSUME_NONNULL_END
