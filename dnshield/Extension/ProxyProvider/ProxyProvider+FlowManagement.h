//
//  ProxyProvider+FlowManagement.h
//  DNShield Network Extension
//
//  Category header for flow management methods
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (FlowManagement)

- (void)processUpstreamResponse:(NSData*)responseData fromServer:(NSString*)server;
- (void)processDNSQueryWithQueuing:(NSData*)queryData
                          fromFlow:(nullable NEAppProxyUDPFlow*)clientFlow
                      fromEndpoint:(nullable NWEndpoint*)clientEndpoint;
- (void)processDNSQuery:(NSData*)queryData
               fromFlow:(nullable NEAppProxyUDPFlow*)clientFlow
           fromEndpoint:(nullable NWEndpoint*)clientEndpoint;
- (void)cleanupStuckQueries;
- (void)clearAllDNSFlows;
- (void)sendResponse:(NSData*)response
              toFlow:(nullable NEAppProxyUDPFlow*)flow
            endpoint:(nullable NWEndpoint*)endpoint;
- (void)enterTransitionMode;
- (void)exitTransitionModeAndProcessQueue;

@end

NS_ASSUME_NONNULL_END
