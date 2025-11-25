#import <Common/LoggingManager.h>
#import "Provider.h"
#import "ProxyProvider+Private.h"

@implementation ProxyProvider (HealthMonitoring)

#pragma mark - Health Checks and Monitoring

- (BOOL)isProxyHealthy {
  // Check if we have active upstream connections
  NSUInteger connectedCount = 0;
  for (NSString* server in self.dnsServers) {
    DNSUpstreamConnection* conn = self.upstreamConnections[server];
    if (conn && conn.isConnected) {
      connectedCount++;
    }
  }

  // Health check criteria
  BOOL hasUpstreamConnections = connectedCount > 0;
  BOOL notInTransitionMode = !self.isInTransitionMode;
  BOOL hasRuleManager = self.ruleManager != nil;
  BOOL networkReachable = [self.networkReachability isReachable];

  return hasUpstreamConnections && notInTransitionMode && hasRuleManager && networkReachable;
}

- (void)performHealthCheck {
  dispatch_async(self.dnsQueue, ^{
    BOOL isHealthy = [self isProxyHealthy];

    // Count connected upstream servers
    NSUInteger connectedCount = 0;
    NSUInteger totalCount = self.dnsServers.count;

    for (NSString* server in self.dnsServers) {
      DNSUpstreamConnection* conn = self.upstreamConnections[server];
      if (conn && conn.isConnected) {
        connectedCount++;
      }
    }

    // Log health check results
    [self.telemetry
        logExtensionLifecycleEvent:@"health_check"
                          metadata:@{
                            @"is_healthy" : @(isHealthy),
                            @"connected_upstream_count" : @(connectedCount),
                            @"total_upstream_count" : @(totalCount),
                            @"network_reachable" : @([self.networkReachability isReachable]),
                            @"in_transition_mode" : @(self.isInTransitionMode),
                            @"active_flows_count" : @(self.activeFlows.count),
                            @"queued_queries_count" : @(self.queuedQueries.count)
                          }];

    if (!isHealthy) {
      DNSLogError(LogCategoryDNS,
                  "DNS proxy health check failed - connected: %lu/%lu, network: %d, transition: %d",
                  (unsigned long)connectedCount, (unsigned long)totalCount,
                  [self.networkReachability isReachable], self.isInTransitionMode);
    }
  });
}

@end
