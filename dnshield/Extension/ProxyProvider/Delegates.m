#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/Manager+Manifest.h>
#import <Rule/RuleDatabase.h>
#import <Rule/RuleSet.h>

#import "AuditLogger.h"
#import "Provider.h"
#import "ProxyProvider+Delegates.h"
#import "ProxyProvider+FlowManagement.h"
#import "ProxyProvider+Initialization.h"

@implementation ProxyProvider (Delegates)

#pragma mark - DNSUpstreamConnectionDelegate

- (void)upstreamConnection:(DNSUpstreamConnection*)connection didReceiveResponse:(NSData*)response {
  [self processUpstreamResponse:response fromServer:connection.serverAddress];
}

- (void)upstreamConnection:(DNSUpstreamConnection*)connection didFailWithError:(NSError*)error {
  DNSLogError(LogCategoryNetwork, "Upstream connection to %{public}@ failed: %{public}@",
              connection.serverAddress, error.localizedDescription);

  // Remove failed connection
  [self.upstreamConnections removeObjectForKey:connection.serverAddress];
}

#pragma mark - RuleManagerDelegate

- (void)ruleManagerDidUpdateRules:(NSArray<DNSRule*>*)dnsRules {
  DNSLogInfo(LogCategoryRuleParsing, "RuleManagerDelegate: Rules updated. Committing to database.");

  dispatch_async(self.dnsQueue, ^{
    [self.ruleDatabase beginTransaction];

    // Clear existing manifest rules before adding new ones
    NSError* deleteError = nil;
    if (![self.ruleDatabase removeAllRulesFromSource:DNSRuleSourceManifest error:&deleteError]) {
      DNSLogError(LogCategoryRuleParsing, "Failed to remove old manifest rules: %{public}@",
                  deleteError.localizedDescription);
      [self.ruleDatabase rollbackTransaction];
      return;
    }

    // Add new rules
    NSError* addError = nil;
    if (![self.ruleDatabase addRules:dnsRules error:&addError]) {
      DNSLogError(LogCategoryRuleParsing, "Failed to add new manifest rules: %{public}@",
                  addError.localizedDescription);
      [self.ruleDatabase rollbackTransaction];
      return;
    }

    // Get old rule count for comparison
    NSUInteger oldRuleCount = self.ruleDatabase.ruleCount;

    // Commit transaction
    if ([self.ruleDatabase commitTransaction]) {
      DNSLogInfo(LogCategoryRuleParsing, "Database updated with %lu new rules",
                 (unsigned long)dnsRules.count);

      // Clear cache to force fresh lookups
      [self.ruleCache clear];
      [self.dnsCache clearCache];

      // Get manifest ID from preferences
      NSString* manifestId =
          [[PreferenceManager sharedManager] preferenceValueForKey:@"ManifestIdentifier"
                                                          inDomain:kDNShieldPreferenceDomain]
              ?: @"default";

      // Log rule update to telemetry
      [self.telemetry logRuleUpdateEvent:manifestId
                              rulesAdded:dnsRules.count
                            rulesRemoved:oldRuleCount
                                metadata:@{
                                  @"total_rules" : @(self.ruleDatabase.ruleCount),
                                  @"update_source" : @"manifest",
                                  @"cache_cleared" : @YES
                                }];

    } else {
      DNSLogError(LogCategoryRuleParsing, "Failed to commit transaction");
    }
  });
}

- (void)ruleManagerDidFailUpdate:(NSError*)error {
  DNSLogError(LogCategoryRuleParsing, "Rule update failed: %@", error.localizedDescription);
}

#pragma mark - WebSocketServerDelegate

- (void)webSocketServerDidStart:(NSUInteger)port {
  DNSLogInfo(LogCategoryNetwork, "WebSocket server started on port %lu", (unsigned long)port);
}

- (void)webSocketServerDidStop {
  DNSLogInfo(LogCategoryNetwork, "WebSocket server stopped");
}

- (void)webSocketServerDidReceiveMessage:(NSDictionary*)message fromClient:(NSString*)clientID {
  DNSLogDebug(LogCategoryNetwork, "Received WebSocket message from client %@", clientID);
  NSString* type = [message[@"type"] isKindOfClass:[NSString class]] ? message[@"type"] : nil;
  if (type.length == 0) {
    DNSLogDebug(LogCategoryNetwork, "Ignoring WebSocket message with missing type");
    return;
  }

  if ([type isEqualToString:@"get_blocked_domains"]) {
    NSString* requestingClientID = [clientID copy];
    __weak typeof(self) weakSelf = self;
    dispatch_async(self.dnsQueue, ^{
      __strong typeof(weakSelf) strongSelf = weakSelf;
      if (!strongSelf)
        return;

      NSArray<DNSRule*>* blockedRules = [strongSelf.ruleDatabase blockedDomains];
      NSMutableOrderedSet<NSString*>* domainSet = [NSMutableOrderedSet orderedSet];
      for (DNSRule* rule in blockedRules) {
        if (rule.domain.length > 0) {
          [domainSet addObject:rule.domain];
        }
      }

      NSDictionary* response =
          @{@"type" : @"blocked_domains_list",
            @"data" : domainSet.array ?: @[]};
      [strongSelf.wsServer sendMessage:response toClient:requestingClientID];
    });
  } else {
    DNSLogDebug(LogCategoryNetwork, "Unhandled WebSocket message type: %@", type);
  }
}

#pragma mark - DNSCommandProcessorDelegate

- (void)processCommand:(NSDictionary*)command {
  NSString* commandId = command[@"commandId"];
  NSString* commandType = command[@"type"];

  DNSLogInfo(LogCategoryConfiguration, "Processing filesystem command: %{public}@ (ID: %{public}@)",
             commandType, commandId);

  NSMutableDictionary* response = [NSMutableDictionary dictionary];
  response[@"commandId"] = commandId;

  NSDateFormatter* isoFormatter = [[NSDateFormatter alloc] init];
  isoFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
  isoFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
  isoFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];

  response[@"timestamp"] = [isoFormatter stringFromDate:[NSDate date]];

  if ([commandType isEqualToString:@"updateRules"]) {
    // Trigger rule update
    if (self.ruleManager) {
      [self.ruleManager forceUpdate];
      response[@"success"] = @YES;
      response[@"message"] = @"Rule update initiated";
    } else {
      response[@"success"] = @NO;
      response[@"error"] = @"Rule manager not initialized";
    }

  } else if ([commandType isEqualToString:@"getStatus"]) {
    // Return current status
    // Get cache performance stats
    NSDictionary* cacheStats = [[DNSCacheStats sharedStats] snapshot];

    response[@"success"] = @YES;
    response[@"status"] = @{
      @"blockedDomainCount" : @(self.ruleDatabase.ruleCount),
      @"cacheEntries" : @(self.ruleCache.currentSize),
      @"cacheHitRate" : @(self.dnsCache.hitRate),
      @"queriesBlocked" : @(self.blockedCount),
      @"queriesAllowed" : @(self.allowedCount),
      @"lastUpdate" : self.ruleDatabase.lastUpdated ?: [NSNull null],
      @"databaseSize" : @(self.ruleDatabase.databaseSizeInBytes),
      @"performance" : cacheStats
    };

  } else if ([commandType isEqualToString:@"clearCache"]) {
    // Clear caches
    [self.dnsCache clearCache];
    [self.ruleCache clear];
    response[@"success"] = @YES;
    response[@"message"] = @"All caches cleared";

    // Log telemetry event for cache clear
    NSDictionary* metadata = @{
      @"command_id" : commandId ?: @"unknown",
      @"manual_clear" : @YES,
      @"cleared_components" : @[ @"dns_cache", @"rule_cache" ],
      @"cache_size_before" : @(self.dnsCache.cacheSize),
      @"rule_count" : @(self.ruleDatabase.ruleCount)
    };
    [self.telemetry logExtensionLifecycleEvent:@"cache_cleared" metadata:metadata];
    DNSLogInfo(LogCategoryCache, "Cache cleared via command, telemetry logged");

  } else if ([commandType isEqualToString:@"reloadConfiguration"]) {
    // Reload configuration
    [self.dnsCache clearCache];
    [self.ruleCache clear];
    [self loadConfiguration];
    response[@"success"] = @YES;
    response[@"message"] = @"Configuration reloaded";

  } else if ([commandType isEqualToString:@"syncRules"]) {
    // Sync rules from manifest server - use the same approach as the working version
    DNSLogInfo(LogCategoryRuleFetching, "Processing syncRules command");

    if (self.ruleManager) {
      // First check if we can use the loadManifestAsync approach (like working version)
      if ([self.ruleManager respondsToSelector:@selector(loadManifestAsync:completion:)] &&
          [self.ruleManager respondsToSelector:@selector(determineManifestIdentifier)]) {
        NSString* manifestIdentifier = [(id)self.ruleManager determineManifestIdentifier];
        DNSLogInfo(LogCategoryRuleFetching, "Loading manifest directly for identifier: %{public}@",
                   manifestIdentifier);

        // Load manifest directly - this handles empty database case properly
        [(id)self.ruleManager loadManifestAsync:manifestIdentifier
                                     completion:^(BOOL success, NSError* error) {
                                       if (success) {
                                         DNSLogInfo(LogCategoryRuleFetching,
                                                    "Manifest loaded successfully, updating rules");

                                         // Trigger rule update from the loaded manifest
                                         [self.ruleManager forceUpdate];

                                         // Log telemetry
                                         NSDictionary* metadata = @{
                                           @"command_id" : commandId ?: @"unknown",
                                           @"source" : @"manual_sync",
                                           @"manifest_id" : manifestIdentifier,
                                           @"success" : @YES
                                         };
                                         [self.telemetry logExtensionLifecycleEvent:@"rules_synced"
                                                                           metadata:metadata];
                                       } else {
                                         DNSLogError(LogCategoryRuleFetching,
                                                     "Failed to load manifest: %{public}@", error);

                                         // Log failure
                                         NSDictionary* metadata = @{
                                           @"command_id" : commandId ?: @"unknown",
                                           @"source" : @"manual_sync",
                                           @"manifest_id" : manifestIdentifier,
                                           @"success" : @NO,
                                           @"error" : error.localizedDescription ?: @"unknown"
                                         };
                                         [self.telemetry
                                             logExtensionLifecycleEvent:@"rules_sync_failed"
                                                               metadata:metadata];
                                       }
                                     }];

        response[@"success"] = @YES;
        response[@"message"] = @"Rule sync initiated successfully";

      } else if ([self.ruleManager respondsToSelector:@selector(reloadManifestIfNeeded)]) {
        // Fallback to reloadManifestIfNeeded (but this won't work with empty database)
        DNSLogInfo(LogCategoryRuleFetching, "Using fallback reloadManifestIfNeeded method");
        [(id)self.ruleManager reloadManifestIfNeeded];

        // Force update even if reloadManifestIfNeeded returns early
        [self.ruleManager forceUpdate];

        response[@"success"] = @YES;
        response[@"message"] = @"Rule sync initiated (fallback method)";

        // Log telemetry
        NSDictionary* metadata = @{
          @"command_id" : commandId ?: @"unknown",
          @"source" : @"manual_sync",
          @"method" : @"fallback"
        };
        [self.telemetry logExtensionLifecycleEvent:@"rules_synced" metadata:metadata];
      } else {
        response[@"success"] = @NO;
        response[@"error"] = @"Rule manager does not support manifest operations";
      }
    } else {
      response[@"success"] = @NO;
      response[@"error"] = @"Rule manager not available";
    }

  } else {
    response[@"success"] = @NO;
    response[@"error"] = [NSString stringWithFormat:@"Unknown command type: %@", commandType];
  }

  // Write response
  NSError* error = nil;
  if (![self.commandProcessor writeResponse:response forCommand:commandId error:&error]) {
    DNSLogError(LogCategoryGeneral, "Failed to write command response: %{public}@", error);
  }
}

#pragma mark - DNSInterfaceManagerDelegate

- (void)interfaceManager:(DNSInterfaceManager*)manager didDetectPathChange:(nw_path_t)path {
  DNSLogInfo(LogCategoryNetwork, "Network path change detected by interface manager");

  // Only clear flows if we have significant path changes
  // The network reachability handler will handle wake scenarios
  dispatch_async(self.dnsQueue, ^{
    // Just clear upstream connections, not all flows
    // This is less disruptive for minor path changes
    for (DNSUpstreamConnection* conn in self.upstreamConnections.allValues) {
      [conn close];
    }
    [self.upstreamConnections removeAllObjects];
    DNSLogInfo(LogCategoryNetwork, "Upstream connections cleared due to path change");
  });
}

- (void)interfaceManager:(DNSInterfaceManager*)manager didUpdateVPNState:(BOOL)isActive {
  DNSLogInfo(LogCategoryNetwork, "VPN state change detected: %{public}@",
             isActive ? @"active" : @"inactive");

  // VPN changes require full flow reset
  [self clearAllDNSFlows];
}

#pragma mark - DNSRetryManagerDelegate

- (void)retryManager:(DNSRetryManager*)manager
    willRetryAttempt:(DNSRetryAttempt*)attempt
       transactionID:(NSString*)transactionID {
  DNSLogInfo(LogCategoryDNS, "Will retry DNS query for transaction %{public}@: %{public}@",
             transactionID, attempt);
}

- (void)retryManager:(DNSRetryManager*)manager
    didExhaustRetries:(NSArray<DNSRetryAttempt*>*)attempts
        transactionID:(NSString*)transactionID {
  DNSLogError(LogCategoryDNS, "Exhausted all %lu retry attempts for transaction %{public}@",
              (unsigned long)attempts.count, transactionID);
}

#pragma mark - NetworkReachabilityDelegate

- (void)networkReachabilityDidChange:(NetworkStatus)status {
  NSString* statusString = [NetworkReachability stringForStatus:status];
  DNSLogInfo(LogCategoryNetwork, "Network status changed: %{public}@", statusString);

  if (NetworkStatusIsReachable(status)) {
    DNSLogInfo(LogCategoryNetwork, "Network became reachable, checking for pending operations");

    // If we were waiting for connectivity during startup and now have it,
    // this will be handled by the waitForConnectivityWithTimeout callback

    // Resume rule updates if they were paused
    if (self.ruleManager && !self.isWaitingForConnectivity) {
      [self.ruleManager startUpdating];
    }

    // Log connectivity restoration
    DNSLogInfo(LogCategoryNetwork, "Network connectivity restored: %{public}@", statusString);
  } else {
    DNSLogInfo(LogCategoryNetwork, "Network became unreachable, entering offline mode");

    // Log connectivity loss
    DNSLogInfo(LogCategoryNetwork, "Network connectivity lost: %{public}@", statusString);
  }
}

- (void)networkReachabilityDidChangeFromStatus:(NetworkStatus)oldStatus
                                      toStatus:(NetworkStatus)newStatus {
  NSString* oldStatusString = [NetworkReachability stringForStatus:oldStatus];
  NSString* newStatusString = [NetworkReachability stringForStatus:newStatus];

  DNSLogInfo(LogCategoryNetwork, "Network transition: %{public}@ -> %{public}@", oldStatusString,
             newStatusString);

  // Clear all flows when transitioning to reachable from any non-reachable state
  // This covers wake from sleep, network reconnection, and initial startup
  if (!NetworkStatusIsReachable(oldStatus) && NetworkStatusIsReachable(newStatus)) {
    DNSLogInfo(LogCategoryNetwork,
               "Network became reachable from non-reachable state - clearing all flows");
    [self clearAllDNSFlows];

    // Give network stack time to stabilize before processing new queries
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), self.dnsQueue, ^{
          DNSLogInfo(LogCategoryNetwork, "Network stabilized, ready for new DNS queries");
        });
  }

  // Log network transition
  DNSLogInfo(LogCategoryNetwork, "Network transition completed: %{public}@ -> %{public}@",
             oldStatusString, newStatusString);
}

@end
