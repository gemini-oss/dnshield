#import <Common/Defaults.h>
#import <Common/LoggingManager.h>

#import <Rule/Manager+Manifest.h>

#import "AuditLogger.h"
#import "DNSManifestResolver.h"
#import "Provider.h"
#import "ProxyProvider+Delegates.h"
#import "ProxyProvider+FlowManagement.h"
#import "ProxyProvider+Health.h"
#import "ProxyProvider+Helpers.h"
#import "ProxyProvider+Initialization.h"
#import "ProxyProvider+Migration.h"
#import "ProxyProvider+Private.h"
#import "ProxyProvider+Statistics.h"
#import "ProxyProvider+Telemetry.h"
#import "ProxyProvider+XPC.h"

@implementation ProxyProvider

#pragma mark - NEDNSProxyProvider Methods

- (void)startProxyWithOptions:(nullable NSDictionary<NSString*, id>*)options
            completionHandler:(void (^)(NSError* _Nullable error))completionHandler {
  NSString* version =
      [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  NSString* build = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  DNSLogInfo(LogCategoryDNS, "Starting DNS proxy provider - Version %{public}@ (Build %{public}@)",
             version ?: @"unknown", build ?: @"unknown");

  // Enter transition mode during startup to queue queries until fully initialized
  [self enterTransitionMode];

  // Log extension startup to telemetry with restart detection
  NSDate* lastStartTime =
      [[NSUserDefaults standardUserDefaults] objectForKey:@"LastExtensionStartTime"];
  NSTimeInterval timeSinceLastStart =
      lastStartTime ? [[NSDate date] timeIntervalSinceDate:lastStartTime] : 0;
  BOOL isRestart = (timeSinceLastStart > 0 &&
                    timeSinceLastStart < 300);  // Less than 5 minutes indicates restart

  [[NSUserDefaults standardUserDefaults] setObject:[NSDate date] forKey:@"LastExtensionStartTime"];
  [[NSUserDefaults standardUserDefaults] synchronize];

  [self.telemetry logExtensionLifecycleEvent:@"extension_started"
                                    metadata:@{
                                      @"version" : version ?: @"unknown",
                                      @"build" : build ?: @"unknown",
                                      @"is_restart" : @(isRestart),
                                      @"seconds_since_last_start" : @(timeSinceLastStart)
                                    }];

  // Start network monitoring
  [self.networkReachability startMonitoring];

  // Always continue with startup - DNS extensions should work offline
  DNSLogInfo(LogCategoryNetwork, "Starting extension initialization (network status: %@)",
             [self.networkReachability isReachable] ? @"reachable" : @"not reachable");
  [self continueStartupWithOptions:options completionHandler:completionHandler];
}

- (void)continueStartupWithOptions:(nullable NSDictionary<NSString*, id>*)options
                 completionHandler:(void (^)(NSError* _Nullable error))completionHandler {
  // Ensure XPC listener is running
  if (!self.xpcListener) {
    DNSLogInfo(LogCategoryDNS, "XPC listener not initialized, starting it now");
    [self startXPCListener];
  }

  // Store provider configuration from options
  if (options && options.count > 0) {
    self.providerConfiguration = options;
    DNSLogInfo(LogCategoryConfiguration, "Received provider configuration with %lu items",
               (unsigned long)options.count);

    // Log WebSocket configuration if present
    if (options[@"WebSocketAuthToken"]) {
      DNSLogInfo(LogCategoryConfiguration, "Provider configuration includes WebSocket auth token");
    }
    if (options[@"EnableWebSocketServer"]) {
      DNSLogInfo(LogCategoryConfiguration, "Provider configuration includes WebSocket enabled: %@",
                 options[@"EnableWebSocketServer"]);
    }
    if (options[@"WebSocketPort"]) {
      DNSLogInfo(LogCategoryConfiguration, "Provider configuration includes WebSocket port: %@",
                 options[@"WebSocketPort"]);
    }

    [self updateConfiguration:options
            completionHandler:^(BOOL success){
            }];
  }

  // Reload configuration to ensure we have the latest settings
  [self loadConfiguration];

  // Initialize command processor for filesystem-based commands
  self.commandProcessor = [DNSCommandProcessor sharedProcessor];
  self.commandProcessor.delegate = self;
  [self.commandProcessor startMonitoring];

  // Initialize SQLite database
  self.ruleDatabase = [RuleDatabase sharedDatabase];
  if (![self.ruleDatabase openDatabase]) {
    DNSLogError(LogCategoryRuleParsing, "Failed to open rule database");
    completionHandler([NSError
        errorWithDomain:@"com.dnshield.networkextension"
                   code:1001
               userInfo:@{NSLocalizedDescriptionKey : @"Failed to open database"}]);
    return;
  }
  [self.ruleDatabase createTablesIfNeeded];

  // Initialize rule cache
  self.ruleCache = [[DNSRuleCache alloc] init];
  self.ruleCache.maxEntries = 10000;
  self.ruleCache.ttl = 300;  // 5 minutes

  // Observe database changes to clear cache
  [[NSNotificationCenter defaultCenter] addObserver:self
                                           selector:@selector(handleDatabaseChange:)
                                               name:RuleDatabaseDidChangeNotification
                                             object:nil];

  // Migrate existing rules from DomainTrie to SQLite if needed
  [self migrateRulesToDatabase];

  // Warm cache with frequently accessed domains
  [self warmCache];

  // Start periodic maintenance tasks
  [self startPeriodicMaintenance];

  // Initialize configuration manager
  self.configManager = [ConfigurationManager sharedManager];
  [self.configManager loadConfiguration];

  // Check if we should use manifest-based configuration
  NSString* manifestIdentifier =
      [self.preferenceManager.sharedDefaults objectForKey:@"useManifest"];
  if (!manifestIdentifier || [manifestIdentifier isEqualToString:@"YES"]) {
    // Determine client identifier for manifest selection
    manifestIdentifier =
        [DNSManifestResolver determineClientIdentifierWithPreferenceManager:self.preferenceManager];
    DNSLogInfo(LogCategoryRuleFetching,
               "Using manifest-based configuration with identifier: %{public}@",
               manifestIdentifier);

    self.ruleManager = [[RuleManager alloc] initWithManifestIdentifier:manifestIdentifier];
    self.ruleManager.delegate = self;
  } else {
    // Fall back to traditional configuration
    DNSConfiguration* config = self.configManager.currentConfiguration;
    if (config) {
      self.ruleManager = [[RuleManager alloc] initWithConfiguration:config];
      self.ruleManager.delegate = self;
    }
  }

  // CRITICAL: Ensure we have a rule manager even if manifest loading failed
  // This prevents DNS resolution from breaking completely
  if (!self.ruleManager) {
    DNSLogError(LogCategoryConfiguration,
                "Failed to initialize rule manager with manifest, using minimal configuration");

    // Create a minimal configuration that allows all DNS queries
    DNSConfiguration* minimalConfig = [DNSConfiguration defaultConfiguration];
    if (!minimalConfig) {
      minimalConfig = [[DNSConfiguration alloc] init];
    }

    self.ruleManager = [[RuleManager alloc] initWithConfiguration:minimalConfig];
    self.ruleManager.delegate = self;

    // Log this critical event
    [self.telemetry logExtensionLifecycleEvent:@"manifest_fallback_to_minimal"
                                      metadata:@{
                                        @"requested_identifier" : manifestIdentifier ?: @"unknown",
                                        @"reason" : @"no_manifest_found"
                                      }];
  }

  if (self.ruleManager) {
    // Start rule updates only if we have network connectivity
    if ([self.networkReachability isReachable]) {
      DNSLogInfo(LogCategoryRuleFetching, "Network available, starting rule updates");
      [self.ruleManager startUpdating];
    } else {
      DNSLogInfo(LogCategoryRuleFetching,
                 "Network not available, deferring rule updates until connectivity is restored");
      // Rule updates will be started when network becomes available (handled in
      // networkReachabilityDidChange)
    }

    DNSLogInfo(LogCategoryRuleFetching, "Rule management system initialized");
  } else {
    DNSLogError(LogCategoryRuleFetching, "Failed to load configuration for rule manager");
  }

  // CRITICAL: Ensure we have DNS servers configured
  if (!self.dnsServers || self.dnsServers.count == 0) {
    DNSLogError(LogCategoryConfiguration, "ERROR: No DNS servers configured! Using defaults.");
    self.dnsServers = @[ @"1.1.1.1", @"8.8.8.8" ];
  }

  // Log current configuration
  DNSLogInfo(LogCategoryDNS, "DNS proxy starting with DNS servers: %{public}@",
             [self.dnsServers componentsJoinedByString:@", "]);

  // Create upstream connections
  [self setupUpstreamConnections];

  // Ensure WebSocket server running for Chrome extension
  [self ensureWebSocketServerRunning];

  // Start cleanup timer for stuck queries
  self.cleanupTimer = [NSTimer scheduledTimerWithTimeInterval:5.0
                                                       target:self
                                                     selector:@selector(cleanupStuckQueries)
                                                     userInfo:nil
                                                      repeats:YES];

  // Periodic cleanup of old command files
  [NSTimer scheduledTimerWithTimeInterval:3600.0  // 1 hour
                                   target:self.commandProcessor
                                 selector:@selector(cleanupOldFiles)
                                 userInfo:nil
                                  repeats:YES];

  // Give connections time to establish
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        DNSLogInfo(LogCategoryDNS, "DNS proxy provider started and ready");

        // Log connection status
        for (NSString* server in self.dnsServers) {
          DNSUpstreamConnection* conn = self.upstreamConnections[server];
          DNSLogInfo(LogCategoryNetwork, "Upstream connection to %{public}@: %@", server,
                     conn.isConnected ? @"CONNECTED" : @"NOT CONNECTED");
        }

        // Exit transition mode and process any queued DNS queries
        [self exitTransitionModeAndProcessQueue];

        // Log successful startup completion
        [self.telemetry
            logExtensionLifecycleEvent:@"extension_ready"
                              metadata:@{
                                @"startup_duration_ms" : @((NSInteger)(
                                    [[NSDate date]
                                        timeIntervalSinceDate:
                                            [[NSUserDefaults standardUserDefaults]
                                                objectForKey:@"LastExtensionStartTime"]] *
                                    1000)),
                                @"upstream_connections_ready" : @(self.upstreamConnections.count)
                              }];
      });

  completionHandler(nil);
}

- (void)stopProxyWithReason:(NEProviderStopReason)reason
          completionHandler:(void (^)(void))completionHandler {
  DNSLogInfo(LogCategoryDNS, "Stopping DNS proxy with reason: %ld", (long)reason);

  // Remove notification observer
  [[NSNotificationCenter defaultCenter] removeObserver:self
                                                  name:RuleDatabaseDidChangeNotification
                                                object:nil];

  // Log extension shutdown to telemetry
  [self.telemetry logExtensionLifecycleEvent:@"extension_stopped"
                                    metadata:@{
                                      @"reason" : @(reason),
                                      @"blocked_count" : @(self.blockedCount),
                                      @"allowed_count" : @(self.allowedCount)
                                    }];

  // Flush telemetry before shutdown
  [self.telemetry flush];

  // Stop cleanup timer
  [self.cleanupTimer invalidate];
  self.cleanupTimer = nil;

  [self resetWebSocketRetryState];

  // Stop WebSocket server
  [self.wsServer stop];

  // Final statistics report
  [self reportStatistics];

  // Close all connections
  for (DNSUpstreamConnection* conn in self.upstreamConnections.allValues) {
    [conn close];
  }
  [self.upstreamConnections removeAllObjects];

  // Clear all pending queries and flows
  [self.queryToClientInfo removeAllObjects];
  [self.queryTimestamps removeAllObjects];
  [self.activeFlows removeAllObjects];
  [self.closedFlows removeAllObjects];

  // Stop network monitoring
  [self.networkReachability stopMonitoring];
  self.networkReachability.delegate = nil;

  completionHandler();
}

#pragma mark - NEDNSProxyProvider Flow Handling

- (BOOL)handleNewFlow:(NEAppProxyTCPFlow*)flow {
  // Check if this is a DNS flow (port 53)
  nw_endpoint_t remoteEndpoint = [self modernEndpointFromLegacy:flow.remoteEndpoint];
  const char* portString = nw_endpoint_copy_port_string(remoteEndpoint);
  if (portString && strcmp(portString, "53") == 0) {
    const char* hostnameString = nw_endpoint_copy_address_string(remoteEndpoint);
    DNSLogInfo(LogCategoryDNS, "Handling TCP DNS flow to %{public}s:%{public}s",
               hostnameString ?: "unknown", portString);
    if (hostnameString)
      free((void*)hostnameString);
    free((void*)portString);

    // Handle TCP DNS flow
    [self handleTCPDNSFlow:flow];
    return YES;
  }

  if (portString)
    free((void*)portString);

  // Return NO to let non-DNS TCP flows pass through normally
  return NO;
}

- (void)handleTCPDNSFlow:(NEAppProxyTCPFlow*)flow {
  __weak typeof(self) weakSelf = self;

  // Store the TCP flow immediately after extracting the transaction ID from the query, before
  // processing

  // Open the TCP flow first
  [flow openWithLocalFlowEndpoint:nil
                completionHandler:^(NSError* _Nullable error) {
                  __strong typeof(weakSelf) strongSelf = weakSelf;
                  if (!strongSelf || error) {
                    DNSLogError(LogCategoryDNS, "Failed to open TCP flow: %{public}@",
                                error.localizedDescription);
                    // TCP flow is closed here; any additional cleanup (e.g., removal from tracking)
                    // relies on the cleanup timer or explicit removal elsewhere.
                    [flow closeReadWithError:error];
                    [flow closeWriteWithError:error];
                    return;
                  }

                  DNSLogInfo(LogCategoryDNS, "TCP DNS flow opened successfully");

                  // Now read the data
                  [flow readDataWithCompletionHandler:^(NSData* _Nullable data,
                                                        NSError* _Nullable readError) {
                    if (!strongSelf || readError || !data) {
                      DNSLogError(LogCategoryDNS, "Failed to read TCP DNS data: %{public}@",
                                  readError.localizedDescription);
                      // TCP flow will be cleaned up after processing
                      [flow closeReadWithError:readError];
                      [flow closeWriteWithError:readError];
                      return;
                    }

                    // TCP DNS format: 2-byte length prefix followed by DNS message
                    if (data.length < 2) {
                      DNSLogError(LogCategoryDNS, "Invalid TCP DNS query - too short");
                      // TCP flow will be cleaned up after processing
                      [flow closeReadWithError:nil];
                      [flow closeWriteWithError:nil];
                      return;
                    }

                    // Extract length and DNS query
                    uint16_t length = ntohs(*(uint16_t*)data.bytes);
                    if (data.length < 2 + length) {
                      DNSLogError(LogCategoryDNS, "Invalid TCP DNS query - length mismatch");
                      // TCP flow will be cleaned up after processing
                      [flow closeReadWithError:nil];
                      [flow closeWriteWithError:nil];
                      return;
                    }

                    NSData* dnsQuery = [data subdataWithRange:NSMakeRange(2, length)];

                    // Extract transaction ID to map this TCP flow BEFORE processing
                    NSData* transactionID = [DNSPacket extractTransactionID:dnsQuery];
                    if (transactionID) {
                      [strongSelf.tcpFlows setObject:flow forKey:transactionID];

                      // Also add to query timestamps for cleanup
                      [strongSelf.queryTimestamps setObject:[NSDate date] forKey:transactionID];
                    }

                    // Process the DNS query (pass nil for UDP flow since this is TCP)
                    NWEndpoint* remoteEndpoint = flow.remoteEndpoint;
                    [strongSelf processDNSQuery:dnsQuery fromFlow:nil fromEndpoint:remoteEndpoint];
                  }];
                }];
}

- (BOOL)handleNewUDPFlow:(NEAppProxyUDPFlow*)flow
    initialRemoteFlowEndpoint:(nw_endpoint_t)remoteEndpoint {
  char* address_string = nw_endpoint_copy_address_string(remoteEndpoint);
  DNSLogDebug(LogCategoryDNS, "Handling new UDP flow from %{public}s", address_string ?: "unknown");
  if (address_string)
    free(address_string);

  // CRITICAL FIX: Open the UDP flow before using it
  // This is required to negotiate the socket receive window
  [flow openWithLocalFlowEndpoint:nil
                completionHandler:^(NSError* _Nullable error) {
                  if (error) {
                    DNSLogError(LogCategoryDNS, "Failed to open UDP flow: %{public}@",
                                error.localizedDescription);
                    dispatch_async(self.dnsQueue, ^{
                      [self.closedFlows addObject:flow];
                      [self.activeFlows removeObject:flow];
                    });
                    [flow closeReadWithError:nil];
                    [flow closeWriteWithError:nil];
                    return;
                  }

                  DNSLogInfo(LogCategoryDNS, "UDP flow opened successfully");

                  // Track this flow
                  dispatch_async(self.dnsQueue, ^{
                    [self.activeFlows addObject:flow];
                  });

                  // Start reading datagrams continuously
                  [self continuouslyReadDatagrams:flow fromEndpoint:remoteEndpoint];
                }];

  // Return YES to indicate we're handling this flow
  return YES;
}

- (void)continuouslyReadDatagrams:(NEAppProxyUDPFlow*)flow
                     fromEndpoint:(nw_endpoint_t)remoteEndpoint {
  __weak typeof(self) weakSelf = self;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  [flow readDatagramsWithCompletionHandler:^(NSArray<NSData*>* _Nullable datagrams,
                                             NSArray<NWEndpoint*>* _Nullable remoteEndpoints,
                                             NSError* _Nullable error) {
#pragma clang diagnostic pop
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    if (error) {
      DNSLogError(LogCategoryDNS, "Error reading datagrams: %{public}@",
                  error.localizedDescription);
      // Close the flow on error
      dispatch_async(strongSelf.dnsQueue, ^{
        [strongSelf.closedFlows addObject:flow];
        [strongSelf.activeFlows removeObject:flow];
      });
      [flow closeReadWithError:error];
      [flow closeWriteWithError:error];
      return;
    }

    if (datagrams && datagrams.count > 0) {
      DNSLogDebug(LogCategoryDNS, "Received %lu DNS queries", (unsigned long)datagrams.count);

      // Process each DNS query
      for (NSUInteger i = 0; i < datagrams.count; i++) {
        NSData* queryData = datagrams[i];
        NWEndpoint* endpoint = (i < remoteEndpoints.count) ? remoteEndpoints[i] : nil;

        dispatch_async(strongSelf.dnsQueue, ^{
          [strongSelf processDNSQueryWithQueuing:queryData fromFlow:flow fromEndpoint:endpoint];
        });
      }
    }

    // Track consecutive empty reads to prevent CPU spikes
    NSValue* flowKey = [NSValue valueWithNonretainedObject:flow];

    if (datagrams && datagrams.count > 0) {
      // Reset empty read counter when we get data
      [strongSelf.flowEmptyReadCounts removeObjectForKey:flowKey];

      // Re-arm immediately when actively receiving data
      dispatch_async(strongSelf.dnsQueue, ^{
        if ([strongSelf.activeFlows containsObject:flow]) {
          [strongSelf continuouslyReadDatagrams:flow fromEndpoint:remoteEndpoint];
        }
      });
    } else {
      // Increment empty read counter
      NSNumber* emptyCount = strongSelf.flowEmptyReadCounts[flowKey] ?: @0;
      NSInteger count = emptyCount.integerValue + 1;
      strongSelf.flowEmptyReadCounts[flowKey] = @(count);

      // CRITICAL FIX: More aggressive exponential backoff to prevent CPU spikes
      // Old: 10ms, 50ms, 100ms, 200ms, 500ms
      // New: 100ms, 500ms, 1s, 2s, 5s, 10s (10x increase)
      int64_t delayMs;
      if (count <= 1) {
        delayMs = 100;  // Was 10ms - too aggressive
      } else if (count <= 2) {
        delayMs = 500;  // Was 50ms
      } else if (count <= 3) {
        delayMs = 1000;  // Was 100ms
      } else if (count <= 4) {
        delayMs = 2000;  // Was 200ms
      } else if (count <= 5) {
        delayMs = 5000;  // Was capped at 500ms
      } else {
        delayMs = 10000;  // Cap at 10 seconds for idle flows
      }

      DNSLogDebug(LogCategoryDNS, "Empty read #%ld for flow, waiting %lldms before retry",
                  (long)count, delayMs);

      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayMs * NSEC_PER_MSEC)),
                     strongSelf.dnsQueue, ^{
                       if ([strongSelf.activeFlows containsObject:flow]) {
                         [strongSelf continuouslyReadDatagrams:flow fromEndpoint:remoteEndpoint];
                       }
                     });
    }
  }];
}

- (void)setupUpstreamConnections {
  // Pre-create connections to upstream DNS servers for better performance
  for (NSString* dnsServer in self.dnsServers) {
    [self getOrCreateUpstreamConnectionForServer:dnsServer];
  }
}

- (DNSUpstreamConnection*)getOrCreateUpstreamConnectionForServer:(NSString*)server {
  DNSUpstreamConnection* connection = self.upstreamConnections[server];

  if (!connection) {
    // Create new connection
    connection = [[DNSUpstreamConnection alloc] initWithServer:server];
    connection.delegate = self;
    self.upstreamConnections[server] = connection;
  }

  return connection;
}

@end
