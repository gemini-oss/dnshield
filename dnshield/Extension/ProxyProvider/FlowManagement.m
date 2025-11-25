#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/Cache.h>
#import <Rule/Precedence.h>
#import "AuditLogger.h"
#import "DNSPacket.h"
#import "Provider.h"
#import "ProxyProvider+Private.h"

#import "ProxyProvider+Cache.h"
#import "ProxyProvider+Helpers.h"
#import "ProxyProvider+Initialization.h"
#import "ProxyProvider+Migration.h"
#import "ProxyProvider+Telemetry.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@implementation ProxyProvider (FlowManagement)

#pragma mark - Flow Management

- (void)clearAllDNSFlows {
  DNSLogInfo(LogCategoryNetwork, "Clearing all DNS flows and connections");

  // Clear DNS cache immediately
  [self.dnsCache clearCache];

  // Clear all flow mappings and connections on the DNS queue
  dispatch_async(self.dnsQueue, ^{
    // Clear upstream connections
    for (DNSUpstreamConnection* conn in self.upstreamConnections.allValues) {
      [conn close];
    }
    [self.upstreamConnections removeAllObjects];

    // Clear flow tracking structures
    [self.queryToClientInfo removeAllObjects];
    [self.queryTimestamps removeAllObjects];

    // Properly close active flows before clearing
    for (NEAppProxyUDPFlow* flow in self.activeFlows) {
      [flow closeReadWithError:nil];
      [flow closeWriteWithError:nil];
    }
    [self.activeFlows removeAllObjects];

    // Clear TCP flows
    for (NEAppProxyTCPFlow* flow in [self.tcpFlows objectEnumerator]) {
      [flow closeReadWithError:nil];
      [flow closeWriteWithError:nil];
    }
    [self.tcpFlows removeAllObjects];

    // Clear closed flows tracking
    [self.closedFlows removeAllObjects];
    [self.flowEmptyReadCounts removeAllObjects];

    DNSLogInfo(LogCategoryNetwork, "All DNS flows and connections cleared");
  });
}

#pragma mark - DNS Query Queuing for Restart Transitions

- (void)enterTransitionMode {
  dispatch_async(self.transitionQueue, ^{
    if (!self.isInTransitionMode) {
      DNSLogInfo(LogCategoryDNS, "Entering DNS query transition mode - queries will be queued");
      self.isInTransitionMode = YES;
    }
  });
}

- (void)exitTransitionModeAndProcessQueue {
  dispatch_async(self.transitionQueue, ^{
    if (self.isInTransitionMode) {
      NSUInteger queuedCount = self.queuedQueries.count;
      DNSLogInfo(LogCategoryDNS, "Exiting transition mode - processing %lu queued queries",
                 (unsigned long)queuedCount);
      self.isInTransitionMode = NO;

      // Log queue metrics to telemetry
      if (queuedCount > 0) {
        [self.telemetry logExtensionLifecycleEvent:@"transition_queue_processed"
                                          metadata:@{
                                            @"queued_queries_count" : @(queuedCount)
                                          }];
      }

      // Process all queued queries
      NSArray* queries = [self.queuedQueries copy];
      [self.queuedQueries removeAllObjects];

      for (NSDictionary* queryInfo in queries) {
        NSData* queryData = queryInfo[@"queryData"];
        id flowObject = queryInfo[@"flow"];
        NEAppProxyUDPFlow* flow = [flowObject isKindOfClass:[NSNull class]] ? nil : flowObject;
        NWEndpoint* endpoint = queryInfo[@"endpoint"];

        dispatch_async(self.dnsQueue, ^{
          [self processDNSQuery:queryData fromFlow:flow fromEndpoint:endpoint];
        });
      }
    }
  });
}

- (BOOL)dnshield_isDNSCacheEnabled {
  BOOL isManaged = [self.preferenceManager isPreferenceManagedForKey:kDNShieldEnableDNSCache
                                                            inDomain:kDNShieldPreferenceDomain];
  if (isManaged) {
    NSNumber* managedPref =
        [self.preferenceManager preferenceValueForKey:kDNShieldEnableDNSCache
                                             inDomain:kDNShieldPreferenceDomain];
    if ([managedPref respondsToSelector:@selector(boolValue)]) {
      return [managedPref boolValue];
    }
    return NO;
  }

  NSNumber* userPref = [self.preferenceManager preferenceValueForKey:kDNShieldUserCanAdjustCache
                                                            inDomain:kDNShieldPreferenceDomain];
  if ([userPref respondsToSelector:@selector(boolValue)]) {
    return [userPref boolValue];
  }

  // Backward compatibility: fall back to legacy EnableDNSCache user preference if present
  NSNumber* legacyPref = [self.preferenceManager preferenceValueForKey:kDNShieldEnableDNSCache
                                                              inDomain:kDNShieldPreferenceDomain];
  if ([legacyPref respondsToSelector:@selector(boolValue)]) {
    return [legacyPref boolValue];
  }

  return NO;
}

- (void)processDNSQueryWithQueuing:(NSData*)queryData
                          fromFlow:(NEAppProxyUDPFlow*)clientFlow
                      fromEndpoint:(NWEndpoint*)clientEndpoint {
  // Check if we're in transition mode
  if (self.isInTransitionMode) {
    dispatch_async(self.transitionQueue, ^{
      if (self.isInTransitionMode) {
        // Queue the query for later processing
        NSDictionary* queryInfo = @{
          @"queryData" : queryData,
          @"flow" : clientFlow ?: [NSNull null],
          @"endpoint" : clientEndpoint,
          @"timestamp" : [NSDate date]
        };
        [self.queuedQueries addObject:queryInfo];

        // Limit queue size to prevent memory issues
        if (self.queuedQueries.count > 1000) {
          [self.queuedQueries removeObjectAtIndex:0];
          DNSLogError(LogCategoryDNS, "DNS query queue overflow - dropping oldest query");
        }

        DNSLogDebug(LogCategoryDNS, "Queued DNS query during transition (queue size: %lu)",
                    (unsigned long)self.queuedQueries.count);
        return;
      }
    });
    return;
  }

  // Not in transition mode, process normally
  [self processDNSQuery:queryData fromFlow:clientFlow fromEndpoint:clientEndpoint];
}

- (void)processDNSQuery:(NSData*)queryData
               fromFlow:(NEAppProxyUDPFlow*)clientFlow
           fromEndpoint:(NWEndpoint*)clientEndpoint {
  // Check network connectivity before processing DNS queries
  if (![self.networkReachability isReachable]) {
    DNSLogInfo(LogCategoryNetwork, "No network connectivity, handling DNS query offline");

    // Try to serve from cache first
    DNSQuery* query = [DNSPacket parseQuery:queryData error:nil];
    if (query) {
      // Check cache for offline response using the correct method
      NSData* cachedResponse = [self.dnsCache getCachedResponseForDomain:query.domain
                                                               queryType:query.queryType];
      if (cachedResponse) {
        DNSLogInfo(LogCategoryCache, "Serving cached response for %{public}@ during offline mode",
                   query.domain);
        [self sendResponse:cachedResponse toFlow:clientFlow endpoint:clientEndpoint];
        return;
      }
    }

    // No cache hit, send SERVFAIL response
    DNSLogInfo(LogCategoryCache,
               "No cached response available, sending SERVFAIL for offline query");
    NSData* servfailResponse = [DNSPacket createServerFailureResponse:queryData];
    [self sendResponse:servfailResponse toFlow:clientFlow endpoint:clientEndpoint];
    return;
  }

  // IMPORTANT: The clientEndpoint parameter is the *destination* (e.g., 8.8.8.8:53)
  // For VPN detection, we need to check if the flow originated from a VPN app
  // Since NEAppProxyUDPFlow doesn't expose source client info directly,
  // we'll skip VPN resolver detection for now and focus on caching

  // Log the destination endpoint for debugging
  DNSLogDebug(LogCategoryDNS, "Processing DNS query to destination: %{public}@",
              clientEndpoint.debugDescription);

  // VPN resolver detection disabled for UDP flows
  // The endpoint parameter is the destination (DNS server), not the source client
  // We'll rely on response content checking instead
  BOOL isFromVPNResolver = NO;

  // Parse DNS query
  NSError* error = nil;
  DNSQuery* query = [DNSPacket parseQuery:queryData error:&error];

  if (!query) {
    DNSLogError(LogCategoryDNS, "Failed to parse DNS query: %{public}@",
                error.localizedDescription);

    // Log failed query to telemetry
    [self.telemetry logDNSQueryEvent:@"[parse_error]"
                              action:DNSQueryActionFailed
                            metadata:@{
                              @"error_message" : error.localizedDescription ?: @"unknown",
                              @"dns_response_code" : @"FORMERR"
                            }];

    // Send format error response
    NSData* errorResponse = [DNSPacket createFormatErrorResponse:queryData];
    [self sendResponse:errorResponse toFlow:clientFlow endpoint:clientEndpoint];
    return;
  }

  DNSLogInfo(LogCategoryDNS, "DNS query for %{public}@ (type %d)", query.domain, query.queryType);

  // Check cache first (skip cache for VPN resolvers and if caching is disabled)
  NSData* cachedResponse = nil;
  BOOL cacheEnabled = [self dnshield_isDNSCacheEnabled];
  if (!isFromVPNResolver && cacheEnabled) {
    cachedResponse = [self.dnsCache getCachedResponseForDomain:query.domain
                                                     queryType:query.queryType];
    if (!cachedResponse) {
      DNSLogDebug(LogCategoryCache, "Cache miss for %{public}@ (type %d)", query.domain,
                  query.queryType);
    }
  } else {
    if (!cacheEnabled) {
      DNSLogDebug(LogCategoryCache, "DNS cache disabled - skipping cache lookup");
    } else if (isFromVPNResolver) {
      DNSLogDebug(LogCategoryCache, "Skipping cache lookup for VPN resolver query");
    }
  }
  if (cachedResponse) {
    DNSLogInfo(LogCategoryCache, "Cache hit for %{public}@ (type %d)", query.domain,
               query.queryType);

    // Log cache hit to telemetry
    [self.telemetry logDNSQueryEvent:query.domain
                              action:DNSQueryActionAllowed
                            metadata:@{
                              @"cache_hit" : @YES,
                              @"query_type" : [self queryTypeToString:query.queryType],
                              @"response_time_ms" : @0.1  // Cache hits are very fast
                            }];

    // Update the cached response with the current query's transaction ID
    NSMutableData* updatedResponse = [cachedResponse mutableCopy];
    if (updatedResponse.length >= 2 && queryData.length >= 2) {
      // Copy transaction ID from query to response
      [updatedResponse replaceBytesInRange:NSMakeRange(0, 2) withBytes:queryData.bytes length:2];
    }

    [self sendResponse:updatedResponse toFlow:clientFlow endpoint:clientEndpoint];
    return;
  }

  // Record query statistics for cache optimization
  [self.ruleDatabase recordQueryForDomain:query.domain];

  // Start timing for performance stats
  NSDate* lookupStart = [NSDate date];

  // Check rules in database (with cache)
  DNSRuleAction cachedAction = [self.ruleCache actionForDomain:query.domain];
  BOOL isWhitelisted = NO;
  BOOL shouldBlock = NO;

  if (cachedAction != DNSRuleActionUnknown) {
    // Cache hit
    isWhitelisted = (cachedAction == DNSRuleActionAllow);
    shouldBlock = (cachedAction == DNSRuleActionBlock);
    NSTimeInterval lookupTime = [[NSDate date] timeIntervalSinceDate:lookupStart];
    [[DNSCacheStats sharedStats] recordHit:lookupTime];
  } else {
    // Cache miss - check database with precedence resolution
    NSArray<DNSRule*>* matchingRules = [RulePrecedence allMatchingRulesForDomain:query.domain
                                                                      inDatabase:self.ruleDatabase];
    NSTimeInterval lookupTime = [[NSDate date] timeIntervalSinceDate:lookupStart];
    [[DNSCacheStats sharedStats] recordMiss:lookupTime];

    if (matchingRules.count > 0) {
      // Resolve conflicts between multiple matching rules
      DNSRuleAction resolvedAction = [RulePrecedence resolveConflictBetweenRules:matchingRules
                                                                       forDomain:query.domain];
      isWhitelisted = (resolvedAction == DNSRuleActionAllow);
      shouldBlock = (resolvedAction == DNSRuleActionBlock);

      // Update cache with adaptive TTL
      NSUInteger queryCount = [self.ruleDatabase queryCountForDomain:query.domain];
      NSTimeInterval adaptiveTTL = [self calculateAdaptiveTTL:queryCount];
      [self.ruleCache setAction:resolvedAction forDomain:query.domain withTTL:adaptiveTTL];
    }
  }

  // Check whitelist first (never block whitelisted domains)
  if (isWhitelisted) {
    DNSLogInfo(LogCategoryDNS, "Domain %{public}@ is whitelisted - allowing", query.domain);

    // Log whitelisted query to telemetry
    [self.telemetry
        logDNSQueryEvent:query.domain
                  action:DNSQueryActionAllowed
                metadata:@{
                  @"rule_source" : @"whitelist",
                  @"query_type" : [self queryTypeToString:query.queryType],
                  @"cache_hit" : @(cachedAction != DNSRuleActionUnknown),
                  @"response_time_ms" : @([[NSDate date] timeIntervalSinceDate:lookupStart] * 1000)
                }];

    self.allowedCount++;

    // Store flow mapping for response
    NSData* transactionID = [DNSPacket extractTransactionID:queryData];
    NSMutableDictionary* clientInfo = [NSMutableDictionary dictionary];
    if (clientFlow) {
      clientInfo[@"flow"] = clientFlow;
    }
    clientInfo[@"endpoint"] =
        clientEndpoint ?: [self createLegacyEndpointWithHostname:@"127.0.0.1" port:@"53"];
    if (clientEndpoint && [clientEndpoint isKindOfClass:[NWHostEndpoint class]]) {
      NWHostEndpoint* hostEndpoint = (NWHostEndpoint*)clientEndpoint;
      NSString* hostname = hostEndpoint.hostname;
      if (hostname.length > 0) {
        clientInfo[@"original_resolver"] = hostname;
      }
      NSString* port = hostEndpoint.port;
      if (port.length > 0) {
        clientInfo[@"original_resolver_port"] = port;
      }
    } else if (clientEndpoint) {
      NSString* resolvedIP = [self extractIPFromEndpoint:clientEndpoint.debugDescription];
      if (resolvedIP.length > 0) {
        clientInfo[@"original_resolver"] = resolvedIP;
      }
    }
    [self.queryToClientInfo setObject:clientInfo forKey:transactionID];
    [self.queryTimestamps setObject:[NSDate date] forKey:transactionID];

    // Forward to upstream DNS
    [self forwardDNSQuery:queryData];

    // Update statistics
    dispatch_async(dispatch_get_main_queue(), ^{
      [self.preferenceManager.sharedDefaults setInteger:self.allowedCount forKey:@"AllowedCount"];
      [self.preferenceManager.sharedDefaults synchronize];
    });
    return;
  }

  // Domain check already performed above
  DNSLogInfo(LogCategoryDNS, "Domain check for %{public}@: blocked=%d, rule_count=%lu",
             query.domain, shouldBlock, (unsigned long)self.ruleDatabase.ruleCount);

  if (shouldBlock) {
    self.blockedCount++;
    DNSLogInfo(LogCategoryDNS, "BLOCKED: %{public}@", query.domain);

    // Get process information
    NSString* processName = @"unknown";
    NSString* bundleId = @"unknown";
    if ([clientFlow respondsToSelector:@selector(metaData)]) {
      NEFlowMetaData* metadata = [clientFlow performSelector:@selector(metaData)];
      if ([metadata respondsToSelector:@selector(sourceAppSigningIdentifier)]) {
        bundleId = [metadata performSelector:@selector(sourceAppSigningIdentifier)] ?: @"unknown";
        processName = bundleId;
      }
    }

    // Get the rule that matched
    DNSRule* matchedRule = [self.ruleDatabase ruleForDomain:query.domain];

    // Extract source IP if available and anonymize it
    NSString* sourceIP = nil;
    if (clientEndpoint) {
      NSString* endpointStr = clientEndpoint.debugDescription;
      NSArray* parts = [endpointStr componentsSeparatedByString:@":"];
      if (parts.count >= 2) {
        sourceIP = [self.telemetry anonymizeIP:parts[0]];
      }
    }

    // Anonymize domain based on privacy settings
    NSNumber* privacyLevel =
        [[PreferenceManager sharedManager] preferenceForKey:kDNShieldTelemetryPrivacyLevel];
    NSString* loggedDomain = query.domain;
    if (privacyLevel && [privacyLevel integerValue] > 0) {
      loggedDomain = [self.telemetry anonymizeDomain:query.domain
                                        privacyLevel:[privacyLevel integerValue]];
    }

    // Log blocked query to telemetry
    NSMutableDictionary* telemetryData = [@{
      @"rule_id" :
          [NSString stringWithFormat:@"%@_%ld", matchedRule.domain, (long)matchedRule.priority],
      @"rule_source" : [self ruleSourceToString:matchedRule.source],
      @"threat_category" : [self categorizeThreat:query.domain],
      @"client_app" : bundleId,
      @"process_name" : processName,
      @"query_type" : [self queryTypeToString:query.queryType],
      @"cache_hit" : @(cachedAction != DNSRuleActionUnknown),
      @"response_time_ms" : @([[NSDate date] timeIntervalSinceDate:lookupStart] * 1000),
      @"dns_response_code" :
              (query.queryType == DNSQueryTypeA || query.queryType == DNSQueryTypeAAAA)
          ? @"NOERROR"
          : @"NXDOMAIN"
    } mutableCopy];

    if (sourceIP) {
      telemetryData[@"source_ip"] = sourceIP;
    }

    [self.telemetry logDNSQueryEvent:loggedDomain
                              action:DNSQueryActionBlocked
                            metadata:telemetryData];

    [self.wsServer notifyBlockedDomain:query.domain process:processName timestamp:[NSDate date]];

    NSData* blockedResponse = nil;

    // Return appropriate response based on query type
    if (query.queryType == DNSQueryTypeA) {
      // Return 127.0.0.1 for A queries
      blockedResponse = [DNSPacket createBlockedAResponse:queryData];
    } else if (query.queryType == DNSQueryTypeAAAA) {
      // Return empty response for AAAA queries
      blockedResponse = [DNSPacket createBlockedAAAAResponse:queryData];
    } else {
      // Return NXDOMAIN for other types
      blockedResponse = [DNSPacket createNXDOMAINResponse:queryData];
    }

    [self sendResponse:blockedResponse toFlow:clientFlow endpoint:clientEndpoint];

  } else {
    self.allowedCount++;
    DNSLogInfo(LogCategoryDNS, "ALLOWED: %{public}@", query.domain);

    // Get process information if available
    NSString* bundleId = @"unknown";
    if ([clientFlow respondsToSelector:@selector(metaData)]) {
      NEFlowMetaData* metadata = [clientFlow performSelector:@selector(metaData)];
      if ([metadata respondsToSelector:@selector(sourceAppSigningIdentifier)]) {
        bundleId = [metadata performSelector:@selector(sourceAppSigningIdentifier)] ?: @"unknown";
      }
    }

    // Anonymize domain based on privacy settings
    NSNumber* privacyLevel =
        [[PreferenceManager sharedManager] preferenceForKey:@"TelemetryPrivacyLevel"];
    NSString* loggedDomain = query.domain;
    if (privacyLevel && [privacyLevel integerValue] > 0) {
      loggedDomain = [self.telemetry anonymizeDomain:query.domain
                                        privacyLevel:[privacyLevel integerValue]];
    }

    // Log allowed query to telemetry
    [self.telemetry
        logDNSQueryEvent:loggedDomain
                  action:DNSQueryActionAllowed
                metadata:@{
                  @"rule_source" : @"default_allow",
                  @"client_app" : bundleId,
                  @"query_type" : [self queryTypeToString:query.queryType],
                  @"cache_hit" : @(cachedAction != DNSRuleActionUnknown),
                  @"response_time_ms" : @([[NSDate date] timeIntervalSinceDate:lookupStart] * 1000)
                }];

    // Store flow mapping for response
    NSData* transactionID = [DNSPacket extractTransactionID:queryData];
    NSMutableDictionary* clientInfo = [NSMutableDictionary dictionary];
    if (clientFlow) {
      clientInfo[@"flow"] = clientFlow;
    }
    clientInfo[@"endpoint"] =
        clientEndpoint ?: [self createLegacyEndpointWithHostname:@"127.0.0.1" port:@"53"];
    [self.queryToClientInfo setObject:clientInfo forKey:transactionID];
    [self.queryTimestamps setObject:[NSDate date] forKey:transactionID];

    // Forward to upstream DNS
    DNSLogInfo(LogCategoryDNS, "Forwarding %{public}@ query for %{public}@ to upstream DNS",
               [self queryTypeToString:query.queryType], query.domain);
    [self forwardDNSQuery:queryData];
  }
}

- (void)processUpstreamResponse:(NSData*)responseData fromServer:(NSString*)server {
  // Extract transaction ID
  NSData* transactionID = [DNSPacket extractTransactionID:responseData];
  if (!transactionID) {
    DNSLogError(LogCategoryDNS, "Failed to extract transaction ID from response");
    return;
  }

  // Find the client info
  NSDictionary* clientInfo = [self.queryToClientInfo objectForKey:transactionID];
  if (!clientInfo) {
    DNSLogDebug(LogCategoryDNS, "No client info found for transaction ID from server %{public}@",
                server);
    return;
  }

  NEAppProxyUDPFlow* clientFlow = clientInfo[@"flow"];
  NWEndpoint* clientEndpoint = clientInfo[@"endpoint"];

  // Remove from mapping
  [self.queryToClientInfo removeObjectForKey:transactionID];
  [self.queryTimestamps removeObjectForKey:transactionID];

  // Parse response for domain name and TTL (for caching and logging)
  NSError* parseError = nil;
  DNSResponse* response = [DNSPacket parseResponse:responseData error:&parseError];
  NSString* domain = response ? response.domain : @"unknown";
  uint32_t ttl = response ? response.ttl : DEFAULT_TTL;

  if (response) {
    // Parse query type from original query if available
    NSString* queryType = @"unknown";
    if (response.answers.count > 0) {
      // Infer from response
      queryType = [response.answers.firstObject containsString:@":"] ? @"AAAA" : @"A";
    }
    DNSLogInfo(LogCategoryDNS,
               "Upstream response for %{public}@ (%{public}@) from %{public}@: %lu bytes, TTL: %u, "
               "answers: %lu",
               domain, queryType, server, (unsigned long)responseData.length, ttl,
               (unsigned long)response.answers.count);
  } else {
    DNSLogInfo(LogCategoryDNS,
               "Upstream response (unparseable) from %{public}@: %lu bytes, error: %{public}@",
               server, (unsigned long)responseData.length, parseError.localizedDescription);
  }

  // Check if response is too large for UDP
  if (responseData.length > 512) {
    DNSLogInfo(LogCategoryDNS, "DNS response size %lu exceeds standard UDP limit, may need TCP",
               (unsigned long)responseData.length);
  }

  // Cache the response if we successfully parsed it (skip caching for VPN responses)
  BOOL shouldCache = YES;
  uint32_t customTTL = 0;

  // Check domain-specific cache rules first
  NSDictionary* cacheRules =
      [self.preferenceManager preferenceValueForKey:kDNShieldDomainCacheRules
                                           inDomain:kDNShieldPreferenceDomain];
  if (cacheRules && response && response.domain) {
    NSDictionary* matchingRule = [self findMatchingCacheRule:response.domain inRules:cacheRules];
    if (matchingRule) {
      NSString* action = matchingRule[@"action"];
      if ([action isEqualToString:@"never"]) {
        shouldCache = NO;
        DNSLogInfo(LogCategoryCache, "Domain %{public}@ matched 'never' cache rule",
                   response.domain);
      } else if ([action isEqualToString:@"always"]) {
        shouldCache = YES;
        DNSLogInfo(LogCategoryCache, "Domain %{public}@ matched 'always' cache rule",
                   response.domain);
      } else if ([action isEqualToString:@"custom"] && matchingRule[@"ttl"]) {
        shouldCache = YES;
        customTTL = [matchingRule[@"ttl"] unsignedIntValue];
        DNSLogInfo(LogCategoryCache, "Domain %{public}@ matched 'custom' cache rule with TTL %u",
                   response.domain, customTTL);
      }
    }
  }

  // Check if the response is from a VPN resolver
  NSArray* vpnResolvers = [self.preferenceManager preferenceValueForKey:kDNShieldVPNResolvers
                                                               inDomain:kDNShieldPreferenceDomain];
  if (!vpnResolvers || vpnResolvers.count == 0) {
    // Default to CGNAT range used by Twingate and other VPNs (both IPv4 and IPv6)
    vpnResolvers = @[
      @"100.64.0.0/10",  // IPv4 CGNAT (100.64.0.0 to 100.127.255.255)
      @"fc00::/7",       // IPv6 ULA
      @"fd00::/8",       // IPv6 ULA subset
      @"fe80::/10"       // IPv6 Link-Local
    ];
  }

  for (NSString* resolver in vpnResolvers) {
    if ([self isIPAddress:server inCIDR:resolver]) {
      shouldCache = NO;
      DNSLogDebug(LogCategoryCache,
                  "Skipping cache for response from VPN resolver %{public}@ (matched %@)", server,
                  resolver);
      break;
    }
  }

  // Also check if the response contains CGNAT IPs (VPN private IPs)
  if (shouldCache && response && response.answers.count > 0) {
    for (NSString* answer in response.answers) {
      // Check if this answer is an IP address in CGNAT range
      if ([answer rangeOfString:@"."].location != NSNotFound) {  // IPv4 check
        for (NSString* vpnRange in vpnResolvers) {
          if ([self isIPAddress:answer inCIDR:vpnRange]) {
            shouldCache = NO;
            DNSLogInfo(
                LogCategoryCache,
                "Not caching response for %{public}@ - contains VPN IP %{public}@ in range %@",
                response.domain, answer, vpnRange);
            break;
          }
        }
        if (!shouldCache)
          break;
      }
    }
  }

  // Check if domain should bypass cache based on configuration
  if (shouldCache && response && response.domain) {
    // Check for auth domains that should never be cached
    NSArray* authDomainPatterns = @[
      @"okta.com", @"oktapreview.com", @"oktacdn.com", @"twingate.com", @"okta-emea.com",
      @"okta-gov.com", @"okta.mil", @"kerberos.okta.com", @"mtls.okta.com",
      @"awsglobalaccelerator.com", @"digicert.com"
    ];

    for (NSString* pattern in authDomainPatterns) {
      if ([response.domain hasSuffix:pattern]) {
        shouldCache = NO;
        DNSLogInfo(LogCategoryCache,
                   "Not caching response for %{public}@ - matches auth domain pattern %@",
                   response.domain, pattern);
        break;
      }
    }

    // Check explicit cache bypass list from preferences
    if (shouldCache) {
      NSArray* cacheBypassDomains =
          [self.preferenceManager preferenceValueForKey:kDNShieldCacheBypassDomains
                                               inDomain:kDNShieldPreferenceDomain];
      if (cacheBypassDomains) {
        for (NSString* bypassDomain in cacheBypassDomains) {
          if ([response.domain hasSuffix:bypassDomain]) {
            shouldCache = NO;
            DNSLogInfo(LogCategoryCache,
                       "Not caching response for %{public}@ - matches cache bypass domain %@",
                       response.domain, bypassDomain);
            break;
          }
        }
      }
    }
  }

  // Check if caching is enabled
  BOOL cacheEnabled = [self dnshield_isDNSCacheEnabled];

  if (cacheEnabled && shouldCache && response && response.responseCode == DNSResponseCodeNoError &&
      response.domain.length > 0) {
    // Use custom TTL if specified, otherwise use response TTL
    uint32_t ttlToUse = (customTTL > 0) ? customTTL : response.ttl;

    [self.dnsCache cacheResponse:responseData
                       forDomain:response.domain
                       queryType:response.queryType
                             ttl:ttlToUse];
    DNSLogDebug(LogCategoryCache, "Cached response for %{public}@ (type %d) with TTL %u%@",
                response.domain, response.queryType, ttlToUse,
                (customTTL > 0) ? @" (custom)" : @"");
  } else if (!cacheEnabled) {
    DNSLogDebug(LogCategoryCache, "Not caching response (DNS cache disabled)");
  } else if (!shouldCache) {
    DNSLogDebug(LogCategoryCache, "Not caching response (VPN resolver or contains VPN IPs)");
  } else {
    DNSLogDebug(LogCategoryCache, "Not caching response (parse failed or error response)");
  }

  // Forward response to client without modification
  [self sendResponse:responseData toFlow:clientFlow endpoint:clientEndpoint];
}

- (void)forwardDNSQuery:(NSData*)queryData {
  // Select DNS server (simple round-robin or failover could be implemented)
  NSString* dnsServer = self.dnsServers.firstObject;
  BOOL enforceOriginalResolver = NO;

  NSData* transactionID = [DNSPacket extractTransactionID:queryData];
  NSDictionary* clientInfo =
      transactionID ? [self.queryToClientInfo objectForKey:transactionID] : nil;

  if (clientInfo) {
    NSString* preferredResolver = clientInfo[@"original_resolver"];
    if (preferredResolver.length > 0) {
      dnsServer = preferredResolver;
      enforceOriginalResolver = YES;
      DNSLogDebug(LogCategoryNetwork,
                  "Using original resolver %{public}@ captured from client flow",
                  preferredResolver);
      if (![self.dnsServers containsObject:preferredResolver]) {
        NSMutableArray<NSString*>* updatedServers =
            [NSMutableArray arrayWithObject:preferredResolver];
        for (NSString* existing in self.dnsServers) {
          if (![existing isEqualToString:preferredResolver]) {
            [updatedServers addObject:existing];
          }
        }
        self.dnsServers = [updatedServers copy];
      }
    }
  }

  // DNS Chain Preservation: Check if this query came from a DNS server
  // This fixes VPN DNS resolution (Twingate, Tailscale, etc.)
  NSNumber* preservationSetting =
      [self.preferenceManager preferenceValueForKey:kDNShieldEnableDNSChainPreservation
                                           inDomain:kDNShieldPreferenceDomain];
  BOOL enableChainPreservation = YES;  // Default to YES

  if (preservationSetting != nil) {
    enableChainPreservation = [preservationSetting boolValue];
  }

  DNSLogInfo(LogCategoryNetwork, "DNS chain preservation enabled: %{public}@ (setting: %{public}@)",
             enableChainPreservation ? @"YES" : @"NO",
             preservationSetting ? [preservationSetting description] : @"nil/default");

  if (enableChainPreservation && clientInfo) {
    NWEndpoint* clientEndpoint = clientInfo[@"endpoint"];
    NSString* endpointStr = clientEndpoint.debugDescription;

    // Check if source port is 53 (DNS server) or from VPN resolver
    BOOL shouldPreserveChain = NO;
    NSString* sourceIP = nil;

    if ([endpointStr containsString:@":53"]) {
      shouldPreserveChain = YES;
    } else {
      // Check if this is from a VPN resolver
      NSArray* vpnResolvers =
          [self.preferenceManager preferenceValueForKey:kDNShieldVPNResolvers
                                               inDomain:kDNShieldPreferenceDomain];
      if (!vpnResolvers || vpnResolvers.count == 0) {
        // Default to CGNAT range used by Twingate and other VPNs (both IPv4 and IPv6)
        vpnResolvers = @[
          @"100.64.0.0/10",  // IPv4 CGNAT (100.64.0.0 to 100.127.255.255)
          @"fc00::/7",       // IPv6 ULA
          @"fd00::/8",       // IPv6 ULA subset
          @"fe80::/10"       // IPv6 Link-Local
        ];
      }

      // Extract IP from endpoint
      NSString* clientIP = [self extractIPFromEndpoint:endpointStr];

      for (NSString* resolver in vpnResolvers) {
        if ([self isIPAddress:clientIP inCIDR:resolver]) {
          shouldPreserveChain = YES;
          DNSLogInfo(LogCategoryNetwork,
                     "DNS chain preservation: Query from VPN resolver %@ (matched %@)", clientIP,
                     resolver);
          break;
        }
      }
    }

    if (shouldPreserveChain) {
      // Extract source IP from endpoint string (format: "IP:port")
      NSArray* parts = [endpointStr componentsSeparatedByString:@":"];
      if (parts.count >= 2) {
        sourceIP = parts[0];
        DNSLogInfo(
            LogCategoryNetwork,
            "DNS chain preservation: Query from DNS server %@, forwarding back to preserve chain",
            sourceIP);
        dnsServer = sourceIP;
        enforceOriginalResolver = YES;
      }
    }
  }

  if (dnsServer.length == 0) {
    DNSLogError(LogCategoryNetwork,
                "No upstream DNS server resolved for query; falling back to 1.1.1.1");
    dnsServer = @"1.1.1.1";
  }

  DNSUpstreamConnection* connection = [self getOrCreateUpstreamConnectionForServer:dnsServer];

  if (!connection || !connection.isConnected) {
    NSString* requestedServer = dnsServer;

    if (!enforceOriginalResolver && self.dnsServers.count > 1) {
      for (NSString* candidate in self.dnsServers) {
        if (![candidate isEqualToString:requestedServer]) {
          dnsServer = candidate;
          connection = [self getOrCreateUpstreamConnectionForServer:dnsServer];
          if (connection && connection.isConnected) {
            DNSLogInfo(LogCategoryNetwork,
                       "Failing over DNS query to alternate upstream server %{public}@", dnsServer);
            break;
          }
        }
      }
    }

    if (!connection || !connection.isConnected) {
      NSDate* queryTime = self.queryTimestamps[transactionID];
      NSString* retryTarget = dnsServer ?: requestedServer;

      if (queryTime && [[NSDate date] timeIntervalSinceDate:queryTime] > 2.0) {
        DNSLogError(
            LogCategoryNetwork,
            "DNS query timeout - upstream connection %{public}@ unavailable after 2 seconds",
            retryTarget);
        [self sendServerFailureForTransactionID:transactionID];
        return;
      }

      if (enforceOriginalResolver) {
        DNSLogInfo(
            LogCategoryNetwork,
            "Original resolver %{public}@ not yet ready; preserving chain and retrying in 500ms",
            retryTarget);
      } else {
        DNSLogInfo(LogCategoryNetwork,
                   "Upstream connection %{public}@ not ready yet, retrying query in 500ms",
                   retryTarget);
      }

      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), self.dnsQueue,
                     ^{
                       if ([self.queryToClientInfo objectForKey:transactionID]) {
                         [self forwardDNSQuery:queryData];
                       }
                     });
      return;
    }
  }

  DNSLogDebug(LogCategoryNetwork, "Forwarding DNS query to upstream server: %{public}@", dnsServer);
  // Send query to upstream
  [connection sendQuery:queryData];
}

- (void)sendResponse:(NSData*)response
              toFlow:(NEAppProxyUDPFlow*)flow
            endpoint:(NWEndpoint*)endpoint {
  // Check if this is a TCP flow response
  if (!flow) {
    // Extract transaction ID from response
    NSData* transactionID = [DNSPacket extractTransactionID:response];
    if (transactionID) {
      NEAppProxyTCPFlow* tcpFlow = [self.tcpFlows objectForKey:transactionID];
      if (tcpFlow) {
        DNSLogDebug(LogCategoryDNS, "Found TCP flow for transaction ID, sending TCP response");
        // Handle TCP response
        // TCP DNS format: prepend 2-byte length
        uint16_t length = htons(response.length);
        NSMutableData* tcpResponse = [NSMutableData dataWithBytes:&length length:2];
        [tcpResponse appendData:response];

        [tcpFlow writeData:tcpResponse
            withCompletionHandler:^(NSError* _Nullable error) {
              if (error) {
                DNSLogError(LogCategoryDNS, "Failed to write TCP DNS response: %{public}@",
                            error.localizedDescription);
              } else {
                DNSLogDebug(LogCategoryDNS, "Successfully sent TCP DNS response");
              }
              // Close the TCP flow after sending response
              [tcpFlow closeReadWithError:nil];
              [tcpFlow closeWriteWithError:nil];
            }];

        // Remove the TCP flow from mapping
        [self.tcpFlows removeObjectForKey:transactionID];
        [self.queryTimestamps removeObjectForKey:transactionID];
        return;
      } else {
        DNSLogError(
            LogCategoryDNS,
            "No TCP flow found for transaction ID: %{public}@. This may occur if the flow was "
            "already closed (e.g., due to timeout, cleanup, or duplicate response), or if there is "
            "a logic error. Investigate if this is expected in the current context.",
            [transactionID debugDescription]);
      }
    } else {
      DNSLogError(LogCategoryDNS, "Failed to extract transaction ID from DNS response");
    }
  }

  // Ensure flow is still open before sending
  if (!flow) {
    DNSLogError(LogCategoryDNS, "Cannot send DNS response - flow is nil");
    return;
  }

  // Check if flow was already closed
  if ([self.closedFlows containsObject:flow]) {
    DNSLogDebug(LogCategoryDNS, "Skipping DNS response - flow was already closed");
    return;
  }

  // Check if flow is still in active set
  if (![self.activeFlows containsObject:flow]) {
    DNSLogDebug(LogCategoryDNS, "Skipping DNS response - flow is no longer active");
    return;
  }

  // Log the response details for debugging
  DNSLogDebug(LogCategoryDNS, "Sending DNS response of %lu bytes", (unsigned long)response.length);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  DNSLogDebug(LogCategoryDNS, "Flow local endpoint: %{public}@",
              flow.localEndpoint.debugDescription);
#pragma clang diagnostic pop
  DNSLogDebug(LogCategoryDNS, "Remote endpoint: %{public}@", endpoint.debugDescription);

  // Check response size
  if (response.length > 512) {
    DNSLogInfo(LogCategoryDNS, "Warning: DNS response size %lu exceeds standard UDP limit",
               (unsigned long)response.length);

    // For large responses, create a truncated response
    response = [self createTruncatedResponse:response];
    DNSLogInfo(LogCategoryDNS, "Created truncated response of %lu bytes",
               (unsigned long)response.length);
  }

  // CRITICAL FIX: Try with the original endpoint parameter
  DNSLogInfo(LogCategoryDNS, "Attempting to send response with endpoint: %{public}@",
             endpoint.debugDescription);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  [flow writeDatagrams:@[ response ]
        sentByEndpoints:@[ endpoint ]
      completionHandler:^(NSError* _Nullable error) {
#pragma clang diagnostic pop
        if (error) {
          // Check if the error is because the flow was closed
          if ([error.localizedDescription containsString:@"flow is closed"] ||
              [error.localizedDescription containsString:@"not connected"]) {
            // Flow was closed by the system - this is expected in some cases
            DNSLogDebug(LogCategoryDNS,
                        "Flow was closed before response could be sent (size: %lu bytes)",
                        (unsigned long)response.length);

            // Mark flow as closed
            dispatch_async(self.dnsQueue, ^{
              [self.closedFlows addObject:flow];
              [self.activeFlows removeObject:flow];
            });
          } else {
            // Unexpected error
            DNSLogError(LogCategoryDNS,
                        "Failed to send DNS response: %{public}@ (response size: %lu)",
                        error.localizedDescription, (unsigned long)response.length);
          }
        } else {
          DNSLogDebug(LogCategoryDNS, "DNS response sent successfully");

          // DO NOT close the flow here - let the system handle flow lifecycle
          // The flow will be closed by the system when appropriate
        }
      }];
}

- (NSData*)createTruncatedResponse:(NSData*)response {
  if (response.length < 12) {
    return response;  // Too small to truncate
  }

  // Create a truncated response with TC bit set
  NSMutableData* truncated =
      [NSMutableData dataWithData:[response subdataWithRange:NSMakeRange(0, 12)]];
  uint8_t* bytes = truncated.mutableBytes;

  // Set TC (truncation) bit
  bytes[2] |= 0x02;

  // Clear answer, authority, and additional counts
  bytes[6] = 0;
  bytes[7] = 0;  // Answer count
  bytes[8] = 0;
  bytes[9] = 0;  // Authority count
  bytes[10] = 0;
  bytes[11] = 0;  // Additional count

  return truncated;
}

- (NSData*)createMinimalTruncatedResponse:(NSData*)response {
  if (response.length < 2) {
    return response;
  }

  // Create minimal 12-byte response with just the header
  uint8_t minimal[12];
  memset(minimal, 0, 12);

  // Copy transaction ID
  memcpy(minimal, response.bytes, 2);

  // Set response bit and truncation bit
  minimal[2] = 0x81;  // QR=1, OPCODE=0, AA=0, TC=1, RD=1
  minimal[3] = 0x80;  // RA=1, Z=0, RCODE=0

  return [NSData dataWithBytes:minimal length:12];
}

- (void)cleanupStuckQueries {
  dispatch_async(self.dnsQueue, ^{
    NSDate* now = [NSDate date];
    NSMutableArray<NSData*>* expiredQueries = [NSMutableArray new];

    // Find queries older than 5 seconds
    for (NSData* transactionID in self.queryTimestamps) {
      NSDate* timestamp = self.queryTimestamps[transactionID];
      if ([now timeIntervalSinceDate:timestamp] > 5.0) {
        [expiredQueries addObject:transactionID];
      }
    }

    // Also cleanup closed flows that are no longer in active flows
    NSMutableSet<NEAppProxyUDPFlow*>* flowsToRemove = [NSMutableSet new];
    for (NEAppProxyUDPFlow* flow in self.closedFlows) {
      if (![self.activeFlows containsObject:flow]) {
        [flowsToRemove addObject:flow];
      }
    }

    if (flowsToRemove.count > 0) {
      DNSLogDebug(LogCategoryDNS, "Removing %lu closed flows from tracking",
                  (unsigned long)flowsToRemove.count);
      [self.closedFlows minusSet:flowsToRemove];
    }

    // Clean up expired queries
    for (NSData* transactionID in expiredQueries) {
      DNSLogDebug(LogCategoryDNS, "Cleaning up stuck DNS query (transaction ID: %{public}@)",
                  [transactionID debugDescription]);

      // Send server failure response to client
      NSDictionary* clientInfo = [self.queryToClientInfo objectForKey:transactionID];
      if (clientInfo && transactionID.length >= 2) {
        // Create a minimal server failure response
        uint8_t response[12];
        memcpy(response, transactionID.bytes, 2);  // Transaction ID
        response[2] = 0x81;                        // QR=1, OPCODE=0, AA=0, TC=0, RD=1
        response[3] = 0x82;                        // RA=1, Z=0, RCODE=2 (Server failure)
        memset(&response[4], 0, 8);                // Clear counts

        NSData* errorResponse = [NSData dataWithBytes:response length:12];
        [self sendResponse:errorResponse
                    toFlow:clientInfo[@"flow"]
                  endpoint:clientInfo[@"endpoint"]];
      }

      // Remove from tracking
      [self.queryToClientInfo removeObjectForKey:transactionID];
      [self.queryTimestamps removeObjectForKey:transactionID];

      // Also clean up any associated TCP flow
      NEAppProxyTCPFlow* tcpFlow = [self.tcpFlows objectForKey:transactionID];
      if (tcpFlow) {
        DNSLogDebug(LogCategoryDNS, "Cleaning up stuck TCP flow");
        [tcpFlow closeReadWithError:nil];
        [tcpFlow closeWriteWithError:nil];
        [self.tcpFlows removeObjectForKey:transactionID];
      }
    }

    if (expiredQueries.count > 0) {
      DNSLogInfo(LogCategoryDNS, "Cleaned up %lu stuck DNS queries",
                 (unsigned long)expiredQueries.count);
    }
  });
}

#pragma clang diagnostic pop

@end
