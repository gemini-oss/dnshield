#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Common/LoggingUtils.h>
#import <Rule/Manager+Manifest.h>
#import <Rule/RuleSet.h>

#import "DNSCacheStats.h"
#import "Provider.h"
#import "ProxyProvider+Private.h"
#import "ProxyProvider+XPC.h"

@implementation ProxyProvider (XPC)

#pragma mark - XPC Communication

- (void)startXPCListener {
  // Get the mach service name from the Info.plist
  NSDictionary* networkExtConfig =
      [[NSBundle mainBundle] objectForInfoDictionaryKey:@"NetworkExtension"];
  NSString* machServiceName = networkExtConfig[@"NEMachServiceName"];

  if (!machServiceName) {
    // Fallback to app group (required for system extensions)
    machServiceName = kDNShieldAppGroup;
  }

  DNSLogInfo(LogCategoryDNS, "Attempting to create XPC listener with service: %{public}@",
             machServiceName);

  @try {
    self.xpcListener = [[NSXPCListener alloc] initWithMachServiceName:machServiceName];
    self.xpcListener.delegate = self;
    [self.xpcListener resume];

    DNSLogInfo(LogCategoryDNS, "XPC listener started successfully with service: %{public}@",
               machServiceName);
  } @catch (NSException* exception) {
    DNSLogError(LogCategoryDNS, "Failed to start XPC listener: %{public}@", exception.reason);

    // Try anonymous listener as fallback
    DNSLogInfo(LogCategoryDNS, "Attempting to use anonymous XPC listener");
    self.xpcListener = [NSXPCListener anonymousListener];
    self.xpcListener.delegate = self;
    [self.xpcListener resume];

    DNSLogInfo(LogCategoryDNS, "Anonymous XPC listener started, endpoint: %{public}@",
               self.xpcListener.endpoint);
  }
}

- (BOOL)listener:(NSXPCListener*)listener
    shouldAcceptNewConnection:(NSXPCConnection*)newConnection {
  DNSLogInfo(LogCategoryDNS, "New XPC connection request received from PID: %d",
             newConnection.processIdentifier);

  // Use modern code signing requirement validation
  @try {
    // Build a requirement that accepts our current app plus trusted helpers
    NSString* requirement = [NSString
        stringWithFormat:@"(identifier \"%@\" or identifier \"%@\" or identifier "
                         @"\"dnshield-ctl\" or identifier \"dnshield-xpc\" or identifier "
                         @"\"dnshield-daemon\") and anchor apple generic and certificate "
                         @"leaf[subject.OU] = \"%@\"",
                         kDefaultAppBundleID, kDNShieldPreferenceDomain, kDNShieldTeamIdentifier];

    // Set the code signing requirement on the connection
    // This is the modern, recommended approach for macOS 13+
    [newConnection setCodeSigningRequirement:requirement];

    DNSLogInfo(LogCategoryDNS, "Code signing requirement set successfully for PID %d",
               newConnection.processIdentifier);
  } @catch (NSException* exception) {
    DNSLogError(LogCategoryDNS, "Failed to set code signing requirement for PID %d: %@",
                newConnection.processIdentifier, exception.reason);
    return NO;
  }

  // Configure the connection
  newConnection.exportedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(XPCExtensionProtocol)];
  newConnection.exportedObject = self;

  // Track the connection
  [self.activeXPCConnections addObject:newConnection];

  __weak typeof(self) weakSelf = self;
  __weak NSXPCConnection* weakConnection = newConnection;

  newConnection.interruptionHandler = ^{
    DNSLogInfo(LogCategoryDNS, "XPC connection interrupted");
  };

  newConnection.invalidationHandler = ^{
    DNSLogInfo(LogCategoryDNS, "XPC connection invalidated");
    dispatch_async(dispatch_get_main_queue(), ^{
      [weakSelf.activeXPCConnections removeObject:weakConnection];
    });
  };

  [newConnection resume];

  DNSLogInfo(LogCategoryDNS, "XPC connection accepted and resumed from PID: %d (total: %lu)",
             newConnection.processIdentifier, (unsigned long)self.activeXPCConnections.count);

  return YES;
}

#pragma mark - XPCExtensionProtocol

- (void)updateBlockedDomains:(NSArray<NSString*>*)domains
           completionHandler:(void (^)(BOOL success))completion {
  DNSLogInfo(LogCategoryDNS, "Extension updateBlockedDomains is deprecated. Use "
                             "addUserBlockedDomain/removeUserBlockedDomain instead.");
  if (completion) {
    completion(NO);
  }
}

- (void)updateDNSServers:(NSArray<NSString*>*)servers
       completionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    self.dnsServers = servers;

    // Save to shared defaults
    [self.preferenceManager.sharedDefaults setObject:servers forKey:@"DNSServers"];

    // Close existing upstream connections
    for (DNSUpstreamConnection* conn in self.upstreamConnections.allValues) {
      [conn close];
    }
    [self.upstreamConnections removeAllObjects];

    DNSLogInfo(LogCategoryConfiguration, "Updated DNS servers: %{public}@",
               [servers componentsJoinedByString:@", "]);

    if (completion) {
      completion(YES);
    }
  });
}

- (void)getStatisticsWithCompletionHandler:(void (^)(NSDictionary* _Nullable stats))completion {
  dispatch_async(self.dnsQueue, ^{
    NSDictionary* stats = @{
      @"blockedCount" : @(self.blockedCount),
      @"allowedCount" : @(self.allowedCount),
      @"blockedDomains" : @(self.ruleDatabase.ruleCount),
      @"cacheSize" : @(self.dnsCache.cacheSize),
      @"cacheHitRate" : @(self.dnsCache.hitRate),
      @"cacheHits" : @(self.dnsCache.hitCount),
      @"cacheMisses" : @(self.dnsCache.missCount)
    };

    if (completion) {
      completion(stats);
    }
  });
}

- (void)clearCacheWithCompletionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    [self.dnsCache clearCache];
    DNSLogInfo(LogCategoryCache, "DNS cache cleared");

    if (completion) {
      completion(YES);
    }
  });
}

- (void)updateConfiguration:(NSDictionary*)config
          completionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    __block BOOL overallSuccess = YES;

    if (config[@"dnsServers"]) {
      NSArray* servers = config[@"dnsServers"];
      [self updateDNSServers:servers
           completionHandler:^(BOOL success){
           }];
    }

    // Handle manual manifest update trigger
    if ([config[@"triggerManifestUpdate"] boolValue]) {
      DNSLogInfo(LogCategoryRuleFetching, "Manual manifest update triggered via XPC");

      // Force a manifest reload and rule update
      if ([self.ruleManager respondsToSelector:@selector(loadManifestAsync:completion:)] &&
          [self.ruleManager respondsToSelector:@selector(determineManifestIdentifier)]) {
        NSString* manifestIdentifier = [(id)self.ruleManager determineManifestIdentifier];
        DNSLogInfo(LogCategoryRuleFetching, "Triggering manifest update for identifier: %{public}@",
                   manifestIdentifier);

        [(id)self.ruleManager
            loadManifestAsync:manifestIdentifier
                   completion:^(BOOL success, NSError* error) {
                     if (success) {
                       DNSLogInfo(LogCategoryRuleFetching, "Manual manifest update succeeded");
                       // Update rules from the newly loaded manifest
                       if ([self.ruleManager
                               respondsToSelector:@selector(updateRulesFromCurrentManifest)]) {
                         [(id)self.ruleManager updateRulesFromCurrentManifest];
                       }

                       // Store last manifest update time
                       NSUserDefaults* sharedDefaults = DNSharedDefaults();
                       [sharedDefaults setObject:[NSDate date] forKey:@"lastManifestUpdate"];
                       [sharedDefaults synchronize];
                     } else {
                       DNSLogError(LogCategoryRuleFetching,
                                   "Manual manifest update failed: %{public}@",
                                   error.localizedDescription);
                       overallSuccess = NO;
                     }

                     if (completion) {
                       completion(overallSuccess);
                     }
                   }];
        return;  // Exit early since we're handling completion async
      } else {
        DNSLogError(LogCategoryRuleFetching, "RuleManager does not support manifest operations");
        overallSuccess = NO;
      }
    }

    if (completion) {
      completion(overallSuccess);
    }
  });
}

// MARK: - Rule Management XPC Methods

- (void)getRuleStatusWithCompletionHandler:(void (^)(NSDictionary* _Nullable status))completion {
  NSDictionary* status = @{
    @"lastUpdate" : self.ruleManager.lastUpdateDate ?: [NSNull null],
    @"isUpdating" : @(self.ruleManager.state == RuleManagerStateRunning),
    @"totalRuleCount" : @(self.ruleDatabase.ruleCount),
    @"sourceCount" : @([self.ruleManager allRuleSources].count)
  };
  if (completion) {
    completion(status);
  }
}

- (void)triggerRuleUpdateWithCompletionHandler:(void (^)(BOOL success,
                                                         NSError* _Nullable error))completion {
  [self.ruleManager forceUpdate];
  // Since forceUpdate is async, we'll assume success
  if (completion) {
    completion(YES, nil);
  }
}

- (void)getRuleSourcesWithCompletionHandler:(void (^)(NSArray* _Nullable sources))completion {
  NSArray* sources = [self.ruleManager allRuleSources];
  NSMutableArray* sourceSummaries = [NSMutableArray array];

  for (RuleSource* source in sources) {
    [sourceSummaries addObject:@{
      @"identifier" : source.identifier,
      @"type" : @(source.type),
      @"url" : source.url ?: [NSNull null],
      @"format" : source.format ?: @"",
      @"enabled" : @(source.enabled),
      @"updateInterval" : @(source.updateInterval)
    }];
  }

  if (completion) {
    completion(sourceSummaries);
  }
}

- (void)getConfigurationInfoWithCompletionHandler:
    (void (^)(NSDictionary* _Nullable configInfo))completion {
  DNSConfiguration* config = self.configManager.currentConfiguration;

  NSMutableDictionary* configInfo = [NSMutableDictionary dictionaryWithDictionary:@{
    @"isManagedByProfile" : @(config.isManagedByProfile),
    @"allowRuleEditing" : @(config.allowRuleEditing),
    @"offlineMode" : @(config.offlineMode),
    @"debugLogging" : @(config.debugLogging),
    @"logLevel" : config.logLevel ?: @"info"
  }];

  // Add manifest information
  if ([self.ruleManager respondsToSelector:@selector(currentManifestIdentifier)]) {
    NSString* manifestId = [(id)self.ruleManager currentManifestIdentifier];
    if (manifestId) {
      configInfo[@"manifestIdentifier"] = manifestId;
    }
  }

  // Add last manifest update time
  NSUserDefaults* sharedDefaults = DNSharedDefaults();
  NSDate* lastUpdate = [sharedDefaults objectForKey:@"lastManifestUpdate"];
  if (lastUpdate) {
    configInfo[@"lastManifestUpdate"] = lastUpdate;
  }

  if (completion) {
    completion(configInfo);
  }
}

- (void)getSyncStatusWithCompletionHandler:(void (^)(NSDictionary* _Nullable syncInfo))completion {
  dispatch_async(self.dnsQueue, ^{
    NSMutableDictionary* syncInfo = [NSMutableDictionary dictionary];

    // Get last rule sync timestamp - check multiple sources
    NSDate* lastRuleSync = self.ruleManager.lastUpdateDate;
    NSDate* lastDBUpdate = self.ruleDatabase.lastUpdated;

    // Use the most recent timestamp as the sync time
    NSDate* mostRecentSync = nil;
    if (lastRuleSync && lastDBUpdate) {
      mostRecentSync = [lastRuleSync laterDate:lastDBUpdate];
    } else {
      mostRecentSync = lastRuleSync ?: lastDBUpdate;
    }

    if (mostRecentSync) {
      syncInfo[@"lastRuleSync"] = mostRecentSync;
    } else {
      // Fallback: If no sync timestamp, show if we have rules at all
      NSUInteger ruleCount = self.ruleDatabase.ruleCount;
      if (ruleCount > 0) {
        // Rules exist but no update timestamp - show application start time as fallback
        syncInfo[@"lastRuleSync"] = [NSDate date];  // Current session
        syncInfo[@"syncNote"] = @"Rules loaded (no update timestamp available)";
      } else {
        syncInfo[@"syncNote"] = @"No rules loaded yet";
      }
    }

    if (lastDBUpdate) {
      syncInfo[@"lastDatabaseUpdate"] = lastDBUpdate;
    }

    // Get actual system DNS servers using scutil
    NSArray* systemDNSServers = [self getSystemDNSServers];
    if (systemDNSServers && systemDNSServers.count > 0) {
      syncInfo[@"dnsResolvers"] = systemDNSServers;
    }

    // Also include configured upstream servers for context
    if (self.dnsServers && self.dnsServers.count > 0) {
      syncInfo[@"upstreamDNSServers"] = [self.dnsServers copy];
    }

    // Get rule count for context
    NSUInteger ruleCount = self.ruleDatabase.ruleCount;
    syncInfo[@"ruleCount"] = @(ruleCount);

    // Get manifest identifier if available
    if ([self.ruleManager respondsToSelector:@selector(currentManifestIdentifier)]) {
      NSString* manifestId = [(id)self.ruleManager currentManifestIdentifier];
      if (manifestId) {
        syncInfo[@"manifestIdentifier"] = manifestId;
      }
    }

    // Get last sync error if any
    NSError* lastError = self.ruleManager.lastUpdateError;
    if (lastError) {
      syncInfo[@"lastSyncError"] = lastError.localizedDescription;
    }

    if (completion) {
      completion(syncInfo);
    }
  });
}

- (NSArray*)getSystemDNSServers {
  @try {
    NSTask* task = [[NSTask alloc] init];
    task.launchPath = @"/usr/sbin/scutil";
    task.arguments = @[ @"--dns" ];

    NSPipe* pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;

    [task launch];
    [task waitUntilExit];

    if (task.terminationStatus == 0) {
      NSFileHandle* file = [pipe fileHandleForReading];
      NSData* data = [file readDataToEndOfFile];
      NSString* output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

      // Parse nameserver entries from scutil output
      NSMutableArray* nameservers = [NSMutableArray array];
      NSMutableSet* seen = [NSMutableSet set];

      NSArray* lines = [output componentsSeparatedByString:@"\n"];
      for (NSString* line in lines) {
        NSString* trimmedLine =
            [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([trimmedLine hasPrefix:@"nameserver["]) {
          // Extract the IP address from nameserver[0] : 1.1.1.1
          NSRange colonRange = [trimmedLine rangeOfString:@" : "];
          if (colonRange.location != NSNotFound) {
            NSString* ip = [[trimmedLine substringFromIndex:colonRange.location + 3]
                stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (ip.length > 0 && ![seen containsObject:ip]) {
              [seen addObject:ip];
              [nameservers addObject:ip];
            }
          }
        }
      }

      return [nameservers copy];
    }
  } @catch (NSException* exception) {
    DNSLogError(LogCategoryNetwork, "Error getting system DNS servers: %@", exception.reason);
  }

  // Fallback - return empty array
  return @[];
}

- (void)getManagedBlockedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion {
  dispatch_async(self.dnsQueue, ^{
    NSArray<DNSRule*>* rules = [self.ruleDatabase rulesFromSource:DNSRuleSourceManifest];
    NSMutableArray<NSString*>* blockedDomains = [NSMutableArray array];
    for (DNSRule* rule in rules) {
      if (rule.action == DNSRuleActionBlock) {
        [blockedDomains addObject:rule.domain];
      }
    }
    if (completion) {
      completion(blockedDomains);
    }
  });
}

- (void)getManagedAllowedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion {
  dispatch_async(self.dnsQueue, ^{
    NSArray<DNSRule*>* rules = [self.ruleDatabase rulesFromSource:DNSRuleSourceManifest];
    NSMutableArray<NSString*>* allowedDomains = [NSMutableArray array];
    for (DNSRule* rule in rules) {
      if (rule.action == DNSRuleActionAllow) {
        [allowedDomains addObject:rule.domain];
      }
    }
    if (completion) {
      completion(allowedDomains);
    }
  });
}

- (void)addUserBlockedDomain:(NSString*)domain
           completionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    DNSRule* rule = [DNSRule ruleWithDomain:domain action:DNSRuleActionBlock];
    rule.source = DNSRuleSourceUser;
    NSError* error = nil;
    BOOL success = [self.ruleDatabase addRule:rule error:&error];
    if (success) {
      [self.ruleCache clear];  // Clear cache to reflect changes
      [self.dnsCache clearCache];
    }
    if (completion) {
      completion(success);
    }
  });
}

- (void)removeUserBlockedDomain:(NSString*)domain
              completionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    NSError* error = nil;
    BOOL success = [self.ruleDatabase removeRuleForDomain:domain error:&error];
    if (success) {
      [self.ruleCache clear];  // Clear cache to reflect changes
      [self.dnsCache clearCache];
    }
    if (completion) {
      completion(success);
    }
  });
}

- (void)addUserAllowedDomain:(NSString*)domain
           completionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    DNSRule* rule = [DNSRule ruleWithDomain:domain action:DNSRuleActionAllow];
    rule.source = DNSRuleSourceUser;
    NSError* error = nil;
    BOOL success = [self.ruleDatabase addRule:rule error:&error];
    if (success) {
      [self.ruleCache clear];  // Clear cache to reflect changes
      [self.dnsCache clearCache];
    }
    if (completion) {
      completion(success);
    }
  });
}

- (void)removeUserAllowedDomain:(NSString*)domain
              completionHandler:(void (^)(BOOL success))completion {
  dispatch_async(self.dnsQueue, ^{
    NSError* error = nil;
    BOOL success = [self.ruleDatabase removeRuleForDomain:domain error:&error];
    if (success) {
      [self.ruleCache clear];  // Clear cache to reflect changes
      [self.dnsCache clearCache];
    }
    if (completion) {
      completion(success);
    }
  });
}

- (void)getAllRulesWithCompletionHandler:(void (^)(NSArray* _Nullable rules))completion {
  dispatch_async(self.dnsQueue, ^{
    NSArray<DNSRule*>* rules = [self.ruleDatabase allRules];
    NSMutableArray* ruleDictionaries = [NSMutableArray arrayWithCapacity:rules.count];

    for (DNSRule* rule in rules) {
      if (rule.domain.length == 0) {
        continue;
      }

      NSMutableDictionary* entry = [NSMutableDictionary dictionary];
      entry[@"domain"] = rule.domain;
      entry[@"action"] = @(rule.action);
      entry[@"source"] = @(rule.source);
      entry[@"type"] = @(rule.type);
      entry[@"priority"] = @(rule.priority);

      if (rule.comment.length > 0) {
        entry[@"comment"] = rule.comment;
      }
      if (rule.customMessage.length > 0) {
        entry[@"customMessage"] = rule.customMessage;
      }
      if (rule.updatedAt) {
        entry[@"updatedAt"] = rule.updatedAt;
      }
      if (rule.expiresAt) {
        entry[@"expiresAt"] = rule.expiresAt;
      }

      [ruleDictionaries addObject:entry];
    }

    NSArray* result = [ruleDictionaries copy];
    if (completion) {
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(result);
      });
    }
  });
}

- (void)getUserBlockedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion {
  dispatch_async(self.dnsQueue, ^{
    NSArray<DNSRule*>* rules = [self.ruleDatabase rulesFromSource:DNSRuleSourceUser];
    NSMutableArray<NSString*>* blockedDomains = [NSMutableArray array];
    for (DNSRule* rule in rules) {
      if (rule.action == DNSRuleActionBlock) {
        [blockedDomains addObject:rule.domain];
      }
    }
    if (completion) {
      completion(blockedDomains);
    }
  });
}

- (void)getUserAllowedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion {
  dispatch_async(self.dnsQueue, ^{
    NSArray<DNSRule*>* rules = [self.ruleDatabase rulesFromSource:DNSRuleSourceUser];
    NSMutableArray<NSString*>* allowedDomains = [NSMutableArray array];
    for (DNSRule* rule in rules) {
      if (rule.action == DNSRuleActionAllow) {
        [allowedDomains addObject:rule.domain];
      }
    }
    if (completion) {
      completion(allowedDomains);
    }
  });
}

@end
