//
//  DNRuleDataProvider.m
//  DNShield
//

#import "DNRuleDataProvider.h"

#import "DNSProxyConfigurationManager.h"
#import "LoggingManager.h"
#import "XPCClient.h"

#import <sqlite3.h>

static NSString* const DNRuleDataProviderErrorDomain = @"com.dnshield.ruleData";

@interface DNRuleDataProvider ()

@property(nonatomic, strong) DNSProxyConfigurationManager* proxyManager;

@end

@implementation DNRuleDataProvider

- (instancetype)initWithProxyManager:(DNSProxyConfigurationManager*)proxyManager {
  self = [super init];
  if (self) {
    _proxyManager = proxyManager;
  }
  return self;
}

- (void)fetchRulesWithCompletion:(DNRuleDataProviderCompletion)completion {
  __weak typeof(self) weakSelf = self;
  [[XPCClient sharedClient] getAllRulesWithCompletionHandler:^(NSArray* _Nullable rules,
                                                               NSError* _Nullable error) {
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    if ([rules isKindOfClass:[NSArray class]]) {
      DNSLogInfo(LogCategoryRuleFetching, "Received %lu rules from XPC",
                 (unsigned long)rules.count);
      [strongSelf processRuleRecords:rules completion:completion];
    } else {
      if (error) {
        DNSLogError(LogCategoryRuleFetching,
                    "Failed to fetch rules via XPC: %{public}@. Falling back to direct database "
                    "read.",
                    error.localizedDescription);
      } else {
        DNSLogInfo(LogCategoryRuleFetching,
                   "Extension returned no rule data over XPC. Falling back to direct database "
                   "read.");
      }
      [strongSelf loadRulesFromLocalDatabaseWithCompletion:completion fallbackError:error];
    }
  }];
}

- (NSDictionary*)currentRulesConfigInfo {
  NSUserDefaults* standardDefaults = [NSUserDefaults standardUserDefaults];
  [standardDefaults synchronize];

  BOOL isManagedByProfile = [self.proxyManager isDNSProxyManagedByProfile];

  return @{
    @"isManagedByProfile" : @(isManagedByProfile),
    @"allowRuleEditing" : @(![standardDefaults boolForKey:@"DisableRuleEditing"]),
    @"manifestIdentifier" : [standardDefaults stringForKey:@"ManifestIdentifier"] ?: @"default"
  };
}

- (NSDictionary*)syncStatusDirectly {
  NSMutableDictionary* syncInfo = [NSMutableDictionary dictionary];

  NSArray* systemDNSServers = [self systemDNSServersFallback];
  if (systemDNSServers.count > 0) {
    syncInfo[@"dnsResolvers"] = systemDNSServers;
  }

  NSString* dbPath = @"/var/db/dnshield/rules.db";
  sqlite3* db;

  if (sqlite3_open([dbPath UTF8String], &db) == SQLITE_OK) {
    const char* countSql = "SELECT COUNT(*) FROM dns_rules";
    sqlite3_stmt* countStmt;
    if (sqlite3_prepare_v2(db, countSql, -1, &countStmt, NULL) == SQLITE_OK) {
      if (sqlite3_step(countStmt) == SQLITE_ROW) {
        int ruleCount = sqlite3_column_int(countStmt, 0);
        syncInfo[@"ruleCount"] = @(ruleCount);
      }
      sqlite3_finalize(countStmt);
    }

    const char* syncSql =
        "SELECT value FROM metadata WHERE key = 'last_sync' ORDER BY rowid DESC LIMIT 1";
    sqlite3_stmt* syncStmt;
    if (sqlite3_prepare_v2(db, syncSql, -1, &syncStmt, NULL) == SQLITE_OK) {
      if (sqlite3_step(syncStmt) == SQLITE_ROW) {
        const char* syncTimeStr = (const char*)sqlite3_column_text(syncStmt, 0);
        if (syncTimeStr) {
          NSTimeInterval timestamp = [[NSString stringWithUTF8String:syncTimeStr] doubleValue];
          if (timestamp > 0) {
            NSDate* lastSync = [NSDate dateWithTimeIntervalSince1970:timestamp];
            syncInfo[@"lastRuleSync"] = lastSync;
          }
        }
      }
      sqlite3_finalize(syncStmt);
    } else {
      NSError* error;
      NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:dbPath
                                                                             error:&error];
      if (attrs && !error) {
        NSDate* modDate = attrs[NSFileModificationDate];
        if (modDate) {
          syncInfo[@"lastRuleSync"] = modDate;
          syncInfo[@"syncNote"] = @"Database last modified";
        }
      }
    }

    sqlite3_close(db);
  } else {
    syncInfo[@"syncNote"] = @"No rules database found";
  }

  return [syncInfo copy];
}

- (NSArray<NSString*>*)systemDNSServersFallback {
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

      NSMutableArray* nameservers = [NSMutableArray array];
      NSMutableSet* seen = [NSMutableSet set];

      NSArray* lines = [output componentsSeparatedByString:@"\n"];
      for (NSString* line in lines) {
        NSString* trimmedLine =
            [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([trimmedLine hasPrefix:@"nameserver["]) {
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
    DNSLogError(LogCategoryDNS, "Error getting system DNS servers: %@", exception.reason);
  }

  return @[];
}

- (NSArray<NSDictionary*>*)manifestEntriesWithURL:(NSString* __autoreleasing*)manifestURL
                                            error:(NSError* __autoreleasing*)error {
  NSString* manifestCachePath = @"/Library/Application Support/DNShield/manifest_cache";
  NSFileManager* fileManager = [NSFileManager defaultManager];

  if (![fileManager fileExistsAtPath:manifestCachePath]) {
    if (error) {
      *error = [NSError errorWithDomain:DNRuleDataProviderErrorDomain
                                   code:1
                               userInfo:@{NSLocalizedDescriptionKey : @"No manifest cache found"}];
    }
    return nil;
  }

  NSString* serialNumber = nil;
  NSArray* contents = [fileManager contentsOfDirectoryAtPath:manifestCachePath error:nil];
  for (NSString* item in contents) {
    if (![item isEqualToString:@"includes"]) {
      BOOL isDirectory;
      NSString* fullPath = [manifestCachePath stringByAppendingPathComponent:item];
      if ([fileManager fileExistsAtPath:fullPath isDirectory:&isDirectory] && !isDirectory) {
        serialNumber = item;
        break;
      }
    }
  }

  NSMutableArray* manifestData = [NSMutableArray array];

  if (serialNumber) {
    NSString* primaryPath = [manifestCachePath stringByAppendingPathComponent:serialNumber];
    NSDictionary* manifestDict = [self manifestDictionaryAtPath:primaryPath];
    NSInteger ruleCount = [self ruleCountFromManifest:manifestDict];
    NSDictionary* attrs = [fileManager attributesOfItemAtPath:primaryPath error:nil];
    [manifestData addObject:@{
      @"identifier" : serialNumber,
      @"type" : @"primary",
      @"ruleCount" : @(ruleCount),
      @"lastUpdated" : attrs[NSFileModificationDate] ?: [NSDate date],
      @"included" : [self includedManifestsForPrimary:primaryPath]
    }];
  }

  NSString* includesPath = [manifestCachePath stringByAppendingPathComponent:@"includes"];
  NSArray* categories = @[ @"default", @"always", @"conditionals" ];
  for (NSString* category in categories) {
    NSString* categoryPath = [includesPath stringByAppendingPathComponent:category];
    BOOL isDirectory;
    if (![fileManager fileExistsAtPath:categoryPath isDirectory:&isDirectory] || !isDirectory) {
      continue;
    }

    NSArray* files = [fileManager contentsOfDirectoryAtPath:categoryPath error:nil];
    for (NSString* file in files) {
      NSString* filePath = [categoryPath stringByAppendingPathComponent:file];
      NSDictionary* manifestDict = [self manifestDictionaryAtPath:filePath];
      NSInteger ruleCount = [self ruleCountFromManifest:manifestDict];
      NSDictionary* attrs = [fileManager attributesOfItemAtPath:filePath error:nil];
      [manifestData addObject:@{
        @"identifier" : file,
        @"type" : category,
        @"ruleCount" : @(ruleCount),
        @"lastUpdated" : attrs[NSFileModificationDate] ?: [NSDate date]
      }];
    }
  }

  NSString* managedPrefsPath = @"/Library/Managed Preferences/com.dnshield.app.plist";
  if (manifestURL && [[NSFileManager defaultManager] fileExistsAtPath:managedPrefsPath]) {
    NSDictionary* mdmPrefs = [NSDictionary dictionaryWithContentsOfFile:managedPrefsPath];
    *manifestURL = mdmPrefs[@"ManifestURL"];
  }

  return [manifestData copy];
}

#pragma mark - Private Helpers

- (void)processRuleRecords:(NSArray<NSDictionary*>*)ruleRecords
                completion:(DNRuleDataProviderCompletion)completion {
  NSMutableArray* blockedDomains = [NSMutableArray array];
  NSMutableArray* allowedDomains = [NSMutableArray array];
  NSMutableDictionary<NSString*, NSMutableArray<NSString*>*>* mutableSources =
      [NSMutableDictionary dictionary];

  for (id entry in ruleRecords) {
    if (![entry isKindOfClass:[NSDictionary class]])
      continue;
    NSDictionary* rule = (NSDictionary*)entry;

    NSString* domain =
        [rule[@"domain"] isKindOfClass:[NSString class]] ? (NSString*)rule[@"domain"] : nil;
    if (domain.length == 0)
      continue;

    NSInteger action = [rule[@"action"] respondsToSelector:@selector(integerValue)]
                           ? [rule[@"action"] integerValue]
                           : -1;
    NSInteger source = [rule[@"source"] respondsToSelector:@selector(integerValue)]
                           ? [rule[@"source"] integerValue]
                           : 0;
    NSInteger type = [rule[@"type"] respondsToSelector:@selector(integerValue)]
                         ? [rule[@"type"] integerValue]
                         : 0;
    NSInteger priority = [rule[@"priority"] respondsToSelector:@selector(integerValue)]
                             ? [rule[@"priority"] integerValue]
                             : 0;
    NSString* comment =
        [rule[@"comment"] isKindOfClass:[NSString class]] ? (NSString*)rule[@"comment"] : @"";

    NSDictionary* ruleDictionary = @{
      @"domain" : domain,
      @"source" : @(source),
      @"type" : @(type),
      @"priority" : @(priority),
      @"comment" : comment ?: @""
    };

    if (action == 0) {
      [blockedDomains addObject:ruleDictionary];
    } else if (action == 1) {
      [allowedDomains addObject:ruleDictionary];
    }

    NSString* sourceKey = [self sourceNameForType:(int)source];
    NSMutableArray<NSString*>* sourceEntries = mutableSources[sourceKey];
    if (!sourceEntries) {
      sourceEntries = [NSMutableArray array];
      mutableSources[sourceKey] = sourceEntries;
    }
    [sourceEntries addObject:domain];
  }

  NSMutableDictionary* ruleSources =
      [NSMutableDictionary dictionaryWithCapacity:mutableSources.count];
  [mutableSources enumerateKeysAndObjectsUsingBlock:^(
                      NSString* key, NSMutableArray<NSString*>* domains, BOOL* stop) {
    ruleSources[key] = [domains copy];
  }];

  if (completion) {
    completion([blockedDomains copy], [allowedDomains copy], [ruleSources copy],
               [self currentRulesConfigInfo], [self syncStatusDirectly], nil);
  }
}

- (void)loadRulesFromLocalDatabaseWithCompletion:(DNRuleDataProviderCompletion)completion
                                   fallbackError:(NSError*)fallbackError {
  NSString* databasePath = @"/var/db/dnshield/rules.db";
  NSFileManager* fileManager = [NSFileManager defaultManager];

  if (![fileManager fileExistsAtPath:databasePath]) {
    if (completion) {
      NSError* error =
          [NSError errorWithDomain:DNRuleDataProviderErrorDomain
                              code:2
                          userInfo:@{NSLocalizedDescriptionKey : @"Rules database not found"}];
      completion(@[], @[], @{}, [self currentRulesConfigInfo], [self syncStatusDirectly], error);
    }
    return;
  }

  sqlite3* database = NULL;
  if (sqlite3_open([databasePath UTF8String], &database) != SQLITE_OK) {
    const char* errorMsg = sqlite3_errmsg(database);
    DNSLogError(LogCategoryError, "Failed to open rules database: %{public}s", errorMsg);
    if (database)
      sqlite3_close(database);

    if (completion) {
      NSError* error =
          [NSError errorWithDomain:DNRuleDataProviderErrorDomain
                              code:3
                          userInfo:@{NSLocalizedDescriptionKey : @"Failed to open rules database"}];
      completion(@[], @[], @{}, [self currentRulesConfigInfo], [self syncStatusDirectly], error);
    }
    return;
  }

  NSMutableArray* blockedDomains = [NSMutableArray array];
  NSMutableArray* allowedDomains = [NSMutableArray array];
  NSMutableDictionary<NSString*, NSMutableArray<NSString*>*>* mutableSources =
      [NSMutableDictionary dictionary];

  const char* query =
      "SELECT domain, action, source, type, priority, comment FROM dns_rules ORDER BY priority "
      "DESC, domain ASC";
  sqlite3_stmt* statement = NULL;

  if (sqlite3_prepare_v2(database, query, -1, &statement, NULL) == SQLITE_OK) {
    while (sqlite3_step(statement) == SQLITE_ROW) {
      const unsigned char* domainText = sqlite3_column_text(statement, 0);
      if (!domainText)
        continue;
      NSString* domain = [NSString stringWithUTF8String:(const char*)domainText];

      int action = sqlite3_column_int(statement, 1);
      int source = sqlite3_column_int(statement, 2);
      int type = sqlite3_column_int(statement, 3);
      int priority = sqlite3_column_int(statement, 4);

      const char* commentCStr = (const char*)sqlite3_column_text(statement, 5);
      NSString* comment = commentCStr ? [NSString stringWithUTF8String:commentCStr] : @"";

      NSDictionary* ruleDictionary = @{
        @"domain" : domain,
        @"source" : @(source),
        @"type" : @(type),
        @"priority" : @(priority),
        @"comment" : comment ?: @""
      };

      if (action == 0) {
        [blockedDomains addObject:ruleDictionary];
      } else if (action == 1) {
        [allowedDomains addObject:ruleDictionary];
      }

      NSString* sourceKey = [self sourceNameForType:source];
      NSMutableArray<NSString*>* sourceEntries = mutableSources[sourceKey];
      if (!sourceEntries) {
        sourceEntries = [NSMutableArray array];
        mutableSources[sourceKey] = sourceEntries;
      }
      [sourceEntries addObject:domain];
    }
    sqlite3_finalize(statement);
  } else {
    DNSLogError(LogCategoryError, "Failed to prepare rules query: %{public}s",
                sqlite3_errmsg(database));
  }

  sqlite3_close(database);

  NSMutableDictionary* ruleSources =
      [NSMutableDictionary dictionaryWithCapacity:mutableSources.count];
  [mutableSources enumerateKeysAndObjectsUsingBlock:^(
                      NSString* key, NSMutableArray<NSString*>* domains, BOOL* stop) {
    ruleSources[key] = [domains copy];
  }];

  if (completion) {
    completion([blockedDomains copy], [allowedDomains copy], [ruleSources copy],
               [self currentRulesConfigInfo], [self syncStatusDirectly], fallbackError);
  }
}

- (NSDictionary*)manifestDictionaryAtPath:(NSString*)path {
  NSData* data = [NSData dataWithContentsOfFile:path];
  if (!data)
    return nil;

  NSError* jsonError = nil;
  NSDictionary* manifestDict =
      [NSJSONSerialization JSONObjectWithData:data
                                      options:NSJSONReadingMutableContainers
                                        error:&jsonError];

  if (!manifestDict || jsonError) {
    NSError* plistError = nil;
    id manifestPlist = [NSPropertyListSerialization propertyListWithData:data
                                                                 options:NSPropertyListImmutable
                                                                  format:nil
                                                                   error:&plistError];
    if (!plistError && [manifestPlist isKindOfClass:[NSDictionary class]]) {
      manifestDict = (NSDictionary*)manifestPlist;
    }
  }

  return manifestDict;
}

- (NSInteger)ruleCountFromManifest:(NSDictionary*)manifestDict {
  if (![manifestDict isKindOfClass:[NSDictionary class]])
    return 0;

  NSInteger ruleCount = 0;
  NSDictionary* managedRules = manifestDict[@"managed_rules"];
  if ([managedRules isKindOfClass:[NSDictionary class]]) {
    NSArray* blockRules = managedRules[@"block"];
    NSArray* allowRules = managedRules[@"allow"];
    if ([blockRules isKindOfClass:[NSArray class]])
      ruleCount += blockRules.count;
    if ([allowRules isKindOfClass:[NSArray class]])
      ruleCount += allowRules.count;
  }

  NSArray* conditionalItems = manifestDict[@"conditional_items"];
  if ([conditionalItems isKindOfClass:[NSArray class]]) {
    for (id item in conditionalItems) {
      if ([item isKindOfClass:[NSDictionary class]]) {
        NSDictionary* conditionalRules = item[@"managed_rules"];
        if ([conditionalRules isKindOfClass:[NSDictionary class]]) {
          NSArray* condBlockRules = conditionalRules[@"block"];
          NSArray* condAllowRules = conditionalRules[@"allow"];
          if ([condBlockRules isKindOfClass:[NSArray class]])
            ruleCount += condBlockRules.count;
          if ([condAllowRules isKindOfClass:[NSArray class]])
            ruleCount += condAllowRules.count;
        }
      }
    }
  }

  return ruleCount;
}

- (NSArray*)includedManifestsForPrimary:(NSString*)primaryPath {
  NSMutableArray* included = [NSMutableArray array];

  NSData* data = [NSData dataWithContentsOfFile:primaryPath];
  if (data) {
    NSError* plistError = nil;
    id manifestPlist = [NSPropertyListSerialization propertyListWithData:data
                                                                 options:NSPropertyListImmutable
                                                                  format:nil
                                                                   error:&plistError];
    if (!plistError && [manifestPlist isKindOfClass:[NSDictionary class]]) {
      NSDictionary* manifestDict = (NSDictionary*)manifestPlist;
      NSArray* includes = manifestDict[@"included_manifests"];
      if ([includes isKindOfClass:[NSArray class]]) {
        for (id item in includes) {
          if ([item isKindOfClass:[NSString class]]) {
            [included addObject:item];
          } else if ([item isKindOfClass:[NSDictionary class]] && item[@"name"]) {
            [included addObject:item[@"name"]];
          }
        }
      }
    }
  }

  return included;
}

- (NSString*)sourceNameForType:(int)sourceType {
  switch (sourceType) {
    case 0: return @"User";
    case 1: return @"Managed";
    case 2: return @"Remote";
    case 3: return @"System";
    default: return @"Unknown";
  }
}

@end
