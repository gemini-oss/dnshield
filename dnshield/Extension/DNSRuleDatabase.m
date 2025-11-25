//
//  DNSRuleDatabase.m
//  DNShield Network Extension
//
//

#import <os/log.h>
#import <sqlite3.h>

#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/RuleDatabase.h>

#import "DNSWildcardConfig.h"

// Notification constant (shared with consumers via RuleDatabase.h)
NSString* const RuleDatabaseDidChangeNotification = @"RuleDatabaseDidChangeNotification";

static os_log_t logHandle;

typedef NS_ENUM(NSInteger, RuleDatabaseOutcome) {
  RuleDatabaseOutcomeSuccess = 0,
  RuleDatabaseOutcomeRetry,
  RuleDatabaseOutcomeFailure,
};

@interface RuleDatabase ()
@property(nonatomic, assign) sqlite3* database;
@property(nonatomic, strong) dispatch_queue_t databaseQueue;
@property(nonatomic, strong) NSDateFormatter* dateFormatter;
- (BOOL)openDatabaseLocked;
- (void)closeDatabaseLocked;
- (BOOL)attemptRecoveryForResult:(int)result context:(NSString*)context didRetry:(BOOL*)didRetry;
- (RuleDatabaseOutcome)prepareStatement:(const char*)sql
                                context:(NSString*)context
                               didRetry:(BOOL*)didRetry
                              statement:(sqlite3_stmt**)outStatement;
- (RuleDatabaseOutcome)stepStatement:(sqlite3_stmt*)statement
                             context:(NSString*)context
                            didRetry:(BOOL*)didRetry
                              result:(int*)outResult;
@end

@implementation DNSRule

+ (instancetype)ruleWithDomain:(NSString*)domain action:(DNSRuleAction)action {
  DNSRule* rule = [[DNSRule alloc] init];
  rule.domain = domain;
  rule.action = action;
  rule.type = DNSRuleTypeExact;
  rule.priority = 100;
  rule.source = DNSRuleSourceUser;
  rule.updatedAt = [NSDate date];
  return rule;
}

- (BOOL)matchesDomain:(NSString*)queryDomain {
  switch (self.type) {
    case DNSRuleTypeExact: return [queryDomain isEqualToString:self.domain];

    case DNSRuleTypeWildcard: {
      // Handle *.example.com style wildcards
      if ([self.domain hasPrefix:@"*."]) {
        NSString* suffix = [self.domain substringFromIndex:2];

        // Check if wildcard should match root domain based on configuration
        DNSWildcardConfig* config = [DNSWildcardConfig sharedConfig];
        BOOL matchRoot = [config wildcardShouldMatchRoot:self.domain];

        // Exact match with the root domain
        if (matchRoot && [queryDomain isEqualToString:suffix]) {
          return YES;
        }

        // Check for subdomain match (must have dot before suffix)
        if ([queryDomain hasSuffix:suffix]) {
          NSUInteger prefixLength = queryDomain.length - suffix.length;
          if (prefixLength > 0 && [queryDomain characterAtIndex:prefixLength - 1] == '.') {
            return YES;
          }
        }
      }
      return NO;
    }

    case DNSRuleTypeRegex: {
      NSError* error = nil;
      NSRegularExpression* regex =
          [NSRegularExpression regularExpressionWithPattern:self.domain
                                                    options:NSRegularExpressionCaseInsensitive
                                                      error:&error];
      if (error)
        return NO;
      NSRange range = [regex rangeOfFirstMatchInString:queryDomain
                                               options:0
                                                 range:NSMakeRange(0, queryDomain.length)];
      return range.location != NSNotFound;
    }
  }
  return NO;
}

@end

@implementation RuleDatabase

+ (void)initialize {
  if (self == [RuleDatabase class]) {
    logHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"RuleDatabase");
  }
}

+ (instancetype)sharedDatabase {
  static RuleDatabase* sharedDatabase = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedDatabase = [[RuleDatabase alloc] init];
  });
  return sharedDatabase;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    NSString* dbDir = kDefaultDBPath;
    NSFileManager* fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dbDir]) {
      NSError* error = nil;
      // Create with proper permissions for system database directory
      NSDictionary* attributes = @{NSFilePosixPermissions : @(0755)};
      [fm createDirectoryAtPath:dbDir
          withIntermediateDirectories:YES
                           attributes:attributes
                                error:&error];
      if (error) {
        os_log_error(logHandle, "Failed to create database directory: %{public}@", error);
      }
    }

    _databasePath = [dbDir stringByAppendingPathComponent:@"rules.db"];
    _databaseQueue = dispatch_queue_create("com.dnshield.database", DISPATCH_QUEUE_SERIAL);

    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    _dateFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
  }
  return self;
}

- (void)dealloc {
  [self closeDatabase];
}

#pragma mark - Database Operations

- (BOOL)createTablesIfNeeded {
  const char* createTableSQL =
      "CREATE TABLE IF NOT EXISTS dns_rules ("
      "    domain TEXT NOT NULL PRIMARY KEY,"
      "    action INTEGER NOT NULL,"
      "    type INTEGER NOT NULL,"
      "    priority INTEGER DEFAULT 100,"
      "    source INTEGER DEFAULT 0,"
      "    custom_msg TEXT,"
      "    updated_at TEXT,"
      "    expires_at TEXT,"
      "    comment TEXT"
      ");"
      // Performance indexes as documented
      "CREATE INDEX IF NOT EXISTS idx_domain_action ON dns_rules(domain, action);"
      "CREATE INDEX IF NOT EXISTS idx_domain_type ON dns_rules(domain, type);"
      "CREATE INDEX IF NOT EXISTS idx_updated_at ON dns_rules(updated_at);"
      "CREATE INDEX IF NOT EXISTS idx_expires_at ON dns_rules(expires_at);"
      "CREATE INDEX IF NOT EXISTS idx_wildcard_domains ON dns_rules(domain) WHERE type = 1;"
      "CREATE INDEX IF NOT EXISTS idx_source_priority ON dns_rules(source, priority DESC);"
      // Legacy indexes for compatibility
      "CREATE INDEX IF NOT EXISTS idx_priority ON dns_rules(priority DESC);"
      "CREATE INDEX IF NOT EXISTS idx_expires ON dns_rules(expires_at);"
      "CREATE INDEX IF NOT EXISTS idx_source ON dns_rules(source);"
      // Create query statistics table for cache warming
      "CREATE TABLE IF NOT EXISTS query_stats ("
      "    domain TEXT NOT NULL PRIMARY KEY,"
      "    query_count INTEGER DEFAULT 0,"
      "    last_queried TEXT,"
      "    created_at TEXT"
      ");";

  BOOL didRetry = NO;

  while (YES) {
    if (!self.database && ![self openDatabaseLocked]) {
      return NO;
    }

    char* errorMsg = NULL;
    int result = sqlite3_exec(self.database, createTableSQL, NULL, NULL, &errorMsg);
    NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
    if (errorMsg)
      sqlite3_free(errorMsg);

    if (result == SQLITE_OK) {
      return YES;
    }

    if ([self attemptRecoveryForResult:result context:@"createTables" didRetry:&didRetry]) {
      continue;
    }

    os_log_error(logHandle, "Failed to create tables: %{public}@", message);
    return NO;
  }
}

#pragma mark - Rule Management

- (BOOL)addRule:(DNSRule*)rule error:(NSError**)error {
  return [self addRules:@[ rule ] error:error];
}

- (BOOL)addRules:(NSArray<DNSRule*>*)rules error:(NSError**)error {
  __block BOOL success = NO;
  __block NSError* blockError = nil;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    BOOL useBulkOptimizations = (rules.count > 100);

    while (YES) {
      if (!self.database && ![self openDatabaseLocked]) {
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:SQLITE_CANTOPEN
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to open database"}];
        break;
      }

      BOOL pragmasApplied = NO;
      if (useBulkOptimizations) {
        sqlite3_exec(self.database, "PRAGMA synchronous = OFF", NULL, NULL, NULL);
        sqlite3_exec(self.database, "PRAGMA temp_store = MEMORY", NULL, NULL, NULL);
        sqlite3_exec(self.database, "PRAGMA cache_size = 10000", NULL, NULL, NULL);
        pragmasApplied = YES;
      }

      if (![self beginTransaction]) {
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:SQLITE_ERROR
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to begin transaction"}];
        if (pragmasApplied && self.database) {
          sqlite3_exec(self.database, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);
        }
        break;
      }

      const char* insertSQL =
          "INSERT OR REPLACE INTO dns_rules "
          "(domain, action, type, priority, source, custom_msg, updated_at, expires_at, comment) "
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

      sqlite3_stmt* statement = NULL;
      int prepareResult = sqlite3_prepare_v2(self.database, insertSQL, -1, &statement, NULL);

      if (prepareResult != SQLITE_OK) {
        if (statement)
          sqlite3_finalize(statement);
        BOOL shouldRetry = [self attemptRecoveryForResult:prepareResult
                                                  context:@"addRules.prepare"
                                                 didRetry:&didRetry];
        if (pragmasApplied && self.database) {
          sqlite3_exec(self.database, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);
        }
        if (shouldRetry) {
          continue;
        }

        os_log_error(logHandle, "Failed to prepare insert statement: %d", prepareResult);
        [self rollbackTransaction];
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:prepareResult
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to add rules"}];
        break;
      }

      BOOL shouldRetry = NO;
      int stepResult = SQLITE_DONE;

      for (DNSRule* rule in rules) {
        sqlite3_bind_text(statement, 1, [rule.domain UTF8String], -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 2, (int)rule.action);
        sqlite3_bind_int(statement, 3, (int)rule.type);
        sqlite3_bind_int(statement, 4, (int)rule.priority);
        sqlite3_bind_int(statement, 5, (int)rule.source);

        if (rule.customMessage) {
          sqlite3_bind_text(statement, 6, [rule.customMessage UTF8String], -1, SQLITE_TRANSIENT);
        } else {
          sqlite3_bind_null(statement, 6);
        }

        sqlite3_bind_text(
            statement, 7,
            [[self.dateFormatter stringFromDate:rule.updatedAt ?: [NSDate date]] UTF8String], -1,
            SQLITE_TRANSIENT);

        if (rule.expiresAt) {
          sqlite3_bind_text(statement, 8,
                            [[self.dateFormatter stringFromDate:rule.expiresAt] UTF8String], -1,
                            SQLITE_TRANSIENT);
        } else {
          sqlite3_bind_null(statement, 8);
        }

        if (rule.comment) {
          sqlite3_bind_text(statement, 9, [rule.comment UTF8String], -1, SQLITE_TRANSIENT);
        } else {
          sqlite3_bind_null(statement, 9);
        }

        stepResult = sqlite3_step(statement);
        if (stepResult != SQLITE_DONE) {
          shouldRetry = [self attemptRecoveryForResult:stepResult
                                               context:@"addRules.step"
                                              didRetry:&didRetry];
          if (!shouldRetry) {
            os_log_error(logHandle, "Failed to insert rule for domain %{public}@: %d", rule.domain,
                         stepResult);
            blockError =
                [NSError errorWithDomain:@"com.dnshield.database"
                                    code:stepResult
                                userInfo:@{NSLocalizedDescriptionKey : @"Failed to add rules"}];
          }
          break;
        }

        sqlite3_reset(statement);
      }

      sqlite3_finalize(statement);

      if (shouldRetry) {
        if (pragmasApplied && self.database) {
          sqlite3_exec(self.database, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);
        }
        continue;
      }

      if (stepResult == SQLITE_DONE) {
        success = [self commitTransaction];
        if (success) {
          os_log_info(logHandle, "Added %lu rules to database", (unsigned long)rules.count);
        } else {
          blockError =
              [NSError errorWithDomain:@"com.dnshield.database"
                                  code:SQLITE_ERROR
                              userInfo:@{NSLocalizedDescriptionKey : @"Failed to commit rules"}];
        }
      } else {
        [self rollbackTransaction];
      }

      if (pragmasApplied && self.database) {
        sqlite3_exec(self.database, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);
      }

      break;
    }
  });

  if (!success && error) {
    *error = blockError;
  }

  return success;
}

- (BOOL)removeRuleForDomain:(NSString*)domain error:(NSError**)error {
  __block BOOL success = NO;
  __block NSError* blockError = nil;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      if (!self.database && ![self openDatabaseLocked]) {
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:SQLITE_CANTOPEN
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to open database"}];
        break;
      }

      const char* deleteSQL = "DELETE FROM dns_rules WHERE domain = ?";
      sqlite3_stmt* statement = NULL;

      int result = sqlite3_prepare_v2(self.database, deleteSQL, -1, &statement, NULL);
      if (result != SQLITE_OK) {
        if (statement)
          sqlite3_finalize(statement);
        if ([self attemptRecoveryForResult:result
                                   context:@"removeRuleForDomain.prepare"
                                  didRetry:&didRetry]) {
          continue;
        }

        os_log_error(logHandle, "Failed to prepare delete statement: %d", result);
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:result
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to remove rule"}];
        break;
      }

      sqlite3_bind_text(statement, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);

      result = sqlite3_step(statement);
      sqlite3_finalize(statement);

      if (result == SQLITE_DONE) {
        success = YES;
        os_log_info(logHandle, "Removed rule for domain: %{public}@", domain);
        break;
      }

      if ([self attemptRecoveryForResult:result
                                 context:@"removeRuleForDomain.step"
                                didRetry:&didRetry]) {
        continue;
      }

      blockError =
          [NSError errorWithDomain:@"com.dnshield.database"
                              code:result
                          userInfo:@{NSLocalizedDescriptionKey : @"Failed to remove rule"}];
      break;
    }
  });

  if (!success && error) {
    *error = blockError;
  }

  return success;
}

- (BOOL)removeAllRulesFromSource:(DNSRuleSource)source error:(NSError**)error {
  __block BOOL success = NO;
  __block NSError* blockError = nil;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      if (!self.database && ![self openDatabaseLocked]) {
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:SQLITE_CANTOPEN
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to open database"}];
        break;
      }

      const char* deleteSQL = "DELETE FROM dns_rules WHERE source = ?";
      sqlite3_stmt* statement = NULL;

      int result = sqlite3_prepare_v2(self.database, deleteSQL, -1, &statement, NULL);
      if (result != SQLITE_OK) {
        if (statement)
          sqlite3_finalize(statement);
        if ([self attemptRecoveryForResult:result
                                   context:@"removeAllRulesFromSource.prepare"
                                  didRetry:&didRetry]) {
          continue;
        }

        os_log_error(logHandle, "Failed to prepare delete statement: %d", result);
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:result
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to remove rules"}];
        break;
      }

      sqlite3_bind_int(statement, 1, (int)source);

      result = sqlite3_step(statement);
      int deletedCount = sqlite3_changes(self.database);
      sqlite3_finalize(statement);

      if (result == SQLITE_DONE) {
        success = YES;
        os_log_info(logHandle, "Removed %d rules from source %ld", deletedCount, (long)source);
        break;
      }

      if ([self attemptRecoveryForResult:result
                                 context:@"removeAllRulesFromSource.step"
                                didRetry:&didRetry]) {
        continue;
      }

      blockError =
          [NSError errorWithDomain:@"com.dnshield.database"
                              code:result
                          userInfo:@{NSLocalizedDescriptionKey : @"Failed to remove rules"}];
      break;
    }
  });

  if (!success && error) {
    *error = blockError;
  }

  return success;
}

- (BOOL)removeExpiredRules:(NSError**)error {
  __block BOOL success = NO;
  __block NSError* blockError = nil;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      if (!self.database && ![self openDatabaseLocked]) {
        blockError =
            [NSError errorWithDomain:@"com.dnshield.database"
                                code:SQLITE_CANTOPEN
                            userInfo:@{NSLocalizedDescriptionKey : @"Failed to open database"}];
        break;
      }

      NSString* nowStr = [self.dateFormatter stringFromDate:[NSDate date]];
      NSString* deleteSQL = [NSString
          stringWithFormat:
              @"DELETE FROM dns_rules WHERE expires_at IS NOT NULL AND expires_at < '%@'", nowStr];

      char* errorMsg = NULL;
      int result = sqlite3_exec(self.database, [deleteSQL UTF8String], NULL, NULL, &errorMsg);
      NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
      if (errorMsg)
        sqlite3_free(errorMsg);

      if (result == SQLITE_OK) {
        success = YES;
        int deletedCount = sqlite3_changes(self.database);
        if (deletedCount > 0) {
          os_log_info(logHandle, "Removed %d expired rules", deletedCount);
        }
        break;
      }

      if ([self attemptRecoveryForResult:result context:@"removeExpiredRules" didRetry:&didRetry]) {
        continue;
      }

      os_log_error(logHandle, "Failed to remove expired rules: %{public}@", message);
      blockError = [NSError
          errorWithDomain:@"com.dnshield.database"
                     code:result
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to remove expired rules"}];
      break;
    }
  });

  if (!success && error) {
    *error = blockError;
  }

  return success;
}

#pragma mark - Rule Queries

- (DNSRule*)lookupRuleForDomainUnlocked:(NSString*)domain {
  DNSRule* matchedRule = nil;
  BOOL didRetry = NO;

  while (YES) {
    matchedRule = nil;

    BOOL shouldRetry = NO;
    BOOL shouldAbort = NO;

    sqlite3_stmt* statement = NULL;
    RuleDatabaseOutcome outcome =
        [self prepareStatement:"SELECT domain, action, type, priority, source, custom_msg, "
                               "updated_at, expires_at, comment "
                               "FROM dns_rules WHERE domain = ?1 "
                               "ORDER BY priority DESC LIMIT 1"
                       context:@"ruleForDomain.exact.prepare"
                      didRetry:&didRetry
                     statement:&statement];

    if (outcome == RuleDatabaseOutcomeRetry) {
      shouldRetry = YES;
    } else if (outcome == RuleDatabaseOutcomeFailure) {
      shouldAbort = YES;
    } else {
      sqlite3_bind_text(statement, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:statement
                            context:@"ruleForDomain.exact.step"
                           didRetry:&didRetry
                             result:&stepResult];

      if (outcome == RuleDatabaseOutcomeRetry) {
        shouldRetry = YES;
      } else if (outcome == RuleDatabaseOutcomeFailure) {
        shouldAbort = YES;
      } else if (stepResult == SQLITE_ROW) {
        matchedRule = [self ruleFromStatement:statement];
      }
      sqlite3_finalize(statement);
    }

    if (shouldRetry) {
      continue;
    }
    if (shouldAbort) {
      break;
    }
    if (matchedRule)
      break;

    NSString* wildcardForDomain = [NSString stringWithFormat:@"*.%@", domain];
    const char* wildcardSQL = "SELECT domain, action, type, priority, source, custom_msg, "
                              "updated_at, expires_at, comment "
                              "FROM dns_rules WHERE domain = ?1 AND type = 1 "
                              "ORDER BY priority DESC LIMIT 1";

    sqlite3_stmt* wildcardStatement = NULL;
    outcome = [self prepareStatement:wildcardSQL
                             context:@"ruleForDomain.wildcardSelf.prepare"
                            didRetry:&didRetry
                           statement:&wildcardStatement];

    if (outcome == RuleDatabaseOutcomeRetry) {
      continue;
    }
    if (outcome == RuleDatabaseOutcomeFailure) {
      shouldAbort = YES;
    } else {
      sqlite3_bind_text(wildcardStatement, 1, [wildcardForDomain UTF8String], -1, SQLITE_TRANSIENT);

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:wildcardStatement
                            context:@"ruleForDomain.wildcardSelf.step"
                           didRetry:&didRetry
                             result:&stepResult];

      if (outcome == RuleDatabaseOutcomeRetry) {
        sqlite3_finalize(wildcardStatement);
        shouldRetry = YES;
      } else if (outcome == RuleDatabaseOutcomeFailure) {
        sqlite3_finalize(wildcardStatement);
        shouldAbort = YES;
      } else if (stepResult == SQLITE_ROW) {
        matchedRule = [self ruleFromStatement:wildcardStatement];
      }
      sqlite3_finalize(wildcardStatement);
    }

    if (shouldRetry) {
      continue;
    }
    if (shouldAbort) {
      break;
    }
    if (matchedRule)
      break;

    NSArray* domainParts = [domain componentsSeparatedByString:@"."];
    for (NSInteger i = 0; i < domainParts.count - 1 && !matchedRule; i++) {
      sqlite3_stmt* parentWildcardStatement = NULL;
      outcome = [self prepareStatement:wildcardSQL
                               context:@"ruleForDomain.parentWildcard.prepare"
                              didRetry:&didRetry
                             statement:&parentWildcardStatement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        shouldRetry = YES;
        break;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        shouldAbort = YES;
        break;
      }

      NSArray* parentParts =
          [domainParts subarrayWithRange:NSMakeRange(i + 1, domainParts.count - i - 1)];
      NSString* wildcardDomain =
          [NSString stringWithFormat:@"*.%@", [parentParts componentsJoinedByString:@"."]];

      sqlite3_bind_text(parentWildcardStatement, 1, [wildcardDomain UTF8String], -1,
                        SQLITE_TRANSIENT);

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:parentWildcardStatement
                            context:@"ruleForDomain.parentWildcard.step"
                           didRetry:&didRetry
                             result:&stepResult];

      if (outcome == RuleDatabaseOutcomeRetry) {
        sqlite3_finalize(parentWildcardStatement);
        shouldRetry = YES;
        break;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        sqlite3_finalize(parentWildcardStatement);
        shouldAbort = YES;
        break;
      }

      if (stepResult == SQLITE_ROW) {
        matchedRule = [self ruleFromStatement:parentWildcardStatement];
      }

      sqlite3_finalize(parentWildcardStatement);
    }

    if (shouldRetry) {
      continue;
    }
    if (shouldAbort) {
      break;
    }

    break;
  }

  return matchedRule;
}

- (nullable DNSRule*)ruleForDomain:(NSString*)domain {
  __block DNSRule* matchedRule = nil;

  dispatch_sync(self.databaseQueue, ^{
    matchedRule = [self lookupRuleForDomainUnlocked:domain];
  });

  return matchedRule;
}

- (void)ruleForDomainAsync:(NSString*)domain
                completion:(void (^)(DNSRule* _Nullable rule))completion {
  if (!completion) {
    return;
  }

  dispatch_async(self.databaseQueue, ^{
    DNSRule* matchedRule = [self lookupRuleForDomainUnlocked:domain];

    // Call completion on main queue
    dispatch_async(dispatch_get_main_queue(), ^{
      completion(matchedRule);
    });
  });
}

- (NSArray<DNSRule*>*)allRules {
  return [self executeQuery:@"SELECT * FROM dns_rules ORDER BY domain"];
}

- (NSArray<DNSRule*>*)rulesFromSource:(DNSRuleSource)source {
  NSString* query = [NSString
      stringWithFormat:@"SELECT * FROM dns_rules WHERE source = %ld ORDER BY domain", (long)source];
  return [self executeQuery:query];
}

- (NSArray<DNSRule*>*)blockedDomains {
  return [self executeQuery:@"SELECT * FROM dns_rules WHERE action = 0 ORDER BY domain"];
}

- (NSArray<DNSRule*>*)allowedDomains {
  return [self executeQuery:@"SELECT * FROM dns_rules WHERE action = 1 ORDER BY domain"];
}

#pragma mark - Batch Operations

- (BOOL)replaceAllRulesFromSource:(DNSRuleSource)source
                        withRules:(NSArray<DNSRule*>*)rules
                            error:(NSError**)error {
  __block BOOL success = NO;
  __block NSError* blockError = nil;

  dispatch_sync(self.databaseQueue, ^{
    [self beginTransaction];

    // First remove all existing rules from this source
    NSError* removeError = nil;
    if ([self removeAllRulesFromSource:source error:&removeError]) {
      // Then add the new rules
      NSError* addError = nil;
      if ([self addRules:rules error:&addError]) {
        success = [self commitTransaction];
        os_log_info(logHandle, "Replaced all rules from source %ld with %lu new rules",
                    (long)source, (unsigned long)rules.count);
      } else {
        [self rollbackTransaction];
        blockError = addError;
      }
    } else {
      [self rollbackTransaction];
      blockError = removeError;
    }
  });

  if (!success && error) {
    *error = blockError;
  }

  return success;
}

#pragma mark - Transaction Support

- (BOOL)beginTransaction {
  BOOL didRetry = NO;
  while (YES) {
    if (!self.database && ![self openDatabaseLocked])
      return NO;

    char* errorMsg = NULL;
    int result = sqlite3_exec(self.database, "BEGIN TRANSACTION", NULL, NULL, &errorMsg);
    NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
    if (errorMsg)
      sqlite3_free(errorMsg);

    if (result == SQLITE_OK) {
      return YES;
    }

    if ([self attemptRecoveryForResult:result context:@"beginTransaction" didRetry:&didRetry]) {
      continue;
    }

    os_log_error(logHandle, "Failed to begin transaction: %{public}@", message);
    return NO;
  }
}

- (BOOL)commitTransaction {
  BOOL didRetry = NO;
  while (YES) {
    if (!self.database && ![self openDatabaseLocked])
      return NO;

    char* errorMsg = NULL;
    int result = sqlite3_exec(self.database, "COMMIT", NULL, NULL, &errorMsg);
    NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
    if (errorMsg)
      sqlite3_free(errorMsg);

    if (result == SQLITE_OK) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:RuleDatabaseDidChangeNotification
                                                            object:self];
      });
      return YES;
    }

    if ([self attemptRecoveryForResult:result context:@"commitTransaction" didRetry:&didRetry]) {
      continue;
    }

    os_log_error(logHandle, "Failed to commit transaction: %{public}@", message);
    return NO;
  }
}

- (BOOL)rollbackTransaction {
  BOOL didRetry = NO;
  while (YES) {
    if (!self.database && ![self openDatabaseLocked])
      return NO;

    char* errorMsg = NULL;
    int result = sqlite3_exec(self.database, "ROLLBACK", NULL, NULL, &errorMsg);
    NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
    if (errorMsg)
      sqlite3_free(errorMsg);

    if (result == SQLITE_OK) {
      return YES;
    }

    if ([self attemptRecoveryForResult:result context:@"rollbackTransaction" didRetry:&didRetry]) {
      continue;
    }

    os_log_error(logHandle, "Failed to rollback transaction: %{public}@", message);
    return NO;
  }
}

#pragma mark - Maintenance

- (BOOL)vacuum {
  __block BOOL success = NO;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      if (!self.database && ![self openDatabaseLocked]) {
        break;
      }

      char* errorMsg = NULL;
      int result = sqlite3_exec(self.database, "VACUUM", NULL, NULL, &errorMsg);
      NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
      if (errorMsg)
        sqlite3_free(errorMsg);

      if (result == SQLITE_OK) {
        success = YES;
        os_log_info(logHandle, "Database vacuumed successfully");
        break;
      }

      if ([self attemptRecoveryForResult:result context:@"vacuum" didRetry:&didRetry]) {
        continue;
      }

      os_log_error(logHandle, "Failed to vacuum database: %{public}@", message);
      break;
    }
  });

  return success;
}

- (NSUInteger)databaseSizeInBytes {
  NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:self.databasePath
                                                                         error:nil];
  return [attrs[NSFileSize] unsignedIntegerValue];
}

- (NSUInteger)ruleCount {
  __block NSUInteger count = 0;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      sqlite3_stmt* statement = NULL;
      RuleDatabaseOutcome outcome = [self prepareStatement:"SELECT COUNT(*) FROM dns_rules"
                                                   context:@"ruleCount.prepare"
                                                  didRetry:&didRetry
                                                 statement:&statement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        break;
      }

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:statement
                            context:@"ruleCount.step"
                           didRetry:&didRetry
                             result:&stepResult];

      if (outcome == RuleDatabaseOutcomeRetry) {
        sqlite3_finalize(statement);
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        sqlite3_finalize(statement);
        break;
      }

      if (stepResult == SQLITE_ROW) {
        count = sqlite3_column_int(statement, 0);
      }

      sqlite3_finalize(statement);
      break;
    }
  });

  return count;
}

- (void)cleanupOldQueryStats:(NSTimeInterval)olderThan {
  dispatch_async(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      if (!self.database && ![self openDatabaseLocked])
        return;

      NSDate* cutoffDate = [NSDate dateWithTimeIntervalSinceNow:-olderThan];
      NSString* cutoffStr = [self.dateFormatter stringFromDate:cutoffDate];
      NSString* sql = [NSString
          stringWithFormat:@"DELETE FROM query_stats WHERE last_queried < '%@'", cutoffStr];

      char* errorMsg = NULL;
      int result = sqlite3_exec(self.database, [sql UTF8String], NULL, NULL, &errorMsg);
      NSString* message = errorMsg ? @(errorMsg) : @"Unknown error";
      if (errorMsg)
        sqlite3_free(errorMsg);

      if (result == SQLITE_OK) {
        int deletedCount = sqlite3_changes(self.database);
        if (deletedCount > 0) {
          os_log_info(logHandle, "Cleaned up %d old query stats entries", deletedCount);
        }
        break;
      }

      if ([self attemptRecoveryForResult:result
                                 context:@"cleanupOldQueryStats"
                                didRetry:&didRetry]) {
        continue;
      }

      os_log_error(logHandle, "Failed to cleanup query stats: %{public}@", message);
      break;
    }
  });
}

#pragma mark - Internal Helpers

static inline int DNPrimarySQLiteCode(int code) {
  return code & 0xFF;
}

- (RuleDatabaseOutcome)prepareStatement:(const char*)sql
                                context:(NSString*)context
                               didRetry:(BOOL*)didRetry
                              statement:(sqlite3_stmt**)outStatement {
  if (!self.database && ![self openDatabaseLocked]) {
    os_log_error(logHandle, "Database unavailable while preparing %{public}@", context);
    if (outStatement)
      *outStatement = NULL;
    return RuleDatabaseOutcomeFailure;
  }

  sqlite3_stmt* statement = NULL;
  int result = sqlite3_prepare_v2(self.database, sql, -1, &statement, NULL);

  if (result == SQLITE_OK) {
    if (outStatement)
      *outStatement = statement;
    return RuleDatabaseOutcomeSuccess;
  }

  if (statement)
    sqlite3_finalize(statement);

  if ([self attemptRecoveryForResult:result context:context didRetry:didRetry]) {
    if (outStatement)
      *outStatement = NULL;
    return RuleDatabaseOutcomeRetry;
  }

  os_log_error(logHandle, "SQLite prepare failed (%d) in %{public}@", result, context);
  if (outStatement)
    *outStatement = NULL;
  return RuleDatabaseOutcomeFailure;
}

- (RuleDatabaseOutcome)stepStatement:(sqlite3_stmt*)statement
                             context:(NSString*)context
                            didRetry:(BOOL*)didRetry
                              result:(int*)outResult {
  int stepResult = sqlite3_step(statement);
  if (outResult)
    *outResult = stepResult;

  if (stepResult == SQLITE_ROW || stepResult == SQLITE_DONE) {
    return RuleDatabaseOutcomeSuccess;
  }

  if ([self attemptRecoveryForResult:stepResult context:context didRetry:didRetry]) {
    return RuleDatabaseOutcomeRetry;
  }

  os_log_error(logHandle, "SQLite step failed (%d) in %{public}@", stepResult, context);
  return RuleDatabaseOutcomeFailure;
}

- (BOOL)attemptRecoveryForResult:(int)result context:(NSString*)context didRetry:(BOOL*)didRetry {
  if (!didRetry)
    return NO;

  int primary = DNPrimarySQLiteCode(result);
  switch (primary) {
    case SQLITE_IOERR:
    case SQLITE_CANTOPEN:
    case SQLITE_NOTADB:
    case SQLITE_CORRUPT: break;
    default: return NO;
  }

  if (*didRetry)
    return NO;

  const char* sqliteMessage = self.database ? sqlite3_errmsg(self.database) : NULL;
  NSString* errorMessage = sqliteMessage ? @(sqliteMessage) : @(sqlite3_errstr(result));

  os_log_error(logHandle,
               "SQLite error %d (%{public}@) in %{public}@; attempting to reopen rule database",
               result, errorMessage, context);

  *didRetry = YES;
  [self closeDatabaseLocked];

  if (self.databasePath.length) {
    NSError* removeError = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:self.databasePath]) {
      [[NSFileManager defaultManager] removeItemAtPath:self.databasePath error:&removeError];
      if (removeError) {
        os_log_error(logHandle, "Failed to remove corrupted database at %{public}@ (%{public}@)",
                     self.databasePath, removeError.localizedDescription);
      } else {
        os_log_info(logHandle, "Removed corrupted database at %{public}@ before reopening",
                    self.databasePath);
      }
    }
  }

  BOOL reopened = [self openDatabaseLocked];

  if (reopened) {
    os_log_info(logHandle, "Successfully reopened rule database after %{public}@ failure", context);
    return YES;
  }

  os_log_error(logHandle, "Failed to reopen rule database after %{public}@ failure", context);
  return NO;
}

- (BOOL)openDatabase {
  __block BOOL success = NO;
  dispatch_sync(self.databaseQueue, ^{
    success = [self openDatabaseLocked];
  });
  return success;
}

- (BOOL)openDatabaseLocked {
  if (self.database)
    return YES;

  NSString* dbDir = kDefaultDBPath;
  NSFileManager* fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:dbDir]) {
    NSError* error = nil;
    NSDictionary* attributes = @{NSFilePosixPermissions : @(0755)};
    [fm createDirectoryAtPath:dbDir
        withIntermediateDirectories:YES
                         attributes:attributes
                              error:&error];
    if (error) {
      os_log_error(logHandle, "Failed to create database directory: %{public}@", error);
    }
  }

  _databasePath = [dbDir stringByAppendingPathComponent:@"rules.db"];
  if (!self.databaseQueue) {
    self.databaseQueue = dispatch_queue_create("com.dnshield.database", DISPATCH_QUEUE_SERIAL);
  }

  if (!self.dateFormatter) {
    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    _dateFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
  }

  NSFileManager* fileManager = [NSFileManager defaultManager];
  BOOL databaseExists = [fileManager fileExistsAtPath:self.databasePath];

  if (!databaseExists) {
    NSBundle* mainBundle = [NSBundle mainBundle];
    NSString* preseedPath = [mainBundle pathForResource:@"rules_preseed" ofType:@"db"];

    if (preseedPath && [fileManager fileExistsAtPath:preseedPath]) {
      os_log_info(logHandle, "Found pre-seeded database, copying to %{public}@", self.databasePath);

      NSString* dbDirectory = [self.databasePath stringByDeletingLastPathComponent];
      NSError* error = nil;
      [fileManager createDirectoryAtPath:dbDirectory
             withIntermediateDirectories:YES
                              attributes:nil
                                   error:&error];

      if (!error) {
        error = nil;
        [fileManager copyItemAtPath:preseedPath toPath:self.databasePath error:&error];

        if (error) {
          os_log_error(logHandle, "Failed to copy pre-seeded database: %{public}@",
                       error.localizedDescription);
        } else {
          os_log_info(logHandle, "Successfully copied pre-seeded database");
        }
      } else {
        os_log_error(logHandle, "Failed to create database directory: %{public}@",
                     error.localizedDescription);
      }
    } else {
      os_log_info(logHandle, "No pre-seeded database found, creating new database");
    }
  }

  int result =
      sqlite3_open_v2([self.databasePath UTF8String], &_database,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);

  if (result == SQLITE_OK) {
    sqlite3_exec(self.database, "PRAGMA journal_mode = WAL", NULL, NULL, NULL);
    sqlite3_exec(self.database, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);
    sqlite3_exec(self.database, "PRAGMA cache_size = 10000", NULL, NULL, NULL);
    sqlite3_exec(self.database, "PRAGMA temp_store = MEMORY", NULL, NULL, NULL);

    BOOL created = [self createTablesIfNeeded];
    if (!created) {
      sqlite3_close(self.database);
      self.database = NULL;
      return NO;
    }

    os_log_info(logHandle, "Database opened successfully at %{public}@", self.databasePath);
    return YES;
  }

  os_log_error(logHandle, "Failed to open database: %d", result);
  if (self.database) {
    sqlite3_close(self.database);
    self.database = NULL;
  }
  return NO;
}

- (void)closeDatabase {
  dispatch_sync(self.databaseQueue, ^{
    [self closeDatabaseLocked];
  });
}

- (void)closeDatabaseLocked {
  if (self.database) {
    sqlite3_close(self.database);
    self.database = NULL;
    os_log_info(logHandle, "Database closed");
  }
}

- (NSDate*)lastUpdated {
  __block NSDate* lastUpdate = nil;

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      sqlite3_stmt* statement = NULL;
      RuleDatabaseOutcome outcome = [self prepareStatement:"SELECT MAX(updated_at) FROM dns_rules"
                                                   context:@"lastUpdated.prepare"
                                                  didRetry:&didRetry
                                                 statement:&statement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        break;
      }

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:statement
                            context:@"lastUpdated.step"
                           didRetry:&didRetry
                             result:&stepResult];

      if (outcome == RuleDatabaseOutcomeRetry) {
        sqlite3_finalize(statement);
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        sqlite3_finalize(statement);
        break;
      }

      if (stepResult == SQLITE_ROW) {
        const char* dateStr = (const char*)sqlite3_column_text(statement, 0);
        if (dateStr) {
          lastUpdate = [self.dateFormatter dateFromString:@(dateStr)];
        }
      }

      sqlite3_finalize(statement);
      break;
    }
  });

  return lastUpdate;
}

#pragma mark - Helper Methods

- (DNSRule*)ruleFromStatement:(sqlite3_stmt*)statement {
  DNSRule* rule = [[DNSRule alloc] init];

  rule.domain = @((const char*)sqlite3_column_text(statement, 0));
  rule.action = sqlite3_column_int(statement, 1);
  rule.type = sqlite3_column_int(statement, 2);
  rule.priority = sqlite3_column_int(statement, 3);
  rule.source = sqlite3_column_int(statement, 4);

  const char* customMsg = (const char*)sqlite3_column_text(statement, 5);
  if (customMsg)
    rule.customMessage = @(customMsg);

  const char* updatedAt = (const char*)sqlite3_column_text(statement, 6);
  if (updatedAt)
    rule.updatedAt = [self.dateFormatter dateFromString:@(updatedAt)];

  const char* expiresAt = (const char*)sqlite3_column_text(statement, 7);
  if (expiresAt)
    rule.expiresAt = [self.dateFormatter dateFromString:@(expiresAt)];

  const char* comment = (const char*)sqlite3_column_text(statement, 8);
  if (comment)
    rule.comment = @(comment);

  return rule;
}

- (NSArray<DNSRule*>*)executeQuery:(NSString*)query {
  __block NSMutableArray<DNSRule*>* rules = [NSMutableArray array];

  dispatch_sync(self.databaseQueue, ^{
    BOOL didRetry = NO;
    while (YES) {
      sqlite3_stmt* statement = NULL;
      RuleDatabaseOutcome outcome = [self prepareStatement:[query UTF8String]
                                                   context:@"executeQuery.prepare"
                                                  didRetry:&didRetry
                                                 statement:&statement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        [rules removeAllObjects];
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        [rules removeAllObjects];
        break;
      }

      BOOL shouldRetry = NO;
      while (YES) {
        int stepResult = SQLITE_DONE;
        outcome = [self stepStatement:statement
                              context:@"executeQuery.step"
                             didRetry:&didRetry
                               result:&stepResult];

        if (outcome == RuleDatabaseOutcomeRetry) {
          shouldRetry = YES;
          break;
        }
        if (outcome == RuleDatabaseOutcomeFailure) {
          shouldRetry = NO;
          break;
        }

        if (stepResult == SQLITE_ROW) {
          [rules addObject:[self ruleFromStatement:statement]];
          continue;
        }
        break;
      }

      sqlite3_finalize(statement);

      if (shouldRetry) {
        [rules removeAllObjects];
        continue;
      }

      break;
    }
  });

  return [rules copy];
}

#pragma mark - Query Statistics

- (void)recordQueryForDomain:(NSString*)domain {
  dispatch_async(self.databaseQueue, ^{
    const char* sql = "INSERT INTO query_stats (domain, query_count, last_queried, created_at) "
                      "VALUES (?, 1, ?, ?) "
                      "ON CONFLICT(domain) DO UPDATE SET "
                      "query_count = query_count + 1, "
                      "last_queried = excluded.last_queried";

    BOOL didRetry = NO;
    while (YES) {
      sqlite3_stmt* statement = NULL;
      RuleDatabaseOutcome outcome = [self prepareStatement:sql
                                                   context:@"recordQuery.prepare"
                                                  didRetry:&didRetry
                                                 statement:&statement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        break;
      }

      NSString* now = [self.dateFormatter stringFromDate:[NSDate date]];
      sqlite3_bind_text(statement, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(statement, 2, [now UTF8String], -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(statement, 3, [now UTF8String], -1, SQLITE_TRANSIENT);

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:statement
                            context:@"recordQuery.step"
                           didRetry:&didRetry
                             result:&stepResult];
      sqlite3_finalize(statement);

      if (outcome == RuleDatabaseOutcomeRetry) {
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        break;
      }

      break;
    }
  });
}

- (NSArray<NSString*>*)mostQueriedDomains:(NSUInteger)limit {
  __block NSMutableArray<NSString*>* domains = [NSMutableArray array];

  dispatch_sync(self.databaseQueue, ^{
    NSString* sql = [NSString stringWithFormat:@"SELECT domain FROM query_stats "
                                               @"ORDER BY query_count DESC, last_queried DESC "
                                               @"LIMIT %lu",
                                               (unsigned long)limit];

    BOOL didRetry = NO;
    while (YES) {
      sqlite3_stmt* statement = NULL;
      RuleDatabaseOutcome outcome = [self prepareStatement:[sql UTF8String]
                                                   context:@"mostQueriedDomains.prepare"
                                                  didRetry:&didRetry
                                                 statement:&statement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        [domains removeAllObjects];
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        [domains removeAllObjects];
        break;
      }

      BOOL shouldRetry = NO;
      while (YES) {
        int stepResult = SQLITE_DONE;
        outcome = [self stepStatement:statement
                              context:@"mostQueriedDomains.step"
                             didRetry:&didRetry
                               result:&stepResult];

        if (outcome == RuleDatabaseOutcomeRetry) {
          shouldRetry = YES;
          break;
        }
        if (outcome == RuleDatabaseOutcomeFailure) {
          shouldRetry = NO;
          break;
        }

        if (stepResult == SQLITE_ROW) {
          const char* domain = (const char*)sqlite3_column_text(statement, 0);
          if (domain) {
            [domains addObject:@(domain)];
          }
          continue;
        }
        break;
      }

      sqlite3_finalize(statement);

      if (shouldRetry) {
        [domains removeAllObjects];
        continue;
      }

      break;
    }
  });

  return [domains copy];
}

- (NSUInteger)queryCountForDomain:(NSString*)domain {
  __block NSUInteger count = 0;

  dispatch_sync(self.databaseQueue, ^{
    const char* sql = "SELECT query_count FROM query_stats WHERE domain = ?";
    BOOL didRetry = NO;

    while (YES) {
      sqlite3_stmt* statement = NULL;
      RuleDatabaseOutcome outcome = [self prepareStatement:sql
                                                   context:@"queryCount.prepare"
                                                  didRetry:&didRetry
                                                 statement:&statement];

      if (outcome == RuleDatabaseOutcomeRetry) {
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        break;
      }

      sqlite3_bind_text(statement, 1, [domain UTF8String], -1, SQLITE_TRANSIENT);

      int stepResult = SQLITE_DONE;
      outcome = [self stepStatement:statement
                            context:@"queryCount.step"
                           didRetry:&didRetry
                             result:&stepResult];

      if (outcome == RuleDatabaseOutcomeRetry) {
        sqlite3_finalize(statement);
        continue;
      }
      if (outcome == RuleDatabaseOutcomeFailure) {
        sqlite3_finalize(statement);
        break;
      }

      if (stepResult == SQLITE_ROW) {
        count = sqlite3_column_int(statement, 0);
      }

      sqlite3_finalize(statement);
      break;
    }
  });

  return count;
}

@end
