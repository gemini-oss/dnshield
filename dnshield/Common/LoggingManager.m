//
//  LoggingManager.m
//  DNShield Network Extension
//
//

#import "LoggingManager.h"
#import <Common/LoggingUtils.h>
#import <os/log.h>
#import "Defaults.h"

@interface LoggingManager ()
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, os_log_t>* logHandles;
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, NSNumber*>* logLevels;
@property(nonatomic, strong) NSMutableDictionary<NSString*, NSDate*>* performanceTimers;
@property(nonatomic, strong) dispatch_queue_t loggingQueue;
@property(nonatomic, assign) BOOL debugMode;
@end

os_log_t DNCreateLogHandle(NSString* subsystem, NSString* category) {
  const char* subsystemCString = subsystem ? subsystem.UTF8String : "";
  const char* categoryCString = category ? category.UTF8String : "";
  return os_log_create(subsystemCString, categoryCString);
}

@implementation LoggingManager

+ (instancetype)sharedManager {
  static LoggingManager* sharedManager = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedManager = [[LoggingManager alloc] init];
  });
  return sharedManager;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _logHandles = [NSMutableDictionary dictionary];
    _logLevels = [NSMutableDictionary dictionary];
    _performanceTimers = [NSMutableDictionary dictionary];
    _loggingQueue = dispatch_queue_create("com.dnshield.logging", DISPATCH_QUEUE_SERIAL);

    [self initializeLogHandles];
    [self setDefaultLogLevels];
  }
  return self;
}

- (void)initializeLogHandles {
  NSString* version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (!version) {
    // Try extension bundle if main bundle doesn't work
    NSBundle* extensionBundle = [NSBundle bundleWithIdentifier:kDefaultExtensionBundleID];
    if (extensionBundle) {
      version = [extensionBundle objectForInfoDictionaryKey:@"CFBundleVersion"];
    }
  }
  if (!version) {
    version = @"unknown";
  }

  // Create subsystem with version included
  NSString* subsystemWithVersion =
      [NSString stringWithFormat:@"%@:%@", kDefaultExtensionBundleID, version];
  const char* subsystem = DNUTF8(subsystemWithVersion);

  self.logHandles[@(LogCategoryGeneral)] = os_log_create(subsystem, "general");
  self.logHandles[@(LogCategoryConfiguration)] = os_log_create(subsystem, "configuration");
  self.logHandles[@(LogCategoryRuleFetching)] = os_log_create(subsystem, "rule_fetching");
  self.logHandles[@(LogCategoryRuleParsing)] = os_log_create(subsystem, "rule_parsing");
  self.logHandles[@(LogCategoryCache)] = os_log_create(subsystem, "cache");
  self.logHandles[@(LogCategoryScheduler)] = os_log_create(subsystem, "scheduler");
  self.logHandles[@(LogCategoryDNS)] = os_log_create(subsystem, "dns");
  self.logHandles[@(LogCategoryPerformance)] = os_log_create(subsystem, "performance");
  self.logHandles[@(LogCategoryNetwork)] = os_log_create(subsystem, "network");
  self.logHandles[@(LogCategoryError)] = os_log_create(subsystem, "error");
  self.logHandles[@(LogCategoryTelemetry)] = os_log_create(subsystem, "telemetry");
}

- (void)setDefaultLogLevels {
  // Set default log levels
  for (NSInteger i = LogCategoryGeneral; i <= LogCategoryTelemetry; i++) {
    self.logLevels[@(i)] = @(LogLevelInfo);
  }

  // Error category defaults to error level
  self.logLevels[@(LogCategoryError)] = @(LogLevelError);
  self.logLevels[@(LogCategoryTelemetry)] = @(LogLevelInfo);
}

#pragma mark - Log Handle Management

- (os_log_t)logHandleForCategory:(LogCategory)category {
  os_log_t handle = self.logHandles[@(category)];
  return handle ?: OS_LOG_DEFAULT;
}

- (NSString*)nameForCategory:(LogCategory)category {
  switch (category) {
    case LogCategoryGeneral: return @"General";
    case LogCategoryConfiguration: return @"Configuration";
    case LogCategoryRuleFetching: return @"Rule Fetching";
    case LogCategoryRuleParsing: return @"Rule Parsing";
    case LogCategoryCache: return @"Cache";
    case LogCategoryScheduler: return @"Scheduler";
    case LogCategoryDNS: return @"DNS";
    case LogCategoryPerformance: return @"Performance";
    case LogCategoryNetwork: return @"Network";
    case LogCategoryError: return @"Error";
    case LogCategoryTelemetry: return @"Telemetry";
    default: return @"Unknown";
  }
}

#pragma mark - Configuration

- (void)configureWithDebugMode:(BOOL)debugMode {
  self.debugMode = debugMode;

  if (debugMode) {
    // Set all categories to debug level in debug mode
    for (NSInteger i = LogCategoryGeneral; i <= LogCategoryTelemetry; i++) {
      [self setLogLevel:LogLevelDebug forCategory:i];
    }
  }
}

- (void)setLogLevel:(LogLevel)level forCategory:(LogCategory)category {
  dispatch_sync(self.loggingQueue, ^{
    self.logLevels[@(category)] = @(level);
  });
}

- (LogLevel)logLevelForCategory:(LogCategory)category {
  __block LogLevel level;
  dispatch_sync(self.loggingQueue, ^{
    level = [self.logLevels[@(category)] integerValue];
  });
  return level;
}

- (void)setPrivacySensitive:(BOOL)sensitive forCategory:(LogCategory)category {
  // Note: Privacy levels are set at compile time in macOS logging
  // This method is here for API completeness but has limited effect
  // In practice, you would use %{private}@ vs %{public}@ in format strings
  os_log_t handle = [self logHandleForCategory:category];
  os_log_info(handle, "Privacy sensitivity %{public}@ for category %{public}@",
              sensitive ? @"enabled" : @"disabled", [self nameForCategory:category]);
}

#pragma mark - Performance Logging

- (void)logPerformanceStart:(NSString*)operation {
  dispatch_async(self.loggingQueue, ^{
    self.performanceTimers[operation] = [NSDate date];

    os_log_t handle = [self logHandleForCategory:LogCategoryPerformance];
    os_log_debug(handle, "Performance tracking started: %{public}@", operation);
  });
}

- (void)logPerformanceEnd:(NSString*)operation {
  dispatch_async(self.loggingQueue, ^{
    NSDate* startDate = self.performanceTimers[operation];
    if (!startDate) {
      os_log_error([self logHandleForCategory:LogCategoryPerformance],
                   "No start time found for operation: %{public}@", operation);
      return;
    }

    NSTimeInterval elapsed = -[startDate timeIntervalSinceNow];
    [self.performanceTimers removeObjectForKey:operation];

    os_log_t handle = [self logHandleForCategory:LogCategoryPerformance];
    os_log_info(handle, "Performance: %{public}@ completed in %.3f seconds", operation, elapsed);

    // Also log to metrics
    [self logMetric:[NSString stringWithFormat:@"performance.%@", operation]
              value:@(elapsed * 1000)  // Convert to milliseconds
           category:LogCategoryPerformance];
  });
}

- (NSTimeInterval)elapsedTimeForOperation:(NSString*)operation {
  __block NSTimeInterval elapsed = 0;
  dispatch_sync(self.loggingQueue, ^{
    NSDate* startDate = self.performanceTimers[operation];
    if (startDate) {
      elapsed = -[startDate timeIntervalSinceNow];
    }
  });
  return elapsed;
}

#pragma mark - Structured Logging

- (void)logEvent:(NSString*)event
        category:(LogCategory)category
           level:(LogLevel)level
      attributes:(nullable NSDictionary*)attributes {
  os_log_t handle = [self logHandleForCategory:category];

  // Check if we should log at this level
  if (level < [self logLevelForCategory:category]) {
    return;
  }

  // Format attributes if provided
  NSString* attributeString = @"";
  if (attributes.count > 0) {
    // Sanitize attributes to handle non-JSON-serializable types like NSDate
    NSDictionary* sanitizedAttributes = [self sanitizeAttributesForJSON:attributes];

    NSError* error;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:sanitizedAttributes
                                                       options:0
                                                         error:&error];
    if (jsonData && !error) {
      attributeString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    } else if (error) {
      os_log_error(handle, "Failed to serialize attributes: %{public}@",
                   error.localizedDescription);
    }
  }

  // Log based on level
  switch (level) {
    case LogLevelDebug:
      os_log_debug(handle, "%{public}@ %{public}@", event, attributeString);
      break;
    case LogLevelInfo: os_log_info(handle, "%{public}@ %{public}@", event, attributeString); break;
    case LogLevelDefault: os_log(handle, "%{public}@ %{public}@", event, attributeString); break;
    case LogLevelError:
      os_log_error(handle, "%{public}@ %{public}@", event, attributeString);
      break;
    case LogLevelFault:
      os_log_fault(handle, "%{public}@ %{public}@", event, attributeString);
      break;
  }
}

#pragma mark - Error Logging

- (void)logError:(NSError*)error
        category:(LogCategory)category
         context:(nullable NSString*)context {
  os_log_t handle = [self logHandleForCategory:category];

  NSMutableDictionary* errorInfo = [NSMutableDictionary dictionary];
  errorInfo[@"domain"] = error.domain;
  errorInfo[@"code"] = @(error.code);
  errorInfo[@"description"] = error.localizedDescription;

  if (error.userInfo.count > 0) {
    errorInfo[@"userInfo"] = error.userInfo.description;
  }

  if (context) {
    errorInfo[@"context"] = context;
  }

  // Log to error category
  os_log_error(handle, "[ERROR] %{public}@ - %{public}@", context ?: @"Unknown context",
               error.localizedDescription);

  // Also log structured event
  [self logEvent:@"error.occurred" category:category level:LogLevelError attributes:errorInfo];
}

#pragma mark - Metrics Logging

- (void)logMetric:(NSString*)metric value:(NSNumber*)value category:(LogCategory)category {
  os_log_t handle = [self logHandleForCategory:category];

  // Log metric with timestamp
  NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];

  os_log_info(handle, "[METRIC] %{public}@ = %{public}@ @ %.0f", metric, value, timestamp);

  // Could also send to analytics service here
}

#pragma mark - Log File Management

- (nullable NSString*)currentLogFilePath {
  // System logs are managed by the OS
  // This would return path to exported logs if implemented
  return nil;
}

- (NSArray<NSString*>*)availableLogFiles {
  // Would return list of exported log files
  return @[];
}

- (BOOL)exportLogsToPath:(NSString*)path error:(NSError**)error {
  // This method returns NO with an appropriate error
  if (error) {
    *error = [NSError
        errorWithDomain:@"com.dnshield.logging"
                   code:1001
               userInfo:@{
                 NSLocalizedDescriptionKey : @"Log export not available in system extension",
                 NSLocalizedRecoverySuggestionErrorKey : @"Use the main app to export logs"
               }];
  }

  os_log_error([self logHandleForCategory:LogCategoryGeneral],
               "Log export requested but not available in system extension context");

  return NO;
}

#pragma mark - Private Helpers

- (id)sanitizeAttributesForJSON:(id)object {
  if ([object isKindOfClass:[NSDate class]]) {
    // Convert NSDate to ISO 8601 string
    static NSDateFormatter* formatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
      formatter = [[NSDateFormatter alloc] init];
      formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSSZ";
      formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
    });
    return [formatter stringFromDate:object];
  } else if ([object isKindOfClass:[NSDictionary class]]) {
    // Recursively sanitize dictionary values
    NSMutableDictionary* sanitized = [NSMutableDictionary dictionaryWithCapacity:[object count]];
    [(NSDictionary*)object enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL* stop) {
      sanitized[key] = [self sanitizeAttributesForJSON:obj];
    }];
    return sanitized;
  } else if ([object isKindOfClass:[NSArray class]]) {
    // Recursively sanitize array elements
    NSMutableArray* sanitized = [NSMutableArray arrayWithCapacity:[object count]];
    for (id element in (NSArray*)object) {
      [sanitized addObject:[self sanitizeAttributesForJSON:element]];
    }
    return sanitized;
  } else if ([object isKindOfClass:[NSNull class]]) {
    return object;  // NSNull is JSON-serializable
  } else if ([object isKindOfClass:[NSString class]] || [object isKindOfClass:[NSNumber class]]) {
    return object;  // Strings and numbers are JSON-serializable
  } else if ([object respondsToSelector:@selector(description)]) {
    // Convert other objects to their string description
    return [object description];
  } else {
    // Fallback for unknown types
    return [NSString stringWithFormat:@"<%@>", NSStringFromClass([object class])];
  }
}

@end
