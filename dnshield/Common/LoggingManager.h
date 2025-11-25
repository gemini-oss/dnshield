//
//  LoggingManager.h
//  DNShield Network Extension
//
//  Logging system with categories, levels, and privacy controls
//  Provides structured logging for rule management subsystem
//

#import <Foundation/Foundation.h>
#import <os/log.h>

NS_ASSUME_NONNULL_BEGIN

// Log categories for different subsystems
typedef NS_ENUM(NSInteger, LogCategory) {
  LogCategoryGeneral = 0,
  LogCategoryConfiguration,
  LogCategoryRuleFetching,
  LogCategoryRuleParsing,
  LogCategoryCache,
  LogCategoryScheduler,
  LogCategoryDNS,
  LogCategoryPerformance,
  LogCategoryNetwork,
  LogCategoryError,
  LogCategoryTelemetry
};

// Log levels matching OSLog types
typedef NS_ENUM(NSInteger, LogLevel) {
  LogLevelDebug = 0,  // os_log_debug
  LogLevelInfo,       // os_log_info
  LogLevelDefault,    // os_log (default)
  LogLevelError,      // os_log_error
  LogLevelFault       // os_log_fault
};

@interface LoggingManager : NSObject

+ (instancetype)sharedManager;

- (os_log_t)logHandleForCategory:(LogCategory)category;
- (NSString*)nameForCategory:(LogCategory)category;

- (void)configureWithDebugMode:(BOOL)debugMode;
- (void)setLogLevel:(LogLevel)level forCategory:(LogCategory)category;
- (LogLevel)logLevelForCategory:(LogCategory)category;

- (void)setPrivacySensitive:(BOOL)sensitive forCategory:(LogCategory)category;

- (void)logPerformanceStart:(NSString*)operation;
- (void)logPerformanceEnd:(NSString*)operation;
- (NSTimeInterval)elapsedTimeForOperation:(NSString*)operation;

- (void)logEvent:(NSString*)event
        category:(LogCategory)category
           level:(LogLevel)level
      attributes:(nullable NSDictionary*)attributes;

- (void)logError:(NSError*)error category:(LogCategory)category context:(nullable NSString*)context;

- (void)logMetric:(NSString*)metric value:(NSNumber*)value category:(LogCategory)category;

- (nullable NSString*)currentLogFilePath;
- (NSArray<NSString*>*)availableLogFiles;
- (BOOL)exportLogsToPath:(NSString*)path error:(NSError**)error;

@end

// Convenience macros for common logging patterns
#define DNSLogDebug(category, format, ...)                                             \
  os_log_debug([[LoggingManager sharedManager] logHandleForCategory:category], format, \
               ##__VA_ARGS__)

#define DNSLogInfo(category, format, ...) \
  os_log_info([[LoggingManager sharedManager] logHandleForCategory:category], format, ##__VA_ARGS__)

#define DNSLogError(category, format, ...)                                             \
  os_log_error([[LoggingManager sharedManager] logHandleForCategory:category], format, \
               ##__VA_ARGS__)

#define DNSLogFault(category, format, ...)                                             \
  os_log_fault([[LoggingManager sharedManager] logHandleForCategory:category], format, \
               ##__VA_ARGS__)

// Performance tracking macros
#define DNSLogPerformanceStart(operation) \
  [[LoggingManager sharedManager] logPerformanceStart:operation]

#define DNSLogPerformanceEnd(operation) [[LoggingManager sharedManager] logPerformanceEnd:operation]

FOUNDATION_EXPORT os_log_t DNCreateLogHandle(NSString* subsystem, NSString* category);

NS_ASSUME_NONNULL_END
