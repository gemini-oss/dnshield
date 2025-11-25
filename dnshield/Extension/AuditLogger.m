//
//  AuditLogger.m
//  DNShield Network Extension
//
//  Security audit logging for bypass system
//

#import "AuditLogger.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <os/log.h>

// File paths
static NSString* const kAuditLogFileName = @"DNSShieldAudit.log";
static NSString* const kAuditLogArchiveFileName = @"DNSShieldAudit.archive";

// Persistence keys
static NSString* const kAuditEventsKey = @"events";
static NSString* const kAuditEventTypeKey = @"type";
static NSString* const kAuditEventTimestampKey = @"timestamp";
static NSString* const kAuditEventUsernameKey = @"username";
static NSString* const kAuditEventSuccessKey = @"success";
static NSString* const kAuditEventReasonKey = @"reason";
static NSString* const kAuditEventMetadataKey = @"metadata";

@implementation DNSAuditEvent

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)initWithType:(DNSAuditEventType)type
                    username:(nullable NSString*)username
                     success:(BOOL)success
                      reason:(nullable NSString*)reason
                    metadata:(nullable NSDictionary*)metadata {
  self = [super init];
  if (self) {
    _eventType = type;
    _timestamp = [NSDate date];
    _username = [username copy];
    _success = success;
    _reason = [reason copy];
    _metadata = [metadata copy];
  }
  return self;
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _eventType = [coder decodeIntegerForKey:kAuditEventTypeKey];
    _timestamp = [coder decodeObjectOfClass:[NSDate class] forKey:kAuditEventTimestampKey];
    _username = [coder decodeObjectOfClass:[NSString class] forKey:kAuditEventUsernameKey];
    _success = [coder decodeBoolForKey:kAuditEventSuccessKey];
    _reason = [coder decodeObjectOfClass:[NSString class] forKey:kAuditEventReasonKey];
    _metadata = [coder decodeObjectOfClasses:[NSSet setWithArray:@[
                         [NSDictionary class], [NSString class], [NSNumber class]
                       ]]
                                      forKey:kAuditEventMetadataKey];
  }
  return self;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeInteger:_eventType forKey:kAuditEventTypeKey];
  [coder encodeObject:_timestamp forKey:kAuditEventTimestampKey];
  [coder encodeObject:_username forKey:kAuditEventUsernameKey];
  [coder encodeBool:_success forKey:kAuditEventSuccessKey];
  [coder encodeObject:_reason forKey:kAuditEventReasonKey];
  [coder encodeObject:_metadata forKey:kAuditEventMetadataKey];
}

- (NSString*)eventDescription {
  NSString* typeString = @"Unknown";
  switch (self.eventType) {
    case DNSAuditEventBypassAttempt: typeString = @"Bypass Attempt"; break;
    case DNSAuditEventBypassActivation: typeString = @"Bypass Activated"; break;
    case DNSAuditEventBypassDeactivation: typeString = @"Bypass Deactivated"; break;
    case DNSAuditEventBypassExpiration: typeString = @"Bypass Expired"; break;
    case DNSAuditEventAccountLockout: typeString = @"Account Locked"; break;
    case DNSAuditEventAdminAction: typeString = @"Admin Action"; break;
    case DNSAuditEventSecurityAlert: typeString = @"Security Alert"; break;
  }

  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";

  NSMutableString* description = [NSMutableString
      stringWithFormat:@"[%@] %@", [formatter stringFromDate:self.timestamp], typeString];

  if (self.username) {
    [description appendFormat:@" - User: %@", self.username];
  }

  [description appendFormat:@" - %@", self.success ? @"Success" : @"Failed"];

  if (self.reason) {
    [description appendFormat:@" - %@", self.reason];
  }

  return description;
}

@end

@interface AuditLogger ()
@property(nonatomic, strong) NSMutableArray<DNSAuditEvent*>* events;
@property(nonatomic, strong) dispatch_queue_t auditQueue;
@property(nonatomic, strong) NSString* logFilePath;
@property(nonatomic, strong) NSString* archiveFilePath;
@property(nonatomic, assign) NSInteger recentFailedAttempts;
@property(nonatomic, strong) NSDate* lastFailedAttemptCheck;
@end

@implementation AuditLogger

- (instancetype)init {
  self = [super init];
  if (self) {
    _events = [NSMutableArray array];
    _auditQueue = dispatch_queue_create("com.dnshield.audit", DISPATCH_QUEUE_SERIAL);
    _maxLogEntries = 10000;
    _failedAttemptAlertThreshold = 5;

    // Setup file paths
    NSArray* paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    NSString* libraryPath = paths.firstObject;
    NSString* logsDirectory = [libraryPath stringByAppendingPathComponent:@"Logs/DNSShield"];

    // Create logs directory if needed
    NSFileManager* fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:logsDirectory]) {
      [fileManager createDirectoryAtPath:logsDirectory
             withIntermediateDirectories:YES
                              attributes:nil
                                   error:nil];
    }

    _logFilePath = [logsDirectory stringByAppendingPathComponent:kAuditLogFileName];
    _archiveFilePath = [logsDirectory stringByAppendingPathComponent:kAuditLogArchiveFileName];

    // Load existing events
    [self loadPersistedEvents];

    DNSLogInfo(LogCategoryGeneral, "AuditLogger initialized with %ld events", (long)_events.count);
  }
  return self;
}

#pragma mark - Logging Methods

- (void)logBypassAttempt:(BOOL)success reason:(NSString*)reason {
  [self logBypassAttemptWithUsername:NSUserName() success:success reason:reason];
}

- (void)logBypassAttemptWithUsername:(nullable NSString*)username
                             success:(BOOL)success
                              reason:(NSString*)reason {
  DNSAuditEvent* event = [[DNSAuditEvent alloc] initWithType:DNSAuditEventBypassAttempt
                                                    username:username
                                                     success:success
                                                      reason:reason
                                                    metadata:nil];
  [self addEvent:event];

  // Check for security alerts
  if (!success) {
    [self checkFailedAttemptThreshold];
  }
}

- (void)logBypassActivation:(NSTimeInterval)duration {
  NSDictionary* metadata = @{@"duration" : @(duration)};
  DNSAuditEvent* event = [[DNSAuditEvent alloc]
      initWithType:DNSAuditEventBypassActivation
          username:NSUserName()
           success:YES
            reason:[NSString stringWithFormat:@"Bypass activated for %.0f minutes", duration / 60]
          metadata:metadata];
  [self addEvent:event];
}

- (void)logBypassDeactivation:(NSTimeInterval)actualDuration manual:(BOOL)manual {
  NSDictionary* metadata = @{@"actualDuration" : @(actualDuration), @"manual" : @(manual)};
  NSString* reason = manual ? @"Manual deactivation" : @"Automatic deactivation";
  DNSAuditEvent* event = [[DNSAuditEvent alloc] initWithType:DNSAuditEventBypassDeactivation
                                                    username:NSUserName()
                                                     success:YES
                                                      reason:reason
                                                    metadata:metadata];
  [self addEvent:event];
}

- (void)logBypassExpiration:(NSTimeInterval)duration {
  NSDictionary* metadata = @{@"duration" : @(duration)};
  DNSAuditEvent* event = [[DNSAuditEvent alloc] initWithType:DNSAuditEventBypassExpiration
                                                    username:NSUserName()
                                                     success:YES
                                                      reason:@"Bypass expired"
                                                    metadata:metadata];
  [self addEvent:event];
}

- (void)logAccountLockout:(NSInteger)failedAttempts {
  NSDictionary* metadata = @{@"failedAttempts" : @(failedAttempts)};
  DNSAuditEvent* event = [[DNSAuditEvent alloc]
      initWithType:DNSAuditEventAccountLockout
          username:NSUserName()
           success:NO
            reason:[NSString stringWithFormat:@"Account locked after %ld failed attempts",
                                              (long)failedAttempts]
          metadata:metadata];
  [self addEvent:event];

  // This is always a security alert
  if ([self.delegate respondsToSelector:@selector(auditLogger:didDetectSecurityAlert:)]) {
    [self.delegate auditLogger:self didDetectSecurityAlert:event];
  }
}

- (void)logAdminAction:(NSString*)action {
  DNSAuditEvent* event = [[DNSAuditEvent alloc] initWithType:DNSAuditEventAdminAction
                                                    username:NSUserName()
                                                     success:YES
                                                      reason:action
                                                    metadata:nil];
  [self addEvent:event];
}

- (void)logSecurityAlert:(NSString*)alert metadata:(nullable NSDictionary*)metadata {
  DNSAuditEvent* event = [[DNSAuditEvent alloc] initWithType:DNSAuditEventSecurityAlert
                                                    username:NSUserName()
                                                     success:NO
                                                      reason:alert
                                                    metadata:metadata];
  [self addEvent:event];

  if ([self.delegate respondsToSelector:@selector(auditLogger:didDetectSecurityAlert:)]) {
    [self.delegate auditLogger:self didDetectSecurityAlert:event];
  }
}

#pragma mark - Query Methods

- (NSArray<DNSAuditEvent*>*)allEvents {
  __block NSArray* eventsCopy;
  dispatch_sync(self.auditQueue, ^{
    eventsCopy = [self.events copy];
  });
  return eventsCopy;
}

- (NSArray<DNSAuditEvent*>*)eventsOfType:(DNSAuditEventType)type {
  __block NSArray* filtered;
  dispatch_sync(self.auditQueue, ^{
    NSPredicate* predicate = [NSPredicate predicateWithFormat:@"eventType == %ld", (long)type];
    filtered = [self.events filteredArrayUsingPredicate:predicate];
  });
  return filtered;
}

- (NSArray<DNSAuditEvent*>*)eventsInDateRange:(NSDate*)startDate endDate:(NSDate*)endDate {
  __block NSArray* filtered;
  dispatch_sync(self.auditQueue, ^{
    NSPredicate* predicate = [NSPredicate
        predicateWithFormat:@"timestamp >= %@ AND timestamp <= %@", startDate, endDate];
    filtered = [self.events filteredArrayUsingPredicate:predicate];
  });
  return filtered;
}

- (NSArray<DNSAuditEvent*>*)recentEvents:(NSInteger)count {
  __block NSArray* recent;
  dispatch_sync(self.auditQueue, ^{
    NSInteger startIndex = MAX(0, self.events.count - count);
    NSInteger length = MIN(count, self.events.count);
    recent = [self.events subarrayWithRange:NSMakeRange(startIndex, length)];
  });
  return recent;
}

- (NSInteger)failedAttemptsInTimeInterval:(NSTimeInterval)interval {
  NSDate* startDate = [NSDate dateWithTimeIntervalSinceNow:-interval];
  NSArray* attempts = [self eventsOfType:DNSAuditEventBypassAttempt];

  NSInteger failedCount = 0;
  for (DNSAuditEvent* event in attempts) {
    if (!event.success && [event.timestamp timeIntervalSinceDate:startDate] > 0) {
      failedCount++;
    }
  }

  return failedCount;
}

#pragma mark - Export Methods

- (BOOL)exportLogsToFile:(NSString*)path error:(NSError**)error {
  NSData* data = [self exportLogsAsData:error];
  if (!data) {
    return NO;
  }

  return [data writeToFile:path options:NSDataWritingAtomic error:error];
}

- (NSData*)exportLogsAsData:(NSError**)error {
  __block NSData* data;
  __block NSError* exportError;

  dispatch_sync(self.auditQueue, ^{
    @try {
      // Create text representation
      NSMutableString* logText = [NSMutableString string];
      [logText appendString:@"DNSShield Audit Log Export\n"];
      [logText appendFormat:@"Export Date: %@\n", [NSDate date]];
      [logText appendFormat:@"Total Events: %ld\n\n", (long)self.events.count];

      for (DNSAuditEvent* event in self.events) {
        [logText appendFormat:@"%@\n", event.eventDescription];
        if (event.metadata) {
          [logText appendFormat:@"  Metadata: %@\n", event.metadata];
        }
      }

      data = [logText dataUsingEncoding:NSUTF8StringEncoding];
    } @catch (NSException* exception) {
      exportError = DNSMakeError(DNSRuleCacheErrorDomain, DNSRuleCacheErrorWriteFailed,
                                 @"Failed to export audit logs");
    }
  });

  if (error && exportError) {
    *error = exportError;
  }

  return data;
}

#pragma mark - Cleanup

- (void)pruneOldEvents {
  dispatch_async(self.auditQueue, ^{
    if (self.events.count > self.maxLogEntries) {
      NSInteger toRemove = self.events.count - self.maxLogEntries;
      [self.events removeObjectsInRange:NSMakeRange(0, toRemove)];
      [self persistEvents];

      DNSLogInfo(LogCategoryGeneral, "Pruned %ld old audit events", (long)toRemove);
    }
  });
}

- (void)clearAllEvents {
  // Requires admin privileges
  if (geteuid() != 0) {
    DNSLogError(LogCategoryGeneral, "clearAllEvents requires admin privileges");
    return;
  }

  dispatch_sync(self.auditQueue, ^{
    [self.events removeAllObjects];
    [self persistEvents];

    // Also remove files
    [[NSFileManager defaultManager] removeItemAtPath:self.logFilePath error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:self.archiveFilePath error:nil];
  });
}

#pragma mark - Private Methods

- (void)addEvent:(DNSAuditEvent*)event {
  dispatch_async(self.auditQueue, ^{
    [self.events addObject:event];

    // Log to system log as well
    os_log_info(OS_LOG_DEFAULT, "DNSShield Audit: %{public}@", event.eventDescription);

    // Notify delegate
    if ([self.delegate respondsToSelector:@selector(auditLogger:didLogEvent:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate auditLogger:self didLogEvent:event];
      });
    }

    // Check if we need to prune
    if (self.events.count > self.maxLogEntries * 1.1) {
      [self pruneOldEvents];
    }

    // Persist periodically
    static NSInteger eventsSinceLastSave = 0;
    eventsSinceLastSave++;
    if (eventsSinceLastSave >= 10) {
      [self persistEvents];
      eventsSinceLastSave = 0;
    }
  });
}

- (void)checkFailedAttemptThreshold {
  NSInteger recentFailures = [self failedAttemptsInTimeInterval:300];  // 5 minutes

  if (recentFailures >= self.failedAttemptAlertThreshold) {
    NSDictionary* metadata = @{@"failedAttempts" : @(recentFailures)};
    [self logSecurityAlert:@"Multiple failed bypass attempts detected" metadata:metadata];
  }
}

- (void)persistEvents {
  @try {
    NSData* data = [NSKeyedArchiver archivedDataWithRootObject:self.events
                                         requiringSecureCoding:YES
                                                         error:nil];
    if (data) {
      [data writeToFile:self.logFilePath atomically:YES];
    }
  } @catch (NSException* exception) {
    DNSLogError(LogCategoryGeneral, "Failed to persist audit events: %@", exception);
  }
}

- (void)loadPersistedEvents {
  @try {
    NSData* data = [NSData dataWithContentsOfFile:self.logFilePath];
    if (data) {
      NSArray* events =
          [NSKeyedUnarchiver unarchivedObjectOfClasses:[NSSet setWithObject:[NSArray class]]
                                              fromData:data
                                                 error:nil];
      if (events) {
        self.events = [events mutableCopy];
      }
    }
  } @catch (NSException* exception) {
    DNSLogError(LogCategoryGeneral, "Failed to load persisted audit events: %@", exception);
  }
}

@end
