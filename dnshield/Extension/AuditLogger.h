//
//  AuditLogger.h
//  DNShield Network Extension
//
//  Security audit logging for bypass system
//  Logs all bypass attempts, activations, and administrative actions
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Audit event types
typedef NS_ENUM(NSInteger, DNSAuditEventType) {
  DNSAuditEventBypassAttempt = 0,
  DNSAuditEventBypassActivation,
  DNSAuditEventBypassDeactivation,
  DNSAuditEventBypassExpiration,
  DNSAuditEventAccountLockout,
  DNSAuditEventAdminAction,
  DNSAuditEventSecurityAlert
};

// Audit event
@interface DNSAuditEvent : NSObject <NSSecureCoding>

@property(nonatomic, readonly) DNSAuditEventType eventType;
@property(nonatomic, readonly) NSDate* timestamp;
@property(nonatomic, readonly, nullable) NSString* username;
@property(nonatomic, readonly) BOOL success;
@property(nonatomic, readonly, nullable) NSString* reason;
@property(nonatomic, readonly, nullable) NSDictionary* metadata;
@property(nonatomic, readonly) NSString* eventDescription;

- (instancetype)initWithType:(DNSAuditEventType)type
                    username:(nullable NSString*)username
                     success:(BOOL)success
                      reason:(nullable NSString*)reason
                    metadata:(nullable NSDictionary*)metadata;

@end

// Audit logger delegate
@protocol AuditLoggerDelegate <NSObject>
@optional
- (void)auditLogger:(id)logger didLogEvent:(DNSAuditEvent*)event;
- (void)auditLogger:(id)logger didDetectSecurityAlert:(DNSAuditEvent*)event;
@end

@interface AuditLogger : NSObject

// Delegate for audit events
@property(nonatomic, weak, nullable) id<AuditLoggerDelegate> delegate;

// Configuration
@property(nonatomic, assign) NSInteger maxLogEntries;                // Default: 10000
@property(nonatomic, assign) NSInteger failedAttemptAlertThreshold;  // Default: 5

// Log bypass attempts
- (void)logBypassAttempt:(BOOL)success reason:(NSString*)reason;
- (void)logBypassAttemptWithUsername:(nullable NSString*)username
                             success:(BOOL)success
                              reason:(NSString*)reason;

// Log bypass state changes
- (void)logBypassActivation:(NSTimeInterval)duration;
- (void)logBypassDeactivation:(NSTimeInterval)actualDuration manual:(BOOL)manual;
- (void)logBypassExpiration:(NSTimeInterval)duration;

// Log security events
- (void)logAccountLockout:(NSInteger)failedAttempts;
- (void)logAdminAction:(NSString*)action;
- (void)logSecurityAlert:(NSString*)alert metadata:(nullable NSDictionary*)metadata;

// Query audit logs
- (NSArray<DNSAuditEvent*>*)allEvents;
- (NSArray<DNSAuditEvent*>*)eventsOfType:(DNSAuditEventType)type;
- (NSArray<DNSAuditEvent*>*)eventsInDateRange:(NSDate*)startDate endDate:(NSDate*)endDate;
- (NSArray<DNSAuditEvent*>*)recentEvents:(NSInteger)count;
- (NSInteger)failedAttemptsInTimeInterval:(NSTimeInterval)interval;

// Export audit logs
- (BOOL)exportLogsToFile:(NSString*)path error:(NSError**)error;
- (NSData*)exportLogsAsData:(NSError**)error;

// Cleanup
- (void)pruneOldEvents;  // Remove events beyond maxLogEntries
- (void)clearAllEvents;  // Requires admin privileges

@end

NS_ASSUME_NONNULL_END
