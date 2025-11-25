//
//  DNSShieldTelemetry.h
//  DNShield
//
//  Splunk HEC telemetry client for DNShield event logging
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, DNSTelemetryEventType) {
  DNSTelemetryEventTypeDNSQuery,
  DNSTelemetryEventTypeRuleUpdate,
  DNSTelemetryEventTypeCachePerformance,
  DNSTelemetryEventTypeExtensionLifecycle,
  DNSTelemetryEventTypeSecurityViolation,
  DNSTelemetryEventTypeWebSocketConnection,
  DNSTelemetryEventTypeBypassToggle,
  DNSTelemetryEventTypePerformanceAnomaly
};

typedef NS_ENUM(NSUInteger, DNSQueryAction) {
  DNSQueryActionAllowed,
  DNSQueryActionBlocked,
  DNSQueryActionFailed,
  DNSQueryActionRedirected
};

@interface DNSShieldTelemetry : NSObject

@property(nonatomic, readonly) BOOL isEnabled;
@property(nonatomic, readonly) NSString* serverURL;
@property(nonatomic, readonly) NSString* serialNumber;
@property(nonatomic, readonly) NSString* extensionVersion;
@property(nonatomic, readonly) NSString* deviceHostname;
@property(nonatomic, readonly) NSString* consoleUser;

+ (instancetype)sharedInstance;

- (void)configure;
- (void)sendEvent:(NSDictionary*)event;
- (void)sendBatch:(NSArray<NSDictionary*>*)events;
- (void)flush;

// Convenience methods for specific event types
- (void)logDNSQueryEvent:(NSString*)domain
                  action:(DNSQueryAction)action
                metadata:(nullable NSDictionary*)metadata;

- (void)logRuleUpdateEvent:(NSString*)manifestId
                rulesAdded:(NSUInteger)rulesAdded
              rulesRemoved:(NSUInteger)rulesRemoved
                  metadata:(nullable NSDictionary*)metadata;

- (void)logCachePerformanceEvent:(NSString*)cacheType
                         hitRate:(double)hitRate
                   evictionCount:(NSUInteger)evictionCount
                     memoryUsage:(NSUInteger)memoryUsageMB
                        metadata:(nullable NSDictionary*)metadata;

- (void)logExtensionLifecycleEvent:(NSString*)eventType metadata:(nullable NSDictionary*)metadata;

- (void)logSecurityViolationEvent:(NSString*)violationType
                         metadata:(nullable NSDictionary*)metadata;

// Privacy controls
- (NSString*)anonymizeIP:(NSString*)ipAddress;
- (NSString*)anonymizeDomain:(NSString*)domain privacyLevel:(NSUInteger)level;

@end

NS_ASSUME_NONNULL_END
