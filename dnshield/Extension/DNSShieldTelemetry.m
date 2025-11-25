//
//  DNSShieldTelemetry.m
//  DNShield
//

#import <CommonCrypto/CommonDigest.h>
#import <IOKit/IOKitLib.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <objc/runtime.h>
#import <os/log.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>

#import "DNSShieldTelemetry.h"
#import "PreferenceManager.h"

static os_log_t telemetryLogHandle = nil;
static void* kTelemetryTimerKey = &kTelemetryTimerKey;

@interface DNSShieldTelemetry ()

@property(nonatomic, strong) NSURLSession* session;
@property(nonatomic, strong) NSMutableArray* eventQueue;
@property(nonatomic, strong) dispatch_queue_t telemetryQueue;
@property(nonatomic, assign) BOOL configured;
@property(nonatomic, strong) NSString* cachedSerialNumber;
@property(nonatomic, strong) NSString* cachedVersion;
@property(nonatomic, strong) NSString* cachedHostname;
@property(nonatomic, strong) NSString* cachedConsoleUser;
@property(nonatomic, strong) NSString* cachedManifestURL;
@property(nonatomic, strong) NSDateFormatter* isoFormatter;
@property(nonatomic, strong) NSString* diskBufferPath;
@property(nonatomic, strong) NSMutableArray* retryQueue;
@property(nonatomic, assign) NSInteger retryCount;
@property(nonatomic, assign) NSTimeInterval retryDelay;
@property(nonatomic, strong) NSString* hecToken;

@end

@implementation DNSShieldTelemetry

- (NSString*)deviceHostname {
  return _cachedHostname;
}

- (NSString*)consoleUser {
  return _cachedConsoleUser;
}

+ (void)initialize {
  if (self == [DNSShieldTelemetry class]) {
    telemetryLogHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"Telemetry");
  }
}

+ (instancetype)sharedInstance {
  static DNSShieldTelemetry* sharedInstance = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedInstance = [[DNSShieldTelemetry alloc] init];
    os_log_info(telemetryLogHandle, "DNSShieldTelemetry singleton created");
  });
  return sharedInstance;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    os_log_info(telemetryLogHandle, "DNSShieldTelemetry init started");

    _eventQueue = [NSMutableArray array];
    _retryQueue = [NSMutableArray array];
    _telemetryQueue = dispatch_queue_create("com.dnshield.telemetry", DISPATCH_QUEUE_SERIAL);
    _configured = NO;
    _retryCount = 0;
    _retryDelay = 2.0;  // Initial retry delay

    // Setup ISO date formatter
    _isoFormatter = [[NSDateFormatter alloc] init];
    _isoFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    _isoFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    _isoFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];

    // Setup disk buffer path
    NSString* appSupport =
        NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES)
            .firstObject;
    NSString* dnshieldDir = [appSupport stringByAppendingPathComponent:@"DNShield"];
    _diskBufferPath = [dnshieldDir stringByAppendingPathComponent:@"telemetry_buffer.plist"];

    os_log_debug(telemetryLogHandle, "DNSShieldTelemetry disk buffer path: %{public}@",
                 _diskBufferPath);

    // Create directory if needed
    [[NSFileManager defaultManager] createDirectoryAtPath:dnshieldDir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];

    // Load buffered events from disk
    [self loadBufferedEvents];

    [self configure];
  }
  return self;
}

- (void)configure {
  dispatch_async(self.telemetryQueue, ^{
    os_log_info(telemetryLogHandle, "Starting telemetry configuration");

    // Check if telemetry is enabled - use default if not set
    PreferenceManager* prefManager = [PreferenceManager sharedManager];

    id telemetryEnabledValue = [prefManager
        preferenceValueForKey:kDNShieldTelemetryEnabled
                     inDomain:kDNShieldPreferenceDomain
                 defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldTelemetryEnabled]];

    NSNumber* telemetryEnabled = nil;
    if ([telemetryEnabledValue isKindOfClass:[NSNumber class]]) {
      telemetryEnabled = telemetryEnabledValue;
    }
    self->_isEnabled =
        telemetryEnabled ? [telemetryEnabled boolValue] : YES;  // Default to YES as per preferences

    os_log_info(telemetryLogHandle, "Telemetry enabled: %{public}@",
                self->_isEnabled ? @"YES" : @"NO");

    if (!self->_isEnabled) {
      os_log_info(telemetryLogHandle, "Telemetry disabled by configuration");
      return;
    }

    // Get server URL from preferences
    self->_serverURL = [[PreferenceManager sharedManager]
        preferenceValueForKey:kDNShieldTelemetryServerURL
                     inDomain:kDNShieldPreferenceDomain
                 defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldTelemetryServerURL]];
    os_log_info(telemetryLogHandle, "Telemetry server URL from PreferenceManager: %{public}@",
                self->_serverURL ?: @"nil");

    // Get HEC token from preferences
    self->_hecToken = [[PreferenceManager sharedManager]
        preferenceValueForKey:kDNShieldTelemetryHECToken
                     inDomain:kDNShieldPreferenceDomain
                 defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldTelemetryHECToken]];
    os_log_info(telemetryLogHandle, "Telemetry HEC token configured: %{public}@",
                self->_hecToken ? @"YES" : @"NO");

    if (!self->_serverURL) {
      os_log_error(telemetryLogHandle, "No telemetry server URL configured");
      self->_isEnabled = NO;
      return;
    }

    if (!self->_hecToken) {
      os_log_error(telemetryLogHandle, "No telemetry HEC token configured");
      self->_isEnabled = NO;
      return;
    }

    // Get manifest URL from preferences
    NSString* manifestURL = [prefManager
        preferenceValueForKey:kDNShieldManifestURL
                     inDomain:kDNShieldPreferenceDomain
                 defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldManifestURL]];

    // Cache static values
    self->_cachedSerialNumber = [self getSerialNumber];
    self->_cachedVersion = [self getExtensionVersion];
    self->_cachedHostname = [self getHostname];
    self->_cachedConsoleUser = [self getConsoleUser];
    self->_cachedManifestURL = manifestURL;

    NSString* hashedSerial = [DNSShieldTelemetry hashString:self->_cachedSerialNumber];
    os_log_debug(telemetryLogHandle,
                 "Cached serial (SHA256): %{public}@, version: %{public}@, hostname: %{public}@, "
                 "console_user: %{public}@, manifest_url: %{public}@",
                 hashedSerial, self->_cachedVersion, self->_cachedHostname,
                 self->_cachedConsoleUser, self->_cachedManifestURL ?: @"unknown");

    // Configure URLSession - keep it simple like yamms
    NSURLSessionConfiguration* config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = 8.0;
    config.timeoutIntervalForResource = 8.0;
    config.HTTPAdditionalHeaders = @{
      @"Content-Type" : @"application/json",
      @"User-Agent" : [NSString stringWithFormat:@"DNShield/%@", self->_cachedVersion]
    };

    self->_session = [NSURLSession sessionWithConfiguration:config];

    // Use dispatch timer instead of NSTimer for background queue
    dispatch_source_t timer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.telemetryQueue);
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC, 10 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
      [self flushInternal];
    });
    dispatch_resume(timer);

    // Keep a strong reference to the timer
    objc_setAssociatedObject(self, kTelemetryTimerKey, timer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    self->_configured = YES;
    os_log_info(telemetryLogHandle, "Telemetry configured successfully with dispatch timer");

    // Send initial startup event with more details
    NSMutableDictionary* startupMetadata = [@{
      @"serial_number" : self->_cachedSerialNumber ?: @"unknown",
      @"version" : self->_cachedVersion ?: @"unknown",
      @"device_hostname" : self->_cachedHostname ?: @"unknown",
      @"console_user" : self->_cachedConsoleUser ?: @"unknown",
      @"server_url" : self->_serverURL ?: @"unknown",
      @"manifest_url" : self->_cachedManifestURL ?: @"unknown",
      @"macos_version" : [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"timestamp" : [self.isoFormatter stringFromDate:[NSDate date]]
    } mutableCopy];

    [self logExtensionLifecycleEvent:@"startup" metadata:startupMetadata];

    // Force immediate flush for debugging
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   self.telemetryQueue, ^{
                     os_log_info(telemetryLogHandle, "Forcing initial telemetry flush");
                     [self flushInternal];
                   });
  });
}

- (void)sendEvent:(NSDictionary*)event {
  if (!_isEnabled || !_configured)
    return;

  dispatch_async(self.telemetryQueue, ^{
    // Add timestamp if not present
    NSMutableDictionary* mutableEvent = [event mutableCopy];
    if (!mutableEvent[@"timestamp"]) {
      mutableEvent[@"timestamp"] = [self.isoFormatter stringFromDate:[NSDate date]];
    }

    // Add standard fields
    mutableEvent[@"serial_number"] = self.cachedSerialNumber;
    mutableEvent[@"extension_version"] = self.cachedVersion;
    mutableEvent[@"device_hostname"] = self.cachedHostname;
    mutableEvent[@"console_user"] = self.cachedConsoleUser;
    mutableEvent[@"manifest_url"] = self.cachedManifestURL ?: @"unknown";

    // Create Splunk HEC format matching test script
    NSDictionary* splunkEvent =
        @{@"sourcetype" : @"macos:dnshield",
          @"event" : @{@"dnshield_data" : mutableEvent}};

    [self.eventQueue addObject:splunkEvent];

    // Flush if queue is getting large
    if (self.eventQueue.count >= 100) {
      [self flushInternal];
    }
  });
}

- (void)sendBatch:(NSArray<NSDictionary*>*)events {
  if (!_isEnabled || !_configured)
    return;

  dispatch_async(self.telemetryQueue, ^{
    for (NSDictionary* event in events) {
      [self sendEvent:event];
    }
  });
}

- (void)flush {
  if (!_isEnabled || !_configured)
    return;

  dispatch_async(self.telemetryQueue, ^{
    [self flushInternal];
  });
}

- (void)flushInternal {
  if (self.eventQueue.count == 0)
    return;

  // Log telemetry attempt
  os_log_info(telemetryLogHandle, "Attempting to send %lu telemetry events to %{public}@",
              (unsigned long)self.eventQueue.count, self.serverURL);

  NSArray* eventsToSend = [self.eventQueue copy];
  [self.eventQueue removeAllObjects];

  // Batch events to prevent CPU spikes - send as single request with newline-delimited JSON
  NSMutableString* batchPayload = [NSMutableString string];
  for (NSDictionary* event in eventsToSend) {
    NSError* error;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:event options:0 error:&error];
    if (jsonData && !error) {
      NSString* jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
      [batchPayload appendString:jsonString];
      [batchPayload appendString:@"\n"];
    }
  }

  if (batchPayload.length > 0) {
    [self sendBatchedEvents:batchPayload eventCount:eventsToSend.count originalEvents:eventsToSend];
  }
}

- (void)sendBatchedEvents:(NSString*)batchPayload
               eventCount:(NSUInteger)count
           originalEvents:(NSArray*)originalEvents {
  NSData* payloadData = [batchPayload dataUsingEncoding:NSUTF8StringEncoding];

  os_log_info(telemetryLogHandle, "Sending batch of %lu events, payload size: %lu bytes",
              (unsigned long)count, (unsigned long)payloadData.length);

  // Send to Splunk HEC with batch endpoint
  NSURL* url = [NSURL URLWithString:self.serverURL];
  NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:url];
  request.HTTPMethod = @"POST";
  request.HTTPBody = payloadData;

  // Add Splunk HEC Authorization header
  [request setValue:[NSString stringWithFormat:@"Splunk %@", self.hecToken]
      forHTTPHeaderField:@"Authorization"];

  NSURLSessionDataTask* task = [self.session
      dataTaskWithRequest:request
        completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
          if (error) {
            os_log_error(telemetryLogHandle, "Telemetry batch send failed: %{public}@", error);
            // Add events back to retry queue
            dispatch_async(self.telemetryQueue, ^{
              [self.retryQueue addObjectsFromArray:originalEvents];
              [self saveBufferedEvents];
            });
          } else {
            NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
            os_log_info(telemetryLogHandle, "Telemetry batch response status: %ld for %lu events",
                        (long)httpResponse.statusCode, (unsigned long)count);

            if (httpResponse.statusCode == 200) {
              os_log_info(telemetryLogHandle, "Successfully sent batch of %lu telemetry events",
                          (unsigned long)count);
              // Reset retry state on success
              dispatch_async(self.telemetryQueue, ^{
                self.retryCount = 0;
                self.retryDelay = 2.0;
              });
            } else {
              os_log_error(telemetryLogHandle, "Telemetry batch HTTP error: %ld",
                           (long)httpResponse.statusCode);
              // Add events back to retry queue for non-200 responses
              dispatch_async(self.telemetryQueue, ^{
                [self.retryQueue addObjectsFromArray:originalEvents];
                [self saveBufferedEvents];
              });
            }
          }
        }];

  [task resume];
  os_log_debug(telemetryLogHandle, "Telemetry batch request initiated");
}

- (void)sendSingleEvent:(NSDictionary*)event {
  // Log first event for debugging
  NSError* debugError;
  NSData* debugData = [NSJSONSerialization dataWithJSONObject:event
                                                      options:NSJSONWritingPrettyPrinted
                                                        error:&debugError];
  if (debugData && !debugError) {
    NSString* debugJSON = [[NSString alloc] initWithData:debugData encoding:NSUTF8StringEncoding];
    os_log_debug(telemetryLogHandle, "Sending event: %{public}@", debugJSON);
  }

  NSError* error;
  NSData* jsonData = [NSJSONSerialization dataWithJSONObject:event options:0 error:&error];
  if (!jsonData || error) {
    os_log_error(telemetryLogHandle, "Failed to serialize event: %{public}@", error);
    return;
  }

  // Log payload size
  os_log_debug(telemetryLogHandle, "Payload size: %lu bytes", (unsigned long)jsonData.length);

  // Send to Splunk HEC
  NSURL* url = [NSURL URLWithString:self.serverURL];
  NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:url];
  request.HTTPMethod = @"POST";
  request.HTTPBody = jsonData;

  // Add Splunk HEC Authorization header
  [request setValue:[NSString stringWithFormat:@"Splunk %@", self.hecToken]
      forHTTPHeaderField:@"Authorization"];

  // Log request details
  os_log_debug(telemetryLogHandle, "Sending POST request to: %{public}@", url.absoluteString);
  os_log_debug(telemetryLogHandle, "Request headers: %{public}@", request.allHTTPHeaderFields);

  NSURLSessionDataTask* task = [self.session
      dataTaskWithRequest:request
        completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
          if (error) {
            os_log_error(telemetryLogHandle, "Telemetry send failed: %{public}@", error);
            os_log_error(telemetryLogHandle, "Error domain: %{public}@, code: %ld", error.domain,
                         (long)error.code);
            // Add event back to retry queue
            dispatch_async(self.telemetryQueue, ^{
              [self.retryQueue addObject:event];
              [self saveBufferedEvents];
            });
          } else {
            NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
            os_log_info(telemetryLogHandle, "Telemetry response status: %ld",
                        (long)httpResponse.statusCode);

            // Log response body for debugging
            if (data) {
              NSString* responseBody = [[NSString alloc] initWithData:data
                                                             encoding:NSUTF8StringEncoding];
              if (responseBody) {
                os_log_debug(telemetryLogHandle, "Response body: %{public}@", responseBody);
              }
            }

            if (httpResponse.statusCode == 200) {
              os_log_info(telemetryLogHandle, "Successfully sent telemetry event");
              // Reset retry state on success
              dispatch_async(self.telemetryQueue, ^{
                self.retryCount = 0;
                self.retryDelay = 2.0;
              });
            } else {
              os_log_error(telemetryLogHandle, "Telemetry HTTP error: %ld",
                           (long)httpResponse.statusCode);
              os_log_error(telemetryLogHandle, "Response headers: %{public}@",
                           httpResponse.allHeaderFields);
              // Add event back to retry queue for non-200 responses
              dispatch_async(self.telemetryQueue, ^{
                [self.retryQueue addObject:event];
                [self saveBufferedEvents];
              });
            }
          }
        }];

  [task resume];
  os_log_debug(telemetryLogHandle, "Telemetry request initiated");
}

#pragma mark - Convenience Methods

- (void)logDNSQueryEvent:(NSString*)domain
                  action:(DNSQueryAction)action
                metadata:(nullable NSDictionary*)metadata {
  NSMutableDictionary* event = [@{
    @"event_type" : @"dns_query",
    @"hostname" : domain ?: @"unknown",
    @"action" : [self actionToString:action]
  } mutableCopy];

  if (metadata) {
    [event addEntriesFromDictionary:metadata];
  }

  [self sendEvent:event];
}

- (void)logRuleUpdateEvent:(NSString*)manifestId
                rulesAdded:(NSUInteger)rulesAdded
              rulesRemoved:(NSUInteger)rulesRemoved
                  metadata:(nullable NSDictionary*)metadata {
  NSMutableDictionary* event = [@{
    @"event_type" : @"rule_update",
    @"manifest_id" : manifestId ?: @"unknown",
    @"rules_added" : @(rulesAdded),
    @"rules_removed" : @(rulesRemoved)
  } mutableCopy];

  if (metadata) {
    [event addEntriesFromDictionary:metadata];
  }

  [self sendEvent:event];
}

- (void)logCachePerformanceEvent:(NSString*)cacheType
                         hitRate:(double)hitRate
                   evictionCount:(NSUInteger)evictionCount
                     memoryUsage:(NSUInteger)memoryUsageMB
                        metadata:(nullable NSDictionary*)metadata {
  NSMutableDictionary* event = [@{
    @"event_type" : @"cache_performance",
    @"cache_type" : cacheType,
    @"hit_rate" : @(hitRate),
    @"eviction_count" : @(evictionCount),
    @"memory_usage_mb" : @(memoryUsageMB)
  } mutableCopy];

  if (metadata) {
    [event addEntriesFromDictionary:metadata];
  }

  [self sendEvent:event];
}

- (void)logExtensionLifecycleEvent:(NSString*)eventType metadata:(nullable NSDictionary*)metadata {
  NSMutableDictionary* event =
      [@{@"event_type" : @"extension_lifecycle", @"lifecycle_event" : eventType} mutableCopy];

  if (metadata) {
    [event addEntriesFromDictionary:metadata];
  }

  [self sendEvent:event];
}

- (void)logSecurityViolationEvent:(NSString*)violationType
                         metadata:(nullable NSDictionary*)metadata {
  NSMutableDictionary* event =
      [@{@"event_type" : @"security_violation", @"violation_type" : violationType} mutableCopy];

  if (metadata) {
    [event addEntriesFromDictionary:metadata];
  }

  [self sendEvent:event];
}

#pragma mark - Privacy Methods

- (NSString*)anonymizeIP:(NSString*)ipAddress {
  if (!ipAddress)
    return @"unknown";

  NSNumber* privacyLevel =
      [[PreferenceManager sharedManager] preferenceForKey:kDNShieldTelemetryPrivacyLevel];
  NSInteger level = privacyLevel ? [privacyLevel integerValue] : 1;

  if (level == 0) {
    // No anonymization
    return ipAddress;
  } else if (level == 1) {
    // Hash the IP
    const char* str = [ipAddress UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(str, (CC_LONG)strlen(str), result);

    NSMutableString* hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < 8; i++) {  // Only first 8 bytes for shorter hash
      [hash appendFormat:@"%02x", result[i]];
    }
    return hash;
  } else {
    // Full anonymization
    return @"[redacted]";
  }
}

- (NSString*)anonymizeDomain:(NSString*)domain privacyLevel:(NSUInteger)level {
  if (!domain)
    return @"unknown";

  if (level == 0) {
    return domain;
  } else if (level == 1) {
    // Keep TLD only
    NSArray* components = [domain componentsSeparatedByString:@"."];
    if (components.count >= 2) {
      return [NSString stringWithFormat:@"***.%@", components.lastObject];
    }
    return @"***";
  } else {
    return @"[redacted]";
  }
}

#pragma mark - Helper Methods

+ (NSString*)hashString:(NSString*)input {
  if (!input)
    return @"unknown";

  const char* str = [input UTF8String];
  unsigned char result[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(str, (CC_LONG)strlen(str), result);

  NSMutableString* hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
    [hash appendFormat:@"%02x", result[i]];
  }
  return hash;
}

- (NSString*)getSerialNumber {
  io_service_t platformExpert =
      IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));

  if (!platformExpert)
    return @"unknown";

  CFStringRef serialNumberRef = (CFStringRef)IORegistryEntryCreateCFProperty(
      platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);

  IOObjectRelease(platformExpert);

  if (!serialNumberRef)
    return @"unknown";

  NSString* serialNumber = (__bridge NSString*)serialNumberRef;
  CFRelease(serialNumberRef);

  return serialNumber;
}

- (NSString*)getExtensionVersion {
  // Try CFBundleVersion first for full semver, fall back to CFBundleShortVersionString
  NSString* fullVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (fullVersion && ![fullVersion isEqualToString:@""]) {
    return fullVersion;
  }

  // Fall back to short version if full version not available
  return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]
             ?: @"unknown";
}

- (NSString*)getHostname {
  // Prefer the system computer name, fall back to the process hostname
  NSString* hostname = CFBridgingRelease(SCDynamicStoreCopyComputerName(NULL, NULL));

  if (!hostname || hostname.length == 0) {
    hostname = [[NSProcessInfo processInfo] hostName];
  }

  return hostname.length > 0 ? hostname : @"unknown";
}

- (NSString*)getConsoleUser {
  // Get the current console user
  CFStringRef console_user = SCDynamicStoreCopyConsoleUser(NULL, NULL, NULL);

  NSString* userName = CFBridgingRelease(console_user);

  return userName ?: @"unknown";
}

- (NSString*)actionToString:(DNSQueryAction)action {
  switch (action) {
    case DNSQueryActionAllowed: return @"allowed";
    case DNSQueryActionBlocked: return @"blocked";
    case DNSQueryActionFailed: return @"failed";
    case DNSQueryActionRedirected: return @"redirected";
    default: return @"unknown";
  }
}

- (void)dealloc {
  // Cancel dispatch timer
  dispatch_source_t timer = objc_getAssociatedObject(self, @selector(configure));
  if (timer) {
    dispatch_source_cancel(timer);
  }
  [self flush];
  [self saveBufferedEvents];
}

#pragma mark - Retry and Buffering

- (void)scheduleRetry {
  if (self.retryCount >= 5) {
    os_log_error(telemetryLogHandle, "Max retry attempts reached, discarding %lu events",
                 (unsigned long)self.retryQueue.count);
    [self.retryQueue removeAllObjects];
    [self saveBufferedEvents];
    return;
  }

  self.retryCount++;

  // Exponential backoff with jitter
  NSTimeInterval delay = self.retryDelay * pow(2, self.retryCount - 1);
  delay += arc4random_uniform(1000) / 1000.0;  // Add 0-1 second jitter
  delay = MIN(delay, 300.0);                   // Cap at 5 minutes

  os_log_info(telemetryLogHandle, "Scheduling retry %ld in %.1f seconds", (long)self.retryCount,
              delay);

  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                 self.telemetryQueue, ^{
                   [self retryFailedEvents];
                 });
}

- (void)retryFailedEvents {
  if (self.retryQueue.count == 0) {
    return;
  }

  os_log_info(telemetryLogHandle, "Retrying %lu failed events",
              (unsigned long)self.retryQueue.count);

  // Move retry queue to event queue and flush
  [self.eventQueue addObjectsFromArray:self.retryQueue];
  [self.retryQueue removeAllObjects];
  [self flushInternal];
}

- (void)saveBufferedEvents {
  if (self.retryQueue.count == 0) {
    // Remove buffer file if no events to save
    [[NSFileManager defaultManager] removeItemAtPath:self.diskBufferPath error:nil];
    return;
  }

  // Limit buffer size to prevent excessive disk usage
  NSUInteger maxBufferSize = 1000;
  if (self.retryQueue.count > maxBufferSize) {
    NSRange removeRange = NSMakeRange(0, self.retryQueue.count - maxBufferSize);
    [self.retryQueue removeObjectsInRange:removeRange];
    os_log_error(telemetryLogHandle, "Buffer overflow, removed oldest events");
  }

  NSError* error;
  NSData* data = [NSPropertyListSerialization dataWithPropertyList:self.retryQueue
                                                            format:NSPropertyListBinaryFormat_v1_0
                                                           options:0
                                                             error:&error];
  if (error) {
    os_log_error(telemetryLogHandle, "Failed to serialize buffer: %{public}@", error);
    return;
  }

  if (![data writeToFile:self.diskBufferPath atomically:YES]) {
    os_log_error(telemetryLogHandle, "Failed to write buffer to disk");
  } else {
    os_log_debug(telemetryLogHandle, "Saved %lu events to disk buffer",
                 (unsigned long)self.retryQueue.count);
  }
}

- (void)loadBufferedEvents {
  if (![[NSFileManager defaultManager] fileExistsAtPath:self.diskBufferPath]) {
    return;
  }

  NSError* error;
  NSData* data = [NSData dataWithContentsOfFile:self.diskBufferPath];
  if (!data) {
    return;
  }

  NSArray* bufferedEvents =
      [NSPropertyListSerialization propertyListWithData:data
                                                options:NSPropertyListImmutable
                                                 format:NULL
                                                  error:&error];
  if (error) {
    os_log_error(telemetryLogHandle, "Failed to deserialize buffer: %{public}@", error);
    [[NSFileManager defaultManager] removeItemAtPath:self.diskBufferPath error:nil];
    return;
  }

  if ([bufferedEvents isKindOfClass:[NSArray class]]) {
    [self.retryQueue addObjectsFromArray:bufferedEvents];
    os_log_info(telemetryLogHandle, "Loaded %lu events from disk buffer",
                (unsigned long)bufferedEvents.count);

    // Schedule retry for buffered events
    if (self.retryQueue.count > 0) {
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                     self.telemetryQueue, ^{
                       [self retryFailedEvents];
                     });
    }
  }
}

@end
