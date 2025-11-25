//
//  main.m
//  DNShield Daemon
//
//  Headless daemon for managing DNShield network extension
//

#import <arpa/inet.h>
#import <libproc.h>
#import <os/log.h>
#import <signal.h>
#import <sys/file.h>
#import <xpc/xpc.h>

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Security/Security.h>
#import <SystemExtensions/SystemExtensions.h>

#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Common/LoggingUtils.h>

// Version info
#define DAEMON_VERSION "1.3"
#define DAEMON_BUILD "147"

#define kDaemonBundleIdentifier kDNShieldDaemonBundleID

static inline const char* DaemonLockFilePath(void) {
  return [kDefaultLockFilePath fileSystemRepresentation];
}

// Security audit logging helper
typedef enum {
  SecurityEventTypeCritical,
  SecurityEventTypeWarning,
  SecurityEventTypeInfo
} SecurityEventType;

static void LogSecurityEvent(SecurityEventType type, const char* message) {
  // Use os_log for security events with special subsystem
  static os_log_t securityLog = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    securityLog = os_log_create("com.dnshield.daemon", "security");
  });

  switch (type) {
    case SecurityEventTypeCritical:
      os_log_error(securityLog, "SECURITY CRITICAL: %{public}s", message);
      DNSLogError(LogCategoryGeneral, "SECURITY CRITICAL: %s", message);
      break;
    case SecurityEventTypeWarning:
      os_log_info(securityLog, "SECURITY WARNING: %{public}s", message);
      DNSLogInfo(LogCategoryGeneral, "SECURITY WARNING: %s", message);
      break;
    case SecurityEventTypeInfo:
      os_log_info(securityLog, "SECURITY INFO: %{public}s", message);
      DNSLogInfo(LogCategoryGeneral, "SECURITY INFO: %s", message);
      break;
  }
}

// Global logger
static os_log_t logHandle = nil;

// Global state
static int lockFileDescriptor = -1;
static xpc_connection_t xpcListener = NULL;
static BOOL shouldTerminate = NO;

static BOOL DNManagedPreferencesExist(CFStringRef appID) {
  if (!appID)
    return NO;

  CFPreferencesAppSynchronize(appID);

  CFArrayRef keyList =
      CFPreferencesCopyKeyList(appID, kCFPreferencesAnyUser, kCFPreferencesCurrentHost);
  if (!keyList) {
    keyList = CFPreferencesCopyKeyList(appID, kCFPreferencesAnyUser, kCFPreferencesAnyHost);
  }
  if (!keyList) {
    keyList = CFPreferencesCopyKeyList(appID, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
  }

  BOOL hasKeys = (keyList && CFArrayGetCount(keyList) > 0);
  if (keyList)
    CFRelease(keyList);
  return hasKeys;
}

static id DNPreferenceCopyValue(NSString* key) {
  if (!key.length)
    return nil;

  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef appID = DNPreferenceDomainCF();

  CFPreferencesAppSynchronize(appID);

  CFTypeRef value =
      CFPreferencesCopyValue(cfKey, appID, kCFPreferencesAnyUser, kCFPreferencesCurrentHost);
  if (!value) {
    value = CFPreferencesCopyValue(cfKey, appID, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
  }
  if (!value) {
    value = CFPreferencesCopyValue(cfKey, appID, kCFPreferencesAnyUser, kCFPreferencesAnyHost);
  }
  if (!value) {
    value = CFPreferencesCopyAppValue(cfKey, appID);
  }
  if (!value) {
    CFTypeRef managed = CFPreferencesCopyValue(CFSTR("mcx_preference_settings"), appID,
                                               kCFPreferencesAnyUser, kCFPreferencesAnyHost);
    if (managed && CFGetTypeID(managed) == CFDictionaryGetTypeID()) {
      CFTypeRef managedValue = CFDictionaryGetValue((CFDictionaryRef)managed, cfKey);
      if (managedValue) {
        CFRetain(managedValue);
        value = managedValue;
      }
    }
    if (managed)
      CFRelease(managed);
  }

  return CFBridgingRelease(value);
}

static NSDictionary* DNDefaultConfiguration(BOOL managedByProfile) {
  return @{
    @"dnsServers" : @[ @"1.1.1.1", @"8.8.8.8" ],
    @"autoStart" : @YES,
    @"updateInterval" : @3600,
    @"logLevel" : @"info",
    @"isManagedByProfile" : @(managedByProfile),
    @"allowRuleEditing" : @YES
  };
}

static BOOL DNIsLikelyLocalDNSProxyConfiguration(NEDNSProxyProviderProtocol* protocol,
                                                 BOOL managedProfileActive) {
  if (!protocol)
    return YES;

  NSDictionary* config = protocol.providerConfiguration;
  if (!config || config.count == 0) {
    // Treat empty configs as managed to avoid tearing down a configuration we don't own.
    return managedProfileActive ? NO : YES;
  }

  if (config[@"payloadInfo"] != nil) {
    NSDictionary* payloadInfo = config[@"payloadInfo"];
    if ([payloadInfo[@"profileSource"] isEqualToString:@"mdm"]) {
      return NO;  // This is an MDM-managed configuration
    }
  }

  // Check for standard MDM configuration fields
  if (config[@"ProviderDesignatedRequirement"] || config[@"designatedRequirement"] != nil ||
      config[@"OnDemandEnabled"] != nil || config[@"UserDefinedName"] != nil ||
      config[@"pluginType"] != nil) {  // MDM profiles have this
    return NO;
  }

  // Check for our custom configuration fields
  if (config[@"WebSocketAuthToken"] != nil || config[@"WebSocketPort"] != nil ||
      config[@"EnableWebSocketServer"] != nil || config[@"ManifestConfiguration"] != nil) {
    return YES;  // Locally-authored configuration for our extension
  }

  // Anything else is likely a locally-authored configuration.
  return managedProfileActive ? NO : YES;
}

@interface DNShieldDaemon : NSObject <OSSystemExtensionRequestDelegate>
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, assign) BOOL extensionInstalled;
@property(nonatomic, assign) BOOL networkFilterEnabled;
@property(nonatomic, strong) NSTimer* healthCheckTimer;
// Security monitoring properties
@property(nonatomic, assign) NSUInteger failedAuthAttempts;
@property(nonatomic, strong) NSMutableDictionary* connectionRateLimits;
@property(nonatomic, strong) NSMutableDictionary* authFailuresByPeer;
@property(nonatomic, strong) NSDate* lastExtensionInstallAttempt;
@property(nonatomic, strong) NSDate* lastProxyConfigurationAttempt;
@end

@implementation DNShieldDaemon

- (instancetype)init {
  self = [super init];
  if (self) {
    _queue = dispatch_queue_create("com.dnshield.daemon.main", DISPATCH_QUEUE_SERIAL);
    _extensionInstalled = NO;
    _networkFilterEnabled = NO;
    _failedAuthAttempts = 0;
    _connectionRateLimits = [NSMutableDictionary dictionary];
    _authFailuresByPeer = [NSMutableDictionary dictionary];
  }
  return self;
}

#pragma mark - Process Lock Management

- (BOOL)acquireProcessLock {
  const char* lockFilePath = DaemonLockFilePath();

  // Check if PID file exists and validate it
  if (access(lockFilePath, F_OK) == 0) {
    // PID file exists, check if process is actually running
    FILE* pidFile = fopen(lockFilePath, "r");
    if (pidFile) {
      char pidStr[32];
      if (fgets(pidStr, sizeof(pidStr), pidFile)) {
        pid_t existingPid = (pid_t)strtol(pidStr, NULL, 10);
        fclose(pidFile);

        // Check if process with this PID exists
        if (existingPid > 0 && kill(existingPid, 0) == 0) {
          // Process exists and is running
          DNSLogError(LogCategoryGeneral, "Another instance is already running with PID: %d",
                      existingPid);
          return NO;
        } else {
          // Process doesn't exist, remove stale PID file
          DNSLogInfo(LogCategoryGeneral, "Removing stale PID file (PID %d no longer exists)",
                     existingPid);
          unlink(lockFilePath);
        }
      } else {
        fclose(pidFile);
        // Corrupt PID file, remove it
        DNSLogError(LogCategoryGeneral, "Removing corrupt PID file");
        unlink(lockFilePath);
      }
    }
  }

  // Create lock file
  lockFileDescriptor = open(lockFilePath, O_CREAT | O_RDWR, 0644);
  if (lockFileDescriptor < 0) {
    DNSLogError(LogCategoryError, "Failed to create lock file: %{public}s", strerror(errno));
    return NO;
  }

  // Try to acquire exclusive lock
  if (flock(lockFileDescriptor, LOCK_EX | LOCK_NB) < 0) {
    if (errno == EWOULDBLOCK) {
      // Another instance is running
      char pidStr[32];
      ssize_t len = read(lockFileDescriptor, pidStr, sizeof(pidStr) - 1);
      if (len > 0) {
        pidStr[len] = '\0';
        DNSLogError(LogCategoryGeneral, "Another instance is already running with PID: %{public}s",
                    pidStr);
      } else {
        DNSLogError(LogCategoryGeneral, "Another instance is already running");
      }
    } else {
      DNSLogError(LogCategoryError, "Failed to acquire lock: %{public}s", strerror(errno));
    }
    close(lockFileDescriptor);
    lockFileDescriptor = -1;
    return NO;
  }

  // Write our PID to the lock file
  ftruncate(lockFileDescriptor, 0);
  lseek(lockFileDescriptor, 0, SEEK_SET);

  char pidStr[32];
  snprintf(pidStr, sizeof(pidStr), "%d", getpid());
  write(lockFileDescriptor, pidStr, strlen(pidStr));

  DNSLogInfo(LogCategoryGeneral, "Process lock acquired, PID: %d", getpid());
  return YES;
}

- (void)releaseProcessLock {
  const char* lockFilePath = DaemonLockFilePath();
  if (lockFileDescriptor >= 0) {
    flock(lockFileDescriptor, LOCK_UN);
    close(lockFileDescriptor);
    unlink(lockFilePath);
    lockFileDescriptor = -1;
    DNSLogInfo(LogCategoryGeneral, "Process lock released");
  }
}

- (BOOL)isManagedByProfile {
  BOOL hasManagedDNSProxy = DNManagedPreferencesExist(CFSTR("com.apple.dnsProxy.managed"));
  BOOL hasManagedDNShield = DNManagedPreferencesExist(DNPreferenceDomainCF());

  Boolean keyExistsAndHasValue = false;
  Boolean managedModePref = CFPreferencesGetAppBooleanValue(
      CFSTR("ManagedMode"), DNPreferenceDomainCF(), &keyExistsAndHasValue);

  BOOL isManaged =
      hasManagedDNSProxy || hasManagedDNShield || (keyExistsAndHasValue && managedModePref);

  DNSLogInfo(LogCategoryConfiguration,
             "Managed profile detection - dnsProxy: %d, dnshield: %d, pref: %d (managed: %d)",
             hasManagedDNSProxy, hasManagedDNShield,
             keyExistsAndHasValue ? (managedModePref ? 1 : 0) : -1, isManaged);

  return isManaged;
}

#pragma mark - System Extension Management

- (void)installSystemExtension {
  NSDate* now = [NSDate date];
  if (self.lastExtensionInstallAttempt &&
      [now timeIntervalSinceDate:self.lastExtensionInstallAttempt] < 30.0) {
    DNSLogInfo(LogCategoryGeneral,
               "Skipping system extension activation request (last attempt < 30s)");
    return;
  }
  self.lastExtensionInstallAttempt = now;

  DNSLogInfo(LogCategoryGeneral, "Installing system extension: %{public}@",
             kDefaultExtensionBundleID);

  OSSystemExtensionRequest* request =
      [OSSystemExtensionRequest activationRequestForExtension:kDefaultExtensionBundleID
                                                        queue:self.queue];
  request.delegate = self;
  [[OSSystemExtensionManager sharedManager] submitRequest:request];
}

- (void)uninstallSystemExtension {
  DNSLogInfo(LogCategoryGeneral, "Uninstalling system extension: %{public}@",
             kDefaultExtensionBundleID);

  OSSystemExtensionRequest* request =
      [OSSystemExtensionRequest deactivationRequestForExtension:kDefaultExtensionBundleID
                                                          queue:self.queue];
  request.delegate = self;
  [[OSSystemExtensionManager sharedManager] submitRequest:request];
}

#pragma mark - OSSystemExtensionRequestDelegate

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest*)request
                  actionForReplacingExtension:(OSSystemExtensionProperties*)existing
                                withExtension:(OSSystemExtensionProperties*)ext {
  DNSLogInfo(LogCategoryGeneral, "Replacing extension version %{public}@ with %{public}@",
             existing.bundleShortVersion, ext.bundleShortVersion);
  return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest*)request {
  DNSLogInfo(LogCategoryGeneral, "System extension requires user approval");
  self.extensionInstalled = NO;
}

- (void)request:(OSSystemExtensionRequest*)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
  switch (result) {
    case OSSystemExtensionRequestCompleted:
      DNSLogInfo(LogCategoryGeneral, "System extension request completed successfully");
      self.extensionInstalled = YES;
      [self configureNetworkFilter];
      break;

    case OSSystemExtensionRequestWillCompleteAfterReboot:
      DNSLogInfo(LogCategoryGeneral, "System extension will complete after reboot");
      break;

    default:
      DNSLogError(LogCategoryGeneral, "System extension request finished with result: %ld",
                  (long)result);
      break;
  }
}

- (void)request:(OSSystemExtensionRequest*)request didFailWithError:(NSError*)error {
  DNSLogError(LogCategoryGeneral, "System extension request failed: %{public}@",
              error.localizedDescription);
  self.extensionInstalled = NO;
}

#pragma mark - Network Filter Configuration

- (BOOL)isDNSProxyConfiguredByMDM {
  // Check if DNS proxy is configured via MDM by looking for existing configuration
  // that matches our extension bundle ID
  __block BOOL isConfigured = NO;
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (!error && NEDNSProxyManager.sharedManager.providerProtocol) {
      NEDNSProxyProviderProtocol* protocol =
          (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
      NSString* bundleIdentifier = protocol.providerBundleIdentifier;
      if (bundleIdentifier.length == 0) {
        DNSLogInfo(LogCategoryConfiguration,
                   "MDM detection found configuration missing bundle identifier, fixing");
        protocol.providerBundleIdentifier = kDefaultExtensionBundleID;
        NEDNSProxyManager.sharedManager.providerProtocol = protocol;
        bundleIdentifier = kDefaultExtensionBundleID;
      }
      if ([bundleIdentifier isEqualToString:kDefaultExtensionBundleID]) {
        isConfigured = YES;
        DNSLogInfo(LogCategoryConfiguration, "DNS proxy is configured by MDM");
      }
    }
    dispatch_semaphore_signal(semaphore);
  }];

  dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
  return isConfigured;
}

- (void)configureNetworkFilter {
  NSDate* now = [NSDate date];
  if (self.lastProxyConfigurationAttempt &&
      [now timeIntervalSinceDate:self.lastProxyConfigurationAttempt] < 5.0) {
    DNSLogInfo(LogCategoryConfiguration,
               "Skipping DNS proxy configuration (last attempt < 5s ago)");
    return;
  }
  self.lastProxyConfigurationAttempt = now;

  DNSLogInfo(LogCategoryConfiguration, "Configuring network filter");

  BOOL managedProfileActive = [self isManagedByProfile];
  if (managedProfileActive) {
    DNSLogInfo(LogCategoryConfiguration,
               "Managed profile active; deferring DNS proxy configuration to MDM payload");
    self.lastProxyConfigurationAttempt = nil;
    [self checkAndEnableMDMConfiguredProxy];
    return;
  }

  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (error) {
      DNSLogError(LogCategoryConfiguration, "Failed to load DNS proxy preferences: %{public}@",
                  error.localizedDescription);
      return;
    }

    // Check if DNS proxy is configured (possibly by MDM)
    NEDNSProxyProviderProtocol* dnsProxy = nil;

    if (NEDNSProxyManager.sharedManager.providerProtocol) {
      dnsProxy = (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
      // Verify it's for our extension
      NSString* bundleIdentifier = dnsProxy.providerBundleIdentifier;
      if (bundleIdentifier.length == 0) {
        DNSLogInfo(LogCategoryConfiguration,
                   "Existing DNS proxy configuration missing bundle identifier, fixing");
        dnsProxy.providerBundleIdentifier = kDefaultExtensionBundleID;
        NEDNSProxyManager.sharedManager.providerProtocol = dnsProxy;
        bundleIdentifier = kDefaultExtensionBundleID;
      }

      if (![bundleIdentifier isEqualToString:kDefaultExtensionBundleID]) {
        DNSLogError(LogCategoryConfiguration,
                    "DNS proxy configured for unexpected bundle ID %{public}@; removing it",
                    bundleIdentifier);
        [NEDNSProxyManager.sharedManager
            removeFromPreferencesWithCompletionHandler:^(NSError* removeError) {
              if (removeError) {
                DNSLogError(LogCategoryConfiguration,
                            "Failed to remove mismatched DNS proxy configuration: %{public}@",
                            removeError.localizedDescription);
              } else {
                DNSLogInfo(LogCategoryConfiguration,
                           "Removed mismatched DNS proxy configuration, recreating");
                self.lastProxyConfigurationAttempt = nil;
                dispatch_async(self.queue, ^{
                  [self configureNetworkFilter];
                });
              }
            }];
        return;
      }
    } else {  // No existing configuration - create new one
      dnsProxy = [[NEDNSProxyProviderProtocol alloc] init];
      dnsProxy.providerBundleIdentifier = kDefaultExtensionBundleID;
      NEDNSProxyManager.sharedManager.providerProtocol = dnsProxy;
      NEDNSProxyManager.sharedManager.localizedDescription = @"DNShield DNS Filter";
      DNSLogInfo(LogCategoryConfiguration, "Created new DNS proxy configuration");
    }

    NSString* wsToken = DNPreferenceCopyValue(@"WebSocketAuthToken");
    NSNumber* wsEnabled = DNPreferenceCopyValue(@"EnableWebSocketServer");
    NSNumber* wsPort = DNPreferenceCopyValue(@"WebSocketPort");
    id rawAdditionalHeaders = DNPreferenceCopyValue(@"AdditionalHttpHeaders");
    NSArray<NSString*>* additionalHeaders = nil;
    if ([rawAdditionalHeaders isKindOfClass:[NSArray class]]) {
      NSMutableArray<NSString*>* validHeaders = [NSMutableArray array];
      for (id header in (NSArray*)rawAdditionalHeaders) {
        if ([header isKindOfClass:[NSString class]]) {
          [validHeaders addObject:header];
        } else {
          DNSLogError(LogCategoryConfiguration,
                      "Ignoring AdditionalHttpHeaders entry of type %{public}@; expected NSString",
                      NSStringFromClass([header class]));
        }
      }
      additionalHeaders = [validHeaders copy];
    } else if (rawAdditionalHeaders) {
      DNSLogError(LogCategoryConfiguration,
                  "AdditionalHttpHeaders preference had unexpected type %{public}@; ignoring value",
                  NSStringFromClass([rawAdditionalHeaders class]));
    }

    // Get existing provider configuration or create new one
    NSMutableDictionary* providerConfig = dnsProxy.providerConfiguration
                                              ? [dnsProxy.providerConfiguration mutableCopy]
                                              : [NSMutableDictionary dictionary];

    // Update with WebSocket settings
    if (wsToken.length > 0) {
      providerConfig[@"WebSocketAuthToken"] = wsToken;
    }
    if (wsEnabled) {
      providerConfig[@"EnableWebSocketServer"] = wsEnabled;
    }
    if (wsPort) {
      providerConfig[@"WebSocketPort"] = wsPort;
    }
    if (additionalHeaders.count > 0) {
      providerConfig[@"AdditionalHttpHeaders"] = additionalHeaders;
    }

    // Set the updated configuration
    if (providerConfig.count > 0) {
      dnsProxy.providerConfiguration = providerConfig;
      DNSLogInfo(LogCategoryConfiguration,
                 "Updated provider configuration with WebSocket settings");
    }

    // Always enable the proxy
    NEDNSProxyManager.sharedManager.enabled = YES;

    [NEDNSProxyManager.sharedManager saveToPreferencesWithCompletionHandler:^(NSError* saveError) {
      if (saveError) {
        DNSLogError(LogCategoryConfiguration, "Failed to save DNS proxy configuration: %{public}@",
                    saveError.localizedDescription);
        self.networkFilterEnabled = NO;

        if ([saveError.domain isEqualToString:@"NEConfigurationErrorDomain"]) {
          DNSLogInfo(LogCategoryConfiguration,
                     "Encountered NEConfigurationErrorDomain (code %ld), will retry after user "
                     "interaction if needed",
                     (long)saveError.code);

          dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), self.queue,
                         ^{
                           self.lastProxyConfigurationAttempt = nil;
                           [self configureNetworkFilter];
                         });
        }
      } else {
        DNSLogInfo(LogCategoryConfiguration, "Network filter configured and enabled successfully");
        self.networkFilterEnabled = YES;
        self.extensionInstalled = YES;

        // Reset attempt timer so future health checks can re-run if needed
        self.lastProxyConfigurationAttempt = nil;
      }
    }];
  }];
}

- (void)checkAndEnableMDMConfiguredProxy {
  DNSLogInfo(LogCategoryConfiguration, "Checking for MDM-configured DNS proxy");
  BOOL managedProfileActive = [self isManagedByProfile];

  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (error) {
      DNSLogError(LogCategoryConfiguration, "Failed to load DNS proxy preferences: %{public}@",
                  error.localizedDescription);
      return;
    }

    // Check if DNS proxy is configured but not enabled
    if (NEDNSProxyManager.sharedManager.providerProtocol) {
      NEDNSProxyProviderProtocol* protocol =
          (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
      NSString* bundleIdentifier = protocol.providerBundleIdentifier;
      if (bundleIdentifier.length == 0) {
        DNSLogInfo(LogCategoryConfiguration,
                   "Found DNS proxy configuration missing bundle identifier, fixing");
        protocol.providerBundleIdentifier = kDefaultExtensionBundleID;
        NEDNSProxyManager.sharedManager.providerProtocol = protocol;
        bundleIdentifier = kDefaultExtensionBundleID;
      }

      if ([bundleIdentifier isEqualToString:kDefaultExtensionBundleID]) {
        DNSLogInfo(LogCategoryConfiguration, "Found MDM-configured DNS proxy for our extension");
        self.extensionInstalled = YES;

        if (managedProfileActive &&
            DNIsLikelyLocalDNSProxyConfiguration(protocol, managedProfileActive)) {
          DNSLogInfo(LogCategoryConfiguration, "MDM-provisioned DNS proxy contains locally managed "
                                               "fields; leaving configuration untouched");
        }

        if (!NEDNSProxyManager.sharedManager.isEnabled) {
          DNSLogInfo(LogCategoryConfiguration,
                     "DNS proxy is configured but not enabled, enabling now");
          NEDNSProxyManager.sharedManager.enabled = YES;

          [NEDNSProxyManager.sharedManager saveToPreferencesWithCompletionHandler:^(
                                               NSError* saveError) {
            if (saveError) {
              DNSLogError(LogCategoryConfiguration,
                          "Failed to enable MDM-configured DNS proxy: %{public}@",
                          saveError.localizedDescription);
              self.networkFilterEnabled = NO;
            } else {
              DNSLogInfo(LogCategoryConfiguration, "Successfully enabled MDM-configured DNS proxy");
              self.networkFilterEnabled = YES;
              self.extensionInstalled = YES;
            }
          }];
        } else {
          DNSLogInfo(LogCategoryConfiguration, "MDM-configured DNS proxy is already enabled");
          self.extensionInstalled = YES;
          self.networkFilterEnabled = YES;
        }
      }
    } else {
      if (managedProfileActive) {
        DNSLogInfo(
            LogCategoryConfiguration,
            "Managed mode active but DNS proxy not yet provisioned; will retry automatically");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), self.queue, ^{
          [self checkAndEnableMDMConfiguredProxy];
        });
      } else {
        DNSLogInfo(LogCategoryConfiguration, "No MDM-configured DNS proxy found");
      }
    }
  }];
}

- (void)disableNetworkFilter {
  DNSLogInfo(LogCategoryConfiguration, "Disabling network filter");

  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (error) {
      DNSLogError(LogCategoryConfiguration, "Failed to load DNS proxy preferences: %{public}@",
                  error.localizedDescription);
      return;
    }

    NEDNSProxyManager.sharedManager.enabled = NO;

    [NEDNSProxyManager.sharedManager saveToPreferencesWithCompletionHandler:^(NSError* saveError) {
      if (saveError) {
        DNSLogError(LogCategoryConfiguration, "Failed to disable DNS proxy: %{public}@",
                    saveError.localizedDescription);
      } else {
        DNSLogInfo(LogCategoryConfiguration, "Network filter disabled successfully");
        self.networkFilterEnabled = NO;
      }
    }];
  }];
}

#pragma mark - Health Monitoring

- (void)startHealthMonitoring {
  self.healthCheckTimer = [NSTimer scheduledTimerWithTimeInterval:60.0
                                                           target:self
                                                         selector:@selector(performHealthCheck)
                                                         userInfo:nil
                                                          repeats:YES];
}

- (void)stopHealthMonitoring {
  [self.healthCheckTimer invalidate];
  self.healthCheckTimer = nil;
}

- (void)performHealthCheck {
  // Check if extension is still running
  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (error) {
      DNSLogError(LogCategoryGeneral, "Health check failed: %{public}@",
                  error.localizedDescription);
      return;
    }

    NEDNSProxyProviderProtocol* protocol =
        (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
    NSString* bundleIdentifier = protocol.providerBundleIdentifier;
    if (bundleIdentifier.length == 0 && protocol) {
      DNSLogInfo(LogCategoryConfiguration,
                 "Health check detected DNS proxy configuration without bundle identifier, fixing");
      protocol.providerBundleIdentifier = kDefaultExtensionBundleID;
      NEDNSProxyManager.sharedManager.providerProtocol = protocol;
      bundleIdentifier = kDefaultExtensionBundleID;
    }

    BOOL hasValidConfiguration =
        (protocol != nil && [bundleIdentifier isEqualToString:kDefaultExtensionBundleID]);
    BOOL isEnabled = NEDNSProxyManager.sharedManager.isEnabled;

    if (hasValidConfiguration && !self.extensionInstalled) {
      DNSLogInfo(LogCategoryConfiguration,
                 "Health check marking system extension as installed based on configuration state");
      self.extensionInstalled = YES;
    }

    if (!self.extensionInstalled) {
      DNSLogInfo(LogCategoryConfiguration,
                 "Health check: system extension not yet installed, requesting activation");
      [self installSystemExtension];
    }

    if (!hasValidConfiguration) {
      DNSLogInfo(LogCategoryConfiguration,
                 "Health check: DNS proxy configuration missing or mismatched (bundle=%{public}@), "
                 "reconfiguring",
                 bundleIdentifier ?: @"(null)");
      [self configureNetworkFilter];
      return;
    }

    if (!isEnabled) {
      DNSLogInfo(LogCategoryConfiguration,
                 "Health check: DNS proxy configuration present but disabled, re-enabling");
      [self configureNetworkFilter];
      return;
    }

    if (!self.networkFilterEnabled) {
      DNSLogInfo(LogCategoryConfiguration,
                 "Health check: DNS proxy enabled, updating internal state");
      self.networkFilterEnabled = YES;
    }
  }];
}

#pragma mark - Configuration Management

- (void)createConfigurationDirectory {
  NSError* error = nil;
  NSFileManager* fileManager = [NSFileManager defaultManager];

  if (![fileManager fileExistsAtPath:kDefaultConfigDirPath]) {
    [fileManager createDirectoryAtPath:kDefaultConfigDirPath
           withIntermediateDirectories:YES
                            attributes:@{NSFilePosixPermissions : @(0755)}
                                 error:&error];

    if (error) {
      DNSLogError(LogCategoryConfiguration, "Failed to create configuration directory: %{public}@",
                  error.localizedDescription);
    } else {
      DNSLogInfo(LogCategoryConfiguration, "Created configuration directory at %{public}@",
                 kDefaultConfigDirPath);
    }
  }
}

- (NSDictionary*)loadConfiguration {
  NSString* configPath = [NSString stringWithFormat:@"%@/config.json", kDefaultConfigDirPath];
  NSError* error = nil;

  NSData* data = [NSData dataWithContentsOfFile:configPath options:0 error:&error];
  if (!data) {
    DNSLogInfo(LogCategoryConfiguration, "No configuration file found, using defaults");
    return DNDefaultConfiguration(self.isManagedByProfile);
  }

  id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
  if (error) {
    DNSLogError(LogCategoryConfiguration, "Failed to parse configuration: %{public}@",
                error.localizedDescription);
    return nil;
  }

  if (![jsonObject isKindOfClass:[NSDictionary class]]) {
    DNSLogError(LogCategoryConfiguration,
                "Failed to parse configuration: unexpected top-level type %{public}@",
                NSStringFromClass([jsonObject class]));
    return nil;
  }

  NSDictionary* config = (NSDictionary*)jsonObject;

  // Validate configuration
  if (![self validateConfiguration:config]) {
    DNSLogError(LogCategoryConfiguration, "Invalid configuration payload; rejecting file");
    return nil;
  }

  return config;
}

- (BOOL)validateConfiguration:(NSDictionary*)config {
  // Validate DNS servers
  NSArray* dnsServers = config[@"dnsServers"];
  if (!dnsServers || ![dnsServers isKindOfClass:[NSArray class]] || dnsServers.count == 0) {
    DNSLogError(LogCategoryConfiguration, "Invalid or missing DNS servers in configuration");
    return NO;
  }

  // Validate each DNS server is a valid IP
  for (id server in dnsServers) {
    if (![server isKindOfClass:[NSString class]]) {
      DNSLogError(LogCategoryConfiguration, "Invalid DNS server entry: not a string");
      return NO;
    }

    NSString* serverStr = (NSString*)server;

    // Validate IP address (IPv4 or IPv6)
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    BOOL isValidIPv4 = inet_pton(AF_INET, [serverStr UTF8String], &(sa.sin_addr)) == 1;
    BOOL isValidIPv6 = inet_pton(AF_INET6, [serverStr UTF8String], &(sa6.sin6_addr)) == 1;

    if (!isValidIPv4 && !isValidIPv6) {
      DNSLogError(LogCategoryConfiguration, "Invalid DNS server IP: %{public}@", serverStr);
      return NO;
    }
  }

  // Validate update interval
  NSNumber* updateInterval = config[@"updateInterval"];
  if (updateInterval && ![updateInterval isKindOfClass:[NSNumber class]]) {
    DNSLogError(LogCategoryConfiguration, "Invalid update interval: not a number");
    return NO;
  }

  // Validate log level
  NSString* logLevel = config[@"logLevel"];
  if (logLevel && ![logLevel isKindOfClass:[NSString class]]) {
    DNSLogError(LogCategoryConfiguration, "Invalid log level: not a string");
    return NO;
  }

  return YES;
}

- (void)saveConfiguration:(NSDictionary*)config {
  NSString* configPath = [NSString stringWithFormat:@"%@/config.json", kDefaultConfigDirPath];
  NSError* error = nil;

  NSData* data = [NSJSONSerialization dataWithJSONObject:config
                                                 options:NSJSONWritingPrettyPrinted
                                                   error:&error];
  if (!data) {
    DNSLogError(LogCategoryConfiguration, "Failed to serialize configuration: %{public}@",
                error.localizedDescription);
    return;
  }

  [data writeToFile:configPath options:NSDataWritingAtomic error:&error];
  if (error) {
    DNSLogError(LogCategoryConfiguration, "Failed to save configuration: %{public}@",
                error.localizedDescription);
  } else {
    DNSLogInfo(LogCategoryConfiguration, "Configuration saved successfully");
  }
}

#pragma mark - XPC Service

- (void)startXPCService {
  const char* serviceName = [kDefaultXPCServiceName UTF8String];
  xpcListener = xpc_connection_create_mach_service(serviceName, dispatch_get_main_queue(),
                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);

  xpc_connection_set_event_handler(xpcListener, ^(xpc_object_t peer) {
    xpc_type_t type = xpc_get_type(peer);

    if (type == XPC_TYPE_CONNECTION) {
      [self handleXPCConnection:peer];
    } else if (type == XPC_TYPE_ERROR) {
      const char* descriptionCString = xpc_dictionary_get_string(peer, XPC_ERROR_KEY_DESCRIPTION);
      NSString* description =
          descriptionCString ? [NSString stringWithUTF8String:descriptionCString] : @"unknown";
      DNSLogError(LogCategoryGeneral, "XPC error: %{public}@", description);
    }
  });

  xpc_connection_resume(xpcListener);
  DNSLogInfo(LogCategoryGeneral, "XPC service started on %{public}@", kDefaultXPCServiceName);
}

- (void)handleXPCConnection:(xpc_connection_t)peer {
  pid_t peerPid = xpc_connection_get_pid(peer);
  NSString* peerKey = [NSString stringWithFormat:@"pid_%d", peerPid];

  // Check rate limit (max 10 connections per minute per PID)
  NSDate* lastConnection = self.connectionRateLimits[peerKey];
  if (lastConnection) {
    NSTimeInterval timeSinceLastConnection = [[NSDate date] timeIntervalSinceDate:lastConnection];
    if (timeSinceLastConnection < 6.0) {  // 10 per minute = 1 per 6 seconds
      DNSLogError(LogCategoryGeneral, "Rate limit exceeded for PID %d", peerPid);
      xpc_connection_cancel(peer);

      // Track rate limit violations
      NSNumber* violations = self.authFailuresByPeer[peerKey];
      self.authFailuresByPeer[peerKey] = @([violations intValue] + 1);

      // If too many violations, log security alert
      if ([self.authFailuresByPeer[peerKey] intValue] > 5) {
        NSString* alertMsg = [NSString
            stringWithFormat:@"XPC rate limit violation - PID %d making excessive connections",
                             peerPid];
        LogSecurityEvent(SecurityEventTypeCritical, [alertMsg UTF8String]);
      }
      return;
    }
  }
  self.connectionRateLimits[peerKey] = [NSDate date];

  // Clean up old rate limit entries periodically (older than 5 minutes)
  static NSDate* lastCleanup = nil;
  if (!lastCleanup || [[NSDate date] timeIntervalSinceDate:lastCleanup] > 300) {
    NSMutableArray* keysToRemove = [NSMutableArray array];
    for (NSString* key in self.connectionRateLimits) {
      NSDate* connectionTime = self.connectionRateLimits[key];
      if ([[NSDate date] timeIntervalSinceDate:connectionTime] > 300) {
        [keysToRemove addObject:key];
      }
    }
    [self.connectionRateLimits removeObjectsForKeys:keysToRemove];
    [self.authFailuresByPeer removeObjectsForKeys:keysToRemove];
    lastCleanup = [NSDate date];
  }

  // Get the process information from the connection on the SecCode for the peer process using its
  // PID
  CFNumberRef pidNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &peerPid);
  CFDictionaryRef attrs =
      CFDictionaryCreate(kCFAllocatorDefault, (const void**)&kSecGuestAttributePid,
                         (const void**)&pidNumber, 1, NULL, NULL);

  SecCodeRef code = NULL;
  OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
  CFRelease(attrs);
  CFRelease(pidNumber);

  if (status != errSecSuccess || code == NULL) {
    DNSLogError(LogCategoryGeneral,
                "Failed to get peer SecCode (status: %d) - rejecting connection", (int)status);
    xpc_connection_cancel(peer);
    return;
  }

  // Verify the code signature is valid and not modified
  status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
  if (status != errSecSuccess) {
    DNSLogError(LogCategoryGeneral,
                "Peer code signature is invalid (status: %d) - rejecting connection", (int)status);
    CFRelease(code);
    xpc_connection_cancel(peer);
    return;
  }

  // Get signing information from the validated code
  CFDictionaryRef signingInfo = NULL;
  status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signingInfo);

  CFStringRef signingId = NULL;
  CFStringRef teamId = NULL;

  if (status == errSecSuccess && signingInfo) {
    // Extract signing identifier
    signingId = CFDictionaryGetValue(signingInfo, kSecCodeInfoIdentifier);
    if (signingId)
      CFRetain(signingId);

    // Extract team identifier from entitlements
    CFDictionaryRef entitlements = CFDictionaryGetValue(signingInfo, kSecCodeInfoEntitlementsDict);
    if (entitlements) {
      teamId = CFDictionaryGetValue(entitlements, CFSTR("com.apple.developer.team-identifier"));
      if (teamId)
        CFRetain(teamId);
    }

    // If we couldn't get team ID from entitlements, try from signing info
    if (!teamId) {
      NSDictionary* info = (__bridge NSDictionary*)signingInfo;
      NSString* teamIdStr = info[@"teamid"];
      if (!teamIdStr) {
        // Try alternative key
        teamIdStr = info[(__bridge NSString*)kSecCodeInfoTeamIdentifier];
      }
      if (teamIdStr) {
        teamId = (__bridge_retained CFStringRef)teamIdStr;
      }
    }
  }

  // Also handle cases where we got partial info
  if (!signingId || !teamId) {
    DNSLogInfo(
        LogCategoryGeneral,
        "Unable to get full signing info (signingId=%@, teamId=%@), checking process path...",
        signingId ? (__bridge NSString*)signingId : @"nil",
        teamId ? (__bridge NSString*)teamId : @"nil");

    // Get process path
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(peerPid, pathBuffer, sizeof(pathBuffer));
    if (ret > 0) {
      NSString* processPath = [NSString stringWithUTF8String:pathBuffer];
      DNSLogInfo(LogCategoryGeneral, "Process path: %{public}@", processPath);

      // Check if this is one of our known binaries
      if ([processPath isEqualToString:@"/usr/local/bin/dnshield-ctl"] ||
          [processPath isEqualToString:@"/Applications/DNShield.app/Contents/MacOS/dnshield-ctl"] ||
          [processPath isEqualToString:@"/Applications/DNShield.app/Contents/MacOS/DNShield"] ||
          [processPath
              isEqualToString:@"/Applications/DNShield.app/Contents/MacOS/dnshield-daemon"]) {
        // This is a known binary path, verify it's properly signed
        NSURL* binaryURL = [NSURL fileURLWithPath:processPath];
        SecStaticCodeRef staticCode = NULL;
        OSStatus staticStatus = SecStaticCodeCreateWithPath((__bridge CFURLRef)binaryURL,
                                                            kSecCSDefaultFlags, &staticCode);

        if (staticStatus == errSecSuccess && staticCode) {
          // Verify static code signature
          staticStatus = SecStaticCodeCheckValidity(staticCode, kSecCSDefaultFlags, NULL);

          if (staticStatus == errSecSuccess) {
            // Get signing info from static code
            CFDictionaryRef staticInfo = NULL;
            staticStatus =
                SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &staticInfo);

            if (staticStatus == errSecSuccess && staticInfo) {
              // Use static code signing info
              if (!signingId) {
                signingId = CFDictionaryGetValue(staticInfo, kSecCodeInfoIdentifier);
                if (signingId)
                  CFRetain(signingId);
              }

              // Try to get team ID from static code
              if (!teamId) {
                NSDictionary* staticDict = (__bridge NSDictionary*)staticInfo;
                NSString* teamStr = staticDict[(__bridge NSString*)kSecCodeInfoTeamIdentifier];
                if (!teamStr) {
                  teamStr = staticDict[@"teamid"];
                }
                if (teamStr) {
                  teamId = (__bridge_retained CFStringRef)teamStr;
                }
              }

              CFRelease(staticInfo);
            }
          }

          CFRelease(staticCode);
        }
      }
    }
  }

  if (signingInfo)
    CFRelease(signingInfo);
  CFRelease(code);

  // Validate against expected values using team ID from build configuration
  NSString* expectedTeamId = kDNShieldTeamIdentifier;

  BOOL isValid = NO;
  if (signingId && teamId) {
    NSString* signingIdStr = (__bridge NSString*)signingId;
    NSString* teamIdStr = (__bridge NSString*)teamId;

    // Log authentication attempt for audit trail
    DNSLogInfo(LogCategoryGeneral, "XPC authentication attempt from: %{public}@ (Team: %{public}@)",
               signingIdStr, teamIdStr);

    // Validate the connection is from our app or extension with correct team ID
    // Allow if we have correct team ID and signing ID
    if ([teamIdStr isEqualToString:expectedTeamId] &&
        ([signingIdStr isEqualToString:kDNShieldPreferenceDomain] ||
         [signingIdStr isEqualToString:kDefaultExtensionBundleID] ||
         [signingIdStr isEqualToString:kDNShieldDaemonBundleID] ||
         [signingIdStr isEqualToString:@"dnshield-ctl"] ||
         [signingIdStr isEqualToString:@"dnshield-xpc"])) {
      isValid = YES;
      DNSLogInfo(LogCategoryGeneral, "XPC authentication successful for: %{public}@", signingIdStr);

      // Log successful authentication for audit trail
      NSString* successMsg = [NSString
          stringWithFormat:@"XPC authentication successful - %@ (PID %d)", signingIdStr, peerPid];
      LogSecurityEvent(SecurityEventTypeInfo, [successMsg UTF8String]);
    } else if (!teamIdStr && signingIdStr &&
               ([signingIdStr isEqualToString:@"dnshield-ctl"] ||
                [signingIdStr isEqualToString:@"dnshield-xpc"] ||
                [signingIdStr isEqualToString:kDNShieldPreferenceDomain] ||
                [signingIdStr isEqualToString:kDNShieldDaemonBundleID])) {
      isValid = YES;
      DNSLogInfo(LogCategoryGeneral,
                 "XPC authentication successful for known binary (no team ID): %{public}@",
                 signingIdStr);

      // Log for audit trail
      NSString* successMsg =
          [NSString stringWithFormat:@"XPC authentication successful (sudo context) - %@ (PID %d)",
                                     signingIdStr, peerPid];
      LogSecurityEvent(SecurityEventTypeInfo, [successMsg UTF8String]);
    } else {
      DNSLogError(
          LogCategoryGeneral,
          "XPC authentication failed - unexpected identifier: %{public}@ (Team: %{public}@)",
          signingIdStr, teamIdStr);
    }
  } else {
    DNSLogError(LogCategoryGeneral, "XPC authentication failed - unable to get signing info");
  }

  // Clean up
  if (signingId)
    CFRelease(signingId);
  if (teamId)
    CFRelease(teamId);

  if (!isValid) {
    DNSLogError(LogCategoryGeneral, "Rejecting XPC connection from untrusted peer");
    xpc_connection_cancel(peer);

    // Increment failed auth counter for monitoring
    self.failedAuthAttempts++;

    // Log to system audit log for security monitoring
    NSString* securityMsg = [NSString
        stringWithFormat:@"XPC authentication failure from PID %d - potential security event",
                         peerPid];
    LogSecurityEvent(SecurityEventTypeWarning, [securityMsg UTF8String]);

    return;
  }

  // Configure the connection
  xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
    xpc_type_t type = xpc_get_type(event);

    if (type == XPC_TYPE_DICTIONARY) {
      // For synchronous messages, we need to handle the reply properly
      const char* command = xpc_dictionary_get_string(event, "command");
      xpc_object_t reply = xpc_dictionary_create(NULL, NULL, 0);

      if (!command) {
        xpc_dictionary_set_string(reply, "error", "Missing command");
      } else if (strcmp(command, "status") == 0) {
        xpc_dictionary_set_bool(reply, "daemonRunning", YES);
        xpc_dictionary_set_bool(reply, "extensionInstalled", self.extensionInstalled);
        xpc_dictionary_set_bool(reply, "filterEnabled", self.networkFilterEnabled);
        xpc_dictionary_set_int64(reply, "pid", getpid());
      } else if (strcmp(command, "enable") == 0) {
        if (!self.extensionInstalled) {
          [self installSystemExtension];
        } else if (!self.networkFilterEnabled) {
          [self configureNetworkFilter];
        }
        xpc_dictionary_set_bool(reply, "success", YES);
      } else if (strcmp(command, "disable") == 0) {
        [self disableNetworkFilter];
        xpc_dictionary_set_bool(reply, "success", YES);
      } else if (strcmp(command, "reload") == 0) {
        NSDictionary* config = [self loadConfiguration];
        xpc_dictionary_set_bool(reply, "success", config != nil);
      } else if (strcmp(command, "shutdown") == 0) {
        xpc_dictionary_set_bool(reply, "success", YES);
        shouldTerminate = YES;
      } else if (strcmp(command, "security-status") == 0) {
        xpc_dictionary_set_uint64(reply, "failed_auth_attempts", self.failedAuthAttempts);
        xpc_dictionary_set_uint64(reply, "active_rate_limits", [self.connectionRateLimits count]);
        xpc_dictionary_set_uint64(reply, "blocked_peers", [self.authFailuresByPeer count]);
        xpc_dictionary_set_string(reply, "team_id", [kDNShieldTeamIdentifier UTF8String]);
        xpc_dictionary_set_bool(reply, "xpc_auth_enabled", YES);
        xpc_dictionary_set_bool(reply, "rate_limiting_enabled", YES);
        xpc_dictionary_set_uint64(reply, "rate_limit_max_per_minute", 10);
        xpc_dictionary_set_bool(reply, "success", YES);
      } else {
        xpc_dictionary_set_string(reply, "error", "Unknown command");
      }

      // Use xpc_dictionary_create_reply to send the reply back
      xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
      if (remote) {
        xpc_connection_send_message(remote, reply);
      } else {
        // This is a fallback - shouldn't normally happen
        xpc_connection_send_message(peer, reply);
      }
    } else if (type == XPC_TYPE_ERROR) {
      if (event == XPC_ERROR_CONNECTION_INVALID) {
        // Connection closed
      }
    }
  });

  xpc_connection_resume(peer);
}

- (void)stopXPCService {
  if (xpcListener) {
    xpc_connection_cancel(xpcListener);
    xpcListener = NULL;
    DNSLogInfo(LogCategoryGeneral, "XPC service stopped");
  }
}

#pragma mark - Lifecycle

- (void)start {
  DNSLogInfo(LogCategoryGeneral, "DNShield daemon starting");

  // Create configuration directory
  [self createConfigurationDirectory];

  // Load configuration
  NSDictionary* config = [self loadConfiguration];

  // Start XPC service
  [self startXPCService];

  BOOL managedByProfile = [self isManagedByProfile];
  if (!config) {
    DNSLogInfo(LogCategoryConfiguration,
               "Proceeding with default runtime configuration due to load failure");
    config = DNDefaultConfiguration(managedByProfile);
  }

  // Check for MDM-configured DNS proxy first
  [self checkAndEnableMDMConfiguredProxy];

  // Install and configure extension if autoStart is enabled and not already configured by MDM
  if (!managedByProfile && [config[@"autoStart"] boolValue] && ![self isDNSProxyConfiguredByMDM]) {
    [self installSystemExtension];
  }

  // Start health monitoring
  [self startHealthMonitoring];

  DNSLogInfo(LogCategoryGeneral, "DNShield daemon started successfully");
}

- (void)stop {
  DNSLogInfo(LogCategoryGeneral, "DNShield daemon stopping");

  // Stop health monitoring
  [self stopHealthMonitoring];

  // Stop XPC service
  [self stopXPCService];

  // Release process lock
  [self releaseProcessLock];

  DNSLogInfo(LogCategoryGeneral, "DNShield daemon stopped");
}

@end

#pragma mark - Signal Handling

static DNShieldDaemon* daemonInstance = nil;

void signalHandler(int signal) {
  DNSLogInfo(LogCategoryGeneral, "Received signal %d", signal);
  shouldTerminate = YES;

  if (daemonInstance) {
    [daemonInstance stop];
  }

  // Clean up PID file on exit
  unlink(DaemonLockFilePath());

  // Exit gracefully
  exit(0);
}

void setupSignalHandlers(void) {
  signal(SIGTERM, signalHandler);
  signal(SIGINT, signalHandler);
  signal(SIGQUIT, signalHandler);  // Handle Ctrl+backslash
  signal(SIGHUP, SIG_IGN);         // Ignore hangup
}

#pragma mark - Main

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    // Check for --version flag
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
      printf("DNShield daemon version %s (build %s)\n", DAEMON_VERSION, DAEMON_BUILD);
      return 0;
    }

    // Initialize logging
    logHandle = DNCreateLogHandle(kDaemonBundleIdentifier, @"daemon");

    DNSLogInfo(LogCategoryGeneral, "DNShield daemon version %s (build %s) starting", DAEMON_VERSION,
               DAEMON_BUILD);

    // Create daemon instance
    daemonInstance = [[DNShieldDaemon alloc] init];

    // Acquire process lock
    if (![daemonInstance acquireProcessLock]) {
      DNSLogError(LogCategoryGeneral, "Failed to acquire process lock, exiting");
      return 1;
    }

    // Setup signal handlers
    setupSignalHandlers();

    // Start daemon
    [daemonInstance start];

    // Run main loop
    while (!shouldTerminate) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                               beforeDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
    }

    // Clean shutdown
    [daemonInstance stop];

    DNSLogInfo(LogCategoryGeneral, "DNShield daemon exiting");
  }

  return 0;
}
