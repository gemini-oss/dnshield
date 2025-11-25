//
//  Extension.m
//  DNShield
//

#import "Extension.h"
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <CoreFoundation/CoreFoundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <SystemExtensions/SystemExtensions.h>
#import <os/log.h>
#import "AppDelegate.h"
#import "LoggingManager.h"

// Constants
#define ACTION_ACTIVATE 1
#define ACTION_DEACTIVATE 0

static id DNPreferenceCopyValue(NSString* key);

/* GLOBALS */

extern os_log_t logHandle;

@implementation Extension

// submit request to toggle system extension
- (void)toggleExtension:(NSUInteger)action reply:(void (^)(BOOL))reply {
  // request
  OSSystemExtensionRequest* request = nil;

  NSString* appPath = [[NSBundle mainBundle] bundlePath];
  NSString* extPath = nil;
  BOOL extExists = NO;

  // dbg msg
  DNSLogDebug(LogCategoryGeneral, "toggling extension (action: %lu)", (unsigned long)action);
  os_log(logHandle, "toggleExtension called with action: %lu", (unsigned long)action);

  // Check if we're running from daemon context (daemon runs from /usr/local/bin)
  BOOL isDaemonContext =
      [[[NSProcessInfo processInfo] processName] isEqualToString:@"dnshield-daemon"] ||
      [appPath containsString:@"/usr/local/"] || ![appPath hasSuffix:@".app"];

  // Only enforce /Applications requirement for UI app
  if (!isDaemonContext && ![appPath hasPrefix:@"/Applications/"]) {
    DNSLogError(LogCategoryGeneral,
                "ERROR: DNShield.app must be installed in /Applications to load system extensions. "
                "Current path: %{public}@",
                appPath);

    // show alert
    dispatch_async(dispatch_get_main_queue(), ^{
      NSAlert* alert = [[NSAlert alloc] init];
      alert.messageText = @"Installation Location Error";
      alert.informativeText =
          @"DNShield.app must be installed in /Applications to load system extensions.\n\nPlease "
          @"move DNShield.app to the Applications folder and try again.";
      alert.alertStyle = NSAlertStyleCritical;
      [alert addButtonWithTitle:@"OK"];
      [alert runModal];
    });

    // bail
    reply(NO);
    return;
  }

  // save reply
  self.replyBlock = reply;

  // activation request
  if (ACTION_ACTIVATE == action) {
    // dbg msg
    DNSLogDebug(LogCategoryGeneral, "creating activation request");

    // init request
    request = [OSSystemExtensionRequest
        activationRequestForExtension:kDefaultExtensionBundleID
                                queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)];
  }
  // deactivation request
  else {
    // dbg msg
    DNSLogDebug(LogCategoryGeneral, "creating deactivation request");

    // init request
    request = [OSSystemExtensionRequest
        deactivationRequestForExtension:kDefaultExtensionBundleID
                                  queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)];
  }

  // sanity check
  if (nil == request) {
    DNSLogError(LogCategoryGeneral, "ERROR: failed to create request for extension");

    goto bail;
  }

  // set delegate
  request.delegate = self;

  // dbg msg
  DNSLogDebug(LogCategoryGeneral, "submitting request");

  // submit request
  os_log(logHandle, "Submitting system extension request for bundle: %{public}@",
         kDefaultExtensionBundleID);

  // Log current app bundle path for debugging (reuse existing appPath variable)
  os_log(logHandle, "App bundle path: %{public}@", appPath);

  // Check if extension exists in bundle
  extPath = [appPath
      stringByAppendingPathComponent:
          [NSString stringWithFormat:@"Contents/Library/SystemExtensions/%@.systemextension",
                                     kDefaultExtensionBundleID]];
  extExists = [[NSFileManager defaultManager] fileExistsAtPath:extPath];
  os_log(logHandle, "Extension bundle exists: %d at path: %{public}@", extExists, extPath);

  [OSSystemExtensionManager.sharedManager submitRequest:request];

  // dbg msg
  DNSLogDebug(LogCategoryGeneral, "submitting request returned...");
  os_log(logHandle, "System extension request submitted");

bail:

  return;
}

// check if extension is running
- (BOOL)isExtensionRunning {
  // flag
  __block BOOL isRunning = NO;

  // wait semaphore
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

  // check if NEDNSProxyManager is configured and enabled
  [NEDNSProxyManager.sharedManager
      loadFromPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
        // no error and has configuration?
        if (nil == error && nil != NEDNSProxyManager.sharedManager.providerProtocol) {
          // check if enabled
          isRunning = NEDNSProxyManager.sharedManager.isEnabled;
        }

        // signal semaphore
        dispatch_semaphore_signal(semaphore);
      }];

  // wait for completion (with timeout)
  dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));

  return isRunning;
}

// get network extension's status
- (BOOL)isNetworkExtensionEnabled {
  // flag
  __block BOOL isEnabled = NO;

  // wait semaphore
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

  // load preferences first to get accurate status
  [NEDNSProxyManager.sharedManager
      loadFromPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
        // no error and has configuration?
        if (nil == error && nil != NEDNSProxyManager.sharedManager.providerProtocol) {
          // check if enabled
          isEnabled = NEDNSProxyManager.sharedManager.isEnabled;
        }
        // signal semaphore
        dispatch_semaphore_signal(semaphore);
      }];

  // wait for completion (with timeout of 2 seconds)
  dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));

  return isEnabled;
}

// activate/deactive network extension
- (BOOL)toggleNetworkExtension:(NSUInteger)action {
  BOOL toggled = NO;

  __block BOOL wasError = NO;

  // config
  __block NEDNSProxyProviderProtocol* dnsConfig = nil;

  // wait semaphore
  dispatch_semaphore_t semaphore = 0;

  // timeout and result variables
  dispatch_time_t timeout;
  long result;

  // init wait semaphore
  semaphore = dispatch_semaphore_create(0);

  // dbg msg
  DNSLogDebug(LogCategoryConfiguration, "toggling network extension: %lu", (unsigned long)action);
  os_log(logHandle, "toggleNetworkExtension called with action: %lu", (unsigned long)action);

  // First ensure system extension is activated when enabling
  if (ACTION_ACTIVATE == action) {
    os_log(logHandle, "Ensuring system extension is activated first...");

    // Create a semaphore for extension activation
    dispatch_semaphore_t extSemaphore = dispatch_semaphore_create(0);
    __block BOOL extActivated = NO;

    // Activate system extension first
    [self toggleExtension:ACTION_ACTIVATE
                    reply:^(BOOL success) {
                      extActivated = success;
                      dispatch_semaphore_signal(extSemaphore);
                    }];

    // Wait for extension activation (10 second timeout)
    timeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
    result = dispatch_semaphore_wait(extSemaphore, timeout);

    if (result != 0 || !extActivated) {
      DNSLogError(LogCategoryConfiguration, "ERROR: Failed to activate system extension");
      return NO;
    }

    os_log(logHandle,
           "System extension activated successfully, proceeding with DNS proxy configuration");
  }

  // load prefs
  [NEDNSProxyManager.sharedManager
      loadFromPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
        // err?
        if (nil != error) {
          wasError = YES;

          // err msg
          DNSLogError(LogCategoryConfiguration,
                      "ERROR: 'loadFromPreferencesWithCompletionHandler' failed with %{public}@",
                      error);
        }

        // signal semaphore
        dispatch_semaphore_signal(semaphore);
      }];

  // dbg msg
  DNSLogDebug(LogCategoryConfiguration, "waiting for network extension configuration...");
  os_log(logHandle, "Waiting for loadFromPreferences to complete...");

  // wait for request to complete with timeout
  timeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
  result = dispatch_semaphore_wait(semaphore, timeout);

  if (result != 0) {
    DNSLogError(LogCategoryConfiguration, "ERROR: loadFromPreferences timed out after 10 seconds");
    wasError = YES;
  } else {
    os_log(logHandle, "loadFromPreferences completed");
  }

  if (YES == wasError)
    goto bail;

  // dbg msg
  DNSLogDebug(LogCategoryConfiguration, "loaded current configuration for the network extension");

  // activate?
  if (ACTION_ACTIVATE == action) {
    // dbg msg
    DNSLogDebug(LogCategoryConfiguration, "activating network extension...");

    // Check if we need to create or update the configuration
    if (nil == NEDNSProxyManager.sharedManager.providerProtocol) {
      // No config exists - create new one
      dnsConfig = [[NEDNSProxyProviderProtocol alloc] init];
      dnsConfig.providerBundleIdentifier = kDefaultExtensionBundleID;
      NEDNSProxyManager.sharedManager.providerProtocol = dnsConfig;
      NEDNSProxyManager.sharedManager.localizedDescription = @"DNShield DNS Filter";
      DNSLogInfo(LogCategoryConfiguration, "Created new DNS proxy configuration");
    } else {
      // Config exists (possibly from MDM) - use existing one
      dnsConfig = (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;

      // Only proceed if it's our extension
      NSString* bundleIdentifier = dnsConfig.providerBundleIdentifier;
      if (bundleIdentifier.length == 0) {
        DNSLogInfo(LogCategoryConfiguration,
                   "Existing DNS proxy configuration missing bundle identifier, fixing");
        dnsConfig.providerBundleIdentifier = kDefaultExtensionBundleID;
        NEDNSProxyManager.sharedManager.providerProtocol = dnsConfig;
        bundleIdentifier = kDefaultExtensionBundleID;
      }

      if (![bundleIdentifier isEqualToString:kDefaultExtensionBundleID]) {
        DNSLogError(LogCategoryConfiguration, "DNS proxy configured for different bundle ID: %@",
                    bundleIdentifier);
        wasError = YES;
        goto bail;
      }
      DNSLogInfo(LogCategoryConfiguration,
                 "Using existing DNS proxy configuration (possibly from MDM)");
    }

    // Always update the provider configuration with WebSocket settings
    // This ensures the extension gets the WebSocket configuration even for MDM-managed proxies
    id wsTokenObj = DNPreferenceCopyValue(@"WebSocketAuthToken");
    id wsEnabledObj = DNPreferenceCopyValue(@"EnableWebSocketServer");
    id wsPortObj = DNPreferenceCopyValue(@"WebSocketPort");

    // Validate types to prevent crashes from unexpected preference values
    NSString* wsToken = [wsTokenObj isKindOfClass:[NSString class]] ? wsTokenObj : nil;
    NSNumber* wsEnabled = [wsEnabledObj isKindOfClass:[NSNumber class]] ? wsEnabledObj : nil;
    NSNumber* wsPort = [wsPortObj isKindOfClass:[NSNumber class]] ? wsPortObj : nil;

    if (wsTokenObj && !wsToken) {
      DNSLogError(LogCategoryConfiguration, "Invalid WebSocketAuthToken type: %@",
                  NSStringFromClass([wsTokenObj class]));
    }
    if (wsEnabledObj && !wsEnabled) {
      DNSLogError(LogCategoryConfiguration, "Invalid EnableWebSocketServer type: %@",
                  NSStringFromClass([wsEnabledObj class]));
    }
    if (wsPortObj && !wsPort) {
      DNSLogError(LogCategoryConfiguration, "Invalid WebSocketPort type: %@",
                  NSStringFromClass([wsPortObj class]));
    }

    // Get existing provider configuration or create new one
    NSMutableDictionary* providerConfig = dnsConfig.providerConfiguration
                                              ? [dnsConfig.providerConfiguration mutableCopy]
                                              : [NSMutableDictionary dictionary];

    // Update with WebSocket settings
    if (wsToken) {
      providerConfig[@"WebSocketAuthToken"] = wsToken;
    }
    if (wsEnabled) {
      providerConfig[@"EnableWebSocketServer"] = wsEnabled;
    }
    if (wsPort) {
      providerConfig[@"WebSocketPort"] = wsPort;
    }

    // Set the updated configuration
    if (providerConfig.count > 0) {
      dnsConfig.providerConfiguration = providerConfig;
      DNSLogInfo(LogCategoryConfiguration,
                 "Updated provider configuration with WebSocket settings");
    }

    NEDNSProxyManager.sharedManager.enabled = YES;
  }

  // deactivate
  //  just set 'enabled' flag
  else {
    // dbg msg
    DNSLogDebug(LogCategoryConfiguration, "deactivating network extension...");

    NEDNSProxyManager.sharedManager.enabled = NO;
  }

  // save preferences
  {
    [NEDNSProxyManager.sharedManager
        saveToPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
          if (nil != error) {
            wasError = YES;

            // err msg
            DNSLogError(LogCategoryConfiguration,
                        "ERROR: 'saveToPreferencesWithCompletionHandler' failed with %{public}@",
                        error);
          }

          // signal semaphore
          dispatch_semaphore_signal(semaphore);
        }];
  }

  // dbg msg
  DNSLogDebug(LogCategoryConfiguration, "waiting for network extension configuration to save...");
  os_log(logHandle, "Waiting for saveToPreferences to complete...");

  // wait for request to complete with timeout
  timeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
  result = dispatch_semaphore_wait(semaphore, timeout);

  if (result != 0) {
    DNSLogError(LogCategoryConfiguration, "ERROR: saveToPreferences timed out after 10 seconds");
    wasError = YES;
  } else {
    os_log(logHandle, "saveToPreferences completed");
  }

  if (YES == wasError)
    goto bail;

  // dbg msg
  DNSLogDebug(LogCategoryConfiguration, "saved current configuration for the network extension");

  // happy
  toggled = YES;

bail:

  os_log(logHandle, "toggleNetworkExtension returning: %d", toggled);
  return toggled;
}

#pragma mark -
#pragma mark OSSystemExtensionRequest delegate methods

//  always replaces, so return 'OSSystemExtensionReplacementActionReplace'
- (OSSystemExtensionReplacementAction)request:(nonnull OSSystemExtensionRequest*)request
                  actionForReplacingExtension:(nonnull OSSystemExtensionProperties*)existing
                                withExtension:(nonnull OSSystemExtensionProperties*)ext {
  // dbg msg
  DNSLogDebug(LogCategoryGeneral, "method '%s' invoked with %{public}@, %{public}@ -> %{public}@",
              __PRETTY_FUNCTION__, request.identifier, existing.bundleShortVersion,
              ext.bundleShortVersion);

  os_log(logHandle, "Extension replacement requested:");
  os_log(logHandle, "  Existing version: %{public}@ (build %{public}@)",
         existing.bundleShortVersion, existing.bundleVersion);
  os_log(logHandle, "  New version: %{public}@ (build %{public}@)", ext.bundleShortVersion,
         ext.bundleVersion);
  os_log(logHandle, "  Action: REPLACE");

  return OSSystemExtensionReplacementActionReplace;
}

// error delegate method
- (void)request:(nonnull OSSystemExtensionRequest*)request
    didFailWithError:(nonnull NSError*)error {
  // err msg
  DNSLogError(LogCategoryGeneral, "ERROR: method '%s' invoked with %{public}@, %{public}@",
              __PRETTY_FUNCTION__, request, error);

  // show user-friendly error message
  NSString* errorMessage = nil;

  switch (error.code) {
    case OSSystemExtensionErrorValidationFailed:
      errorMessage = @"The system extension validation failed. Please ensure it's properly signed.";
      break;
    case OSSystemExtensionErrorForbiddenBySystemPolicy:
      errorMessage = @"System policy prevents loading the extension. Please check System Settings "
                     @"> Privacy & Security.";
      break;
    case OSSystemExtensionErrorUnsupportedParentBundleLocation:
      errorMessage = @"DNShield must be installed in /Applications.";
      break;
    case OSSystemExtensionErrorExtensionNotFound:
      errorMessage = @"The network extension bundle was not found.";
      break;
    case OSSystemExtensionErrorDuplicateExtensionIdentifer:
      errorMessage = @"Another extension with the same identifier is already installed.";
      break;
    case OSSystemExtensionErrorAuthorizationRequired:
      errorMessage = @"Administrator authorization is required.";
      break;
    default:
      errorMessage = [NSString stringWithFormat:@"Failed to load extension: %@ (Code: %ld)",
                                                error.localizedDescription, (long)error.code];
      break;
  }

  // show alert on main thread
  dispatch_async(dispatch_get_main_queue(), ^{
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"Extension Installation Failed";
    alert.informativeText = errorMessage;
    alert.alertStyle = NSAlertStyleCritical;
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
  });

  // invoke reply
  self.replyBlock(NO);

  return;
}

// finish delegate method
//  install request? now can activate network ext
//  uninstall request? now can complete uninstall
- (void)request:(nonnull OSSystemExtensionRequest*)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
  // happy
  BOOL completed = NO;

  // dbg msg
  DNSLogDebug(LogCategoryGeneral, "method '%s' invoked with %{public}@, %ld", __PRETTY_FUNCTION__,
              request, (long)result);
  os_log(logHandle, "Extension request finished with result: %ld", (long)result);

  // issue/error?
  if (OSSystemExtensionRequestCompleted != result) {
    // err msg
    DNSLogError(LogCategoryGeneral,
                "ERROR: result %ld is an unexpected result for system extension request",
                (long)result);

    // bail
    goto bail;
  }

  // happy
  completed = YES;

bail:

  // reply
  os_log(logHandle, "Calling reply block with completed=%d", completed);
  if (self.replyBlock) {
    self.replyBlock(completed);
    os_log(logHandle, "Reply block called successfully");
  } else {
    DNSLogError(LogCategoryGeneral, "ERROR: Reply block is nil!");
  }

  return;
}

// user approval delegate
//  if this isn't the first time launch, will alert user to approve
- (void)requestNeedsUserApproval:(nonnull OSSystemExtensionRequest*)request {
  // dbg msg
  DNSLogDebug(LogCategoryGeneral, "method '%s' invoked with %{public}@", __PRETTY_FUNCTION__,
              request);

  // don't block - just log that approval is needed
  DNSLogInfo(LogCategoryGeneral, "System extension needs user approval. User should check System "
                                 "Settings > Privacy & Security");

  // show non-blocking notification
  dispatch_async(dispatch_get_main_queue(), ^{
    os_log(logHandle, "User approval needed - Please check System Settings > Privacy & Security to "
                      "approve the DNShield extension");

    // Show alert instead of deprecated notification
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"DNShield Extension Approval Required";
    alert.informativeText = @"Please approve the extension in System Settings > Privacy & Security";
    alert.alertStyle = NSAlertStyleInformational;
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
  });

  return;
}

@end
#pragma mark - Preference Helpers

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
