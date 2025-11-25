//
//  DNSProxyConfigurationManager.m
//  DNShield
//

#import "DNSProxyConfigurationManager.h"

#import "DNShieldPreferences.h"
#import "Defaults.h"
#import "Extension.h"
#import "LoggingManager.h"

#import <NetworkExtension/NetworkExtension.h>
#import <os/log.h>

#define ACTION_ACTIVATE 1

extern os_log_t logHandle;

static BOOL DNIsLikelyLocalDNSProxyConfiguration(NEDNSProxyProviderProtocol* protocol) {
  if (!protocol)
    return YES;
  NSDictionary* config = protocol.providerConfiguration;
  if (!config)
    return YES;

  if (config[@"payloadInfo"] != nil) {
    NSDictionary* payloadInfo = config[@"payloadInfo"];
    if ([payloadInfo[@"profileSource"] isEqualToString:@"mdm"]) {
      return NO;  // MDM-managed configuration
    }
  }

  if (config[@"ProviderDesignatedRequirement"] != nil || config[@"designatedRequirement"] != nil ||
      config[@"OnDemandEnabled"] != nil || config[@"UserDefinedName"] != nil ||
      config[@"pluginType"] != nil) {
    return NO;
  }

  if (config[@"WebSocketAuthToken"] != nil || config[@"WebSocketPort"] != nil ||
      config[@"EnableWebSocketServer"] != nil || config[@"ManifestConfiguration"] != nil) {
    return NO;
  }

  return YES;
}

@interface DNSProxyConfigurationManager ()

@property(nonatomic, strong) Extension* extensionManager;
@property(nonatomic, assign) BOOL cachedDNSProxyConfigured;
@property(nonatomic, strong, nullable) NSDate* lastDNSProxyCheck;
@property(nonatomic, assign, getter=isMDMManaged) BOOL MDMManaged;

@end

@implementation DNSProxyConfigurationManager

- (instancetype)initWithExtensionManager:(Extension*)extensionManager {
  self = [super init];
  if (self) {
    _extensionManager = extensionManager;
    _cachedDNSProxyConfigured = NO;
    _MDMManaged = NO;
  }
  return self;
}

- (void)migrateUserPreferencesToAppGroupIfNeeded {
  DNPreferenceMirrorLegacyDomainToAppGroup();
  os_log_info(logHandle, "Mirrored legacy preferences from %{public}@ into app group container",
              kDNShieldPreferenceDomain);
}

- (BOOL)isDNSProxyManagedByProfile {
  NSString* managedPrefPath = @"/Library/Managed Preferences/com.apple.dnsProxy.managed.plist";
  BOOL hasManagedDNSProxy = [[NSFileManager defaultManager] fileExistsAtPath:managedPrefPath];

  NSString* dnshieldManagedPath = @"/Library/Managed Preferences/com.dnshield.app.plist";
  BOOL hasManagedDNShield = [[NSFileManager defaultManager] fileExistsAtPath:dnshieldManagedPath];

  NSString* userName = NSUserName();
  NSString* userManagedPath = [NSString
      stringWithFormat:@"/Library/Managed Preferences/%@/com.dnshield.app.plist", userName];
  BOOL hasUserManagedDNShield = [[NSFileManager defaultManager] fileExistsAtPath:userManagedPath];

  NSUserDefaults* standardDefaults = [NSUserDefaults standardUserDefaults];
  [standardDefaults synchronize];
  BOOL hasMDMKeys = [standardDefaults objectForKey:@"ManifestURL"] != nil ||
                    [standardDefaults objectForKey:@"ManifestIdentifier"] != nil;

  BOOL isManagedByProfile =
      hasManagedDNSProxy || hasManagedDNShield || hasUserManagedDNShield || hasMDMKeys;

  os_log(logHandle,
         "MDM detection: dnsProxy.managed=%d, dnshield.managed=%d, user.managed=%d, mdmKeys=%d, "
         "result=%d",
         hasManagedDNSProxy, hasManagedDNShield, hasUserManagedDNShield, hasMDMKeys,
         isManagedByProfile);

  self.MDMManaged = isManagedByProfile;
  return isManagedByProfile;
}

- (BOOL)isDNSProxyConfiguredByMDM {
  if (self.lastDNSProxyCheck &&
      [[NSDate date] timeIntervalSinceDate:self.lastDNSProxyCheck] < 5.0) {
    return self.cachedDNSProxyConfigured;
  }

  [self updateDNSProxyConfigurationAsync];
  return self.cachedDNSProxyConfigured;
}

- (void)updateDNSProxyConfigurationAsync {
  BOOL isMDMManaged = [self isDNSProxyManagedByProfile];

  __weak typeof(self) weakSelf = self;
  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(
                                       NSError* _Nullable error) {
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    if (error) {
      DNSLogError(LogCategoryConfiguration, "Failed to load DNS proxy preferences: %{public}@",
                  error.localizedDescription);
      strongSelf.cachedDNSProxyConfigured = NO;
    } else {
      NEDNSProxyProviderProtocol* protocol =
          (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
      if (protocol) {
        NSString* bundleIdentifier = protocol.providerBundleIdentifier;
        if (bundleIdentifier.length == 0) {
          os_log(logHandle, "DNS proxy configuration missing bundle identifier, assigning default");
          protocol.providerBundleIdentifier = kDefaultExtensionBundleID;
          NEDNSProxyManager.sharedManager.providerProtocol = protocol;
          bundleIdentifier = kDefaultExtensionBundleID;
        }

        if ([bundleIdentifier isEqualToString:kDefaultExtensionBundleID]) {
          if (isMDMManaged && DNIsLikelyLocalDNSProxyConfiguration(protocol)) {
            os_log(logHandle, "Managed mode active but DNS proxy configuration appears locally "
                              "managed; removing local configuration");
            [strongSelf removeLocalDNSProxyConfigurationWithReason:
                            @"found locally managed configuration while MDM active"];

            NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
            [defaults removeObjectForKey:@"HasConfiguredDNSProxy"];
            [defaults synchronize];

            strongSelf.cachedDNSProxyConfigured = NO;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                             [strongSelf updateDNSProxyConfigurationAsync];
                           });
            return;
          }

          strongSelf.cachedDNSProxyConfigured = YES;
          os_log(logHandle, "DNS proxy is configured with bundle ID: %{public}@, enabled: %d",
                 bundleIdentifier, NEDNSProxyManager.sharedManager.isEnabled);

          NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
          if (![defaults boolForKey:@"HasConfiguredDNSProxy"]) {
            [defaults setBool:YES forKey:@"HasConfiguredDNSProxy"];
          }
        } else {
          strongSelf.cachedDNSProxyConfigured = NO;
        }
      } else {
        strongSelf.cachedDNSProxyConfigured = NO;
      }
    }

    strongSelf.lastDNSProxyCheck = [NSDate date];
    [strongSelf notifyDelegateOfStateChange];
  }];
}

- (void)checkAndEnableMDMDNSProxy {
  BOOL isMDMManaged = [self isDNSProxyManagedByProfile];

  if (!isMDMManaged) {
    os_log(logHandle, "Not managed by MDM, checking if DNS proxy needs configuration");

    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    BOOL hasConfiguredDNSProxy = [defaults boolForKey:@"HasConfiguredDNSProxy"];

    if (hasConfiguredDNSProxy) {
      return;
    }
  }

  __weak typeof(self) weakSelf = self;
  [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(
                                       NSError* _Nullable error) {
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    if (error) {
      DNSLogError(LogCategoryConfiguration, "Failed to load DNS proxy for auto-enable: %{public}@",
                  error.localizedDescription);
      return;
    }

    NEDNSProxyProviderProtocol* protocol =
        (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
    if (protocol) {
      NSString* bundleIdentifier = protocol.providerBundleIdentifier;
      if (bundleIdentifier.length == 0) {
        os_log(logHandle,
               "DNS proxy configuration missing bundle identifier during MDM check, assigning");
        protocol.providerBundleIdentifier = kDefaultExtensionBundleID;
        NEDNSProxyManager.sharedManager.providerProtocol = protocol;
        bundleIdentifier = kDefaultExtensionBundleID;
      }
      strongSelf.cachedDNSProxyConfigured =
          [bundleIdentifier isEqualToString:kDefaultExtensionBundleID];
      if (strongSelf.cachedDNSProxyConfigured) {
        NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
        if (![defaults boolForKey:@"HasConfiguredDNSProxy"]) {
          [defaults setBool:YES forKey:@"HasConfiguredDNSProxy"];
        }
      }
    } else {
      strongSelf.cachedDNSProxyConfigured = NO;
    }

    strongSelf.lastDNSProxyCheck = [NSDate date];

    if (!strongSelf.cachedDNSProxyConfigured) {
      if (isMDMManaged) {
        os_log(logHandle,
               "Managed mode detected and DNS proxy not yet provisioned; will retry without "
               "creating a local configuration");
        [strongSelf
            removeLocalDNSProxyConfigurationWithReason:@"waiting for managed configuration"];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
                         [strongSelf updateDNSProxyConfigurationAsync];
                       });
      } else {
        os_log(logHandle, "DNS proxy not configured, will configure now");

        dispatch_async(dispatch_get_main_queue(), ^{
          os_log(logHandle, "Configuring DNS proxy via toggleNetworkExtension");

          dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            if ([strongSelf.extensionManager toggleNetworkExtension:ACTION_ACTIVATE]) {
              os_log(logHandle, "DNS proxy configuration initiated successfully");

              NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
              [defaults setBool:YES forKey:@"HasConfiguredDNSProxy"];
              [defaults synchronize];

              [strongSelf notifyDelegateOfStateChange];
            } else {
              os_log(logHandle, "Failed to configure DNS proxy");
            }
          });
        });
      }
      return;
    }

    if (NEDNSProxyManager.sharedManager.isEnabled) {
      os_log(logHandle, "DNS proxy already enabled for MDM configuration");
      [strongSelf notifyDelegateOfStateChange];
      return;
    }

    os_log(logHandle, "Auto-enabling MDM-configured DNS proxy");
    NEDNSProxyManager.sharedManager.enabled = YES;

    [NEDNSProxyManager.sharedManager
        saveToPreferencesWithCompletionHandler:^(NSError* _Nullable saveError) {
          if (saveError) {
            DNSLogError(LogCategoryConfiguration, "Failed to auto-enable DNS proxy: %{public}@",
                        saveError.localizedDescription);
          } else {
            os_log(logHandle, "Successfully auto-enabled MDM-configured DNS proxy");

            NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
            if (![defaults boolForKey:@"HasConfiguredDNSProxy"]) {
              [defaults setBool:YES forKey:@"HasConfiguredDNSProxy"];
            }

            [strongSelf notifyDelegateOfStateChange];
          }
        }];
  }];
}

- (void)removeLocalDNSProxyConfigurationWithReason:(NSString*)reason {
  BOOL managedProfileActive = [self isDNSProxyManagedByProfile];
  if (managedProfileActive) {
    NEDNSProxyProviderProtocol* protocol =
        (NEDNSProxyProviderProtocol*)NEDNSProxyManager.sharedManager.providerProtocol;
    if (!DNIsLikelyLocalDNSProxyConfiguration(protocol)) {
      os_log(logHandle,
             "Skipping removal of DNS proxy configuration (%{public}@); managed profile owns "
             "current payload",
             reason);
      return;
    }

    os_log(logHandle,
           "Managed profile active but DNS proxy configuration appears locally managed; proceeding "
           "with removal (%{public}@)",
           reason);
  }

  os_log(logHandle, "Removing locally managed DNS proxy configuration (%{public}@)", reason);
  [NEDNSProxyManager.sharedManager
      removeFromPreferencesWithCompletionHandler:^(NSError* _Nullable removeError) {
        if (removeError) {
          DNSLogError(LogCategoryConfiguration,
                      "Failed to remove locally managed DNS proxy configuration: %{public}@",
                      removeError.localizedDescription);
        } else {
          os_log(logHandle, "Removed locally managed DNS proxy configuration");
        }
      }];
}

- (void)notifyDelegateOfStateChange {
  if ([self.delegate respondsToSelector:@selector(dnsProxyConfigurationManagerDidUpdateState:)]) {
    [self.delegate dnsProxyConfigurationManagerDidUpdateState:self];
  }
}

@end
