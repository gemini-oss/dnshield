//
//  RuleManager+Manifest.m
//  DNShield Network Extension
//

#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/Manager+Manifest.h>

#import "ConfigurationManager.h"
#import "DNSManifest.h"
#import "DNSManifestResolver.h"
#import "PreferenceManager.h"
#import "UpdateScheduler.h"

static void* ManifestResolverKey = &ManifestResolverKey;
static void* CurrentResolvedManifestKey = &CurrentResolvedManifestKey;
static void* CurrentManifestIdentifierKey = &CurrentManifestIdentifierKey;
static void* ManifestUpdateTimerKey = &ManifestUpdateTimerKey;

@implementation RuleManager (Manifest)

#pragma mark - Properties

- (DNSManifestResolver*)manifestResolver {
  DNSManifestResolver* resolver = objc_getAssociatedObject(self, ManifestResolverKey);
  if (!resolver) {
    resolver = [[DNSManifestResolver alloc] init];
    objc_setAssociatedObject(self, ManifestResolverKey, resolver,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  }
  return resolver;
}

- (void)setManifestResolver:(DNSManifestResolver*)resolver {
  objc_setAssociatedObject(self, ManifestResolverKey, resolver, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (DNSResolvedManifest*)currentResolvedManifest {
  return objc_getAssociatedObject(self, CurrentResolvedManifestKey);
}

- (void)setCurrentResolvedManifest:(DNSResolvedManifest*)manifest {
  objc_setAssociatedObject(self, CurrentResolvedManifestKey, manifest,
                           OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (NSString*)currentManifestIdentifier {
  return objc_getAssociatedObject(self, CurrentManifestIdentifierKey);
}

- (void)setCurrentManifestIdentifier:(NSString*)identifier {
  objc_setAssociatedObject(self, CurrentManifestIdentifierKey, identifier,
                           OBJC_ASSOCIATION_COPY_NONATOMIC);
}

#pragma mark - Initialization

- (instancetype)initWithManifestIdentifier:(NSString*)manifestIdentifier {
  [[LoggingManager sharedManager] logEvent:@"InitializingRuleManagerWithManifest"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{@"identifier" : manifestIdentifier ?: @"nil"}];

  // First get default configuration - this ensures we always have something
  DNSConfiguration* defaultConfig = [DNSConfiguration defaultConfiguration];

  self = [self initWithConfiguration:defaultConfig];
  if (self) {
    // Determine the actual manifest identifier to use
    NSString* actualIdentifier = manifestIdentifier ?: [self determineManifestIdentifier];

    NSError* error = nil;
    BOOL manifestLoaded = [self loadManifest:actualIdentifier error:&error];

    if (!manifestLoaded) {
      [[LoggingManager sharedManager]
          logError:error
          category:LogCategoryConfiguration
           context:[NSString
                       stringWithFormat:
                           @"Failed to load manifest %@, continuing with default configuration",
                           actualIdentifier]];

      // CRITICAL: Don't fail initialization, continue with default config
      // This ensures DNS resolution continues to work
      [[LoggingManager sharedManager] logEvent:@"UsingDefaultConfiguration"
                                      category:LogCategoryConfiguration
                                         level:LogLevelDefault
                                    attributes:@{
                                      @"reason" : @"manifest_not_found",
                                      @"attempted_identifier" : actualIdentifier
                                    }];
    } else {
      [[LoggingManager sharedManager] logEvent:@"ManifestLoadedSuccessfully"
                                      category:LogCategoryConfiguration
                                         level:LogLevelInfo
                                    attributes:@{@"identifier" : actualIdentifier}];
    }

    // Manifest timer disabled - using unified configuration reload timer in DNSProxyProvider
    // [self startManifestUpdateTimer];
    DNSLogInfo(LogCategoryConfiguration, " MANIFEST TIMER: Skipping separate manifest timer - "
                                         "using unified timer in DNSProxyProvider");
  }
  return self;
}

#pragma mark - Manifest Loading

- (BOOL)loadManifest:(NSString*)manifestIdentifier error:(NSError**)error {
  [[LoggingManager sharedManager] logEvent:@"LoadingManifest"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{@"identifier" : manifestIdentifier}];

  // Use the resolver's built-in fallback logic instead of duplicating it here
  DNSResolvedManifest* resolved =
      [self.manifestResolver resolveManifestWithFallback:manifestIdentifier error:error];

  if (!resolved) {
    return NO;
  }

  // Convert to configuration
  DNSConfiguration* configuration =
      [[ConfigurationManager sharedManager] configurationFromResolvedManifest:resolved];
  if (!configuration) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorInvalidFormat
                 userInfo:@{
                   NSLocalizedDescriptionKey : @"Failed to convert manifest to configuration"
                 }];
    }
    return NO;
  }

  // Update configuration
  [self updateConfiguration:configuration];

  // Store manifest info
  self.currentResolvedManifest = resolved;
  // Store the actual identifier that was loaded (might be fallback)
  self.currentManifestIdentifier = manifestIdentifier;

  // Kick off a rule update immediately for manifest mode.
  // Scheduler is intentionally not started in manifest mode; updates are event-driven.
  [self forceUpdate];

  // Log warnings if any
  for (NSError* warning in resolved.warnings) {
    [[LoggingManager sharedManager] logError:warning
                                    category:LogCategoryConfiguration
                                     context:@"Manifest warning"];
  }

  [[LoggingManager sharedManager] logEvent:@"ManifestLoaded"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{
                                  @"requestedIdentifier" : manifestIdentifier,
                                  @"loadedIdentifier" : manifestIdentifier,
                                  @"ruleSourceCount" : @(resolved.resolvedRuleSources.count)
                                }];

  return YES;
}

- (void)loadManifestAsync:(NSString*)manifestIdentifier
               completion:(void (^)(BOOL success, NSError* error))completion {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSError* error = nil;
    BOOL success = [self loadManifest:manifestIdentifier error:&error];

    dispatch_async(dispatch_get_main_queue(), ^{
      if (completion) {
        completion(success, error);
      }
    });
  });
}

- (void)reloadManifestIfNeeded {
  if (!self.currentManifestIdentifier) {
    return;
  }

  // Check if context has changed significantly
  DNSEvaluationContext* currentContext = self.manifestResolver.evaluationContext;
  [currentContext updateTimeProperties];

  // Re-resolve manifest with updated context and fallback support
  NSError* error = nil;
  DNSResolvedManifest* newResolved =
      [self.manifestResolver resolveManifestWithFallback:self.currentManifestIdentifier
                                                   error:&error];

  if (newResolved) {
    if (![self isResolvedManifestEqual:self.currentResolvedManifest to:newResolved]) {
      [[LoggingManager sharedManager] logEvent:@"ManifestContextChanged"
                                      category:LogCategoryConfiguration
                                         level:LogLevelInfo
                                    attributes:@{@"action" : @"reloading"}];

      DNSConfiguration* configuration =
          [[ConfigurationManager sharedManager] configurationFromResolvedManifest:newResolved];
      if (configuration) {
        [self updateConfiguration:configuration];
        self.currentResolvedManifest = newResolved;

        // Trigger actual rule update from the new sources
        DNSLogInfo(LogCategoryScheduler, "Manifest changed - triggering rule update");
        [self forceUpdate];
      }
    } else if (self.currentResolvedManifest) {
      // Manifest unchanged, but do periodic rule update if we have a valid manifest
      DNSLogInfo(LogCategoryScheduler, "Periodic rule update - fetching latest rules");
      [self forceUpdate];
    }
  } else {
    // All fallbacks failed - log error and don't trigger updates that might cause infinite loops
    [[LoggingManager sharedManager] logError:error
                                    category:LogCategoryConfiguration
                                     context:@"Failed to resolve manifest with all fallbacks"];
    DNSLogError(
        LogCategoryScheduler,
        "Manifest resolution failed completely, skipping rule update to prevent infinite loops");
  }
}

- (void)updateManifestContext:(NSDictionary*)contextUpdates {
  DNSEvaluationContext* context = self.manifestResolver.evaluationContext;

  for (NSString* key in contextUpdates) {
    id value = contextUpdates[key];

    // Update known properties
    if ([key isEqualToString:@"network_location"]) {
      context.networkLocation = value;
    } else if ([key isEqualToString:@"network_ssid"]) {
      context.networkSSID = value;
    } else if ([key isEqualToString:@"vpn_connected"]) {
      context.vpnConnected = [value boolValue];
    } else if ([key isEqualToString:@"user_group"]) {
      context.userGroup = value;
    } else if ([key isEqualToString:@"security_score"]) {
      context.securityScore = value;
    } else {
      // Custom property
      [context setCustomProperty:value forKey:key];
    }
  }

  // Reload if needed
  [self reloadManifestIfNeeded];
}

- (BOOL)isUsingManifest {
  return self.currentManifestIdentifier != nil;
}

#pragma mark - Conversion

- (DNSManifest*)convertConfigurationToManifest:(DNSConfiguration*)configuration {
  NSString* identifier = [[NSUUID UUID] UUIDString];
  NSString* displayName = @"Converted Configuration";

  DNSManifestMetadata* metadata =
      [[DNSManifestMetadata alloc] initWithAuthor:@"System"
                                      description:@"Auto-converted from legacy configuration"
                                     lastModified:[NSDate date]
                                          version:@"1.0"
                                     customFields:nil];

  DNSManifest* manifest = [[DNSManifest alloc] initWithIdentifier:identifier
                                                      displayName:displayName
                                                includedManifests:@[]
                                                      ruleSources:configuration.ruleSources
                                                     managedRules:@{}
                                                 conditionalItems:@[]
                                                         metadata:metadata];

  return manifest;
}

#pragma mark - Helper Methods

- (BOOL)isResolvedManifestEqual:(DNSResolvedManifest*)manifest1 to:(DNSResolvedManifest*)manifest2 {
  // Compare rule sources
  if (manifest1.resolvedRuleSources.count != manifest2.resolvedRuleSources.count) {
    return NO;
  }

  // Compare each rule source
  for (NSUInteger i = 0; i < manifest1.resolvedRuleSources.count; i++) {
    RuleSource* source1 = manifest1.resolvedRuleSources[i];
    RuleSource* source2 = manifest2.resolvedRuleSources[i];

    if (![source1.identifier isEqualToString:source2.identifier] ||
        source1.enabled != source2.enabled || source1.priority != source2.priority) {
      return NO;
    }
  }

  // Compare managed rules
  if (![manifest1.resolvedManagedRules isEqualToDictionary:manifest2.resolvedManagedRules]) {
    return NO;
  }

  return YES;
}

#pragma mark - Manifest Update Timer

- (dispatch_source_t)manifestUpdateTimer {
  return objc_getAssociatedObject(self, ManifestUpdateTimerKey);
}

- (void)setManifestUpdateTimer:(dispatch_source_t)timer {
  dispatch_source_t oldTimer = objc_getAssociatedObject(self, ManifestUpdateTimerKey);
  if (oldTimer) {
    dispatch_source_cancel(oldTimer);
  }
  objc_setAssociatedObject(self, ManifestUpdateTimerKey, timer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (void)startManifestUpdateTimer {
  // Stop any existing timer first to prevent stacking
  [self stopManifestUpdateTimer];

  // Get update interval from preferences (default to 300 seconds / 5 minutes)
  NSTimeInterval updateInterval = 300.0;
  NSNumber* intervalValue =
      [[PreferenceManager sharedManager] preferenceValueForKey:kDNShieldManifestUpdateInterval
                                                      inDomain:kDNShieldPreferenceDomain];
  if (intervalValue && [intervalValue doubleValue] > 0) {
    updateInterval = [intervalValue doubleValue];
  }

  DNSLogInfo(LogCategoryConfiguration,
             " MANIFEST TIMER: Starting manifest update timer with interval: %.1f seconds (%.1f "
             "minutes)",
             updateInterval, updateInterval / 60.0);

  [[LoggingManager sharedManager]
        logEvent:@"StartingManifestUpdateTimer"
        category:LogCategoryConfiguration
           level:LogLevelInfo
      attributes:@{@"interval" : @(updateInterval), @"intervalMinutes" : @(updateInterval / 60.0)}];

  dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

  dispatch_source_set_timer(
      timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(updateInterval * NSEC_PER_SEC)),
      (int64_t)(updateInterval * NSEC_PER_SEC),
      (int64_t)(1.0 * NSEC_PER_SEC));  // 1 second leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(timer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    static NSUInteger manifestTimerFireCount = 0;
    manifestTimerFireCount++;

    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"HH:mm:ss";
    NSString* timestamp = [formatter stringFromDate:[NSDate date]];

    DNSLogInfo(LogCategoryConfiguration,
               " MANIFEST TIMER FIRED #%lu at %{public}@: Checking for manifest updates",
               (unsigned long)manifestTimerFireCount, timestamp);

    [[LoggingManager sharedManager] logEvent:@"ManifestUpdateTimerFired"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:@{
                                    @"identifier" : strongSelf.currentManifestIdentifier ?: @"nil",
                                    @"fireCount" : @(manifestTimerFireCount),
                                    @"timestamp" : timestamp
                                  }];

    // Determine manifest identifier based on preference hierarchy
    NSString* manifestIdentifier = [strongSelf determineManifestIdentifier];

    [[LoggingManager sharedManager] logEvent:@"DeterminedManifestIdentifier"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:@{@"identifier" : manifestIdentifier}];

    // Load manifest with fallback logic
    NSError* error = nil;
    if (![strongSelf loadManifest:manifestIdentifier error:&error]) {
      [[LoggingManager sharedManager] logError:error
                                      category:LogCategoryConfiguration
                                       context:@"Failed to reload manifest on timer"];
    } else {
      // After successful manifest load, trigger rule updates
      // This replaces the UpdateScheduler functionality
      [strongSelf updateRulesFromCurrentManifest];
    }
  });

  dispatch_resume(timer);
  self.manifestUpdateTimer = timer;
}

- (void)stopManifestUpdateTimer {
  dispatch_source_t timer = self.manifestUpdateTimer;
  if (timer) {
    DNSLogInfo(LogCategoryConfiguration, " MANIFEST TIMER: Stopping manifest update timer");

    [[LoggingManager sharedManager] logEvent:@"StoppingManifestUpdateTimer"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:nil];
    dispatch_source_cancel(timer);
    self.manifestUpdateTimer = nil;
  }
}

#pragma mark - Manifest Identifier Resolution

- (NSString*)determineManifestIdentifier {
  PreferenceManager* prefManager = [PreferenceManager sharedManager];

  // Check preference hierarchy: MDM > root > system > user
  NSString* configuredIdentifier = [prefManager preferenceValueForKey:@"ManifestIdentifier"
                                                             inDomain:kDNShieldPreferenceDomain];
  if (configuredIdentifier) {
    [[LoggingManager sharedManager] logEvent:@"ManifestIdentifierFromPreference"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:@{@"identifier" : configuredIdentifier}];
    // Return the configured identifier - loadManifest will handle fallback if it fails
    return configuredIdentifier;
  }

  // No manifest preference set - use machine serial
  NSString* serialNumber = [self getMachineSerialNumber];
  if (serialNumber) {
    [[LoggingManager sharedManager] logEvent:@"UsingMachineSerialAsIdentifier"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:@{@"identifier" : serialNumber}];
    return serialNumber;
  }

  // No serial available - use default
  [[LoggingManager sharedManager] logEvent:@"UsingDefaultManifestIdentifier"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:nil];
  return @"default";
}

- (void)updateRulesFromCurrentManifest {
  if (!self.currentResolvedManifest) {
    [[LoggingManager sharedManager] logEvent:@"NoManifestToUpdateRulesFrom"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:nil];
    return;
  }

  DNSLogInfo(LogCategoryConfiguration,
             " MANIFEST UPDATE: Starting rule update from manifest with %lu rule sources",
             (unsigned long)self.currentResolvedManifest.resolvedRuleSources.count);

  // Process each rule source from the manifest
  NSArray<RuleSource*>* ruleSources = self.currentResolvedManifest.resolvedRuleSources;

  [[LoggingManager sharedManager] logEvent:@"UpdatingRulesFromManifest"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{@"sourceCount" : @(ruleSources.count)}];

  // Update configuration with rule sources from manifest
  DNSConfiguration* currentConfig = [[ConfigurationManager sharedManager] currentConfiguration];
  if (currentConfig) {
    currentConfig.ruleSources = ruleSources;
    [self updateConfiguration:currentConfig];
  }

  // Trigger a force update of all sources
  [self forceUpdate];
}

#pragma mark - Helper Methods

- (NSString*)getMachineSerialNumber {
  io_service_t platformExpert =
      IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
  if (!platformExpert) {
    return nil;
  }

  CFStringRef serialNumberRef = IORegistryEntryCreateCFProperty(
      platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
  IOObjectRelease(platformExpert);

  if (!serialNumberRef) {
    return nil;
  }

  NSString* serialNumber = (__bridge_transfer NSString*)serialNumberRef;
  return serialNumber;
}

@end
