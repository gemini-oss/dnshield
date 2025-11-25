//
//  DNShieldPreferences.m
//  DNShield Network Extension
//
//

#import "DNShieldPreferences.h"
#import <CoreFoundation/CoreFoundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <unistd.h>
#import "Defaults.h"

// Preference Keys
NSString* const kDNShieldAdditionalHttpHeaders = @"AdditionalHttpHeaders";
NSString* const kDNShieldBindInterfaceStrategy = @"BindInterfaceStrategy";
NSString* const kDNShieldBlockedDomains = @"BlockedDomains";
NSString* const kDNShieldBypassPassword = @"BypassPassword";
NSString* const kDNShieldCacheBypassDomains = @"CacheBypassDomains";
NSString* const kDNShieldCacheDirectory = @"CacheDirectory";
NSString* const kDNShieldClientIdentifier = @"ClientIdentifier";
NSString* const kDNShieldDefaultManifestIdentifier = @"DefaultManifestIdentifier";
NSString* const kDNShieldDomainCacheRules = @"DomainCacheRules";
NSString* const kDNShieldEnableDNSCache = @"EnableDNSCache";
NSString* const kDNShieldEnableDNSChainPreservation = @"EnableDNSChainPreservation";
NSString* const kDNShieldEnableDNSInterfaceBinding = @"EnableDNSInterfaceBinding";
NSString* const kDNShieldEnableWebSocketServer = @"EnableWebSocketServer";
NSString* const kDNShieldInitialBackoffMs = @"InitialBackoffMs";
NSString* const kDNShieldLogLevel = @"LogLevel";
NSString* const kDNShieldConfigurationArchiveKey = @"Configuration";
NSString* const kDNShieldManifestUpdateInterval = @"ManifestUpdateInterval";
NSString* const kDNShieldManifestURL = @"ManifestURL";
NSString* const kDNShieldMaxRetries = @"MaxRetries";
NSString* const kDNShieldRuleSources = @"RuleSources";
NSString* const kDNShieldS3AccessKeyId = @"S3AccessKeyId";
NSString* const kDNShieldS3SecretAccessKey = @"S3SecretAccessKey";
NSString* const kDNShieldSoftwareRepoURL = @"SoftwareRepoURL";
NSString* const kDNShieldStickyInterfacePerTransaction = @"StickyInterfacePerTransaction";
NSString* const kDNShieldTelemetryEnabled = @"TelemetryEnabled";
NSString* const kDNShieldTelemetryHECToken = @"TelemetryHECToken";
NSString* const kDNShieldTelemetryPrivacyLevel = @"TelemetryPrivacyLevel";
NSString* const kDNShieldTelemetryServerURL = @"TelemetryServerURL";
NSString* const kDNShieldUpdateInterval = @"UpdateInterval";
NSString* const kDNShieldUserCanAdjustCacheTTL = @"UserCanAdjustCacheTTL";
NSString* const kDNShieldUserCanAdjustCache = @"UserCanAdjustCache";
NSString* const kDNShieldVerboseTelemetry = @"VerboseTelemetry";
NSString* const kDNShieldVPNResolvers = @"VPNResolvers";
NSString* const kDNShieldWhitelistedDomains = @"WhitelistedDomains";
NSString* const kDNShieldManifestFormat = @"ManifestFormat";
NSString* const kDNShieldWebSocketPort = @"WebSocketPort";
NSString* const kDNShieldWebSocketAuthToken = @"WebSocketAuthToken";
NSString* const kDNShieldWebSocketRetryBackoff = @"WebSocketRetryBackoff";
NSString* const kDNShieldChromeExtensionIDs = @"ChromeExtensionIDs";

NSString* DNManagedPreferencesPath(void) {
  return [NSString
      stringWithFormat:@"/Library/Managed Preferences/%@.plist", kDNShieldPreferenceDomain];
}

NSString* DNManagedPreferencesPathForUser(NSString* _Nullable userName) {
  if (userName.length == 0) {
    return DNManagedPreferencesPath();
  }
  return [NSString stringWithFormat:@"/Library/Managed Preferences/%@/%@.plist", userName,
                                    kDNShieldPreferenceDomain];
}

static NSString* DNConsoleUser(void) {
  static NSString* cachedConsoleUser = nil;
  static NSDate* lastLookup = nil;
  static dispatch_queue_t lookupQueue;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    lookupQueue =
        dispatch_queue_create("com.dnshield.preferences.consoleUser", DISPATCH_QUEUE_SERIAL);
  });

  __block NSString* result = nil;
  dispatch_sync(lookupQueue, ^{
    NSDate* now = [NSDate date];
    if (cachedConsoleUser && lastLookup && [now timeIntervalSinceDate:lastLookup] < 5.0) {
      result = cachedConsoleUser;
      return;
    }

    uid_t uid = 0;
    gid_t gid = 0;
    CFStringRef consoleUserRef = SCDynamicStoreCopyConsoleUser(NULL, &uid, &gid);
    NSString* consoleUser = (__bridge_transfer NSString*)consoleUserRef;
    if ([consoleUser isEqualToString:@"loginwindow"] || consoleUser.length == 0) {
      consoleUser = nil;
    }
    cachedConsoleUser = consoleUser;
    lastLookup = now;
    result = consoleUser;
  });

  return result;
}

static NSSet<NSString*>* DNPreferenceKeySet(void) {
  static NSSet<NSString*>* keySet = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    keySet = [NSSet setWithArray:[DNShieldPreferences defaultPreferences].allKeys];
  });
  return keySet;
}

static BOOL DNPreferenceValuesEqual(id a, id b) {
  if (a == b)
    return YES;
  if (!a || !b)
    return NO;
  return [a isEqual:b];
}

static id DNCopyCFPreferenceValue(CFStringRef key, CFStringRef domain, CFStringRef user,
                                  CFStringRef host) {
  if (!key || !domain)
    return nil;
  CFPropertyListRef value = CFPreferencesCopyValue(key, domain, user, host);
  if (!value)
    return nil;
  return CFBridgingRelease(value);
}

static id DNManagedPreferenceValueForKey(NSString* key) {
  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef domain = (__bridge CFStringRef)kDNShieldPreferenceDomain;

  if (CFPreferencesAppValueIsForced(cfKey, domain)) {
    CFPropertyListRef forcedValue = CFPreferencesCopyAppValue(cfKey, domain);
    if (forcedValue) {
      return CFBridgingRelease(forcedValue);
    }
  }

  NSDictionary* globalManaged =
      [NSDictionary dictionaryWithContentsOfFile:DNManagedPreferencesPath()];
  id managedValue = globalManaged[key];
  if (managedValue) {
    return managedValue;
  }

  NSString* consoleUser = DNConsoleUser();
  if (consoleUser.length > 0) {
    NSString* userPath = DNManagedPreferencesPathForUser(consoleUser);
    NSDictionary* userManaged = [NSDictionary dictionaryWithContentsOfFile:userPath];
    managedValue = userManaged[key];
    if (managedValue) {
      return managedValue;
    }
  }

  NSString* processUser = NSUserName();
  if (processUser.length > 0) {
    NSString* userPath = DNManagedPreferencesPathForUser(processUser);
    NSDictionary* userManaged = [NSDictionary dictionaryWithContentsOfFile:userPath];
    managedValue = userManaged[key];
    if (managedValue) {
      return managedValue;
    }
  }

  return nil;
}

static id DNLegacyPreferenceValueForKey(NSString* key) {
  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef domain = (__bridge CFStringRef)kDNShieldPreferenceDomain;

  // Root-level preference
  if (geteuid() == 0) {
    id rootValue = DNCopyCFPreferenceValue(cfKey, domain, CFSTR("root"), kCFPreferencesAnyHost);
    if (rootValue) {
      return rootValue;
    }
  }

  // System-wide (any user) preferences
  id systemValue =
      DNCopyCFPreferenceValue(cfKey, domain, kCFPreferencesAnyUser, kCFPreferencesCurrentHost);
  if (systemValue) {
    return systemValue;
  }
  systemValue =
      DNCopyCFPreferenceValue(cfKey, domain, kCFPreferencesAnyUser, kCFPreferencesAnyHost);
  if (systemValue) {
    return systemValue;
  }

  // Console user preferences
  NSString* consoleUser = DNConsoleUser();
  if (consoleUser.length > 0) {
    id consoleValue = DNCopyCFPreferenceValue(cfKey, domain, (__bridge CFStringRef)consoleUser,
                                              kCFPreferencesCurrentHost);
    if (consoleValue) {
      return consoleValue;
    }
    consoleValue = DNCopyCFPreferenceValue(cfKey, domain, (__bridge CFStringRef)consoleUser,
                                           kCFPreferencesAnyHost);
    if (consoleValue) {
      return consoleValue;
    }
  }

  // Current process user
  NSString* processUser = NSUserName();
  if (processUser.length > 0) {
    id userValue = DNCopyCFPreferenceValue(cfKey, domain, (__bridge CFStringRef)processUser,
                                           kCFPreferencesCurrentHost);
    if (userValue) {
      return userValue;
    }
    userValue = DNCopyCFPreferenceValue(cfKey, domain, (__bridge CFStringRef)processUser,
                                        kCFPreferencesAnyHost);
    if (userValue) {
      return userValue;
    }
  }

  return nil;
}

static void DNMirrorLegacyPreferencesInto(NSUserDefaults* sharedDefaults, BOOL overrideExisting) {
  if (!sharedDefaults)
    return;

  CFStringRef domain = (__bridge CFStringRef)kDNShieldPreferenceDomain;
  CFPreferencesSynchronize(domain, kCFPreferencesAnyUser, kCFPreferencesAnyHost);
  CFPreferencesSynchronize(domain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);

  for (NSString* key in DNPreferenceKeySet()) {
    id managedValue = DNManagedPreferenceValueForKey(key);
    if (managedValue) {
      continue;
    }

    id sharedValue = [sharedDefaults objectForKey:key];
    if (!overrideExisting && sharedValue != nil) {
      continue;
    }

    id legacyValue = DNLegacyPreferenceValueForKey(key);
    if (!legacyValue) {
      continue;
    }

    if (![legacyValue isKindOfClass:[NSNull class]]) {
      [sharedDefaults setObject:legacyValue forKey:key];
    } else {
      [sharedDefaults removeObjectForKey:key];
    }
  }

  [sharedDefaults synchronize];
}

static void DNWriteLegacyPreferenceValue(NSString* key, id value) {
  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef domain = (__bridge CFStringRef)kDNShieldPreferenceDomain;
  CFPropertyListRef cfValue = (__bridge CFPropertyListRef)value;

  NSString* targetUser = DNConsoleUser();
  if (targetUser.length == 0) {
    targetUser = NSUserName();
  }

  CFStringRef userRef =
      targetUser.length > 0 ? (__bridge CFStringRef)targetUser : kCFPreferencesCurrentUser;

  if (value) {
    CFPreferencesSetValue(cfKey, cfValue, domain, userRef, kCFPreferencesAnyHost);
  } else {
    CFPreferencesSetValue(cfKey, NULL, domain, userRef, kCFPreferencesAnyHost);
  }

  CFPreferencesSynchronize(domain, userRef, kCFPreferencesAnyHost);
}

@implementation DNShieldPreferences

+ (NSDictionary*)defaultPreferences {
  static NSDictionary* defaults = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    defaults = @{
      kDNShieldAdditionalHttpHeaders : [NSNull null],
      kDNShieldBindInterfaceStrategy :
          @"resolver_cidr",  // "resolver_cidr" | "original_path" | "active_resolver"
      kDNShieldBlockedDomains : @[],
      kDNShieldBypassPassword : [NSNull null],
      kDNShieldCacheBypassDomains : @[],  // Domains that should never be cached
      kDNShieldCacheDirectory : @"/Library/Application Support/DNShield/Cache",
      kDNShieldClientIdentifier : @"",
      kDNShieldDefaultManifestIdentifier : @"global-allowlist",
      kDNShieldDomainCacheRules :
          @{},  // Default never-cache rules for authentication and VPN domains
      kDNShieldEnableDNSCache : [NSNull null],  // Managed via profile when specified
      kDNShieldEnableDNSChainPreservation : @YES,
      kDNShieldEnableDNSInterfaceBinding : @NO,  // Feature flag: default OFF for safety
      kDNShieldEnableWebSocketServer : @YES,
      kDNShieldWebSocketPort : @(8876),
      kDNShieldWebSocketAuthToken : [NSNull null],
      kDNShieldWebSocketRetryBackoff : @YES,
      kDNShieldChromeExtensionIDs : @[],
      kDNShieldWebSocketRetryIntervalKey : @(kDNShieldDefaultWebSocketRetryInterval),
      kDNShieldInitialBackoffMs : @250,
      kDNShieldLogLevel : @1,                          // Info level
      kDNShieldManifestUpdateInterval : @DEFAULT_TTL,  // 5 minutes
      kDNShieldManifestURL : @"https://dnshield-manifests.example.com",
      kDNShieldManifestFormat : @"json",
      kDNShieldMaxRetries : @3,
      kDNShieldRuleSources : @[],
      kDNShieldS3AccessKeyId : [NSNull null],
      kDNShieldS3SecretAccessKey : [NSNull null],
      kDNShieldSoftwareRepoURL : @"https://dnshield-rules.example.com",
      kDNShieldStickyInterfacePerTransaction : @YES,
      kDNShieldTelemetryEnabled : @YES,             // Enable telemetry by default
      kDNShieldTelemetryHECToken : [NSNull null],   // Splunk HEC token - must be configured
      kDNShieldTelemetryPrivacyLevel : @1,          // 0=None, 1=Hash IPs, 2=Full anonymization
      kDNShieldTelemetryServerURL : [NSNull null],  // Must be configured
      kDNShieldUpdateInterval : @300,               // 5 minutes
      kDNShieldUserCanAdjustCache : @NO,
      kDNShieldUserCanAdjustCacheTTL : @NO,
      kDNShieldVerboseTelemetry : @NO,
      kDNShieldVPNResolvers : @[],
      kDNShieldWhitelistedDomains : @[]
    };
  });
  return defaults;
}

+ (nullable id)defaultValueForKey:(NSString*)key {
  id value = [self defaultPreferences][key];
  return (value == [NSNull null]) ? nil : value;
}

+ (BOOL)boolDefaultForKey:(NSString*)key fallback:(BOOL)fallback {
  id value = [self defaultValueForKey:key];
  if ([value isKindOfClass:[NSNumber class]]) {
    return [value boolValue];
  }
  return fallback;
}

+ (NSInteger)integerDefaultForKey:(NSString*)key fallback:(NSInteger)fallback {
  id value = [self defaultValueForKey:key];
  if ([value isKindOfClass:[NSNumber class]]) {
    return [value integerValue];
  }
  return fallback;
}

+ (nullable NSString*)stringDefaultForKey:(NSString*)key {
  id value = [self defaultValueForKey:key];
  if ([value isKindOfClass:[NSString class]]) {
    return value;
  }
  return nil;
}

+ (NSArray*)arrayDefaultForKey:(NSString*)key {
  id value = [self defaultValueForKey:key];
  if ([value isKindOfClass:[NSArray class]]) {
    return value;
  }
  return @[];
}

@end

id DNPreferenceCopyValue(NSString* key) {
  if (key.length == 0 || ![DNPreferenceKeySet() containsObject:key]) {
    return nil;
  }

  if (DNPreferenceIsManaged(key)) {
    return DNManagedPreferenceValueForKey(key);
  }

  NSUserDefaults* shared = DNSharedDefaults();
  id value = [shared objectForKey:key];
  if (value != nil) {
    return value;
  }

  id legacyValue = DNLegacyPreferenceValueForKey(key);
  if (legacyValue && legacyValue != [NSNull null]) {
    id existing = [shared objectForKey:key];
    if (!DNPreferenceValuesEqual(existing, legacyValue)) {
      [shared setObject:legacyValue forKey:key];
    }
    return legacyValue;
  }

  return [DNShieldPreferences defaultValueForKey:key];
}

BOOL DNPreferenceGetBool(NSString* key, BOOL fallback) {
  id value = DNPreferenceCopyValue(key);
  if ([value respondsToSelector:@selector(boolValue)]) {
    return [value boolValue];
  }
  return fallback;
}

NSInteger DNPreferenceGetInteger(NSString* key, NSInteger fallback) {
  id value = DNPreferenceCopyValue(key);
  if ([value respondsToSelector:@selector(integerValue)]) {
    return [value integerValue];
  }
  return fallback;
}

double DNPreferenceGetDouble(NSString* key, double fallback) {
  id value = DNPreferenceCopyValue(key);
  if ([value respondsToSelector:@selector(doubleValue)]) {
    return [value doubleValue];
  }
  return fallback;
}

NSArray* DNPreferenceGetArray(NSString* key) {
  id value = DNPreferenceCopyValue(key);
  return [value isKindOfClass:[NSArray class]] ? value : nil;
}

NSDictionary* DNPreferenceGetDictionary(NSString* key) {
  id value = DNPreferenceCopyValue(key);
  return [value isKindOfClass:[NSDictionary class]] ? value : nil;
}

void DNPreferenceSetValue(NSString* key, id value) {
  if (key.length == 0 || ![DNPreferenceKeySet() containsObject:key]) {
    return;
  }

  if (DNPreferenceIsManaged(key)) {
    return;
  }

  NSUserDefaults* shared = DNSharedDefaults();
  id currentValue = [shared objectForKey:key];
  if (value) {
    if (!DNPreferenceValuesEqual(currentValue, value)) {
      [shared setObject:value forKey:key];
    }
  } else if (currentValue != nil) {
    [shared removeObjectForKey:key];
  }
  [shared synchronize];

  DNWriteLegacyPreferenceValue(key, value);
  DNPreferenceDomainSynchronize(kDNShieldPreferenceDomain);
}

void DNPreferenceSetBool(NSString* key, BOOL value) {
  DNPreferenceSetValue(key, @(value));
}

void DNPreferenceSetInteger(NSString* key, NSInteger value) {
  DNPreferenceSetValue(key, @(value));
}

void DNPreferenceSetDouble(NSString* key, double value) {
  DNPreferenceSetValue(key, @(value));
}

void DNPreferenceRemoveValue(NSString* key) {
  DNPreferenceSetValue(key, nil);
}

BOOL DNPreferenceHasUserValue(NSString* key) {
  if (key.length == 0 || ![DNPreferenceKeySet() containsObject:key]) {
    return NO;
  }
  return [DNSharedDefaults() objectForKey:key] != nil;
}

BOOL DNPreferenceIsManaged(NSString* key) {
  if (key.length == 0 || ![DNPreferenceKeySet() containsObject:key]) {
    return NO;
  }
  return DNManagedPreferenceValueForKey(key) != nil;
}

void DNPreferenceMirrorLegacyDomainToAppGroup(void) {
  DNMirrorLegacyPreferencesInto(DNSharedDefaults(), YES);
}

NSUserDefaults* DNSharedDefaults(void) {
  static NSUserDefaults* sharedDefaults = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedDefaults = [[NSUserDefaults alloc] initWithSuiteName:kDNShieldAppGroup];
    DNMirrorLegacyPreferencesInto(sharedDefaults, NO);
  });
  return sharedDefaults;
}

BOOL DNPreferenceDomainSynchronize(NSString* domain) {
  if (domain.length == 0) {
    return NO;
  }
  // App Group domains must use NSUserDefaults(suiteName:) to sync; CFPreferences with containers
  // can trigger cfprefsd warnings and is not supported.
  if ([domain hasPrefix:@"group."]) {
    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:domain];
    [defaults synchronize];
    return YES;
  }
  Boolean result = CFPreferencesSynchronize((__bridge CFStringRef)domain, kCFPreferencesCurrentUser,
                                            kCFPreferencesAnyHost);

  if ([domain isEqualToString:kDNShieldPreferenceDomain]) {
    static NSTimeInterval lastMirrorTime = 0;
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (now - lastMirrorTime > 2.0 || lastMirrorTime == 0) {
      NSUserDefaults* shared = DNSharedDefaults();
      DNMirrorLegacyPreferencesInto(shared, YES);
      lastMirrorTime = now;
    }
  }

  return result == true ? YES : NO;
}

BOOL DNPreferenceAppSynchronize(NSString* domain) {
  if (domain.length == 0) {
    return NO;
  }
  Boolean result = CFPreferencesAppSynchronize((__bridge CFStringRef)domain);
  return result == true ? YES : NO;
}

BOOL DNPreferenceAppGroupSynchronize(void) {
  return DNPreferenceDomainSynchronize(kDNShieldAppGroup);
}
