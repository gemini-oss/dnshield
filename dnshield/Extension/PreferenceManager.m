//
//  PreferenceManager.m
//  DNShield Network Extension
//
//  Implementation of preference reading using CoreFoundation APIs
//

#import "PreferenceManager.h"
#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <os/log.h>

// Log handle
extern os_log_t logHandle;

@interface PreferenceManager ()
@property(nonatomic, strong) NSCache* preferenceCache;
@property(nonatomic, strong) NSUserDefaults* sharedDefaults;
@property(nonatomic, copy, nullable) NSString* cachedConsoleUser;
@property(nonatomic, strong, nullable) NSDate* consoleUserCacheDate;
@end

@implementation PreferenceManager

+ (instancetype)sharedManager {
  static PreferenceManager* sharedManager = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedManager = [[PreferenceManager alloc] init];
  });
  return sharedManager;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _preferenceCache = [[NSCache alloc] init];
    _preferenceCache.countLimit = 100;

    // Initialize shared defaults for app group
    _sharedDefaults = DNSharedDefaults();
    if (!_sharedDefaults) {
      os_log_error(logHandle, "Failed to initialize shared defaults for app group: %{public}@",
                   kDNShieldAppGroup);
    }
  }
  return self;
}

- (nullable NSString*)currentConsoleUser {
  NSDate* now = [NSDate date];
  if (self.cachedConsoleUser && self.consoleUserCacheDate &&
      [now timeIntervalSinceDate:self.consoleUserCacheDate] < 5.0) {
    return self.cachedConsoleUser;
  }

  uid_t uid = 0;
  gid_t gid = 0;
  CFStringRef consoleUserRef = SCDynamicStoreCopyConsoleUser(NULL, &uid, &gid);
  NSString* consoleUser = nil;

  if (consoleUserRef) {
    consoleUser = [(__bridge NSString*)consoleUserRef copy];
    CFRelease(consoleUserRef);

    if ([consoleUser isEqualToString:@"loginwindow"] || consoleUser.length == 0) {
      consoleUser = nil;
    }
  }

  self.cachedConsoleUser = consoleUser;
  self.consoleUserCacheDate = now;
  return consoleUser;
}

#pragma mark - Core Preference Reading

- (nullable id)preferenceValueForKey:(NSString*)key inDomain:(NSString*)domain {
  // For App Group domains, always read via NSUserDefaults(suiteName:), not CFPreferences.
  if ([domain hasPrefix:@"group."]) {
    id v = [self.sharedDefaults objectForKey:key];
    return v;
  }
  if ([domain isEqualToString:kDNShieldPreferenceDomain]) {
    return DNPreferenceCopyValue(key);
  }
  // Follow Apple's preference hierarchy:
  // 1. MDM/Configuration Profile (forced)
  // 2. /var/root/Library/Preferences/ (root user preferences)
  // 3. /Library/Preferences/ (system-wide)
  // 4. ~/Library/Preferences/ (current user)

  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef cfDomain = (__bridge CFStringRef)domain;

  // 1. Check for MDM/forced values first
  if (CFPreferencesAppValueIsForced(cfKey, cfDomain)) {
    CFPropertyListRef forcedValue = CFPreferencesCopyAppValue(cfKey, cfDomain);
    if (forcedValue) {
      os_log_debug(logHandle, "Found forced value for key %{public}@ in domain %{public}@", key,
                   domain);
      return CFBridgingRelease(forcedValue);
    }
  }

  // 2. Check root preferences if running as root
  if (geteuid() == 0) {
    CFPropertyListRef rootValue =
        CFPreferencesCopyValue(cfKey, cfDomain, CFSTR("root"), kCFPreferencesAnyHost);
    if (rootValue) {
      os_log_debug(logHandle, "Found root value for key %{public}@ in domain %{public}@", key,
                   domain);
      return CFBridgingRelease(rootValue);
    }
  }

  // 3. Check system-wide preferences (skip for app groups)
  if (![domain hasPrefix:@"group."]) {
    CFPropertyListRef systemValue =
        CFPreferencesCopyValue(cfKey, cfDomain, kCFPreferencesAnyUser, kCFPreferencesCurrentHost);
    if (systemValue) {
      os_log_debug(logHandle, "Found system value for key %{public}@ in domain %{public}@", key,
                   domain);
      return CFBridgingRelease(systemValue);
    }
  }

  // 4. Fall back to console user preferences (active logged-in user)
  NSString* consoleUser = [self currentConsoleUser];
  if (consoleUser.length > 0 && ![consoleUser isEqualToString:NSUserName()]) {
    id consoleValue = [self preferenceValueForKey:key
                                         inDomain:domain
                                          forUser:consoleUser
                                          forHost:NO];
    if (consoleValue) {
      return consoleValue;
    }
  }

  // 5. Fall back to current process user preferences
  id userValue = [self preferenceValueForKey:key inDomain:domain forUser:NSUserName() forHost:NO];
  if (userValue) {
    return userValue;
  }

  return nil;
}

- (nullable id)preferenceValueForKey:(NSString*)key
                            inDomain:(NSString*)domain
                             forUser:(nullable NSString*)userName
                             forHost:(BOOL)hostSpecific {
  // App Group domains should use shared defaults rather than CFPreferences.
  if ([domain hasPrefix:@"group."]) {
    id v = [self.sharedDefaults objectForKey:key];
    return v;
  }
  if ([domain isEqualToString:kDNShieldPreferenceDomain]) {
    return DNPreferenceCopyValue(key);
  }
  // Check cache first
  NSString* cacheKey =
      [NSString stringWithFormat:@"%@.%@.%@.%d", domain, key, userName ?: @"any", hostSpecific];
  id cachedValue = [self.preferenceCache objectForKey:cacheKey];
  if (cachedValue) {
    return cachedValue != [NSNull null] ? cachedValue : nil;
  }

  // Use CFPreferences to get the value
  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef cfDomain = (__bridge CFStringRef)domain;
  CFStringRef cfUser = userName ? (__bridge CFStringRef)userName : kCFPreferencesCurrentUser;
  CFStringRef cfHost = hostSpecific ? kCFPreferencesCurrentHost : kCFPreferencesAnyHost;

  CFPropertyListRef value = CFPreferencesCopyValue(cfKey, cfDomain, cfUser, cfHost);

  id result = nil;
  if (value) {
    result = CFBridgingRelease(value);
    [self.preferenceCache setObject:result forKey:cacheKey];
  } else {
    [self.preferenceCache setObject:[NSNull null] forKey:cacheKey];
  }

  return result;
}

- (nullable NSDictionary*)allPreferencesForDomain:(NSString*)domain {
  CFStringRef cfDomain = (__bridge CFStringRef)domain;

  // Get all keys for the domain
  CFArrayRef keys =
      CFPreferencesCopyKeyList(cfDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
  if (!keys) {
    return nil;
  }

  NSArray* keyArray = CFBridgingRelease(keys);
  NSMutableDictionary* result = [NSMutableDictionary dictionary];

  for (NSString* key in keyArray) {
    id value = [self preferenceValueForKey:key inDomain:domain];
    if (value) {
      result[key] = value;
    }
  }

  return [result copy];
}

#pragma mark - Preference Level Detection

- (PreferenceLevel)preferenceLevelForKey:(NSString*)key inDomain:(NSString*)domain {
  if ([domain isEqualToString:kDNShieldPreferenceDomain]) {
    if (DNPreferenceIsManaged(key)) {
      return PreferenceLevelManaged;
    }

    if (DNPreferenceHasUserValue(key)) {
      return PreferenceLevelUser;
    }

    if ([self preferenceExistsForKey:key inDomain:domain atLevel:PreferenceLevelHost]) {
      return PreferenceLevelHost;
    }

    if ([self preferenceExistsForKey:key inDomain:domain atLevel:PreferenceLevelGlobal]) {
      return PreferenceLevelGlobal;
    }

    return PreferenceLevelNone;
  }

  // Check managed preferences first (highest priority)
  if ([self isPreferenceManagedForKey:key inDomain:domain]) {
    return PreferenceLevelManaged;
  }

  // Check user level
  if ([self preferenceExistsForKey:key inDomain:domain atLevel:PreferenceLevelUser]) {
    return PreferenceLevelUser;
  }

  // Check host level
  if ([self preferenceExistsForKey:key inDomain:domain atLevel:PreferenceLevelHost]) {
    return PreferenceLevelHost;
  }

  // Check global level
  if ([self preferenceExistsForKey:key inDomain:domain atLevel:PreferenceLevelGlobal]) {
    return PreferenceLevelGlobal;
  }

  return PreferenceLevelNone;
}

- (BOOL)preferenceExistsForKey:(NSString*)key
                      inDomain:(NSString*)domain
                       atLevel:(PreferenceLevel)level {
  if ([domain isEqualToString:kDNShieldPreferenceDomain]) {
    switch (level) {
      case PreferenceLevelManaged: return DNPreferenceIsManaged(key);
      case PreferenceLevelUser: return DNPreferenceHasUserValue(key);
      default: break;
    }
  }

  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef cfDomain = (__bridge CFStringRef)domain;
  CFStringRef user;
  CFStringRef host;

  switch (level) {
    case PreferenceLevelUser:
      user = kCFPreferencesCurrentUser;
      host = kCFPreferencesAnyHost;
      break;

    case PreferenceLevelHost:
      user = kCFPreferencesCurrentUser;
      host = kCFPreferencesCurrentHost;
      break;

    case PreferenceLevelGlobal:
      user = kCFPreferencesAnyUser;
      host = kCFPreferencesAnyHost;
      break;

    default: return NO;
  }

  CFPropertyListRef value = CFPreferencesCopyValue(cfKey, cfDomain, user, host);
  if (value) {
    CFRelease(value);
    return YES;
  }

  if (level == PreferenceLevelUser && [domain isEqualToString:kDNShieldPreferenceDomain]) {
    id sharedValue = [self.sharedDefaults objectForKey:key];
    if (sharedValue != nil) {
      return YES;
    }

    NSString* consoleUser = [self currentConsoleUser];
    if (consoleUser.length > 0) {
      CFPropertyListRef consoleValue = CFPreferencesCopyValue(
          cfKey, cfDomain, (__bridge CFStringRef)consoleUser, kCFPreferencesAnyHost);
      if (consoleValue) {
        CFRelease(consoleValue);
        return YES;
      }
    }
  }

  return NO;
}

#pragma mark - File Path Detection

- (nullable NSString*)preferenceFilePathForKey:(NSString*)key inDomain:(NSString*)domain {
  PreferenceLevel level = [self preferenceLevelForKey:key inDomain:domain];

  switch (level) {
    case PreferenceLevelUser:
      return
          [NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", NSHomeDirectory(), domain];

    case PreferenceLevelHost: {
      // Get hardware UUID for ByHost preferences
      io_registry_entry_t ioRegistryRoot =
          IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
      CFStringRef uuidCf = (CFStringRef)IORegistryEntryCreateCFProperty(
          ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
      NSString* uuid = CFBridgingRelease(uuidCf);
      IOObjectRelease(ioRegistryRoot);

      if (uuid) {
        return [NSString stringWithFormat:@"%@/Library/Preferences/ByHost/%@.%@.plist",
                                          NSHomeDirectory(), domain, uuid];
      }
      break;
    }

    case PreferenceLevelGlobal:
      return [NSString stringWithFormat:@"/Library/Preferences/%@.plist", domain];

    case PreferenceLevelManaged:
      return [NSString
          stringWithFormat:@"/Library/Managed Preferences/%@/%@.plist", NSUserName(), domain];

    default: break;
  }

  return nil;
}

#pragma mark - MDM Support

- (BOOL)isPreferenceManagedForKey:(NSString*)key inDomain:(NSString*)domain {
  // Check if the preference is forced by MDM
  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef cfDomain = (__bridge CFStringRef)domain;

  Boolean forced = CFPreferencesAppValueIsForced(cfKey, cfDomain);

  if (forced) {
    return YES;
  }

  // Also check managed preferences directory
  NSString* managedPath =
      [NSString stringWithFormat:@"/Library/Managed Preferences/%@/%@.plist", NSUserName(), domain];

  if ([[NSFileManager defaultManager] fileExistsAtPath:managedPath]) {
    NSDictionary* managedPrefs = [NSDictionary dictionaryWithContentsOfFile:managedPath];
    if (managedPrefs[key]) {
      return YES;
    }
  }

  return NO;
}

#pragma mark - Synchronization

- (void)synchronizePreferencesForDomain:(NSString*)domain {
  // Clear cache for this domain
  [self.preferenceCache removeAllObjects];

  // Force synchronization
  DNPreferenceDomainSynchronize(domain);

  os_log_info(logHandle, "Synchronized preferences for domain: %{public}@", domain);
}

#pragma mark - DNShield Specific Preferences

- (nullable NSArray<NSString*>*)blockedDomains {
  id value =
      [self preferenceValueForKey:kDNShieldBlockedDomains
                         inDomain:kDNShieldPreferenceDomain
                     defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldBlockedDomains]];

  if ([value isKindOfClass:[NSArray class]]) {
    return value;
  }

  return nil;
}

- (nullable NSArray<NSString*>*)whitelistedDomains {
  id value = [self
      preferenceValueForKey:kDNShieldWhitelistedDomains
                   inDomain:kDNShieldPreferenceDomain
               defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldWhitelistedDomains]];

  if ([value isKindOfClass:[NSArray class]]) {
    return value;
  }

  return nil;
}

- (nullable NSDictionary*)ruleSourceConfiguration {
  id value =
      [self preferenceValueForKey:kDNShieldRuleSources
                         inDomain:kDNShieldPreferenceDomain
                     defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldRuleSources]];

  if ([value isKindOfClass:[NSDictionary class]]) {
    return value;
  }

  return nil;
}

- (NSTimeInterval)updateInterval {
  id value =
      [self preferenceValueForKey:kDNShieldUpdateInterval
                         inDomain:kDNShieldPreferenceDomain
                     defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldUpdateInterval]];

  if ([value isKindOfClass:[NSNumber class]]) {
    return [value doubleValue];
  }

  // Default to 5 minutes
  return 300.0;
}

- (nullable NSString*)cacheDirectory {
  id value =
      [self preferenceValueForKey:kDNShieldCacheDirectory
                         inDomain:kDNShieldPreferenceDomain
                     defaultValue:[DNShieldPreferences defaultValueForKey:kDNShieldCacheDirectory]];

  if ([value isKindOfClass:[NSString class]]) {
    return value;
  }

  return nil;
}

#pragma mark - Preference Writing

- (void)setPreferenceValue:(nullable id)value forKey:(NSString*)key inDomain:(NSString*)domain {
  if ([domain isEqualToString:kDNShieldPreferenceDomain]) {
    DNPreferenceSetValue(key, value);
    [self.preferenceCache removeAllObjects];
    os_log_info(logHandle, "Set DNShield preference %{public}@", key);
    return;
  }

  // App Group writes must go through NSUserDefaults(suiteName:).
  if ([domain hasPrefix:@"group."]) {
    if (value) {
      [self.sharedDefaults setObject:value forKey:key];
    } else {
      [self.sharedDefaults removeObjectForKey:key];
    }
    [self.sharedDefaults synchronize];

    NSString* cacheKey = [NSString stringWithFormat:@"%@.%@.any.0", domain, key];
    [self.preferenceCache removeObjectForKey:cacheKey];
    os_log_info(logHandle, "Set (app-group) preference %{public}@ in domain %{public}@", key,
                domain);
    return;
  }

  // Write to /Library/Preferences (system-wide) for non-group domains
  CFStringRef cfKey = (__bridge CFStringRef)key;
  CFStringRef cfDomain = (__bridge CFStringRef)domain;
  CFPropertyListRef cfValue = (__bridge CFPropertyListRef)value;

  CFPreferencesSetValue(cfKey, cfValue, cfDomain, kCFPreferencesAnyUser, kCFPreferencesCurrentHost);

  // Clear cache for this key
  NSString* cacheKey = [NSString stringWithFormat:@"%@.%@.any.0", domain, key];
  [self.preferenceCache removeObjectForKey:cacheKey];

  // Synchronize to disk
  Boolean success =
      CFPreferencesSynchronize(cfDomain, kCFPreferencesAnyUser, kCFPreferencesCurrentHost);

  if (success) {
    os_log_info(logHandle, "Set preference %{public}@ in domain %{public}@", key, domain);
  } else {
    os_log_error(logHandle, "Failed to set preference %{public}@ in domain %{public}@", key,
                 domain);
  }
}

#pragma mark - Default Value Support

- (nullable id)preferenceValueForKey:(NSString*)key
                            inDomain:(NSString*)domain
                        defaultValue:(nullable id)defaultValue {
  id value = [self preferenceValueForKey:key inDomain:domain];

  if (value == nil && defaultValue != nil) {
    // Write default value to preferences for admin discoverability
    [self setPreferenceValue:defaultValue forKey:key inDomain:domain];
    return defaultValue;
  }

  return value;
}

#pragma mark - Debugging Support

- (NSString*)preferenceLevelDescriptionForKey:(NSString*)key inDomain:(NSString*)domain {
  PreferenceLevel level = [self preferenceLevelForKey:key inDomain:domain];
  NSString* filePath = [self preferenceFilePathForKey:key inDomain:domain];

  switch (level) {
    case PreferenceLevelManaged: return @"[MANAGED]";

    case PreferenceLevelUser:
      if ([domain isEqualToString:kDNShieldPreferenceDomain] && DNPreferenceHasUserValue(key)) {
        return [NSString stringWithFormat:@"[Group Container: %@]", kDNShieldAppGroup];
      }
      return filePath ? [NSString stringWithFormat:@"[%@]", filePath] : @"[~/Library/Preferences]";

    case PreferenceLevelHost:
      return filePath ? [NSString stringWithFormat:@"[%@]", filePath]
                      : @"[~/Library/Preferences/ByHost]";

    case PreferenceLevelGlobal:
      return filePath ? [NSString stringWithFormat:@"[%@]", filePath] : @"[/Library/Preferences]";

    case PreferenceLevelNone: return @"[not set]";

    default: return @"[unknown]";
  }
}

#pragma mark - Convenience Methods

- (nullable id)preferenceValueForKey:(NSString*)key {
  // Use app group for extension instead of app domain
  return [self preferenceValueForKey:key inDomain:kDNShieldAppGroup];
}

- (nullable id)preferenceForKey:(NSString*)key {
  return [self preferenceValueForKey:key];
}

- (void)setPreferenceValue:(nullable id)value forKey:(NSString*)key {
  // Use app group for extension instead of app domain
  [self setPreferenceValue:value forKey:key inDomain:kDNShieldAppGroup];
}

@end
