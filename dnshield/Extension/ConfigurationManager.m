//
//  ConfigurationManager.m
//  DNShield Network Extension
//
//  Implementation of configuration management
//

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Rule/RuleDatabase.h>

#import "ConfigurationManager.h"
#import "DNSManifest.h"

#import "PreferenceManager.h"

// Constants
NSString* const DNSConfigurationDidChangeNotification = @"DNSConfigurationDidChangeNotification";
NSString* const DNSConfigurationChangeReasonKey = @"reason";
NSString* const DNSConfigurationErrorDomain = @"com.dnshield.configuration";

// Log handle
extern os_log_t logHandle;

#pragma mark - DNSConfiguration

@implementation DNSConfiguration

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _ruleSources = @[];
    _updateConfig = [UpdateConfiguration defaultUpdateConfiguration];
    _cacheConfig = [CacheConfiguration defaultCacheConfiguration];
    _upstreamDNSServers = @[ @"1.1.1.1", @"8.8.8.8" ];
    _dnsTimeout = 5.0;
    _offlineMode = NO;
    _debugLogging = NO;
    _logLevel = @"info";
    _isManagedByProfile = NO;
    _allowRuleEditing = YES;
    _isTransitionState = NO;

    // WebSocket settings defaults
    _webSocketEnabled = [DNShieldPreferences boolDefaultForKey:kDNShieldEnableWebSocketServer
                                                      fallback:YES];
    _webSocketPort = 8876;
    _webSocketAuthToken = nil;

    // Manifest settings defaults
    _manifestURL = [DNShieldPreferences stringDefaultForKey:kDNShieldManifestURL];
    _manifestUpdateInterval =
        (int)[DNShieldPreferences integerDefaultForKey:kDNShieldManifestUpdateInterval
                                              fallback:300];  // 5 minutes

    // Telemetry settings defaults
    _telemetryEnabled = [DNShieldPreferences boolDefaultForKey:kDNShieldTelemetryEnabled
                                                      fallback:YES];
    _telemetryServerURL = [DNShieldPreferences stringDefaultForKey:kDNShieldTelemetryServerURL];
    _telemetryHECToken = [DNShieldPreferences stringDefaultForKey:kDNShieldTelemetryHECToken];

    // HTTP settings defaults
    id httpHeaders = [DNShieldPreferences defaultValueForKey:kDNShieldAdditionalHttpHeaders];
    _additionalHttpHeaders = [httpHeaders isKindOfClass:[NSDictionary class]] ? httpHeaders : nil;

    // VPN settings defaults
    _enableDNSChainPreservation =
        [DNShieldPreferences boolDefaultForKey:kDNShieldEnableDNSChainPreservation fallback:YES];
    _vpnResolvers = [DNShieldPreferences arrayDefaultForKey:kDNShieldVPNResolvers];
  }
  return self;
}

+ (instancetype)defaultConfiguration {
  DNSConfiguration* config = [[DNSConfiguration alloc] init];
  // By default, there are no rule sources. The system must be configured
  // either via preferences or a manifest.
  config.ruleSources = @[];
  return config;
}

- (BOOL)isValid:(NSError**)error {
  // Validate rule sources - allow empty rule sources during transition states
  if (self.ruleSources.count == 0 && !self.isTransitionState) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSConfigurationErrorDomain
                     code:DNSConfigurationErrorMissingRequired
                 userInfo:@{NSLocalizedDescriptionKey : @"At least one rule source is required"}];
    }
    return NO;
  }

  for (RuleSource* source in self.ruleSources) {
    if (![source isValid:error]) {
      return NO;
    }
  }

  // Validate DNS servers
  if (self.upstreamDNSServers.count == 0) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSConfigurationErrorDomain
                     code:DNSConfigurationErrorMissingRequired
                 userInfo:@{
                   NSLocalizedDescriptionKey : @"At least one upstream DNS server is required"
                 }];
    }
    return NO;
  }

  return YES;
}

- (void)mergeWithConfiguration:(DNSConfiguration*)other {
  if (other.ruleSources.count > 0) {
    self.ruleSources = other.ruleSources;
  }
  if (other.updateConfig) {
    self.updateConfig = other.updateConfig;
  }
  if (other.cacheConfig) {
    self.cacheConfig = other.cacheConfig;
  }
  if (other.upstreamDNSServers.count > 0) {
    self.upstreamDNSServers = other.upstreamDNSServers;
  }
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.ruleSources forKey:@"ruleSources"];
  [coder encodeObject:self.updateConfig forKey:@"updateConfig"];
  [coder encodeObject:self.cacheConfig forKey:@"cacheConfig"];
  [coder encodeObject:self.upstreamDNSServers forKey:@"upstreamDNSServers"];
  [coder encodeDouble:self.dnsTimeout forKey:@"dnsTimeout"];
  [coder encodeBool:self.offlineMode forKey:@"offlineMode"];
  [coder encodeBool:self.debugLogging forKey:@"debugLogging"];
  [coder encodeObject:self.logLevel forKey:@"logLevel"];
  [coder encodeBool:self.isManagedByProfile forKey:@"isManagedByProfile"];
  [coder encodeBool:self.allowRuleEditing forKey:@"allowRuleEditing"];
  [coder encodeBool:self.isTransitionState forKey:@"isTransitionState"];

  // WebSocket settings
  [coder encodeBool:self.webSocketEnabled forKey:@"webSocketEnabled"];
  [coder encodeInt:self.webSocketPort forKey:@"webSocketPort"];
  [coder encodeObject:self.webSocketAuthToken forKey:@"webSocketAuthToken"];

  // Manifest settings
  [coder encodeObject:self.manifestURL forKey:@"manifestURL"];
  [coder encodeInt:self.manifestUpdateInterval forKey:@"manifestUpdateInterval"];

  // Telemetry settings
  [coder encodeBool:self.telemetryEnabled forKey:@"telemetryEnabled"];
  [coder encodeObject:self.telemetryServerURL forKey:@"telemetryServerURL"];
  [coder encodeObject:self.telemetryHECToken forKey:@"telemetryHECToken"];

  // HTTP settings
  [coder encodeObject:self.additionalHttpHeaders forKey:@"additionalHttpHeaders"];

  // VPN settings
  [coder encodeBool:self.enableDNSChainPreservation forKey:@"enableDNSChainPreservation"];
  [coder encodeObject:self.vpnResolvers forKey:@"vpnResolvers"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _ruleSources =
        [coder decodeObjectOfClasses:[NSSet setWithArray:@[ [NSArray class], [RuleSource class] ]]
                              forKey:@"ruleSources"]
            ?: @[];
    _updateConfig = [coder decodeObjectOfClass:[UpdateConfiguration class] forKey:@"updateConfig"];
    _cacheConfig = [coder decodeObjectOfClass:[CacheConfiguration class] forKey:@"cacheConfig"];
    _upstreamDNSServers =
        [coder decodeObjectOfClasses:[NSSet setWithArray:@[ [NSArray class], [NSString class] ]]
                              forKey:@"upstreamDNSServers"]
            ?: @[ @"1.1.1.1", @"8.8.8.8" ];
    _dnsTimeout = [coder decodeDoubleForKey:@"dnsTimeout"];
    _offlineMode = [coder decodeBoolForKey:@"offlineMode"];
    _debugLogging = [coder decodeBoolForKey:@"debugLogging"];
    _logLevel = [coder decodeObjectOfClass:[NSString class] forKey:@"logLevel"] ?: @"info";
    _isManagedByProfile = [coder decodeBoolForKey:@"isManagedByProfile"];
    _allowRuleEditing = [coder decodeBoolForKey:@"allowRuleEditing"];
    _isTransitionState = [coder decodeBoolForKey:@"isTransitionState"];

    // WebSocket settings
    _webSocketEnabled = [coder decodeBoolForKey:@"webSocketEnabled"];
    _webSocketPort = [coder decodeIntForKey:@"webSocketPort"];
    _webSocketAuthToken = [coder decodeObjectOfClass:[NSString class] forKey:@"webSocketAuthToken"];

    // Manifest settings
    _manifestURL = [coder decodeObjectOfClass:[NSString class] forKey:@"manifestURL"];
    _manifestUpdateInterval = [coder decodeIntForKey:@"manifestUpdateInterval"];

    // Telemetry settings
    _telemetryEnabled = [coder decodeBoolForKey:@"telemetryEnabled"];
    _telemetryServerURL = [coder decodeObjectOfClass:[NSString class] forKey:@"telemetryServerURL"];
    _telemetryHECToken = [coder decodeObjectOfClass:[NSString class] forKey:@"telemetryHECToken"];

    // HTTP settings
    _additionalHttpHeaders = [coder
        decodeObjectOfClasses:[NSSet setWithArray:@[ [NSDictionary class], [NSString class] ]]
                       forKey:@"additionalHttpHeaders"];

    // VPN settings
    _enableDNSChainPreservation = [coder decodeBoolForKey:@"enableDNSChainPreservation"];
    _vpnResolvers =
        [coder decodeObjectOfClasses:[NSSet setWithArray:@[ [NSArray class], [NSString class] ]]
                              forKey:@"vpnResolvers"];
  }
  return self;
}

@end

#pragma mark - RuleSource

@implementation RuleSource

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _identifier = [[NSUUID UUID] UUIDString];
    _enabled = YES;
    _priority = 100;
    _updateInterval = 300;  // 5 minutes default (same as ManifestUpdateInterval)
    _format = @"json";
  }
  return self;
}

- (BOOL)isValid:(NSError**)error {
  if (!self.identifier || self.identifier.length == 0) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSConfigurationErrorDomain
                     code:DNSConfigurationErrorInvalidRuleSource
                 userInfo:@{NSLocalizedDescriptionKey : @"Rule source identifier is required"}];
    }
    return NO;
  }

  switch (self.type) {
    case RuleSourceTypeHTTPS:
      if (!self.url || self.url.length == 0) {
        if (error) {
          *error = [NSError
              errorWithDomain:DNSConfigurationErrorDomain
                         code:DNSConfigurationErrorInvalidRuleSource
                     userInfo:@{NSLocalizedDescriptionKey : @"HTTPS rule source requires URL"}];
        }
        return NO;
      }
      break;

    case RuleSourceTypeFile:
      if (!self.path || self.path.length == 0) {
        if (error) {
          *error = [NSError
              errorWithDomain:DNSConfigurationErrorDomain
                         code:DNSConfigurationErrorInvalidRuleSource
                     userInfo:@{NSLocalizedDescriptionKey : @"File rule source requires path"}];
        }
        return NO;
      }
      break;

    default:
      if (error) {
        *error =
            [NSError errorWithDomain:DNSConfigurationErrorDomain
                                code:DNSConfigurationErrorInvalidRuleSource
                            userInfo:@{NSLocalizedDescriptionKey : @"Unknown rule source type"}];
      }
      return NO;
  }

  return YES;
}

+ (nullable instancetype)sourceFromDictionary:(NSDictionary*)dict {
  if (!dict)
    return nil;

  RuleSource* source = [[RuleSource alloc] init];

  // Basic properties
  source.identifier = dict[@"id"] ?: [[NSUUID UUID] UUIDString];
  source.name = dict[@"name"] ?: @"Unnamed Source";
  source.format = dict[@"format"] ?: @"json";
  source.enabled = [dict[@"enabled"] boolValue];
  source.priority = [dict[@"priority"] integerValue] ?: 100;
  source.updateInterval = [dict[@"updateInterval"] doubleValue]
                              ?: 300;  // 5 minutes default (same as ManifestUpdateInterval)

  // Determine type
  NSString* typeStr = dict[@"type"];
  if ([typeStr isEqualToString:@"https"]) {
    source.type = RuleSourceTypeHTTPS;
    source.url = dict[@"url"];
    source.apiKey = dict[@"apiKey"];
  } else if ([typeStr isEqualToString:@"file"]) {
    source.type = RuleSourceTypeFile;
    source.path = dict[@"path"];
  } else {
    source.type = RuleSourceTypeUnknown;
  }

  source.configuration = dict;

  return source;
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.identifier forKey:@"identifier"];
  [coder encodeObject:self.name forKey:@"name"];
  [coder encodeInteger:self.type forKey:@"type"];
  [coder encodeObject:self.format forKey:@"format"];
  [coder encodeObject:self.configuration forKey:@"configuration"];
  [coder encodeDouble:self.updateInterval forKey:@"updateInterval"];
  [coder encodeInteger:self.priority forKey:@"priority"];
  [coder encodeBool:self.enabled forKey:@"enabled"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _identifier = [coder decodeObjectOfClass:[NSString class] forKey:@"identifier"];
    _name = [coder decodeObjectOfClass:[NSString class] forKey:@"name"];
    _type = [coder decodeIntegerForKey:@"type"];
    _format = [coder decodeObjectOfClass:[NSString class] forKey:@"format"];
    _configuration = [coder decodeObjectOfClasses:[NSSet setWithArray:@[
                              [NSDictionary class], [NSString class], [NSNumber class]
                            ]]
                                           forKey:@"configuration"];
    _updateInterval = [coder decodeDoubleForKey:@"updateInterval"];
    _priority = [coder decodeIntegerForKey:@"priority"];
    _enabled = [coder decodeBoolForKey:@"enabled"];
  }
  return self;
}

- (NSDictionary*)toDictionary {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  // Basic properties
  dict[@"identifier"] = self.identifier;
  dict[@"name"] = self.name;
  dict[@"format"] = self.format;
  dict[@"enabled"] = @(self.enabled);
  dict[@"priority"] = @(self.priority);
  dict[@"update_interval"] = @(self.updateInterval);

  // Type
  switch (self.type) {
    case RuleSourceTypeHTTPS: dict[@"type"] = @"https"; break;
    case RuleSourceTypeFile: dict[@"type"] = @"file"; break;
    default: dict[@"type"] = @"unknown"; break;
  }
  if (self.configuration) {
    dict[@"configuration"] = self.configuration;
  }

  return dict;
}

@end

#pragma mark - CacheConfiguration

@implementation CacheConfiguration

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    NSArray* paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    _cacheDirectory = [paths[0] stringByAppendingPathComponent:@"DNShield"];
    _maxCacheSize = 100 * 1024 * 1024;       // 100MB
    _defaultTTL = 86400;                     // 24 hours
    _maxMemoryCacheSize = 10 * 1024 * 1024;  // 10MB
    _persistCache = YES;
    _cleanupInterval = 3600;  // 1 hour
  }
  return self;
}

+ (instancetype)defaultCacheConfiguration {
  return [[CacheConfiguration alloc] init];
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.cacheDirectory forKey:@"cacheDirectory"];
  [coder encodeInteger:self.maxCacheSize forKey:@"maxCacheSize"];
  [coder encodeDouble:self.defaultTTL forKey:@"defaultTTL"];
  [coder encodeInteger:self.maxMemoryCacheSize forKey:@"maxMemoryCacheSize"];
  [coder encodeBool:self.persistCache forKey:@"persistCache"];
  [coder encodeDouble:self.cleanupInterval forKey:@"cleanupInterval"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _cacheDirectory = [coder decodeObjectOfClass:[NSString class] forKey:@"cacheDirectory"];
    _maxCacheSize = [coder decodeIntegerForKey:@"maxCacheSize"];
    _defaultTTL = [coder decodeDoubleForKey:@"defaultTTL"];
    _maxMemoryCacheSize = [coder decodeIntegerForKey:@"maxMemoryCacheSize"];
    _persistCache = [coder decodeBoolForKey:@"persistCache"];
    _cleanupInterval = [coder decodeDoubleForKey:@"cleanupInterval"];
  }
  return self;
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  CacheConfiguration* copy = [[CacheConfiguration allocWithZone:zone] init];
  copy.cacheDirectory = [self.cacheDirectory copyWithZone:zone];
  copy.maxCacheSize = self.maxCacheSize;
  copy.defaultTTL = self.defaultTTL;
  copy.maxMemoryCacheSize = self.maxMemoryCacheSize;
  copy.persistCache = self.persistCache;
  copy.cleanupInterval = self.cleanupInterval;
  return copy;
}

@end

#pragma mark - UpdateConfiguration

@implementation UpdateConfiguration

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _strategy = UpdateStrategyInterval;
    _interval = 300;  // 5 minutes default (same as ManifestUpdateInterval)
    _scheduledTimes = @[];
    _maxRetries = 3;
    _retryDelay = 30;
    _updateOnStart = YES;
    _updateOnNetworkChange = YES;
  }
  return self;
}

+ (instancetype)defaultUpdateConfiguration {
  return [[UpdateConfiguration alloc] init];
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeInteger:self.strategy forKey:@"strategy"];
  [coder encodeDouble:self.interval forKey:@"interval"];
  [coder encodeObject:self.scheduledTimes forKey:@"scheduledTimes"];
  [coder encodeInteger:self.maxRetries forKey:@"maxRetries"];
  [coder encodeDouble:self.retryDelay forKey:@"retryDelay"];
  [coder encodeBool:self.updateOnStart forKey:@"updateOnStart"];
  [coder encodeBool:self.updateOnNetworkChange forKey:@"updateOnNetworkChange"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _strategy = [coder decodeIntegerForKey:@"strategy"];
    _interval = [coder decodeDoubleForKey:@"interval"];
    _scheduledTimes =
        [coder decodeObjectOfClasses:[NSSet setWithArray:@[ [NSArray class], [NSString class] ]]
                              forKey:@"scheduledTimes"]
            ?: @[];
    _maxRetries = [coder decodeIntegerForKey:@"maxRetries"];
    _retryDelay = [coder decodeDoubleForKey:@"retryDelay"];
    _updateOnStart = [coder decodeBoolForKey:@"updateOnStart"];
    _updateOnNetworkChange = [coder decodeBoolForKey:@"updateOnNetworkChange"];
  }
  return self;
}

@end

#pragma mark - ConfigurationManager

@interface ConfigurationManager ()
@property(nonatomic, strong) DNSConfiguration* currentConfiguration;
@property(nonatomic, strong) NSHashTable* observers;
@property(nonatomic, strong) dispatch_queue_t configQueue;
@property(nonatomic, assign, readwrite) BOOL isUsingManifest;
@property(nonatomic, strong, readwrite) NSString* currentManifestIdentifier;
@end

@implementation ConfigurationManager

+ (instancetype)sharedManager {
  static ConfigurationManager* sharedManager = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedManager = [[ConfigurationManager alloc] init];
  });
  return sharedManager;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _configQueue = dispatch_queue_create("com.dnshield.config", DISPATCH_QUEUE_SERIAL);
    _observers = [NSHashTable weakObjectsHashTable];
    [self loadConfiguration];
  }
  return self;
}

- (void)loadConfiguration {
  dispatch_sync(self.configQueue, ^{
    PreferenceManager* prefManager = [PreferenceManager sharedManager];

    // Check if configuration is managed by MDM (highest priority)
    BOOL isManaged = [prefManager isPreferenceManagedForKey:kDNShieldConfigurationArchiveKey
                                                   inDomain:kDNShieldPreferenceDomain];

    NSData* configData = [prefManager preferenceValueForKey:kDNShieldConfigurationArchiveKey
                                                   inDomain:kDNShieldPreferenceDomain];

    if (configData && [configData isKindOfClass:[NSData class]]) {
      NSError* error = nil;
      DNSConfiguration* config = [NSKeyedUnarchiver unarchivedObjectOfClass:[DNSConfiguration class]
                                                                   fromData:configData
                                                                      error:&error];
      if (config && !error) {
        if (isManaged) {
          config.isManagedByProfile = YES;
          config.allowRuleEditing = NO;  // no editing for MDM configs
        }
        self.currentConfiguration = config;
        os_log_info(logHandle, "Loaded configuration from preferences (managed: %d)", isManaged);
        return;
      }
    }

    // Check system preferences if NOT managed by MDM
    if (!isManaged) {  // Check if ManagedMode is set in system preferences
      CFPropertyListRef managedModePref =
          CFPreferencesCopyValue(CFSTR("ManagedMode"), DNPreferenceDomainCF(),
                                 kCFPreferencesAnyUser, kCFPreferencesCurrentHost);
      BOOL isManagedByPrefs = (managedModePref != NULL);
      if (managedModePref) {
        CFRelease(managedModePref);
      }

      if (isManagedByPrefs) {
        // Load configuration from preferences
        DNSConfiguration* config = [[DNSConfiguration alloc] init];
        config.isManagedByProfile = YES;

        // Load other preferences from managed preference domain
        NSDictionary* prefs = CFBridgingRelease(CFPreferencesCopyMultiple(
            NULL, DNPreferenceDomainCF(), kCFPreferencesAnyUser, kCFPreferencesCurrentHost));
        if (prefs) {
          // Apply preferences to config
          if (prefs[@"EnableWebSocketServer"]) {
            config.webSocketEnabled = [prefs[@"EnableWebSocketServer"] boolValue];
          }
          if (prefs[@"WebSocketPort"]) {
            config.webSocketPort = [prefs[@"WebSocketPort"] intValue];
          }
          if (prefs[@"WebSocketAuthToken"]) {
            config.webSocketAuthToken = prefs[@"WebSocketAuthToken"];
          }
          if (prefs[@"ManifestURL"]) {
            config.manifestURL = prefs[@"ManifestURL"];
          }
          if (prefs[@"ManifestUpdateInterval"]) {
            config.manifestUpdateInterval = [prefs[@"ManifestUpdateInterval"] intValue];
          }
          if (prefs[@"TelemetryEnabled"]) {
            config.telemetryEnabled = [prefs[@"TelemetryEnabled"] boolValue];
          }
          if (prefs[@"TelemetryServerURL"]) {
            config.telemetryServerURL = prefs[@"TelemetryServerURL"];
          }
          if (prefs[@"TelemetryHECToken"]) {
            config.telemetryHECToken = prefs[@"TelemetryHECToken"];
          }
          if (prefs[@"AdditionalHttpHeaders"]) {
            config.additionalHttpHeaders = prefs[@"AdditionalHttpHeaders"];
          }
          if (prefs[@"EnableDNSChainPreservation"]) {
            config.enableDNSChainPreservation = [prefs[@"EnableDNSChainPreservation"] boolValue];
          }
          if (prefs[@"VPNResolvers"]) {
            config.vpnResolvers = prefs[@"VPNResolvers"];
          }
        }

        if (config.allowRuleEditing != NO) {
          config.allowRuleEditing = NO;  // Default to NO for managed configs
        }
        self.currentConfiguration = config;
        os_log_info(logHandle,
                    "Loaded managed configuration from preferences - isManagedByProfile: %d, "
                    "allowRuleEditing: %d",
                    config.isManagedByProfile, config.allowRuleEditing);
        return;
      }
    }

    // Load from legacy format
    NSArray* ruleSources = [prefManager preferenceValueForKey:kDNShieldRuleSources
                                                     inDomain:kDNShieldPreferenceDomain];
    if (ruleSources && [ruleSources isKindOfClass:[NSArray class]]) {
      DNSConfiguration* config = [[DNSConfiguration alloc] init];
      NSMutableArray* sources = [NSMutableArray array];

      for (NSDictionary* sourceDict in ruleSources) {
        RuleSource* source = [RuleSource sourceFromDictionary:sourceDict];
        if (source) {
          [sources addObject:source];
        }
      }

      config.ruleSources = sources;
      self.currentConfiguration = config;
      os_log_info(logHandle, "Loaded configuration from legacy format");
      return;
    }

    // Use default configuration
    self.currentConfiguration = [DNSConfiguration defaultConfiguration];
    os_log_info(logHandle, "Using default configuration");
  });
}

- (BOOL)saveConfiguration:(DNSConfiguration*)configuration error:(NSError**)error {
  if (![self validateConfiguration:configuration error:error]) {
    return NO;
  }

  __block BOOL success = NO;
  __block NSError* saveError = nil;

  dispatch_sync(self.configQueue, ^{
    NSError* archiveError = nil;
    NSData* configData = [NSKeyedArchiver archivedDataWithRootObject:configuration
                                               requiringSecureCoding:YES
                                                               error:&archiveError];

    if (!configData || archiveError) {
      saveError =
          archiveError
              ?: [NSError errorWithDomain:DNSConfigurationErrorDomain
                                     code:DNSConfigurationErrorSaveFailed
                                 userInfo:@{
                                   NSLocalizedDescriptionKey : @"Failed to archive configuration"
                                 }];
      return;
    }

    // Save to preferences
    CFPreferencesSetValue((__bridge CFStringRef)kDNShieldConfigurationArchiveKey,
                          (__bridge CFPropertyListRef)configData,
                          (__bridge CFStringRef)kDNShieldPreferenceDomain,
                          kCFPreferencesCurrentUser, kCFPreferencesAnyHost);

    DNPreferenceDomainSynchronize(kDNShieldPreferenceDomain);

    self.currentConfiguration = configuration;
    success = YES;

    os_log_info(logHandle, "Saved configuration to preferences");
  });

  if (success) {
    [self notifyConfigurationChange:@"save"];
  } else if (error) {
    *error = saveError;
  }

  return success;
}

- (nullable DNSConfiguration*)loadConfigurationFromFile:(NSString*)path error:(NSError**)error {
  NSData* data = [NSData dataWithContentsOfFile:path];
  if (!data) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSConfigurationErrorDomain
                     code:DNSConfigurationErrorInvalid
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to read configuration file"}];
    }
    return nil;
  }

  // Try JSON format
  NSError* jsonError = nil;
  NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
  if (json) {
    return [self configurationFromJSON:json];
  }

  // Try archived format
  NSError* archiveError = nil;
  DNSConfiguration* config = [NSKeyedUnarchiver unarchivedObjectOfClass:[DNSConfiguration class]
                                                               fromData:data
                                                                  error:&archiveError];
  if (config) {
    return config;
  }

  if (error) {
    *error = [NSError
        errorWithDomain:DNSConfigurationErrorDomain
                   code:DNSConfigurationErrorInvalid
               userInfo:@{NSLocalizedDescriptionKey : @"Unsupported configuration format"}];
  }

  return nil;
}

- (DNSConfiguration*)configurationFromJSON:(NSDictionary*)json {
  DNSConfiguration* config = [[DNSConfiguration alloc] init];

  // Parse rule sources
  NSArray* sources = json[@"ruleSources"];
  if ([sources isKindOfClass:[NSArray class]]) {
    NSMutableArray* ruleSources = [NSMutableArray array];
    for (NSDictionary* sourceDict in sources) {
      RuleSource* source = [RuleSource sourceFromDictionary:sourceDict];
      if (source) {
        [ruleSources addObject:source];
      }
    }
    config.ruleSources = ruleSources;
  }

  // Parse DNS servers
  NSArray* dnsServers = json[@"dnsServers"];
  if ([dnsServers isKindOfClass:[NSArray class]]) {
    config.upstreamDNSServers = dnsServers;
  }

  // Parse other settings
  if (json[@"dnsTimeout"]) {
    config.dnsTimeout = [json[@"dnsTimeout"] doubleValue];
  }

  config.offlineMode = [json[@"offlineMode"] boolValue];
  config.debugLogging = [json[@"debugLogging"] boolValue];

  if (json[@"logLevel"]) {
    config.logLevel = json[@"logLevel"];
  }

  // Parse managed mode settings
  config.isManagedByProfile = [json[@"isManagedByProfile"] boolValue];
  if (json[@"allowRuleEditing"] != nil) {
    config.allowRuleEditing = [json[@"allowRuleEditing"] boolValue];
  } else {
    // Default to NO if managed, YES if not managed
    config.allowRuleEditing = !config.isManagedByProfile;
  }

  return config;
}

- (BOOL)validateConfiguration:(DNSConfiguration*)configuration error:(NSError**)error {
  return [configuration isValid:error];
}

- (nullable RuleSource*)ruleSourceWithIdentifier:(NSString*)identifier {
  for (RuleSource* source in self.currentConfiguration.ruleSources) {
    if ([source.identifier isEqualToString:identifier]) {
      return source;
    }
  }
  return nil;
}

#pragma mark - Observers

- (void)addConfigurationObserver:(id)observer selector:(SEL)selector {
  dispatch_sync(self.configQueue, ^{
    [self.observers addObject:observer];
  });
}

- (void)removeConfigurationObserver:(id)observer {
  dispatch_sync(self.configQueue, ^{
    [self.observers removeObject:observer];
  });
}

- (void)notifyConfigurationChange:(NSString*)reason {
  dispatch_async(dispatch_get_main_queue(), ^{
    [[NSNotificationCenter defaultCenter]
        postNotificationName:DNSConfigurationDidChangeNotification
                      object:self
                    userInfo:@{DNSConfigurationChangeReasonKey : reason}];

    // Call selectors on observers
    NSArray* observersCopy = [self.observers allObjects];
    for (id observer in observersCopy) {
      if ([observer respondsToSelector:@selector(configurationDidChange:)]) {
        [observer performSelector:@selector(configurationDidChange:) withObject:self];
      }
    }
  });
}

#pragma mark - Manifest Support

- (BOOL)shouldUseManifest {
  NSString* useManifest =
      [[PreferenceManager sharedManager] preferenceValueForKey:@"useManifest"
                                                      inDomain:kDNShieldPreferenceDomain];
  // Default to YES if not set, or if explicitly set to YES
  return !useManifest || [useManifest isEqualToString:@"YES"];
}

- (void)setManifestIdentifier:(NSString*)identifier {
  self.currentManifestIdentifier = identifier;
  self.isUsingManifest = YES;
  // Note: PreferenceManager is read-only in the extension context
  // These values would need to be set through MDM or the main app
  [self notifyConfigurationChange:@"ManifestIdentifierChanged"];
}

- (nullable NSDictionary*)exportConfigurationAsManifest {
  if (!self.currentConfiguration) {
    return nil;
  }

  NSMutableDictionary* manifest = [NSMutableDictionary dictionary];

  // Manifest metadata
  manifest[@"manifest_version"] = @"1.0";
  manifest[@"identifier"] = @"converted-config";
  manifest[@"display_name"] = @"Converted Configuration";

  // Convert rule sources
  NSMutableArray* ruleSources = [NSMutableArray array];
  for (RuleSource* source in self.currentConfiguration.ruleSources) {
    [ruleSources addObject:[source toDictionary]];
  }
  if (ruleSources.count > 0) {
    manifest[@"rule_sources"] = ruleSources;
  }

  // Add metadata
  manifest[@"metadata"] = @{
    @"description" : @"Automatically converted from DNShield configuration",
    @"last_modified" : [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                      dateStyle:NSDateFormatterShortStyle
                                                      timeStyle:NSDateFormatterShortStyle],
    @"author" : @"DNShield Configuration Manager"
  };

  return manifest;
}

- (nullable DNSConfiguration*)configurationFromResolvedManifest:
    (DNSResolvedManifest*)resolvedManifest {
  if (!resolvedManifest) {
    return nil;
  }

  DNSConfiguration* config = [[DNSConfiguration alloc] init];

  // Convert rule sources from the resolved manifest
  config.ruleSources = resolvedManifest.resolvedRuleSources ?: @[];

  // Process managed rules from the manifest
  if (resolvedManifest.resolvedManagedRules) {
    [[LoggingManager sharedManager]
          logEvent:@"ProcessingManagedRules"
          category:LogCategoryConfiguration
             level:LogLevelInfo
        attributes:@{@"ruleCount" : @(resolvedManifest.resolvedManagedRules.count)}];

    // Import managed rules into the database
    [self importManagedRules:resolvedManifest.resolvedManagedRules];
  }

  // Inherit settings from the current configuration, but ensure managed status is correctly set
  if (self.currentConfiguration) {
    config.cacheConfig = self.currentConfiguration.cacheConfig;
    config.updateConfig = self.currentConfiguration.updateConfig;
    config.upstreamDNSServers = self.currentConfiguration.upstreamDNSServers;
    config.dnsTimeout = self.currentConfiguration.dnsTimeout;
    config.offlineMode = self.currentConfiguration.offlineMode;
    config.debugLogging = self.currentConfiguration.debugLogging;
    config.logLevel = self.currentConfiguration.logLevel;
  }

  // When a manifest is used, it is always considered managed, and rule editing should be disabled.
  config.isManagedByProfile = YES;
  config.allowRuleEditing = NO;

  self.isUsingManifest = YES;
  self.currentManifestIdentifier = resolvedManifest.primaryManifest.identifier;

  os_log_info(logHandle, "Created configuration from manifest '%{public}@', rule editing disabled.",
              self.currentManifestIdentifier);

  return config;
}

- (void)importManagedRules:(NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules {
  RuleDatabase* database = [RuleDatabase sharedDatabase];
  NSDate* now = [NSDate date];
  NSInteger importedCount = 0;
  NSInteger failedCount = 0;

  [[LoggingManager sharedManager] logEvent:@"StartingManagedRuleImport"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{@"totalCategories" : @(managedRules.count)}];

  // First, remove all existing managed rules to ensure clean state
  NSError* cleanupError = nil;
  if (![database removeAllRulesFromSource:DNSRuleSourceManifest error:&cleanupError]) {
    [[LoggingManager sharedManager] logError:cleanupError
                                    category:LogCategoryConfiguration
                                     context:@"Failed to cleanup old managed rules"];
  }

  // Batch rule insertion to avoid many thousands (potentially) of individual transactions
  // Build arrays of rules to insert in batches
  NSMutableArray<DNSRule*>* rulesToInsert = [NSMutableArray array];
  const NSInteger BATCH_SIZE = 1000;  // Batches of 1000 rules

  // Process block rules
  NSArray* blockedDomains = managedRules[@"block"];
  if (blockedDomains) {
    [[LoggingManager sharedManager] logEvent:@"ImportingBlockRules"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:@{@"count" : @(blockedDomains.count)}];

    for (NSString* domain in blockedDomains) {
      DNSRule* rule = [DNSRule ruleWithDomain:domain action:DNSRuleActionBlock];
      rule.source = DNSRuleSourceManifest;
      rule.type = [self determineRuleType:domain];
      rule.priority = 90;  // Slightly lower than user rules (100)
      rule.updatedAt = now;
      rule.comment = @"Managed rule from manifest";

      [rulesToInsert addObject:rule];

      // Insert batch when we reach the batch size
      if (rulesToInsert.count >= BATCH_SIZE) {
        NSError* error = nil;
        if ([database addRules:rulesToInsert error:&error]) {
          importedCount += rulesToInsert.count;
        } else {
          failedCount += rulesToInsert.count;
          [[LoggingManager sharedManager] logError:error
                                          category:LogCategoryConfiguration
                                           context:@"Failed to add batch of block rules"];
        }
        [rulesToInsert removeAllObjects];
      }
    }
  }

  // Process allow rules
  NSArray* allowedDomains = managedRules[@"allow"];
  if (allowedDomains) {
    [[LoggingManager sharedManager] logEvent:@"ImportingAllowRules"
                                    category:LogCategoryConfiguration
                                       level:LogLevelInfo
                                  attributes:@{@"count" : @(allowedDomains.count)}];

    for (NSString* domain in allowedDomains) {
      DNSRule* rule = [DNSRule ruleWithDomain:domain action:DNSRuleActionAllow];
      rule.source = DNSRuleSourceManifest;
      rule.type = [self determineRuleType:domain];
      rule.priority = 110;  // Higher priority than block rules
      rule.updatedAt = now;
      rule.comment = @"Managed rule from manifest";

      [rulesToInsert addObject:rule];

      // Insert batch when we reach the batch size
      if (rulesToInsert.count >= BATCH_SIZE) {
        NSError* error = nil;
        if ([database addRules:rulesToInsert error:&error]) {
          importedCount += rulesToInsert.count;
        } else {
          failedCount += rulesToInsert.count;
          [[LoggingManager sharedManager] logError:error
                                          category:LogCategoryConfiguration
                                           context:@"Failed to add batch of allow rules"];
        }
        [rulesToInsert removeAllObjects];
      }
    }
  }

  // Insert any remaining rules
  if (rulesToInsert.count > 0) {
    NSError* error = nil;
    if ([database addRules:rulesToInsert error:&error]) {
      importedCount += rulesToInsert.count;
    } else {
      failedCount += rulesToInsert.count;
      [[LoggingManager sharedManager] logError:error
                                      category:LogCategoryConfiguration
                                       context:@"Failed to add final batch of rules"];
    }
  }

  [[LoggingManager sharedManager] logEvent:@"ManagedRuleImportCompleted"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{
                                  @"imported" : @(importedCount),
                                  @"failed" : @(failedCount),
                                  @"totalProcessed" : @(importedCount + failedCount)
                                }];
}

- (DNSRuleType)determineRuleType:(NSString*)domain {
  if ([domain hasPrefix:@"*."]) {
    return DNSRuleTypeWildcard;
  } else if ([domain containsString:@"*"]) {
    return DNSRuleTypeRegex;  // Use regex for pattern matching
  } else {
    return DNSRuleTypeExact;
  }
}

@end
