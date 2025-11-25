//
//  DNSManifestResolver.m
//  DNShield Network Extension
//

#import "DNSManifestResolver.h"
#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <IOKit/IOKitLib.h>
#import <sys/utsname.h>
#import "ConfigurationManager.h"
#import "DNSManifest.h"
#import "DNSManifestParser.h"
#import "DNSPredicateEvaluator.h"
#import "HTTPRuleFetcher.h"
#import "PreferenceManager.h"

// DNSResolvedManifest is implemented in DNSManifest.m

#pragma mark - Evaluation Context

@implementation DNSEvaluationContext

- (instancetype)init {
  if (self = [super init]) {
    _customProperties = [NSMutableDictionary dictionary];
    [self updateSystemProperties];
    [self updateTimeProperties];
  }
  return self;
}

// Note: cache directory injection belongs to DNSManifestResolver, not the evaluation context

+ (instancetype)defaultContext {
  return [[self alloc] init];
}

- (void)updateSystemProperties {
  // OS Version
  _osVersion = [[NSProcessInfo processInfo] operatingSystemVersionString];

  // Device type and model
  struct utsname systemInfo;
  uname(&systemInfo);
  _deviceModel = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];

  // Simplified device type detection
  if ([_deviceModel containsString:@"MacBook"]) {
    _deviceType = @"laptop";
  } else if ([_deviceModel containsString:@"iMac"] || [_deviceModel containsString:@"Mac"]) {
    _deviceType = @"desktop";
  } else {
    _deviceType = @"unknown";
  }
}

- (void)updateTimeProperties {
  _currentDate = [NSDate date];

  NSDateFormatter* timeFormatter = [[NSDateFormatter alloc] init];
  timeFormatter.dateFormat = @"HH:mm";
  _timeOfDay = [timeFormatter stringFromDate:_currentDate];

  NSDateFormatter* dayFormatter = [[NSDateFormatter alloc] init];
  dayFormatter.dateFormat = @"EEEE";
  _dayOfWeek = [dayFormatter stringFromDate:_currentDate];

  NSCalendar* calendar = [NSCalendar currentCalendar];
  NSDateComponents* components = [calendar components:NSCalendarUnitWeekday fromDate:_currentDate];
  _isWeekend = (components.weekday == 1 || components.weekday == 7);  // Sunday = 1, Saturday = 7
}

- (NSDictionary*)allProperties {
  NSMutableDictionary* properties = [NSMutableDictionary dictionary];

  // System properties
  if (_osVersion)
    properties[@"os_version"] = _osVersion;
  if (_deviceType)
    properties[@"device_type"] = _deviceType;
  if (_deviceModel)
    properties[@"device_model"] = _deviceModel;

  // Network properties
  if (_networkLocation)
    properties[@"network_location"] = _networkLocation;
  if (_networkSSID)
    properties[@"network_ssid"] = _networkSSID;
  properties[@"vpn_connected"] = @(_vpnConnected);
  if (_vpnIdentifier)
    properties[@"vpn_identifier"] = _vpnIdentifier;

  // Time properties
  if (_timeOfDay)
    properties[@"time_of_day"] = _timeOfDay;
  if (_dayOfWeek)
    properties[@"day_of_week"] = _dayOfWeek;
  properties[@"is_weekend"] = @(_isWeekend);

  // Current date in YYYY-MM-DD format for condition evaluation
  if (_currentDate) {
    NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
    dateFormatter.dateFormat = @"yyyy-MM-dd";
    properties[@"current_date"] = [dateFormatter stringFromDate:_currentDate];
  }

  // User/device properties
  if (_userGroup)
    properties[@"user_group"] = _userGroup;
  if (_deviceIdentifier)
    properties[@"device_identifier"] = _deviceIdentifier;
  if (_securityScore)
    properties[@"security_score"] = _securityScore;

  // Custom properties
  [properties addEntriesFromDictionary:_customProperties];

  return properties;
}

- (void)setCustomProperty:(id)value forKey:(NSString*)key {
  if (value && key) {
    _customProperties[key] = value;
  }
}

@end

#pragma mark - Manifest Cache

@interface DNSManifestCache ()
@property(nonatomic, strong)
    NSMutableDictionary<NSString*, NSString*>* manifestPaths;  // identifier -> file path
@property(nonatomic, strong) NSString* cacheDirectory;
@property(nonatomic, assign) NSTimeInterval timeout;
@end

// Forward declaration of helper function
static id DNS_SanitizeForPlist(id object);

@implementation DNSManifestCache

- (instancetype)init {
  if (self = [super init]) {
    _manifestPaths = [NSMutableDictionary dictionary];
    _timeout = 1800;  // 30 minutes (longer than Munki's for network transitions)

    // Use the same cache directory as the existing system
    _cacheDirectory = @"/Library/Application Support/DNShield/manifest_cache";

    NSError* error;
    if (![[NSFileManager defaultManager] fileExistsAtPath:_cacheDirectory]) {
      [[NSFileManager defaultManager] createDirectoryAtPath:_cacheDirectory
                                withIntermediateDirectories:YES
                                                 attributes:nil
                                                      error:&error];
      if (error) {
        [[LoggingManager sharedManager] logError:error
                                        category:LogCategoryRuleFetching
                                         context:@"Failed to create manifest cache directory"];
      }
    }

    // Load existing cached manifests on startup
    [self loadCachedManifests];
  }
  return self;
}

- (void)loadCachedManifests {
  [self loadCachedManifestsInDirectory:_cacheDirectory withPrefix:@""];
}

- (void)loadCachedManifestsInDirectory:(NSString*)directory withPrefix:(NSString*)prefix {
  NSError* error;
  NSArray* items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory
                                                                       error:&error];
  if (error) {
    [[LoggingManager sharedManager]
        logError:error
        category:LogCategoryRuleFetching
         context:[NSString
                     stringWithFormat:@"Failed to load cached manifests from: %@", directory]];
    return;
  }

  for (NSString* item in items) {
    NSString* itemPath = [directory stringByAppendingPathComponent:item];
    BOOL isDirectory;

    if ([[NSFileManager defaultManager] fileExistsAtPath:itemPath isDirectory:&isDirectory]) {
      if (isDirectory) {
        // Recursively load manifests from subdirectories (includes/global/, includes/team/, etc.)
        NSString* newPrefix =
            prefix.length > 0 ? [NSString stringWithFormat:@"%@/%@", prefix, item] : item;
        [self loadCachedManifestsInDirectory:itemPath withPrefix:newPrefix];
      } else {
        // Load individual manifest file (no extension check needed)
        NSString* identifier;
        if (prefix.length > 0) {
          // Nested manifest: includes/global/ai -> includes/global/ai
          identifier = [NSString stringWithFormat:@"%@/%@", prefix, item];
        } else {
          // Root manifest: C02ABC1234 -> C02ABC1234
          identifier = item;
        }

        // Check if file is still valid (within timeout period)
        NSDictionary* attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:itemPath
                                                                                    error:nil];
        NSDate* modDate = attributes[NSFileModificationDate];
        BOOL isExpired = NO;
        if (modDate) {
          NSTimeInterval age = [[NSDate date] timeIntervalSinceDate:modDate];
          isExpired = age > _timeout;
        }

        _manifestPaths[identifier] = itemPath;

        if (isExpired) {
          [[LoggingManager sharedManager]
                logEvent:@"LoadedExpiredCachedManifest"
                category:LogCategoryRuleFetching
                   level:LogLevelInfo
              attributes:@{@"identifier" : identifier, @"path" : itemPath}];
        } else {
          [[LoggingManager sharedManager]
                logEvent:@"LoadedCachedManifest"
                category:LogCategoryRuleFetching
                   level:LogLevelInfo
              attributes:@{@"identifier" : identifier, @"path" : itemPath}];
        }
      }
    }
  }
}

- (NSString*)cacheFilePathForIdentifier:(NSString*)identifier {
  // Match existing system format: no extensions, proper directory structure
  // Root: C02ABC1234 -> /Library/Application Support/DNShield/manifest_cache/C02ABC1234
  // Includes: includes/global/ai -> /Library/Application
  // Support/DNShield/manifest_cache/includes/global/ai
  return [_cacheDirectory stringByAppendingPathComponent:identifier];
}

- (DNSManifest*)manifestForIdentifier:(NSString*)identifier {
  BOOL ignoredExpiredFlag = NO;
  return [self manifestForIdentifier:identifier allowExpired:NO wasExpired:&ignoredExpiredFlag];
}

- (DNSManifest*)manifestForIdentifier:(NSString*)identifier
                         allowExpired:(BOOL)allowExpired
                           wasExpired:(BOOL*)wasExpired {
  NSString* cachedPath = _manifestPaths[identifier];
  if (!cachedPath || ![[NSFileManager defaultManager] fileExistsAtPath:cachedPath]) {
    // Remove stale entry
    [_manifestPaths removeObjectForKey:identifier];
    return nil;
  }

  // Check if cache file is still valid
  NSDictionary* attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:cachedPath
                                                                              error:nil];
  NSDate* modDate = attributes[NSFileModificationDate];

  BOOL expired = YES;
  if (modDate) {
    expired = [[NSDate date] timeIntervalSinceDate:modDate] > _timeout;
  }

  if (wasExpired) {
    *wasExpired = expired;
  }

  if (expired && !allowExpired) {
    [[LoggingManager sharedManager]
          logEvent:@"CacheEntryExpired"
          category:LogCategoryRuleFetching
             level:LogLevelDebug
        attributes:@{@"identifier" : identifier ?: @"unknown", @"path" : cachedPath ?: @"unknown"}];
    return nil;
  }

  // Load manifest from disk
  NSError* error;
  NSData* data = [NSData dataWithContentsOfFile:cachedPath options:0 error:&error];
  if (!data) {
    [[LoggingManager sharedManager]
        logError:error
        category:LogCategoryRuleFetching
         context:[NSString stringWithFormat:@"Failed to read cached manifest: %@", identifier]];
    [_manifestPaths removeObjectForKey:identifier];
    return nil;
  }

  NSDictionary* plistDict = [NSPropertyListSerialization propertyListWithData:data
                                                                      options:0
                                                                       format:nil
                                                                        error:&error];
  if (!plistDict) {
    [[LoggingManager sharedManager]
        logError:error
        category:LogCategoryRuleFetching
         context:[NSString stringWithFormat:@"Failed to parse cached manifest: %@", identifier]];
    // Remove corrupted cache file
    [[NSFileManager defaultManager] removeItemAtPath:cachedPath error:nil];
    [_manifestPaths removeObjectForKey:identifier];
    return nil;
  }

  DNSManifest* manifest = [[DNSManifest alloc] initWithDictionary:plistDict error:&error];
  if (!manifest) {
    [[LoggingManager sharedManager]
        logError:error
        category:LogCategoryRuleFetching
         context:[NSString
                     stringWithFormat:@"Failed to create manifest from cache: %@", identifier]];
    // Remove corrupted cache file
    [[NSFileManager defaultManager] removeItemAtPath:cachedPath error:nil];
    [_manifestPaths removeObjectForKey:identifier];
    return nil;
  }

  if (expired && allowExpired) {
    [[LoggingManager sharedManager]
          logEvent:@"UsingExpiredCachedManifest"
          category:LogCategoryRuleFetching
             level:LogLevelInfo
        attributes:@{@"identifier" : identifier ?: @"unknown", @"path" : cachedPath ?: @"unknown"}];
  }

  return manifest;
}

- (void)cacheManifest:(DNSManifest*)manifest forIdentifier:(NSString*)identifier {
  if (!manifest || !identifier) {
    [[LoggingManager sharedManager] logEvent:@"CacheManifestSkipped"
                                    category:LogCategoryRuleFetching
                                       level:LogLevelError
                                  attributes:@{
                                    @"reason" : @"nil manifest or identifier",
                                    @"manifest" : manifest ? @"exists" : @"nil",
                                    @"identifier" : identifier ?: @"nil"
                                  }];
    return;
  }

  [[LoggingManager sharedManager] logEvent:@"CachingManifest"
                                  category:LogCategoryRuleFetching
                                     level:LogLevelInfo
                                attributes:@{@"identifier" : identifier}];

  // Cache the manifest itself
  [self cacheManifestToDisk:manifest forIdentifier:identifier];

  // Note: Recursive caching of included manifests will be handled by the resolver
  // when it processes each included manifest during resolution
}

- (void)cacheManifestToDisk:(DNSManifest*)manifest forIdentifier:(NSString*)identifier {
  NSString* cachePath = [self cacheFilePathForIdentifier:identifier];

  [[LoggingManager sharedManager] logEvent:@"CacheManifestToDisk_Start"
                                  category:LogCategoryRuleFetching
                                     level:LogLevelInfo
                                attributes:@{
                                  @"identifier" : identifier,
                                  @"cachePath" : cachePath,
                                  @"cacheDirectory" : _cacheDirectory ?: @"nil"
                                }];

  // Create directory structure for nested includes (e.g., includes/global/, includes/team/)
  NSString* cacheDir = [cachePath stringByDeletingLastPathComponent];
  NSError* dirError;
  BOOL dirExists = [[NSFileManager defaultManager] fileExistsAtPath:cacheDir];

  [[LoggingManager sharedManager]
        logEvent:@"CacheDirectory_Check"
        category:LogCategoryRuleFetching
           level:LogLevelInfo
      attributes:@{@"directory" : cacheDir, @"exists" : dirExists ? @"YES" : @"NO"}];

  if (!dirExists) {
    [[NSFileManager defaultManager] createDirectoryAtPath:cacheDir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:&dirError];
    if (dirError) {
      [[LoggingManager sharedManager]
          logError:dirError
          category:LogCategoryRuleFetching
           context:[NSString
                       stringWithFormat:@"Failed to create cache directory for: %@", identifier]];
      return;
    }
    [[LoggingManager sharedManager] logEvent:@"CacheDirectory_Created"
                                    category:LogCategoryRuleFetching
                                       level:LogLevelInfo
                                  attributes:@{@"directory" : cacheDir}];
  }

  // Convert manifest to dictionary for serialization
  NSDictionary* manifestDict = [manifest toDictionary];
  if (!manifestDict) {
    [[LoggingManager sharedManager] logEvent:@"ManifestSerializationFailed"
                                    category:LogCategoryRuleFetching
                                       level:LogLevelError
                                  attributes:@{@"identifier" : identifier}];
    return;
  }

  // Sanitize the dictionary to remove NSNull values that can't be serialized to plist
  manifestDict = DNS_SanitizeForPlist(manifestDict);

  [[LoggingManager sharedManager]
        logEvent:@"ManifestSerialized"
        category:LogCategoryRuleFetching
           level:LogLevelInfo
      attributes:@{@"identifier" : identifier, @"dictKeys" : @(manifestDict.allKeys.count)}];

  NSError* error;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:manifestDict
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&error];
  if (!plistData) {
    [[LoggingManager sharedManager]
        logError:error
        category:LogCategoryRuleFetching
         context:[NSString stringWithFormat:@"Failed to serialize manifest: %@", identifier]];
    return;
  }

  // Write to disk with proper directory structure
  [[LoggingManager sharedManager] logEvent:@"AttemptingFileWrite"
                                  category:LogCategoryRuleFetching
                                     level:LogLevelInfo
                                attributes:@{
                                  @"identifier" : identifier,
                                  @"path" : cachePath,
                                  @"dataSize" : @(plistData.length)
                                }];

  BOOL writeSuccess = [plistData writeToFile:cachePath options:NSDataWritingAtomic error:&error];

  if (writeSuccess) {
    _manifestPaths[identifier] = cachePath;

    // Verify the file was actually written
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:cachePath];
    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:cachePath
                                                                           error:nil];

    [[LoggingManager sharedManager] logEvent:@"ManifestCachedToDisk"
                                    category:LogCategoryRuleFetching
                                       level:LogLevelInfo
                                  attributes:@{
                                    @"identifier" : identifier,
                                    @"path" : cachePath,
                                    @"fileExists" : fileExists ? @"YES" : @"NO",
                                    @"fileSize" : attrs[NSFileSize] ?: @"unknown"
                                  }];
  } else {
    [[LoggingManager sharedManager]
        logError:error
        category:LogCategoryRuleFetching
         context:[NSString
                     stringWithFormat:@"Failed to write cached manifest: %@ to path: %@. Error: %@",
                                      identifier, cachePath, error.localizedDescription]];
  }
}

- (void)removeManifestForIdentifier:(NSString*)identifier {
  NSString* cachedPath = _manifestPaths[identifier];
  if (cachedPath) {
    [[NSFileManager defaultManager] removeItemAtPath:cachedPath error:nil];
    [_manifestPaths removeObjectForKey:identifier];
  }
}

- (void)removeAllManifests {
  // Remove all cached files
  for (NSString* path in _manifestPaths.allValues) {
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  }
  [_manifestPaths removeAllObjects];
}

- (NSArray<NSString*>*)cachedIdentifiers {
  return _manifestPaths.allKeys;
}

@end

#pragma mark - Manifest Resolver

@interface DNSManifestResolver ()
@property(nonatomic, strong) DNSManifestCache* cache;
// Removed resolvedIdentifiers - will use local variable instead for thread safety
@property(nonatomic, strong) DNSPredicateEvaluator* predicateEvaluator;
@property(nonatomic, strong) HTTPRuleFetcher* httpFetcher;
@property(nonatomic, assign) Class ruleFetcherClass;
@property(nonatomic, strong) NSString* manifestBaseURL;
@property(nonatomic, strong) NSMutableSet<NSString*>* negativeURLCache;  // 404s this session
@end

@implementation DNSManifestResolver

#pragma mark - Test/Advanced Initializers

- (instancetype)initWithCacheDirectory:(NSString*)cacheDirectory {
  self = [self init];
  if (self) {
    if (!_cache) {
      _cache = [[DNSManifestCache alloc] init];
    }
    if (cacheDirectory.length > 0) {
      [_cache setValue:cacheDirectory forKey:@"cacheDirectory"];
    }
  }
  return self;
}

#pragma mark - Client Identification

+ (NSString*)determineClientIdentifierWithPreferenceManager:(PreferenceManager*)prefs {
  // 1. Check for kDNShieldClientIdentifier preference first
  NSString* clientIdentifier = [prefs preferenceValueForKey:kDNShieldClientIdentifier
                                                   inDomain:kDNShieldPreferenceDomain];
  if (clientIdentifier && clientIdentifier.length > 0) {
    [[LoggingManager sharedManager]
          logEvent:@"ClientIdentifierFound"
          category:LogCategoryConfiguration
             level:LogLevelInfo
        attributes:@{@"source" : @"ClientIdentifier", @"identifier" : clientIdentifier}];
    return clientIdentifier;
  }

  // 2. Check for ManifestIdentifier preference (legacy/backwards compatibility)
  NSString* configuredIdentifier = [prefs preferenceValueForKey:@"ManifestIdentifier"
                                                       inDomain:kDNShieldPreferenceDomain];
  if (configuredIdentifier && configuredIdentifier.length > 0) {
    [[LoggingManager sharedManager]
          logEvent:@"ClientIdentifierFound"
          category:LogCategoryConfiguration
             level:LogLevelInfo
        attributes:@{@"source" : @"ManifestIdentifier", @"identifier" : configuredIdentifier}];
    return configuredIdentifier;
  }

  // 3. Fallback to serial number.
  NSString* serialNumber = [self getMachineSerialNumber];
  if (serialNumber) {
    [[LoggingManager sharedManager]
          logEvent:@"ClientIdentifierFallback"
          category:LogCategoryConfiguration
             level:LogLevelInfo
        attributes:@{@"source" : @"SerialNumber", @"identifier" : serialNumber}];
    return serialNumber;
  }

  // 4. Final fallback to "default".
  [[LoggingManager sharedManager] logEvent:@"ClientIdentifierFallback"
                                  category:LogCategoryConfiguration
                                     level:LogLevelInfo
                                attributes:@{@"source" : @"Default", @"identifier" : @"default"}];
  return @"default";
}

+ (NSString*)getMachineSerialNumber {
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

- (instancetype)init {
  NSMutableArray* defaultPaths =
      [NSMutableArray arrayWithObjects:@"/Library/Application Support/DNShield/manifests",
                                       @"~/Library/Application Support/DNShield/manifests", nil];

  // Only add bundle path if it exists (may be nil in system extension)
  NSString* bundlePath = [[NSBundle mainBundle] pathForResource:@"manifests" ofType:nil];
  if (bundlePath) {
    [defaultPaths addObject:bundlePath];
  }

  return [self initWithSearchPaths:defaultPaths];
}

- (instancetype)initWithSearchPaths:(NSArray<NSString*>*)searchPaths {
  if (self = [super init]) {
    _manifestSearchPaths = [searchPaths copy];
    _cache = [[DNSManifestCache alloc] init];
    // Removed _resolvedIdentifiers initialization
    _predicateEvaluator = [[DNSPredicateEvaluator alloc] init];
    _evaluationContext = [DNSEvaluationContext defaultContext];
    _enableCaching = YES;
    _cacheTimeout = 300;  // 5 minutes
    _negativeURLCache = [NSMutableSet set];
    _ruleFetcherClass = [HTTPRuleFetcher class];

    // Initialize HTTP fetcher if configured
    [self setupHTTPFetcher];
  }
  return self;
}

#pragma mark - Public Methods

- (DNSResolvedManifest*)resolveManifest:(NSString*)identifier error:(NSError**)error {
  return [self resolveManifestWithFallback:identifier error:error];
}

- (DNSResolvedManifest*)resolveManifestWithFallback:(NSString*)initialIdentifier
                                              error:(NSError**)error {
  NSMutableArray<NSString*>* fallbackIdentifiers = [NSMutableArray array];
  NSString* serialNumber = [DNSManifestResolver getMachineSerialNumber];

  // Build proper fallback chain according to spec:
  // 1. ClientIdentifier (if set) - this is the initialIdentifier passed in
  // 2. Device serial number (if different)
  // 3. "default" as final fallback

  if (initialIdentifier && initialIdentifier.length > 0) {
    [fallbackIdentifiers addObject:initialIdentifier];
  }

  // Only add serial if it's different from initial identifier
  if (serialNumber && serialNumber.length > 0 &&
      ![serialNumber isEqualToString:initialIdentifier]) {
    [fallbackIdentifiers addObject:serialNumber];
  }

  // Always add 'default' as final fallback unless it's already in the chain
  if (![initialIdentifier isEqualToString:@"default"] &&
      (!serialNumber || ![serialNumber isEqualToString:@"default"])) {
    [fallbackIdentifiers addObject:@"default"];
  }

  DNSResolvedManifest* resolvedManifest = nil;
  NSError* lastError = nil;

  for (NSString* identifier in fallbackIdentifiers) {
    if (!identifier || [identifier isEqualToString:@""])
      continue;

    [[LoggingManager sharedManager] logEvent:@"AttemptingToResolveManifest"
                                    category:LogCategoryRuleFetching
                                       level:LogLevelInfo
                                  attributes:@{@"identifier" : identifier}];

    resolvedManifest = [self performResolve:identifier error:&lastError];

    if (resolvedManifest) {
      [[LoggingManager sharedManager] logEvent:@"ManifestResolvedSuccessfully"
                                      category:LogCategoryRuleFetching
                                         level:LogLevelInfo
                                    attributes:@{@"identifier" : identifier}];
      return resolvedManifest;
    } else {
      [[LoggingManager sharedManager] logEvent:@"FailedToResolveManifest"
                                      category:LogCategoryRuleFetching
                                         level:LogLevelDefault
                                    attributes:@{
                                      @"identifier" : identifier,
                                      @"error" : lastError.localizedDescription ?: @"Unknown error"
                                    }];
    }
  }

  if (error) {
    *error = lastError;
  }

  return nil;
}

- (NSArray<NSString*>*)orderedExtensionsWithDotForIdentifier:(NSString*)identifier {
  // Simplified policy:
  // - If kDNShieldManifestFormat is one of {json, plist, yml} -> only that extension.
  // - If not set or unsupported -> only .json.
  PreferenceManager* prefManager = [PreferenceManager sharedManager];
  id manifestFormatPref = [prefManager preferenceValueForKey:kDNShieldManifestFormat
                                                    inDomain:kDNShieldPreferenceDomain];

  NSSet<NSString*>* supported = [NSSet setWithArray:@[ @"json", @"plist", @"yml" ]];
  NSString* preferredFormat = nil;
  if ([manifestFormatPref isKindOfClass:[NSString class]]) {
    NSCharacterSet* trimSet = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    preferredFormat = [(NSString*)manifestFormatPref stringByTrimmingCharactersInSet:trimSet];
    if ([preferredFormat hasPrefix:@"."]) {
      preferredFormat = [preferredFormat substringFromIndex:1];
    }
    preferredFormat = [preferredFormat lowercaseString];
  }

  if (preferredFormat.length && [supported containsObject:preferredFormat]) {
    if ([preferredFormat isEqualToString:@"json"])
      return @[ @".json" ];
    if ([preferredFormat isEqualToString:@"plist"])
      return @[ @".plist" ];
    if ([preferredFormat isEqualToString:@"yml"])
      return @[ @".yml" ];
  }

  // Default: JSON only
  return @[ @".json" ];
}

- (DNSResolvedManifest*)performResolve:(NSString*)identifier error:(NSError**)error {
  [[LoggingManager sharedManager] logEvent:@"ResolvingManifest"
                                  category:LogCategoryRuleFetching
                                     level:LogLevelInfo
                                attributes:@{@"identifier" : identifier}];

  if ([_delegate respondsToSelector:@selector(manifestResolver:didStartResolvingManifest:)]) {
    [_delegate manifestResolver:self didStartResolvingManifest:identifier];
  }

  // Track manifests currently being processed vs. those already fully resolved
  NSMutableSet<NSString*>* processingIdentifiers = [NSMutableSet set];
  NSMutableSet<NSString*>* visitedIdentifiers = [NSMutableSet set];

  DNSResolvedManifest* resolved = [[DNSResolvedManifest alloc] init];
  NSMutableArray* warnings = [NSMutableArray array];

  DNSManifest* primaryManifest = [self getManifest:identifier error:error];
  if (!primaryManifest) {
    if ([_delegate respondsToSelector:@selector(manifestResolver:
                                          didFailToResolveManifest:error:)]) {
      [_delegate manifestResolver:self didFailToResolveManifest:identifier error:*error];
    }
    return nil;
  }

  [resolved setValue:primaryManifest forKey:@"primaryManifest"];

  NSMutableArray* manifestChain = [NSMutableArray array];
  NSMutableArray* allRuleSources = [NSMutableArray array];
  NSMutableDictionary* mergedManagedRules = [NSMutableDictionary dictionary];

  BOOL success = [self resolveManifestHierarchy:primaryManifest
                                  manifestChain:manifestChain
                                    ruleSources:allRuleSources
                                   managedRules:mergedManagedRules
                                       warnings:warnings
                          processingIdentifiers:processingIdentifiers
                             visitedIdentifiers:visitedIdentifiers
                                          error:error];

  if (!success) {
    if ([_delegate respondsToSelector:@selector(manifestResolver:
                                          didFailToResolveManifest:error:)]) {
      [_delegate manifestResolver:self didFailToResolveManifest:identifier error:*error];
    }
    return nil;
  }

  [allRuleSources sortUsingComparator:^NSComparisonResult(RuleSource* obj1, RuleSource* obj2) {
    return [@(obj2.priority) compare:@(obj1.priority)];
  }];

  [resolved setValue:manifestChain forKey:@"manifestChain"];
  [resolved setValue:allRuleSources forKey:@"resolvedRuleSources"];
  [resolved setValue:mergedManagedRules forKey:@"resolvedManagedRules"];
  [resolved setValue:warnings forKey:@"warnings"];

  if ([_delegate respondsToSelector:@selector(manifestResolver:didResolveManifest:)]) {
    [_delegate manifestResolver:self didResolveManifest:identifier];
  }

  [[LoggingManager sharedManager]
        logEvent:@"ManifestResolved"
        category:LogCategoryRuleFetching
           level:LogLevelInfo
      attributes:@{@"identifier" : identifier, @"ruleSourceCount" : @(allRuleSources.count)}];

  return resolved;
}

- (void)resolveManifestAsync:(NSString*)identifier
                  completion:(void (^)(DNSResolvedManifest* resolved, NSError* error))completion {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSError* error = nil;
    DNSResolvedManifest* resolved = [self resolveManifest:identifier error:&error];

    dispatch_async(dispatch_get_main_queue(), ^{
      completion(resolved, error);
    });
  });
}

- (void)clearCache {
  [_cache removeAllManifests];
}

- (void)clearCacheForManifest:(NSString*)identifier {
  [_cache removeManifestForIdentifier:identifier];
}

- (BOOL)manifestExists:(NSString*)identifier {
  return [self findManifestFile:identifier] != nil;
}

- (void)preCacheManifests:(NSArray<NSString*>*)identifiers {
  for (NSString* identifier in identifiers) {
    NSError* error = nil;
    [self getManifest:identifier error:&error];
    if (error) {
      [[LoggingManager sharedManager]
          logError:error
          category:LogCategoryRuleFetching
           context:[NSString stringWithFormat:@"Failed to pre-cache manifest %@", identifier]];
    }
  }
}

// Shared sanitization helper used by both resolver and cache
static id DNS_SanitizeForPlist(id object) {
  if ([object isKindOfClass:[NSDictionary class]]) {
    NSMutableDictionary* sanitized = [NSMutableDictionary dictionary];
    NSDictionary* dict = (NSDictionary*)object;
    [dict enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL* stop) {
      if ([obj isKindOfClass:[NSNull class]])
        return;  // Skip NSNull
      id sanitizedValue = DNS_SanitizeForPlist(obj);
      if (sanitizedValue)
        sanitized[key] = sanitizedValue;
    }];
    return sanitized;
  } else if ([object isKindOfClass:[NSArray class]]) {
    NSMutableArray* sanitized = [NSMutableArray array];
    for (id obj in (NSArray*)object) {
      if ([obj isKindOfClass:[NSNull class]])
        continue;  // Skip NSNull
      id sanitizedValue = DNS_SanitizeForPlist(obj);
      if (sanitizedValue)
        [sanitized addObject:sanitizedValue];
    }
    return sanitized;
  }
  // Return scalars unchanged
  return object;
}

#pragma mark - Helper Methods

- (id)sanitizeDictionaryForPlist:(id)object {
  return DNS_SanitizeForPlist(object);
}

#pragma mark - Private Methods

- (NSString*)findManifestFile:(NSString*)identifier {
  // Single source of truth: derive order once
  NSArray<NSString*>* dotExtensions = [self orderedExtensionsWithDotForIdentifier:identifier];
  NSMutableArray<NSString*>* extensions = [NSMutableArray arrayWithCapacity:dotExtensions.count];
  for (NSString* dotExt in dotExtensions) {
    [extensions addObject:[dotExt hasPrefix:@"."] ? [dotExt substringFromIndex:1] : dotExt];
  }

  // Search for manifest file in all search paths
  for (NSString* searchPath in _manifestSearchPaths) {
    NSString* expandedPath = [searchPath stringByExpandingTildeInPath];

    // Try with different extensions in preference order
    for (NSString* ext in extensions) {
      NSString* filePath = [expandedPath
          stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.%@", identifier, ext]];
      if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        return filePath;
      }
    }

    // Try without extension
    NSString* filePath = [expandedPath stringByAppendingPathComponent:identifier];
    if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
      return filePath;
    }
  }

  return nil;
}

- (BOOL)resolveManifestHierarchy:(DNSManifest*)manifest
                   manifestChain:(NSMutableArray*)manifestChain
                     ruleSources:(NSMutableArray*)ruleSources
                    managedRules:(NSMutableDictionary*)managedRules
                        warnings:(NSMutableArray*)warnings
           processingIdentifiers:(NSMutableSet*)processingIdentifiers
              visitedIdentifiers:(NSMutableSet*)visitedIdentifiers
                           error:(NSError**)error {
  // Detect circular dependencies using the current processing stack
  if ([processingIdentifiers containsObject:manifest.identifier]) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorCircularDependency
                 userInfo:@{
                   NSLocalizedDescriptionKey : [NSString
                       stringWithFormat:@"Circular dependency detected: %@", manifest.identifier]
                 }];
    }
    return NO;
  }

  // Skip manifests we've already processed successfully to avoid duplicate work
  if ([visitedIdentifiers containsObject:manifest.identifier]) {
    [[LoggingManager sharedManager] logEvent:@"ManifestAlreadyProcessed"
                                    category:LogCategoryRuleParsing
                                       level:LogLevelDebug
                                  attributes:@{@"identifier" : manifest.identifier ?: @"unknown"}];
    return YES;
  }

  [processingIdentifiers addObject:manifest.identifier];
  [[LoggingManager sharedManager] logEvent:@"ProcessingManifest"
                                  category:LogCategoryRuleParsing
                                     level:LogLevelInfo
                                attributes:@{
                                  @"identifier" : manifest.identifier ?: @"unknown",
                                  @"include_count" : @(manifest.includedManifests.count),
                                  @"conditional_count" : @(manifest.conditionalItems.count)
                                }];
  [manifestChain addObject:manifest];

  // Process included manifests first (depth-first)
  for (NSString* includedIdentifier in manifest.includedManifests) {
    NSError* includeError = nil;
    [[LoggingManager sharedManager] logEvent:@"ResolvingIncludedManifest"
                                    category:LogCategoryRuleParsing
                                       level:LogLevelInfo
                                  attributes:@{
                                    @"parent" : manifest.identifier ?: @"unknown",
                                    @"include" : includedIdentifier ?: @"unknown"
                                  }];
    DNSManifest* includedManifest = [self getManifest:includedIdentifier error:&includeError];

    if (!includedManifest) {
      // Log warning but continue
      NSMutableDictionary* userInfo = [NSMutableDictionary
          dictionaryWithObject:[NSString stringWithFormat:@"Included manifest '%@' not found",
                                                          includedIdentifier]
                        forKey:NSLocalizedDescriptionKey];

      if (includeError) {
        userInfo[NSUnderlyingErrorKey] = includeError;
      }

      NSError* warning = [NSError errorWithDomain:DNSManifestErrorDomain
                                             code:DNSManifestErrorManifestNotFound
                                         userInfo:userInfo];
      [[LoggingManager sharedManager] logEvent:@"IncludedManifestMissing"
                                      category:LogCategoryRuleParsing
                                         level:LogLevelError
                                    attributes:@{
                                      @"parent" : manifest.identifier ?: @"unknown",
                                      @"include" : includedIdentifier ?: @"unknown"
                                    }];
      if (includeError) {
        [[LoggingManager sharedManager]
            logError:includeError
            category:LogCategoryRuleParsing
             context:[NSString stringWithFormat:@"Failed to load included manifest '%@' for '%@'",
                                                includedIdentifier ?: @"unknown",
                                                manifest.identifier ?: @"unknown"]];
      }
      [warnings addObject:warning];

      if ([_delegate respondsToSelector:@selector(manifestResolver:
                                               didEncounterWarning:forManifest:)]) {
        [_delegate manifestResolver:self
                didEncounterWarning:warning
                        forManifest:manifest.identifier];
      }
      continue;
    }

    BOOL success = [self resolveManifestHierarchy:includedManifest
                                    manifestChain:manifestChain
                                      ruleSources:ruleSources
                                     managedRules:managedRules
                                         warnings:warnings
                            processingIdentifiers:processingIdentifiers
                               visitedIdentifiers:visitedIdentifiers
                                            error:error];
    if (!success) {
      [processingIdentifiers removeObject:manifest.identifier];
      return NO;
    }
    [[LoggingManager sharedManager] logEvent:@"IncludedManifestResolved"
                                    category:LogCategoryRuleParsing
                                       level:LogLevelInfo
                                  attributes:@{
                                    @"parent" : manifest.identifier ?: @"unknown",
                                    @"include" : includedIdentifier ?: @"unknown"
                                  }];
  }

  // Process conditional items
  if (manifest.conditionalItems.count > 0) {
    [[LoggingManager sharedManager] logEvent:@"ProcessingConditionalItems"
                                    category:LogCategoryRuleParsing
                                       level:LogLevelInfo
                                  attributes:@{
                                    @"manifest_id" : manifest.identifier ?: @"unknown",
                                    @"conditional_item_count" : @(manifest.conditionalItems.count)
                                  }];
  }

  for (DNSConditionalItem* conditionalItem in manifest.conditionalItems) {
    BOOL conditionResult = [_predicateEvaluator evaluatePredicate:conditionalItem.condition
                                                      withContext:_evaluationContext];

    // Log all condition evaluations with detailed context
    NSMutableDictionary* logAttributes = [@{
      @"manifest_id" : manifest.identifier ?: @"unknown",
      @"condition" : conditionalItem.condition ?: @"empty",
      @"result" : @(conditionResult),
      @"current_date" : [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                       dateStyle:NSDateFormatterShortStyle
                                                       timeStyle:NSDateFormatterNoStyle]
          ?: @"unknown",
      @"current_time" : [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                       dateStyle:NSDateFormatterNoStyle
                                                       timeStyle:NSDateFormatterMediumStyle]
          ?: @"unknown"
    } mutableCopy];

    // Add rule counts if condition is true
    if (conditionResult) {
      NSUInteger allowRuleCount = [conditionalItem.managedRules[@"allow"] count];
      NSUInteger blockRuleCount = [conditionalItem.managedRules[@"block"] count];
      NSUInteger includedManifestCount = [conditionalItem.includedManifests count];
      NSUInteger ruleSourceCount = [conditionalItem.ruleSources count];

      logAttributes[@"allow_rules_applied"] = @(allowRuleCount);
      logAttributes[@"block_rules_applied"] = @(blockRuleCount);
      logAttributes[@"included_manifests_applied"] = @(includedManifestCount);
      logAttributes[@"rule_sources_applied"] = @(ruleSourceCount);

      // Log a sample of the rules being applied
      if (allowRuleCount > 0) {
        NSArray* allowRules = conditionalItem.managedRules[@"allow"];
        logAttributes[@"sample_allow_rules"] =
            allowRules.count > 3 ? [allowRules subarrayWithRange:NSMakeRange(0, 3)] : allowRules;
      }
      if (blockRuleCount > 0) {
        NSArray* blockRules = conditionalItem.managedRules[@"block"];
        logAttributes[@"sample_block_rules"] =
            blockRules.count > 3 ? [blockRules subarrayWithRange:NSMakeRange(0, 3)] : blockRules;
      }
    }

    [[LoggingManager sharedManager] logEvent:@"ConditionalItemEvaluated"
                                    category:LogCategoryRuleParsing
                                       level:LogLevelInfo
                                  attributes:logAttributes];

    if (conditionResult) {
      // Add conditional rule sources
      [ruleSources addObjectsFromArray:conditionalItem.ruleSources];

      // Merge conditional managed rules
      [self mergeManagedRules:conditionalItem.managedRules into:managedRules];

      // Process conditional included manifests
      for (NSString* includedIdentifier in conditionalItem.includedManifests) {
        NSError* includeError = nil;
        [[LoggingManager sharedManager] logEvent:@"ResolvingConditionalIncludedManifest"
                                        category:LogCategoryRuleParsing
                                           level:LogLevelInfo
                                      attributes:@{
                                        @"parent" : manifest.identifier ?: @"unknown",
                                        @"include" : includedIdentifier ?: @"unknown",
                                        @"condition" : conditionalItem.condition ?: @"empty"
                                      }];
        DNSManifest* includedManifest = [self getManifest:includedIdentifier error:&includeError];

        if (includedManifest) {
          BOOL success = [self resolveManifestHierarchy:includedManifest
                                          manifestChain:manifestChain
                                            ruleSources:ruleSources
                                           managedRules:managedRules
                                               warnings:warnings
                                  processingIdentifiers:processingIdentifiers
                                     visitedIdentifiers:visitedIdentifiers
                                                  error:error];
          if (!success) {
            [processingIdentifiers removeObject:manifest.identifier];
            return NO;
          }
          [[LoggingManager sharedManager] logEvent:@"ConditionalIncludedManifestResolved"
                                          category:LogCategoryRuleParsing
                                             level:LogLevelInfo
                                        attributes:@{
                                          @"parent" : manifest.identifier ?: @"unknown",
                                          @"include" : includedIdentifier ?: @"unknown",
                                          @"condition" : conditionalItem.condition ?: @"empty"
                                        }];
        } else {
          // Log when included manifests from conditions can't be found
          [[LoggingManager sharedManager]
                logEvent:@"ConditionalIncludeManifestNotFound"
                category:LogCategoryRuleParsing
                   level:LogLevelError
              attributes:@{
                @"manifest_id" : manifest.identifier ?: @"unknown",
                @"condition" : conditionalItem.condition ?: @"empty",
                @"missing_include" : includedIdentifier ?: @"unknown",
                @"error" : includeError ? includeError.localizedDescription : @"unknown error"
              }];
          if (includeError) {
            [[LoggingManager sharedManager]
                logError:includeError
                category:LogCategoryRuleParsing
                 context:[NSString stringWithFormat:@"Failed conditional include '%@' for '%@'",
                                                    includedIdentifier ?: @"unknown",
                                                    manifest.identifier ?: @"unknown"]];
          }
        }
      }
    }
  }

  // Add this manifest's rule sources
  [ruleSources addObjectsFromArray:manifest.ruleSources];

  // Merge this manifest's managed rules
  [self mergeManagedRules:manifest.managedRules into:managedRules];

  // Mark manifest as fully processed
  [processingIdentifiers removeObject:manifest.identifier];
  [visitedIdentifiers addObject:manifest.identifier];
  [[LoggingManager sharedManager] logEvent:@"ManifestProcessed"
                                  category:LogCategoryRuleParsing
                                     level:LogLevelInfo
                                attributes:@{
                                  @"identifier" : manifest.identifier ?: @"unknown",
                                  @"aggregate_rule_sources" : @(ruleSources.count),
                                  @"aggregate_managed_categories" : @(managedRules.count)
                                }];

  return YES;
}

- (void)mergeManagedRules:(NSDictionary*)source into:(NSMutableDictionary*)destination {
  for (NSString* key in source) {
    NSMutableArray* existingRules = destination[key];
    if (!existingRules) {
      existingRules = [NSMutableArray array];
      destination[key] = existingRules;
    }

    // Convert to NSSet for O(1) lookups instead of O(n)
    // With 244,498 rules, containsObject: was causing billions of comparisons
    NSMutableSet* existingSet = [NSMutableSet setWithArray:existingRules];
    NSArray* newRules = source[key];

    NSMutableArray* rulesToAdd = [NSMutableArray array];
    for (NSString* rule in newRules) {
      if (![existingSet containsObject:rule]) {
        [rulesToAdd addObject:rule];
        [existingSet addObject:rule];  // Keep set updated for subsequent checks
      }
    }

    // Add all new rules at once
    if (rulesToAdd.count > 0) {
      [existingRules addObjectsFromArray:rulesToAdd];
    }
  }
}

#pragma mark - S3 Support

- (void)setupHTTPFetcher {
  PreferenceManager* prefManager = [PreferenceManager sharedManager];

  // Check for ManifestURL or SoftwareRepoURL first (Munki-style)
  NSString* manifestURL = [prefManager preferenceValueForKey:kDNShieldManifestURL
                                                    inDomain:kDNShieldPreferenceDomain];
  if (!manifestURL) {
    manifestURL = [prefManager preferenceValueForKey:kDNShieldSoftwareRepoURL
                                            inDomain:kDNShieldPreferenceDomain];
  }

  if (manifestURL) {
    NSURL* url = [NSURL URLWithString:manifestURL];
    if (url) {
      _manifestBaseURL = manifestURL;
      _httpFetcher = [[HTTPRuleFetcher alloc] initWithURL:url];
      [self configureHTTPFetcherAuth];
      // Diagnostic: Log exact base URL and any configured headers
      [[LoggingManager sharedManager] logEvent:@"ruleFetcherConfigured"
                                      category:LogCategoryRuleFetching
                                         level:LogLevelInfo
                                    attributes:@{
                                      @"type" : @"HTTP",
                                      @"base_url" : manifestURL,
                                      @"header_count" : @(_httpFetcher.customHeaders.count ?: 0)
                                    }];
    } else {
      [[LoggingManager sharedManager] logEvent:@"invalidManifestBaseURL"
                                      category:LogCategoryRuleFetching
                                         level:LogLevelError
                                    attributes:@{@"value" : manifestURL ?: @"(nil)"}];
    }
    return;
  }

  // Legacy S3 configuration removed - use HTTPRuleFetcher for all HTTP(S) endpoints
}

- (NSURL*)manifestURLForIdentifier:(NSString*)identifier withExtension:(NSString*)extension {
  if (!_manifestBaseURL) {
    return nil;
  }

  NSString* filename = [NSString stringWithFormat:@"%@%@", identifier, extension];
  NSString* fullURLString;

  // Check if base URL already ends with slash
  if ([_manifestBaseURL hasSuffix:@"/"]) {
    fullURLString = [NSString stringWithFormat:@"%@%@", _manifestBaseURL, filename];
  } else {
    fullURLString = [NSString stringWithFormat:@"%@/%@", _manifestBaseURL, filename];
  }

  return [NSURL URLWithString:fullURLString];
}

- (void)configureHTTPFetcherAuth {
  if (!_httpFetcher) {
    return;
  }

  PreferenceManager* prefManager = [PreferenceManager sharedManager];

  // Load AdditionalHttpHeaders for auth (like Munki-style Basic Auth)
  NSArray* additionalHeaders = [prefManager preferenceValueForKey:kDNShieldAdditionalHttpHeaders
                                                         inDomain:kDNShieldPreferenceDomain];

  [[LoggingManager sharedManager]
        logEvent:@"CheckingHTTPHeaders"
        category:LogCategoryConfiguration
           level:LogLevelInfo
      attributes:@{
        @"headers_found" : additionalHeaders ? @"YES" : @"NO",
        @"headers_type" : NSStringFromClass([additionalHeaders class]) ?: @"nil",
        @"headers_count" : @([(NSArray*)additionalHeaders count])
      }];

  if ([additionalHeaders isKindOfClass:[NSArray class]] && additionalHeaders.count > 0) {
    NSMutableDictionary* headerDict = [NSMutableDictionary dictionary];

    for (NSString* headerString in additionalHeaders) {
      if ([headerString isKindOfClass:[NSString class]]) {
        NSArray* parts = [headerString componentsSeparatedByString:@": "];
        if (parts.count >= 2) {
          NSString* headerName = parts[0];
          NSString* headerValue = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)]
              componentsJoinedByString:@": "];
          headerDict[headerName] = headerValue;
        }
      }
    }

    if (headerDict.count > 0) {
      _httpFetcher.customHeaders = headerDict;
      [[LoggingManager sharedManager] logEvent:@"ConfiguredHTTPHeaders"
                                      category:LogCategoryConfiguration
                                         level:LogLevelInfo
                                    attributes:@{@"headerCount" : @(headerDict.count)}];
    }
  }
}

- (DNSManifest*)getManifest:(NSString*)identifier error:(NSError**)error {
  // Check cache first
  if (_enableCaching) {
    BOOL cachedWasExpired = NO;
    DNSManifest* cached = [_cache manifestForIdentifier:identifier
                                           allowExpired:NO
                                             wasExpired:&cachedWasExpired];
    if (cached) {
      [[LoggingManager sharedManager]
            logEvent:@"CacheHit"
            category:LogCategoryCache
               level:LogLevelDebug
          attributes:@{@"type" : @"manifest", @"identifier" : identifier}];
      return cached;
    }
  }

  // Try local file first
  NSString* manifestPath = [self findManifestFile:identifier];
  if (manifestPath) {
    DNSManifest* manifest = [DNSManifestParser parseManifestFromFile:manifestPath error:error];
    if (manifest && _enableCaching) {
      [_cache cacheManifest:manifest forIdentifier:identifier];
      [self cacheIncludedManifestsAsync:manifest forParent:identifier];
    }
    return manifest;
  }

  NSError* lastFetchError = nil;
  NSTimeInterval fetchTimeout = 10.0;

  // Try HTTP fetcher if configured
  if (_httpFetcher && _manifestBaseURL) {
    // Determine format preference and build extension order
    PreferenceManager* prefManager = [PreferenceManager sharedManager];
    // Apply fetch timeout preference (defaults to 10s if not set - 30s was way too long)
    id timeoutPref = [prefManager preferenceValueForKey:@"ManifestFetchTimeoutSeconds"
                                               inDomain:kDNShieldPreferenceDomain];
    if ([timeoutPref respondsToSelector:@selector(doubleValue)]) {
      double v = [timeoutPref doubleValue];
      if (v > 0.0 && v <= 60.0)
        fetchTimeout = v;  // Cap at 60 seconds max
    }

    NSArray<NSString*>* extensionOrder = [self orderedExtensionsWithDotForIdentifier:identifier];

    [[LoggingManager sharedManager]
          logEvent:@"ManifestExtensionOrder"
          category:LogCategoryRuleFetching
             level:LogLevelInfo
        attributes:@{
          @"identifier" :
              ([identifier pathExtension].length > 0 ? [identifier stringByDeletingPathExtension]
                                                     : identifier),
          @"preferredFormat" : [[self orderedExtensionsWithDotForIdentifier:identifier].firstObject
              stringByReplacingOccurrencesOfString:@"."
                                        withString:@""],
          @"extensionOrder" : extensionOrder
        }];

    // Try each extension synchronously
    NSString* normalizedIdentifier = ([identifier pathExtension].length > 0)
                                         ? [identifier stringByDeletingPathExtension]
                                         : identifier;
    __block NSError* lastAttemptError = nil;
    for (NSString* extension in extensionOrder) {
      NSURL* manifestURL = [self manifestURLForIdentifier:normalizedIdentifier
                                            withExtension:extension];
      if (!manifestURL)
        continue;

      // Negative cache: skip URLs known to 404 in this session
      if ([_negativeURLCache containsObject:manifestURL.absoluteString]) {
        [[LoggingManager sharedManager] logEvent:@"SkippingNegativeCachedURL"
                                        category:LogCategoryRuleFetching
                                           level:LogLevelDebug
                                      attributes:@{@"url" : manifestURL.absoluteString}];
        continue;
      }

      __block DNSManifest* httpManifest = nil;
      __block NSError* httpError = nil;
      dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

      [[LoggingManager sharedManager] logEvent:@"FetchingManifestHTTP"
                                      category:LogCategoryRuleFetching
                                         level:LogLevelInfo
                                    attributes:@{
                                      @"url" : manifestURL.absoluteString,
                                      @"format" : extension,
                                      @"identifier" : normalizedIdentifier,
                                      @"headers" : _httpFetcher.customHeaders ?: @{}
                                    }];

      // Reuse the configured fetcher with proper authentication headers.
      // IMPORTANT: Disable retries for manifest resolution so we can advance
      // to the next extension/identifier immediately on 404.
      Class fetcherClass = self.ruleFetcherClass ?: [HTTPRuleFetcher class];
      HTTPRuleFetcher* fetcher;
      if (_httpFetcher) {
        // Clone base configuration and override retry behavior
        NSMutableDictionary* cfg =
            [NSMutableDictionary dictionaryWithDictionary:_httpFetcher.configuration ?: @{}];
        cfg[RuleFetcherConfigKeyRetryCount] = @0;
        cfg[RuleFetcherConfigKeyRetryDelay] = @0.0;
        cfg[RuleFetcherConfigKeyTimeout] = @(fetchTimeout);
        fetcher = [[fetcherClass alloc] initWithURL:manifestURL configuration:cfg];
        if (_httpFetcher.customHeaders) {
          fetcher.customHeaders = _httpFetcher.customHeaders;
        }
      } else {
        fetcher = [[fetcherClass alloc] initWithURL:manifestURL
                                      configuration:@{
                                        RuleFetcherConfigKeyRetryCount : @0,
                                        RuleFetcherConfigKeyRetryDelay : @0.0,
                                        RuleFetcherConfigKeyTimeout : @(fetchTimeout)
                                      }];
      }

      [fetcher fetchRulesWithCompletion:^(NSData* data, NSError* fetchError) {
        [[LoggingManager sharedManager] logEvent:@"FetchCompletionBlockCalled"
                                        category:LogCategoryRuleFetching
                                           level:LogLevelInfo
                                      attributes:@{
                                        @"hasData" : data ? @"YES" : @"NO",
                                        @"dataSize" : data ? @(data.length) : @0,
                                        @"hasError" : fetchError ? @"YES" : @"NO",
                                        @"url" : manifestURL.absoluteString
                                      }];
        if (data) {
          [[LoggingManager sharedManager] logEvent:@"ManifestDataReceived"
                                          category:LogCategoryRuleFetching
                                             level:LogLevelInfo
                                        attributes:@{
                                          @"url" : manifestURL.absoluteString,
                                          @"dataSize" : @(data.length)
                                        }];
          NSError* parseError = nil;
          httpManifest = [DNSManifestParser parseManifestFromData:data error:&parseError];
          [[LoggingManager sharedManager]
                logEvent:@"ParseAttemptComplete"
                category:LogCategoryRuleFetching
                   level:LogLevelInfo
              attributes:@{
                @"url" : manifestURL.absoluteString,
                @"manifestCreated" : httpManifest ? @"YES" : @"NO",
                @"parseError" : parseError ? parseError.localizedDescription : @"none"
              }];
          if (httpManifest) {
            [[LoggingManager sharedManager] logEvent:@"ManifestParsedSuccessfully"
                                            category:LogCategoryRuleFetching
                                               level:LogLevelInfo
                                          attributes:@{
                                            @"url" : manifestURL.absoluteString,
                                            @"identifier" : normalizedIdentifier
                                          }];
          } else {
            [[LoggingManager sharedManager] logEvent:@"ManifestParseFailed"
                                            category:LogCategoryRuleFetching
                                               level:LogLevelError
                                          attributes:@{
                                            @"url" : manifestURL.absoluteString,
                                            @"error" : parseError.localizedDescription ?: @"unknown"
                                          }];
          }
          httpError = parseError;
        } else {
          httpError = fetchError;
          [[LoggingManager sharedManager] logEvent:@"ManifestFetchFailed"
                                          category:LogCategoryRuleFetching
                                             level:LogLevelError
                                        attributes:@{
                                          @"url" : manifestURL.absoluteString,
                                          @"error" : fetchError.localizedDescription ?: @"unknown"
                                        }];
          // Record 404s to avoid retrying this exact URL again during the session
          NSNumber* status = fetchError.userInfo[@"statusCode"];
          if ([fetchError.domain isEqualToString:DNSRuleFetcherErrorDomain] &&
              fetchError.code == DNSRuleFetcherErrorHTTPError && status &&
              status.integerValue == 404) {
            [self.negativeURLCache addObject:manifestURL.absoluteString];
          }
        }
        if (httpError) {
          lastAttemptError = httpError;
        }
        dispatch_semaphore_signal(semaphore);
      }];

      // Wait for the fetch to complete - add small buffer time beyond HTTP timeout to account for
      // processing
      NSTimeInterval semaphoreTimeout = fetchTimeout + 2.0;  // Add 2 seconds buffer for processing
      dispatch_time_t timeout =
          dispatch_time(DISPATCH_TIME_NOW, (int64_t)(semaphoreTimeout * NSEC_PER_SEC));
      if (dispatch_semaphore_wait(semaphore, timeout) == 0) {
        if (httpManifest) {
          [[LoggingManager sharedManager] logEvent:@"ManifestFetchSuccess_PreCache"
                                          category:LogCategoryRuleFetching
                                             level:LogLevelInfo
                                        attributes:@{
                                          @"identifier" : identifier,
                                          @"url" : manifestURL.absoluteString,
                                          @"cachingEnabled" : _enableCaching ? @"YES" : @"NO",
                                          @"cacheObject" : _cache ? @"exists" : @"nil"
                                        }];
          // Cache the successful result
          if (_enableCaching) {
            [[LoggingManager sharedManager] logEvent:@"CallingCacheManifest"
                                            category:LogCategoryRuleFetching
                                               level:LogLevelInfo
                                          attributes:@{@"identifier" : identifier}];
            [_cache cacheManifest:httpManifest forIdentifier:identifier];
            [self cacheIncludedManifestsAsync:httpManifest forParent:identifier];
          } else {
            [[LoggingManager sharedManager] logEvent:@"CachingDisabled"
                                            category:LogCategoryRuleFetching
                                               level:LogLevelDefault
                                          attributes:@{@"identifier" : identifier}];
          }
          return httpManifest;
        }
        // Continue to try next extension on parse error
      } else {
        // Timeout - cancel this fetch and try next extension
        [[LoggingManager sharedManager] logEvent:@"ManifestFetchTimeout"
                                        category:LogCategoryRuleFetching
                                           level:LogLevelDefault
                                      attributes:@{
                                        @"identifier" : identifier,
                                        @"url" : manifestURL.absoluteString,
                                        @"timeoutSeconds" : @(fetchTimeout)
                                      }];
        [fetcher cancelFetch];
      }
    }

    if (lastAttemptError) {
      lastFetchError = lastAttemptError;
    }
  }

  if (_enableCaching) {
    BOOL wasExpired = NO;
    DNSManifest* fallbackManifest = [_cache manifestForIdentifier:identifier
                                                     allowExpired:YES
                                                       wasExpired:&wasExpired];
    if (fallbackManifest) {
      NSMutableDictionary* attributes = [@{
        @"identifier" : identifier ?: @"unknown",
        @"usedExpiredCache" : wasExpired ? @"YES" : @"NO"
      } mutableCopy];
      if (lastFetchError) {
        attributes[@"lastError"] = lastFetchError.localizedDescription ?: @"unknown";
      }

      [[LoggingManager sharedManager] logEvent:@"ManifestFetchFallbackToCache"
                                      category:LogCategoryRuleFetching
                                         level:LogLevelInfo
                                    attributes:attributes];

      if (wasExpired) {
        [_cache cacheManifest:fallbackManifest forIdentifier:identifier];
      }

      return fallbackManifest;
    }
  }

  // All extensions failed
  if (error) {
    *error =
        [NSError errorWithDomain:DNSManifestErrorDomain
                            code:DNSManifestErrorManifestNotFound
                        userInfo:@{
                          NSLocalizedDescriptionKey : [NSString
                              stringWithFormat:
                                  @"Manifest fetch timed out after %.0f seconds for identifier: %@",
                                  fetchTimeout, identifier]
                        }];
  }

  return nil;
}

- (void)cacheIncludedManifestsAsync:(DNSManifest*)manifest forParent:(NSString*)parentIdentifier {
  if (!manifest.includedManifests || manifest.includedManifests.count == 0) {
    return;
  }

  [[LoggingManager sharedManager] logEvent:@"CachingIncludedManifests"
                                  category:LogCategoryRuleFetching
                                     level:LogLevelInfo
                                attributes:@{
                                  @"parent" : parentIdentifier,
                                  @"includeCount" : @(manifest.includedManifests.count)
                                }];

  for (NSString* includedIdentifier in manifest.includedManifests) {
    // Check if we already have this included manifest cached
    if (![_cache.cachedIdentifiers containsObject:includedIdentifier]) {
      [[LoggingManager sharedManager]
            logEvent:@"FetchingIncludedManifest"
            category:LogCategoryRuleFetching
               level:LogLevelInfo
          attributes:@{@"parent" : parentIdentifier, @"included" : includedIdentifier}];

      // Fetch and cache the included manifest asynchronously to avoid blocking
      dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError* error;
        DNSResolvedManifest* resolvedManifest = [self resolveManifest:includedIdentifier
                                                                error:&error];
        if (resolvedManifest.primaryManifest && self->_enableCaching) {
          [self->_cache cacheManifest:resolvedManifest.primaryManifest
                        forIdentifier:includedIdentifier];
          // Recursively cache nested includes
          [self cacheIncludedManifestsAsync:resolvedManifest.primaryManifest
                                  forParent:includedIdentifier];
        } else if (error) {
          [[LoggingManager sharedManager] logEvent:@"FailedToFetchIncludedManifest"
                                          category:LogCategoryRuleFetching
                                             level:LogLevelError
                                        attributes:@{
                                          @"parent" : parentIdentifier,
                                          @"included" : includedIdentifier,
                                          @"error" : error.localizedDescription ?: @"unknown"
                                        }];
        }
      });
    }
  }
}

@end
