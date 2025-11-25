//
//  ConfigurationManager.h
//  DNShield Network Extension
//
//  Manages DNShield configuration from various sources
//  Provides a unified configuration model for all components
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Forward declarations
@class DNSResolvedManifest;
@class ConfigurationManager;

// Configuration observer protocol
@protocol ConfigurationManagerObserver <NSObject>
@optional
- (void)configurationDidChange:(ConfigurationManager*)manager;
@end

// Rule source types
typedef NS_ENUM(NSInteger, RuleSourceType) {
  RuleSourceTypeHTTPS = 0,
  RuleSourceTypeFile,
  RuleSourceTypeUnknown
};

// Update strategies
typedef NS_ENUM(NSInteger, UpdateStrategy) {
  UpdateStrategyInterval = 0,  // Update at fixed intervals
  UpdateStrategyScheduled,     // Update at specific times
  UpdateStrategyManual,        // Only update on demand
  UpdateStrategyPush           // Update on push notification
};

// Forward declarations
@class RuleSource;
@class CacheConfiguration;
@class UpdateConfiguration;

#pragma mark - Main Configuration

@interface DNSConfiguration : NSObject <NSCoding, NSSecureCoding>

// Rule sources
@property(nonatomic, strong) NSArray<RuleSource*>* ruleSources;

// Transition state tracking - allows saving configurations during startup/restart
@property(nonatomic, assign) BOOL isTransitionState;

// Update settings
@property(nonatomic, strong) UpdateConfiguration* updateConfig;

// Cache settings
@property(nonatomic, strong) CacheConfiguration* cacheConfig;

// DNS settings
@property(nonatomic, strong) NSArray<NSString*>* upstreamDNSServers;
@property(nonatomic, assign) NSTimeInterval dnsTimeout;

// General settings
@property(nonatomic, assign) BOOL offlineMode;
@property(nonatomic, assign) BOOL debugLogging;
@property(nonatomic, strong) NSString* logLevel;

// Managed mode settings
@property(nonatomic, assign) BOOL isManagedByProfile;
@property(nonatomic, assign) BOOL allowRuleEditing;

// WebSocket settings
@property(nonatomic, assign) BOOL webSocketEnabled;
@property(nonatomic, assign) int webSocketPort;
@property(nonatomic, strong, nullable) NSString* webSocketAuthToken;

// Manifest settings
@property(nonatomic, strong, nullable) NSString* manifestURL;
@property(nonatomic, assign) int manifestUpdateInterval;

// Telemetry settings
@property(nonatomic, assign) BOOL telemetryEnabled;
@property(nonatomic, strong, nullable) NSString* telemetryServerURL;
@property(nonatomic, strong, nullable) NSString* telemetryHECToken;

// HTTP settings
@property(nonatomic, strong, nullable) NSDictionary* additionalHttpHeaders;

// VPN settings
@property(nonatomic, assign) BOOL enableDNSChainPreservation;
@property(nonatomic, strong, nullable) NSArray<NSString*>* vpnResolvers;

// Create default configuration
+ (instancetype)defaultConfiguration;

// Validate configuration
- (BOOL)isValid:(NSError**)error;

// Merge with another configuration (for updates)
- (void)mergeWithConfiguration:(DNSConfiguration*)other;

@end

#pragma mark - Rule Source

@interface RuleSource : NSObject <NSCoding, NSSecureCoding>

@property(nonatomic, strong) NSString* identifier;
@property(nonatomic, strong) NSString* name;
@property(nonatomic, assign) RuleSourceType type;
@property(nonatomic, strong) NSString* format;  // json, yaml, hosts
@property(nonatomic, strong) NSDictionary* configuration;
@property(nonatomic, assign) NSTimeInterval updateInterval;
@property(nonatomic, assign) NSInteger priority;  // Higher = more important
@property(nonatomic, assign) BOOL enabled;

// Type-specific configurations
@property(nonatomic, strong, nullable) NSString* url;          // HTTPS
@property(nonatomic, strong, nullable) NSString* bucket;       // S3
@property(nonatomic, strong, nullable) NSString* region;       // S3
@property(nonatomic, strong, nullable) NSString* path;         // S3/File
@property(nonatomic, strong, nullable) NSString* apiKey;       // HTTPS
@property(nonatomic, strong, nullable) NSString* accessKeyId;  // S3
@property(nonatomic, strong, nullable) NSString* secretKey;    // S3

// Validate source configuration
- (BOOL)isValid:(NSError**)error;

// Create source from dictionary
+ (nullable instancetype)sourceFromDictionary:(NSDictionary*)dict;

// Export to dictionary
- (NSDictionary*)toDictionary;

@end

#pragma mark - Cache Configuration

@interface CacheConfiguration : NSObject <NSCoding, NSSecureCoding, NSCopying>

@property(nonatomic, strong) NSString* cacheDirectory;
@property(nonatomic, assign) NSUInteger maxCacheSize;         // In bytes
@property(nonatomic, assign) NSTimeInterval defaultTTL;       // Cache TTL
@property(nonatomic, assign) NSUInteger maxMemoryCacheSize;   // In bytes
@property(nonatomic, assign) BOOL persistCache;               // Save to disk
@property(nonatomic, assign) NSTimeInterval cleanupInterval;  // Cleanup frequency

+ (instancetype)defaultCacheConfiguration;

@end

#pragma mark - Update Configuration

@interface UpdateConfiguration : NSObject <NSCoding, NSSecureCoding>

@property(nonatomic, assign) UpdateStrategy strategy;
@property(nonatomic, assign) NSTimeInterval interval;             // For interval strategy
@property(nonatomic, strong) NSArray<NSString*>* scheduledTimes;  // For scheduled strategy
@property(nonatomic, assign) NSUInteger maxRetries;
@property(nonatomic, assign) NSTimeInterval retryDelay;
@property(nonatomic, assign) BOOL updateOnStart;
@property(nonatomic, assign) BOOL updateOnNetworkChange;

+ (instancetype)defaultUpdateConfiguration;

@end

#pragma mark - Configuration Manager

@interface ConfigurationManager : NSObject

// Singleton instance
+ (instancetype)sharedManager;

// Current configuration
@property(nonatomic, strong, readonly) DNSConfiguration* currentConfiguration;

// Load configuration from preferences
- (void)loadConfiguration;

// Save configuration to preferences
- (BOOL)saveConfiguration:(DNSConfiguration*)configuration error:(NSError**)error;

// Load configuration from file
- (nullable DNSConfiguration*)loadConfigurationFromFile:(NSString*)path error:(NSError**)error;

// Configuration change notifications
- (void)addConfigurationObserver:(id)observer selector:(SEL)selector;
- (void)removeConfigurationObserver:(id)observer;

// Configuration validation
- (BOOL)validateConfiguration:(DNSConfiguration*)configuration error:(NSError**)error;

// Get configuration for specific rule source
- (nullable RuleSource*)ruleSourceWithIdentifier:(NSString*)identifier;

// Manifest support
@property(nonatomic, assign, readonly) BOOL isUsingManifest;
@property(nonatomic, strong, readonly, nullable) NSString* currentManifestIdentifier;

// Check if manifest mode is enabled
- (BOOL)shouldUseManifest;

// Set manifest identifier to use
- (void)setManifestIdentifier:(NSString*)identifier;

// Convert current configuration to manifest format
- (nullable NSDictionary*)exportConfigurationAsManifest;

// Create configuration from resolved manifest
- (nullable DNSConfiguration*)configurationFromResolvedManifest:
    (DNSResolvedManifest*)resolvedManifest;

@end

// Notifications
extern NSString* const DNSConfigurationDidChangeNotification;
extern NSString* const DNSConfigurationChangeReasonKey;

// Error domain
extern NSString* const DNSConfigurationErrorDomain;

// Error codes
typedef NS_ENUM(NSInteger, DNSConfigurationError) {
  DNSConfigurationErrorInvalid = 1000,
  DNSConfigurationErrorMissingRequired,
  DNSConfigurationErrorInvalidRuleSource,
  DNSConfigurationErrorInvalidCacheSettings,
  DNSConfigurationErrorInvalidUpdateSettings,
  DNSConfigurationErrorSaveFailed
};

NS_ASSUME_NONNULL_END
