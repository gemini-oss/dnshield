//
//  DNShieldPreferences.h
//  DNShield Network Extension
//
//  Defines all preference keys and default values used by DNShield
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Preference Keys
extern NSString* const kDNShieldAdditionalHttpHeaders;
extern NSString* const kDNShieldBlockedDomains;
extern NSString* const kDNShieldBypassPassword;
extern NSString* const kDNShieldCacheDirectory;
extern NSString* const kDNShieldClientIdentifier;
extern NSString* const kDNShieldEnableWebSocketServer;
extern NSString* const kDNShieldLogLevel;
extern NSString* const kDNShieldManifestURL;
extern NSString* const kDNShieldRuleSources;
extern NSString* const kDNShieldS3AccessKeyId;
extern NSString* const kDNShieldS3SecretAccessKey;
extern NSString* const kDNShieldSoftwareRepoURL;
extern NSString* const kDNShieldUpdateInterval;
extern NSString* const kDNShieldWhitelistedDomains;
extern NSString* const kDNShieldDefaultManifestIdentifier;
extern NSString* const kDNShieldManifestUpdateInterval;
extern NSString* const kDNShieldVPNResolvers;
extern NSString* const kDNShieldEnableDNSChainPreservation;
extern NSString* const kDNShieldCacheBypassDomains;
extern NSString* const kDNShieldEnableDNSCache;
extern NSString* const kDNShieldDomainCacheRules;
extern NSString* const kDNShieldUserCanAdjustCacheTTL;
extern NSString* const kDNShieldUserCanAdjustCache;
extern NSString* const kDNShieldManifestFormat;
extern NSString* const kDNShieldWebSocketPort;
extern NSString* const kDNShieldWebSocketAuthToken;
extern NSString* const kDNShieldWebSocketRetryBackoff;
extern NSString* const kDNShieldChromeExtensionIDs;

// DNS Interface Binding Feature
extern NSString* const kDNShieldEnableDNSInterfaceBinding;
extern NSString* const kDNShieldBindInterfaceStrategy;
extern NSString* const kDNShieldStickyInterfacePerTransaction;
extern NSString* const kDNShieldMaxRetries;
extern NSString* const kDNShieldInitialBackoffMs;
extern NSString* const kDNShieldVerboseTelemetry;
extern NSString* const kDNShieldConfigurationArchiveKey;

// Telemetry Preferences
extern NSString* const kDNShieldTelemetryEnabled;
extern NSString* const kDNShieldTelemetryServerURL;
extern NSString* const kDNShieldTelemetryPrivacyLevel;
extern NSString* const kDNShieldTelemetryHECToken;

// Default Values
@interface DNShieldPreferences : NSObject

+ (NSDictionary*)defaultPreferences;
+ (nullable id)defaultValueForKey:(NSString*)key;
+ (BOOL)boolDefaultForKey:(NSString*)key fallback:(BOOL)fallback;
+ (NSInteger)integerDefaultForKey:(NSString*)key fallback:(NSInteger)fallback;
+ (nullable NSString*)stringDefaultForKey:(NSString*)key;
+ (NSArray*)arrayDefaultForKey:(NSString*)key;

@end

// Unified preference accessors for DNShield keys.
FOUNDATION_EXPORT id _Nullable DNPreferenceCopyValue(NSString* key);
FOUNDATION_EXPORT BOOL DNPreferenceGetBool(NSString* key, BOOL fallback);
FOUNDATION_EXPORT NSInteger DNPreferenceGetInteger(NSString* key, NSInteger fallback);
FOUNDATION_EXPORT double DNPreferenceGetDouble(NSString* key, double fallback);
FOUNDATION_EXPORT NSArray* _Nullable DNPreferenceGetArray(NSString* key);
FOUNDATION_EXPORT NSDictionary* _Nullable DNPreferenceGetDictionary(NSString* key);
FOUNDATION_EXPORT void DNPreferenceSetValue(NSString* key, id _Nullable value);
FOUNDATION_EXPORT void DNPreferenceSetBool(NSString* key, BOOL value);
FOUNDATION_EXPORT void DNPreferenceSetInteger(NSString* key, NSInteger value);
FOUNDATION_EXPORT void DNPreferenceSetDouble(NSString* key, double value);
FOUNDATION_EXPORT void DNPreferenceRemoveValue(NSString* key);
FOUNDATION_EXPORT BOOL DNPreferenceHasUserValue(NSString* key);
FOUNDATION_EXPORT BOOL DNPreferenceIsManaged(NSString* key);
FOUNDATION_EXPORT void DNPreferenceMirrorLegacyDomainToAppGroup(void);

FOUNDATION_EXPORT NSUserDefaults* DNSharedDefaults(void);
FOUNDATION_EXPORT BOOL DNPreferenceDomainSynchronize(NSString* domain);
FOUNDATION_EXPORT BOOL DNPreferenceAppSynchronize(NSString* domain);
FOUNDATION_EXPORT BOOL DNPreferenceAppGroupSynchronize(void);

NS_ASSUME_NONNULL_END
