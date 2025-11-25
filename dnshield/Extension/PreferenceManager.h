//
//  PreferenceManager.h
//  DNShield Network Extension
//
//  Manages reading preferences from macOS preference domains using CFPreferences
//  Supports MDM-managed preferences and preference hierarchy
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, PreferenceLevel) {
  PreferenceLevelNone = 0,
  PreferenceLevelGlobal,  // /Library/Preferences/
  PreferenceLevelHost,    // /Library/Preferences/ByHost/
  PreferenceLevelUser,    // ~/Library/Preferences/
  PreferenceLevelManaged  // Managed by MDM
};

@interface PreferenceManager : NSObject

// Singleton instance
+ (instancetype)sharedManager;

// App Group shared defaults (for IPC between app and extension)
@property(nonatomic, readonly) NSUserDefaults* sharedDefaults;

// Convenience methods for common preferences
- (nullable id)preferenceValueForKey:(NSString*)key;
- (nullable id)preferenceForKey:(NSString*)key;  // Alias for preferenceValueForKey
- (void)setPreferenceValue:(nullable id)value forKey:(NSString*)key;

// Read preference value for key in domain
- (nullable id)preferenceValueForKey:(NSString*)key inDomain:(NSString*)domain;

// Read preference with specific user/host combination
- (nullable id)preferenceValueForKey:(NSString*)key
                            inDomain:(NSString*)domain
                             forUser:(nullable NSString*)userName
                             forHost:(BOOL)hostSpecific;

// Get all preferences for a domain
- (nullable NSDictionary*)allPreferencesForDomain:(NSString*)domain;

// Determine where a preference is defined
- (PreferenceLevel)preferenceLevelForKey:(NSString*)key inDomain:(NSString*)domain;

// Get the file path where preference is stored
- (nullable NSString*)preferenceFilePathForKey:(NSString*)key inDomain:(NSString*)domain;

// Check if preference is managed by MDM
- (BOOL)isPreferenceManagedForKey:(NSString*)key inDomain:(NSString*)domain;

// Synchronize preferences (force reload from disk)
- (void)synchronizePreferencesForDomain:(NSString*)domain;

// Set preference value (writes to /Library/Preferences)
- (void)setPreferenceValue:(nullable id)value forKey:(NSString*)key inDomain:(NSString*)domain;

// Get preference with default value
- (nullable id)preferenceValueForKey:(NSString*)key
                            inDomain:(NSString*)domain
                        defaultValue:(nullable id)defaultValue;

// Get preference level description (for debugging)
- (NSString*)preferenceLevelDescriptionForKey:(NSString*)key inDomain:(NSString*)domain;

// DNShield specific preferences
- (nullable NSArray<NSString*>*)blockedDomains;
- (nullable NSArray<NSString*>*)whitelistedDomains;
- (nullable NSDictionary*)ruleSourceConfiguration;
- (NSTimeInterval)updateInterval;
- (nullable NSString*)cacheDirectory;

@end

// Preference domain is now defined in DNShieldPreferences.h

NS_ASSUME_NONNULL_END
