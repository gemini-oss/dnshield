//
//  DNSManifestResolver.h
//  DNShield Network Extension
//
//  Resolves manifest hierarchies and conditional items
//

#import <Foundation/Foundation.h>
#import "PreferenceManager.h"

NS_ASSUME_NONNULL_BEGIN

@class DNSManifest;
@class DNSResolvedManifest;
@class DNSEvaluationContext;

typedef void (^DNSManifestFetchCompletion)(DNSManifest* _Nullable manifest,
                                           NSError* _Nullable error);

@protocol DNSManifestResolverDelegate <NSObject>
@optional
- (void)manifestResolver:(id)resolver didStartResolvingManifest:(NSString*)identifier;
- (void)manifestResolver:(id)resolver didResolveManifest:(NSString*)identifier;
- (void)manifestResolver:(id)resolver
    didFailToResolveManifest:(NSString*)identifier
                       error:(NSError*)error;
- (void)manifestResolver:(id)resolver
     didEncounterWarning:(NSError*)warning
             forManifest:(NSString*)identifier;
@end

@interface DNSManifestResolver : NSObject

@property(nonatomic, weak) id<DNSManifestResolverDelegate> delegate;

// Search paths for manifest files
@property(nonatomic, strong) NSArray<NSString*>* manifestSearchPaths;

// Evaluation context for conditional items
@property(nonatomic, strong) DNSEvaluationContext* evaluationContext;

// Cache settings
@property(nonatomic, assign) BOOL enableCaching;
@property(nonatomic, assign) NSTimeInterval cacheTimeout;

// Initialize with default search paths
- (instancetype)init;

// Initialize with custom search paths
- (instancetype)initWithSearchPaths:(NSArray<NSString*>*)searchPaths NS_DESIGNATED_INITIALIZER;

// Testing/advanced initializer: inject a custom cache directory for on-disk manifest caching
- (instancetype)initWithCacheDirectory:(NSString*)cacheDirectory;

// Resolve a manifest by identifier
- (nullable DNSResolvedManifest*)resolveManifest:(NSString*)identifier error:(NSError**)error;

// Resolve with fallback identifiers (serial number -> default)
- (nullable DNSResolvedManifest*)resolveManifestWithFallback:(NSString*)initialIdentifier
                                                       error:(NSError**)error;

// Async resolution
- (void)resolveManifestAsync:(NSString*)identifier
                  completion:(void (^)(DNSResolvedManifest* _Nullable resolved,
                                       NSError* _Nullable error))completion;

// Clear cache
- (void)clearCache;
- (void)clearCacheForManifest:(NSString*)identifier;

// Check if manifest exists
- (BOOL)manifestExists:(NSString*)identifier;

// Get manifest without resolving includes
- (nullable DNSManifest*)getManifest:(NSString*)identifier error:(NSError**)error;

// Pre-cache manifests
- (void)preCacheManifests:(NSArray<NSString*>*)identifiers;

// Determine client identifier for manifest selection
+ (NSString*)determineClientIdentifierWithPreferenceManager:(PreferenceManager*)prefs;
+ (NSString*)getMachineSerialNumber;

@end

#pragma mark - Evaluation Context

@interface DNSEvaluationContext : NSObject

// System properties
@property(nonatomic, strong) NSString* osVersion;
@property(nonatomic, strong) NSString* deviceType;
@property(nonatomic, strong) NSString* deviceModel;

// Network properties
@property(nonatomic, strong) NSString* networkLocation;  // home/office/public
@property(nonatomic, strong, nullable) NSString* networkSSID;
@property(nonatomic, assign) BOOL vpnConnected;
@property(nonatomic, strong, nullable) NSString* vpnIdentifier;

// Time properties
@property(nonatomic, strong) NSDate* currentDate;
@property(nonatomic, strong) NSString* timeOfDay;  // HH:mm format
@property(nonatomic, strong) NSString* dayOfWeek;  // Monday, Tuesday, etc.
@property(nonatomic, assign) BOOL isWeekend;

// User/device properties
@property(nonatomic, strong, nullable) NSString* userGroup;
@property(nonatomic, strong, nullable) NSString* deviceIdentifier;
@property(nonatomic, strong, nullable) NSNumber* securityScore;

// Custom properties
@property(nonatomic, strong) NSMutableDictionary<NSString*, id>* customProperties;

// Create default context with system values
+ (instancetype)defaultContext;

// Update time-based properties
- (void)updateTimeProperties;

// Get all properties as dictionary for predicate evaluation
- (NSDictionary*)allProperties;

// Set custom property
- (void)setCustomProperty:(id)value forKey:(NSString*)key;

@end

#pragma mark - Manifest Cache

@interface DNSManifestCache : NSObject

- (nullable DNSManifest*)manifestForIdentifier:(NSString*)identifier;
- (nullable DNSManifest*)manifestForIdentifier:(NSString*)identifier
                                  allowExpired:(BOOL)allowExpired
                                    wasExpired:(BOOL*)wasExpired;
- (void)cacheManifest:(DNSManifest*)manifest forIdentifier:(NSString*)identifier;
- (void)removeManifestForIdentifier:(NSString*)identifier;
- (void)removeAllManifests;
- (NSArray<NSString*>*)cachedIdentifiers;

@end

NS_ASSUME_NONNULL_END
