//
//  Manager+Manifest.h
//  DNShield Network Extension
//
//  Manifest support for RuleManager
//

#import "Manager.h"

NS_ASSUME_NONNULL_BEGIN

@class DNSManifest;
@class DNSManifestResolver;
@class DNSResolvedManifest;

@interface RuleManager (Manifest)

// Manifest support
@property(nonatomic, strong, readonly, nullable) DNSManifestResolver* manifestResolver;
@property(nonatomic, strong, readonly, nullable) DNSResolvedManifest* currentResolvedManifest;
@property(nonatomic, strong, readonly, nullable) NSString* currentManifestIdentifier;

// Initialize with manifest
- (instancetype)initWithManifestIdentifier:(NSString*)manifestIdentifier;

// Load manifest
- (BOOL)loadManifest:(NSString*)manifestIdentifier error:(NSError**)error;
- (void)loadManifestAsync:(NSString*)manifestIdentifier
               completion:(void (^)(BOOL success, NSError* _Nullable error))completion;

// Reload current manifest
- (void)reloadManifestIfNeeded;

// Update evaluation context for conditional items
- (void)updateManifestContext:(NSDictionary*)contextUpdates;

// Check if using manifest-based configuration
- (BOOL)isUsingManifest;

// Convert legacy configuration to manifest
- (nullable DNSManifest*)convertConfigurationToManifest:(DNSConfiguration*)configuration;

// Manifest update timer management (internal use)
- (void)startManifestUpdateTimer;
- (void)stopManifestUpdateTimer;

// Manifest identifier resolution
- (NSString*)determineManifestIdentifier;

// Rule updates from manifest
- (void)updateRulesFromCurrentManifest;

@end

NS_ASSUME_NONNULL_END
