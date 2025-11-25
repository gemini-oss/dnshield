//
//  DNSManifest.h
//  DNShield Network Extension
//
//  Manifest-based configuration system inspired by Munki
//  Provides hierarchical, conditional rule management
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Forward declarations
@class RuleSource;
@class DNSConditionalItem;
@class DNSManifestMetadata;

#pragma mark - DNS Manifest

@interface DNSManifest : NSObject <NSSecureCoding, NSCopying>

// Identification
@property(nonatomic, strong, readonly) NSString* identifier;
@property(nonatomic, strong, nullable, readonly) NSString* displayName;

// Manifest hierarchy
@property(nonatomic, strong, readonly) NSArray<NSString*>* includedManifests;

// Rule sources
@property(nonatomic, strong, readonly) NSArray<RuleSource*>* ruleSources;

// Direct rules in manifest
@property(nonatomic, strong, readonly)
    NSDictionary<NSString*, NSArray<NSString*>*>* managedRules;  // @{@"block": @[], @"allow": @[]}

// Conditional items
@property(nonatomic, strong, readonly) NSArray<DNSConditionalItem*>* conditionalItems;

// Metadata
@property(nonatomic, strong, readonly) DNSManifestMetadata* metadata;

// Version info
@property(nonatomic, strong, readonly) NSString* manifestVersion;

// Initialize from dictionary (parsed from YAML/JSON)
- (nullable instancetype)initWithDictionary:(NSDictionary*)dictionary error:(NSError**)error;

// Initialize programmatically
- (instancetype)initWithIdentifier:(NSString*)identifier
                       displayName:(nullable NSString*)displayName
                 includedManifests:(NSArray<NSString*>*)includedManifests
                       ruleSources:(NSArray<RuleSource*>*)ruleSources
                      managedRules:(NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules
                  conditionalItems:(NSArray<DNSConditionalItem*>*)conditionalItems
                          metadata:(DNSManifestMetadata*)metadata NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Validation
- (BOOL)validateWithError:(NSError**)error;

// Export
- (NSDictionary*)toDictionary;

@end

#pragma mark - Conditional Item

@interface DNSConditionalItem : NSObject <NSSecureCoding, NSCopying>

// Predicate condition to evaluate
@property(nonatomic, strong, readonly) NSString* condition;

// Items to apply if condition is true
@property(nonatomic, strong, nullable, readonly)
    NSDictionary<NSString*, NSArray<NSString*>*>* managedRules;
@property(nonatomic, strong, nullable, readonly) NSArray<RuleSource*>* ruleSources;
@property(nonatomic, strong, nullable, readonly) NSArray<NSString*>* includedManifests;

- (instancetype)initWithCondition:(NSString*)condition
                     managedRules:
                         (nullable NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules
                      ruleSources:(nullable NSArray<RuleSource*>*)ruleSources
                includedManifests:(nullable NSArray<NSString*>*)includedManifests
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Initialize from dictionary
- (nullable instancetype)initWithDictionary:(NSDictionary*)dictionary error:(NSError**)error;

// Validation
- (BOOL)validateWithError:(NSError**)error;

// Export
- (NSDictionary*)toDictionary;

@end

#pragma mark - Manifest Metadata

@interface DNSManifestMetadata : NSObject <NSSecureCoding, NSCopying>

@property(nonatomic, strong, nullable, readonly) NSString* author;
@property(nonatomic, strong, nullable, readonly) NSString* manifestDescription;
@property(nonatomic, strong, nullable, readonly) NSDate* lastModified;
@property(nonatomic, strong, nullable, readonly) NSString* version;
@property(nonatomic, strong, nullable, readonly) NSDictionary* customFields;

- (instancetype)initWithAuthor:(nullable NSString*)author
                   description:(nullable NSString*)description
                  lastModified:(nullable NSDate*)lastModified
                       version:(nullable NSString*)version
                  customFields:(nullable NSDictionary*)customFields NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Initialize from dictionary
- (nullable instancetype)initWithDictionary:(NSDictionary*)dictionary;

// Export
- (NSDictionary*)toDictionary;

@end

#pragma mark - Resolved Manifest

// Result of resolving a manifest hierarchy
@interface DNSResolvedManifest : NSObject

// Original manifest that was resolved
@property(nonatomic, strong, readonly) DNSManifest* primaryManifest;

// All manifests in resolution order
@property(nonatomic, strong, readonly) NSArray<DNSManifest*>* manifestChain;

// Merged rule sources (with priority resolution)
@property(nonatomic, strong, readonly) NSArray<RuleSource*>* resolvedRuleSources;

// Merged managed rules
@property(nonatomic, strong, readonly)
    NSDictionary<NSString*, NSArray<NSString*>*>* resolvedManagedRules;

// Timestamp of resolution
@property(nonatomic, strong, readonly) NSDate* resolvedAt;

// Any errors during resolution (non-fatal)
@property(nonatomic, strong, readonly) NSArray<NSError*>* warnings;

@end

#pragma mark - Error Domain and Codes

extern NSString* const DNSManifestErrorDomain;

typedef NS_ENUM(NSInteger, DNSManifestError) {
  DNSManifestErrorInvalidFormat = 1000,
  DNSManifestErrorMissingRequired,
  DNSManifestErrorInvalidVersion,
  DNSManifestErrorCircularDependency,
  DNSManifestErrorManifestNotFound,
  DNSManifestErrorInvalidCondition,
  DNSManifestErrorValidationFailed,
  DNSManifestErrorTimeout
};

NS_ASSUME_NONNULL_END
