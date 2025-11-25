//
//  RuleSet.h
//  DNShield Network Extension
//
//  Common output format for all rule parsers
//  Represents a collection of DNS filtering rules with metadata
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Rule Types

// Type of rule action
typedef NS_ENUM(NSInteger, RuleAction) {
  RuleActionBlock = 0,  // Block the domain
  RuleActionAllow,      // Allow the domain (whitelist)
  RuleActionRedirect,   // Redirect to another IP (future use)
  RuleActionMonitor     // Monitor but don't block (future use)
};

// Rule priority for conflict resolution
typedef NS_ENUM(NSInteger, RulePriority) {
  RulePriorityLow = 0,
  RulePriorityMedium = 50,
  RulePriorityHigh = 100,
  RulePriorityOverride = 999  // User-defined overrides
};

#pragma mark - Rule Entry

@interface RuleEntry : NSObject <NSCopying, NSSecureCoding>

@property(nonatomic, readonly)
    NSString* domain;  // Domain pattern (e.g., "ads.example.com", "*.tracking.com")
@property(nonatomic, readonly) RuleAction action;            // What to do with this domain
@property(nonatomic, readonly) RulePriority priority;        // Priority for conflict resolution
@property(nonatomic, nullable, readonly) NSString* comment;  // Optional comment/reason
@property(nonatomic, nullable, readonly) NSDate* addedDate;  // When the rule was added
@property(nonatomic, nullable, readonly) NSString* source;   // Which list this came from

- (instancetype)initWithDomain:(NSString*)domain
                        action:(RuleAction)action
                      priority:(RulePriority)priority
                       comment:(nullable NSString*)comment
                     addedDate:(nullable NSDate*)addedDate
                        source:(nullable NSString*)source NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Convenience initializers
+ (instancetype)blockRuleForDomain:(NSString*)domain;
+ (instancetype)allowRuleForDomain:(NSString*)domain;

// Check if this rule matches a given domain
- (BOOL)matchesDomain:(NSString*)domain;

// Check if this is a wildcard rule
- (BOOL)isWildcard;

@end

#pragma mark - Rule Set Metadata

@interface RuleSetMetadata : NSObject <NSCopying, NSSecureCoding>

@property(nonatomic, nullable, readonly) NSString* name;              // Name of the rule set
@property(nonatomic, nullable, readonly) NSString* version;           // Version string
@property(nonatomic, nullable, readonly) NSDate* updatedDate;         // Last update time
@property(nonatomic, nullable, readonly) NSString* author;            // Author/maintainer
@property(nonatomic, nullable, readonly) NSString* sourceURL;         // Where it came from
@property(nonatomic, nullable, readonly) NSString* description;       // Description of the list
@property(nonatomic, nullable, readonly) NSString* license;           // License information
@property(nonatomic, nullable, readonly) NSDictionary* customFields;  // Any additional metadata

- (instancetype)initWithName:(nullable NSString*)name
                     version:(nullable NSString*)version
                 updatedDate:(nullable NSDate*)updatedDate
                      author:(nullable NSString*)author
                   sourceURL:(nullable NSString*)sourceURL
                 description:(nullable NSString*)description
                     license:(nullable NSString*)license
                customFields:(nullable NSDictionary*)customFields NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Convenience initializer with common fields
+ (instancetype)metadataWithName:(NSString*)name version:(NSString*)version;

@end

#pragma mark - Rule Statistics

@interface RuleSetStatistics : NSObject

@property(nonatomic, readonly) NSUInteger totalRules;      // Total number of rules
@property(nonatomic, readonly) NSUInteger blockRules;      // Number of block rules
@property(nonatomic, readonly) NSUInteger allowRules;      // Number of allow rules
@property(nonatomic, readonly) NSUInteger wildcardRules;   // Number of wildcard rules
@property(nonatomic, readonly) NSUInteger uniqueDomains;   // Number of unique domains
@property(nonatomic, readonly) NSUInteger duplicateRules;  // Number of duplicate rules found
@property(nonatomic, readonly) NSUInteger invalidRules;    // Number of invalid rules skipped

- (instancetype)initWithRules:(NSArray<RuleEntry*>*)rules NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

#pragma mark - Main Rule Set

@interface RuleSet : NSObject <NSCopying, NSSecureCoding>

@property(nonatomic, readonly) NSArray<RuleEntry*>* rules;     // All rules in the set
@property(nonatomic, readonly) RuleSetMetadata* metadata;      // Metadata about the set
@property(nonatomic, readonly) RuleSetStatistics* statistics;  // Statistics about the rules
@property(nonatomic, readonly) NSDate* parseDate;              // When this was parsed

// Initialize with rules and metadata
- (instancetype)initWithRules:(NSArray<RuleEntry*>*)rules
                     metadata:(RuleSetMetadata*)metadata NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Query methods
- (nullable RuleEntry*)ruleForDomain:(NSString*)domain;  // Find the highest priority matching rule
- (NSArray<RuleEntry*>*)rulesForDomain:(NSString*)domain;  // Find all matching rules
- (BOOL)shouldBlockDomain:(NSString*)domain;  // Quick check if domain should be blocked

// Filtering and manipulation
- (RuleSet*)ruleSetByFilteringWithPredicate:(NSPredicate*)predicate;
- (RuleSet*)ruleSetByMergingWithRuleSet:(RuleSet*)otherRuleSet;
- (RuleSet*)ruleSetByRemovingDuplicates;

// Export methods
- (nullable NSData*)exportToJSONWithError:(NSError**)error;
- (nullable NSDictionary*)exportToDictionary;

// Validation
- (BOOL)validateWithError:(NSError**)error;

// Performance optimization
- (void)buildIndex;  // Pre-build internal indexes for faster lookups

@end

#pragma mark - Rule Set Merge Options

typedef NS_OPTIONS(NSUInteger, RuleSetMergeOptions) {
  RuleSetMergeOptionNone = 0,
  RuleSetMergeOptionPreferHigherPriority = 1 << 0,  // Keep higher priority rules on conflict
  RuleSetMergeOptionPreferNewer = 1 << 1,           // Keep newer rules on conflict
  RuleSetMergeOptionKeepDuplicates = 1 << 2,        // Don't remove duplicates
  RuleSetMergeOptionCombineMetadata = 1 << 3        // Merge metadata fields
};

// Rule set merging utility
@interface RuleSetMerger : NSObject

+ (RuleSet*)mergeRuleSets:(NSArray<RuleSet*>*)ruleSets
                  options:(RuleSetMergeOptions)options
                    error:(NSError**)error;

@end

NS_ASSUME_NONNULL_END
