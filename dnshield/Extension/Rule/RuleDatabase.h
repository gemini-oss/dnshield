//
//  RuleDatabase.h
//  DNShield Network Extension
//
//  SQLite-based rule storage inspired by Santa
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Notification sent when rules are modified directly in database
extern NSString* const RuleDatabaseDidChangeNotification;

// Rule action types
typedef NS_ENUM(NSInteger, DNSRuleAction) {
  DNSRuleActionBlock = 0,
  DNSRuleActionAllow = 1,
  DNSRuleActionUnknown = -1  // Used for cache misses
};

// Rule match types
typedef NS_ENUM(NSInteger, DNSRuleType) {
  DNSRuleTypeExact = 0,     // Exact domain match
  DNSRuleTypeWildcard = 1,  // *.example.com style
  DNSRuleTypeRegex = 2      // Regular expression
};

// Rule source types
typedef NS_ENUM(NSInteger, DNSRuleSource) {
  DNSRuleSourceUser = 0,      // User-defined
  DNSRuleSourceManifest = 1,  // From manifest
  DNSRuleSourceRemote = 2,    // Remote update
  DNSRuleSourceSystem = 3     // System default
};

@interface DNSRule : NSObject
@property(nonatomic, strong) NSString* domain;
@property(nonatomic, assign) DNSRuleAction action;
@property(nonatomic, assign) DNSRuleType type;
@property(nonatomic, assign) NSInteger priority;
@property(nonatomic, assign) DNSRuleSource source;
@property(nonatomic, strong, nullable) NSString* customMessage;
@property(nonatomic, strong, nullable) NSDate* updatedAt;
@property(nonatomic, strong, nullable) NSDate* expiresAt;
@property(nonatomic, strong, nullable) NSString* comment;

+ (instancetype)ruleWithDomain:(NSString*)domain action:(DNSRuleAction)action;
- (BOOL)matchesDomain:(NSString*)domain;
@end

@interface RuleDatabase : NSObject

@property(nonatomic, readonly) NSString* databasePath;
@property(nonatomic, readonly) NSUInteger ruleCount;
@property(nonatomic, readonly) NSDate* lastUpdated;

// Singleton instance
+ (instancetype)sharedDatabase;

// Database operations
- (BOOL)openDatabase;
- (void)closeDatabase;
- (BOOL)createTablesIfNeeded;

// Rule management
- (BOOL)addRule:(DNSRule*)rule error:(NSError**)error;
- (BOOL)addRules:(NSArray<DNSRule*>*)rules error:(NSError**)error;
- (BOOL)removeRuleForDomain:(NSString*)domain error:(NSError**)error;
- (BOOL)removeAllRulesFromSource:(DNSRuleSource)source error:(NSError**)error;
- (BOOL)removeExpiredRules:(NSError**)error;

// Rule queries
- (nullable DNSRule*)ruleForDomain:(NSString*)domain;
- (void)ruleForDomainAsync:(NSString*)domain
                completion:(void (^)(DNSRule* _Nullable rule))completion;
- (NSArray<DNSRule*>*)allRules;
- (NSArray<DNSRule*>*)rulesFromSource:(DNSRuleSource)source;
- (NSArray<DNSRule*>*)blockedDomains;
- (NSArray<DNSRule*>*)allowedDomains;

// Batch operations
- (BOOL)replaceAllRulesFromSource:(DNSRuleSource)source
                        withRules:(NSArray<DNSRule*>*)rules
                            error:(NSError**)error;

// Transaction support
- (BOOL)beginTransaction;
- (BOOL)commitTransaction;
- (BOOL)rollbackTransaction;

// Maintenance
- (BOOL)vacuum;
- (NSUInteger)databaseSizeInBytes;

// Query statistics for cache warming
- (void)recordQueryForDomain:(NSString*)domain;
- (NSArray<NSString*>*)mostQueriedDomains:(NSUInteger)limit;
- (NSUInteger)queryCountForDomain:(NSString*)domain;
- (void)cleanupOldQueryStats:(NSTimeInterval)olderThan;

@end

NS_ASSUME_NONNULL_END
