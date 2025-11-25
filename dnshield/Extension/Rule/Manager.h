//
//  Manager.h
//  DNShield Network Extension
//
//  Main orchestration class for rule management
//  Coordinates fetchers, parsers, cache, and provides unified rule access
//

#import <Foundation/Foundation.h>
#import "UpdateScheduler.h"

NS_ASSUME_NONNULL_BEGIN

// Forward declarations
@class RuleSet;
@class RuleSource;
@class DNSConfiguration;
@class RuleCache;
@protocol RuleManagerDelegate;

// Rule manager state
typedef NS_ENUM(NSInteger, RuleManagerState) {
  RuleManagerStateStopped = 0,
  RuleManagerStateStarting,
  RuleManagerStateRunning,
  RuleManagerStateStopping,
  RuleManagerStateError
};

// Update result
@interface RuleUpdateResult : NSObject

@property(nonatomic, strong, readonly) RuleSource* source;
@property(nonatomic, strong, nullable, readonly) RuleSet* ruleSet;
@property(nonatomic, strong, nullable, readonly) NSError* error;
@property(nonatomic, readonly) BOOL success;
@property(nonatomic, readonly) BOOL fromCache;
@property(nonatomic, strong, readonly) NSDate* timestamp;
@property(nonatomic, readonly) NSTimeInterval fetchDuration;
@property(nonatomic, readonly) NSTimeInterval parseDuration;
@property(nonatomic, readonly) NSUInteger ruleCount;

@end

#pragma mark - Rule Manager

@interface RuleManager : NSObject

// Delegate
@property(nonatomic, weak) id<RuleManagerDelegate> delegate;

// Current state
@property(nonatomic, readonly) RuleManagerState state;

// Current merged rule set
@property(nonatomic, strong, readonly, nullable) RuleSet* currentRuleSet;

// Last update information
@property(nonatomic, strong, readonly, nullable) NSDate* lastUpdateDate;
@property(nonatomic, strong, readonly, nullable) NSError* lastUpdateError;

// Initialize with configuration
- (instancetype)initWithConfiguration:(DNSConfiguration*)configuration;

// Start/stop management
- (void)startUpdating;
- (void)stopUpdating;

// Force update
- (void)forceUpdate;
- (void)forceUpdateSource:(RuleSource*)source;

// Query rule sources
- (NSArray<RuleSource*>*)allRuleSources;
- (nullable RuleSource*)ruleSourceWithIdentifier:(NSString*)identifier;

// Get rule set for specific source
- (nullable RuleSet*)ruleSetForSource:(RuleSource*)source;

// Update status
- (nullable RuleUpdateResult*)lastUpdateResultForSource:(RuleSource*)source;
- (NSArray<RuleUpdateResult*>*)recentUpdateResults;

// Cache management
- (void)clearCache;
- (void)clearCacheForSource:(RuleSource*)source;
- (NSUInteger)cacheSize;

// Statistics
@property(nonatomic, readonly) NSUInteger totalRuleCount;

@property(nonatomic, readonly) NSDictionary<NSString*, NSNumber*>* ruleCountBySource;

// Configuration updates
- (void)updateConfiguration:(DNSConfiguration*)configuration;

// Testing support
- (void)injectTestRuleSet:(RuleSet*)ruleSet forSource:(RuleSource*)source;

@end

#pragma mark - Rule Manager Delegate

@protocol RuleManagerDelegate <NSObject>

@required
// Called when rules are updated
- (void)ruleManagerDidUpdateRules:(RuleSet*)newRuleSet;

@optional
// Called when update fails
- (void)ruleManagerDidFailUpdate:(NSError*)error;

// Called for individual source updates
- (void)ruleManager:(RuleManager*)manager
    didUpdateSource:(RuleSource*)source
         withResult:(RuleUpdateResult*)result;

// State changes
- (void)ruleManagerDidStart:(RuleManager*)manager;
- (void)ruleManagerDidStop:(RuleManager*)manager;
- (void)ruleManager:(RuleManager*)manager didChangeState:(RuleManagerState)newState;

// Progress updates
- (void)ruleManager:(RuleManager*)manager
     updateProgress:(float)progress
          forSource:(RuleSource*)source;

// Cache events
- (void)ruleManager:(RuleManager*)manager didLoadFromCacheForSource:(RuleSource*)source;
- (void)ruleManagerDidClearCache:(RuleManager*)manager;

@end

NS_ASSUME_NONNULL_END
