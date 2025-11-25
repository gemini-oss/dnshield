//
//  UpdateStrategy.h
//  DNShield Network Extension
//
//  Defines different strategies for updating rule sets
//  Part of Stream 5: Scheduling implementation
//

#import <Foundation/Foundation.h>
#import "ConfigurationManager.h"

NS_ASSUME_NONNULL_BEGIN

// Update strategy types
typedef NS_ENUM(NSInteger, UpdateStrategyType) {
  UpdateStrategyTypeInterval,
  UpdateStrategyTypeScheduled,
  UpdateStrategyTypeManual,
  UpdateStrategyTypeDynamic
};

// Forward declarations
@class RuleSource;
@protocol UpdateStrategyDelegate;

#pragma mark - Update Strategy Protocol

@protocol UpdateStrategy <NSObject>

@required
// Strategy type
@property(nonatomic, readonly) UpdateStrategyType strategyType;

// Delegate for update events
@property(nonatomic, weak) id<UpdateStrategyDelegate> delegate;

// Start the update strategy
- (void)startWithConfiguration:(UpdateConfiguration*)configuration;

// Stop the update strategy
- (void)stop;

// Check if strategy is active
@property(nonatomic, readonly) BOOL isActive;

// Force an immediate update
- (void)triggerImmediateUpdate;

// Get next scheduled update time (if applicable)
- (nullable NSDate*)nextUpdateTime;

// Configure for a specific rule source
- (void)configureForRuleSource:(RuleSource*)source;

@optional
// Pause/resume for strategies that support it
- (void)pause;
- (void)resume;
@property(nonatomic, readonly) BOOL isPaused;

// Update history
@property(nonatomic, readonly) NSArray<NSDate*>* updateHistory;

// Statistics
@property(nonatomic, readonly) NSUInteger updateCount;
@property(nonatomic, readonly) NSDate* lastUpdateTime;

@end

#pragma mark - Update Strategy Delegate

@protocol UpdateStrategyDelegate <NSObject>

@required
// Called when strategy determines it's time to update
- (void)updateStrategy:(id<UpdateStrategy>)strategy shouldUpdateSource:(RuleSource*)source;

@optional
// Called when strategy scheduling changes
- (void)updateStrategy:(id<UpdateStrategy>)strategy didScheduleNextUpdateAt:(NSDate*)date;

// Called when strategy encounters an error
- (void)updateStrategy:(id<UpdateStrategy>)strategy didEncounterError:(NSError*)error;

// Called when strategy state changes
- (void)updateStrategyDidStart:(id<UpdateStrategy>)strategy;
- (void)updateStrategyDidStop:(id<UpdateStrategy>)strategy;
- (void)updateStrategyDidPause:(id<UpdateStrategy>)strategy;
- (void)updateStrategyDidResume:(id<UpdateStrategy>)strategy;

@end

#pragma mark - Base Update Strategy

@interface UpdateStrategyBase : NSObject <UpdateStrategy>

// Common properties
@property(nonatomic, weak) id<UpdateStrategyDelegate> delegate;
@property(nonatomic, strong) UpdateConfiguration* configuration;
@property(nonatomic, strong) RuleSource* ruleSource;
@property(nonatomic, strong) NSMutableArray<NSDate*>* updateHistory;
@property(nonatomic, strong) dispatch_queue_t strategyQueue;
@property(nonatomic, assign, readwrite) BOOL isActive;

// Subclasses must override
- (UpdateStrategyType)strategyType;
- (void)scheduleNextUpdate;
- (void)cancelScheduledUpdate;

// Helper methods for subclasses
- (void)notifyDelegateShouldUpdate;
- (void)notifyDelegateNextUpdateAt:(NSDate*)date;
- (void)notifyDelegateError:(NSError*)error;
- (void)recordUpdate;

@end

#pragma mark - Interval Update Strategy

@interface IntervalUpdateStrategy : UpdateStrategyBase

// Interval in seconds
@property(nonatomic, assign) NSTimeInterval updateInterval;

// Timer
@property(nonatomic, strong, nullable) dispatch_source_t updateTimer;

// Jitter to avoid thundering herd (random delay ± jitterPercent)
@property(nonatomic, assign) double jitterPercent;  // 0.0 - 1.0

@end

#pragma mark - Scheduled Update Strategy

@interface ScheduledUpdateStrategy : UpdateStrategyBase

// Scheduled times (e.g., "14:30", "02:00")
@property(nonatomic, strong) NSArray<NSString*>* scheduledTimes;

// Time zone for scheduled times
@property(nonatomic, strong) NSTimeZone* timeZone;

// Days of week to run (1=Sunday, 7=Saturday), nil = every day
@property(nonatomic, strong, nullable) NSArray<NSNumber*>* daysOfWeek;

// Next scheduled timer
@property(nonatomic, strong, nullable) dispatch_source_t scheduledTimer;

// Calculate next update time from scheduled times
- (nullable NSDate*)calculateNextScheduledTime;

@end

#pragma mark - Manual Update Strategy

@interface ManualUpdateStrategy : UpdateStrategyBase

// Last manual trigger time
@property(nonatomic, strong, nullable) NSDate* lastManualTrigger;

// Minimum interval between manual updates (to prevent abuse)
@property(nonatomic, assign) NSTimeInterval minimumInterval;

// Check if update can be triggered
- (BOOL)canTriggerUpdate;

@end

#pragma mark - Push Update Strategy

@interface PushUpdateStrategy : UpdateStrategyBase

// Push notification token/identifier
@property(nonatomic, strong, nullable) NSString* pushToken;

// Push notification endpoint
@property(nonatomic, strong, nullable) NSURL* pushEndpoint;

// Register for push notifications
- (void)registerForPushNotifications;

// Handle incoming push notification
- (void)handlePushNotification:(NSDictionary*)userInfo;

// Fallback interval if push fails
@property(nonatomic, assign) NSTimeInterval fallbackInterval;
@property(nonatomic, strong, nullable) dispatch_source_t fallbackTimer;

@end

#pragma mark - Adaptive Update Strategy

// Strategy that adapts based on update patterns and network conditions
@interface AdaptiveUpdateStrategy : UpdateStrategyBase

// Base interval that gets adjusted
@property(nonatomic, assign) NSTimeInterval baseInterval;

// Adjustment factors
@property(nonatomic, assign) double successMultiplier;    // Multiply interval on success
@property(nonatomic, assign) double failureMultiplier;    // Multiply interval on failure
@property(nonatomic, assign) NSTimeInterval minInterval;  // Minimum allowed interval
@property(nonatomic, assign) NSTimeInterval maxInterval;  // Maximum allowed interval

// Timer
@property(nonatomic, strong, nullable) dispatch_source_t updateTimer;

// Current adaptive interval
@property(nonatomic, assign, readonly) NSTimeInterval currentInterval;

// Update success/failure tracking
@property(nonatomic, assign) NSUInteger consecutiveSuccesses;
@property(nonatomic, assign) NSUInteger consecutiveFailures;

// Network-aware updating
@property(nonatomic, assign) BOOL pauseOnExpensiveNetwork;
@property(nonatomic, assign) BOOL pauseOnLowBattery;

// Record update result for adaptation
- (void)recordUpdateSuccess:(BOOL)success;

@end

#pragma mark - Update Strategy Factory

@interface UpdateStrategyFactory : NSObject

// Create strategy based on configuration
+ (id<UpdateStrategy>)strategyForConfiguration:(UpdateConfiguration*)configuration;

// Create specific strategy type
+ (id<UpdateStrategy>)strategyOfType:(UpdateStrategyType)type;

// Register custom strategy class
+ (void)registerStrategyClass:(Class)strategyClass forType:(UpdateStrategyType)type;

@end

NS_ASSUME_NONNULL_END
