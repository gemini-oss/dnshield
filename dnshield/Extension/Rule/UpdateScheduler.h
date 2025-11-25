//
//  UpdateScheduler.h
//  DNShield Network Extension
//
//  Timer-based scheduling system for rule updates
//  Manages multiple rule sources with different update strategies
//

#import <Foundation/Foundation.h>
#import "UpdateStrategy.h"

NS_ASSUME_NONNULL_BEGIN

// Forward declarations
@class RuleSource;
@class UpdateConfiguration;
@protocol UpdateSchedulerDelegate;

// Scheduler state
typedef NS_ENUM(NSInteger, UpdateSchedulerState) {
  UpdateSchedulerStateStopped = 0,
  UpdateSchedulerStateRunning,
  UpdateSchedulerStatePaused,
  UpdateSchedulerStateSuspended  // System-initiated suspension
};

// Update priority for concurrent updates
typedef NS_ENUM(NSInteger, UpdatePriority) {
  UpdatePriorityBackground = 0,
  UpdatePriorityNormal,
  UpdatePriorityHigh,
  UpdatePriorityCritical
};

#pragma mark - Update Task

@interface UpdateTask : NSObject

@property(nonatomic, strong, readonly) NSString* taskIdentifier;
@property(nonatomic, strong, readonly) RuleSource* source;
@property(nonatomic, assign, readonly) UpdatePriority priority;
@property(nonatomic, strong, readonly) NSDate* scheduledTime;
@property(nonatomic, strong, nullable) NSDate* startTime;
@property(nonatomic, strong, nullable) NSDate* completionTime;
@property(nonatomic, strong, nullable) NSError* error;
@property(nonatomic, assign) BOOL success;
@property(nonatomic, assign, getter=isCancelled) BOOL cancelled;

- (instancetype)initWithSource:(RuleSource*)source
                      priority:(UpdatePriority)priority
                 scheduledTime:(NSDate*)scheduledTime;

@end

#pragma mark - Update Scheduler

@interface UpdateScheduler : NSObject

// State
@property(nonatomic, readonly) UpdateSchedulerState state;

// Delegate
@property(nonatomic, weak) id<UpdateSchedulerDelegate> delegate;

// Configuration
@property(nonatomic, assign) NSUInteger maxConcurrentUpdates;
@property(nonatomic, assign) BOOL updateOnNetworkChange;
@property(nonatomic, assign) BOOL updateOnStart;
@property(nonatomic, assign) BOOL pauseOnExpensiveNetwork;
@property(nonatomic, assign) BOOL pauseOnLowPower;

// Initialize with configuration
- (instancetype)initWithConfiguration:(UpdateConfiguration*)configuration;

// Start/stop scheduling
- (void)start;
- (void)stop;
- (void)stopSynchronously;  // Synchronous stop for use in dealloc
- (void)pause;
- (void)resume;

// Add/remove sources
- (void)addRuleSource:(RuleSource*)source;
- (void)removeRuleSource:(RuleSource*)source;
- (void)removeAllRuleSources;

// Update specific source
- (void)updateSource:(RuleSource*)source priority:(UpdatePriority)priority;
- (void)updateSourceWithIdentifier:(NSString*)identifier priority:(UpdatePriority)priority;

// Update all sources
- (void)updateAllSourcesWithPriority:(UpdatePriority)priority;

// Cancel updates
- (void)cancelUpdateForSource:(RuleSource*)source;
- (void)cancelAllUpdates;

// Query methods
- (NSArray<RuleSource*>*)scheduledSources;
- (nullable UpdateTask*)currentTaskForSource:(RuleSource*)source;
- (NSArray<UpdateTask*>*)pendingTasks;
- (NSArray<UpdateTask*>*)completedTasks;

// Next update time
- (nullable NSDate*)nextScheduledUpdateTime;
- (nullable NSDate*)nextUpdateTimeForSource:(RuleSource*)source;

// Statistics
@property(nonatomic, readonly) NSUInteger totalUpdatesScheduled;
@property(nonatomic, readonly) NSUInteger totalUpdatesCompleted;
@property(nonatomic, readonly) NSUInteger totalUpdatesFailed;
@property(nonatomic, readonly) NSTimeInterval averageUpdateDuration;

// Reset statistics
- (void)resetStatistics;

@end

#pragma mark - Update Scheduler Delegate

@protocol UpdateSchedulerDelegate <NSObject>

@required
// Called when scheduler needs to update a source
- (void)updateScheduler:(UpdateScheduler*)scheduler
     shouldUpdateSource:(RuleSource*)source
               withTask:(UpdateTask*)task;

@optional
// State changes
- (void)updateSchedulerDidStart:(UpdateScheduler*)scheduler;
- (void)updateSchedulerDidStop:(UpdateScheduler*)scheduler;
- (void)updateSchedulerDidPause:(UpdateScheduler*)scheduler;
- (void)updateSchedulerDidResume:(UpdateScheduler*)scheduler;

// Task lifecycle
- (void)updateScheduler:(UpdateScheduler*)scheduler willBeginTask:(UpdateTask*)task;

- (void)updateScheduler:(UpdateScheduler*)scheduler didCompleteTask:(UpdateTask*)task;

- (void)updateScheduler:(UpdateScheduler*)scheduler
            didFailTask:(UpdateTask*)task
              withError:(NSError*)error;

- (void)updateScheduler:(UpdateScheduler*)scheduler didCancelTask:(UpdateTask*)task;

// Scheduling events
- (void)updateScheduler:(UpdateScheduler*)scheduler
    didScheduleNextUpdateAt:(NSDate*)date
                  forSource:(RuleSource*)source;

// Network events
- (void)updateSchedulerDidDetectNetworkChange:(UpdateScheduler*)scheduler;
- (void)updateSchedulerDidPauseForExpensiveNetwork:(UpdateScheduler*)scheduler;
- (void)updateSchedulerDidPauseForLowPower:(UpdateScheduler*)scheduler;

@end

#pragma mark - Scheduler Queue

// Internal queue for managing update tasks
@interface UpdateSchedulerQueue : NSObject

- (void)enqueueTask:(UpdateTask*)task;
- (nullable UpdateTask*)dequeueTask;
- (void)removeTask:(UpdateTask*)task;
- (void)removeTasksForSource:(RuleSource*)source;
- (void)removeAllTasks;

@property(nonatomic, readonly) NSUInteger count;
@property(nonatomic, readonly) NSArray<UpdateTask*>* allTasks;

- (nullable UpdateTask*)taskForSource:(RuleSource*)source;
- (NSArray<UpdateTask*>*)tasksWithPriority:(UpdatePriority)priority;

@end

NS_ASSUME_NONNULL_END
