//
//  UpdateScheduler.m
//  DNShield Network Extension
//
//  Implementation of timer-based scheduling for rule updates
//

#import "Rule/UpdateScheduler.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import "ConfigurationManager.h"
#import "NetworkReachability.h"

#pragma mark - Update Task

@implementation UpdateTask

- (instancetype)initWithSource:(RuleSource*)source
                      priority:(UpdatePriority)priority
                 scheduledTime:(NSDate*)scheduledTime {
  self = [super init];
  if (self) {
    _taskIdentifier = [[NSUUID UUID] UUIDString];
    _source = source;
    _priority = priority;
    _scheduledTime = scheduledTime;
  }
  return self;
}

- (NSString*)description {
  return [NSString stringWithFormat:@"<UpdateTask %@: source=%@, priority=%ld, scheduled=%@>",
                                    self.taskIdentifier, self.source.identifier,
                                    (long)self.priority, self.scheduledTime];
}

@end

#pragma mark - Update Scheduler Queue

@interface UpdateSchedulerQueue ()
@property(nonatomic, strong) NSMutableArray<UpdateTask*>* tasks;
@property(nonatomic, strong) dispatch_queue_t queueAccessQueue;
@end

@implementation UpdateSchedulerQueue

- (instancetype)init {
  self = [super init];
  if (self) {
    _tasks = [NSMutableArray array];
    _queueAccessQueue =
        dispatch_queue_create("com.dnshield.scheduler.queue", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)enqueueTask:(UpdateTask*)task {
  dispatch_sync(self.queueAccessQueue, ^{
    // Insert based on priority and scheduled time
    NSUInteger insertIndex = 0;
    for (NSUInteger i = 0; i < self.tasks.count; i++) {
      UpdateTask* existingTask = self.tasks[i];

      // Higher priority first
      if (task.priority > existingTask.priority) {
        break;
      }

      // Same priority - earlier scheduled time first
      if (task.priority == existingTask.priority &&
          [task.scheduledTime compare:existingTask.scheduledTime] == NSOrderedAscending) {
        break;
      }

      insertIndex++;
    }

    [self.tasks insertObject:task atIndex:insertIndex];
  });
}

- (nullable UpdateTask*)dequeueTask {
  __block UpdateTask* task = nil;
  dispatch_sync(self.queueAccessQueue, ^{
    if (self.tasks.count > 0) {
      task = self.tasks.firstObject;
      [self.tasks removeObjectAtIndex:0];
    }
  });
  return task;
}

- (void)removeTask:(UpdateTask*)task {
  dispatch_sync(self.queueAccessQueue, ^{
    [self.tasks removeObject:task];
  });
}

- (void)removeTasksForSource:(RuleSource*)source {
  dispatch_sync(self.queueAccessQueue, ^{
    [self.tasks filterUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(UpdateTask* task,
                                                                           NSDictionary* bindings) {
                  return ![task.source.identifier isEqualToString:source.identifier];
                }]];
  });
}

- (void)removeAllTasks {
  dispatch_sync(self.queueAccessQueue, ^{
    [self.tasks removeAllObjects];
  });
}

- (NSUInteger)count {
  __block NSUInteger count;
  dispatch_sync(self.queueAccessQueue, ^{
    count = self.tasks.count;
  });
  return count;
}

- (NSArray<UpdateTask*>*)allTasks {
  __block NSArray* tasks;
  dispatch_sync(self.queueAccessQueue, ^{
    tasks = [self.tasks copy];
  });
  return tasks;
}

- (nullable UpdateTask*)taskForSource:(RuleSource*)source {
  __block UpdateTask* foundTask = nil;
  dispatch_sync(self.queueAccessQueue, ^{
    for (UpdateTask* task in self.tasks) {
      if ([task.source.identifier isEqualToString:source.identifier]) {
        foundTask = task;
        break;
      }
    }
  });
  return foundTask;
}

- (NSArray<UpdateTask*>*)tasksWithPriority:(UpdatePriority)priority {
  __block NSArray* filteredTasks;
  dispatch_sync(self.queueAccessQueue, ^{
    NSPredicate* predicate = [NSPredicate predicateWithFormat:@"priority == %ld", (long)priority];
    filteredTasks = [self.tasks filteredArrayUsingPredicate:predicate];
  });
  return filteredTasks;
}

@end

#pragma mark - Update Scheduler

@interface UpdateScheduler () <UpdateStrategyDelegate, NetworkReachabilityDelegate>

@property(nonatomic, strong) UpdateConfiguration* configuration;
@property(nonatomic, strong) NSMutableDictionary<NSString*, id<UpdateStrategy>>* strategies;
@property(nonatomic, strong) NSMutableDictionary<NSString*, RuleSource*>* sources;
@property(nonatomic, strong) UpdateSchedulerQueue* pendingQueue;
@property(nonatomic, strong) NSMutableArray<UpdateTask*>* activeTasks;
@property(nonatomic, strong) NSMutableArray<UpdateTask*>* completedTasksHistory;
@property(nonatomic, strong) dispatch_queue_t schedulerQueue;
@property(nonatomic, strong) dispatch_group_t updateGroup;

// Statistics
@property(nonatomic, assign) NSUInteger totalUpdatesScheduled;
@property(nonatomic, assign) NSUInteger totalUpdatesCompleted;
@property(nonatomic, assign) NSUInteger totalUpdatesFailed;
@property(nonatomic, strong) NSMutableArray<NSNumber*>* updateDurations;

// Network monitoring
@property(nonatomic, assign) BOOL networkPaused;
@property(nonatomic, assign) BOOL powerPaused;

@end

@implementation UpdateScheduler

#pragma mark - Initialization

- (instancetype)initWithConfiguration:(UpdateConfiguration*)configuration {
  self = [super init];
  if (self) {
    _configuration = configuration;
    _strategies = [NSMutableDictionary dictionary];
    _sources = [NSMutableDictionary dictionary];
    _pendingQueue = [[UpdateSchedulerQueue alloc] init];
    _activeTasks = [NSMutableArray array];
    _completedTasksHistory = [NSMutableArray array];
    _updateDurations = [NSMutableArray array];

    _schedulerQueue = dispatch_queue_create("com.dnshield.updatescheduler", DISPATCH_QUEUE_SERIAL);
    _updateGroup = dispatch_group_create();

    _maxConcurrentUpdates = 3;  // Default
    _updateOnNetworkChange = configuration.updateOnNetworkChange;
    _updateOnStart = configuration.updateOnStart;
    _pauseOnExpensiveNetwork = YES;
    _pauseOnLowPower = YES;

    // Setup network monitoring
    [[NetworkReachability sharedInstance] setDelegate:self];

    DNSLogInfo(LogCategoryScheduler, "UpdateScheduler initialized with configuration");
  }
  return self;
}

- (void)dealloc {
  // Use synchronous stop for dealloc to avoid async issues
  // Call a private ivar-based helper to avoid messaging self
  [self stopSynchronouslyUsingIvars];
  [[NetworkReachability sharedInstance] setDelegate:nil];
}

- (void)stopSynchronouslyUsingIvars {
  // Directly set state and iterate using ivars to avoid property getters
  _state = UpdateSchedulerStateStopped;

  [_strategies enumerateKeysAndObjectsUsingBlock:^(NSString* identifier,
                                                   id<UpdateStrategy> strategy, BOOL* stop) {
    [strategy stop];
  }];
}

- (void)stopSynchronously {
  // Reuse the ivar-based helper to avoid property access during teardown
  [self stopSynchronouslyUsingIvars];

  // Note: We can't access internal task management structures directly here
  // as they may not be exposed. The async stop method handles this properly.
  // This synchronous method just ensures the scheduler state is stopped
  // to prevent any new operations from starting.
}

#pragma mark - State Management

- (void)start {
  dispatch_async(self.schedulerQueue, ^{
    if (self.state == UpdateSchedulerStateRunning) {
      DNSLogInfo(LogCategoryScheduler, "Scheduler already running");
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Starting update scheduler");

    self->_state = UpdateSchedulerStateRunning;

    // Start network monitoring
    [[NetworkReachability sharedInstance] startMonitoring];

    // Start strategies for all sources
    [self.sources
        enumerateKeysAndObjectsUsingBlock:^(NSString* identifier, RuleSource* source, BOOL* stop) {
          [self startStrategyForSource:source];
        }];

    // Update on start if configured
    if (self.updateOnStart) {
      DNSLogInfo(LogCategoryScheduler, "Triggering initial update for all sources");
      [self updateAllSourcesWithPriority:UpdatePriorityHigh];
    }

    // Process any pending tasks
    [self processPendingTasks];

    if ([self.delegate respondsToSelector:@selector(updateSchedulerDidStart:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateSchedulerDidStart:self];
      });
    }
  });
}

- (void)stop {
  // Create a strong reference to self for the block to ensure it stays alive
  UpdateScheduler* __block strongSelf = self;

  dispatch_async(self.schedulerQueue, ^{
    if (strongSelf->_state == UpdateSchedulerStateStopped) {
      strongSelf = nil;  // Release the strong reference
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Stopping update scheduler");

    strongSelf->_state = UpdateSchedulerStateStopped;

    // Stop all strategies
    [strongSelf.strategies enumerateKeysAndObjectsUsingBlock:^(
                               NSString* identifier, id<UpdateStrategy> strategy, BOOL* stop) {
      [strategy stop];
    }];

    // Cancel all pending tasks
    [strongSelf cancelAllUpdates];

    // Wait for active tasks to complete with a reasonable timeout
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
    dispatch_group_wait(strongSelf.updateGroup, timeout);

    // Use weak reference for the delegate callback to avoid retain cycles
    __weak typeof(strongSelf) weakSelf = strongSelf;
    if ([strongSelf.delegate respondsToSelector:@selector(updateSchedulerDidStop:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [weakSelf.delegate updateSchedulerDidStop:weakSelf];
      });
    }

    strongSelf = nil;  // Release the strong reference
  });
}

- (void)pause {
  dispatch_async(self.schedulerQueue, ^{
    if (self.state != UpdateSchedulerStateRunning) {
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Pausing update scheduler");

    self->_state = UpdateSchedulerStatePaused;

    // Pause all strategies that support it
    [self.strategies enumerateKeysAndObjectsUsingBlock:^(NSString* identifier,
                                                         id<UpdateStrategy> strategy, BOOL* stop) {
      if ([strategy respondsToSelector:@selector(pause)]) {
        [strategy pause];
      }
    }];

    if ([self.delegate respondsToSelector:@selector(updateSchedulerDidPause:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateSchedulerDidPause:self];
      });
    }
  });
}

- (void)resume {
  dispatch_async(self.schedulerQueue, ^{
    if (self.state != UpdateSchedulerStatePaused) {
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Resuming update scheduler");

    self->_state = UpdateSchedulerStateRunning;

    // Resume all strategies that support it
    [self.strategies enumerateKeysAndObjectsUsingBlock:^(NSString* identifier,
                                                         id<UpdateStrategy> strategy, BOOL* stop) {
      if ([strategy respondsToSelector:@selector(resume)]) {
        [strategy resume];
      }
    }];

    // Process any pending tasks
    [self processPendingTasks];

    if ([self.delegate respondsToSelector:@selector(updateSchedulerDidResume:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateSchedulerDidResume:self];
      });
    }
  });
}

#pragma mark - Source Management

- (void)addRuleSource:(RuleSource*)source {
  dispatch_async(self.schedulerQueue, ^{
    if (self.sources[source.identifier]) {
      DNSLogInfo(LogCategoryScheduler, "Source already added: %@", source.identifier);
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Adding rule source: %@", source.identifier);

    self.sources[source.identifier] = source;

    if (self.state == UpdateSchedulerStateRunning) {
      [self startStrategyForSource:source];

      if (self.updateOnStart) {
        [self updateSource:source priority:UpdatePriorityNormal];
      }
    }
  });
}

- (void)removeRuleSource:(RuleSource*)source {
  dispatch_async(self.schedulerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Removing rule source: %@", source.identifier);

    // Stop strategy
    id<UpdateStrategy> strategy = self.strategies[source.identifier];
    if (strategy) {
      [strategy stop];
      [self.strategies removeObjectForKey:source.identifier];
    }

    // Remove source
    [self.sources removeObjectForKey:source.identifier];

    // Cancel pending tasks
    [self.pendingQueue removeTasksForSource:source];
  });
}

- (void)removeAllRuleSources {
  dispatch_async(self.schedulerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Removing all rule sources");

    // Stop all strategies
    [self.strategies enumerateKeysAndObjectsUsingBlock:^(NSString* identifier,
                                                         id<UpdateStrategy> strategy, BOOL* stop) {
      [strategy stop];
    }];

    [self.strategies removeAllObjects];
    [self.sources removeAllObjects];
    [self.pendingQueue removeAllTasks];
  });
}

#pragma mark - Update Management

- (void)updateSource:(RuleSource*)source priority:(UpdatePriority)priority {
  dispatch_async(self.schedulerQueue, ^{
    if (!self.sources[source.identifier]) {
      DNSLogError(LogCategoryScheduler, "Cannot update unknown source: %@", source.identifier);
      return;
    }

    // Check if already updating
    UpdateTask* existingTask = [self.pendingQueue taskForSource:source];
    if (existingTask) {
      DNSLogInfo(LogCategoryScheduler, "Update already pending for source: %@", source.identifier);

      // Update priority if higher
      if (priority > existingTask.priority) {
        existingTask = [[UpdateTask alloc] initWithSource:source
                                                 priority:priority
                                            scheduledTime:[NSDate date]];
        [self.pendingQueue removeTasksForSource:source];
        [self.pendingQueue enqueueTask:existingTask];
      }
      return;
    }

    // Create new task
    UpdateTask* task = [[UpdateTask alloc] initWithSource:source
                                                 priority:priority
                                            scheduledTime:[NSDate date]];

    DNSLogInfo(LogCategoryScheduler, "Scheduling update for source: %@ with priority: %ld",
               source.identifier, (long)priority);

    [self.pendingQueue enqueueTask:task];
    self.totalUpdatesScheduled++;

    // Process immediately if we have capacity
    [self processPendingTasks];
  });
}

- (void)updateSourceWithIdentifier:(NSString*)identifier priority:(UpdatePriority)priority {
  RuleSource* source = self.sources[identifier];
  if (source) {
    [self updateSource:source priority:priority];
  }
}

- (void)updateAllSourcesWithPriority:(UpdatePriority)priority {
  dispatch_async(self.schedulerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Scheduling updates for all sources with priority: %ld",
               (long)priority);

    [self.sources
        enumerateKeysAndObjectsUsingBlock:^(NSString* identifier, RuleSource* source, BOOL* stop) {
          [self updateSource:source priority:priority];
        }];
  });
}

- (void)cancelUpdateForSource:(RuleSource*)source {
  dispatch_async(self.schedulerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Cancelling update for source: %@", source.identifier);

    [self.pendingQueue removeTasksForSource:source];

    // Cancel active task if any
    for (UpdateTask* task in self.activeTasks) {
      if ([task.source.identifier isEqualToString:source.identifier]) {
        task.cancelled = YES;
      }
    }
  });
}

- (void)cancelAllUpdates {
  dispatch_async(self.schedulerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Cancelling all updates");

    [self.pendingQueue removeAllTasks];

    for (UpdateTask* task in self.activeTasks) {
      task.cancelled = YES;
    }
  });
}

#pragma mark - Query Methods

- (NSArray<RuleSource*>*)scheduledSources {
  __block NSArray* sources;
  dispatch_sync(self.schedulerQueue, ^{
    sources = [self.sources allValues];
  });
  return sources;
}

- (nullable UpdateTask*)currentTaskForSource:(RuleSource*)source {
  __block UpdateTask* currentTask = nil;
  dispatch_sync(self.schedulerQueue, ^{
    for (UpdateTask* task in self.activeTasks) {
      if ([task.source.identifier isEqualToString:source.identifier]) {
        currentTask = task;
        break;
      }
    }
  });
  return currentTask;
}

- (NSArray<UpdateTask*>*)pendingTasks {
  return self.pendingQueue.allTasks;
}

- (NSArray<UpdateTask*>*)completedTasks {
  __block NSArray* tasks;
  dispatch_sync(self.schedulerQueue, ^{
    tasks = [self.completedTasksHistory copy];
  });
  return tasks;
}

- (nullable NSDate*)nextScheduledUpdateTime {
  __block NSDate* nextTime = nil;
  dispatch_sync(self.schedulerQueue, ^{
    // Check all strategies for next update time
    [self.strategies enumerateKeysAndObjectsUsingBlock:^(NSString* identifier,
                                                         id<UpdateStrategy> strategy, BOOL* stop) {
      NSDate* strategyNextTime = [strategy nextUpdateTime];
      if (strategyNextTime) {
        if (!nextTime || [strategyNextTime compare:nextTime] == NSOrderedAscending) {
          nextTime = strategyNextTime;
        }
      }
    }];
  });
  return nextTime;
}

- (nullable NSDate*)nextUpdateTimeForSource:(RuleSource*)source {
  __block NSDate* nextTime = nil;
  dispatch_sync(self.schedulerQueue, ^{
    id<UpdateStrategy> strategy = self.strategies[source.identifier];
    if (strategy) {
      nextTime = [strategy nextUpdateTime];
    }
  });
  return nextTime;
}

#pragma mark - Statistics

- (NSTimeInterval)averageUpdateDuration {
  __block NSTimeInterval average = 0;
  dispatch_sync(self.schedulerQueue, ^{
    if (self.updateDurations.count > 0) {
      NSTimeInterval total = 0;
      for (NSNumber* duration in self.updateDurations) {
        total += [duration doubleValue];
      }
      average = total / self.updateDurations.count;
    }
  });
  return average;
}

- (void)resetStatistics {
  dispatch_async(self.schedulerQueue, ^{
    self.totalUpdatesScheduled = 0;
    self.totalUpdatesCompleted = 0;
    self.totalUpdatesFailed = 0;
    [self.updateDurations removeAllObjects];
    [self.completedTasksHistory removeAllObjects];
  });
}

#pragma mark - Private Methods

- (void)startStrategyForSource:(RuleSource*)source {
  // Create appropriate strategy
  id<UpdateStrategy> strategy = [UpdateStrategyFactory strategyForConfiguration:self.configuration];
  strategy.delegate = self;
  [strategy configureForRuleSource:source];

  self.strategies[source.identifier] = strategy;

  // Start the strategy
  [strategy startWithConfiguration:self.configuration];
}

- (void)processPendingTasks {
  if (self.state != UpdateSchedulerStateRunning) {
    return;
  }

  if (self.networkPaused || self.powerPaused) {
    DNSLogDebug(LogCategoryScheduler, "Updates paused due to network/power conditions");
    return;
  }

  // Check capacity
  while (self.activeTasks.count < self.maxConcurrentUpdates && self.pendingQueue.count > 0) {
    UpdateTask* task = [self.pendingQueue dequeueTask];
    if (!task)
      break;

    if (task.cancelled)
      continue;

    DNSLogInfo(LogCategoryScheduler, "Starting update task: %@", task);

    task.startTime = [NSDate date];
    [self.activeTasks addObject:task];

    // Notify delegate to perform update
    dispatch_group_enter(self.updateGroup);

    if ([self.delegate respondsToSelector:@selector(updateScheduler:willBeginTask:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateScheduler:self willBeginTask:task];
      });
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      [self.delegate updateScheduler:self shouldUpdateSource:task.source withTask:task];
    });
  }
}

- (void)completeTask:(UpdateTask*)task success:(BOOL)success error:(nullable NSError*)error {
  dispatch_async(self.schedulerQueue, ^{
    task.completionTime = [NSDate date];
    task.success = success;
    task.error = error;

    // Calculate duration
    NSTimeInterval duration = [task.completionTime timeIntervalSinceDate:task.startTime];
    [self.updateDurations addObject:@(duration)];

    // Keep only last 100 durations
    if (self.updateDurations.count > 100) {
      [self.updateDurations removeObjectsInRange:NSMakeRange(0, self.updateDurations.count - 100)];
    }

    // Update statistics
    if (success) {
      self.totalUpdatesCompleted++;
    } else {
      self.totalUpdatesFailed++;
    }

    // Remove from active
    [self.activeTasks removeObject:task];

    // Add to history
    [self.completedTasksHistory addObject:task];

    // Keep only last 50 completed tasks
    if (self.completedTasksHistory.count > 50) {
      [self.completedTasksHistory
          removeObjectsInRange:NSMakeRange(0, self.completedTasksHistory.count - 50)];
    }

    // Notify delegate
    if (success && [self.delegate respondsToSelector:@selector(updateScheduler:didCompleteTask:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateScheduler:self didCompleteTask:task];
      });
    } else if (!success && [self.delegate respondsToSelector:@selector
                                          (updateScheduler:didFailTask:withError:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateScheduler:self didFailTask:task withError:error];
      });
    }

    dispatch_group_leave(self.updateGroup);

    // Process next pending task
    [self processPendingTasks];
  });
}

#pragma mark - UpdateStrategy Delegate

- (void)updateStrategy:(id<UpdateStrategy>)strategy shouldUpdateSource:(RuleSource*)source {
  DNSLogInfo(LogCategoryScheduler, "Strategy triggered update for source: %@", source.identifier);
  [self updateSource:source priority:UpdatePriorityNormal];
}

- (void)updateStrategy:(id<UpdateStrategy>)strategy didScheduleNextUpdateAt:(NSDate*)date {
  DNSLogDebug(LogCategoryScheduler, "Strategy scheduled next update at: %@", date);

  // Find the source for this strategy
  __block RuleSource* source = nil;
  [self.strategies enumerateKeysAndObjectsUsingBlock:^(NSString* identifier, id<UpdateStrategy> str,
                                                       BOOL* stop) {
    if (str == strategy) {
      source = self.sources[identifier];
      *stop = YES;
    }
  }];

  if (source && [self.delegate respondsToSelector:@selector(updateScheduler:
                                                      didScheduleNextUpdateAt:forSource:)]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      [self.delegate updateScheduler:self didScheduleNextUpdateAt:date forSource:source];
    });
  }
}

- (void)updateStrategy:(id<UpdateStrategy>)strategy didEncounterError:(NSError*)error {
  DNSLogError(LogCategoryScheduler, "Strategy error: %@", error);
}

#pragma mark - NetworkReachability Delegate

- (void)networkReachabilityDidChange:(NetworkStatus)status {
  dispatch_async(self.schedulerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Network status changed: %@",
               [NetworkReachability stringForStatus:status]);

    BOOL wasNetworkPaused = self.networkPaused;

    // Check if we should pause for expensive network
    if (self.pauseOnExpensiveNetwork && [[NetworkReachability sharedInstance] isExpensive]) {
      self.networkPaused = YES;
      if (!wasNetworkPaused && [self.delegate respondsToSelector:@selector
                                              (updateSchedulerDidPauseForExpensiveNetwork:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
          [self.delegate updateSchedulerDidPauseForExpensiveNetwork:self];
        });
      }
    } else if (NetworkStatusIsReachable(status)) {
      self.networkPaused = NO;

      // Resume if we were paused
      if (wasNetworkPaused) {
        [self processPendingTasks];
      }

      // Update on network change if configured
      if (self.updateOnNetworkChange) {
        DNSLogInfo(LogCategoryScheduler, "Network changed - triggering updates");
        [self updateAllSourcesWithPriority:UpdatePriorityNormal];
      }
    }

    if ([self.delegate respondsToSelector:@selector(updateSchedulerDidDetectNetworkChange:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate updateSchedulerDidDetectNetworkChange:self];
      });
    }
  });
}

@end
