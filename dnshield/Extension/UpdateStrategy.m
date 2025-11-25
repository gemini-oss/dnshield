//
//  UpdateStrategy.m
//  DNShield Network Extension
//
//  Implementation of different update strategies for rule sets
//

#import "UpdateStrategy.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import "NetworkReachability.h"

#pragma mark - Update Strategy Base

@implementation UpdateStrategyBase

- (instancetype)init {
  self = [super init];
  if (self) {
    _updateHistory = [NSMutableArray array];
    NSString* queueLabel =
        [NSString stringWithFormat:@"com.dnshield.updatestrategy.%@", [[NSUUID UUID] UUIDString]];
    _strategyQueue = dispatch_queue_create([queueLabel UTF8String], DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)dealloc {
  [self stop];
}

#pragma mark - UpdateStrategy Protocol

- (UpdateStrategyType)strategyType {
  // Subclasses must override
  NSAssert(NO, @"Subclasses must override strategyType");
  return UpdateStrategyTypeManual;
}

- (void)startWithConfiguration:(UpdateConfiguration*)configuration {
  dispatch_async(self.strategyQueue, ^{
    if (self.isActive) {
      DNSLogInfo(LogCategoryScheduler, "Update strategy already active");
      return;
    }

    self.configuration = configuration;
    self->_isActive = YES;

    DNSLogInfo(LogCategoryScheduler, "Starting %@ update strategy", [self strategyTypeString]);

    [self scheduleNextUpdate];

    if ([self.delegate respondsToSelector:@selector(updateStrategyDidStart:)]) {
      [self.delegate updateStrategyDidStart:self];
    }
  });
}

- (void)stop {
  dispatch_async(self.strategyQueue, ^{
    if (!self.isActive) {
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Stopping %@ update strategy", [self strategyTypeString]);

    [self cancelScheduledUpdate];
    self->_isActive = NO;

    if ([self.delegate respondsToSelector:@selector(updateStrategyDidStop:)]) {
      [self.delegate updateStrategyDidStop:self];
    }
  });
}

- (void)triggerImmediateUpdate {
  dispatch_async(self.strategyQueue, ^{
    if (!self.isActive) {
      DNSLogError(LogCategoryScheduler, "Cannot trigger update - strategy not active");
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Triggering immediate update");
    [self notifyDelegateShouldUpdate];
  });
}

- (nullable NSDate*)nextUpdateTime {
  // Default implementation - subclasses may override
  return nil;
}

- (void)configureForRuleSource:(RuleSource*)source {
  self.ruleSource = source;
}

#pragma mark - Subclass Override Points

- (void)scheduleNextUpdate {
  NSAssert(NO, @"Subclasses must override scheduleNextUpdate");
}

- (void)cancelScheduledUpdate {
  NSAssert(NO, @"Subclasses must override cancelScheduledUpdate");
}

#pragma mark - Helper Methods

- (void)notifyDelegateShouldUpdate {
  if (!self.delegate || !self.ruleSource) {
    DNSLogError(LogCategoryScheduler, "No delegate or rule source configured");
    return;
  }

  [self recordUpdate];

  dispatch_async(dispatch_get_main_queue(), ^{
    [self.delegate updateStrategy:self shouldUpdateSource:self.ruleSource];
  });
}

- (void)notifyDelegateNextUpdateAt:(NSDate*)date {
  if ([self.delegate respondsToSelector:@selector(updateStrategy:didScheduleNextUpdateAt:)]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      [self.delegate updateStrategy:self didScheduleNextUpdateAt:date];
    });
  }
}

- (void)notifyDelegateError:(NSError*)error {
  if ([self.delegate respondsToSelector:@selector(updateStrategy:didEncounterError:)]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      [self.delegate updateStrategy:self didEncounterError:error];
    });
  }
}

- (void)recordUpdate {
  [self.updateHistory addObject:[NSDate date]];

  // Keep only last 100 updates
  if (self.updateHistory.count > 100) {
    [self.updateHistory removeObjectsInRange:NSMakeRange(0, self.updateHistory.count - 100)];
  }
}

- (NSUInteger)updateCount {
  return self.updateHistory.count;
}

- (NSDate*)lastUpdateTime {
  return self.updateHistory.lastObject;
}

- (NSString*)strategyTypeString {
  switch (self.strategyType) {
    case UpdateStrategyTypeInterval: return @"Interval";
    case UpdateStrategyTypeScheduled: return @"Scheduled";
    case UpdateStrategyTypeManual: return @"Manual";
    case UpdateStrategyTypeDynamic: return @"Dynamic";
    default: return @"Unknown";
  }
}

@end

#pragma mark - Interval Update Strategy

@implementation IntervalUpdateStrategy

- (instancetype)init {
  self = [super init];
  if (self) {
    _jitterPercent = 0.1;  // Default 10% jitter
  }
  return self;
}

- (UpdateStrategyType)strategyType {
  return UpdateStrategyTypeInterval;
}

- (void)startWithConfiguration:(UpdateConfiguration*)configuration {
  self.updateInterval = configuration.interval;
  [super startWithConfiguration:configuration];
}

- (void)scheduleNextUpdate {
  [self cancelScheduledUpdate];

  if (self.updateInterval <= 0) {
    DNSLogError(LogCategoryScheduler, "Invalid update interval: %f", self.updateInterval);
    return;
  }

  // Apply jitter
  NSTimeInterval interval = self.updateInterval;
  if (self.jitterPercent > 0) {
    double jitter = (arc4random_uniform(1000) / 1000.0 - 0.5) * 2.0 * self.jitterPercent;
    interval = interval * (1.0 + jitter);
  }

  DNSLogInfo(LogCategoryScheduler, "Scheduling next update in %.1f seconds", interval);

  self.updateTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.strategyQueue);

  dispatch_source_set_timer(self.updateTimer,
                            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(interval * NSEC_PER_SEC)),
                            DISPATCH_TIME_FOREVER,
                            (int64_t)(1.0 * NSEC_PER_SEC));  // 1 second leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(self.updateTimer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    DNSLogInfo(LogCategoryScheduler, "Interval timer fired");
    [strongSelf notifyDelegateShouldUpdate];
    [strongSelf scheduleNextUpdate];  // Reschedule
  });

  dispatch_resume(self.updateTimer);

  NSDate* nextUpdate = [NSDate dateWithTimeIntervalSinceNow:interval];
  [self notifyDelegateNextUpdateAt:nextUpdate];
}

- (void)cancelScheduledUpdate {
  dispatch_source_t timer = self.updateTimer;
  if (timer) {
    dispatch_source_cancel(timer);
    self.updateTimer = nil;
  }
}

- (NSDate*)nextUpdateTime {
  if (!self.isActive || !self.updateTimer) {
    return nil;
  }

  dispatch_time_t nextFireTime = dispatch_source_get_data(self.updateTimer);
  if (nextFireTime == 0) {
    return nil;
  }

  NSTimeInterval interval = (double)nextFireTime / NSEC_PER_SEC;
  return [NSDate dateWithTimeIntervalSinceNow:interval];
}

@end

#pragma mark - Scheduled Update Strategy

@implementation ScheduledUpdateStrategy

- (instancetype)init {
  self = [super init];
  if (self) {
    _timeZone = [NSTimeZone systemTimeZone];
  }
  return self;
}

- (UpdateStrategyType)strategyType {
  return UpdateStrategyTypeScheduled;
}

- (void)startWithConfiguration:(UpdateConfiguration*)configuration {
  self.scheduledTimes = configuration.scheduledTimes;
  [super startWithConfiguration:configuration];
}

- (void)scheduleNextUpdate {
  [self cancelScheduledUpdate];

  NSDate* nextScheduledTime = [self calculateNextScheduledTime];
  if (!nextScheduledTime) {
    DNSLogError(LogCategoryScheduler, "No valid scheduled times configured");
    return;
  }

  NSTimeInterval interval = [nextScheduledTime timeIntervalSinceNow];
  if (interval <= 0) {
    // Should not happen, but handle it
    DNSLogError(LogCategoryScheduler, "Next scheduled time is in the past");
    return;
  }

  DNSLogInfo(LogCategoryScheduler, "Scheduling next update at %@ (in %.1f seconds)",
             nextScheduledTime, interval);

  self.scheduledTimer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.strategyQueue);

  dispatch_source_set_timer(self.scheduledTimer,
                            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(interval * NSEC_PER_SEC)),
                            DISPATCH_TIME_FOREVER,
                            (int64_t)(60.0 * NSEC_PER_SEC));  // 1 minute leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(self.scheduledTimer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    DNSLogInfo(LogCategoryScheduler, "Scheduled timer fired");
    [strongSelf notifyDelegateShouldUpdate];
    [strongSelf scheduleNextUpdate];  // Schedule next occurrence
  });

  dispatch_resume(self.scheduledTimer);

  [self notifyDelegateNextUpdateAt:nextScheduledTime];
}

- (void)cancelScheduledUpdate {
  dispatch_source_t timer = self.scheduledTimer;
  if (timer) {
    dispatch_source_cancel(timer);
    self.scheduledTimer = nil;
  }
}

- (NSDate*)nextUpdateTime {
  return [self calculateNextScheduledTime];
}

- (nullable NSDate*)calculateNextScheduledTime {
  if (!self.scheduledTimes || self.scheduledTimes.count == 0) {
    return nil;
  }

  NSCalendar* calendar = [NSCalendar currentCalendar];
  calendar.timeZone = self.timeZone;

  NSDate* now = [NSDate date];
  NSDate* nextTime = nil;
  NSTimeInterval shortestInterval = DBL_MAX;

  // Check each scheduled time
  for (NSString* timeString in self.scheduledTimes) {
    NSArray* components = [timeString componentsSeparatedByString:@":"];
    if (components.count != 2)
      continue;

    NSInteger hour = [components[0] integerValue];
    NSInteger minute = [components[1] integerValue];

    if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
      continue;

    // Create date components for today
    NSDateComponents* todayComponents =
        [calendar components:NSCalendarUnitYear | NSCalendarUnitMonth | NSCalendarUnitDay
                    fromDate:now];
    todayComponents.hour = hour;
    todayComponents.minute = minute;
    todayComponents.second = 0;

    NSDate* scheduledToday = [calendar dateFromComponents:todayComponents];

    // Check if we need to consider day of week restrictions
    if (self.daysOfWeek && self.daysOfWeek.count > 0) {
      NSDateComponents* weekdayComponents = [calendar components:NSCalendarUnitWeekday
                                                        fromDate:scheduledToday];
      if (![self.daysOfWeek containsObject:@(weekdayComponents.weekday)]) {
        // This day of week is not allowed, skip
        continue;
      }
    }

    // If scheduled time has passed today, check tomorrow
    if ([scheduledToday compare:now] == NSOrderedAscending) {
      NSDateComponents* dayComponent = [[NSDateComponents alloc] init];
      dayComponent.day = 1;
      scheduledToday = [calendar dateByAddingComponents:dayComponent
                                                 toDate:scheduledToday
                                                options:0];

      // Check day of week for tomorrow
      if (self.daysOfWeek && self.daysOfWeek.count > 0) {
        NSDateComponents* weekdayComponents = [calendar components:NSCalendarUnitWeekday
                                                          fromDate:scheduledToday];
        NSInteger daysToAdd = 0;
        while (![self.daysOfWeek containsObject:@(weekdayComponents.weekday)] && daysToAdd < 7) {
          dayComponent.day = 1;
          scheduledToday = [calendar dateByAddingComponents:dayComponent
                                                     toDate:scheduledToday
                                                    options:0];
          weekdayComponents = [calendar components:NSCalendarUnitWeekday fromDate:scheduledToday];
          daysToAdd++;
        }
      }
    }

    NSTimeInterval interval = [scheduledToday timeIntervalSinceNow];
    if (interval < shortestInterval) {
      shortestInterval = interval;
      nextTime = scheduledToday;
    }
  }

  return nextTime;
}

@end

#pragma mark - Manual Update Strategy

@implementation ManualUpdateStrategy

- (instancetype)init {
  self = [super init];
  if (self) {
    _minimumInterval = 60.0;  // Default 1 minute minimum between updates
  }
  return self;
}

- (UpdateStrategyType)strategyType {
  return UpdateStrategyTypeManual;
}

- (void)scheduleNextUpdate {
  // Manual strategy doesn't schedule updates
  DNSLogDebug(LogCategoryScheduler, "Manual strategy - no scheduled updates");
}

- (void)cancelScheduledUpdate {
  // Nothing to cancel for manual strategy
}

- (void)triggerImmediateUpdate {
  dispatch_async(self.strategyQueue, ^{
    if (![self canTriggerUpdate]) {
      NSTimeInterval timeUntilNext =
          self.minimumInterval - [[NSDate date] timeIntervalSinceDate:self.lastManualTrigger];
      NSError* error = DNSMakeError(
          DNSSchedulerErrorDomain, DNSSchedulerErrorInvalidInterval,
          [NSString stringWithFormat:@"Manual update rate limited. Try again in %.0f seconds",
                                     timeUntilNext]);
      [self notifyDelegateError:error];
      return;
    }

    self.lastManualTrigger = [NSDate date];
    [super triggerImmediateUpdate];
  });
}

- (BOOL)canTriggerUpdate {
  if (!self.lastManualTrigger) {
    return YES;
  }

  NSTimeInterval timeSinceLastTrigger =
      [[NSDate date] timeIntervalSinceDate:self.lastManualTrigger];
  return timeSinceLastTrigger >= self.minimumInterval;
}

@end

#pragma mark - Push Update Strategy

@implementation PushUpdateStrategy

- (instancetype)init {
  self = [super init];
  if (self) {
    _fallbackInterval = 3600.0;  // Default 1 hour fallback
  }
  return self;
}

- (UpdateStrategyType)strategyType {
  return UpdateStrategyTypeDynamic;
}

- (void)startWithConfiguration:(UpdateConfiguration*)configuration {
  [super startWithConfiguration:configuration];

  // Register for push notifications
  [self registerForPushNotifications];

  // Start fallback timer
  [self scheduleFallbackTimer];
}

- (void)scheduleNextUpdate {
  // Push strategy relies on notifications, but schedule fallback
  [self scheduleFallbackTimer];
}

- (void)cancelScheduledUpdate {
  dispatch_source_t timer = self.fallbackTimer;
  if (timer) {
    dispatch_source_cancel(timer);
    self.fallbackTimer = nil;
  }
}

- (void)registerForPushNotifications {
  DNSLogInfo(LogCategoryScheduler, "Registering for push notifications");

  // This is a placeholder - actual implementation would register with push service
  // For now, we'll just log and rely on fallback

  if (self.pushEndpoint) {
    DNSLogInfo(LogCategoryScheduler, "Push endpoint: %@", self.pushEndpoint);
  }
}

- (void)handlePushNotification:(NSDictionary*)userInfo {
  dispatch_async(self.strategyQueue, ^{
    if (!self.isActive) {
      DNSLogError(LogCategoryScheduler, "Received push but strategy not active");
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Handling push notification: %@", userInfo);

    // Reset fallback timer
    [self scheduleFallbackTimer];

    // Trigger update
    [self notifyDelegateShouldUpdate];
  });
}

- (void)scheduleFallbackTimer {
  [self cancelScheduledUpdate];

  if (self.fallbackInterval <= 0) {
    return;
  }

  DNSLogDebug(LogCategoryScheduler, "Scheduling fallback timer for %.1f seconds",
              self.fallbackInterval);

  self.fallbackTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.strategyQueue);

  dispatch_source_set_timer(
      self.fallbackTimer,
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.fallbackInterval * NSEC_PER_SEC)),
      DISPATCH_TIME_FOREVER,
      (int64_t)(60.0 * NSEC_PER_SEC));  // 1 minute leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(self.fallbackTimer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    DNSLogInfo(LogCategoryScheduler, "Push fallback timer fired");
    [strongSelf notifyDelegateShouldUpdate];
    [strongSelf scheduleFallbackTimer];  // Reschedule
  });

  dispatch_resume(self.fallbackTimer);
}

- (NSDate*)nextUpdateTime {
  if (!self.isActive || !self.fallbackTimer) {
    return nil;
  }

  return [NSDate dateWithTimeIntervalSinceNow:self.fallbackInterval];
}

@end

#pragma mark - Adaptive Update Strategy

@interface AdaptiveUpdateStrategy ()
@property(nonatomic, assign, readwrite) NSTimeInterval currentInterval;
@end

@implementation AdaptiveUpdateStrategy

- (instancetype)init {
  self = [super init];
  if (self) {
    _baseInterval = 300.0;  // Default 5 minutes
    _successMultiplier = 1.5;
    _failureMultiplier = 0.5;
    _minInterval = 60.0;     // 1 minute
    _maxInterval = 86400.0;  // 24 hours
    _currentInterval = _baseInterval;
    _pauseOnExpensiveNetwork = YES;
    _pauseOnLowBattery = YES;
  }
  return self;
}

- (UpdateStrategyType)strategyType {
  return UpdateStrategyTypeDynamic;
}

- (void)scheduleNextUpdate {
  [self cancelScheduledUpdate];

  // Check network conditions
  if (self.pauseOnExpensiveNetwork && [[NetworkReachability sharedInstance] isExpensive]) {
    DNSLogInfo(LogCategoryScheduler, "Pausing updates - expensive network");
    [self scheduleNetworkCheck];
    return;
  }

  // Check battery conditions
  if (self.pauseOnLowBattery && [self isLowBattery]) {
    DNSLogInfo(LogCategoryScheduler, "Pausing updates - low battery");
    [self scheduleBatteryCheck];
    return;
  }

  DNSLogInfo(LogCategoryScheduler, "Scheduling adaptive update in %.1f seconds",
             self.currentInterval);

  dispatch_source_t timer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.strategyQueue);

  dispatch_source_set_timer(
      timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.currentInterval * NSEC_PER_SEC)),
      DISPATCH_TIME_FOREVER,
      (int64_t)(10.0 * NSEC_PER_SEC));  // 10 second leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(timer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    DNSLogInfo(LogCategoryScheduler, "Adaptive timer fired");
    [strongSelf notifyDelegateShouldUpdate];
  });

  dispatch_resume(timer);
  self.updateTimer = timer;

  NSDate* nextUpdate = [NSDate dateWithTimeIntervalSinceNow:self.currentInterval];
  [self notifyDelegateNextUpdateAt:nextUpdate];
}

- (void)cancelScheduledUpdate {
  dispatch_source_t timer = self.updateTimer;
  if (timer) {
    dispatch_source_cancel(timer);
    self.updateTimer = nil;
  }
}

- (void)recordUpdateSuccess:(BOOL)success {
  dispatch_async(self.strategyQueue, ^{
    if (success) {
      self.consecutiveSuccesses++;
      self.consecutiveFailures = 0;

      // Increase interval on success (less frequent updates)
      self.currentInterval = MIN(self.currentInterval * self.successMultiplier, self.maxInterval);

      DNSLogDebug(LogCategoryScheduler, "Update succeeded - new interval: %.1f seconds",
                  self.currentInterval);
    } else {
      self.consecutiveFailures++;
      self.consecutiveSuccesses = 0;

      // Decrease interval on failure (more frequent retries)
      self.currentInterval = MAX(self.currentInterval * self.failureMultiplier, self.minInterval);

      DNSLogDebug(LogCategoryScheduler, "Update failed - new interval: %.1f seconds",
                  self.currentInterval);
    }

    // Schedule next update with new interval
    [self scheduleNextUpdate];
  });
}

- (BOOL)isLowBattery {
  // This is a placeholder - actual implementation would check battery level
  // For now, always return NO
  return NO;
}

- (void)scheduleNetworkCheck {
  // Schedule a check in 5 minutes to see if network conditions improved
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(300 * NSEC_PER_SEC)),
                 self.strategyQueue, ^{
                   if (self.isActive) {
                     [self scheduleNextUpdate];
                   }
                 });
}

- (void)scheduleBatteryCheck {
  // Schedule a check in 10 minutes to see if battery conditions improved
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(600 * NSEC_PER_SEC)),
                 self.strategyQueue, ^{
                   if (self.isActive) {
                     [self scheduleNextUpdate];
                   }
                 });
}

@end

#pragma mark - Update Strategy Factory

@implementation UpdateStrategyFactory

static NSMutableDictionary* _strategyClasses;

+ (void)initialize {
  if (self == [UpdateStrategyFactory class]) {
    _strategyClasses = [NSMutableDictionary dictionary];

    // Register default strategies
    [self registerStrategyClass:[IntervalUpdateStrategy class] forType:UpdateStrategyTypeInterval];
    [self registerStrategyClass:[ScheduledUpdateStrategy class]
                        forType:UpdateStrategyTypeScheduled];
    [self registerStrategyClass:[ManualUpdateStrategy class] forType:UpdateStrategyTypeManual];
    [self registerStrategyClass:[PushUpdateStrategy class] forType:UpdateStrategyTypeDynamic];
  }
}

+ (id<UpdateStrategy>)strategyForConfiguration:(UpdateConfiguration*)configuration {
  // Convert UpdateStrategy enum to UpdateStrategyType enum
  UpdateStrategyType type;
  switch (configuration.strategy) {
    case UpdateStrategyInterval: type = UpdateStrategyTypeInterval; break;
    case UpdateStrategyScheduled: type = UpdateStrategyTypeScheduled; break;
    case UpdateStrategyManual: type = UpdateStrategyTypeManual; break;
    case UpdateStrategyPush: type = UpdateStrategyTypeDynamic; break;
    default: type = UpdateStrategyTypeInterval; break;
  }
  return [self strategyOfType:type];
}

+ (id<UpdateStrategy>)strategyOfType:(UpdateStrategyType)type {
  Class strategyClass = _strategyClasses[@(type)];
  if (!strategyClass) {
    DNSLogError(LogCategoryScheduler, "No strategy class registered for type: %ld", (long)type);
    return nil;
  }

  return [[strategyClass alloc] init];
}

+ (void)registerStrategyClass:(Class)strategyClass forType:(UpdateStrategyType)type {
  if (![strategyClass conformsToProtocol:@protocol(UpdateStrategy)]) {
    DNSLogError(LogCategoryScheduler, "Strategy class does not conform to UpdateStrategy protocol");
    return;
  }

  _strategyClasses[@(type)] = strategyClass;
}

@end
