//
//  RuleManager.m
//  DNShield Network Extension
//
//  Implementation of the main rule management orchestration
//

#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <Rule/Fetcher.h>
#import <Rule/FileRuleFetcher.h>
#import <Rule/HTTPRuleFetcher.h>
#import <Rule/Manager.h>
#import <Rule/Parser.h>
#import <Rule/RuleSet.h>

#import "ConfigurationManager.h"
#import "NetworkReachability.h"
#import "RuleCache.h"
#import "UpdateScheduler.h"

#pragma mark - Rule Update Result

@interface RuleUpdateResult ()
@property(nonatomic, strong) RuleSource* source;
@property(nonatomic, strong, nullable) RuleSet* ruleSet;
@property(nonatomic, strong, nullable) NSError* error;
@property(nonatomic, assign) BOOL success;
@property(nonatomic, assign) BOOL fromCache;
@property(nonatomic, strong) NSDate* timestamp;
@property(nonatomic, assign) NSTimeInterval fetchDuration;
@property(nonatomic, assign) NSTimeInterval parseDuration;
@property(nonatomic, assign) NSUInteger ruleCount;
@end

@implementation RuleUpdateResult

- (instancetype)initWithSource:(RuleSource*)source {
  self = [super init];
  if (self) {
    _source = source;
    _timestamp = [NSDate date];
  }
  return self;
}

@end

#pragma mark - Rule Manager Private

@interface RuleManager () <UpdateSchedulerDelegate>

@property(nonatomic, strong) DNSConfiguration* configuration;
@property(nonatomic, strong) UpdateScheduler* scheduler;
@property(nonatomic, strong) RuleCache* cache;
@property(nonatomic, strong) NSMutableDictionary<NSString*, id<RuleFetcher>>* fetchers;
@property(nonatomic, strong) NSMutableDictionary<NSString*, id<RuleParser>>* parsers;
@property(nonatomic, strong) NSMutableDictionary<NSString*, RuleUpdateResult*>* updateResults;
@property(nonatomic, strong) dispatch_queue_t managerQueue;
@property(nonatomic, strong) dispatch_queue_t updateQueue;
@property(nonatomic, strong) NSOperationQueue* updateOperationQueue;

// State management
@property(nonatomic, assign) RuleManagerState state;
@property(nonatomic, strong, nullable) RuleSet* currentRuleSet;
@property(nonatomic, strong, nullable) NSDate* lastUpdateDate;
@property(nonatomic, strong, nullable) NSError* lastUpdateError;

// Rule sets by source
@property(nonatomic, strong) NSMutableDictionary<NSString*, RuleSet*>* sourceRuleSets;

// Statistics
@property(nonatomic, strong) NSMutableDictionary<NSString*, NSNumber*>* ruleCountBySource;

@end

@implementation RuleManager

#pragma mark - Initialization

- (instancetype)initWithConfiguration:(DNSConfiguration*)configuration {
  self = [super init];
  if (self) {
    _configuration = configuration;
    _state = RuleManagerStateStopped;

    // Initialize queues
    _managerQueue = dispatch_queue_create("com.dnshield.rulemanager", DISPATCH_QUEUE_SERIAL);
    _updateQueue =
        dispatch_queue_create("com.dnshield.rulemanager.update", DISPATCH_QUEUE_CONCURRENT);

    _updateOperationQueue = [[NSOperationQueue alloc] init];
    _updateOperationQueue.maxConcurrentOperationCount = 3;
    _updateOperationQueue.name = @"com.dnshield.rulemanager.operations";

    // Initialize storage
    _fetchers = [NSMutableDictionary dictionary];
    _parsers = [NSMutableDictionary dictionary];
    _updateResults = [NSMutableDictionary dictionary];
    _sourceRuleSets = [NSMutableDictionary dictionary];
    _ruleCountBySource = [NSMutableDictionary dictionary];

    // Initialize cache
    _cache = [[RuleCache alloc] initWithConfiguration:configuration.cacheConfig];

    // Initialize scheduler
    _scheduler = [[UpdateScheduler alloc] initWithConfiguration:configuration.updateConfig];
    _scheduler.delegate = self;

    // Setup components for each rule source
    [self setupComponentsForConfiguration:configuration];

    DNSLogInfo(LogCategoryScheduler, "RuleManager initialized with %lu sources",
               (unsigned long)configuration.ruleSources.count);
  }
  return self;
}

- (void)dealloc {
  // Do not call stopUpdating from dealloc as it uses async blocks
  // which can't safely reference self during deallocation.
  // stopUpdating should be called explicitly before the object is released.

  // Synchronously clean up resources that don't need self references
  if (_updateOperationQueue) {
    [_updateOperationQueue cancelAllOperations];
  }

  if (_scheduler) {
    // Use synchronous stop to avoid async dispatch issues during dealloc
    if ([_scheduler respondsToSelector:@selector(stopSynchronously)]) {
      [_scheduler stopSynchronously];
    } else {
      // Fallback to regular stop if stopSynchronously is not available
      [_scheduler stop];
    }
  }
}

#pragma mark - Setup

- (void)setupComponentsForConfiguration:(DNSConfiguration*)configuration {
  for (RuleSource* source in configuration.ruleSources) {
    if (!source.enabled) {
      DNSLogInfo(LogCategoryScheduler, "Skipping disabled source: %@", source.identifier);
      continue;
    }

    // Create fetcher
    id<RuleFetcher> fetcher = [self createFetcherForSource:source];
    if (fetcher) {
      self.fetchers[source.identifier] = fetcher;
    } else {
      DNSLogError(LogCategoryScheduler, "Failed to create fetcher for source: %@",
                  source.identifier);
      continue;
    }

    // Create parser
    id<RuleParser> parser = [RuleParserFactory parserForFormat:source.format];
    if (parser) {
      self.parsers[source.identifier] = parser;
    } else {
      DNSLogError(LogCategoryScheduler, "Failed to create parser for format: %@", source.format);
      continue;
    }

    // Add to scheduler
    [self.scheduler addRuleSource:source];
  }
}

- (id<RuleFetcher>)createFetcherForSource:(RuleSource*)source {
  switch (source.type) {
    case RuleSourceTypeHTTPS: {
      if (!source.url) {
        DNSLogError(LogCategoryScheduler, "HTTPS source missing URL");
        return nil;
      }

      NSURL* url = [NSURL URLWithString:source.url];
      HTTPRuleFetcher* fetcher = [[HTTPRuleFetcher alloc] initWithURL:url
                                                        configuration:source.configuration];

      // Configure authentication if needed
      if (source.apiKey) {
        [fetcher configureAPIKeyAuth:source.apiKey headerName:@"X-API-Key"];
      }

      return fetcher;
    }

    case RuleSourceTypeFile: {
      if (!source.path) {
        DNSLogError(LogCategoryScheduler, "File source missing path");
        return nil;
      }

      FileRuleFetcher* fetcher = [[FileRuleFetcher alloc] initWithFilePath:source.path
                                                             configuration:source.configuration];

      // Start watching if configured
      NSNumber* watchForChanges = source.configuration[@"watchForChanges"];
      if ([watchForChanges boolValue]) {
        [fetcher startWatching];
      }

      return fetcher;
    }

    case RuleSourceTypeUnknown:
    default:
      DNSLogError(LogCategoryScheduler, "Unknown source type: %ld", (long)source.type);
      return nil;
  }
}

#pragma mark - State Management

- (void)startUpdating {
  __weak typeof(self) weakSelf = self;
  dispatch_async(self.managerQueue, ^{
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (!strongSelf) {
      DNSLogInfo(LogCategoryScheduler,
                 "RuleManager deallocated before startUpdating block executed");
      return;
    }

    if (strongSelf.state == RuleManagerStateRunning) {
      DNSLogInfo(LogCategoryScheduler, "RuleManager already running");
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Starting RuleManager");

    [strongSelf setState:RuleManagerStateStarting];

    // Load cached rules first
    [strongSelf loadCachedRules];

    // Only start the scheduler if NOT using manifest-based configuration
    // Manifest mode uses its own timer that handles both manifest and rule updates
    BOOL usingManifest = NO;
    if ([strongSelf respondsToSelector:@selector(isUsingManifest)]) {
      usingManifest = [(id)strongSelf isUsingManifest];
    }

    if (!usingManifest) {
      // Start the scheduler for non-manifest mode
      [strongSelf.scheduler start];
      DNSLogInfo(LogCategoryScheduler, "Started UpdateScheduler (non-manifest mode)");
    } else {
      DNSLogInfo(LogCategoryScheduler, "Skipping UpdateScheduler start (manifest mode active)");
    }

    [strongSelf setState:RuleManagerStateRunning];

    if ([strongSelf.delegate respondsToSelector:@selector(ruleManagerDidStart:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [strongSelf.delegate ruleManagerDidStart:strongSelf];
      });
    }
  });
}

- (void)stopUpdating {
  __weak typeof(self) weakSelf = self;
  dispatch_async(self.managerQueue, ^{
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (!strongSelf) {
      DNSLogInfo(LogCategoryScheduler,
                 "RuleManager deallocated before stopUpdating block executed");
      return;
    }

    if (strongSelf.state == RuleManagerStateStopped) {
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Stopping RuleManager");

    [strongSelf setState:RuleManagerStateStopping];

    // Stop the scheduler
    [strongSelf.scheduler stop];

    // Cancel all operations
    [strongSelf.updateOperationQueue cancelAllOperations];
    [strongSelf.updateOperationQueue waitUntilAllOperationsAreFinished];

    // Stop file watchers
    [strongSelf.fetchers
        enumerateKeysAndObjectsUsingBlock:^(NSString* key, id<RuleFetcher> fetcher, BOOL* stop) {
          if ([fetcher isKindOfClass:[FileRuleFetcher class]]) {
            [(FileRuleFetcher*)fetcher stopWatching];
          }
        }];

// Stop manifest update timer if using manifest-based configuration
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"
    if ([strongSelf respondsToSelector:@selector(stopManifestUpdateTimer)]) {
      [strongSelf performSelector:@selector(stopManifestUpdateTimer)];
    }
#pragma clang diagnostic pop

    [strongSelf setState:RuleManagerStateStopped];

    if ([strongSelf.delegate respondsToSelector:@selector(ruleManagerDidStop:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [strongSelf.delegate ruleManagerDidStop:strongSelf];
      });
    }
  });
}

- (void)setState:(RuleManagerState)newState {
  if (_state != newState) {
    _state = newState;

    DNSLogInfo(LogCategoryScheduler, "RuleManager state changed to: %@",
               [self stateString:newState]);

    if ([self.delegate respondsToSelector:@selector(ruleManager:didChangeState:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate ruleManager:self didChangeState:newState];
      });
    }
  }
}

- (NSString*)stateString:(RuleManagerState)state {
  switch (state) {
    case RuleManagerStateStopped: return @"Stopped";
    case RuleManagerStateStarting: return @"Starting";
    case RuleManagerStateRunning: return @"Running";
    case RuleManagerStateStopping: return @"Stopping";
    case RuleManagerStateError: return @"Error";
  }
}

#pragma mark - Updates

- (void)forceUpdate {
  dispatch_async(self.managerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Forcing update of all sources");
    [self.scheduler updateAllSourcesWithPriority:UpdatePriorityHigh];
  });
}

- (void)forceUpdateSource:(RuleSource*)source {
  dispatch_async(self.managerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Forcing update of source: %@", source.identifier);
    [self.scheduler updateSource:source priority:UpdatePriorityHigh];
  });
}

#pragma mark - Rule Source Management

- (NSArray<RuleSource*>*)allRuleSources {
  return self.configuration.ruleSources;
}

- (nullable RuleSource*)ruleSourceWithIdentifier:(NSString*)identifier {
  for (RuleSource* source in self.configuration.ruleSources) {
    if ([source.identifier isEqualToString:identifier]) {
      return source;
    }
  }
  return nil;
}

- (nullable RuleSet*)ruleSetForSource:(RuleSource*)source {
  return self.sourceRuleSets[source.identifier];
}

- (nullable RuleUpdateResult*)lastUpdateResultForSource:(RuleSource*)source {
  return self.updateResults[source.identifier];
}

- (NSArray<RuleUpdateResult*>*)recentUpdateResults {
  return [self.updateResults allValues];
}

#pragma mark - Cache Management

- (void)clearCache {
  dispatch_async(self.managerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Clearing all cache");
    [self.cache clearAllCaches];

    if ([self.delegate respondsToSelector:@selector(ruleManagerDidClearCache:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate ruleManagerDidClearCache:self];
      });
    }
  });
}

- (void)clearCacheForSource:(RuleSource*)source {
  dispatch_async(self.managerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Clearing cache for source: %@", source.identifier);
    [self.cache invalidateCacheForSource:source.identifier];
  });
}

- (NSUInteger)cacheSize {
  return [self.cache totalCacheSize];
}

#pragma mark - Statistics

- (NSUInteger)totalRuleCount {
  __block NSUInteger total = 0;
  [self.sourceRuleSets
      enumerateKeysAndObjectsUsingBlock:^(NSString* key, RuleSet* ruleSet, BOOL* stop) {
        total += ruleSet.rules.count;
      }];
  return total;
}

#pragma mark - Configuration Updates

- (void)updateConfiguration:(DNSConfiguration*)configuration {
  dispatch_async(self.managerQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Updating configuration");

    self.configuration = configuration;

    // Mark configuration as transition state if it has no rule sources but we're in startup/restart
    if (configuration.ruleSources.count == 0) {
      configuration.isTransitionState = YES;
      DNSLogInfo(LogCategoryConfiguration,
                 "Marking configuration as transition state due to empty rule sources");
    }

    // Also update ConfigurationManager to ensure consistency
    NSError* saveError = nil;
    if (![[ConfigurationManager sharedManager] saveConfiguration:configuration error:&saveError]) {
      DNSLogError(LogCategoryConfiguration,
                  "Failed to save configuration to ConfigurationManager: %@", saveError);
    }

    // Check if we're using manifest-based configuration
    BOOL usingManifest = NO;
    if ([self respondsToSelector:@selector(isUsingManifest)]) {
      usingManifest = [(id)self isUsingManifest];
    }

    if (!usingManifest) {
      // Only manage scheduler if NOT in manifest mode
      DNSLogInfo(LogCategoryScheduler, "Managing scheduler updates (non-manifest mode)");
      // Update scheduler configuration
      [self.scheduler stop];
      [self.scheduler removeAllRuleSources];
    } else {
      DNSLogInfo(LogCategoryScheduler, "Skipping scheduler management (manifest mode active)");
    }

    // Clear old components
    [self.fetchers removeAllObjects];
    [self.parsers removeAllObjects];

    // Setup new components
    [self setupComponentsForConfiguration:configuration];

    if (!usingManifest) {
      // Restart if we were running and NOT in manifest mode
      if (self.state == RuleManagerStateRunning) {
        [self.scheduler start];
      }
    }
  });
}

#pragma mark - Testing Support

- (void)injectTestRuleSet:(RuleSet*)ruleSet forSource:(RuleSource*)source {
  dispatch_async(self.managerQueue, ^{
    DNSLogDebug(LogCategoryScheduler, "Injecting test rule set for source: %@", source.identifier);

    self.sourceRuleSets[source.identifier] = ruleSet;
    [self.cache storeRuleSet:ruleSet forSource:source.identifier timeToLive:3600];

    // Merge and notify
    [self mergeRuleSetsAndNotify];
  });
}

#pragma mark - Private Methods

- (void)loadCachedRules {
  DNSLogInfo(LogCategoryScheduler, "Loading cached rules");

  for (RuleSource* source in self.configuration.ruleSources) {
    RuleSet* cachedRuleSet = [self.cache ruleSetForSource:source.identifier];
    if (cachedRuleSet) {
      DNSLogInfo(LogCategoryScheduler, "Loaded cached rules for source: %@ (%lu rules)",
                 source.identifier, (unsigned long)cachedRuleSet.rules.count);

      self.sourceRuleSets[source.identifier] = cachedRuleSet;

      if ([self.delegate respondsToSelector:@selector(ruleManager:didLoadFromCacheForSource:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
          [self.delegate ruleManager:self didLoadFromCacheForSource:source];
        });
      }
    }
  }

  // Merge cached rules
  [self mergeRuleSetsAndNotify];
}

- (void)performUpdateForSource:(RuleSource*)source task:(UpdateTask*)task {
  DNSLogInfo(LogCategoryScheduler, "Starting update for source: %@", source.identifier);

  RuleUpdateResult* result = [[RuleUpdateResult alloc] initWithSource:source];
  NSDate* startTime = [NSDate date];

  // Get fetcher and parser
  id<RuleFetcher> fetcher = self.fetchers[source.identifier];
  id<RuleParser> parser = self.parsers[source.identifier];

  if (!fetcher || !parser) {
    NSError* error = DNSMakeError(DNSRuleManagerErrorDomain, DNSRuleManagerErrorNotInitialized,
                                  @"Fetcher or parser not available");
    result.error = error;
    result.success = NO;
    [self completeUpdateWithResult:result task:task];
    return;
  }

  // Check cache first
  RuleSet* cachedRuleSet = [self.cache ruleSetForSource:source.identifier
                                                 maxAge:source.updateInterval];
  if (cachedRuleSet && task.priority != UpdatePriorityHigh) {
    DNSLogInfo(LogCategoryScheduler, "Using cached rules for source: %@", source.identifier);

    result.ruleSet = cachedRuleSet;
    result.success = YES;
    result.fromCache = YES;
    result.ruleCount = cachedRuleSet.rules.count;

    self.sourceRuleSets[source.identifier] = cachedRuleSet;
    [self completeUpdateWithResult:result task:task];
    return;
  }

  // Fetch new rules
  __weak typeof(self) weakSelf = self;
  [fetcher
      fetchRulesWithProgress:^(float progress) {
        __strong typeof(self) strongSelf = weakSelf;
        if (strongSelf && [strongSelf.delegate respondsToSelector:@selector
                                               (ruleManager:updateProgress:forSource:)]) {
          dispatch_async(dispatch_get_main_queue(), ^{
            [strongSelf.delegate ruleManager:strongSelf updateProgress:progress forSource:source];
          });
        }
      }
      completion:^(NSData* data, NSError* error) {
        __strong typeof(self) strongSelf = weakSelf;
        if (!strongSelf)
          return;

        if (error) {
          DNSLogError(LogCategoryScheduler, "Failed to fetch rules for source %@: %@",
                      source.identifier, error);

          // Try to use cached version as fallback
          RuleSet* fallbackRuleSet = [strongSelf.cache ruleSetForSource:source.identifier];
          if (fallbackRuleSet) {
            DNSLogInfo(LogCategoryScheduler, "Using cached rules as fallback for source: %@",
                       source.identifier);

            result.ruleSet = fallbackRuleSet;
            result.success = YES;
            result.fromCache = YES;
            result.ruleCount = fallbackRuleSet.rules.count;
            result.error = error;  // Still record the fetch error

            strongSelf.sourceRuleSets[source.identifier] = fallbackRuleSet;
          } else {
            result.error = error;
            result.success = NO;
          }

          result.fetchDuration = [[NSDate date] timeIntervalSinceDate:startTime];
          [strongSelf completeUpdateWithResult:result task:task];
          return;
        }

        result.fetchDuration = [[NSDate date] timeIntervalSinceDate:startTime];
        NSDate* parseStartTime = [NSDate date];

        // Parse the data
        NSError* parseError;
        RuleSet* ruleSet = [parser parseData:data error:&parseError];

        if (parseError || !ruleSet) {
          DNSLogError(LogCategoryScheduler, "Failed to parse rules for source %@: %@",
                      source.identifier, parseError);

          result.error = parseError
                             ?: DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorUnknown,
                                             @"Parser returned nil without error");
          result.success = NO;
          result.parseDuration = [[NSDate date] timeIntervalSinceDate:parseStartTime];
          [strongSelf completeUpdateWithResult:result task:task];
          return;
        }

        result.parseDuration = [[NSDate date] timeIntervalSinceDate:parseStartTime];

        DNSLogInfo(LogCategoryScheduler, "Successfully updated source %@ with %lu rules",
                   source.identifier, (unsigned long)ruleSet.rules.count);

        // Store in cache
        [strongSelf.cache storeRuleSet:ruleSet forSource:source.identifier];

        // Update results
        result.ruleSet = ruleSet;
        result.success = YES;
        result.fromCache = NO;
        result.ruleCount = ruleSet.rules.count;

        strongSelf.sourceRuleSets[source.identifier] = ruleSet;
        [strongSelf->_ruleCountBySource setObject:@(ruleSet.rules.count) forKey:source.identifier];

        [strongSelf completeUpdateWithResult:result task:task];
      }];
}

- (void)completeUpdateWithResult:(RuleUpdateResult*)result task:(UpdateTask*)task {
  dispatch_async(self.managerQueue, ^{
    // Store result
    self.updateResults[result.source.identifier] = result;

    // Update last update info
    self.lastUpdateDate = [NSDate date];
    if (!result.success && result.error) {
      self.lastUpdateError = result.error;
    }

    // Notify delegate
    if ([self.delegate respondsToSelector:@selector(ruleManager:didUpdateSource:withResult:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate ruleManager:self didUpdateSource:result.source withResult:result];
      });
    }

    // If successful, merge and notify
    if (result.success) {
      [self mergeRuleSetsAndNotify];
    }

    // Complete the task
    task.success = result.success;
    task.error = result.error;
    task.completionTime = [NSDate date];

    // Task completed - scheduler will be notified via delegate callback
  });
}

- (void)mergeRuleSetsAndNotify {
  dispatch_async(self.updateQueue, ^{
    DNSLogInfo(LogCategoryScheduler, "Merging rule sets from %lu sources",
               (unsigned long)self.sourceRuleSets.count);

    // Clear transition state if we have successfully loaded rule sets
    if (self.sourceRuleSets.count > 0 && self.configuration.isTransitionState) {
      self.configuration.isTransitionState = NO;
      DNSLogInfo(LogCategoryConfiguration, "Clearing transition state - rules successfully loaded");

      // Save the updated configuration to persist the change
      NSError* saveError = nil;
      if (![[ConfigurationManager sharedManager] saveConfiguration:self.configuration
                                                             error:&saveError]) {
        DNSLogError(LogCategoryConfiguration,
                    "Failed to save configuration after clearing transition state: %@", saveError);
      }
    }

    NSMutableArray<RuleSet*>* ruleSetsToMerge = [NSMutableArray array];

    // Collect rule sets sorted by priority
    NSArray* sortedSources = [self.configuration.ruleSources
        sortedArrayUsingComparator:^NSComparisonResult(RuleSource* s1, RuleSource* s2) {
          return [@(s2.priority) compare:@(s1.priority)];  // Higher priority first
        }];

    for (RuleSource* source in sortedSources) {
      RuleSet* ruleSet = self.sourceRuleSets[source.identifier];
      if (ruleSet) {
        [ruleSetsToMerge addObject:ruleSet];
      }
    }

    if (ruleSetsToMerge.count == 0) {
      DNSLogInfo(LogCategoryScheduler, "No rule sets to merge");
      return;
    }

    // Merge rule sets
    NSError* mergeError;
    RuleSet* mergedRuleSet = [RuleSetMerger mergeRuleSets:ruleSetsToMerge
                                                  options:RuleSetMergeOptionPreferHigherPriority
                                                    error:&mergeError];

    if (mergeError || !mergedRuleSet) {
      DNSLogError(LogCategoryScheduler, "Failed to merge rule sets: %@", mergeError);
      self.lastUpdateError = mergeError;

      if ([self.delegate respondsToSelector:@selector(ruleManagerDidFailUpdate:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
          [self.delegate ruleManagerDidFailUpdate:mergeError];
        });
      }
      return;
    }

    DNSLogInfo(LogCategoryScheduler, "Merged rule set contains %lu rules",
               (unsigned long)mergedRuleSet.rules.count);

    // Update current rule set
    dispatch_async(self.managerQueue, ^{
      self.currentRuleSet = mergedRuleSet;
      self.lastUpdateDate = [NSDate date];
      self.lastUpdateError = nil;

      // Notify delegate
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate ruleManagerDidUpdateRules:mergedRuleSet];
      });
    });
  });
}

#pragma mark - UpdateScheduler Delegate

- (void)updateScheduler:(UpdateScheduler*)scheduler
     shouldUpdateSource:(RuleSource*)source
               withTask:(UpdateTask*)task {
  // Create operation for update
  NSBlockOperation* updateOperation = [NSBlockOperation blockOperationWithBlock:^{
    if (task.cancelled) {
      return;
    }

    [self performUpdateForSource:source task:task];
  }];

  updateOperation.name = [NSString stringWithFormat:@"Update-%@", source.identifier];
  updateOperation.queuePriority = [self operationPriorityFromUpdatePriority:task.priority];

  [self.updateOperationQueue addOperation:updateOperation];
}

- (NSOperationQueuePriority)operationPriorityFromUpdatePriority:(UpdatePriority)priority {
  switch (priority) {
    case UpdatePriorityCritical: return NSOperationQueuePriorityVeryHigh;
    case UpdatePriorityHigh: return NSOperationQueuePriorityHigh;
    case UpdatePriorityNormal: return NSOperationQueuePriorityNormal;
    case UpdatePriorityBackground: return NSOperationQueuePriorityLow;
  }
}

- (void)updateSchedulerDidStart:(UpdateScheduler*)scheduler {
  DNSLogDebug(LogCategoryScheduler, "Update scheduler started");
}

- (void)updateSchedulerDidStop:(UpdateScheduler*)scheduler {
  DNSLogDebug(LogCategoryScheduler, "Update scheduler stopped");
}

- (void)updateScheduler:(UpdateScheduler*)scheduler
            didFailTask:(UpdateTask*)task
              withError:(NSError*)error {
  DNSLogError(LogCategoryScheduler, "Update task failed for source %@: %@", task.source.identifier,
              error);
}

@end
