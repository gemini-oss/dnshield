//
//  RuleFetcher.m
//  DNShield Network Extension
//
//  Implementation of base fetcher functionality
//

#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <Rule/Fetcher.h>

// Configuration keys
NSString* const RuleFetcherConfigKeyTimeout = @"timeout";
NSString* const RuleFetcherConfigKeyRetryCount = @"retryCount";
NSString* const RuleFetcherConfigKeyRetryDelay = @"retryDelay";
NSString* const RuleFetcherConfigKeyMaxSize = @"maxSize";
NSString* const RuleFetcherConfigKeyCachePolicy = @"cachePolicy";
NSString* const RuleFetcherConfigKeyPriority = @"priority";

// Notification names
NSString* const RuleFetcherDidStartNotification = @"RuleFetcherDidStartNotification";
NSString* const RuleFetcherDidUpdateProgressNotification =
    @"RuleFetcherDidUpdateProgressNotification";
NSString* const RuleFetcherDidCompleteNotification = @"RuleFetcherDidCompleteNotification";
NSString* const RuleFetcherDidCancelNotification = @"RuleFetcherDidCancelNotification";

// Notification user info keys
NSString* const RuleFetcherNotificationKeyProgress = @"progress";
NSString* const RuleFetcherNotificationKeyData = @"data";
NSString* const RuleFetcherNotificationKeyError = @"error";
NSString* const RuleFetcherNotificationKeyIdentifier = @"identifier";

@interface RuleFetcherBase ()
@property(nonatomic, strong) dispatch_queue_t fetchQueue;
@property(nonatomic, strong) dispatch_queue_t delegateQueue;
@property(nonatomic, strong) NSMutableDictionary* statistics;
@property(nonatomic, strong) NSDate* fetchStartDate;
@property(nonatomic, assign) BOOL cancelled;
@property(nonatomic, copy) RuleFetcherProgressBlock progressBlock;
@property(nonatomic, copy) RuleFetcherCompletionBlock completionBlock;
@end

@implementation RuleFetcherBase

- (instancetype)init {
  return [self initWithConfiguration:nil];
}

- (instancetype)initWithConfiguration:(nullable NSDictionary*)configuration {
  self = [super init];
  if (self) {
    _identifier = [[NSUUID UUID] UUIDString];
    _configuration = configuration ?: @{};
    _statistics = [NSMutableDictionary dictionary];

    // Create queues
    NSString* queueLabel = [NSString stringWithFormat:@"com.dnshield.rulefetcher.%@", _identifier];
    _fetchQueue = dispatch_queue_create([queueLabel UTF8String], DISPATCH_QUEUE_SERIAL);
    _delegateQueue = dispatch_queue_create(
        [[queueLabel stringByAppendingString:@".delegate"] UTF8String], DISPATCH_QUEUE_SERIAL);

    // Apply configuration
    [self applyConfiguration:_configuration];

    DNSLogDebug(LogCategoryRuleFetching, "RuleFetcherBase initialized with ID: %@", _identifier);
  }
  return self;
}

- (void)applyConfiguration:(NSDictionary*)config {
  // Timeout (default 10 seconds - reduced from 30)
  NSNumber* timeout = config[RuleFetcherConfigKeyTimeout];
  self.timeout = timeout ? [timeout doubleValue] : 10.0;

  // Retry settings
  NSNumber* retryCount = config[RuleFetcherConfigKeyRetryCount];
  self.maxRetryCount = retryCount ? [retryCount unsignedIntegerValue] : 3;

  NSNumber* retryDelay = config[RuleFetcherConfigKeyRetryDelay];
  self.retryDelay = retryDelay ? [retryDelay doubleValue] : 1.0;

  // Default to exponential backoff
  self.useExponentialBackoff = YES;
}

#pragma mark - RuleFetcher Protocol (Required)

- (void)fetchRulesWithCompletion:(RuleFetcherCompletionBlock)completion {
  [self fetchRulesWithProgress:nil completion:completion];
}

- (void)fetchRulesWithProgress:(nullable RuleFetcherProgressBlock)progress
                    completion:(RuleFetcherCompletionBlock)completion {
  dispatch_async(self.fetchQueue, ^{
    if (self.isFetching) {
      NSError* error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorUnknown,
                                    @"Fetch already in progress");
      dispatch_async(self.delegateQueue, ^{
        completion(nil, error);
      });
      return;
    }

    DNSLogInfo(LogCategoryRuleFetching, "Starting fetch with fetcher: %@", self.identifier);
    NSString* perfKey = [NSString stringWithFormat:@"fetch_%@", self.identifier];
    DNSLogPerformanceStart(perfKey);

    self->_isFetching = YES;
    self->_cancelled = NO;
    self.progressBlock = progress;
    self.completionBlock = completion;
    self.fetchStartDate = [NSDate date];

    [self.statistics removeAllObjects];
    self.statistics[@"startTime"] = self.fetchStartDate;

    [self notifyStart];

    // Start fetch with retry logic
    [self performFetchWithRetry:self.maxRetryCount
                     completion:^(NSData* data, NSError* error) {
                       [self handleFetchCompletion:data error:error];
                     }];
  });
}

- (BOOL)supportsResume {
  // Default implementation - subclasses should override if they support resume
  return NO;
}

- (void)cancelFetch {
  dispatch_async(self.fetchQueue, ^{
    if (!self.isFetching) {
      return;
    }

    DNSLogInfo(LogCategoryRuleFetching, "Cancelling fetch for fetcher: %@", self.identifier);

    self.cancelled = YES;
    [self performCancelFetch];

    self->_isFetching = NO;
    [self notifyCancel];

    NSError* error =
        DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorCancelled, @"Fetch cancelled");
    if (self.completionBlock) {
      dispatch_async(self.delegateQueue, ^{
        self.completionBlock(nil, error);
        self.completionBlock = nil;
        self.progressBlock = nil;
      });
    }
  });
}

#pragma mark - Optional Protocol Methods

- (void)configureWithOptions:(NSDictionary*)options {
  self.configuration = options;
  [self applyConfiguration:options];
}

- (BOOL)validateConfiguration:(NSError**)error {
  // Default implementation - subclasses should override for specific validation
  return YES;
}

- (void)resumeFetchWithCompletion:(RuleFetcherCompletionBlock)completion {
  if (![self supportsResume]) {
    if (completion) {
      NSError* error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorUnknown,
                                    @"Resume not supported by this fetcher");
      completion(nil, error);
    }
    return;
  }

  // Subclasses that support resume should override this
  [self fetchRulesWithCompletion:completion];
}

- (NSTimeInterval)estimatedTimeRemaining {
  if (!self.isFetching || !self.fetchStartDate) {
    return 0;
  }

  NSNumber* progress = self.statistics[@"progress"];
  if (!progress || [progress floatValue] <= 0) {
    return -1;  // Unknown
  }

  NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:self.fetchStartDate];
  float currentProgress = [progress floatValue];

  if (currentProgress >= 1.0) {
    return 0;
  }

  NSTimeInterval totalEstimated = elapsed / currentProgress;
  return totalEstimated - elapsed;
}

- (NSDictionary*)downloadStatistics {
  return [self.statistics copy];
}

#pragma mark - Subclass Override Points

- (void)performFetchWithCompletion:(RuleFetcherCompletionBlock)completion {
  // Subclasses must override this
  NSAssert(NO, @"Subclasses must override performFetchWithCompletion:");
  NSError* error =
      DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorUnknown, @"Not implemented");
  completion(nil, error);
}

- (void)performCancelFetch {
  // Subclasses should override this to cancel their specific operations
}

#pragma mark - Helper Methods

- (void)notifyProgress:(float)progress {
  dispatch_async(self.delegateQueue, ^{
    self.statistics[@"progress"] = @(progress);

    if (self.progressBlock) {
      self.progressBlock(progress);
    }

    if ([self.delegate respondsToSelector:@selector(ruleFetcher:didUpdateProgress:)]) {
      [self.delegate ruleFetcher:self didUpdateProgress:progress];
    }

    [[NSNotificationCenter defaultCenter]
        postNotificationName:RuleFetcherDidUpdateProgressNotification
                      object:self
                    userInfo:@{
                      RuleFetcherNotificationKeyProgress : @(progress),
                      RuleFetcherNotificationKeyIdentifier : self.identifier
                    }];
  });
}

- (void)notifyCompletion:(nullable NSData*)data error:(nullable NSError*)error {
  dispatch_async(self.delegateQueue, ^{
    if ([self.delegate respondsToSelector:@selector(ruleFetcher:didCompleteWithData:error:)]) {
      [self.delegate ruleFetcher:self didCompleteWithData:data error:error];
    }

    NSMutableDictionary* userInfo =
        [@{RuleFetcherNotificationKeyIdentifier : self.identifier} mutableCopy];
    if (data)
      userInfo[RuleFetcherNotificationKeyData] = data;
    if (error)
      userInfo[RuleFetcherNotificationKeyError] = error;

    [[NSNotificationCenter defaultCenter] postNotificationName:RuleFetcherDidCompleteNotification
                                                        object:self
                                                      userInfo:userInfo];
  });
}

- (void)notifyStart {
  dispatch_async(self.delegateQueue, ^{
    if ([self.delegate respondsToSelector:@selector(ruleFetcherDidStart:)]) {
      [self.delegate ruleFetcherDidStart:self];
    }

    [[NSNotificationCenter defaultCenter]
        postNotificationName:RuleFetcherDidStartNotification
                      object:self
                    userInfo:@{RuleFetcherNotificationKeyIdentifier : self.identifier}];
  });
}

- (void)notifyCancel {
  dispatch_async(self.delegateQueue, ^{
    if ([self.delegate respondsToSelector:@selector(ruleFetcherDidCancel:)]) {
      [self.delegate ruleFetcherDidCancel:self];
    }

    [[NSNotificationCenter defaultCenter]
        postNotificationName:RuleFetcherDidCancelNotification
                      object:self
                    userInfo:@{RuleFetcherNotificationKeyIdentifier : self.identifier}];
  });
}

#pragma mark - Retry Logic

- (NSTimeInterval)retryDelayForAttempt:(NSUInteger)attempt {
  if (!self.useExponentialBackoff) {
    return self.retryDelay;
  }

  // Exponential backoff: delay * 2^(attempt-1)
  // With jitter to avoid thundering herd
  NSTimeInterval baseDelay = self.retryDelay * pow(2, attempt - 1);
  NSTimeInterval jitter = (arc4random_uniform(1000) / 1000.0) * 0.3 * baseDelay;  // ±30% jitter
  return baseDelay + jitter;
}

- (void)performFetchWithRetry:(NSUInteger)remainingAttempts
                   completion:(RuleFetcherCompletionBlock)completion {
  if (self.cancelled) {
    NSError* error =
        DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorCancelled, @"Fetch cancelled");
    completion(nil, error);
    return;
  }

  NSUInteger attemptNumber = self.maxRetryCount - remainingAttempts + 1;
  DNSLogDebug(LogCategoryRuleFetching, "Fetch attempt %lu of %lu", attemptNumber,
              self.maxRetryCount + 1);

  [self performFetchWithCompletion:^(NSData* data, NSError* error) {
    if (!error || remainingAttempts == 0 || !DNSIsRetryableError(error) || self.cancelled) {
      // Success, no retries left, non-retryable error, or cancelled
      completion(data, error);
      return;
    }

    // Calculate retry delay
    NSTimeInterval delay = [self retryDelayForAttempt:attemptNumber];

    DNSLogInfo(LogCategoryRuleFetching,
               "Fetch failed with retryable error: %@. Retrying in %.2f seconds...",
               error.localizedDescription, delay);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   self.fetchQueue, ^{
                     [self performFetchWithRetry:remainingAttempts - 1 completion:completion];
                   });
  }];
}

#pragma mark - Private Methods

- (void)handleFetchCompletion:(nullable NSData*)data error:(nullable NSError*)error {
  dispatch_async(self.fetchQueue, ^{
    if (!self.isFetching) {
      return;  // Already cancelled or completed
    }

    NSString* perfEndKey = [NSString stringWithFormat:@"fetch_%@", self.identifier];
    DNSLogPerformanceEnd(perfEndKey);

    self->_isFetching = NO;
    self->_lastFetchDate = [NSDate date];
    self->_lastError = error;

    self.statistics[@"endTime"] = self.lastFetchDate;
    self.statistics[@"duration"] =
        @([self.lastFetchDate timeIntervalSinceDate:self.fetchStartDate]);
    if (data) {
      self.statistics[@"dataSize"] = @(data.length);
    }

    if (error) {
      DNSLogError(LogCategoryRuleFetching, "Fetch completed with error: %@", error);
      [[LoggingManager sharedManager] logError:error
                                      category:LogCategoryRuleFetching
                                       context:@"Rule fetch completion"];
    } else {
      DNSLogInfo(LogCategoryRuleFetching, "Fetch completed successfully. Data size: %lu bytes",
                 (unsigned long)data.length);
    }

    [self notifyCompletion:data error:error];

    if (self.completionBlock) {
      dispatch_async(self.delegateQueue, ^{
        self.completionBlock(data, error);
        self.completionBlock = nil;
        self.progressBlock = nil;
      });
    }
  });
}

@end
