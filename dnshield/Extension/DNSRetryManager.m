//
//  DNSRetryManager.m
//  DNShield Network Extension
//
//  Implementation of DNS retry and fallback logic
//

#import "DNSRetryManager.h"
#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingUtils.h>
#import <os/log.h>
#import "PreferenceManager.h"

static os_log_t retryLogHandle = nil;

__attribute__((constructor)) static void initializeRetryManagerLogging(void) {
  if (!retryLogHandle) {
    retryLogHandle = os_log_create(DNUTF8(kDefaultExtensionBundleID), "RetryManager");
  }
}

@implementation DNSRetryAttempt

- (instancetype)initWithAttemptNumber:(NSUInteger)attemptNumber
                               reason:(DNSRetryReason)reason
                         backoffDelay:(NSTimeInterval)backoffDelay
                                error:(nullable NSError*)error
                     resolverEndpoint:(NSString*)resolverEndpoint
                        interfaceName:(nullable NSString*)interfaceName {
  if (self = [super init]) {
    _attemptNumber = attemptNumber;
    _reason = reason;
    _backoffDelay = backoffDelay;
    _timestamp = [NSDate date];
    _error = error;
    _resolverEndpoint = [resolverEndpoint copy];
    _interfaceName = [interfaceName copy];
  }
  return self;
}

- (NSString*)description {
  NSString* reasonStr = [self reasonString:self.reason];
  return [NSString stringWithFormat:@"<DNSRetryAttempt #%lu: %@ -> %@ via %@ (delay: %.0fms)>",
                                    (unsigned long)self.attemptNumber, reasonStr,
                                    self.resolverEndpoint, self.interfaceName ?: @"default",
                                    self.backoffDelay * 1000];
}

- (NSString*)reasonString:(DNSRetryReason)reason {
  switch (reason) {
    case DNSRetryReasonPeerClosed: return @"PeerClosed";
    case DNSRetryReasonTimeout: return @"Timeout";
    case DNSRetryReasonNetworkError: return @"NetworkError";
    case DNSRetryReasonInterfaceUnavailable: return @"InterfaceUnavailable";
    default: return @"Unknown";
  }
}

@end

@interface DNSRetryManager ()
@property(nonatomic, strong) PreferenceManager* preferenceManager;
@property(nonatomic, strong)
    NSMutableDictionary<NSString*, NSMutableArray<DNSRetryAttempt*>*>* transactionRetries;
@property(nonatomic, strong) dispatch_queue_t retryQueue;
@property(nonatomic, assign) NSUInteger maxRetries;
@property(nonatomic, assign) NSTimeInterval initialBackoffMs;
@end

@implementation DNSRetryManager

- (instancetype)initWithPreferenceManager:(PreferenceManager*)preferenceManager {
  if (self = [super init]) {
    _preferenceManager = preferenceManager;
    _transactionRetries = [NSMutableDictionary dictionary];
    _retryQueue = dispatch_queue_create("com.dnshield.retry", DISPATCH_QUEUE_SERIAL);
    [self reloadConfiguration];
  }
  return self;
}

#pragma mark - Configuration

- (void)reloadConfiguration {
  // Max retries
  NSNumber* maxRetries = [self.preferenceManager preferenceValueForKey:kDNShieldMaxRetries
                                                              inDomain:kDNShieldPreferenceDomain];
  self.maxRetries = maxRetries ? [maxRetries unsignedIntegerValue] : 3;

  // Initial backoff
  NSNumber* backoffMs = [self.preferenceManager preferenceValueForKey:kDNShieldInitialBackoffMs
                                                             inDomain:kDNShieldPreferenceDomain];
  self.initialBackoffMs =
      (backoffMs ? [backoffMs doubleValue] : 250.0) / 1000.0;  // Convert ms to seconds

  os_log_info(retryLogHandle, "DNS retry configuration: maxRetries=%lu, initialBackoff=%.0fms",
              (unsigned long)self.maxRetries, self.initialBackoffMs * 1000);
}

#pragma mark - Retry Decision Making

- (BOOL)shouldRetryError:(NSError*)error
            attemptCount:(NSUInteger)attemptCount
        resolverEndpoint:(NSString*)resolverEndpoint {
  // Check attempt count limit
  if (attemptCount >= self.maxRetries) {
    os_log_info(retryLogHandle, "Max retries (%lu) reached for resolver %{public}@",
                (unsigned long)self.maxRetries, resolverEndpoint);
    return NO;
  }

  // Check error type
  DNSRetryReason reason = [self retryReasonForError:error];
  BOOL shouldRetry = [self shouldRetryForReason:reason];

  os_log_info(retryLogHandle,
              "Retry decision for %{public}@: attempt %lu/%lu, reason=%ld, shouldRetry=%{public}@",
              resolverEndpoint, (unsigned long)attemptCount, (unsigned long)self.maxRetries,
              (long)reason, shouldRetry ? @"YES" : @"NO");

  return shouldRetry;
}

- (DNSRetryReason)retryReasonForError:(NSError*)error {
  if (!error) {
    return DNSRetryReasonNetworkError;
  }

  // Check for peer closed error (the main issue we're solving)
  if ([error.localizedDescription containsString:@"peer closed"] ||
      [error.localizedDescription containsString:@"connection reset"]) {
    return DNSRetryReasonPeerClosed;
  }

  // Check for timeout errors
  if (error.code == NSURLErrorTimedOut || [error.localizedDescription containsString:@"timeout"]) {
    return DNSRetryReasonTimeout;
  }

  // Check for interface/network errors
  if ([error.localizedDescription containsString:@"interface"] ||
      [error.localizedDescription containsString:@"network"]) {
    return DNSRetryReasonInterfaceUnavailable;
  }

  return DNSRetryReasonNetworkError;
}

- (BOOL)shouldRetryForReason:(DNSRetryReason)reason {
  switch (reason) {
    case DNSRetryReasonPeerClosed:
      // Always retry peer closed errors - this is the main fix
      return YES;

    case DNSRetryReasonInterfaceUnavailable:
      // Retry interface issues - might be temporary
      return YES;

    case DNSRetryReasonTimeout:
      // Retry timeouts
      return YES;

    case DNSRetryReasonNetworkError:
      // Generally retry network errors
      return YES;

    default: return NO;
  }
}

- (NSTimeInterval)backoffDelayForAttempt:(NSUInteger)attemptNumber reason:(DNSRetryReason)reason {
  // Exponential backoff: 250ms, 500ms, 1s, 2s (capped)
  NSTimeInterval baseDelay = self.initialBackoffMs;
  NSTimeInterval exponentialDelay = baseDelay * (1 << (attemptNumber - 1));
  NSTimeInterval maxDelay = 2.0;  // 2 second cap

  NSTimeInterval delay = MIN(exponentialDelay, maxDelay);

  // For peer closed errors, use immediate retry for first attempt
  if (reason == DNSRetryReasonPeerClosed && attemptNumber == 1) {
    delay = 0.0;  // Immediate retry
  }

  return delay;
}

#pragma mark - Retry Scheduling

- (void)scheduleRetry:(void (^)(void))retryBlock afterAttempt:(DNSRetryAttempt*)attempt {
  if (attempt.backoffDelay <= 0) {
    // Immediate retry
    dispatch_async(self.retryQueue, ^{
      retryBlock();
    });
  } else {
    // Delayed retry
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(attempt.backoffDelay * NSEC_PER_SEC)),
                   self.retryQueue, ^{
                     retryBlock();
                   });
  }

  os_log_info(retryLogHandle, "Scheduled retry attempt #%lu after %.0fms delay",
              (unsigned long)attempt.attemptNumber, attempt.backoffDelay * 1000);
}

#pragma mark - Retry Tracking

- (void)recordRetryAttempt:(DNSRetryAttempt*)attempt forTransactionID:(NSString*)transactionID {
  @synchronized(self.transactionRetries) {
    NSMutableArray* attempts = self.transactionRetries[transactionID];
    if (!attempts) {
      attempts = [NSMutableArray array];
      self.transactionRetries[transactionID] = attempts;
    }
    [attempts addObject:attempt];
  }

  os_log_debug(retryLogHandle, "Recorded retry attempt for transaction %{public}@: %{public}@",
               transactionID, attempt);

  // Notify delegate
  if ([self.delegate respondsToSelector:@selector(retryManager:willRetryAttempt:transactionID:)]) {
    [self.delegate retryManager:self willRetryAttempt:attempt transactionID:transactionID];
  }
}

- (NSArray<DNSRetryAttempt*>*)retriesForTransactionID:(NSString*)transactionID {
  @synchronized(self.transactionRetries) {
    NSArray* attempts = self.transactionRetries[transactionID];
    return attempts ? [attempts copy] : @[];
  }
}

- (void)clearRetriesForTransactionID:(NSString*)transactionID {
  @synchronized(self.transactionRetries) {
    NSArray* attempts = self.transactionRetries[transactionID];
    if (attempts.count > 0) {
      os_log_debug(retryLogHandle, "Clearing %lu retry attempts for transaction %{public}@",
                   (unsigned long)attempts.count, transactionID);

      // Notify delegate of exhausted retries if there were attempts
      if ([self.delegate respondsToSelector:@selector(retryManager:
                                                 didExhaustRetries:transactionID:)]) {
        [self.delegate retryManager:self didExhaustRetries:attempts transactionID:transactionID];
      }
    }

    [self.transactionRetries removeObjectForKey:transactionID];
  }
}

@end
