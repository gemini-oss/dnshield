//
//  RuleFetcher.h
//  DNShield Network Extension
//
//  Abstract base class/protocol for fetching rule lists from various sources
//  Part of Stream 3: Networking implementation
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Forward declaration
@protocol RuleFetcher;

// Progress callback type
typedef void (^RuleFetcherProgressBlock)(float progress);

// Completion callback type
typedef void (^RuleFetcherCompletionBlock)(NSData* _Nullable data, NSError* _Nullable error);

// RuleFetcher delegate protocol for optional delegate pattern
@protocol RuleFetcherDelegate <NSObject>
@optional
- (void)ruleFetcher:(id<RuleFetcher>)fetcher didUpdateProgress:(float)progress;
- (void)ruleFetcher:(id<RuleFetcher>)fetcher
    didCompleteWithData:(nullable NSData*)data
                  error:(nullable NSError*)error;
- (void)ruleFetcherDidStart:(id<RuleFetcher>)fetcher;
- (void)ruleFetcherDidCancel:(id<RuleFetcher>)fetcher;
@end

// Main RuleFetcher protocol that all fetchers must conform to
@protocol RuleFetcher <NSObject>

@required
// Fetch rules with simple completion handler
- (void)fetchRulesWithCompletion:(RuleFetcherCompletionBlock)completion;

// Fetch rules with progress updates and completion
- (void)fetchRulesWithProgress:(nullable RuleFetcherProgressBlock)progress
                    completion:(RuleFetcherCompletionBlock)completion;

// Indicates if this fetcher supports resuming interrupted downloads
- (BOOL)supportsResume;

// Cancel any ongoing fetch operation
- (void)cancelFetch;

@optional
// Optional delegate for event-based notifications
@property(nonatomic, weak) id<RuleFetcherDelegate> delegate;

// Unique identifier for this fetcher instance
@property(nonatomic, readonly) NSString* identifier;

// Current state of the fetcher
@property(nonatomic, readonly) BOOL isFetching;

// Last fetch timestamp
@property(nonatomic, readonly, nullable) NSDate* lastFetchDate;

// Last fetch error
@property(nonatomic, readonly, nullable) NSError* lastError;

// Configuration dictionary for fetcher-specific settings
- (void)configureWithOptions:(NSDictionary*)options;

// Validate configuration before fetching
- (BOOL)validateConfiguration:(NSError**)error;

// Resume a previously interrupted fetch (if supported)
- (void)resumeFetchWithCompletion:(RuleFetcherCompletionBlock)completion;

// Get estimated time remaining for current fetch
- (NSTimeInterval)estimatedTimeRemaining;

// Get current download statistics
- (NSDictionary*)downloadStatistics;

@end

// Base fetcher configuration keys
extern NSString* const RuleFetcherConfigKeyTimeout;      // NSNumber (seconds)
extern NSString* const RuleFetcherConfigKeyRetryCount;   // NSNumber
extern NSString* const RuleFetcherConfigKeyRetryDelay;   // NSNumber (seconds)
extern NSString* const RuleFetcherConfigKeyMaxSize;      // NSNumber (bytes)
extern NSString* const RuleFetcherConfigKeyCachePolicy;  // NSString
extern NSString* const RuleFetcherConfigKeyPriority;     // NSString

// Notification names
extern NSString* const RuleFetcherDidStartNotification;
extern NSString* const RuleFetcherDidUpdateProgressNotification;
extern NSString* const RuleFetcherDidCompleteNotification;
extern NSString* const RuleFetcherDidCancelNotification;

// Notification user info keys
extern NSString* const RuleFetcherNotificationKeyProgress;    // NSNumber (0.0-1.0)
extern NSString* const RuleFetcherNotificationKeyData;        // NSData
extern NSString* const RuleFetcherNotificationKeyError;       // NSError
extern NSString* const RuleFetcherNotificationKeyIdentifier;  // NSString

// Abstract base class providing common functionality
@interface RuleFetcherBase : NSObject <RuleFetcher>

// Delegate for event notifications
@property(nonatomic, weak) id<RuleFetcherDelegate> delegate;

// Unique identifier
@property(nonatomic, readonly) NSString* identifier;

// Fetch state
@property(nonatomic, readonly) BOOL isFetching;

// Last fetch information
@property(nonatomic, readonly, nullable) NSDate* lastFetchDate;
@property(nonatomic, readonly, nullable) NSError* lastError;

// Configuration
@property(nonatomic, strong) NSDictionary* configuration;

// Retry settings
@property(nonatomic, assign) NSUInteger maxRetryCount;
@property(nonatomic, assign) NSTimeInterval retryDelay;
@property(nonatomic, assign) BOOL useExponentialBackoff;

// Timeout
@property(nonatomic, assign) NSTimeInterval timeout;

// Initialize with configuration
- (instancetype)initWithConfiguration:(nullable NSDictionary*)configuration;

// Subclasses must override these
- (void)performFetchWithCompletion:(RuleFetcherCompletionBlock)completion;
- (void)performCancelFetch;

// Helper methods for subclasses
- (void)notifyProgress:(float)progress;
- (void)notifyCompletion:(nullable NSData*)data error:(nullable NSError*)error;
- (void)notifyStart;
- (void)notifyCancel;

// Retry logic helpers
- (NSTimeInterval)retryDelayForAttempt:(NSUInteger)attempt;
- (void)performFetchWithRetry:(NSUInteger)remainingAttempts
                   completion:(RuleFetcherCompletionBlock)completion;

@end

NS_ASSUME_NONNULL_END
