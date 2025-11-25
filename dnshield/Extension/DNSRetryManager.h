//
//  DNSRetryManager.h
//  DNShield Network Extension
//
//  Manages retry and fallback logic for DNS queries
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

@class PreferenceManager, DNSInterfaceBinding;
@protocol DNSRetryManagerDelegate;

typedef NS_ENUM(NSInteger, DNSRetryReason) {
  DNSRetryReasonPeerClosed = 0,
  DNSRetryReasonTimeout = 1,
  DNSRetryReasonNetworkError = 2,
  DNSRetryReasonInterfaceUnavailable = 3
};

@interface DNSRetryAttempt : NSObject
@property(nonatomic, readonly) NSUInteger attemptNumber;
@property(nonatomic, readonly) DNSRetryReason reason;
@property(nonatomic, readonly) NSTimeInterval backoffDelay;
@property(nonatomic, readonly) NSDate* timestamp;
@property(nonatomic, readonly, nullable) NSError* error;
@property(nonatomic, readonly) NSString* resolverEndpoint;
@property(nonatomic, readonly, nullable) NSString* interfaceName;

- (instancetype)initWithAttemptNumber:(NSUInteger)attemptNumber
                               reason:(DNSRetryReason)reason
                         backoffDelay:(NSTimeInterval)backoffDelay
                                error:(nullable NSError*)error
                     resolverEndpoint:(NSString*)resolverEndpoint
                        interfaceName:(nullable NSString*)interfaceName;
@end

@interface DNSRetryManager : NSObject

@property(nonatomic, weak, nullable) id<DNSRetryManagerDelegate> delegate;
@property(nonatomic, readonly) NSUInteger maxRetries;
@property(nonatomic, readonly) NSTimeInterval initialBackoffMs;

- (instancetype)initWithPreferenceManager:(PreferenceManager*)preferenceManager;

// Retry decision making
- (BOOL)shouldRetryError:(NSError*)error
            attemptCount:(NSUInteger)attemptCount
        resolverEndpoint:(NSString*)resolverEndpoint;

- (NSTimeInterval)backoffDelayForAttempt:(NSUInteger)attemptNumber reason:(DNSRetryReason)reason;

// Retry scheduling
- (void)scheduleRetry:(void (^)(void))retryBlock afterAttempt:(DNSRetryAttempt*)attempt;

// Retry tracking
- (void)recordRetryAttempt:(DNSRetryAttempt*)attempt forTransactionID:(NSString*)transactionID;
- (NSArray<DNSRetryAttempt*>*)retriesForTransactionID:(NSString*)transactionID;
- (void)clearRetriesForTransactionID:(NSString*)transactionID;

// Configuration updates
- (void)reloadConfiguration;

@end

@protocol DNSRetryManagerDelegate <NSObject>
@optional
- (void)retryManager:(DNSRetryManager*)manager
    willRetryAttempt:(DNSRetryAttempt*)attempt
       transactionID:(NSString*)transactionID;

- (void)retryManager:(DNSRetryManager*)manager
    didExhaustRetries:(NSArray<DNSRetryAttempt*>*)attempts
        transactionID:(NSString*)transactionID;
@end

NS_ASSUME_NONNULL_END
