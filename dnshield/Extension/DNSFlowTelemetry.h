//
//  DNSFlowTelemetry.h
//  DNShield Network Extension
//
//  Structured telemetry logging for DNS flow decisions
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

@class PreferenceManager, DNSInterfaceBinding, DNSRetryAttempt;

typedef NS_ENUM(NSInteger, DNSFlowOutcome) {
  DNSFlowOutcomeSuccess = 0,
  DNSFlowOutcomeRetry = 1,
  DNSFlowOutcomeFailed = 2,
  DNSFlowOutcomeBlocked = 3,
  DNSFlowOutcomeTimeout = 4
};

@interface DNSFlowDecision : NSObject

// Flow identification
@property(nonatomic, readonly) NSString* transactionID;
@property(nonatomic, readonly) NSString* processName;
@property(nonatomic, readonly) NSString* queryName;
@property(nonatomic, readonly) NSString* resolverIP;

// Interface binding decision
@property(nonatomic, readonly, nullable) NSString* interfaceName;
@property(nonatomic, readonly) uint32_t interfaceIndex;
@property(nonatomic, readonly) BOOL vpnSatisfied;
@property(nonatomic, readonly) NSString* pathStatus;
@property(nonatomic, readonly) BOOL chainPreservation;
@property(nonatomic, readonly) BOOL resolverInVPNCIDR;
@property(nonatomic, readonly) NSString* bindStrategy;
@property(nonatomic, readonly) BOOL policyOverride;

// Timing and outcome
@property(nonatomic, readonly) NSTimeInterval latencyMs;
@property(nonatomic, readonly) DNSFlowOutcome outcome;
@property(nonatomic, readonly, nullable) NSString* errorCode;
@property(nonatomic, readonly) NSDate* timestamp;

- (instancetype)initWithTransactionID:(NSString*)transactionID
                          processName:(NSString*)processName
                            queryName:(NSString*)queryName
                           resolverIP:(NSString*)resolverIP
                     interfaceBinding:(nullable DNSInterfaceBinding*)binding
                         vpnSatisfied:(BOOL)vpnSatisfied
                           pathStatus:(NSString*)pathStatus
                    chainPreservation:(BOOL)chainPreservation
                    resolverInVPNCIDR:(BOOL)resolverInVPNCIDR
                         bindStrategy:(NSString*)bindStrategy
                       policyOverride:(BOOL)policyOverride
                            latencyMs:(NSTimeInterval)latencyMs
                              outcome:(DNSFlowOutcome)outcome
                            errorCode:(nullable NSString*)errorCode;

@end

@interface DNSFlowTelemetry : NSObject

@property(nonatomic, readonly) BOOL isEnabled;
@property(nonatomic, readonly) BOOL verboseLogging;

- (instancetype)initWithPreferenceManager:(PreferenceManager*)preferenceManager;

// Flow decision logging
- (void)logFlowDecision:(DNSFlowDecision*)decision;

// Retry attempt logging
- (void)logRetryAttempt:(DNSRetryAttempt*)attempt transactionID:(NSString*)transactionID;

// Interface binding events
- (void)logInterfaceBindingEvent:(NSString*)event
                   interfaceName:(nullable NSString*)interfaceName
                      resolverIP:(NSString*)resolverIP
                   transactionID:(NSString*)transactionID
                       timestamp:(NSDate*)timestamp;

// Path change events
- (void)logPathChangeEvent:(NSString*)event
             fromInterface:(nullable NSString*)fromInterface
               toInterface:(nullable NSString*)toInterface
                 timestamp:(NSDate*)timestamp;

// Configuration updates
- (void)reloadConfiguration;

@end

NS_ASSUME_NONNULL_END
