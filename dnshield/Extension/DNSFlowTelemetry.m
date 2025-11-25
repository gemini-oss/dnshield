//
//  DNSFlowTelemetry.m
//  DNShield Network Extension
//
//  Implementation of structured DNS flow telemetry
//

#import <os/log.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingUtils.h>
#import "DNSFlowTelemetry.h"
#import "DNSInterfaceManager.h"
#import "DNSRetryManager.h"
#import "PreferenceManager.h"

// File-local log handle for this TU
static os_log_t flowTelemetryHandle = nil;

// Initialize once at load time
__attribute__((constructor)) static void initializeFlowTelemetryLogging(void) {
  if (!flowTelemetryHandle) {
    flowTelemetryHandle = os_log_create(DNUTF8(kDefaultExtensionBundleID), "FlowTelemetry");
  }
}

@implementation DNSFlowDecision

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
                            errorCode:(nullable NSString*)errorCode {
  if (self = [super init]) {
    _transactionID = [transactionID copy];
    _processName = [processName copy];
    _queryName = [queryName copy];
    _resolverIP = [resolverIP copy];
    _interfaceName = [binding.interfaceName copy];
    _interfaceIndex = binding ? binding.interfaceIndex : 0;
    _vpnSatisfied = vpnSatisfied;
    _pathStatus = [pathStatus copy];
    _chainPreservation = chainPreservation;
    _resolverInVPNCIDR = resolverInVPNCIDR;
    _bindStrategy = [bindStrategy copy];
    _policyOverride = policyOverride;
    _latencyMs = latencyMs;
    _outcome = outcome;
    _errorCode = [errorCode copy];
    _timestamp = [NSDate date];
  }
  return self;
}

- (NSDictionary*)toDictionary {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  dict[@"timestamp"] = @([self.timestamp timeIntervalSince1970]);
  dict[@"transaction_id"] = self.transactionID;
  dict[@"process"] = self.processName;
  dict[@"qname"] = self.queryName;
  dict[@"resolver_ip"] = self.resolverIP;

  if (self.interfaceName) {
    dict[@"ifname"] = self.interfaceName;
  }
  dict[@"ifindex"] = @(self.interfaceIndex);
  dict[@"vpn_satisfied"] = @(self.vpnSatisfied);
  dict[@"path_status"] = self.pathStatus;
  dict[@"chain_preservation"] = @(self.chainPreservation);
  dict[@"resolver_in_vpn_cidr"] = @(self.resolverInVPNCIDR);
  dict[@"bind_strategy"] = self.bindStrategy;
  dict[@"policy_override"] = @(self.policyOverride);
  dict[@"latency_ms"] = @(self.latencyMs);
  dict[@"outcome"] = @(self.outcome);

  if (self.errorCode) {
    dict[@"error_code"] = self.errorCode;
  }

  return [dict copy];
}

- (NSString*)description {
  return [NSString stringWithFormat:@"<DNSFlowDecision: %@ %@ -> %@ via %@(%u) %@ms outcome:%ld>",
                                    self.transactionID, self.queryName, self.resolverIP,
                                    self.interfaceName ?: @"default", self.interfaceIndex,
                                    @(self.latencyMs), (long)self.outcome];
}

@end

@interface DNSFlowTelemetry ()
@property(nonatomic, strong) PreferenceManager* preferenceManager;
@property(nonatomic, assign) BOOL isEnabled;
@property(nonatomic, assign) BOOL verboseLogging;
@property(nonatomic, strong) dispatch_queue_t telemetryQueue;
@end

@implementation DNSFlowTelemetry

- (instancetype)initWithPreferenceManager:(PreferenceManager*)preferenceManager {
  if (self = [super init]) {
    _preferenceManager = preferenceManager;
    _telemetryQueue = dispatch_queue_create("com.dnshield.flow-telemetry", DISPATCH_QUEUE_SERIAL);
    [self reloadConfiguration];
  }
  return self;
}

#pragma mark - Configuration

- (void)reloadConfiguration {
  // Check if verbose telemetry is enabled
  NSNumber* verboseEnabled =
      [self.preferenceManager preferenceValueForKey:kDNShieldVerboseTelemetry
                                           inDomain:kDNShieldPreferenceDomain];
  self.verboseLogging = verboseEnabled ? [verboseEnabled boolValue] : NO;

  // Check if general telemetry is enabled
  NSNumber* telemetryEnabled =
      [self.preferenceManager preferenceValueForKey:kDNShieldTelemetryEnabled
                                           inDomain:kDNShieldPreferenceDomain];
  self.isEnabled = telemetryEnabled ? [telemetryEnabled boolValue] : YES;

  os_log_info(flowTelemetryHandle,
              "DNS flow telemetry configuration: enabled=%{public}@, verbose=%{public}@",
              self.isEnabled ? @"YES" : @"NO", self.verboseLogging ? @"YES" : @"NO");
}

#pragma mark - Flow Decision Logging

- (void)logFlowDecision:(DNSFlowDecision*)decision {
  if (!self.isEnabled) {
    return;
  }

  dispatch_async(self.telemetryQueue, ^{
    // Always log structured decision data
    NSDictionary* telemetryData = [decision toDictionary];

    if (self.verboseLogging) {
      os_log_info(flowTelemetryHandle, "dns.flow.decision: %{public}@", telemetryData);
    } else {
      // Log only key fields for performance
      os_log_info(
          flowTelemetryHandle,
          "dns.flow.decision: {ts:%f, txid:%{public}@, qname:%{public}@, resolver:%{public}@, "
          "iface:%{public}@, vpn:%{public}@, outcome:%ld, latency:%.1f}",
          [decision.timestamp timeIntervalSince1970], decision.transactionID, decision.queryName,
          decision.resolverIP, decision.interfaceName ?: @"default",
          decision.vpnSatisfied ? @"Y" : @"N", (long)decision.outcome, decision.latencyMs);
    }
  });
}

#pragma mark - Retry Attempt Logging

- (void)logRetryAttempt:(DNSRetryAttempt*)attempt transactionID:(NSString*)transactionID {
  if (!self.isEnabled) {
    return;
  }

  dispatch_async(self.telemetryQueue, ^{
    NSDictionary* retryData = @{
      @"timestamp" : @([attempt.timestamp timeIntervalSince1970]),
      @"transaction_id" : transactionID,
      @"attempt" : @(attempt.attemptNumber),
      @"reason" : [self retryReasonString:attempt.reason],
      @"backoff_ms" : @(attempt.backoffDelay * 1000),
      @"resolver_endpoint" : attempt.resolverEndpoint,
      @"interface_name" : attempt.interfaceName ?: [NSNull null]
    };

    if (self.verboseLogging) {
      os_log_info(flowTelemetryHandle, "dns.flow.retry: %{public}@", retryData);
    } else {
      os_log_info(
          flowTelemetryHandle,
          "dns.flow.retry: {txid:%{public}@, attempt:%lu, reason:%{public}@, backoff:%.0fms}",
          transactionID, (unsigned long)attempt.attemptNumber,
          [self retryReasonString:attempt.reason], attempt.backoffDelay * 1000);
    }
  });
}

- (NSString*)retryReasonString:(DNSRetryReason)reason {
  switch (reason) {
    case DNSRetryReasonPeerClosed: return @"peer_closed";
    case DNSRetryReasonTimeout: return @"timeout";
    case DNSRetryReasonNetworkError: return @"network_error";
    case DNSRetryReasonInterfaceUnavailable: return @"interface_unavailable";
    default: return @"unknown";
  }
}

#pragma mark - Interface Binding Events

- (void)logInterfaceBindingEvent:(NSString*)event
                   interfaceName:(nullable NSString*)interfaceName
                      resolverIP:(NSString*)resolverIP
                   transactionID:(NSString*)transactionID
                       timestamp:(NSDate*)timestamp {
  if (!self.isEnabled) {
    return;
  }

  dispatch_async(self.telemetryQueue, ^{
    NSDictionary* bindingData = @{
      @"timestamp" : @([timestamp timeIntervalSince1970]),
      @"event" : event,
      @"interface_name" : interfaceName ?: [NSNull null],
      @"resolver_ip" : resolverIP,
      @"transaction_id" : transactionID
    };

    if (self.verboseLogging) {
      os_log_info(flowTelemetryHandle, "dns.interface.binding: %{public}@", bindingData);
    } else {
      os_log_info(flowTelemetryHandle,
                  "dns.interface.binding: {event:%{public}@, iface:%{public}@, "
                  "resolver:%{public}@, txid:%{public}@}",
                  event, interfaceName ?: @"default", resolverIP, transactionID);
    }
  });
}

#pragma mark - Path Change Events

- (void)logPathChangeEvent:(NSString*)event
             fromInterface:(nullable NSString*)fromInterface
               toInterface:(nullable NSString*)toInterface
                 timestamp:(NSDate*)timestamp {
  if (!self.isEnabled) {
    return;
  }

  dispatch_async(self.telemetryQueue, ^{
    NSDictionary* pathData = @{
      @"timestamp" : @([timestamp timeIntervalSince1970]),
      @"event" : event,
      @"from_interface" : fromInterface ?: [NSNull null],
      @"to_interface" : toInterface ?: [NSNull null]
    };

    if (self.verboseLogging) {
      os_log_info(flowTelemetryHandle, "dns.path.change: %{public}@", pathData);
    } else {
      os_log_info(flowTelemetryHandle,
                  "dns.path.change: {event:%{public}@, from:%{public}@, to:%{public}@}", event,
                  fromInterface ?: @"none", toInterface ?: @"none");
    }
  });
}

@end
