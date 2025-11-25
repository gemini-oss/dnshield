//
//  NetworkReachability.m
//  DNShield Network Extension
//
//  Implementation of network reachability monitoring using Network framework
//

#import "NetworkReachability.h"
#import <Common/LoggingManager.h>

// Notifications
NSString* const NetworkReachabilityChangedNotification = @"NetworkReachabilityChangedNotification";
NSString* const NetworkReachabilityNotificationKeyStatus = @"status";
NSString* const NetworkReachabilityNotificationKeyPreviousStatus = @"previousStatus";
NSString* const NetworkReachabilityNotificationKeyPath = @"path";

@interface NetworkReachability ()
@property(nonatomic, strong) dispatch_queue_t monitorQueue;
@property(nonatomic, strong) nw_path_monitor_t pathMonitor;
@property(nonatomic, strong) dispatch_queue_t delegateQueue;
@property(nonatomic, assign) NetworkStatus previousStatus;
@property(nonatomic, strong) NSMutableArray<void (^)(BOOL)>* connectivityWaiters;
@property(nonatomic, strong) NSMutableDictionary<NSString*, nw_connection_t>* hostChecks;
@end

@implementation NetworkReachability

#pragma mark - Singleton

+ (instancetype)sharedInstance {
  static NetworkReachability* sharedInstance = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedInstance = [[NetworkReachability alloc] init];
  });
  return sharedInstance;
}

#pragma mark - Initialization

- (instancetype)init {
  self = [super init];
  if (self) {
    _currentStatus = NetworkStatusUnknown;
    _previousStatus = NetworkStatusUnknown;
    _connectivityWaiters = [NSMutableArray array];
    _hostChecks = [NSMutableDictionary dictionary];

    // Create queues
    _monitorQueue = dispatch_queue_create("com.dnshield.network.monitor", DISPATCH_QUEUE_SERIAL);
    _delegateQueue = dispatch_queue_create("com.dnshield.network.delegate", DISPATCH_QUEUE_SERIAL);

    DNSLogDebug(LogCategoryNetwork, "NetworkReachability initialized");
  }
  return self;
}

- (void)dealloc {
  [self stopMonitoring];
}

#pragma mark - Monitoring Control

- (void)startMonitoring {
  if (self.isMonitoring) {
    DNSLogDebug(LogCategoryNetwork, "Network monitoring already active");
    return;
  }

  DNSLogInfo(LogCategoryNetwork, "Starting network reachability monitoring");

  // Create path monitor
  self.pathMonitor = nw_path_monitor_create();

  // Set update handler
  __weak typeof(self) weakSelf = self;
  nw_path_monitor_set_update_handler(self.pathMonitor, ^(nw_path_t path) {
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    [strongSelf handlePathUpdate:path];
  });

  // Start monitoring
  nw_path_monitor_set_queue(self.pathMonitor, self.monitorQueue);
  nw_path_monitor_start(self.pathMonitor);
}

- (void)stopMonitoring {
  if (!self.isMonitoring) {
    return;
  }

  DNSLogInfo(LogCategoryNetwork, "Stopping network reachability monitoring");

  nw_path_monitor_cancel(self.pathMonitor);
  self.pathMonitor = nil;
  _currentPath = nil;
  _currentStatus = NetworkStatusUnknown;
}

- (BOOL)isMonitoring {
  return self.pathMonitor != nil;
}

#pragma mark - Path Update Handling

- (void)handlePathUpdate:(nw_path_t)path {
  NetworkStatus newStatus = [self statusFromPath:path];
  NetworkConnectionType connectionTypes = [self connectionTypesFromPath:path];

  BOOL statusChanged = (newStatus != self.currentStatus);

  // Update properties
  _previousStatus = _currentStatus;
  _currentStatus = newStatus;
  _currentPath = path;
  _availableConnectionTypes = connectionTypes;
  _isExpensive = nw_path_is_expensive(path);
  _isConstrained = nw_path_is_constrained(path);

  DNSLogInfo(LogCategoryNetwork, "Network path update: %@ -> %@ (expensive: %d, constrained: %d)",
             [NetworkReachability stringForStatus:self.previousStatus],
             [NetworkReachability stringForStatus:newStatus], self.isExpensive, self.isConstrained);

  if (statusChanged) {
    [self notifyStatusChange];
  }

  // Notify waiters if we became reachable
  if (NetworkStatusIsReachable(newStatus) && self.connectivityWaiters.count > 0) {
    NSArray* waiters = [self.connectivityWaiters copy];
    [self.connectivityWaiters removeAllObjects];

    dispatch_async(self.delegateQueue, ^{
      for (void (^completion)(BOOL) in waiters) {
        completion(YES);
      }
    });
  }
}

- (NetworkStatus)statusFromPath:(nw_path_t)path {
  nw_path_status_t status = nw_path_get_status(path);

  if (status != nw_path_status_satisfied) {
    return NetworkStatusNotReachable;
  }

  // Check interface types
  __block NetworkStatus networkStatus = NetworkStatusReachableViaOther;

  nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
    nw_interface_type_t type = nw_interface_get_type(interface);

    switch (type) {
      case nw_interface_type_wifi:
        networkStatus = NetworkStatusReachableViaWiFi;
        return false;  // Stop enumeration, WiFi has priority

      case nw_interface_type_cellular:
        if (networkStatus != NetworkStatusReachableViaWiFi) {
          networkStatus = NetworkStatusReachableViaCellular;
        }
        break;

      case nw_interface_type_wired:
        if (networkStatus != NetworkStatusReachableViaWiFi &&
            networkStatus != NetworkStatusReachableViaCellular) {
          networkStatus = NetworkStatusReachableViaWired;
        }
        break;

      case nw_interface_type_loopback:
        if (networkStatus == NetworkStatusReachableViaOther) {
          networkStatus = NetworkStatusReachableViaLoopback;
        }
        break;

      default: break;
    }

    return true;  // Continue enumeration
  });

  return networkStatus;
}

- (NetworkConnectionType)connectionTypesFromPath:(nw_path_t)path {
  __block NetworkConnectionType types = NetworkConnectionTypeNone;

  if (nw_path_get_status(path) != nw_path_status_satisfied) {
    return types;
  }

  nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
    nw_interface_type_t type = nw_interface_get_type(interface);

    switch (type) {
      case nw_interface_type_wifi: types |= NetworkConnectionTypeWiFi; break;
      case nw_interface_type_cellular: types |= NetworkConnectionTypeCellular; break;
      case nw_interface_type_wired: types |= NetworkConnectionTypeWired; break;
      case nw_interface_type_loopback: types |= NetworkConnectionTypeLoopback; break;
      default: types |= NetworkConnectionTypeOther; break;
    }

    return true;
  });

  return types;
}

#pragma mark - Notifications

- (void)notifyStatusChange {
  dispatch_async(self.delegateQueue, ^{
    // Delegate notification
    if ([self.delegate respondsToSelector:@selector(networkReachabilityDidChange:)]) {
      [self.delegate networkReachabilityDidChange:self.currentStatus];
    }

    if ([self.delegate respondsToSelector:@selector(networkReachabilityDidChangeFromStatus:
                                                                                  toStatus:)]) {
      [self.delegate networkReachabilityDidChangeFromStatus:self.previousStatus
                                                   toStatus:self.currentStatus];
    }

    if ([self.delegate respondsToSelector:@selector(networkPathDidChange:)] && self.currentPath) {
      [self.delegate networkPathDidChange:self.currentPath];
    }

    // Post notification
    [[NSNotificationCenter defaultCenter]
        postNotificationName:NetworkReachabilityChangedNotification
                      object:self
                    userInfo:@{
                      NetworkReachabilityNotificationKeyStatus : @(self.currentStatus),
                      NetworkReachabilityNotificationKeyPreviousStatus : @(self.previousStatus)
                    }];
  });
}

#pragma mark - Reachability Checks

- (BOOL)isReachable {
  return NetworkStatusIsReachable(self.currentStatus);
}

- (BOOL)isReachableViaWiFi {
  return self.currentStatus == NetworkStatusReachableViaWiFi;
}

- (BOOL)isReachableViaCellular {
  return self.currentStatus == NetworkStatusReachableViaCellular;
}

- (BOOL)isReachableViaWired {
  return self.currentStatus == NetworkStatusReachableViaWired;
}

#pragma mark - Host Reachability

- (void)checkReachabilityForHost:(NSString*)host
                            port:(nullable NSNumber*)port
                      completion:(void (^)(BOOL reachable, NetworkStatus status))completion {
  if (!host || host.length == 0) {
    if (completion) {
      completion(NO, NetworkStatusNotReachable);
    }
    return;
  }

  dispatch_async(self.monitorQueue, ^{
    // Cancel any existing check for this host
    NSString* hostKey = port ? [NSString stringWithFormat:@"%@:%@", host, port] : host;
    nw_connection_t existingConnection = self.hostChecks[hostKey];
    if (existingConnection) {
      nw_connection_cancel(existingConnection);
    }

    // Create endpoint
    const char* hostname = [host UTF8String];
    const char* portString = port ? [[port stringValue] UTF8String] : "443";  // Default to HTTPS

    nw_endpoint_t endpoint = nw_endpoint_create_host(hostname, portString);

    // Create connection parameters
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DEFAULT_CONFIGURATION, NW_PARAMETERS_DEFAULT_CONFIGURATION);

    // Create connection
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    self.hostChecks[hostKey] = connection;

    // Set state change handler
    __weak typeof(self) weakSelf = self;
    nw_connection_set_state_changed_handler(
        connection, ^(nw_connection_state_t state, nw_error_t error) {
          __strong typeof(self) strongSelf = weakSelf;
          if (!strongSelf)
            return;

          switch (state) {
            case nw_connection_state_ready:
              DNSLogDebug(LogCategoryNetwork, "Host %@ is reachable", host);
              if (completion) {
                dispatch_async(strongSelf.delegateQueue, ^{
                  completion(YES, strongSelf.currentStatus);
                });
              }
              nw_connection_cancel(connection);
              [strongSelf.hostChecks removeObjectForKey:hostKey];
              break;

            case nw_connection_state_failed:
              DNSLogDebug(LogCategoryNetwork, "Host %@ is not reachable: %@", host, error);
              if (completion) {
                dispatch_async(strongSelf.delegateQueue, ^{
                  completion(NO, NetworkStatusNotReachable);
                });
              }
              [strongSelf.hostChecks removeObjectForKey:hostKey];
              break;

            case nw_connection_state_cancelled:
              [strongSelf.hostChecks removeObjectForKey:hostKey];
              break;

            default: break;
          }
        });

    // Set queue and start
    nw_connection_set_queue(connection, self.monitorQueue);
    nw_connection_start(connection);

    // Timeout after 10 seconds
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)), self.monitorQueue, ^{
          nw_connection_t timeoutConnection = self.hostChecks[hostKey];
          if (timeoutConnection) {
            DNSLogDebug(LogCategoryNetwork, "Host reachability check timed out for %@", host);
            nw_connection_cancel(timeoutConnection);
            [self.hostChecks removeObjectForKey:hostKey];

            if (completion) {
              dispatch_async(self.delegateQueue, ^{
                completion(NO, NetworkStatusNotReachable);
              });
            }
          }
        });
  });
}

#pragma mark - Wait for Connectivity

- (void)waitForConnectivityWithTimeout:(NSTimeInterval)timeout
                            completion:(void (^)(BOOL connected))completion {
  if (!completion)
    return;

  // If already connected, return immediately
  if (self.isReachable) {
    dispatch_async(self.delegateQueue, ^{
      completion(YES);
    });
    return;
  }

  // Add to waiters
  dispatch_async(self.monitorQueue, ^{
    [self.connectivityWaiters addObject:completion];
  });

  // Set timeout
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                 self.monitorQueue, ^{
                   NSUInteger index = [self.connectivityWaiters indexOfObject:completion];
                   if (index != NSNotFound) {
                     [self.connectivityWaiters removeObjectAtIndex:index];
                     dispatch_async(self.delegateQueue, ^{
                       completion(NO);
                     });
                   }
                 });
}

#pragma mark - Status Strings

- (NSString*)statusString {
  return [NetworkReachability stringForStatus:self.currentStatus];
}

+ (NSString*)stringForStatus:(NetworkStatus)status {
  switch (status) {
    case NetworkStatusUnknown: return @"Unknown";
    case NetworkStatusNotReachable: return @"Not Reachable";
    case NetworkStatusReachableViaWiFi: return @"WiFi";
    case NetworkStatusReachableViaCellular: return @"Cellular";
    case NetworkStatusReachableViaWired: return @"Wired";
    case NetworkStatusReachableViaLoopback: return @"Loopback";
    case NetworkStatusReachableViaOther: return @"Other";
  }
}

@end
