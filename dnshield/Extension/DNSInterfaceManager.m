//
//  DNSInterfaceManager.m
//  DNShield Network Extension
//
//  Implementation of DNS interface binding logic
//

#import <Network/Network.h>
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <os/log.h>
#import <sys/socket.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingUtils.h>
#import "DNSInterfaceManager.h"
#import "PreferenceManager.h"

// File-local log handle for this translation unit
static os_log_t interfaceLogHandle = nil;

__attribute__((constructor)) static void initializeInterfaceManagerLogging(void) {
  if (!interfaceLogHandle) {
    interfaceLogHandle = os_log_create(DNUTF8(kDefaultExtensionBundleID), "InterfaceManager");
  }
}

@implementation DNSInterfaceBinding

- (instancetype)initWithInterfaceName:(NSString*)interfaceName
                       interfaceIndex:(uint32_t)interfaceIndex
                        interfaceType:(DNSInterfaceType)interfaceType
                     resolverEndpoint:(NSString*)resolverEndpoint
                        transactionID:(NSString*)transactionID {
  if (self = [super init]) {
    _interfaceName = [interfaceName copy];
    _interfaceIndex = interfaceIndex;
    _interfaceType = interfaceType;
    _resolverEndpoint = [resolverEndpoint copy];
    _bindingTime = [NSDate date];
    _transactionID = [transactionID copy];
  }
  return self;
}

- (NSString*)description {
  return
      [NSString stringWithFormat:@"<DNSInterfaceBinding: %@ (idx:%u, type:%ld) -> %@ [%@]>",
                                 self.interfaceName, self.interfaceIndex, (long)self.interfaceType,
                                 self.resolverEndpoint, self.transactionID];
}

@end

@interface DNSInterfaceManager ()
@property(nonatomic, strong) PreferenceManager* preferenceManager;
@property(nonatomic, strong)
    NSMutableDictionary<NSString*, DNSInterfaceBinding*>* transactionBindings;
@property(nonatomic, strong) NSArray<NSString*>* vpnResolverCIDRs;
@property(nonatomic, assign) DNSBindStrategy bindStrategy;
@property(nonatomic, assign) BOOL isEnabled;
@property(nonatomic, assign) BOOL stickyTransactions;
@property(nonatomic, strong) nw_path_monitor_t pathMonitor;
@property(nonatomic, strong) dispatch_queue_t monitorQueue;
@property(nonatomic, assign) BOOL vpnActive;
@end

@implementation DNSInterfaceManager

- (instancetype)initWithPreferenceManager:(PreferenceManager*)preferenceManager {
  if (self = [super init]) {
    _preferenceManager = preferenceManager;
    _transactionBindings = [NSMutableDictionary dictionary];
    _monitorQueue = dispatch_queue_create("com.dnshield.interface-monitor", DISPATCH_QUEUE_SERIAL);
    [self reloadConfiguration];
    [self startPathMonitoring];
  }
  return self;
}

- (void)dealloc {
  [self stopPathMonitoring];
}

#pragma mark - Configuration

- (void)reloadConfiguration {
  // Feature flag check
  NSNumber* enabled =
      [self.preferenceManager preferenceValueForKey:kDNShieldEnableDNSInterfaceBinding
                                           inDomain:kDNShieldPreferenceDomain];
  self.isEnabled = enabled ? [enabled boolValue] : NO;

  if (!self.isEnabled) {
    return;
  }

  // Bind strategy
  NSString* strategyString =
      [self.preferenceManager preferenceValueForKey:kDNShieldBindInterfaceStrategy
                                           inDomain:kDNShieldPreferenceDomain];
  if ([@"original_path" isEqualToString:strategyString]) {
    self.bindStrategy = DNSBindStrategyOriginalPath;
  } else if ([@"active_resolver" isEqualToString:strategyString]) {
    self.bindStrategy = DNSBindStrategyActiveResolver;
  } else {
    self.bindStrategy = DNSBindStrategyResolverCIDR;  // default
  }

  // Sticky transactions
  NSNumber* sticky =
      [self.preferenceManager preferenceValueForKey:kDNShieldStickyInterfacePerTransaction
                                           inDomain:kDNShieldPreferenceDomain];
  self.stickyTransactions = sticky ? [sticky boolValue] : YES;

  // VPN resolver CIDRs
  NSArray* cidrs = [self.preferenceManager preferenceValueForKey:kDNShieldVPNResolvers
                                                        inDomain:kDNShieldPreferenceDomain];
  self.vpnResolverCIDRs = cidrs ?: @[ @"100.64.0.0/10" ];

  os_log_info(
      interfaceLogHandle,
      "DNS interface binding enabled: strategy=%{public}@, sticky=%{public}@, cidrs=%{public}@",
      strategyString ?: @"resolver_cidr", self.stickyTransactions ? @"YES" : @"NO",
      self.vpnResolverCIDRs);
}

#pragma mark - Interface Binding

- (nullable DNSInterfaceBinding*)bindingForResolver:(nw_endpoint_t)resolverEndpoint
                                       originalFlow:(NEAppProxyUDPFlow*)originalFlow
                                      transactionID:(NSString*)transactionID {
  if (!self.isEnabled) {
    return nil;
  }

  // Check for existing sticky binding
  if (self.stickyTransactions) {
    DNSInterfaceBinding* existingBinding = [self existingBindingForTransactionID:transactionID];
    if (existingBinding) {
      os_log_debug(interfaceLogHandle,
                   "Using sticky binding for transaction %{public}@: %{public}@", transactionID,
                   existingBinding);
      return existingBinding;
    }
  }

  NSString* resolverIP = [self extractIPFromEndpoint:resolverEndpoint];
  if (!resolverIP) {
    os_log_error(interfaceLogHandle, "Failed to extract IP from resolver endpoint");
    return nil;
  }

  DNSInterfaceBinding* binding = nil;

  switch (self.bindStrategy) {
    case DNSBindStrategyResolverCIDR:
      binding = [self bindingForResolverCIDRStrategy:resolverIP
                                        originalFlow:originalFlow
                                       transactionID:transactionID];
      break;

    case DNSBindStrategyOriginalPath:
      binding = [self bindingForOriginalPathStrategy:originalFlow
                                       transactionID:transactionID
                                          resolverIP:resolverIP];
      break;

    case DNSBindStrategyActiveResolver:
      binding = [self bindingForActiveResolverStrategy:resolverIP transactionID:transactionID];
      break;
  }

  if (binding && self.stickyTransactions) {
    [self setBinding:binding forTransactionID:transactionID];
  }

  return binding;
}

- (nullable DNSInterfaceBinding*)bindingForResolverCIDRStrategy:(NSString*)resolverIP
                                                   originalFlow:(NEAppProxyUDPFlow*)originalFlow
                                                  transactionID:(NSString*)transactionID {
  BOOL isVPNResolver = [self isResolverInVPNCIDRString:resolverIP];

  if (isVPNResolver && self.vpnActive) {
    // Bind to VPN interface
    NSString* vpnInterface = [self findActiveVPNInterface];
    if (vpnInterface) {
      uint32_t ifIndex = [self interfaceIndexForName:vpnInterface];
      DNSInterfaceType ifType = [self interfaceTypeForName:vpnInterface];

      return [[DNSInterfaceBinding alloc] initWithInterfaceName:vpnInterface
                                                 interfaceIndex:ifIndex
                                                  interfaceType:ifType
                                               resolverEndpoint:resolverIP
                                                  transactionID:transactionID];
    }
  }

  // Fall back to system default path
  NSString* defaultInterface = [self findDefaultInterface];
  if (defaultInterface) {
    uint32_t ifIndex = [self interfaceIndexForName:defaultInterface];
    DNSInterfaceType ifType = [self interfaceTypeForName:defaultInterface];

    return [[DNSInterfaceBinding alloc] initWithInterfaceName:defaultInterface
                                               interfaceIndex:ifIndex
                                                interfaceType:ifType
                                             resolverEndpoint:resolverIP
                                                transactionID:transactionID];
  }

  return nil;
}

- (nullable DNSInterfaceBinding*)bindingForOriginalPathStrategy:(NEAppProxyUDPFlow*)originalFlow
                                                  transactionID:(NSString*)transactionID
                                                     resolverIP:(NSString*)resolverIP {
  // Extract interface from the original flow if possible
  // This is a simplified implementation - in practice, we'd need to inspect the flow's path
  NSString* defaultInterface = [self findDefaultInterface];
  if (defaultInterface) {
    uint32_t ifIndex = [self interfaceIndexForName:defaultInterface];
    DNSInterfaceType ifType = [self interfaceTypeForName:defaultInterface];

    return [[DNSInterfaceBinding alloc] initWithInterfaceName:defaultInterface
                                               interfaceIndex:ifIndex
                                                interfaceType:ifType
                                             resolverEndpoint:resolverIP
                                                transactionID:transactionID];
  }

  return nil;
}

- (nullable DNSInterfaceBinding*)bindingForActiveResolverStrategy:(NSString*)resolverIP
                                                    transactionID:(NSString*)transactionID {
  NSString* activeInterface = [self findActiveInterfaceForResolver:resolverIP];
  if (activeInterface) {
    uint32_t ifIndex = [self interfaceIndexForName:activeInterface];
    DNSInterfaceType ifType = [self interfaceTypeForName:activeInterface];

    return [[DNSInterfaceBinding alloc] initWithInterfaceName:activeInterface
                                               interfaceIndex:ifIndex
                                                interfaceType:ifType
                                             resolverEndpoint:resolverIP
                                                transactionID:transactionID];
  }

  return nil;
}

#pragma mark - VPN State Detection

- (BOOL)isVPNActive {
  return self.vpnActive;
}

- (BOOL)isResolverInVPNCIDR:(nw_endpoint_t)resolverEndpoint {
  NSString* resolverIP = [self extractIPFromEndpoint:resolverEndpoint];
  return resolverIP ? [self isResolverInVPNCIDRString:resolverIP] : NO;
}

- (BOOL)isResolverInVPNCIDRString:(NSString*)resolverIP {
  for (NSString* cidr in self.vpnResolverCIDRs) {
    if ([self isIPAddress:resolverIP inCIDR:cidr]) {
      return YES;
    }
  }
  return NO;
}

- (BOOL)isIPAddress:(NSString*)ipAddress inCIDR:(NSString*)cidr {
  NSArray* parts = [cidr componentsSeparatedByString:@"/"];
  if (parts.count != 2) {
    return NO;
  }

  NSString* networkIP = parts[0];
  NSInteger prefixLength = [parts[1] integerValue];

  // IPv4 CIDR checking
  if ([ipAddress containsString:@"."]) {
    return [self isIPv4Address:ipAddress inCIDR:networkIP prefixLength:(int)prefixLength];
  }
  // IPv6 CIDR checking
  else if ([ipAddress containsString:@":"]) {
    return [self isIPv6Address:ipAddress inCIDR:networkIP prefixLength:(int)prefixLength];
  }

  return NO;
}

- (BOOL)isIPv4Address:(NSString*)ipAddress
               inCIDR:(NSString*)networkIP
         prefixLength:(int)prefixLength {
  struct in_addr addr, network;
  if (inet_pton(AF_INET, [ipAddress UTF8String], &addr) != 1) {
    return NO;
  }
  if (inet_pton(AF_INET, [networkIP UTF8String], &network) != 1) {
    return NO;
  }

  uint32_t mask = 0xFFFFFFFF << (32 - prefixLength);
  return (ntohl(addr.s_addr) & mask) == (ntohl(network.s_addr) & mask);
}

- (BOOL)isIPv6Address:(NSString*)ipAddress
               inCIDR:(NSString*)networkIP
         prefixLength:(int)prefixLength {
  struct in6_addr addr, network;
  if (inet_pton(AF_INET6, [ipAddress UTF8String], &addr) != 1) {
    return NO;
  }
  if (inet_pton(AF_INET6, [networkIP UTF8String], &network) != 1) {
    return NO;
  }

  // Create mask and compare
  uint8_t mask[16] = {0};
  int bytes = prefixLength / 8;
  int bits = prefixLength % 8;

  for (int i = 0; i < bytes; i++) {
    mask[i] = 0xFF;
  }
  if (bits > 0 && bytes < 16) {
    mask[bytes] = 0xFF << (8 - bits);
  }

  for (int i = 0; i < 16; i++) {
    if ((addr.s6_addr[i] & mask[i]) != (network.s6_addr[i] & mask[i])) {
      return NO;
    }
  }

  return YES;
}

- (DNSInterfaceType)interfaceTypeForName:(NSString*)interfaceName {
  if ([interfaceName hasPrefix:@"utun"] || [interfaceName hasPrefix:@"ipsec"] ||
      [interfaceName hasPrefix:@"ppp"]) {
    return DNSInterfaceTypeVPN;
  } else if ([interfaceName hasPrefix:@"en"]) {
    // Could be WiFi or Ethernet - simplified detection
    return DNSInterfaceTypeWiFi;
  } else if ([interfaceName hasPrefix:@"pdp_ip"]) {
    return DNSInterfaceTypeCellular;
  }

  return DNSInterfaceTypeUnknown;
}

#pragma mark - Transaction Management

- (void)setBinding:(DNSInterfaceBinding*)binding forTransactionID:(NSString*)transactionID {
  @synchronized(self.transactionBindings) {
    self.transactionBindings[transactionID] = binding;
  }
}

- (nullable DNSInterfaceBinding*)existingBindingForTransactionID:(NSString*)transactionID {
  @synchronized(self.transactionBindings) {
    return self.transactionBindings[transactionID];
  }
}

- (void)clearBindingForTransactionID:(NSString*)transactionID {
  @synchronized(self.transactionBindings) {
    [self.transactionBindings removeObjectForKey:transactionID];
  }
}

#pragma mark - Path Monitoring

- (void)startPathMonitoring {
  if (self.pathMonitor) {
    return;
  }

  self.pathMonitor = nw_path_monitor_create();
  nw_path_monitor_set_queue(self.pathMonitor, self.monitorQueue);

  __weak typeof(self) weakSelf = self;
  nw_path_monitor_set_update_handler(self.pathMonitor, ^(nw_path_t path) {
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    [strongSelf handlePathUpdate:path];
  });

  nw_path_monitor_start(self.pathMonitor);
  os_log_info(interfaceLogHandle, "Started path monitoring for interface binding");
}

- (void)stopPathMonitoring {
  if (self.pathMonitor) {
    nw_path_monitor_cancel(self.pathMonitor);
    self.pathMonitor = nil;
    os_log_info(interfaceLogHandle, "Stopped path monitoring");
  }
}

- (void)handlePathUpdate:(nw_path_t)path {
  BOOL wasVPNActive = self.vpnActive;
  self.vpnActive = [self detectVPNFromPath:path];

  if (wasVPNActive != self.vpnActive) {
    os_log_info(interfaceLogHandle, "VPN state changed: %{public}@ -> %{public}@",
                wasVPNActive ? @"active" : @"inactive", self.vpnActive ? @"active" : @"inactive");

    // Clear transaction bindings on VPN state change
    @synchronized(self.transactionBindings) {
      [self.transactionBindings removeAllObjects];
    }

    if ([self.delegate respondsToSelector:@selector(interfaceManager:didUpdateVPNState:)]) {
      [self.delegate interfaceManager:self didUpdateVPNState:self.vpnActive];
    }
  }

  if ([self.delegate respondsToSelector:@selector(interfaceManager:didDetectPathChange:)]) {
    [self.delegate interfaceManager:self didDetectPathChange:path];
  }
}

- (BOOL)detectVPNFromPath:(nw_path_t)path {
  __block BOOL hasVPN = NO;

  nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
    const char* name = nw_interface_get_name(interface);
    if (name && (strncmp(name, "utun", 4) == 0 || strncmp(name, "ipsec", 5) == 0)) {
      hasVPN = YES;
      return false;  // Stop enumeration
    }
    return true;  // Continue enumeration
  });

  return hasVPN;
}

#pragma mark - Path Validation

- (BOOL)validatePathToResolver:(nw_endpoint_t)resolverEndpoint
                  viaInterface:(NSString*)interfaceName {
  if (!resolverEndpoint || !interfaceName) {
    return NO;
  }

  // Check if the interface is up and running
  nw_path_status_t interfaceStatus = [self pathStatusForInterface:interfaceName];
  if (interfaceStatus != nw_path_status_satisfied) {
    os_log_debug(interfaceLogHandle, "Interface %{public}@ is not satisfied (status: %d)",
                 interfaceName, interfaceStatus);
    return NO;
  }

  // For now, if the interface is up and running, we consider it valid
  // A more sophisticated implementation could use socket-level reachability tests
  os_log_debug(interfaceLogHandle,
               "Path validation for %{public}@ via %{public}@: valid=YES (interface up)",
               [self extractIPFromEndpoint:resolverEndpoint] ?: @"unknown", interfaceName);

  return YES;
}

- (nw_path_status_t)pathStatusForInterface:(NSString*)interfaceName {
  // Get interface index
  uint32_t ifIndex = [self interfaceIndexForName:interfaceName];
  if (ifIndex == 0) {
    return nw_path_status_unsatisfied;
  }

  // Check if interface exists and is up
  struct ifaddrs *ifap, *ifa;
  BOOL interfaceFound = NO;
  BOOL interfaceUp = NO;

  if (getifaddrs(&ifap) == 0) {
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
      if (strcmp(ifa->ifa_name, [interfaceName UTF8String]) == 0) {
        interfaceFound = YES;
        interfaceUp = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
        break;
      }
    }
    freeifaddrs(ifap);
  }

  if (!interfaceFound) {
    return nw_path_status_invalid;
  }

  if (!interfaceUp) {
    return nw_path_status_unsatisfied;
  }

  return nw_path_status_satisfied;
}

#pragma mark - Utility Methods

- (nullable NSString*)extractIPFromEndpoint:(nw_endpoint_t)endpoint {
  if (!endpoint) {
    return nil;
  }

  // Use modern Network framework functions to extract hostname
  nw_endpoint_type_t endpointType = nw_endpoint_get_type(endpoint);

  if (endpointType == nw_endpoint_type_host) {
    const char* hostname = nw_endpoint_get_hostname(endpoint);
    if (hostname) {
      return [NSString stringWithUTF8String:hostname];
    }
  } else if (endpointType == nw_endpoint_type_address) {
    char* address_string = nw_endpoint_copy_address_string(endpoint);
    if (address_string) {
      NSString* result = [NSString stringWithUTF8String:address_string];
      free(address_string);
      return result;
    }
  }

  // Return nil instead of placeholder - let caller handle the failure
  return nil;
}

- (uint32_t)interfaceIndexForName:(NSString*)interfaceName {
  return if_nametoindex([interfaceName UTF8String]);
}

- (nullable NSString*)findActiveVPNInterface {
  struct ifaddrs *ifap, *ifa;
  NSString* vpnInterface = nil;

  if (getifaddrs(&ifap) == 0) {
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_flags & IFF_UP && ifa->ifa_flags & IFF_RUNNING) {
        NSString* name = [NSString stringWithUTF8String:ifa->ifa_name];
        if ([name hasPrefix:@"utun"]) {
          vpnInterface = name;
          break;
        }
      }
    }
    freeifaddrs(ifap);
  }

  return vpnInterface;
}

- (nullable NSString*)findDefaultInterface {
  struct ifaddrs *ifap, *ifa;
  NSString* defaultInterface = nil;

  if (getifaddrs(&ifap) == 0) {
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_flags & IFF_UP && ifa->ifa_flags & IFF_RUNNING) {
        NSString* name = [NSString stringWithUTF8String:ifa->ifa_name];
        // Prefer en0 (usually primary interface)
        if ([name isEqualToString:@"en0"]) {
          defaultInterface = name;
          break;
        } else if (!defaultInterface && [name hasPrefix:@"en"]) {
          defaultInterface = name;
        }
      }
    }
    freeifaddrs(ifap);
  }

  return defaultInterface;
}

- (nullable NSString*)findActiveInterfaceForResolver:(NSString*)resolverIP {
  // Simplified implementation - in practice, we'd check routing table
  return [self findDefaultInterface];
}

- (nw_interface_t)findInterfaceByName:(NSString*)interfaceName {
  // Create a path monitor to enumerate available interfaces
  nw_path_monitor_t monitor = nw_path_monitor_create();
  __block nw_interface_t foundInterface = nil;

  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

  nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
    nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
      const char* name = nw_interface_get_name(interface);
      if (name && strcmp(name, [interfaceName UTF8String]) == 0) {
        foundInterface = interface;
        return false;  // Stop enumeration
      }
      return true;  // Continue enumeration
    });
    dispatch_semaphore_signal(semaphore);
  });

  dispatch_queue_t queue =
      dispatch_queue_create("com.dnshield.interface-finder", DISPATCH_QUEUE_SERIAL);
  nw_path_monitor_set_queue(monitor, queue);
  nw_path_monitor_start(monitor);

  // Wait for the path update with timeout
  dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC);
  dispatch_semaphore_wait(semaphore, timeout);

  nw_path_monitor_cancel(monitor);

  return foundInterface;
}

@end
