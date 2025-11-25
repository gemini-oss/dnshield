#import <arpa/inet.h>
#import <math.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>

#import <Common/LoggingManager.h>
#import "Provider.h"
#import "ProxyProvider+Helpers.h"
#import "ProxyProvider+Private.h"

@implementation ProxyProvider (NetworkHelpers)

#pragma mark - Network Framework Conversion Helpers

// Helper function to convert deprecated NWEndpoint to modern nw_endpoint_t
- (nw_endpoint_t)modernEndpointFromLegacy:(NWEndpoint*)legacyEndpoint {
  if (!legacyEndpoint) {
    return nil;
  }

  // Handle NWHostEndpoint conversion
  if ([legacyEndpoint isKindOfClass:[NWHostEndpoint class]]) {
    NWHostEndpoint* hostEndpoint = (NWHostEndpoint*)legacyEndpoint;
    NSString* hostname = hostEndpoint.hostname;
    NSString* port = hostEndpoint.port;

    if (hostname && port) {
      return nw_endpoint_create_host([hostname UTF8String], [port UTF8String]);
    }
  }

  // Fallback: try to extract from description using regex
  NSString* description = [legacyEndpoint description];
  if (description && description.length > 0) {
    // Try to extract hostname:port pattern
    NSRegularExpression* hostPortRegex =
        [NSRegularExpression regularExpressionWithPattern:@"([^:]+):(\\d+)" options:0 error:nil];

    NSTextCheckingResult* match =
        [hostPortRegex firstMatchInString:description
                                  options:0
                                    range:NSMakeRange(0, description.length)];
    if (match) {
      NSString* hostname = [description substringWithRange:[match rangeAtIndex:1]];
      NSString* port = [description substringWithRange:[match rangeAtIndex:2]];
      return nw_endpoint_create_host([hostname UTF8String], [port UTF8String]);
    }
  }

  return nil;
}

// Helper function to create NWEndpoint for compatibility with NetworkExtension
- (NWEndpoint*)createLegacyEndpointWithHostname:(NSString*)hostname port:(NSString*)port {
  if (@available(macOS 15.0, *)) {
// Still need to use the deprecated API since NetworkExtension expects it
// This suppresses the deprecation warning in a controlled way
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [NWHostEndpoint endpointWithHostname:hostname port:port];
#pragma clang diagnostic pop
  } else {
    return [NWHostEndpoint endpointWithHostname:hostname port:port];
  }
}

#pragma mark - IP Address Helpers

// Helper method to check if an IP address is in a CIDR range (supports both IPv4 and IPv6)
- (BOOL)isIPAddress:(NSString*)ipAddress inCIDR:(NSString*)cidr {
  // First determine if this is IPv6 or IPv4
  BOOL isIPv6 = [ipAddress rangeOfString:@":"].location != NSNotFound;
  BOOL isCIDRv6 = [cidr rangeOfString:@":"].location != NSNotFound;

  // If IP and CIDR are different families, they can't match
  if (isIPv6 != isCIDRv6) {
    return NO;
  }

  // Handle IPv6
  if (isIPv6) {
    return [self isIPv6Address:ipAddress inCIDR:cidr];
  }

  // Handle IPv4 (existing logic)
  NSArray* cidrParts = [cidr componentsSeparatedByString:@"/"];
  if (cidrParts.count != 2) {
    // Not CIDR notation, treat as prefix match
    return [ipAddress hasPrefix:cidr];
  }

  NSString* networkAddress = cidrParts[0];
  NSInteger prefixLength = [cidrParts[1] integerValue];

  // Check prefixLength bounds to avoid undefined shift behavior
  if (prefixLength < 0 || prefixLength > 32) {
    DNSLogError(LogCategoryNetwork, "Invalid CIDR prefix length: %ld for %@", (long)prefixLength,
                cidr);
    return NO;
  }

  // Convert IP addresses to 32-bit integers
  uint32_t ip = [self ipToUInt32:ipAddress];
  uint32_t network = [self ipToUInt32:networkAddress];

  if (ip == 0 || network == 0) {
    // Invalid IP, fall back to string prefix matching
    DNSLogError(LogCategoryNetwork,
                "Fallback to string prefix matching in isIPAddress:inCIDR:. ipAddress: %{public}@, "
                "networkAddress: %{public}@",
                ipAddress, networkAddress);
    return [ipAddress hasPrefix:networkAddress];
  }

  // Create subnet mask (special case for /0 and /32)
  uint32_t mask;
  if (prefixLength == 0) {
    mask = 0;  // Match all IPs
  } else if (prefixLength == 32) {
    mask = 0xFFFFFFFF;  // Match exact IP only
  } else {
    mask = 0xFFFFFFFF << (32 - prefixLength);
  }

  // Check if IP is in the network range
  return (ip & mask) == (network & mask);
}

// Helper method to check if an IPv6 address is in a CIDR range
- (BOOL)isIPv6Address:(NSString*)ipAddress inCIDR:(NSString*)cidr {
  // Parse CIDR notation (e.g., "2001:db8::/32")
  NSArray* cidrParts = [cidr componentsSeparatedByString:@"/"];
  if (cidrParts.count != 2) {
    // Not CIDR notation, check for exact match
    return [ipAddress isEqualToString:cidr];
  }

  NSString* networkAddress = cidrParts[0];
  NSInteger prefixLength = [cidrParts[1] integerValue];

  // Check prefixLength bounds for IPv6
  if (prefixLength < 0 || prefixLength > 128) {
    DNSLogError(LogCategoryNetwork, "Invalid IPv6 CIDR prefix length: %ld for %@",
                (long)prefixLength, cidr);
    return NO;
  }

  // Convert IPv6 addresses to binary using inet_pton
  struct in6_addr ip6;
  struct in6_addr network6;

  if (inet_pton(AF_INET6, [ipAddress UTF8String], &ip6) != 1) {
    DNSLogError(LogCategoryNetwork, "Invalid IPv6 address: %{public}@", ipAddress);
    return NO;
  }

  if (inet_pton(AF_INET6, [networkAddress UTF8String], &network6) != 1) {
    DNSLogError(LogCategoryNetwork, "Invalid IPv6 network address: %{public}@", networkAddress);
    return NO;
  }

  // Compare the addresses up to the prefix length
  // IPv6 addresses are 128 bits (16 bytes)
  NSInteger bytesToCheck = prefixLength / 8;
  NSInteger bitsInLastByte = prefixLength % 8;

  // Check full bytes
  for (NSInteger i = 0; i < bytesToCheck; i++) {
    if (ip6.s6_addr[i] != network6.s6_addr[i]) {
      return NO;
    }
  }

  // Check remaining bits in the last partial byte
  if (bitsInLastByte > 0 && bytesToCheck < 16) {
    uint8_t mask = (uint8_t)(0xFF << (8 - bitsInLastByte));
    if ((ip6.s6_addr[bytesToCheck] & mask) != (network6.s6_addr[bytesToCheck] & mask)) {
      return NO;
    }
  }

  return YES;
}

// Helper to convert IP string to uint32
- (uint32_t)ipToUInt32:(NSString*)ipString {
  // Extract just the IP address if it contains a port
  NSString* ip = ipString;
  NSRange colonRange = [ipString rangeOfString:@":"];
  if (colonRange.location != NSNotFound) {
    ip = [ipString substringToIndex:colonRange.location];
  }

  NSArray* octets = [ip componentsSeparatedByString:@"."];
  if (octets.count != 4)
    return 0;

  uint32_t result = 0;
  for (uint32_t i = 0; i < 4; i++) {
    NSInteger octet = [octets[i] integerValue];
    if (octet < 0 || octet > 255)
      return 0;
    result = (result << 8) | (uint32_t)octet;
  }
  return result;
}

// Helper to extract IP from endpoint string
- (NSString*)extractIPFromEndpoint:(NSString*)endpointStr {
  // Handle IPv6 format: [2001:db8::1]:53
  if ([endpointStr hasPrefix:@"["]) {
    NSRange closeBracket = [endpointStr rangeOfString:@"]"];
    if (closeBracket.location != NSNotFound) {
      // Extract IPv6 address between brackets
      return [endpointStr substringWithRange:NSMakeRange(1, closeBracket.location - 1)];
    }
  }

  // Handle IPv4 format: 192.168.1.1:53
  // Find the last colon to separate IP from port
  NSRange lastColon = [endpointStr rangeOfString:@":" options:NSBackwardsSearch];
  if (lastColon.location != NSNotFound) {
    NSString* possibleIP = [endpointStr substringToIndex:lastColon.location];
    // Check if this looks like IPv4 (no colons) or IPv6 (has colons)
    if ([possibleIP rangeOfString:@":"].location == NSNotFound) {
      // No colons in the IP part, it's IPv4
      return possibleIP;
    }
    // Has colons, probably IPv6 without brackets (less common but possible)
    // Return the whole string as it's likely IPv6 without port
    return endpointStr;
  }

  // No port separator found, return as-is
  return endpointStr;
}

- (NSTimeInterval)resolveWebSocketRetryInterval {
  NSNumber* retryPref =
      [self.preferenceManager preferenceValueForKey:kDNShieldWebSocketRetryIntervalKey
                                           inDomain:kDNShieldPreferenceDomain];
  NSTimeInterval retryInterval =
      retryPref ? [retryPref doubleValue] : kDNShieldDefaultWebSocketRetryInterval;
  if (retryInterval <= 0)
    retryInterval = kDNShieldDefaultWebSocketRetryInterval;
  return retryInterval;
}

- (void)resetWebSocketRetryState {
  if (self.webSocketRetryTimer) {
    dispatch_source_cancel(self.webSocketRetryTimer);
    self.webSocketRetryTimer = nil;
  }
  self.webSocketRetryInterval = [self resolveWebSocketRetryInterval];
  self.webSocketRetryAttempt = 0;
  NSNumber* backoffPref = [self.preferenceManager preferenceValueForKey:@"WebSocketRetryBackoff"
                                                               inDomain:kDNShieldPreferenceDomain];
  self.webSocketBackoffEnabled = backoffPref ? [backoffPref boolValue] : YES;
}

- (BOOL)isWebSocketServerRunning {
  return self.wsServer && self.wsServer.isRunning;
}

- (void)ensureWebSocketServerRunning {
  dispatch_async(self.dnsQueue, ^{
    if ([self isWebSocketServerRunning]) {
      if (self.webSocketRetryTimer) {
        dispatch_source_cancel(self.webSocketRetryTimer);
        self.webSocketRetryTimer = nil;
      }
      self.webSocketRetryAttempt = 0;
      return;
    }

    NSNumber* wsEnabled =
        [self.preferenceManager preferenceValueForKey:kDNShieldEnableWebSocketServer
                                             inDomain:kDNShieldPreferenceDomain];
    if (wsEnabled && ![wsEnabled boolValue]) {
      DNSLogInfo(LogCategoryNetwork, "WebSocket server disabled via preferences");
      if (self.webSocketRetryTimer) {
        dispatch_source_cancel(self.webSocketRetryTimer);
        self.webSocketRetryTimer = nil;
      }
      return;
    }

    // Check provider configuration first (from MDM/managed preferences)
    NSString* wsToken = nil;
    NSUInteger port = 8876;

    if (self.providerConfiguration) {
      wsToken = self.providerConfiguration[@"WebSocketAuthToken"];
      NSNumber* wsPort = self.providerConfiguration[@"WebSocketPort"];
      if (wsPort) {
        port = [wsPort unsignedIntegerValue];
      }

      if (wsToken) {
        DNSLogInfo(LogCategoryNetwork, "Using WebSocket configuration from provider options");
      }
    }

    // Fall back to preference manager if no provider configuration
    if (!wsToken) {
      NSNumber* wsPortPref =
          [self.preferenceManager preferenceValueForKey:@"WebSocketPort"
                                               inDomain:kDNShieldPreferenceDomain];
      if (wsPortPref) {
        port = [wsPortPref unsignedIntegerValue];
      }
    }

    self.wsServer = [[WebSocketServer alloc] initWithPort:port authToken:wsToken];
    self.wsServer.delegate = self;

    NSError* wsError = nil;
    if (![self.wsServer start:&wsError]) {
      DNSLogError(
          LogCategoryNetwork,
          "Failed to start WebSocket server on port %lu: %{public}@ (attempt %lu, interval %.1fs)",
          (unsigned long)port, wsError.localizedDescription ?: @"unknown",
          (unsigned long)self.webSocketRetryAttempt + 1, self.webSocketRetryInterval);
      [self scheduleWebSocketRetryWithError:wsError];
    } else {
      DNSLogInfo(LogCategoryNetwork, "WebSocket server started on port %lu", (unsigned long)port);
      self.webSocketRetryAttempt = 0;
      if (self.webSocketRetryTimer) {
        dispatch_source_cancel(self.webSocketRetryTimer);
        self.webSocketRetryTimer = nil;
      }
    }
  });
}

- (void)scheduleWebSocketRetryWithError:(NSError* _Nullable)error {
  if (self.webSocketRetryTimer) {
    dispatch_source_cancel(self.webSocketRetryTimer);
    self.webSocketRetryTimer = nil;
  }

  (void)error;

  self.webSocketRetryAttempt += 1;

  NSTimeInterval interval = self.webSocketRetryInterval;
  if (self.webSocketBackoffEnabled) {
    // Use bit shifting for exponential backoff (more efficient than pow())
    interval =
        MIN(self.webSocketRetryInterval * (double)(1 << (self.webSocketRetryAttempt - 1)), 300.0);
  }

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.dnsQueue);
  dispatch_source_set_timer(timer,
                            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(interval * NSEC_PER_SEC)), 0,
                            (1ull * NSEC_PER_SEC));

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(timer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;
    strongSelf.webSocketRetryTimer = nil;
    DNSLogInfo(LogCategoryNetwork, "Retrying WebSocket server start (attempt %lu, interval %.1fs)",
               (unsigned long)strongSelf.webSocketRetryAttempt, interval);
    [strongSelf ensureWebSocketServerRunning];
  });

  self.webSocketRetryTimer = timer;
  dispatch_resume(timer);
}

@end
