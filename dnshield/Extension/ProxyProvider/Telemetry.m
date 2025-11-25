#import <Common/DNShieldPreferences.h>
#import <Common/LoggingManager.h>
#import "AuditLogger.h"
#import "DNSPacket.h"
#import "Provider.h"
#import "ProxyProvider+FlowManagement.h"
#import "ProxyProvider+Initialization.h"
#import "ProxyProvider+Migration.h"
#import "ProxyProvider+Private.h"
#import "ProxyProvider+Telemetry.h"

@implementation ProxyProvider (TelemetryHelpers)

#pragma mark - Telemetry Helper Methods

- (NSString*)queryTypeToString:(DNSQueryType)queryType {
  switch (queryType) {
    case DNSQueryTypeA: return @"A";
    case DNSQueryTypeAAAA: return @"AAAA";
    case DNSQueryTypeCNAME: return @"CNAME";
    case DNSQueryTypeMX: return @"MX";
    case DNSQueryTypeNS: return @"NS";
    case DNSQueryTypePTR: return @"PTR";
    case DNSQueryTypeSOA: return @"SOA";
    case DNSQueryTypeTXT: return @"TXT";
    case DNSQueryTypeSRV: return @"SRV";
    default: return [NSString stringWithFormat:@"TYPE%d", queryType];
  }
}

- (NSString*)categorizeThreat:(NSString*)domain {
  // Simple categorization based on domain patterns
  // In production, this would use a more sophisticated threat intelligence feed

  NSString* lowerDomain = [domain lowercaseString];

  if ([lowerDomain containsString:@"doubleclick"] ||
      [lowerDomain containsString:@"googleadservices"] ||
      [lowerDomain containsString:@"googlesyndication"] ||
      [lowerDomain containsString:@"amazon-adsystem"] ||
      [lowerDomain containsString:@"facebook.com/tr"]) {
    return @"ads";
  }

  if ([lowerDomain containsString:@"google-analytics"] ||
      [lowerDomain containsString:@"googletagmanager"] ||
      [lowerDomain containsString:@"scorecardresearch"] ||
      [lowerDomain containsString:@"quantserve"] || [lowerDomain containsString:@"segment.io"]) {
    return @"tracker";
  }

  if ([lowerDomain containsString:@"phishing"] || [lowerDomain containsString:@"malware"]) {
    return @"malware";
  }

  return @"other";
}

- (NSString*)ruleSourceToString:(DNSRuleSource)source {
  switch (source) {
    case DNSRuleSourceUser: return @"user";
    case DNSRuleSourceManifest: return @"manifest";
    case DNSRuleSourceRemote: return @"remote";
    case DNSRuleSourceSystem: return @"system";
    default: return @"unknown";
  }
}

// Helper method to send server failure response
- (void)sendServerFailureForTransactionID:(NSData*)transactionID {
  NSDictionary* clientInfo = [self.queryToClientInfo objectForKey:transactionID];
  if (clientInfo && transactionID.length >= 2) {
    // Create a minimal server failure response
    uint8_t response[12];
    memcpy(response, transactionID.bytes, 2);  // Transaction ID
    response[2] = 0x81;                        // QR=1, OPCODE=0, AA=0, TC=0, RD=1
    response[3] = 0x82;                        // RA=1, Z=0, RCODE=2 (Server failure)
    memset(&response[4], 0, 8);                // Clear counts

    NSData* errorResponse = [NSData dataWithBytes:response length:12];
    [self sendResponse:errorResponse toFlow:clientInfo[@"flow"] endpoint:clientInfo[@"endpoint"]];
  }

  // Clean up
  [self.queryToClientInfo removeObjectForKey:transactionID];
  [self.queryTimestamps removeObjectForKey:transactionID];
}

- (void)handleDatabaseChange:(NSNotification*)notification {
  DNSLogInfo(LogCategoryCache, "Database changed externally, clearing caches");
  dispatch_async(self.dnsQueue, ^{
    [self.dnsCache clearCache];
    [self.ruleCache clear];

    // Re-warm cache with updated rules
    [self warmCache];
  });
}

@end
