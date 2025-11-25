//
//  ProxyProvider+Telemetry.h
//  DNShield Network Extension
//
//  Category interface for telemetry helpers shared by proxy components
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (TelemetryHelpers)

- (NSString*)queryTypeToString:(DNSQueryType)queryType;
- (NSString*)categorizeThreat:(NSString*)domain;
- (NSString*)ruleSourceToString:(DNSRuleSource)source;
- (void)sendServerFailureForTransactionID:(NSData*)transactionID;
- (void)handleDatabaseChange:(NSNotification*)notification;

@end

NS_ASSUME_NONNULL_END
