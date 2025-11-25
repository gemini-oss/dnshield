//
//  DNRuleDataProvider.h
//  DNShield
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class DNSProxyConfigurationManager;

typedef void (^DNRuleDataProviderCompletion)(NSArray* blockedDomains, NSArray* allowedDomains,
                                             NSDictionary* ruleSources, NSDictionary* configInfo,
                                             NSDictionary* syncInfo, NSError* _Nullable error);

@interface DNRuleDataProvider : NSObject

- (instancetype)initWithProxyManager:(DNSProxyConfigurationManager*)proxyManager;

- (void)fetchRulesWithCompletion:(DNRuleDataProviderCompletion)completion;
- (NSDictionary*)currentRulesConfigInfo;
- (NSDictionary*)syncStatusDirectly;
- (NSArray<NSString*>*)systemDNSServersFallback;
- (NSArray<NSDictionary*>*)manifestEntriesWithURL:(NSString* _Nullable* _Nullable)manifestURL
                                            error:(NSError* _Nullable* _Nullable)error;

@end

NS_ASSUME_NONNULL_END
