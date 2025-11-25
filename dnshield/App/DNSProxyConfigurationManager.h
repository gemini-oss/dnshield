//
//  DNSProxyConfigurationManager.h
//  DNShield
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class Extension;
@class DNSProxyConfigurationManager;

@protocol DNSProxyConfigurationManagerDelegate <NSObject>
- (void)dnsProxyConfigurationManagerDidUpdateState:
    (DNSProxyConfigurationManager*)configurationManager;
@end

@interface DNSProxyConfigurationManager : NSObject

@property(nonatomic, weak) id<DNSProxyConfigurationManagerDelegate> delegate;
@property(nonatomic, readonly, getter=isMDMManaged) BOOL MDMManaged;
@property(nonatomic, readonly) BOOL cachedDNSProxyConfigured;
@property(nonatomic, strong, readonly, nullable) NSDate* lastDNSProxyCheck;

- (instancetype)initWithExtensionManager:(Extension*)extensionManager;

- (void)migrateUserPreferencesToAppGroupIfNeeded;
- (BOOL)isDNSProxyManagedByProfile;
- (BOOL)isDNSProxyConfiguredByMDM;
- (void)updateDNSProxyConfigurationAsync;
- (void)checkAndEnableMDMDNSProxy;
- (void)removeLocalDNSProxyConfigurationWithReason:(NSString*)reason;

@end

NS_ASSUME_NONNULL_END
