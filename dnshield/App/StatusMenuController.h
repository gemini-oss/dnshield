//
//  StatusMenuController.h
//  DNShield
//

#import <Cocoa/Cocoa.h>

#import "DNRuleDataProvider.h"
#import "DNSProxyConfigurationManager.h"
#import "DNSStateColorPreferencesController.h"
#import "DNShieldDaemonService.h"

NS_ASSUME_NONNULL_BEGIN

@class Extension;

@interface StatusMenuController : NSObject <NSMenuDelegate,
                                            DNSStateColorPreferencesControllerDelegate,
                                            DNShieldDaemonServiceDelegate,
                                            DNSProxyConfigurationManagerDelegate>

@property(nonatomic, strong, readonly) NSStatusItem* statusItem;

- (instancetype)initWithProxyManager:(DNSProxyConfigurationManager*)proxyManager
                       daemonService:(DNShieldDaemonService*)daemonService
                    ruleDataProvider:(DNRuleDataProvider*)ruleDataProvider
                    extensionManager:(Extension*)extensionManager
          colorPreferencesController:(DNSStateColorPreferencesController*)colorController;

- (void)setupStatusBar;
- (void)invalidate;

@end

NS_ASSUME_NONNULL_END
