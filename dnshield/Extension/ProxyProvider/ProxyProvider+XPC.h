//
//  ProxyProvider+XPC.h
//  DNShield Network Extension
//
//  Category interface for XPC listener utilities
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (XPC) <XPCExtensionProtocol, NSXPCListenerDelegate>

- (void)startXPCListener;

@end

NS_ASSUME_NONNULL_END
