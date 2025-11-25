//
//  Extension.h
//  DNShield
//
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <SystemExtensions/SystemExtensions.h>
#import <os/log.h>

typedef void (^replyBlockType)(BOOL);

@interface Extension : NSObject <OSSystemExtensionRequestDelegate>

/* PROPERTIES */

// reply
@property(nonatomic, copy) replyBlockType replyBlock;

/* METHODS */

// submit request to toggle extension
- (void)toggleExtension:(NSUInteger)action reply:(replyBlockType)reply;

// check if extension is running
- (BOOL)isExtensionRunning;

// activate/deactive network extension
- (BOOL)toggleNetworkExtension:(NSUInteger)action;

// get network extension's status
- (BOOL)isNetworkExtensionEnabled;

@end
