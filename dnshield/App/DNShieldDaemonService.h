//
//  DNShieldDaemonService.h
//  DNShield
//

#import <Cocoa/Cocoa.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

NS_ASSUME_NONNULL_BEGIN

@class DNShieldDaemonService;

@protocol DNShieldDaemonServiceDelegate <NSObject>
- (void)daemonService:(DNShieldDaemonService*)service didUpdateAvailability:(BOOL)available;
- (void)daemonService:(DNShieldDaemonService*)service didDetectStalePidFile:(BOOL)hasStalePidFile;
@end

@interface DNShieldDaemonService : NSObject

@property(nonatomic, weak) id<DNShieldDaemonServiceDelegate> delegate;
@property(nonatomic, readonly) BOOL daemonAvailable;
@property(nonatomic, readonly) BOOL hasStalePidFile;

- (void)start;
- (void)stop;
- (void)sendCommand:(NSString*)command;
- (void)requestStatusWithReply:(void (^)(NSDictionary* _Nullable reply,
                                         NSError* _Nullable error))replyBlock;
- (BOOL)writeCommand:(NSDictionary*)command error:(NSError**)error;
- (void)checkForStalePidFile;
- (void)showStalePidWarning;

@end

NS_ASSUME_NONNULL_END
