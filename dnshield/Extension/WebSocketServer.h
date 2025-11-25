//
//  WebSocketServer.h
//  DNShield Network Extension
//
//  WebSocket server for communicating with Chrome extension
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol WebSocketServerDelegate <NSObject>
@optional
- (void)webSocketServerDidStart:(NSUInteger)port;
- (void)webSocketServerDidStop;
- (void)webSocketServerDidReceiveMessage:(NSDictionary*)message fromClient:(NSString*)clientID;
@end

@interface WebSocketServer : NSObject

@property(nonatomic, weak) id<WebSocketServerDelegate> delegate;
@property(nonatomic, readonly, getter=isRunning) BOOL running;
@property(nonatomic, readonly) NSUInteger port;
@property(nonatomic, readonly) NSString* authToken;

- (instancetype)initWithPort:(NSUInteger)port;
- (instancetype)initWithPort:(NSUInteger)port authToken:(nullable NSString*)authToken;
- (BOOL)start:(NSError**)error;
- (void)stop;
- (void)setAuthToken:(NSString*)authToken;

// Authentication
- (BOOL)storeAuthTokenInKeychain:(NSError**)error;
- (nullable NSString*)retrieveAuthTokenFromKeychain;

// Send a message to all connected clients
- (void)broadcastMessage:(NSDictionary*)message;

// Send a message to a specific client
- (void)sendMessage:(NSDictionary*)message toClient:(NSString*)clientID;

// Send a blocked domain notification
- (void)notifyBlockedDomain:(NSString*)domain
                    process:(NSString*)process
                  timestamp:(NSDate*)timestamp;

@end

NS_ASSUME_NONNULL_END
