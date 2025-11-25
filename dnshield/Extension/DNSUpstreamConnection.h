//
//  DNSUpstreamConnection.h
//  DNShield Network Extension
//
//  Manages connections to upstream DNS servers
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

@class DNSInterfaceBinding;
@protocol DNSUpstreamConnectionDelegate;

@interface DNSUpstreamConnection : NSObject

@property(nonatomic, weak) id<DNSUpstreamConnectionDelegate> delegate;
@property(nonatomic, readonly) NSString* serverAddress;
@property(nonatomic, readonly) BOOL isConnected;
@property(nonatomic, readonly, nullable) DNSInterfaceBinding* interfaceBinding;

- (instancetype)initWithServer:(NSString*)server;
- (instancetype)initWithServer:(NSString*)server
              interfaceBinding:(nullable DNSInterfaceBinding*)binding;
- (void)sendQuery:(NSData*)queryData;
- (void)close;

@end

@protocol DNSUpstreamConnectionDelegate <NSObject>
- (void)upstreamConnection:(DNSUpstreamConnection*)connection didReceiveResponse:(NSData*)response;
- (void)upstreamConnection:(DNSUpstreamConnection*)connection didFailWithError:(NSError*)error;
@end

NS_ASSUME_NONNULL_END
