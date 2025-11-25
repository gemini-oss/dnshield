//
//  XPCClient.h
//  DNShield
//
//  XPC Client for communicating with the Network Extension
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface XPCClient : NSObject

+ (instancetype)sharedClient;

// Update blocked domains
- (void)updateBlockedDomains:(NSArray<NSString*>*)domains
           completionHandler:(void (^_Nullable)(BOOL success, NSError* _Nullable error))completion;

// Update DNS servers
- (void)updateDNSServers:(NSArray<NSString*>*)servers
       completionHandler:(void (^_Nullable)(BOOL success, NSError* _Nullable error))completion;

// Get statistics
- (void)getStatisticsWithCompletionHandler:(void (^)(NSDictionary* _Nullable stats,
                                                     NSError* _Nullable error))completion;

// Clear cache
- (void)clearCacheWithCompletionHandler:(void (^_Nullable)(BOOL success,
                                                           NSError* _Nullable error))completion;

// Update configuration
- (void)updateConfiguration:(NSDictionary*)config
          completionHandler:(void (^_Nullable)(BOOL success, NSError* _Nullable error))completion;

// Get remote object proxy
- (id)remoteObjectProxyWithErrorHandler:(void (^)(NSError* error))errorHandler;

// Fetch full rule metadata
- (void)getAllRulesWithCompletionHandler:(void (^)(NSArray* _Nullable rules,
                                                   NSError* _Nullable error))completion;

// Connection Management
- (void)verifyConnectionWithCompletionHandler:(void (^)(BOOL connected,
                                                        NSError* _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
