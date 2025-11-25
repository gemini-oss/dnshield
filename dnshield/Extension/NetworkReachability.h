//
//  NetworkReachability.h
//  DNShield Network Extension
//
//  Network reachability monitoring using NWPathMonitor
//  Provides network status updates to coordinate rule fetching
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

// Network status
typedef NS_ENUM(NSInteger, NetworkStatus) {
  NetworkStatusUnknown = 0,
  NetworkStatusNotReachable,
  NetworkStatusReachableViaWiFi,
  NetworkStatusReachableViaCellular,
  NetworkStatusReachableViaWired,
  NetworkStatusReachableViaLoopback,
  NetworkStatusReachableViaOther
};

// Connection type flags
typedef NS_OPTIONS(NSUInteger, NetworkConnectionType) {
  NetworkConnectionTypeNone = 0,
  NetworkConnectionTypeWiFi = 1 << 0,
  NetworkConnectionTypeCellular = 1 << 1,
  NetworkConnectionTypeWired = 1 << 2,
  NetworkConnectionTypeLoopback = 1 << 3,
  NetworkConnectionTypeOther = 1 << 4
};

// Notifications
extern NSString* const NetworkReachabilityChangedNotification;
extern NSString* const NetworkReachabilityNotificationKeyStatus;
extern NSString* const NetworkReachabilityNotificationKeyPreviousStatus;
extern NSString* const NetworkReachabilityNotificationKeyPath;

// Delegate protocol
@protocol NetworkReachabilityDelegate <NSObject>
@optional
- (void)networkReachabilityDidChange:(NetworkStatus)status;
- (void)networkReachabilityDidChangeFromStatus:(NetworkStatus)oldStatus
                                      toStatus:(NetworkStatus)newStatus;
- (void)networkPathDidChange:(nw_path_t)path;
@end

@interface NetworkReachability : NSObject

// Singleton instance for app-wide monitoring
+ (instancetype)sharedInstance;

// Current network status
@property(nonatomic, readonly) NetworkStatus currentStatus;
@property(nonatomic, readonly) NetworkConnectionType availableConnectionTypes;

// Network path details
@property(nonatomic, readonly, nullable) nw_path_t currentPath;
@property(nonatomic, readonly) BOOL isExpensive;
@property(nonatomic, readonly) BOOL isConstrained;

// Delegate
@property(nonatomic, weak) id<NetworkReachabilityDelegate> delegate;

// Start/stop monitoring
- (void)startMonitoring;
- (void)stopMonitoring;
@property(nonatomic, readonly) BOOL isMonitoring;

// Check specific reachability
- (BOOL)isReachable;
- (BOOL)isReachableViaWiFi;
- (BOOL)isReachableViaCellular;
- (BOOL)isReachableViaWired;

// Check if specific host is reachable
- (void)checkReachabilityForHost:(NSString*)host
                            port:(nullable NSNumber*)port
                      completion:(void (^)(BOOL reachable, NetworkStatus status))completion;

// Get human-readable status string
- (NSString*)statusString;
+ (NSString*)stringForStatus:(NetworkStatus)status;

// Wait for connectivity (with timeout)
- (void)waitForConnectivityWithTimeout:(NSTimeInterval)timeout
                            completion:(void (^)(BOOL connected))completion;

@end

// Utility functions
NS_INLINE BOOL NetworkStatusIsReachable(NetworkStatus status) {
  return status != NetworkStatusUnknown && status != NetworkStatusNotReachable;
}

NS_INLINE BOOL NetworkStatusIsWiFi(NetworkStatus status) {
  return status == NetworkStatusReachableViaWiFi;
}

NS_INLINE BOOL NetworkStatusIsCellular(NetworkStatus status) {
  return status == NetworkStatusReachableViaCellular;
}

NS_ASSUME_NONNULL_END
