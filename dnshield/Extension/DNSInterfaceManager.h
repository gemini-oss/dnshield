//
//  DNSInterfaceManager.h
//  DNShield Network Extension
//
//  Manages interface binding for DNS queries to prevent VPN routing issues
//  Implements the DNS Interface Binding V1 feature
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

@class PreferenceManager;
@protocol DNSInterfaceManagerDelegate;

typedef NS_ENUM(NSInteger, DNSBindStrategy) {
  DNSBindStrategyResolverCIDR = 0,   // Bind based on resolver IP CIDR matching
  DNSBindStrategyOriginalPath = 1,   // Bind to the interface that received the query
  DNSBindStrategyActiveResolver = 2  // Bind to the system's active resolver interface
};

typedef NS_ENUM(NSInteger, DNSInterfaceType) {
  DNSInterfaceTypeUnknown = 0,
  DNSInterfaceTypeVPN = 1,       // utun*, ipsec*, ppp*
  DNSInterfaceTypeWiFi = 2,      // en0, en1
  DNSInterfaceTypeEthernet = 3,  // en* (wired)
  DNSInterfaceTypeCellular = 4   // pdp_ip*
};

@interface DNSInterfaceBinding : NSObject
@property(nonatomic, readonly) NSString* interfaceName;
@property(nonatomic, readonly) uint32_t interfaceIndex;
@property(nonatomic, readonly) DNSInterfaceType interfaceType;
@property(nonatomic, readonly) NSString* resolverEndpoint;
@property(nonatomic, readonly) NSDate* bindingTime;
@property(nonatomic, readonly) NSString* transactionID;
@end

@interface DNSInterfaceManager : NSObject

@property(nonatomic, weak, nullable) id<DNSInterfaceManagerDelegate> delegate;
@property(nonatomic, readonly) BOOL isEnabled;
@property(nonatomic, readonly) DNSBindStrategy bindStrategy;

- (instancetype)initWithPreferenceManager:(PreferenceManager*)preferenceManager;

// Interface binding decisions
- (nullable DNSInterfaceBinding*)bindingForResolver:(nw_endpoint_t)resolverEndpoint
                                       originalFlow:(NEAppProxyUDPFlow*)originalFlow
                                      transactionID:(NSString*)transactionID;

// VPN state detection
- (BOOL)isVPNActive;
- (BOOL)isResolverInVPNCIDR:(nw_endpoint_t)resolverEndpoint;
- (DNSInterfaceType)interfaceTypeForName:(NSString*)interfaceName;

// Transaction stickiness
- (void)setBinding:(DNSInterfaceBinding*)binding forTransactionID:(NSString*)transactionID;
- (nullable DNSInterfaceBinding*)existingBindingForTransactionID:(NSString*)transactionID;
- (void)clearBindingForTransactionID:(NSString*)transactionID;

// Path monitoring
- (void)startPathMonitoring;
- (void)stopPathMonitoring;

// Path validation
- (BOOL)validatePathToResolver:(nw_endpoint_t)resolverEndpoint
                  viaInterface:(NSString*)interfaceName;
- (nw_path_status_t)pathStatusForInterface:(NSString*)interfaceName;

// Configuration updates
- (void)reloadConfiguration;

@end

@protocol DNSInterfaceManagerDelegate <NSObject>
@optional
- (void)interfaceManager:(DNSInterfaceManager*)manager didDetectPathChange:(nw_path_t)path;
- (void)interfaceManager:(DNSInterfaceManager*)manager didUpdateVPNState:(BOOL)isActive;
@end

NS_ASSUME_NONNULL_END
