//
//  ProxyProvider+Private.h
//  DNShield Network Extension
//
//  Shared internal state for ProxyProvider categories
//

#import "Provider.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider ()

@property(nonatomic, strong) NSXPCListener* xpcListener;
@property(nonatomic, strong) DNSCache* dnsCache;
@property(nonatomic, strong) NSArray<NSString*>* dnsServers;
@property(nonatomic, strong) dispatch_queue_t dnsQueue;
@property(nonatomic, strong) WebSocketServer* wsServer;
@property(nonatomic, strong, nullable) NSDictionary* providerConfiguration;
@property(nonatomic, strong, nullable) dispatch_source_t webSocketRetryTimer;
@property(nonatomic, assign) NSTimeInterval webSocketRetryInterval;
@property(nonatomic, assign) NSUInteger webSocketRetryAttempt;
@property(nonatomic, assign) BOOL webSocketBackoffEnabled;

@property(nonatomic, assign) NSUInteger blockedCount;
@property(nonatomic, assign) NSUInteger allowedCount;
@property(nonatomic, strong) PreferenceManager* preferenceManager;

@property(nonatomic, strong) NSMapTable<NSData*, NSDictionary*>* queryToClientInfo;
@property(nonatomic, strong)
    NSMutableDictionary<NSString*, DNSUpstreamConnection*>* upstreamConnections;
@property(nonatomic, strong) NSMutableDictionary<NSData*, NSDate*>* queryTimestamps;
@property(nonatomic, strong, nullable) NSTimer* cleanupTimer;
@property(nonatomic, strong) NSMutableSet<NEAppProxyUDPFlow*>* activeFlows;
@property(nonatomic, strong) NSMapTable<NSData*, NEAppProxyTCPFlow*>* tcpFlows;
@property(nonatomic, strong) NSMutableSet<NEAppProxyUDPFlow*>* closedFlows;
@property(nonatomic, strong) NSMutableDictionary<NSValue*, NSNumber*>* flowEmptyReadCounts;

- (DNSUpstreamConnection*)getOrCreateUpstreamConnectionForServer:(NSString*)server;

@property(nonatomic, strong) RuleManager* ruleManager;
@property(nonatomic, strong) ConfigurationManager* configManager;
@property(nonatomic, strong) DNSCommandProcessor* commandProcessor;
@property(nonatomic, strong) RuleDatabase* ruleDatabase;
@property(nonatomic, strong) DNSRuleCache* ruleCache;
@property(nonatomic, strong) NSMutableArray<NSXPCConnection*>* activeXPCConnections;
@property(nonatomic, strong) DNSShieldTelemetry* telemetry;

@property(nonatomic, strong) NSMutableArray<NSDictionary*>* queuedQueries;
@property(nonatomic, assign) BOOL isInTransitionMode;
@property(nonatomic, strong) dispatch_queue_t transitionQueue;

@property(nonatomic, strong) DNSInterfaceManager* interfaceManager;
@property(nonatomic, strong) DNSRetryManager* retryManager;
@property(nonatomic, strong) DNSFlowTelemetry* flowTelemetry;
@property(nonatomic, strong) NetworkReachability* networkReachability;
@property(nonatomic, assign) BOOL isWaitingForConnectivity;

- (NSArray<NSString*>*)getSystemDNSServers;

@end

NS_ASSUME_NONNULL_END
