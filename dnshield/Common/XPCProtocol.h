//
//  XPCProtocol.h
//  DNShield
//
//  XPC Protocol definitions for communication between app and extension
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Protocol for extension to call app
@protocol XPCAppProtocol <NSObject>

// Report statistics
- (void)updateStatistics:(NSDictionary*)stats;

// Report errors
- (void)reportError:(NSString*)error;

// Request configuration update
- (void)requestConfigurationUpdate;

// Bypass notifications
- (void)notifyBypassStateChanged:(BOOL)isActive;
- (void)notifyBypassSecurityAlert:(NSString*)alert;

// Rule update notifications
- (void)notifyRulesUpdated:(NSDictionary*)ruleInfo;
- (void)notifyRuleUpdateFailed:(NSError*)error;

@end

// Protocol for app to call extension
@protocol XPCExtensionProtocol <NSObject>

// Update blocked domains
- (void)updateBlockedDomains:(NSArray<NSString*>*)domains
           completionHandler:(void (^)(BOOL success))completion;

// Update DNS servers
- (void)updateDNSServers:(NSArray<NSString*>*)servers
       completionHandler:(void (^)(BOOL success))completion;

// Get current statistics
- (void)getStatisticsWithCompletionHandler:(void (^)(NSDictionary* _Nullable stats))completion;

// Clear DNS cache
- (void)clearCacheWithCompletionHandler:(void (^)(BOOL success))completion;

// Update configuration
- (void)updateConfiguration:(NSDictionary*)config
          completionHandler:(void (^)(BOOL success))completion;

// MARK: - Rule Management

// Get managed blocked domains
- (void)getManagedBlockedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion;

// Get managed allowed domains
- (void)getManagedAllowedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion;

// Get user blocked domains
- (void)getUserBlockedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion;

// Get user allowed domains
- (void)getUserAllowedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains))completion;

// Get full rule metadata
- (void)getAllRulesWithCompletionHandler:(void (^)(NSArray* _Nullable rules))completion;

// Add user blocked domain
- (void)addUserBlockedDomain:(NSString*)domain completionHandler:(void (^)(BOOL success))completion;

// Remove user blocked domain
- (void)removeUserBlockedDomain:(NSString*)domain
              completionHandler:(void (^)(BOOL success))completion;

// Add user allowed domain
- (void)addUserAllowedDomain:(NSString*)domain completionHandler:(void (^)(BOOL success))completion;

// Remove user allowed domain
- (void)removeUserAllowedDomain:(NSString*)domain
              completionHandler:(void (^)(BOOL success))completion;

// Get rule sources
- (void)getRuleSourcesWithCompletionHandler:(void (^)(NSArray* _Nullable sources))completion;

// Get configuration info
- (void)getConfigurationInfoWithCompletionHandler:
    (void (^)(NSDictionary* _Nullable configInfo))completion;

// Get sync status and resolver info for troubleshooting
- (void)getSyncStatusWithCompletionHandler:(void (^)(NSDictionary* _Nullable syncInfo))completion;

@end

// Notification names
extern NSString* const XPCBypassStateDidChangeNotification;
extern NSString* const XPCBypassSecurityAlertNotification;
extern NSString* const XPCRulesDidUpdateNotification;

NS_ASSUME_NONNULL_END
