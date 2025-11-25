//
//  Defaults.h
//  DNShield
//

#import <Foundation/Foundation.h>

#ifndef Defaults_h
#define Defaults_h

// Default TTL for DNS responses (5 minutes)
#define DEFAULT_TTL 300

extern NSString* const kDefaultName;
extern NSString* const kDefaultDBPath;
extern NSString* const kDefaultBundlePrefix;
extern NSString* const kDefaultDomainName;
extern NSString* const kDefaultAppBundleID;
extern NSString* const kDefaultExtensionBundleID;
extern NSString* const kDNShieldDaemonBundleID;
extern NSString* const kDNShieldPreferenceDomain;
extern NSString* const kDNShieldAppGroup;
extern NSString* const kDefaultLogFilePath;
extern NSString* const kDNShieldLogDirectory;
extern NSString* const kDefaultXPCServiceName;
extern NSString* const kDefaultConfigDirPath;
extern NSString* const kDefaultLockFilePath;
extern NSString* const kDNShieldApplicationBundlePath;
extern NSString* const kDNShieldApplicationBinaryDirectory;
extern NSString* const kDNShieldDaemonBinaryPath;
extern NSString* const kDNShieldXPCBinaryPath;
extern NSString* const kDNShieldDaemonPlistPath;
extern NSString* const kDNShieldWebSocketRetryIntervalKey;
extern NSTimeInterval const kDNShieldDefaultWebSocketRetryInterval;
extern NSString* const kDNShieldTeamIdentifier;

#endif /* Defaults_h */
