//
//  Defaults.m
//  DNShield
//

#import <Foundation/Foundation.h>

#import "DNIdentity.h"
#import "Defaults.h"

// Defaults for names, bundles, and various others.
// Note:
//  These are the values you would change if you wanted to customize the app.
NSString* const kDefaultName = DN_IDENTITY_DISPLAY_NAME;
NSString* const kDefaultBundlePrefix = DN_IDENTITY_BUNDLE_PREFIX;
NSString* const kDefaultDomainName = DN_IDENTITY_DOMAIN_NAME;
NSString* const kDefaultAppBundleID = DN_IDENTITY_APP_BUNDLE_ID;
NSString* const kDefaultExtensionBundleID = DN_IDENTITY_EXTENSION_BUNDLE_ID;
NSString* const kDNShieldDaemonBundleID = DN_IDENTITY_DAEMON_BUNDLE_ID;
NSString* const kDNShieldPreferenceDomain =
    DN_IDENTITY_PREFERENCE_DOMAIN;                          // Main preference domain
NSString* const kDNShieldAppGroup = DN_IDENTITY_APP_GROUP;  // App Group
NSString* const kDefaultLogFilePath = @"/Library/Logs/DNShield/extension.log";
NSString* const kDNShieldLogDirectory = @"/Library/Logs/DNShield";
NSString* const kDefaultDBPath = @"/var/db/dnshield";
NSString* const kDefaultXPCServiceName = DN_IDENTITY_MACH_SERVICE;
NSString* const kDefaultConfigDirPath = @"/Library/Application Support/DNShield";
NSString* const kDefaultLockFilePath = @"/var/run/dnshield.pid";
NSString* const kDNShieldApplicationBundlePath = @"/Applications/DNShield.app";
NSString* const kDNShieldApplicationBinaryDirectory = @"/Applications/DNShield.app/Contents/MacOS";
NSString* const kDNShieldDaemonBinaryPath =
    @"/Applications/DNShield.app/Contents/MacOS/dnshield-daemon";
NSString* const kDNShieldXPCBinaryPath = @"/Applications/DNShield.app/Contents/MacOS/dnshield-xpc";
NSString* const kDNShieldDaemonPlistPath = @"/Library/LaunchDaemons/com.dnshield.daemon.plist";
NSString* const kDNShieldWebSocketRetryIntervalKey = @"WebSocketRetryInterval";
NSTimeInterval const kDNShieldDefaultWebSocketRetryInterval = 10.0;
NSString* const kDNShieldTeamIdentifier = DN_IDENTITY_TEAM_IDENTIFIER;
