//
//  Defaults.m
//  DNShield
//

#import <Foundation/Foundation.h>

#import "Defaults.h"

// Defaults for names, bundles, and various others.
// Note:
//  These are the values you would change if you wanted to customize the app.
NSString* const kDefaultName = @"DNShield";
NSString* const kDefaultBundlePrefix = @"com.gemini";
NSString* const kDefaultDomainName = @"dnshield";
NSString* const kDefaultAppBundleID = @"com.dnshield.app";
NSString* const kDefaultExtensionBundleID = @"com.dnshield.extension";
NSString* const kDNShieldDaemonBundleID = @"com.dnshield.daemon";
NSString* const kDNShieldPreferenceDomain = @"com.dnshield.app";  // Main preference domain
NSString* const kDNShieldAppGroup = @"group.C6F9Y6M584.com.gemini.dnshield";  // App Group
NSString* const kDefaultLogFilePath = @"/Library/Logs/DNShield/extension.log";
NSString* const kDNShieldLogDirectory = @"/Library/Logs/DNShield";
NSString* const kDefaultDBPath = @"/var/db/dnshield";
NSString* const kDefaultXPCServiceName = @"com.dnshield.daemon.xpc";
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
NSString* const kDNShieldTeamIdentifier = @"C6F9Y6M584";
