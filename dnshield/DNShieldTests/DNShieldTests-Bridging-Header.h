//
//  DNShieldTests-Bridging-Header.h
//  DNShield Tests
//
//  Bridging header for test imports
//

#ifndef DNShieldTests_Bridging_Header_h
#define DNShieldTests_Bridging_Header_h

// Extension headers
#import "../Extension/BaseFetcher.h"
#import "../Extension/ConfigurationManager.h"
#import "../Extension/DNSManifest.h"
#import "../Extension/DNSManifestParser.h"
#import "../Extension/DNSManifestResolver.h"
#import "../Extension/HTTPRuleFetcher.h"
#import "../Extension/PlistRuleParser.h"
#import "../Extension/PreferenceManager.h"
#import "../Extension/ProxyProvider/Provider.h"
#import "../Extension/Rule/Manager+Manifest.h"
#import "../Extension/Rule/Manager.h"
#import "../Extension/Rule/RuleDatabase.h"
#import "../Extension/Rule/RuleSet.h"

// Common headers
#import "../Common/DNShieldPreferences.h"
#import "../Common/Defaults.h"
#import "../Common/LoggingManager.h"

// App headers if needed
#import "../App/AppDelegate.h"

#endif /* DNShieldTests_Bridging_Header_h */
