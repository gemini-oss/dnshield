//
//  DNSWildcardConfig.m
//  DNShield Network Extension
//
//  Configuration for wildcard domain matching behavior implementation
//

#import "DNSWildcardConfig.h"
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <os/log.h>

static os_log_t logHandle;

@interface DNSWildcardConfig ()
@property(nonatomic, readwrite) DNSWildcardMode mode;
@property(nonatomic, readwrite) BOOL respectAllowlistPrecedence;
@end

@implementation DNSWildcardConfig

+ (void)initialize {
  if (self == [DNSWildcardConfig class]) {
    logHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"WildcardConfig");
  }
}

+ (instancetype)sharedConfig {
  static DNSWildcardConfig* sharedConfig = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedConfig = [[DNSWildcardConfig alloc] init];
    [sharedConfig loadConfiguration];
  });
  return sharedConfig;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    // Default values
    _mode = DNSWildcardModeSubdomainsOnly;  // Default to traditional behavior for backward
                                            // compatibility
    _respectAllowlistPrecedence = YES;
  }
  return self;
}

- (void)setMode:(DNSWildcardMode)mode {
  _mode = mode;
  os_log_info(logHandle, "Wildcard mode set to: %ld", (long)mode);
}

- (void)setRespectAllowlistPrecedence:(BOOL)respect {
  _respectAllowlistPrecedence = respect;
  os_log_info(logHandle, "Respect allowlist precedence: %@", respect ? @"YES" : @"NO");
}

- (BOOL)wildcardShouldMatchRoot:(NSString*)wildcardDomain {
  // If not a wildcard domain, return NO
  if (![wildcardDomain hasPrefix:@"*."]) {
    return NO;
  }

  switch (self.mode) {
    case DNSWildcardModeSubdomainsOnly:
      // Traditional behavior - wildcards don't match root
      return NO;

    case DNSWildcardModeIncludeRoot:
      // Enhanced security - wildcards always match root
      return YES;

    case DNSWildcardModeSmart:
      // Smart mode - check if root is explicitly allowed
      // This would require checking the allowlist database
      // For now, default to including root for security
      return YES;
  }
}

- (void)loadConfiguration {
  NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:kDNShieldPreferenceDomain];

  // Load wildcard mode
  if ([defaults objectForKey:@"WildcardMode"]) {
    self.mode = [defaults integerForKey:@"WildcardMode"];
  }

  // Load allowlist precedence setting
  if ([defaults objectForKey:@"RespectAllowlistPrecedence"]) {
    self.respectAllowlistPrecedence = [defaults boolForKey:@"RespectAllowlistPrecedence"];
  }

  os_log_info(logHandle, "Loaded configuration - Mode: %ld, Respect Allowlist: %@", (long)self.mode,
              self.respectAllowlistPrecedence ? @"YES" : @"NO");
}

- (void)saveConfiguration {
  NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:kDNShieldPreferenceDomain];

  [defaults setInteger:self.mode forKey:@"WildcardMode"];
  [defaults setBool:self.respectAllowlistPrecedence forKey:@"RespectAllowlistPrecedence"];
  [defaults synchronize];

  os_log_info(logHandle, "Saved configuration - Mode: %ld, Respect Allowlist: %@", (long)self.mode,
              self.respectAllowlistPrecedence ? @"YES" : @"NO");
}

@end
