#import "DNCTLCommands.h"

#import "Common/Defaults.h"
#import "DNCTLCommon.h"

static NSString* DNCTLPreferencePath(NSString* base, BOOL appendPlist) {
  if (appendPlist) {
    return [[base stringByAppendingPathComponent:kDNShieldPreferenceDomain]
        stringByAppendingPathExtension:@"plist"];
  }
  return [base stringByAppendingPathComponent:kDNShieldPreferenceDomain];
}

static void ReportDaemonStatus(void) {
  NSNumber* pidNumber = DNCTLReadPID();
  if (pidNumber && DNCTLProcessExists(pidNumber.intValue)) {
    DNCTLLogInfo([NSString stringWithFormat:@"Process: Running (PID: %d)", pidNumber.intValue]);
  } else {
    DNCTLLogError(@"Process: Not running");
  }
}

static void ReportLaunchDaemon(void) {
  CommandResult* result = DNCTLRunEnvCommand(@"launchctl", @[ @"list" ]);
  if (result.status == 0 && [result.stdoutString containsString:kDNShieldDaemonBundleID]) {
    DNCTLLogInfo(@"LaunchDaemon: Loaded");
  } else {
    DNCTLLogError(@"LaunchDaemon: Not loaded");
  }
}

static void ReportSystemExtension(void) {
  CommandResult* result = DNCTLRunEnvCommand(@"systemextensionsctl", @[ @"list" ]);
  if (result.status == 0 && [result.stdoutString containsString:kDefaultExtensionBundleID]) {
    DNCTLLogInfo(@"System Extension: Installed");
  } else {
    DNCTLLogWarning(@"System Extension: Not installed");
  }
}

static void ReportConfigSource(NSString* label, NSString* path) {
  if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
    DNCTLLogInfo([NSString stringWithFormat:@"%@: Found", label]);
  } else {
    printf("  %s: Not configured\n", label.UTF8String);
  }
}

static void ReportConfigurationHierarchy(void) {
  ReportConfigSource(@"1. MDM/Configuration Profile",
                     DNCTLPreferencePath(@"/Library/Managed Preferences", NO));
  ReportConfigSource(@"2. Root Preferences",
                     DNCTLPreferencePath(@"/var/root/Library/Preferences", YES));
  ReportConfigSource(@"3. System Preferences", DNCTLPreferencePath(@"/Library/Preferences", YES));
  NSString* userPath = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences"]
      stringByAppendingPathComponent:[NSString
                                         stringWithFormat:@"%@.plist", kDNShieldPreferenceDomain]];
  ReportConfigSource(@"4. User Preferences", userPath);
}

static void ReportEffectiveConfiguration(void) {
  NSArray<NSString*>* candidates = @[
    DNCTLPreferencePath(@"/Library/Managed Preferences", NO),
    DNCTLPreferencePath(@"/var/root/Library/Preferences", YES),
    DNCTLPreferencePath(@"/Library/Preferences", YES), kDNShieldPreferenceDomain
  ];
  for (NSString* path in candidates) {
    CommandResult* result = DNCTLRunEnvCommand(@"defaults", @[ @"read", path, @"ManifestURL" ]);
    if (result.status == 0 && result.stdoutString.length) {
      printf("  Manifest URL: %s\n", result.stdoutString.UTF8String);
      return;
    }
  }
  printf("  Manifest URL: Not configured\n");
}

static void ReportRuleDatabase(void) {
  NSString* dbPath = @"/var/db/dnshield/rules.db";
  if (![[NSFileManager defaultManager] fileExistsAtPath:dbPath])
    return;

  NSString* sqlite = DNCTLFindExecutable(@"sqlite3");
  if (![[NSFileManager defaultManager] isExecutableFileAtPath:sqlite])
    return;

  printf("Rule Database:\n");
  CommandResult* total =
      DNCTLRunEnvCommand(sqlite, @[ dbPath, @"SELECT COUNT(*) FROM dns_rules;" ]);
  CommandResult* blocked =
      DNCTLRunEnvCommand(sqlite, @[ dbPath, @"SELECT COUNT(*) FROM dns_rules WHERE action = 0;" ]);
  CommandResult* allowed =
      DNCTLRunEnvCommand(sqlite, @[ dbPath, @"SELECT COUNT(*) FROM dns_rules WHERE action = 1;" ]);
  CommandResult* size = DNCTLRunEnvCommand(@"du", @[ @"-h", dbPath ]);

  if (total.status == 0)
    printf("  Total Rules: %s\n", total.stdoutString.UTF8String);
  if (blocked.status == 0)
    printf("  Blocked Domains: %s\n", blocked.stdoutString.UTF8String);
  if (allowed.status == 0)
    printf("  Allowed Domains: %s\n", allowed.stdoutString.UTF8String);
  if (size.status == 0) {
    NSString* human = [[size.stdoutString componentsSeparatedByString:@"\t"] firstObject] ?: @"";
    printf("  Database Size: %s\n", human.UTF8String);
  }
}

void DNCTLCommandStatus(void) {
  if (DNCTLGetOutputFormat() == DNOutputFormatText) {
    printf("%sDNShield Status%s\n", DNCTLColorBlue.UTF8String, DNCTLColorReset.UTF8String);
    ReportDaemonStatus();
    ReportLaunchDaemon();
    ReportSystemExtension();
    printf("\nConfiguration Sources (priority order):\n");
    ReportConfigurationHierarchy();
    printf("\nEffective Configuration:\n");
    ReportEffectiveConfiguration();
    printf("\n");
    ReportRuleDatabase();
    return;
  }

  NSMutableDictionary* status = [NSMutableDictionary dictionary];
  NSNumber* pidNumber = DNCTLReadPID();
  BOOL running = (pidNumber && DNCTLProcessExists(pidNumber.intValue));

  status[@"daemon"] = @{@"running" : @(running), @"pid" : running ? pidNumber : (id)[NSNull null]};

  CommandResult* ld = DNCTLRunEnvCommand(@"launchctl", @[ @"list" ]);
  BOOL loaded = (ld.status == 0 && [ld.stdoutString containsString:kDNShieldDaemonBundleID]);
  status[@"launchDaemon"] = @{@"loaded" : @(loaded)};

  CommandResult* se = DNCTLRunEnvCommand(@"systemextensionsctl", @[ @"list" ]);
  BOOL installed = (se.status == 0 && [se.stdoutString containsString:kDefaultExtensionBundleID]);
  status[@"systemExtension"] = @{@"installed" : @(installed)};

  NSMutableDictionary* sources = [NSMutableDictionary dictionary];
  NSFileManager* fm = [NSFileManager defaultManager];
  sources[@"mdm"] =
      @([fm fileExistsAtPath:DNCTLPreferencePath(@"/Library/Managed Preferences", YES)] ||
        [fm fileExistsAtPath:DNCTLPreferencePath(@"/Library/Managed Preferences", NO)]);
  sources[@"root"] =
      @([fm fileExistsAtPath:DNCTLPreferencePath(@"/var/root/Library/Preferences", YES)]);
  sources[@"system"] = @([fm fileExistsAtPath:DNCTLPreferencePath(@"/Library/Preferences", YES)]);
  NSString* userPlistPath =
      [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences"]
          stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.plist",
                                                                    kDNShieldPreferenceDomain]];
  sources[@"user"] = @([fm fileExistsAtPath:userPlistPath]);
  status[@"configurationSources"] = sources;

  __block NSString* manifestURL = nil;
  NSArray<NSString*>* candidates = @[
    DNCTLPreferencePath(@"/Library/Managed Preferences", NO),
    DNCTLPreferencePath(@"/var/root/Library/Preferences", YES),
    DNCTLPreferencePath(@"/Library/Preferences", YES), kDNShieldPreferenceDomain
  ];
  for (NSString* path in candidates) {
    CommandResult* r = DNCTLRunEnvCommand(@"defaults", @[ @"read", path, @"ManifestURL" ]);
    if (r.status == 0 && r.stdoutString.length) {
      manifestURL = r.stdoutString;
      break;
    }
  }
  status[@"effectiveConfiguration"] = @{@"ManifestURL" : manifestURL ?: (id)[NSNull null]};

  NSString* dbPath = @"/var/db/dnshield/rules.db";
  NSMutableDictionary* dbInfo = [NSMutableDictionary dictionary];
  if ([fm fileExistsAtPath:dbPath]) {
    NSString* sqlite = DNCTLFindExecutable(@"sqlite3");
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:sqlite]) {
      CommandResult* total =
          DNCTLRunEnvCommand(sqlite, @[ dbPath, @"SELECT COUNT(*) FROM dns_rules;" ]);
      CommandResult* blocked = DNCTLRunEnvCommand(
          sqlite, @[ dbPath, @"SELECT COUNT(*) FROM dns_rules WHERE action = 0;" ]);
      CommandResult* allowed = DNCTLRunEnvCommand(
          sqlite, @[ dbPath, @"SELECT COUNT(*) FROM dns_rules WHERE action = 1;" ]);
      dbInfo[@"total"] = @(DNCTLTrimmedString(total.stdoutString).longLongValue);
      dbInfo[@"blocked"] = @(DNCTLTrimmedString(blocked.stdoutString).longLongValue);
      dbInfo[@"allowed"] = @(DNCTLTrimmedString(allowed.stdoutString).longLongValue);
    }
    NSDictionary* attrs = [fm attributesOfItemAtPath:dbPath error:nil];
    if (attrs)
      dbInfo[@"sizeBytes"] = @([attrs fileSize]);
    dbInfo[@"path"] = dbPath;
  }
  status[@"ruleDatabase"] = dbInfo;

  BOOL isDir = NO;
  NSMutableDictionary* logdir = [NSMutableDictionary dictionary];
  logdir[@"path"] = kDNShieldLogDirectory;
  if ([fm fileExistsAtPath:kDNShieldLogDirectory isDirectory:&isDir] && isDir) {
    logdir[@"exists"] = @YES;
    NSMutableDictionary* files = [NSMutableDictionary dictionary];
    for (NSString* file in @[ @"daemon.stdout.log", @"daemon.stderr.log" ]) {
      NSString* fp = [kDNShieldLogDirectory stringByAppendingPathComponent:file];
      NSDictionary* attr = [fm attributesOfItemAtPath:fp error:nil];
      if (attr)
        files[file] = @{@"sizeBytes" : @([attr fileSize])};
    }
    logdir[@"files"] = files;
  } else {
    logdir[@"exists"] = @NO;
  }
  status[@"logDirectory"] = logdir;

  DNCTLPrintObject(status, DNCTLGetOutputFormat());
}
