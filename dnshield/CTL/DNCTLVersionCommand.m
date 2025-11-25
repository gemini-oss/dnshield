#import "DNCTLCommands.h"

#import "Common/Defaults.h"
#import "DNCTLCommon.h"

static NSString* ReadAppBundleVersion(void) {
  NSString* path =
      [kDNShieldApplicationBundlePath stringByAppendingPathComponent:@"Contents/Info.plist"];
  NSDictionary* info = [NSDictionary dictionaryWithContentsOfFile:path];
  NSString* ver = info[@"CFBundleVersion"] ?: info[@"CFBundleShortVersionString"];
  return ver ?: @"unknown";
}

static NSString* ReadDaemonVersion(void) {
  NSArray<NSString*>* candidates =
      @[ @"/usr/local/bin/dnshield-daemon", kDNShieldDaemonBinaryPath ];
  for (NSString* path in candidates) {
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:path]) {
      CommandResult* r = DNCTLRunEnvCommand(path, @[ @"--version" ]);
      if (r.status == 0 && r.stdoutString.length) {
        NSArray<NSString*>* lines = [r.stdoutString
            componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        for (NSString* ln in lines) {
          NSString* t = DNCTLTrimmedString(ln);
          if (t.length)
            return t;
        }
      }
    }
  }
  return @"unknown";
}

static NSDictionary* ReadSystemExtensionInfo(void) {
  CommandResult* r = DNCTLRunEnvCommand(@"systemextensionsctl", @[ @"list" ]);
  if (r.status != 0)
    return @{};
  __block NSString* version = nil;
  __block NSString* state = nil;
  NSArray<NSString*>* lines =
      [r.stdoutString componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

  NSRegularExpression* re =
      [NSRegularExpression regularExpressionWithPattern:@"\\(([^/]+)/([^\\)]+)\\).*\\[([^\\]]+)\\]"
                                                options:0
                                                  error:nil];

  for (NSString* line in lines) {
    if ([line containsString:kDefaultExtensionBundleID] &&
        ([line hasPrefix:@"*"] || [line containsString:@"activated"] ||
         [line containsString:@"enabled"])) {
      NSTextCheckingResult* m = [re firstMatchInString:line
                                               options:0
                                                 range:NSMakeRange(0, line.length)];
      if (m && m.numberOfRanges >= 4) {
        NSString* full = [line substringWithRange:[m rangeAtIndex:2]];
        version = DNCTLTrimmedString(full);
        state = DNCTLTrimmedString([line substringWithRange:[m rangeAtIndex:3]]);
        break;
      }
    }
  }

  if (!version) {
    for (NSString* line in lines) {
      if ([line containsString:kDefaultExtensionBundleID]) {
        NSTextCheckingResult* m = [re firstMatchInString:line
                                                 options:0
                                                   range:NSMakeRange(0, line.length)];
        if (m && m.numberOfRanges >= 4) {
          NSString* full = [line substringWithRange:[m rangeAtIndex:2]];
          version = DNCTLTrimmedString(full);
          state = DNCTLTrimmedString([line substringWithRange:[m rangeAtIndex:3]]);
          break;
        }
      }
    }
  }

  NSMutableDictionary* info = [NSMutableDictionary dictionary];
  if (version)
    info[@"version"] = version;
  if (state)
    info[@"state"] = state;
  info[@"installed"] = @(version != nil);
  return info;
}

void DNCTLCommandVersion(void) {
  NSString* appVersion = ReadAppBundleVersion();
  NSString* daemonVersion = ReadDaemonVersion();
  NSDictionary* seInfo = ReadSystemExtensionInfo();

  NSDictionary* payload = @{
    @"app" : appVersion ?: @"unknown",
    @"daemon" : daemonVersion ?: @"unknown",
    @"systemExtension" : seInfo ?: @{}
  };

  if (DNCTLGetOutputFormat() == DNOutputFormatText) {
    printf("DNShield Versions\n");
    printf("App: %s\n", [appVersion ?: @"unknown" UTF8String]);
    printf("System Extension: %s", [([seInfo objectForKey:@"version"] ?: @"unknown") UTF8String]);
    if (seInfo[@"state"])
      printf("  [%s]", [seInfo[@"state"] UTF8String]);
    printf("\n");
    printf("Daemon: %s\n", [daemonVersion ?: @"unknown" UTF8String]);
  } else {
    DNCTLPrintObject(payload, DNCTLGetOutputFormat());
  }
}
