#import "DNCTLCommands.h"

#import "Common/Defaults.h"
#import "DNCTLCommon.h"

static NSDictionary* ExportedDefaultsAt(NSString* domainOrPath) {
  CommandResult* result = DNCTLRunEnvCommand(@"defaults", @[ @"export", domainOrPath, @"-" ]);
  if (result.status != 0 || result.stdoutString.length == 0)
    return nil;
  NSData* data = [result.stdoutString dataUsingEncoding:NSUTF8StringEncoding];
  if (!data)
    return nil;
  NSError* err = nil;
  id obj =
      [NSPropertyListSerialization propertyListWithData:data
                                                options:NSPropertyListMutableContainersAndLeaves
                                                 format:NULL
                                                  error:&err];
  if (err || ![obj isKindOfClass:[NSDictionary class]])
    return nil;
  return obj;
}

static NSDictionary* ReadPreferencesFromCandidates(NSArray<NSString*>* candidates) {
  for (NSString* candidate in candidates) {
    NSDictionary* prefs = ExportedDefaultsAt(candidate);
    if (prefs.count > 0)
      return prefs;
  }
  return nil;
}

static id TryDecodeConfigurationData(NSData* data) {
  if (!data)
    return nil;
  NSError* err = nil;
  id plist =
      [NSPropertyListSerialization propertyListWithData:data
                                                options:NSPropertyListMutableContainersAndLeaves
                                                 format:NULL
                                                  error:&err];
  if (plist && !err)
    return plist;
  NSSet* classes = [NSSet setWithArray:@[
    [NSDictionary class], [NSArray class], [NSString class], [NSNumber class], [NSData class],
    [NSDate class]
  ]];
  err = nil;
  id unarch = [NSKeyedUnarchiver unarchivedObjectOfClasses:classes fromData:data error:&err];
  if (unarch && !err)
    return unarch;
  return nil;
}

static NSDictionary* MakePreferencesReadable(NSDictionary* prefs) {
  if (!prefs)
    return nil;
  NSMutableDictionary* mutable = [prefs mutableCopy];
  id cfg = mutable[@"Configuration"];
  if ([cfg isKindOfClass:[NSData class]]) {
    id decoded = TryDecodeConfigurationData((NSData*)cfg);
    if (decoded)
      mutable[@"Configuration"] = decoded;
  }
  return mutable;
}

void DNCTLCommandConfig(NSArray<NSString*>* args) {
  if (args.count > 0 && [args.firstObject isEqualToString:@"set"]) {
    DNCTLEnsureRoot();
    if (args.count < 3) {
      DNCTLLogError(@"Usage: dnshield-ctl config set <key> <value>");
      exit(EXIT_FAILURE);
    }
    NSString* key = args[1];
    NSString* value = args[2];
    DNCTLLogInfo([NSString
        stringWithFormat:@"Setting %@ = %@ in %@", key, value, kDNShieldPreferenceDomain]);
    NSString* systemDomain =
        [@"/Library/Preferences/" stringByAppendingString:kDNShieldPreferenceDomain];
    CommandResult* write = DNCTLRunEnvCommand(@"defaults", @[ @"write", systemDomain, key, value ]);
    if (write.status != 0) {
      DNCTLLogError(write.stderrString ?: @"Failed to set preference");
      exit(EXIT_FAILURE);
    }
    (void)DNCTLRunEnvCommand(@"defaults",
                             @[ @"write", systemDomain, @"ManagedMode", @"-bool", @"YES" ]);
    DNCTLLogSuccess(@"Configuration updated. Restart daemon to apply changes.");
    return;
  }

  DNOutputFormat fmt = DNCTLGetOutputFormat();
  NSArray<NSString*>* remaining = args;
  if (DNCTLParseFormatFromArgs(args, &fmt, (NSArray<NSString*>**)&remaining)) {
    DNCTLSetOutputFormat(fmt);
  }

  NSDictionary* mdmPrefs = ReadPreferencesFromCandidates(@[
    [@"/Library/Managed Preferences/" stringByAppendingString:kDNShieldPreferenceDomain],
    [NSString stringWithFormat:@"/Library/Managed Preferences/%@.plist", kDNShieldPreferenceDomain]
  ]);

  NSDictionary* systemPrefs = ReadPreferencesFromCandidates(@[
    [@"/Library/Preferences/" stringByAppendingString:kDNShieldPreferenceDomain],
    [NSString stringWithFormat:@"/Library/Preferences/%@.plist", kDNShieldPreferenceDomain]
  ]);

  NSString* userPlist = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences"]
      stringByAppendingPathComponent:[NSString
                                         stringWithFormat:@"%@.plist", kDNShieldPreferenceDomain]];
  NSDictionary* userPrefs =
      ReadPreferencesFromCandidates(@[ kDNShieldPreferenceDomain, userPlist ]);
  userPrefs = MakePreferencesReadable(userPrefs);

  if (DNCTLGetOutputFormat() == DNOutputFormatText) {
    printf("%sCurrent Configuration:%s\n", DNCTLColorBlue.UTF8String, DNCTLColorReset.UTF8String);

    printf("MDM/Forced Preferences:\n");
    if (mdmPrefs.count) {
      NSString* s = DNCTLPlistStringFromObject(mdmPrefs);
      printf("%s\n", (s ?: @"").UTF8String);
    } else {
      printf("  None\n");
    }

    printf("\nSystem Preferences:\n");
    if (systemPrefs.count) {
      NSString* s = DNCTLPlistStringFromObject(systemPrefs);
      printf("%s\n", (s ?: @"").UTF8String);
    } else {
      printf("  Not configured\n");
    }

    printf("\nUser Preferences:\n");
    if (userPrefs.count) {
      NSString* s = DNCTLPlistStringFromObject(userPrefs);
      printf("%s\n", (s ?: @"").UTF8String);
    } else {
      printf("  Not configured\n");
    }
  } else {
    NSDictionary* payload = @{
      @"mdm" : mdmPrefs ?: @{},
      @"system" : systemPrefs ?: @{},
      @"user" : userPrefs ?: @{},
    };
    DNCTLPrintObject(payload, DNCTLGetOutputFormat());
  }
}
