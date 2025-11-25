//
//  main.m
//  Network Extension Status Inspector
//
//  Ported from Swift version by erikng
//  Original: https://github.com/erikng/gnes
//

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

// Forward declarations for private NetworkExtension classes
@class NEConfiguration;
@class NEContentFilter;
@class NEDNSProxy;
@class NEVPN;
@class NEProvider;
@class NEPayloadInfo;
@class NEVPNProtocol;

// Function pointer types
typedef id (*NEConfigurationManagerSharedManagerFunc)(Class, SEL);
typedef void (*NEConfigurationManagerLoadConfigsFunc)(id, SEL, dispatch_queue_t,
                                                      void (^)(NSArray*, NSError*));

// Private interface declarations
@interface NEConfigurationManager : NSObject
@end

@interface NEConfiguration : NSObject
@property(readonly) NSString* identifier;
@property(readonly) NSString* name;
@property(readonly) NSString* application;
@property(readonly) NSString* applicationName;
@property(readonly) NSInteger grade;
@property(readonly) NEContentFilter* contentFilter;
@property(readonly) NEDNSProxy* dnsProxy;
@property(readonly) NEVPN* VPN;
@property(readonly) NEPayloadInfo* payloadInfo;
@end

@interface NEContentFilter : NSObject
@property(readonly) BOOL enabled;
@property(readonly) NSInteger grade;
@property(readonly) NEProvider* provider;
@end

@interface NEDNSProxy : NSObject
@property(readonly) BOOL enabled;
@property(readonly) NEVPNProtocol* protocol;
@end

@interface NEVPN : NSObject
@property(readonly) BOOL enabled;
@property(readonly) BOOL onDemandEnabled;
@property(readonly) NEVPNProtocol* protocol;
@end

@interface NEProvider : NSObject
@property(readonly) NSString* pluginType;
@property(readonly) NSString* dataProviderBundleIdentifier;
@property(readonly) NSString* dataProviderDesignatedRequirement;
@property(readonly) NSString* packetProviderBundleIdentifier;
@property(readonly) NSString* organization;
@property(readonly) BOOL filterPackets;
@property(readonly) BOOL filterSockets;
@property(readonly) BOOL preserveExistingConnections;
@end

@interface NEVPNProtocol : NSObject
@property(readonly) NSString* serverAddress;
@property(readonly) NSString* providerBundleIdentifier;
@property(readonly) NSString* designatedRequirement;
@property(readonly) NSString* pluginType;
@end

@interface NEPayloadInfo : NSObject
@property(readonly) NSString* payloadUUID;
@property(readonly) NSString* payloadOrganization;
@property(readonly) NSString* profileUUID;
@property(readonly) NSString* profileIdentifier;
@property(readonly) NSString* profileSource;
@property(readonly) BOOL isSetAside;
@property(readonly) NSDate* profileIngestionDate;
@property(readonly) NSString* systemVersion;
@end

// Formatter class
@interface NESIFormatter : NSObject
+ (void)printConfiguration:(NEConfiguration*)config
                    asJSON:(BOOL)json
                     asXML:(BOOL)xml
                     asRaw:(BOOL)raw;
+ (void)printAllConfigurations:(NSArray<NEConfiguration*>*)configs
                        asJSON:(BOOL)json
                         asXML:(BOOL)xml
                         asRaw:(BOOL)raw;
+ (void)printIdentifiersFromConfigurations:(NSArray<NEConfiguration*>*)configs
                                    asJSON:(BOOL)json
                                     asXML:(BOOL)xml
                                     asRaw:(BOOL)raw;
+ (NSDictionary*)configurationToDictionary:(NEConfiguration*)config;
+ (NSString*)extensionTypeFromConfig:(NEConfiguration*)config;
+ (id)safeValueForKey:(NSString*)key fromObject:(id)object;
@end

@implementation NESIFormatter

+ (NSString*)extensionTypeFromConfig:(NEConfiguration*)config {
  id contentFilter = [self safeValueForKey:@"contentFilter" fromObject:config];
  id dnsProxy = [self safeValueForKey:@"dnsProxy" fromObject:config];
  id vpn = [self safeValueForKey:@"VPN" fromObject:config];

  if (contentFilter) {
    return @"contentFilter";
  } else if (dnsProxy) {
    return @"dnsProxy";
  } else if (vpn) {
    return @"vpn";
  }
  return @"unknown";
}

+ (id)safeValueForKey:(NSString*)key fromObject:(id)object {
  @try {
    return [object valueForKey:key];
  } @catch (NSException* exception) {
    return nil;
  }
}

+ (NSDictionary*)configurationToDictionary:(NEConfiguration*)config {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  // Use safe KVC for property access - ensure identifier is always a string
  id identifierObj = [self safeValueForKey:@"identifier" fromObject:config];
  NSString* identifier =
      [identifierObj isKindOfClass:[NSString class]] ? identifierObj : [identifierObj description];
  dict[@"identifier"] = identifier ?: @"";

  dict[@"name"] = [self safeValueForKey:@"name" fromObject:config] ?: @"";
  dict[@"application"] = [self safeValueForKey:@"application" fromObject:config] ?: @"";
  dict[@"applicationName"] = [self safeValueForKey:@"applicationName" fromObject:config] ?: @"";

  id gradeValue = [self safeValueForKey:@"grade" fromObject:config];
  dict[@"grade"] = gradeValue ? gradeValue : @(0);
  dict[@"type"] = [self extensionTypeFromConfig:config];

  // Content Filter
  id contentFilter = [self safeValueForKey:@"contentFilter" fromObject:config];
  if (contentFilter) {
    NSMutableDictionary* cfDict = [NSMutableDictionary dictionary];

    id enabledValue = [self safeValueForKey:@"enabled" fromObject:contentFilter];
    cfDict[@"enabled"] = enabledValue ? enabledValue : @NO;

    id gradeValue = [self safeValueForKey:@"grade" fromObject:contentFilter];
    cfDict[@"filterGrade"] = gradeValue ? gradeValue : @(0);

    id provider = [self safeValueForKey:@"provider" fromObject:contentFilter];
    if (provider) {
      NSMutableDictionary* providerDict = [NSMutableDictionary dictionary];

      // Try various property name variations
      providerDict[@"pluginType"] = [self safeValueForKey:@"pluginType" fromObject:provider] ?: @"";
      providerDict[@"dataProviderBundleIdentifier"] = 
                [self safeValueForKey:@"dataProviderBundleIdentifier" fromObject:provider] ?:
                [self safeValueForKey:@"providerBundleIdentifier" fromObject:provider] ?: @"";
      providerDict[@"dataProviderDesignatedRequirement"] = 
                [self safeValueForKey:@"dataProviderDesignatedRequirement" fromObject:provider] ?:
                [self safeValueForKey:@"designatedRequirement" fromObject:provider] ?: @"";
      providerDict[@"packetProviderBundleIdentifier"] =
          [self safeValueForKey:@"packetProviderBundleIdentifier" fromObject:provider] ?: @"";
      providerDict[@"organization"] =
          [self safeValueForKey:@"organization" fromObject:provider] ?: @"";

      id filterPackets = [self safeValueForKey:@"filterPackets" fromObject:provider];
      providerDict[@"filterPackets"] = filterPackets ? filterPackets : @NO;

      id filterSockets = [self safeValueForKey:@"filterSockets" fromObject:provider];
      providerDict[@"filterSockets"] = filterSockets ? filterSockets : @NO;

      id preserveConnections = [self safeValueForKey:@"preserveExistingConnections"
                                          fromObject:provider];
      providerDict[@"preserveExistingConnections"] =
          preserveConnections ? preserveConnections : @NO;

      cfDict[@"provider"] = providerDict;
    }

    dict[@"contentFilter"] = cfDict;
  }

  // DNS Proxy
  id dnsProxy = [self safeValueForKey:@"dnsProxy" fromObject:config];
  if (dnsProxy) {
    NSMutableDictionary* dnsDict = [NSMutableDictionary dictionary];

    id enabledValue = [self safeValueForKey:@"enabled" fromObject:dnsProxy];
    dnsDict[@"enabled"] = enabledValue ? enabledValue : @NO;

    id protocol = [self safeValueForKey:@"protocol" fromObject:dnsProxy];
    if (protocol) {
      NSMutableDictionary* protocolDict = [NSMutableDictionary dictionary];
      protocolDict[@"providerBundleIdentifier"] =
          [self safeValueForKey:@"providerBundleIdentifier" fromObject:protocol] ?: @"";
      protocolDict[@"designatedRequirement"] =
          [self safeValueForKey:@"designatedRequirement" fromObject:protocol] ?: @"";
      protocolDict[@"pluginType"] = [self safeValueForKey:@"pluginType" fromObject:protocol] ?: @"";
      dnsDict[@"protocol"] = protocolDict;
    }

    dict[@"dnsProxy"] = dnsDict;
  }

  // VPN
  id vpn = [self safeValueForKey:@"VPN" fromObject:config];
  if (vpn) {
    NSMutableDictionary* vpnDict = [NSMutableDictionary dictionary];

    // Try different property names for enabled
    id enabledValue = [self safeValueForKey:@"enabled" fromObject:vpn];
    if (!enabledValue) {
      enabledValue = [self safeValueForKey:@"isEnabled" fromObject:vpn];
    }
    vpnDict[@"enabled"] = enabledValue ? enabledValue : @NO;

    // Try different property names for onDemandEnabled
    id onDemandValue = [self safeValueForKey:@"onDemandEnabled" fromObject:vpn];
    if (!onDemandValue) {
      onDemandValue = [self safeValueForKey:@"isOnDemandEnabled" fromObject:vpn];
    }
    vpnDict[@"onDemandEnabled"] = onDemandValue ? onDemandValue : @NO;

    id protocol = [self safeValueForKey:@"protocol" fromObject:vpn];
    if (protocol) {
      NSMutableDictionary* protocolDict = [NSMutableDictionary dictionary];
      protocolDict[@"serverAddress"] =
          [self safeValueForKey:@"serverAddress" fromObject:protocol] ?: @"";
      protocolDict[@"providerBundleIdentifier"] =
          [self safeValueForKey:@"providerBundleIdentifier" fromObject:protocol] ?: @"";
      protocolDict[@"designatedRequirement"] =
          [self safeValueForKey:@"designatedRequirement" fromObject:protocol] ?: @"";
      protocolDict[@"pluginType"] = [self safeValueForKey:@"pluginType" fromObject:protocol] ?: @"";
      vpnDict[@"protocol"] = protocolDict;
    }

    dict[@"VPN"] = vpnDict;
  }

  // Payload Info
  id payloadInfo = [self safeValueForKey:@"payloadInfo" fromObject:config];
  if (payloadInfo) {
    NSMutableDictionary* payloadDict = [NSMutableDictionary dictionary];
    payloadDict[@"payloadUUID"] =
        [self safeValueForKey:@"payloadUUID" fromObject:payloadInfo] ?: @"";
    payloadDict[@"payloadOrganization"] =
        [self safeValueForKey:@"payloadOrganization" fromObject:payloadInfo] ?: @"";
    payloadDict[@"profileUUID"] =
        [self safeValueForKey:@"profileUUID" fromObject:payloadInfo] ?: @"";
    payloadDict[@"profileIdentifier"] =
        [self safeValueForKey:@"profileIdentifier" fromObject:payloadInfo] ?: @"";
    payloadDict[@"profileSource"] =
        [self safeValueForKey:@"profileSource" fromObject:payloadInfo] ?: @"";

    id isSetAside = [self safeValueForKey:@"isSetAside" fromObject:payloadInfo];
    payloadDict[@"isSetAside"] = isSetAside ? isSetAside : @NO;

    id ingestionDate = [self safeValueForKey:@"profileIngestionDate" fromObject:payloadInfo];
    if (ingestionDate && [ingestionDate isKindOfClass:[NSDate class]]) {
      NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
      formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss Z";
      formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
      payloadDict[@"profileIngestionDate"] = [formatter stringFromDate:ingestionDate];
    }

    payloadDict[@"systemVersion"] =
        [self safeValueForKey:@"systemVersion" fromObject:payloadInfo] ?: @"";
    dict[@"payloadInfo"] = payloadDict;
  }

  return dict;
}

+ (void)printConfiguration:(NEConfiguration*)config
                    asJSON:(BOOL)json
                     asXML:(BOOL)xml
                     asRaw:(BOOL)raw {
  if (raw) {
    printf("%s\n", [config.description UTF8String]);
  } else if (json) {
    NSDictionary* dict = [self configurationToDictionary:config];
    NSError* error;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:dict
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (jsonData) {
      printf("%s\n",
             [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding].UTF8String);
    }
  } else if (xml) {
    NSDictionary* dict = [self configurationToDictionary:config];
    NSError* error;
    NSData* plistData =
        [NSPropertyListSerialization dataWithPropertyList:dict
                                                   format:NSPropertyListXMLFormat_v1_0
                                                  options:0
                                                    error:&error];
    if (plistData) {
      printf("%s\n",
             [[NSString alloc] initWithData:plistData encoding:NSUTF8StringEncoding].UTF8String);
    }
  } else {
    printf("%s\n", [config.description UTF8String]);
  }
}

+ (void)printAllConfigurations:(NSArray<NEConfiguration*>*)configs
                        asJSON:(BOOL)json
                         asXML:(BOOL)xml
                         asRaw:(BOOL)raw {
  if (raw) {
    NSMutableDictionary* allDict = [NSMutableDictionary dictionary];
    for (NEConfiguration* config in configs) {
      id identifier = [self safeValueForKey:@"identifier" fromObject:config];
      NSString* key =
          [identifier isKindOfClass:[NSString class]] ? identifier : [identifier description];
      allDict[key] = config;
    }
    printf("%s\n", [allDict.description UTF8String]);
  } else if (json) {
    NSMutableDictionary* allDict = [NSMutableDictionary dictionary];
    for (NEConfiguration* config in configs) {
      NSDictionary* dict = [self configurationToDictionary:config];
      // Convert identifier to string for JSON compatibility
      id identifier = dict[@"identifier"];
      NSString* key =
          [identifier isKindOfClass:[NSString class]] ? identifier : [identifier description];
      allDict[key] = dict;
    }
    NSError* error;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:allDict
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (jsonData) {
      printf("%s\n",
             [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding].UTF8String);
    } else if (error) {
      fprintf(stderr, "JSON serialization error: %s\n", error.localizedDescription.UTF8String);
    }
  } else if (xml) {
    NSMutableDictionary* allDict = [NSMutableDictionary dictionary];
    for (NEConfiguration* config in configs) {
      NSDictionary* dict = [self configurationToDictionary:config];
      // Convert identifier to string for PLIST compatibility
      id identifier = dict[@"identifier"];
      NSString* key =
          [identifier isKindOfClass:[NSString class]] ? identifier : [identifier description];
      allDict[key] = dict;
    }
    NSError* error;
    NSData* plistData =
        [NSPropertyListSerialization dataWithPropertyList:allDict
                                                   format:NSPropertyListXMLFormat_v1_0
                                                  options:0
                                                    error:&error];
    if (plistData) {
      printf("%s\n",
             [[NSString alloc] initWithData:plistData encoding:NSUTF8StringEncoding].UTF8String);
    }
  } else {
    for (NEConfiguration* config in configs) {
      printf("%s\n\n", [config.description UTF8String]);
    }
  }
}

+ (void)printIdentifiersFromConfigurations:(NSArray<NEConfiguration*>*)configs
                                    asJSON:(BOOL)json
                                     asXML:(BOOL)xml
                                     asRaw:(BOOL)raw {
  NSMutableDictionary* identifiers = [NSMutableDictionary dictionary];
  identifiers[@"contentFilter"] = [NSMutableArray array];
  identifiers[@"dnsProxy"] = [NSMutableArray array];
  identifiers[@"vpn"] = [NSMutableArray array];
  identifiers[@"unknown"] = [NSMutableArray array];

  for (NEConfiguration* config in configs) {
    NSString* bundleID = config.application ?: @"";
    NSString* type = [self extensionTypeFromConfig:config];

    if (![identifiers[type] containsObject:bundleID] && bundleID.length > 0) {
      [identifiers[type] addObject:bundleID];
    }
  }

  if (json) {
    NSError* error;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:identifiers
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (jsonData) {
      printf("%s\n",
             [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding].UTF8String);
    }
  } else if (xml) {
    NSError* error;
    NSData* plistData =
        [NSPropertyListSerialization dataWithPropertyList:identifiers
                                                   format:NSPropertyListXMLFormat_v1_0
                                                  options:0
                                                    error:&error];
    if (plistData) {
      printf("%s\n",
             [[NSString alloc] initWithData:plistData encoding:NSUTF8StringEncoding].UTF8String);
    }
  } else {
    printf("%s\n", [identifiers.description UTF8String]);
  }
}

@end

void printUsage(void) {
  printf("NAME\n");
  printf("    nesi - Network Extension Status Inspector\n\n");
  printf("SYNOPSIS\n");
  printf("    nesi -dump [-all -identifiers -raw] [-identifier %%identifier%%] [-type %%type%%] "
         "%%output%%\n\n");
  printf("DESCRIPTION\n");
  printf("    The nesi command is used to read and print network extension status\n\n");
  printf("OPTIONS\n");
  printf("    -dump\n");
  printf("        Optional: Returns requested data. Must be combined with sub-option.\n");
  printf("        -all: Returns all found bundle identifiers and their data\n");
  printf("        -identifiers: Returns all found bundle identifiers\n");
  printf("        -raw: Returns all found data directly from NEConfiguration\n\n");
  printf("    -identifier\n");
  printf("        Required: The bundle identifier of the network extension to query\n\n");
  printf("    -type\n");
  printf("        Required: The type of the network extension to query\n");
  printf("        Allowed values: \"contentFilter\", \"dnsProxy\", \"vpn\"\n\n");
  printf("    output\n");
  printf("        Optional: Specific output formats:\n");
  printf("        -stdout-enabled: Returns Network Extensions enabled status\n");
  printf("        -stdout-json: Returns Network Extension(s) data in JSON format\n");
  printf("        -stdout-raw: Returns Network Extension(s) data in raw format\n");
  printf("        -stdout-xml: Returns Network Extension(s) data in PLIST format\n");
  printf("        None passed: Returns standard Network Extension(s) data\n\n");
}

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    NSArray* args = [[NSProcessInfo processInfo] arguments];

    if (args.count < 2) {
      printUsage();
      return 1;
    }

    BOOL isDump = NO;
    BOOL isAll = NO;
    BOOL isIdentifiers = NO;
    BOOL isRaw = NO;
    BOOL isJSON = NO;
    BOOL isXML = NO;
    BOOL isEnabled = NO;
    NSString* identifier = nil;
    NSString* type = nil;

    for (NSUInteger i = 1; i < args.count; i++) {
      NSString* arg = args[i];

      if ([arg isEqualToString:@"-dump"]) {
        isDump = YES;
      } else if ([arg isEqualToString:@"-all"]) {
        isAll = YES;
      } else if ([arg isEqualToString:@"-identifiers"]) {
        isIdentifiers = YES;
      } else if ([arg isEqualToString:@"-raw"]) {
        isRaw = YES;
      } else if ([arg isEqualToString:@"-stdout-json"]) {
        isJSON = YES;
      } else if ([arg isEqualToString:@"-stdout-xml"]) {
        isXML = YES;
      } else if ([arg isEqualToString:@"-stdout-raw"]) {
        isRaw = YES;
      } else if ([arg isEqualToString:@"-stdout-enabled"]) {
        isEnabled = YES;
      } else if ([arg isEqualToString:@"-identifier"] && i + 1 < args.count) {
        identifier = args[++i];
      } else if ([arg isEqualToString:@"-type"] && i + 1 < args.count) {
        type = args[++i];
      }
    }

    // Check if running as root - actually, this shouldn't be necessary
    // The original Swift version doesn't require sudo

    // Try to get the NEConfigurationManager class
    Class managerClass = NSClassFromString(@"NEConfigurationManager");
    if (!managerClass) {
      fprintf(stderr, "Error: NEConfigurationManager class not found.\n");
      fprintf(stderr, "This tool requires macOS with NetworkExtension framework.\n");
      return 1;
    }

    // Get the shared manager using performSelector to avoid compiler warnings
    SEL sharedManagerSel = NSSelectorFromString(@"sharedManager");
    if (![managerClass respondsToSelector:sharedManagerSel]) {
      fprintf(stderr, "Error: NEConfigurationManager does not respond to sharedManager.\n");
      return 1;
    }

    id manager = [managerClass performSelector:sharedManagerSel];
    if (!manager) {
      fprintf(stderr, "Error: Could not get NEConfigurationManager instance.\n");
      return 1;
    }

    // Load configurations
    __block NSArray* configurations = nil;
    __block NSError* loadError = nil;
    __block BOOL completed = NO;

    // Try the simpler loadConfigurations method first
    SEL loadConfigsSel = NSSelectorFromString(@"loadConfigurations:");

    if ([manager respondsToSelector:loadConfigsSel]) {
      fprintf(stderr, "DEBUG: Using loadConfigurations: method\n");

      // Create the handler block
      id handler = ^(NSArray* configs, NSError* error) {
        configurations = [configs copy];
        loadError = error;
        completed = YES;
      };

// Call using performSelector
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      [manager performSelector:loadConfigsSel withObject:handler];
#pragma clang diagnostic pop

    } else {
      // Try the queue-based version
      loadConfigsSel = NSSelectorFromString(@"loadConfigurationsWithCompletionQueue:handler:");
      if (![manager respondsToSelector:loadConfigsSel]) {
        fprintf(stderr, "Error: NEConfigurationManager does not support any known load method.\n");
        fprintf(stderr, "Available methods:\n");

        unsigned int methodCount;
        Method* methods = class_copyMethodList([manager class], &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
          SEL selector = method_getName(methods[i]);
          fprintf(stderr, "  - %s\n", sel_getName(selector));
        }
        free(methods);
        return 1;
      }

      dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

      // Create the handler block
      id handler = ^(NSArray* configs, NSError* error) {
        configurations = [configs copy];
        loadError = error;
        completed = YES;
      };

      // Use objc_msgSend directly
      typedef void (*LoadConfigsFunc)(id, SEL, dispatch_queue_t, id);
      LoadConfigsFunc loadConfigs = (LoadConfigsFunc)objc_msgSend;
      loadConfigs(manager, loadConfigsSel, queue, handler);
    }

    // Wait for completion with timeout
    NSDate* timeout = [NSDate dateWithTimeIntervalSinceNow:5.0];
    while (!completed && [timeout timeIntervalSinceNow] > 0) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                               beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    if (!completed) {
      fprintf(stderr, "Error: Timeout waiting for configurations.\n");
      return 1;
    }

    if (loadError) {
      fprintf(stderr, "Error loading configurations: %s\n",
              loadError.localizedDescription.UTF8String);
      return 1;
    }

    if (!configurations || configurations.count == 0) {
      printf("No network extension configurations found.\n");
      return 0;
    }

    // Process based on options
    if (isDump) {
      if (isAll) {
        [NESIFormatter printAllConfigurations:configurations asJSON:isJSON asXML:isXML asRaw:isRaw];
      } else if (isIdentifiers) {
        [NESIFormatter printIdentifiersFromConfigurations:configurations
                                                   asJSON:isJSON
                                                    asXML:isXML
                                                    asRaw:isRaw];
      } else if (isRaw) {
        [NESIFormatter printAllConfigurations:configurations asJSON:NO asXML:NO asRaw:YES];
      }
    } else if (identifier && type) {
      // Find specific configuration
      NEConfiguration* targetConfig = nil;

      for (NEConfiguration* config in configurations) {
        NSString* configApp =
            [NESIFormatter safeValueForKey:@"application" fromObject:config] ?: @"";

        // Also check pluginType as fallback for matching
        NSString* pluginType = nil;
        id contentFilter = [NESIFormatter safeValueForKey:@"contentFilter" fromObject:config];
        id dnsProxy = [NESIFormatter safeValueForKey:@"dnsProxy" fromObject:config];
        id vpn = [NESIFormatter safeValueForKey:@"VPN" fromObject:config];

        if (contentFilter) {
          id provider = [NESIFormatter safeValueForKey:@"provider" fromObject:contentFilter];
          pluginType = [NESIFormatter safeValueForKey:@"pluginType" fromObject:provider];
        } else if (dnsProxy) {
          id protocol = [NESIFormatter safeValueForKey:@"protocol" fromObject:dnsProxy];
          pluginType = [NESIFormatter safeValueForKey:@"pluginType" fromObject:protocol];
        } else if (vpn) {
          id protocol = [NESIFormatter safeValueForKey:@"protocol" fromObject:vpn];
          pluginType = [NESIFormatter safeValueForKey:@"pluginType" fromObject:protocol];
        }

        // Match by application or pluginType
        BOOL identifierMatches =
            [configApp isEqualToString:identifier] || [pluginType isEqualToString:identifier];

        if (identifierMatches) {
          NSString* configType = [NESIFormatter extensionTypeFromConfig:config];
          if ([configType isEqualToString:type]) {
            targetConfig = config;
            break;
          }
        }
      }

      if (targetConfig) {
        if (isEnabled) {
          BOOL enabled = NO;

          if ([type isEqualToString:@"contentFilter"]) {
            id contentFilter = [NESIFormatter safeValueForKey:@"contentFilter"
                                                   fromObject:targetConfig];
            if (contentFilter) {
              id enabledValue = [NESIFormatter safeValueForKey:@"enabled" fromObject:contentFilter];
              enabled = [enabledValue boolValue];
            }
          } else if ([type isEqualToString:@"dnsProxy"]) {
            id dnsProxy = [NESIFormatter safeValueForKey:@"dnsProxy" fromObject:targetConfig];
            if (dnsProxy) {
              id enabledValue = [NESIFormatter safeValueForKey:@"enabled" fromObject:dnsProxy];
              enabled = [enabledValue boolValue];
            }
          } else if ([type isEqualToString:@"vpn"]) {
            id vpn = [NESIFormatter safeValueForKey:@"VPN" fromObject:targetConfig];
            if (vpn) {
              id enabledValue = [NESIFormatter safeValueForKey:@"enabled" fromObject:vpn];
              if (!enabledValue) {
                enabledValue = [NESIFormatter safeValueForKey:@"isEnabled" fromObject:vpn];
              }
              enabled = [enabledValue boolValue];
            }
          }

          printf("%s\n", enabled ? "true" : "false");
        } else {
          [NESIFormatter printConfiguration:targetConfig asJSON:isJSON asXML:isXML asRaw:isRaw];
        }
      } else {
        fprintf(stderr, "Configuration not found for identifier: %s, type: %s\n",
                identifier.UTF8String, type.UTF8String);
        return 1;
      }
    } else {
      printUsage();
      return 1;
    }
  }
  return 0;
}
