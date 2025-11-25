#import <Foundation/Foundation.h>

#import "DNCTLCommands.h"
#import "DNCTLCommon.h"

static NSArray<NSString*>* RemainingArgumentsAfterFormat(NSArray<NSString*>* args) {
  DNOutputFormat fmt = DNCTLGetOutputFormat();
  NSArray<NSString*>* remaining = args;
  if (DNCTLParseFormatFromArgs(args, &fmt, (NSArray<NSString*>**)&remaining)) {
    DNCTLSetOutputFormat(fmt);
  }
  return remaining;
}

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc < 2) {
      DNCTLPrintUsage();
      return EXIT_SUCCESS;
    }

    NSMutableArray<NSString*>* arguments = [NSMutableArray array];
    for (int i = 1; i < argc; i++) {
      [arguments addObject:[NSString stringWithUTF8String:argv[i]]];
    }

    NSString* command = arguments.firstObject.lowercaseString;
    NSArray<NSString*>* subArgs =
        arguments.count > 1 ? [arguments subarrayWithRange:NSMakeRange(1, arguments.count - 1)]
                            : @[];

    if ([command isEqualToString:@"status"]) {
      RemainingArgumentsAfterFormat(subArgs);
      DNCTLCommandStatus();
    } else if ([command isEqualToString:@"start"]) {
      DNCTLCommandStart();
    } else if ([command isEqualToString:@"stop"]) {
      DNCTLCommandStop();
    } else if ([command isEqualToString:@"restart"]) {
      DNCTLCommandRestart();
    } else if ([command isEqualToString:@"enable"]) {
      DNCTLCommandEnable();
    } else if ([command isEqualToString:@"disable"]) {
      DNCTLCommandDisable();
    } else if ([command isEqualToString:@"config"]) {
      DNCTLCommandConfig(subArgs);
    } else if ([command isEqualToString:@"logs"]) {
      DNCTLCommandLogs(subArgs);
    } else if ([command isEqualToString:@"version"]) {
      RemainingArgumentsAfterFormat(subArgs);
      DNCTLCommandVersion();
    } else if ([command isEqualToString:@"help"] || [command isEqualToString:@"-h"] ||
               [command isEqualToString:@"--help"]) {
      DNCTLPrintUsage();
    } else {
      DNCTLLogError([NSString stringWithFormat:@"Unknown command: %@", command]);
      printf("\n");
      DNCTLPrintUsage();
      return EXIT_FAILURE;
    }
  }
  return EXIT_SUCCESS;
}
