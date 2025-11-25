#import "DNCTLCommon.h"

#import <errno.h>
#import <signal.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>

#import "Common/Defaults.h"

NSString* const DNCTLColorRed = @"\033[0;31m";
NSString* const DNCTLColorGreen = @"\033[0;32m";
NSString* const DNCTLColorYellow = @"\033[1;33m";
NSString* const DNCTLColorBlue = @"\033[0;34m";
NSString* const DNCTLColorReset = @"\033[0m";

@implementation CommandResult
@end

static DNOutputFormat gDNCTLOutputFormat = DNOutputFormatText;
static volatile sig_atomic_t gDNCTLInterrupted = 0;
static pid_t gDNCTLActiveChildPID = -1;
static BOOL gDNCTLSignalHandlersInstalled = NO;

DNOutputFormat DNCTLGetOutputFormat(void) {
  return gDNCTLOutputFormat;
}

void DNCTLSetOutputFormat(DNOutputFormat format) {
  gDNCTLOutputFormat = format;
}

static void DNCTLHandleSignal(int sig) {
  (void)sig;
  gDNCTLInterrupted = 1;
  if (gDNCTLActiveChildPID > 0) {
    kill(gDNCTLActiveChildPID, SIGTERM);
  }
}

void DNCTLInstallSignalHandlersIfNeeded(void) {
  if (gDNCTLSignalHandlersInstalled)
    return;
  signal(SIGINT, DNCTLHandleSignal);
  signal(SIGTERM, DNCTLHandleSignal);
  gDNCTLSignalHandlersInstalled = YES;
}

BOOL DNCTLIsInterrupted(void) {
  return gDNCTLInterrupted != 0;
}

void DNCTLSetActiveChildPID(pid_t pid) {
  gDNCTLActiveChildPID = pid;
}

void DNCTLClearActiveChildPID(void) {
  gDNCTLActiveChildPID = -1;
}

NSString* DNCTLTrimmedString(NSString* value) {
  if (!value)
    return @"";
  return [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

BOOL DNCTLContainsUnknownFlag(NSArray<NSString*>* tokens, NSSet<NSString*>* knownFlags) {
  for (NSString* token in tokens) {
    if ([token hasPrefix:@"-"] && ![knownFlags containsObject:token]) {
      return YES;
    }
  }
  return NO;
}

BOOL DNCTLParseFormatFromArgs(NSArray<NSString*>* args, DNOutputFormat* outFormat,
                              NSArray<NSString*>** outRemaining) {
  DNOutputFormat format = DNOutputFormatText;
  NSMutableArray<NSString*>* remaining = [args mutableCopy];
  for (NSInteger i = 0; i < (NSInteger)remaining.count; i++) {
    NSString* token = remaining[i];
    if ([token.lowercaseString isEqualToString:@"format"] && i + 1 < (NSInteger)remaining.count) {
      NSString* fmt = remaining[i + 1].lowercaseString;
      if ([fmt isEqualToString:@"plist"])
        format = DNOutputFormatPlist;
      else if ([fmt isEqualToString:@"json"])
        format = DNOutputFormatJSON;
      else if ([fmt isEqualToString:@"yaml"])
        format = DNOutputFormatYAML;
      [remaining removeObjectAtIndex:i + 1];
      [remaining removeObjectAtIndex:i];
      if (outFormat)
        *outFormat = format;
      if (outRemaining)
        *outRemaining = [remaining copy];
      return YES;
    }
  }
  if (outFormat)
    *outFormat = DNOutputFormatText;
  if (outRemaining)
    *outRemaining = args;
  return NO;
}

static void DNCTLLogMessage(NSString* color, NSString* tag, NSString* message) {
  const char* c = color.UTF8String;
  const char* reset = DNCTLColorReset.UTF8String;
  printf("%s[%s]%s %s\n", c, tag.UTF8String, reset, message.UTF8String);
}

void DNCTLLogInfo(NSString* message) {
  DNCTLLogMessage(DNCTLColorBlue, @"INFO", message);
}

void DNCTLLogWarning(NSString* message) {
  DNCTLLogMessage(DNCTLColorYellow, @"WARN", message);
}

void DNCTLLogError(NSString* message) {
  DNCTLLogMessage(DNCTLColorRed, @"ERROR", message);
}

void DNCTLLogSuccess(NSString* message) {
  DNCTLLogMessage(DNCTLColorGreen, @"OK", message);
}

static NSData* DNCTLDataFromStringUTF8(NSString* s) {
  return [s dataUsingEncoding:NSUTF8StringEncoding];
}

NSString* DNCTLJSONStringFromObject(id obj) {
  if (!obj)
    return @"{}";
  if (![NSJSONSerialization isValidJSONObject:obj]) {
    obj = @{@"value" : obj};
  }
  NSError* error = nil;
  NSData* json = [NSJSONSerialization dataWithJSONObject:obj
                                                 options:NSJSONWritingPrettyPrinted
                                                   error:&error];
  if (!json || error)
    return @"{}";
  return [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] ?: @"{}";
}

static NSData* DNCTLPlistDataFromObject(id obj) {
  NSError* err = nil;
  NSPropertyListFormat fmt = NSPropertyListXMLFormat_v1_0;
  NSData* data = [NSPropertyListSerialization dataWithPropertyList:obj
                                                            format:fmt
                                                           options:0
                                                             error:&err];
  return err ? nil : data;
}

NSString* DNCTLPlistStringFromObject(id obj) {
  NSData* data = DNCTLPlistDataFromObject(obj);
  return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
}

static void DNCTLYAMLWriteIndented(NSMutableString* out, NSUInteger indent, NSString* line) {
  for (NSUInteger i = 0; i < indent; i++) {
    [out appendString:@"  "];
  }
  [out appendString:line];
  [out appendString:@"\n"];
}

static NSString* DNCTLYAMLQuoteString(NSString* s) {
  if (s.length == 0)
    return @"''";
  NSCharacterSet* set = [[NSCharacterSet
      characterSetWithCharactersInString:
          @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"] invertedSet];
  if ([s rangeOfCharacterFromSet:set].location != NSNotFound) {
    NSString* escaped = [s stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    return [NSString stringWithFormat:@"\"%@\"", escaped];
  }
  return s;
}

static void DNCTLYAMLAppendObject(NSMutableString* out, id obj, NSUInteger indent) {
  if (!obj || obj == [NSNull null]) {
    DNCTLYAMLWriteIndented(out, indent, @"null");
    return;
  }
  if ([obj isKindOfClass:[NSDictionary class]]) {
    NSDictionary* dict = obj;
    if (dict.count == 0) {
      DNCTLYAMLWriteIndented(out, indent, @"{}");
      return;
    }
    for (id key in dict) {
      NSString* k = [key description];
      id val = dict[key];
      if ([val isKindOfClass:[NSDictionary class]] || [val isKindOfClass:[NSArray class]]) {
        DNCTLYAMLWriteIndented(out, indent,
                               [NSString stringWithFormat:@"%@:", DNCTLYAMLQuoteString(k)]);
        DNCTLYAMLAppendObject(out, val, indent + 1);
      } else if ([val isKindOfClass:[NSData class]]) {
        NSString* b64 = [(NSData*)val base64EncodedStringWithOptions:0];
        DNCTLYAMLWriteIndented(
            out, indent, [NSString stringWithFormat:@"%@: !!binary |", DNCTLYAMLQuoteString(k)]);
        NSUInteger width = 76;
        for (NSUInteger i = 0; i < b64.length; i += width) {
          NSUInteger len = MIN(width, b64.length - i);
          NSString* chunk = [b64 substringWithRange:NSMakeRange(i, len)];
          DNCTLYAMLWriteIndented(out, indent + 1, chunk);
        }
      } else if ([val isKindOfClass:[NSDate class]]) {
        NSDateFormatter* fmt = [NSDateFormatter new];
        fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        fmt.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZZZZZ";
        DNCTLYAMLWriteIndented(out, indent,
                               [NSString stringWithFormat:@"%@: %@", DNCTLYAMLQuoteString(k),
                                                          [fmt stringFromDate:val]]);
      } else if ([val isKindOfClass:[NSString class]]) {
        DNCTLYAMLWriteIndented(out, indent,
                               [NSString stringWithFormat:@"%@: %@", DNCTLYAMLQuoteString(k),
                                                          DNCTLYAMLQuoteString(val)]);
      } else if ([val isKindOfClass:[NSNumber class]]) {
        DNCTLYAMLWriteIndented(
            out, indent,
            [NSString stringWithFormat:@"%@: %@", DNCTLYAMLQuoteString(k), [val stringValue]]);
      } else {
        DNCTLYAMLWriteIndented(out, indent,
                               [NSString stringWithFormat:@"%@: %@", DNCTLYAMLQuoteString(k),
                                                          DNCTLYAMLQuoteString([val description])]);
      }
    }
    return;
  }
  if ([obj isKindOfClass:[NSArray class]]) {
    NSArray* arr = obj;
    if (arr.count == 0) {
      DNCTLYAMLWriteIndented(out, indent, @"[]");
      return;
    }
    for (id val in arr) {
      if ([val isKindOfClass:[NSDictionary class]] || [val isKindOfClass:[NSArray class]]) {
        DNCTLYAMLWriteIndented(out, indent, @"-");
        DNCTLYAMLAppendObject(out, val, indent + 1);
      } else if ([val isKindOfClass:[NSString class]]) {
        DNCTLYAMLWriteIndented(out, indent,
                               [NSString stringWithFormat:@"- %@", DNCTLYAMLQuoteString(val)]);
      } else if ([val isKindOfClass:[NSNumber class]]) {
        DNCTLYAMLWriteIndented(out, indent, [NSString stringWithFormat:@"- %@", [val stringValue]]);
      } else if ([val isKindOfClass:[NSData class]]) {
        NSString* b64 = [(NSData*)val base64EncodedStringWithOptions:0];
        DNCTLYAMLWriteIndented(out, indent, @"- !!binary |");
        NSUInteger width = 76;
        for (NSUInteger i = 0; i < b64.length; i += width) {
          NSUInteger len = MIN(width, b64.length - i);
          NSString* chunk = [b64 substringWithRange:NSMakeRange(i, len)];
          DNCTLYAMLWriteIndented(out, indent + 1, chunk);
        }
      } else {
        DNCTLYAMLWriteIndented(
            out, indent,
            [NSString stringWithFormat:@"- %@", DNCTLYAMLQuoteString([val description])]);
      }
    }
    return;
  }
  if ([obj isKindOfClass:[NSString class]]) {
    DNCTLYAMLWriteIndented(out, indent, DNCTLYAMLQuoteString(obj));
    return;
  }
  if ([obj isKindOfClass:[NSNumber class]]) {
    DNCTLYAMLWriteIndented(out, indent, [obj stringValue]);
    return;
  }
  DNCTLYAMLWriteIndented(out, indent, DNCTLYAMLQuoteString([obj description]));
}

static NSString* DNCTLYAMLStringForObject(id obj, NSUInteger indent) {
  NSMutableString* out = [NSMutableString string];
  DNCTLYAMLAppendObject(out, obj, indent);
  return out;
}

void DNCTLPrintObject(id obj, DNOutputFormat format) {
  NSString* output = @"";
  switch (format) {
    case DNOutputFormatJSON: output = DNCTLJSONStringFromObject(obj); break;
    case DNOutputFormatPlist: output = DNCTLPlistStringFromObject(obj); break;
    case DNOutputFormatYAML: output = DNCTLYAMLStringForObject(obj, 0); break;
    case DNOutputFormatText:
    default: output = [obj description]; break;
  }
  printf("%s\n", output.UTF8String);
}

CommandResult* DNCTLRunEnvCommand(NSString* program, NSArray<NSString*>* arguments) {
  NSTask* task = [NSTask new];
  task.launchPath = program;
  task.arguments = arguments;
  NSPipe* stdoutPipe = [NSPipe pipe];
  NSPipe* stderrPipe = [NSPipe pipe];
  task.standardOutput = stdoutPipe;
  task.standardError = stderrPipe;
  [task launch];
  [task waitUntilExit];

  CommandResult* result = [CommandResult new];
  result.status = (int)task.terminationStatus;
  result.stdoutString =
      [[NSString alloc] initWithData:stdoutPipe.fileHandleForReading.readDataToEndOfFile
                            encoding:NSUTF8StringEncoding];
  result.stderrString =
      [[NSString alloc] initWithData:stderrPipe.fileHandleForReading.readDataToEndOfFile
                            encoding:NSUTF8StringEncoding];
  return result;
}

CommandResult* DNCTLRunStreamingCommand(NSString* path, NSArray<NSString*>* arguments) {
  CommandResult* result = [CommandResult new];
  NSTask* task = [NSTask new];
  task.launchPath = path;
  task.arguments = arguments;
  NSPipe* pipe = [NSPipe pipe];
  task.standardOutput = pipe;
  task.standardError = pipe;
  [task launch];
  DNCTLSetActiveChildPID(task.processIdentifier);

  NSFileHandle* handle = pipe.fileHandleForReading;
  NSData* data = nil;
  while ((data = [handle availableData]).length > 0 && !DNCTLIsInterrupted()) {
    fwrite(data.bytes, 1, data.length, stdout);
  }
  [task waitUntilExit];
  DNCTLClearActiveChildPID();
  result.status = (int)task.terminationStatus;
  return result;
}

BOOL DNCTLProcessExists(pid_t pid) {
  if (pid <= 0)
    return NO;
  int result = kill(pid, 0);
  return (result == 0 || errno != ESRCH);
}

NSNumber* DNCTLReadPID(void) {
  NSData* data = [NSData dataWithContentsOfFile:kDefaultLockFilePath];
  if (!data)
    return nil;
  NSString* string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (!string.length)
    return nil;
  return @([string intValue]);
}

void DNCTLEnsureRoot(void) {
  if (geteuid() != 0) {
    DNCTLLogError(@"This command must be run as root (use sudo)");
    exit(EXIT_FAILURE);
  }
}

static pid_t DNCTLFindProcessNamed(NSString* name) {
  CommandResult* result = DNCTLRunEnvCommand(@"pgrep", @[ @"-f", name ]);
  if (result.status != 0 || !result.stdoutString.length)
    return -1;
  NSArray<NSString*>* lines = [result.stdoutString
      componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
  for (NSString* line in lines) {
    NSString* trimmed =
        [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!trimmed.length)
      continue;
    return (pid_t)[trimmed intValue];
  }
  return -1;
}

pid_t DNCTLFindDaemonPID(void) {
  NSNumber* pidNumber = DNCTLReadPID();
  if (pidNumber && DNCTLProcessExists(pidNumber.intValue)) {
    return pidNumber.intValue;
  }
  return DNCTLFindProcessNamed(@"dnshield-daemon");
}

void DNCTLCleanupStalePID(void) {
  NSNumber* pidNumber = DNCTLReadPID();
  if (!pidNumber)
    return;
  if (!DNCTLProcessExists(pidNumber.intValue)) {
    [[NSFileManager defaultManager] removeItemAtPath:kDefaultLockFilePath error:nil];
  }
}

void DNCTLSendCommandFile(NSString* command, pid_t pid) {
  NSError* error = nil;
  [command writeToFile:@"/tmp/dnshield.command"
            atomically:YES
              encoding:NSUTF8StringEncoding
                 error:&error];
  if (error) {
    DNCTLLogError([NSString
        stringWithFormat:@"Failed to write command file: %@", error.localizedDescription]);
    exit(EXIT_FAILURE);
  }
  if (kill(pid, SIGUSR1) != 0) {
    DNCTLLogError([NSString stringWithFormat:@"Failed to signal daemon (PID: %d)", pid]);
    exit(EXIT_FAILURE);
  }
}

NSString* DNCTLFindExecutable(NSString* name) {
  NSArray<NSString*>* paths = @[ @"/usr/bin", @"/usr/local/bin" ];
  for (NSString* path in paths) {
    NSString* candidate = [path stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:candidate]) {
      return candidate;
    }
  }
  return name;
}
