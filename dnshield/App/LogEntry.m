//
//  LogEntry.m
//  DNShield
//
//  log viewer
//

#import "LogEntry.h"
#import <OSLog/OSLog.h>

@implementation LogEntry

+ (instancetype)entryFromOSLogEntry:(id)osLogEntry {
  LogEntry* entry = [[LogEntry alloc] init];

  // Use KVC to safely access properties, with better error handling
  @try {
    entry.date = [osLogEntry valueForKey:@"date"] ?: [NSDate date];

    // Get process info using proper OSLogEntry API
    // Use safe method invocation instead of direct casting
    if ([osLogEntry respondsToSelector:@selector(processIdentifier)]) {
      NSMethodSignature* sig = [osLogEntry methodSignatureForSelector:@selector(processIdentifier)];
      NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
      [inv setTarget:osLogEntry];
      [inv setSelector:@selector(processIdentifier)];
      [inv invoke];
      int pid;
      [inv getReturnValue:&pid];
      entry.processID = pid;
    } else {
      entry.processID = 0;
    }

    // Get process image path safely using string selector
    NSString* processImagePath = nil;
    SEL processImagePathSel = NSSelectorFromString(@"processImagePath");
    if ([osLogEntry respondsToSelector:processImagePathSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      processImagePath = [osLogEntry performSelector:processImagePathSel];
#pragma clang diagnostic pop
    }

    if (processImagePath && processImagePath.length > 0) {
      NSString* executableName = [processImagePath lastPathComponent];

      // Debug logging
      if ([executableName containsString:@"dnshield"] ||
          [executableName containsString:@"DNShield"]) {
        NSLog(@"[LogEntry] Found DNShield process: %@ from path: %@", executableName,
              processImagePath);
      }

      // Clean up system extension paths
      if ([executableName isEqualToString:@"com.dnshield.extension"]) {
        entry.process = @"dnshield.extension";
      } else if ([executableName isEqualToString:@"DNShield"]) {
        entry.process = @"DNShield";
      } else {
        entry.process = executableName;
      }
    } else {
      // Will set process name after we get subsystem/sender info
      entry.process = @"unknown";
    }

    // Get thread and activity IDs safely
    if ([osLogEntry respondsToSelector:@selector(threadIdentifier)]) {
      NSMethodSignature* sig = [osLogEntry methodSignatureForSelector:@selector(threadIdentifier)];
      NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
      [inv setTarget:osLogEntry];
      [inv setSelector:@selector(threadIdentifier)];
      [inv invoke];
      uint64_t threadID;
      [inv getReturnValue:&threadID];
      entry.threadID = threadID;
    } else {
      entry.threadID = 0;
    }

    if ([osLogEntry respondsToSelector:@selector(activityIdentifier)]) {
      NSMethodSignature* sig =
          [osLogEntry methodSignatureForSelector:@selector(activityIdentifier)];
      NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
      [inv setTarget:osLogEntry];
      [inv setSelector:@selector(activityIdentifier)];
      [inv invoke];
      uint64_t activityID;
      [inv getReturnValue:&activityID];
      entry.activityID = activityID;
    } else {
      entry.activityID = 0;
    }

    // Get log entry details safely using string selectors
    SEL subsystemSel = NSSelectorFromString(@"subsystem");
    if ([osLogEntry respondsToSelector:subsystemSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      entry.subsystem = [osLogEntry performSelector:subsystemSel] ?: @"";
#pragma clang diagnostic pop
    } else {
      entry.subsystem = @"";
    }

    SEL categorySel = NSSelectorFromString(@"category");
    if ([osLogEntry respondsToSelector:categorySel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      entry.category = [osLogEntry performSelector:categorySel] ?: @"";
#pragma clang diagnostic pop
    } else {
      entry.category = @"";
    }

    SEL senderSel = NSSelectorFromString(@"sender");
    if ([osLogEntry respondsToSelector:senderSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      entry.sender = [osLogEntry performSelector:senderSel] ?: @"";
#pragma clang diagnostic pop
    } else {
      entry.sender = entry.process;
    }

    // Get message safely
    SEL composedMessageSel = NSSelectorFromString(@"composedMessage");
    if ([osLogEntry respondsToSelector:composedMessageSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      entry.message = [osLogEntry performSelector:composedMessageSel] ?: @"";
#pragma clang diagnostic pop
    } else {
      entry.message = [osLogEntry description] ?: @"";
    }

    // Determine entry type and get log level using proper API
    entry.type = LogEntryTypeRegular;  // Default

    if ([osLogEntry respondsToSelector:@selector(level)]) {
      // This is an OSLogEntryLog - get level safely
      NSMethodSignature* sig = [osLogEntry methodSignatureForSelector:@selector(level)];
      NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
      [inv setTarget:osLogEntry];
      [inv setSelector:@selector(level)];
      [inv invoke];
      NSInteger levelValue;
      [inv getReturnValue:&levelValue];

      switch (levelValue) {
        case 0:  // OSLogEntryLogLevelUndefined
          entry.level = LogEntryLevelDefault;
          break;
        case 1:  // OSLogEntryLogLevelDebug
          entry.level = LogEntryLevelDebug;
          break;
        case 2:  // OSLogEntryLogLevelInfo
          entry.level = LogEntryLevelInfo;
          break;
        case 16:  // OSLogEntryLogLevelNotice
          entry.level = LogEntryLevelInfo;
          break;
        case 17:  // OSLogEntryLogLevelError
          entry.level = LogEntryLevelError;
          break;
        case 18:  // OSLogEntryLogLevelFault
          entry.level = LogEntryLevelFault;
          break;
        default: entry.level = LogEntryLevelDefault; break;
      }
    } else if ([osLogEntry respondsToSelector:@selector(parentActivityIdentifier)]) {
      // This is an OSLogEntryActivity
      entry.type = LogEntryTypeActivity;
      entry.level = LogEntryLevelDefault;

      NSMethodSignature* sig =
          [osLogEntry methodSignatureForSelector:@selector(parentActivityIdentifier)];
      NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
      [inv setTarget:osLogEntry];
      [inv setSelector:@selector(parentActivityIdentifier)];
      [inv invoke];
      uint64_t parentID;
      [inv getReturnValue:&parentID];
      entry.parentActivityID = parentID;
    } else if ([osLogEntry respondsToSelector:@selector(signpostIdentifier)]) {
      // This is an OSLogEntrySignpost
      entry.type = LogEntryTypeSignpost;
      entry.level = LogEntryLevelDefault;

      if ([osLogEntry respondsToSelector:@selector(signpostIdentifier)]) {
        NSMethodSignature* sig =
            [osLogEntry methodSignatureForSelector:@selector(signpostIdentifier)];
        NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
        [inv setTarget:osLogEntry];
        [inv setSelector:@selector(signpostIdentifier)];
        [inv invoke];
        uint64_t signpostID;
        [inv getReturnValue:&signpostID];
        entry.signpostID = signpostID;
      }

      if ([osLogEntry respondsToSelector:@selector(signpostName)]) {
        entry.signpostName = [osLogEntry performSelector:@selector(signpostName)] ?: @"";
      }

      if ([osLogEntry respondsToSelector:@selector(signpostType)]) {
        NSMethodSignature* sig = [osLogEntry methodSignatureForSelector:@selector(signpostType)];
        NSInvocation* inv = [NSInvocation invocationWithMethodSignature:sig];
        [inv setTarget:osLogEntry];
        [inv setSelector:@selector(signpostType)];
        [inv invoke];
        NSInteger signpostTypeValue;
        [inv getReturnValue:&signpostTypeValue];

        switch (signpostTypeValue) {
          case 0: entry.signpostType = @"undefined"; break;
          case 1: entry.signpostType = @"poi"; break;
          case 2: entry.signpostType = @"event"; break;
          case 3: entry.signpostType = @"begin"; break;
          case 4: entry.signpostType = @"end"; break;
          default: entry.signpostType = @"unknown"; break;
        }
      }
    } else {
      // Unknown type or boundary
      entry.type = LogEntryTypeRegular;
      entry.level = LogEntryLevelDefault;
    }

    // Infer process name if still unknown, now that we have subsystem/sender
    if ([entry.process isEqualToString:@"unknown"]) {
      if (entry.subsystem && [entry.subsystem containsString:@"com.gemini.dnshield"]) {
        if ([entry.subsystem containsString:@"extension"]) {
          entry.process = @"dnshield.extension";
        } else if ([entry.subsystem containsString:@"app"]) {
          entry.process = @"DNShield";
        } else {
          entry.process = @"dnshield";
        }
      } else if ([entry.subsystem isEqualToString:@"com.dnshield"]) {
        entry.process = @"DNShield";
      } else if ([entry.sender containsString:@"NetworkExtension"] ||
                 [entry.sender containsString:@"libnetworkextension"]) {
        // These are extension-related logs
        entry.process = @"dnshield.extension";
      } else if ([entry.message containsString:@"com.gemini.dnshield"]) {
        // Infer from message content
        if ([entry.message containsString:@"extension"]) {
          entry.process = @"dnshield.extension";
        } else {
          entry.process = @"DNShield";
        }
      } else {
        // Try to extract a meaningful name from subsystem
        if (entry.subsystem && entry.subsystem.length > 0) {
          NSArray* parts = [entry.subsystem componentsSeparatedByString:@"."];
          if (parts.count >= 2) {
            entry.process = [parts lastObject];  // e.g., "com.apple.xpc" -> "xpc"
          } else {
            entry.process = entry.subsystem;
          }
        } else {
          entry.process = @"system";
        }
      }
    }

    // Ensure we have at least basic info
    if (!entry.sender || entry.sender.length == 0) {
      entry.sender = entry.process;
    }

  } @catch (NSException* exception) {
    NSLog(@"[LogEntry] Exception parsing entry: %@", exception);
    // If we can't get proper data, create a minimal entry
    entry.date = [NSDate date];
    entry.type = LogEntryTypeRegular;
    entry.level = LogEntryLevelDefault;
    entry.process = @"unknown";
    entry.processID = 0;
    entry.threadID = 0;
    entry.activityID = 0;
    entry.subsystem = @"";
    entry.category = @"";
    entry.sender = @"";
    entry.message = [osLogEntry description] ?: @"Failed to parse";
  }

  return entry;
}

- (NSString*)formattedString {
  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSSSSS";

  NSMutableString* result = [[NSMutableString alloc] init];

  [result appendFormat:@"%@ ", [formatter stringFromDate:self.date]];
  [result appendFormat:@"%ld ", (long)self.type];
  [result appendFormat:@"%llu ", (unsigned long long)self.activityID];

  if (self.category) {
    [result appendFormat:@"%@ ", self.category];
  }

  [result appendFormat:@"%ld ", (long)self.level];

  if (self.parentActivityID > 0) {
    [result appendFormat:@"%llu ", (unsigned long long)self.parentActivityID];
  }

  if (self.sender) {
    [result appendFormat:@"%@ ", self.sender];
  }

  if (self.process) {
    [result appendFormat:@"%@ ", self.process];
  }

  [result appendFormat:@"%d ", self.processID];

  if (self.subsystem) {
    [result appendFormat:@"%@ ", self.subsystem];
  }

  [result appendFormat:@"%llu ", (unsigned long long)self.threadID];

  if (self.type == LogEntryTypeSignpost) {
    [result appendFormat:@"%llu ", (unsigned long long)self.signpostID];
    if (self.signpostName) {
      [result appendFormat:@"%@ ", self.signpostName];
    }
    if (self.signpostType) {
      [result appendFormat:@"%@ ", self.signpostType];
    }
  }

  if (self.message) {
    [result appendString:self.message];
  }

  return [result copy];
}

- (NSString*)compactFormattedString {
  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSSSSS";

  return [NSString stringWithFormat:@"%@ %@ %@ %@", [formatter stringFromDate:self.date],
                                    self.sender ?: @"", self.subsystem ?: @"", self.message ?: @""];
}

- (NSDictionary*)toDictionary {
  NSMutableDictionary* dict = [[NSMutableDictionary alloc] init];

  // Convert date to string to avoid JSON serialization issues
  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSSSSS";
  dict[@"date"] = [formatter stringFromDate:self.date];

  dict[@"type"] = @(self.type);
  dict[@"level"] = @(self.level);
  dict[@"processID"] = @(self.processID);
  dict[@"threadID"] = @(self.threadID);
  dict[@"activityID"] = @(self.activityID);

  if (self.category)
    dict[@"category"] = self.category;
  if (self.subsystem)
    dict[@"subsystem"] = self.subsystem;
  if (self.sender)
    dict[@"sender"] = self.sender;
  if (self.process)
    dict[@"process"] = self.process;
  if (self.message)
    dict[@"message"] = self.message;

  if (self.parentActivityID > 0) {
    dict[@"parentActivityID"] = @(self.parentActivityID);
  }

  if (self.type == LogEntryTypeSignpost) {
    dict[@"signpostID"] = @(self.signpostID);
    if (self.signpostName)
      dict[@"signpostName"] = self.signpostName;
    if (self.signpostType)
      dict[@"signpostType"] = self.signpostType;
  }

  return [dict copy];
}

@end
