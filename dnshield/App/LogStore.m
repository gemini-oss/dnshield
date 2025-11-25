//
//  LogStore.m
//  DNShield
//
//  log viewer
//

#import "LogStore.h"
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <os/log.h>

// Helpers to compose common identifiers from Defaults
static inline NSString* DNSubsystemBase(void) {
  return [NSString stringWithFormat:@"%@.%@", kDefaultBundlePrefix, kDefaultDomainName];
}
static inline NSString* DNExtensionProcessName(void) {
  return [NSString stringWithFormat:@"%@.%@.extension", kDefaultBundlePrefix, kDefaultDomainName];
}

@implementation LogStore

+ (instancetype)defaultStore {
  LogStore* store = [[LogStore alloc] init];
  store.timeRange = 3600;  // 1 hour
  store.maxEntries = 1000;
  store.includeSignposts = NO;
  store.showAllFields = NO;
  store.useStreamMode = NO;
  store.predicateType = PredicateTypeAllDNShield;
  store.predicateText = @"";
  return store;
}

- (void)fetchLogEntriesWithCompletion:(void (^)(NSArray<LogEntry*>* entries,
                                                NSError* _Nullable error))completion {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    @try {
      // Try native OSLogStore API first
      NSError* storeError;
      OSLogStore* store = [OSLogStore localStoreAndReturnError:&storeError];

      if (store && !storeError) {
        NSLog(@"[LogStore] Using native OSLogStore API");
        NSArray<LogEntry*>* entries = [self fetchEntriesFromOSLogStore:store];

        dispatch_async(dispatch_get_main_queue(), ^{
          completion(entries, nil);
        });
        return;
      } else {
        NSLog(@"[LogStore] OSLogStore failed: %@, falling back to command line",
              storeError.localizedDescription);
      }

      // Fallback to command line approach
      NSArray<LogEntry*>* entries = [self fetchEntriesUsingLogCommand];

      dispatch_async(dispatch_get_main_queue(), ^{
        completion(entries, nil);
      });
    } @catch (NSException* exception) {
      NSError* error = [NSError
          errorWithDomain:@"LogStoreError"
                     code:-1
                 userInfo:@{
                   NSLocalizedDescriptionKey : exception.reason ?: @"Failed to fetch log entries"
                 }];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(@[], error);
      });
    }
  });
}

- (void)fetchLogEntriesFromArchive:(NSURL*)archiveURL
                        completion:(void (^)(NSArray<LogEntry*>* entries,
                                             NSError* _Nullable error))completion {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    // For now, logarchive support is not implemented - fallback to regular log fetch
    NSArray<LogEntry*>* entries = [self fetchEntriesUsingLogCommand];

    dispatch_async(dispatch_get_main_queue(), ^{
      completion(entries, nil);
    });
  });
}

- (NSArray<LogEntry*>*)fetchEntriesUsingLogCommand {
  NSMutableArray<LogEntry*>* entries = [[NSMutableArray alloc] init];

  // For time ranges > 30 minutes, use the simpler fallback approach immediately
  // since log show with predicates is very slow for large time ranges
  if (self.timeRange > 1800 && !self.startDate && !self.endDate) {  // > 30 minutes
    NSLog(@"[LogStore] Time range > 30m, using simple command with client-side filtering");
    return [self fetchEntriesWithSimpleCommand];
  }

  // Build log command arguments
  NSMutableArray* arguments = [[NSMutableArray alloc] init];

  // Use log stream for real-time (recent) data, log show for historical
  BOOL useStream = self.useStreamMode ||
                   (self.timeRange <= 300 && !self.startDate && !self.endDate);  // <= 5 minutes

  if (useStream) {  // Stream mode - will capture for a short time then stop
    [arguments addObject:@"stream"];
    NSLog(@"[LogStore] Using log stream mode for recent/real-time logs");
  } else {
    [arguments addObject:@"show"];
    NSLog(@"[LogStore] Using log show mode for historical logs");
  }

  // Add predicate based on selection
  [arguments addObject:@"--predicate"];
  NSString* predicate = [self buildPredicateString];
  [arguments addObject:predicate];

  // Add time range - either --last or start/end dates (not supported in stream mode)
  if (!useStream) {
    if (self.startDate && self.endDate) {  // Use specific date range
      NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
      formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";

      [arguments addObject:@"--start"];
      [arguments addObject:[formatter stringFromDate:self.startDate]];
      [arguments addObject:@"--end"];
      [arguments addObject:[formatter stringFromDate:self.endDate]];
    } else {  // Use --last with time range - format as whole minutes/hours/days
      [arguments addObject:@"--last"];
      if (self.timeRange >= 86400) {  // >= 1 day
        NSInteger days = (NSInteger)(self.timeRange / 86400);
        [arguments addObject:[NSString stringWithFormat:@"%ldd", (long)days]];
      } else if (self.timeRange >= 3600) {  // >= 1 hour
        NSInteger hours = (NSInteger)(self.timeRange / 3600);
        [arguments addObject:[NSString stringWithFormat:@"%ldh", (long)hours]];
      } else {  // minutes
        NSInteger minutes = MAX(1, (NSInteger)(self.timeRange / 60));
        [arguments addObject:[NSString stringWithFormat:@"%ldm", (long)minutes]];
      }
    }
  }

  // Add debug level if needed
  [arguments addObject:@"--info"];

  // Add style
  [arguments addObject:@"--style"];
  [arguments addObject:@"compact"];

  // Execute log command
  NSTask* task = [[NSTask alloc] init];
  task.launchPath = @"/usr/bin/log";
  task.arguments = arguments;

  // Set environment and working directory
  task.environment = [[NSProcessInfo processInfo] environment];
  task.currentDirectoryPath = NSTemporaryDirectory();

  NSPipe* pipe = [NSPipe pipe];
  task.standardOutput = pipe;
  task.standardError = pipe;

  @try {
    // Debug: Print the full command being executed
    NSString* fullCommand =
        [NSString stringWithFormat:@"log %@", [arguments componentsJoinedByString:@" "]];
    NSLog(@"[LogStore] Executing command: %@", fullCommand);

    [task launch];

    // Set appropriate timeout based on command type and time range
    NSTimeInterval timeout;
    if (useStream) {
      // For stream mode, run for the requested time period then stop
      timeout = MIN(self.timeRange, 60.0);  // Max 1 minute of streaming
      NSLog(@"[LogStore] Stream mode - will collect for %.0f seconds", timeout);
    } else {
      // For show mode, use realistic timeout based on your timing data
      if (self.timeRange >= 86400) {        // >= 1 day (3+ minutes based on your test)
        timeout = 600.0;                    // 10 minutes for day+ ranges
      } else if (self.timeRange >= 3600) {  // >= 1 hour
        timeout = 300.0;                    // 5 minutes for hour+ ranges
      } else {
        timeout = 120.0;  // 2 minutes for shorter ranges
      }
      NSLog(@"[LogStore] Show mode - timeout set to %.0f seconds", timeout);
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                     if (task.isRunning) {
                       NSLog(@"[LogStore] Log command timeout after %.0fs - terminating", timeout);
                       [task terminate];
                     }
                   });

    [task waitUntilExit];

    NSLog(@"[LogStore] Task completed with exit code: %d", task.terminationStatus);

    NSData* data = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString* output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    NSLog(@"[LogStore] Got %lu bytes of output", output.length);

    if (task.terminationStatus != 0) {
      NSLog(@"[LogStore] Log command failed with exit code %d", task.terminationStatus);
      if (output.length > 0) {
        NSLog(@"[LogStore] Error output: %@", [output substringToIndex:MIN(500, output.length)]);
      }

      // Try a simpler fallback command
      NSLog(@"[LogStore] Trying fallback command without predicate");
      NSArray<LogEntry*>* fallbackEntries = [self fetchEntriesWithSimpleCommand];
      [entries addObjectsFromArray:fallbackEntries];

    } else if (output && output.length > 0) {
      // Parse log output into LogEntry objects
      NSArray* lines = [output componentsSeparatedByString:@"\n"];
      NSUInteger count = 0;

      NSLog(@"[LogStore] Parsing %lu lines", lines.count);

      for (NSString* line in lines) {
        if (count >= self.maxEntries)
          break;
        if (line.length == 0)
          continue;

        LogEntry* entry = [self parseLogLine:line];
        if (entry) {
          [entries addObject:entry];
          count++;
        }
      }

      NSLog(@"[LogStore] Parsed %lu log entries", entries.count);
    } else {
      NSLog(@"[LogStore] No output received from log command");
    }
  } @catch (NSException* exception) {
    NSLog(@"[LogStore] Exception executing log command: %@", exception);
  }

  // Sort by date (newest first)
  [entries sortUsingComparator:^NSComparisonResult(LogEntry* obj1, LogEntry* obj2) {
    return [obj2.date compare:obj1.date];
  }];

  return [entries copy];
}

- (NSArray<LogEntry*>*)fetchEntriesWithSimpleCommand {
  NSMutableArray<LogEntry*>* entries = [[NSMutableArray alloc] init];

  // Try a much simpler approach: get recent logs and filter in code
  NSArray* timeArgs;
  if (self.timeRange >= 86400) {
    NSInteger days = (NSInteger)(self.timeRange / 86400);
    timeArgs = @[ @"--last", [NSString stringWithFormat:@"%ldd", (long)days] ];
  } else if (self.timeRange >= 3600) {
    NSInteger hours = (NSInteger)(self.timeRange / 3600);
    timeArgs = @[ @"--last", [NSString stringWithFormat:@"%ldh", (long)hours] ];
  } else {
    NSInteger minutes = MAX(1, (NSInteger)(self.timeRange / 60));
    timeArgs = @[ @"--last", [NSString stringWithFormat:@"%ldm", (long)minutes] ];
  }

  NSArray* arguments = [@[ @"show" ] arrayByAddingObjectsFromArray:timeArgs];
  arguments = [arguments arrayByAddingObjectsFromArray:@[ @"--info", @"--style", @"compact" ]];

  NSTask* task = [[NSTask alloc] init];
  task.launchPath = @"/usr/bin/log";
  task.arguments = arguments;
  task.environment = [[NSProcessInfo processInfo] environment];

  NSPipe* pipe = [NSPipe pipe];
  task.standardOutput = pipe;
  task.standardError = pipe;

  @try {
    NSLog(@"[LogStore] Fallback command: log %@", [arguments componentsJoinedByString:@" "]);

    [task launch];

    // Reasonable timeout for fallback (simpler command should be faster)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(120.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                     if (task.isRunning) {
                       NSLog(@"[LogStore] Fallback command timeout after 2m - terminating");
                       [task terminate];
                     }
                   });

    [task waitUntilExit];

    NSData* data = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString* output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    NSLog(@"[LogStore] Fallback got %lu bytes, exit code: %d", output.length,
          task.terminationStatus);

    if (task.terminationStatus == 0 && output.length > 0) {
      NSArray* lines = [output componentsSeparatedByString:@"\n"];
      NSUInteger count = 0;

      for (NSString* line in lines) {
        if (count >= self.maxEntries)
          break;
        if (line.length == 0)
          continue;

        // Filter for DNShield-related lines using our predicate logic
        BOOL matchesPredicate = NO;
        switch (self.predicateType) {
          case PredicateTypeAllDNShield:
            matchesPredicate = ([line localizedCaseInsensitiveContainsString:kDefaultName] ||
                                [line localizedCaseInsensitiveContainsString:kDefaultDomainName] ||
                                [line localizedCaseInsensitiveContainsString:kDefaultBundlePrefix]);
            break;
          case PredicateTypeDNShieldApp:
            matchesPredicate = [line localizedCaseInsensitiveContainsString:kDefaultName];
            break;
          case PredicateTypeDNShieldExtension:
            matchesPredicate =
                [line localizedCaseInsensitiveContainsString:kDefaultExtensionBundleID];
            break;
          case PredicateTypeDNShieldSubsystem:
            matchesPredicate = ([line localizedCaseInsensitiveContainsString:kDefaultAppBundleID] &&
                                ![line localizedCaseInsensitiveContainsString:@"extension"]);
            break;
          default:
            matchesPredicate = ([line localizedCaseInsensitiveContainsString:kDefaultName] ||
                                [line localizedCaseInsensitiveContainsString:kDefaultDomainName] ||
                                [line localizedCaseInsensitiveContainsString:kDefaultBundlePrefix]);
            break;
        }

        if (matchesPredicate) {
          LogEntry* entry = [self parseLogLine:line];
          if (entry) {
            [entries addObject:entry];
            count++;
          }
        }
      }

      NSLog(@"[LogStore] Fallback found %lu DNShield entries", entries.count);
    }
  } @catch (NSException* exception) {
    NSLog(@"[LogStore] Fallback command failed: %@", exception);
  }

  return [entries copy];
}

- (NSArray<LogEntry*>*)fetchEntriesFromOSLogStore:(OSLogStore*)store {
  NSMutableArray<LogEntry*>* entries = [[NSMutableArray alloc] init];

  @try {
    // Create position for time range
    OSLogPosition* position = nil;
    NSDate* startDate = self.startDate;
    NSDate* endDate = self.endDate;

    if (!startDate && !endDate) {
      // Use time range from now
      endDate = [NSDate date];
      startDate = [endDate dateByAddingTimeInterval:-self.timeRange];
    }

    if (startDate) {
      position = [store positionWithDate:startDate];
      NSLog(@"[LogStore] Created position for date: %@", startDate);
    }

    // Build native NSPredicate
    NSPredicate* predicate = [self buildNativePredicate];
    NSLog(@"[LogStore] Using predicate: %@", predicate);

    // Create enumerator
    NSError* enumError;
    OSLogEnumerator* enumerator = [store entriesEnumeratorWithOptions:0
                                                             position:position
                                                            predicate:predicate
                                                                error:&enumError];

    if (enumError) {
      NSLog(@"[LogStore] Failed to create enumerator: %@", enumError.localizedDescription);
      return @[];
    }

    NSLog(@"[LogStore] Starting to enumerate entries...");

    // Enumerate entries
    NSUInteger count = 0;
    id logEntry;
    while ((logEntry = [enumerator nextObject]) && count < self.maxEntries) {
      // Filter by end date if specified
      NSDate* entryDate = [logEntry valueForKey:@"date"];
      if (endDate && entryDate && [entryDate compare:endDate] == NSOrderedDescending) {
        continue;
      }

      LogEntry* entry = [LogEntry entryFromOSLogEntry:logEntry];
      if (entry) {
        [entries addObject:entry];
        count++;

        // Log first few entries for debugging
        if (count <= 3) {
          NSLog(@"[LogStore] Entry %lu: %@ - %@", count, entry.process, entry.message);
        }
      }
    }

    NSLog(@"[LogStore] OSLogStore enumerated %lu entries", entries.count);

  } @catch (NSException* exception) {
    NSLog(@"[LogStore] Exception in OSLogStore enumeration: %@", exception);
    return @[];
  }

  // Sort by date (newest first)
  [entries sortUsingComparator:^NSComparisonResult(LogEntry* obj1, LogEntry* obj2) {
    return [obj2.date compare:obj1.date];
  }];

  return [entries copy];
}

- (NSPredicate*)buildNativePredicate {
  NSMutableArray* predicates = [NSMutableArray array];

  NSString* subsysBase = DNSubsystemBase();
  NSString* subsysApp = kDefaultAppBundleID;
  NSString* extSuffix = [NSString stringWithFormat:@"%@.extension", kDefaultDomainName];

  switch (self.predicateType) {
    case PredicateTypeAllDNShield: {
      NSPredicate* p = [NSPredicate
          predicateWithFormat:
              // Prefer == %@ for strings (lets NSPredicate handle quoting/escaping)
              @"processImagePath ENDSWITH %@ OR "
               "subsystem == %@ OR subsystem == %@ OR "
               "processImagePath CONTAINS %@ OR "
               "(subsystem == 'com.apple.networkextension' AND composedMessage CONTAINS %@)",
              kDefaultName, subsysBase, subsysApp, extSuffix, subsysBase];
      [predicates addObject:p];
      break;
    }
    case PredicateTypeDNShieldApp: {
      NSPredicate* p =
          [NSPredicate predicateWithFormat:@"processImagePath ENDSWITH %@", kDefaultName];
      [predicates addObject:p];
      break;
    }
    case PredicateTypeDNShieldExtension: {
      // match by process image path containing "<dnshield>.extension"
      NSPredicate* p = [NSPredicate predicateWithFormat:@"processImagePath CONTAINS %@", extSuffix];
      [predicates addObject:p];
      break;
    }
    case PredicateTypeDNShieldSubsystem: {
      NSPredicate* p = [NSPredicate
          predicateWithFormat:@"subsystem == %@ OR subsystem == %@", subsysBase, subsysApp];
      [predicates addObject:p];
      break;
    }
    case PredicateTypeCustom: {
      if (self.customPredicate.length > 0) {
        @try {
          NSPredicate* p = [NSPredicate predicateWithFormat:self.customPredicate];
          [predicates addObject:p];
        } @catch (NSException* ex) {
          NSLog(@"[LogStore] Invalid custom predicate: %@", ex.reason);
          NSPredicate* fallback =
              [NSPredicate predicateWithFormat:@"processImagePath ENDSWITH %@", kDefaultName];
          [predicates addObject:fallback];
        }
      }
      break;
    }
    default: break;
  }

  if (predicates.count > 1) {
    return [NSCompoundPredicate andPredicateWithSubpredicates:predicates];
  } else if (predicates.count == 1) {
    return predicates.firstObject;
  }
  return nil;
}

- (LogEntry*)parseLogLine:(NSString*)line {
  // Simple parsing of log command output
  // Format: 2025-01-27 15:30:45.123456-0800 0x12345 Default 0x0 0 0 DNShield: [subsystem] message

  LogEntry* entry = [[LogEntry alloc] init];
  entry.type = LogEntryTypeRegular;
  entry.level = LogEntryLevelInfo;

  // Try to extract timestamp
  NSRegularExpression* timestampRegex =
      [NSRegularExpression regularExpressionWithPattern:
                               @"^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{6}[+-]\\d{4})"
                                                options:0
                                                  error:nil];
  NSTextCheckingResult* timestampMatch =
      [timestampRegex firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
  if (timestampMatch) {
    NSString* timestampStr = [line substringWithRange:[timestampMatch rangeAtIndex:1]];
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSSSSSz";
    entry.date = [formatter dateFromString:timestampStr] ?: [NSDate date];
  } else {
    entry.date = [NSDate date];
  }

  // Try to extract process name and message
  NSRegularExpression* processRegex =
      [NSRegularExpression regularExpressionWithPattern:@"(\\w+):\\s*(.+)$" options:0 error:nil];
  NSTextCheckingResult* processMatch =
      [processRegex firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
  if (processMatch && processMatch.numberOfRanges >= 3) {
    entry.process = [line substringWithRange:[processMatch rangeAtIndex:1]];
    entry.message = [line substringWithRange:[processMatch rangeAtIndex:2]];

    // Try to extract subsystem from message
    if ([entry.message containsString:@"["]) {
      NSRegularExpression* subsystemRegex =
          [NSRegularExpression regularExpressionWithPattern:@"\\[([^\\]]+)\\]" options:0 error:nil];
      NSTextCheckingResult* subsystemMatch =
          [subsystemRegex firstMatchInString:entry.message
                                     options:0
                                       range:NSMakeRange(0, entry.message.length)];
      if (subsystemMatch) {
        entry.subsystem = [entry.message substringWithRange:[subsystemMatch rangeAtIndex:1]];
      }
    }
  } else {
    entry.process = @"unknown";
    entry.message = line;
  }

  // Set default values
  entry.sender = entry.process;
  entry.category = @"";
  entry.processID = 0;
  entry.threadID = 0;
  entry.activityID = 0;

  return entry;
}

- (NSString*)buildPredicateString {
  NSString* subsysBase = DNSubsystemBase();
  NSString* subsysApp = kDefaultAppBundleID;
  NSString* extProc = DNExtensionProcessName();

  switch (self.predicateType) {
    case PredicateTypeAllDNShield:
      return [NSString stringWithFormat:@"process == \"%@\" OR subsystem == \"%@\" OR subsystem == "
                                        @"\"%@\" OR process == \"%@\"",
                                        kDefaultName, subsysBase, subsysApp, extProc];

    case PredicateTypeDNShieldApp:
      return [NSString stringWithFormat:@"process == \"%@\"", kDefaultName];

    case PredicateTypeDNShieldExtension:
      return [NSString stringWithFormat:@"process == \"%@\"", extProc];

    case PredicateTypeDNShieldSubsystem:
      return [NSString
          stringWithFormat:@"subsystem == \"%@\" OR subsystem == \"%@\"", subsysBase, subsysApp];

    case PredicateTypeCustom:
      if (self.customPredicate.length > 0)
        return self.customPredicate;
      // fallthrough

    case PredicateTypeNone:
    default:
      return [NSString stringWithFormat:@"process == \"%@\" OR subsystem == \"%@\" OR subsystem == "
                                        @"\"%@\" OR process == \"%@\"",
                                        kDefaultName, subsysBase, subsysApp, extProc];
  }
}

- (NSPredicate*)buildPredicate {
  NSPredicate* p = [NSPredicate predicateWithFormat:@"process.executableName CONTAINS[c] %@ OR "
                                                     "subsystem CONTAINS[c] %@ OR "
                                                     "subsystem CONTAINS[c] %@ OR "
                                                     "process.executableName CONTAINS[c] %@",
                                                    kDefaultName, kDefaultDomainName,
                                                    kDefaultBundlePrefix, kDefaultDomainName];
  return p;
}

- (NSArray<LogEntry*>*)filterEntries:(NSArray<LogEntry*>*)entries
                      withSearchText:(NSString*)searchText
                             inField:(NSString*)field {
  if (!searchText || searchText.length == 0) {
    return entries;
  }

  NSMutableArray<LogEntry*>* filtered = [[NSMutableArray alloc] init];

  for (LogEntry* entry in entries) {
    BOOL matches = NO;
    NSString* searchValue = nil;

    if ([field isEqualToString:@"Messages"]) {
      searchValue = entry.message;
    } else if ([field isEqualToString:@"Processes"]) {
      searchValue = entry.process;
    } else if ([field isEqualToString:@"Senders"]) {
      searchValue = entry.sender;
    } else if ([field isEqualToString:@"Subsystems"]) {
      searchValue = entry.subsystem;
    }

    if (searchValue) {
      matches = [searchValue localizedCaseInsensitiveContainsString:searchText];
    }

    if (matches) {
      [filtered addObject:entry];
    }
  }

  return [filtered copy];
}

- (NSString*)exportEntriesToJSON:(NSArray<LogEntry*>*)entries {
  NSMutableArray* jsonEntries = [[NSMutableArray alloc] init];

  for (LogEntry* entry in entries) {
    [jsonEntries addObject:[entry toDictionary]];
  }

  NSError* error;
  NSData* jsonData = [NSJSONSerialization dataWithJSONObject:jsonEntries
                                                     options:NSJSONWritingPrettyPrinted
                                                       error:&error];

  if (error) {
    return nil;
  }

  return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

- (NSString*)exportEntriesToRTF:(NSArray<LogEntry*>*)entries {
  NSMutableString* rtf = [[NSMutableString alloc] init];

  // RTF header
  [rtf appendString:@"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Menlo;}}"];
  [rtf appendString:@"\\f0\\fs20 "];

  // Color table
  [rtf appendString:@"{\\colortbl;"];
  [rtf appendString:@"\\red255\\green255\\blue255;"];  // White background
  [rtf appendString:@"\\red0\\green0\\blue0;"];        // Black text
  [rtf appendString:@"\\red255\\green0\\blue0;"];      // Red (error)
  [rtf appendString:@"\\red255\\green165\\blue0;"];    // Orange (warning)
  [rtf appendString:@"\\red0\\green128\\blue0;"];      // Green (success)
  [rtf appendString:@"\\red0\\green0\\blue255;"];      // Blue (info)
  [rtf appendString:@"}"];

  for (LogEntry* entry in entries) {
    NSString* levelColor = @"\\cf2";  // Default black

    switch (entry.level) {
      case LogEntryLevelError:
      case LogEntryLevelFault:
        levelColor = @"\\cf3";  // Red
        break;
      case LogEntryLevelDebug:
        levelColor = @"\\cf6";  // Blue
        break;
      case LogEntryLevelInfo:
        levelColor = @"\\cf5";  // Green
        break;
      default: break;
    }

    NSString* line = [entry formattedString];
    // Escape RTF special characters
    line = [line stringByReplacingOccurrencesOfString:@"{" withString:@"\\{"];
    line = [line stringByReplacingOccurrencesOfString:@"}" withString:@"\\}"];
    line = [line stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];

    [rtf appendFormat:@"%@%@\\line ", levelColor, line];
  }

  [rtf appendString:@"}"];

  return [rtf copy];
}

@end
