#import "DNCTLCommands.h"

#include <string.h>

#import "Common/Defaults.h"
#import "DNCTLCommon.h"

typedef NS_ENUM(NSInteger, DNSubsystemSelectorKind) {
  DNSubsystemSelectorKindSubsystem = 0,
  DNSubsystemSelectorKindProcess = 1
};

static NSString* ClauseKindString(DNSubsystemSelectorKind kind) {
  return kind == DNSubsystemSelectorKindProcess ? @"process" : @"subsystem";
}

static NSString* SubsystemClauseKey(NSString* kind, NSString* value, NSString* match) {
  NSString* normalizedMatch = match.length ? match.lowercaseString : @"exact";
  return [NSString
      stringWithFormat:@"%@::%@::%@", kind.lowercaseString, normalizedMatch, value.lowercaseString];
}

static NSArray<NSDictionary*>* DefaultSubsystemSelectors(void) {
  static NSArray<NSDictionary*>* selectors = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    selectors = @[
      @{
        @"kind" : ClauseKindString(DNSubsystemSelectorKindSubsystem),
        @"value" : kDNShieldPreferenceDomain,
        @"match" : @"prefix"
      },
      @{
        @"kind" : ClauseKindString(DNSubsystemSelectorKindSubsystem),
        @"value" : kDefaultExtensionBundleID,
        @"match" : @"prefix"
      },
      @{
        @"kind" : ClauseKindString(DNSubsystemSelectorKindSubsystem),
        @"value" : kDNShieldDaemonBundleID,
        @"match" : @"prefix"
      },
      @{
        @"kind" : ClauseKindString(DNSubsystemSelectorKindProcess),
        @"value" : kDefaultExtensionBundleID,
        @"match" : @"exact"
      }
    ];
  });
  return selectors;
}

static NSDictionary* MatchSelectorForValue(NSString* value, NSArray<NSDictionary*>* selectors) {
  if (!value.length)
    return nil;
  NSString* needle = value.lowercaseString;
  for (NSDictionary* entry in selectors) {
    NSString* candidate = [entry[@"value"] lowercaseString];
    if (candidate && [candidate isEqualToString:needle]) {
      return entry;
    }
  }
  return nil;
}

static NSDictionary* ParseSubsystemSelectorToken(NSString* token,
                                                 NSArray<NSDictionary*>* referenceSelectors,
                                                 NSString** outError) {
  NSString* trim = DNCTLTrimmedString(token);
  if (!trim.length) {
    if (outError)
      *outError = @"Selector value cannot be empty";
    return nil;
  }

  NSDictionary* matched = MatchSelectorForValue(trim, referenceSelectors);
  if (matched)
    return matched;

  NSString* kindString = @"subsystem";
  NSString* value = trim;
  NSRange colonRange = [trim rangeOfString:@":" options:NSLiteralSearch];
  if (colonRange.location != NSNotFound) {
    kindString = DNCTLTrimmedString([trim substringToIndex:colonRange.location]);
    value = DNCTLTrimmedString([trim substringFromIndex:colonRange.location + 1]);
  }

  if (!value.length) {
    if (outError)
      *outError = @"Selector value cannot be empty";
    return nil;
  }

  NSString* normalizedKind = kindString.lowercaseString;
  if (![normalizedKind isEqualToString:@"subsystem"] &&
      ![normalizedKind isEqualToString:@"process"]) {
    if (outError) {
      *outError = [NSString
          stringWithFormat:@"Unknown selector type '%@' (use subsystem:VALUE or process:VALUE)",
                           kindString];
    }
    return nil;
  }

  NSString* match = @"exact";
  if ([normalizedKind isEqualToString:@"subsystem"]) {
    if ([value hasSuffix:@"*"]) {
      match = @"prefix";
      value = DNCTLTrimmedString([value substringToIndex:value.length - 1]);
    }
  }

  return @{@"kind" : normalizedKind, @"value" : value, @"match" : match};
}

static NSString* PredicateClauseForSubsystemSelectors(NSArray<NSDictionary*>* selectors) {
  NSMutableArray<NSString*>* parts = [NSMutableArray arrayWithCapacity:selectors.count];
  for (NSDictionary* entry in selectors) {
    NSString* kind = entry[@"kind"] ?: @"subsystem";
    NSString* value = entry[@"value"] ?: @"";
    NSString* match = entry[@"match"] ?: @"exact";
    if ([kind isEqualToString:@"process"]) {
      [parts addObject:[NSString stringWithFormat:@"process == \"%@\"", value]];
    } else {
      if ([match isEqualToString:@"prefix"]) {
        [parts addObject:[NSString stringWithFormat:@"subsystem BEGINSWITH \"%@\"", value]];
      } else {
        [parts addObject:[NSString stringWithFormat:@"subsystem == \"%@\"", value]];
      }
    }
  }
  return [parts componentsJoinedByString:@" OR "];
}

static BOOL EntryMatchesSubsystemSelectors(NSArray<NSDictionary*>* selectors, NSString* subsystem,
                                           NSString* process) {
  if (!selectors.count)
    return YES;
  for (NSDictionary* entry in selectors) {
    NSString* kind = entry[@"kind"] ?: @"subsystem";
    NSString* value = entry[@"value"] ?: @"";
    NSString* match = entry[@"match"] ?: @"exact";
    if ([kind isEqualToString:@"process"]) {
      if (process.length && [process isEqualToString:value])
        return YES;
    } else {
      if (!subsystem.length)
        continue;
      if ([match isEqualToString:@"prefix"]) {
        if ([subsystem hasPrefix:value])
          return YES;
      } else {
        if ([subsystem isEqualToString:value])
          return YES;
      }
    }
  }
  return NO;
}

static NSString* PredicateClauseForValues(NSString* field, NSArray<NSString*>* values) {
  if (values.count == 0)
    return @"";
  NSMutableArray<NSString*>* parts = [NSMutableArray arrayWithCapacity:values.count];
  for (NSString* value in values) {
    NSString* trim = DNCTLTrimmedString(value);
    if (!trim.length)
      continue;
    [parts addObject:[NSString stringWithFormat:@"%1$@ == \"%2$@\"", field, trim]];
  }
  if (parts.count == 0)
    return @"";
  return [NSString stringWithFormat:@"(%@)", [parts componentsJoinedByString:@" OR "]];
}

static NSString* NormalizeCategoryToken(NSString* token) {
  NSString* trim = DNCTLTrimmedString(token);
  NSRange colonRange = [trim rangeOfString:@":" options:NSLiteralSearch];
  if (colonRange.location != NSNotFound) {
    NSString* prefix = [[trim substringToIndex:colonRange.location] lowercaseString];
    if ([prefix isEqualToString:@"category"]) {
      NSString* value = DNCTLTrimmedString([trim substringFromIndex:colonRange.location + 1]);
      return value;
    }
  }
  return trim;
}

static BOOL ResolveSubsystemSelectors(NSArray<NSString*>* includeTokens,
                                      NSArray<NSString*>* excludeTokens,
                                      NSMutableArray<NSDictionary*>** outSelectors,
                                      NSString** outError) {
  NSArray<NSDictionary*>* defaultSelectors = DefaultSubsystemSelectors();
  NSMutableArray<NSDictionary*>* selectors =
      includeTokens.count > 0 ? [NSMutableArray array] : [defaultSelectors mutableCopy];
  NSMutableSet<NSString*>* selectorKeys = [NSMutableSet set];

  void (^AddSelector)(NSDictionary*) = ^(NSDictionary* entry) {
    if (!entry)
      return;
    NSString* kind = entry[@"kind"] ?: @"subsystem";
    NSString* value = entry[@"value"] ?: @"";
    NSString* match = entry[@"match"] ?: @"exact";
    if (!value.length)
      return;
    NSString* key = SubsystemClauseKey(kind, value, match);
    if (![selectorKeys containsObject:key]) {
      [selectorKeys addObject:key];
      [selectors addObject:@{@"kind" : kind, @"value" : value, @"match" : match}];
    }
  };

  if (includeTokens.count == 0) {
    for (NSDictionary* entry in selectors) {
      NSString* key = SubsystemClauseKey(entry[@"kind"] ?: @"subsystem", entry[@"value"] ?: @"",
                                         entry[@"match"] ?: @"exact");
      [selectorKeys addObject:key];
    }
  } else {
    for (NSString* token in includeTokens) {
      NSString* parseError = nil;
      NSDictionary* selector = ParseSubsystemSelectorToken(token, defaultSelectors, &parseError);
      if (!selector) {
        if (outError)
          *outError =
              parseError ?: [NSString stringWithFormat:@"Unable to parse selector '%@'", token];
        return NO;
      }
      AddSelector(selector);
    }
    if (selectors.count == 0) {
      if (outError)
        *outError = @"No subsystem selectors specified via --include";
      return NO;
    }
  }

  if (excludeTokens.count > 0) {
    for (NSString* token in excludeTokens) {
      NSString* parseError = nil;
      NSDictionary* selector = ParseSubsystemSelectorToken(token, selectors, &parseError);
      if (!selector) {
        selector = ParseSubsystemSelectorToken(token, defaultSelectors, &parseError);
      }
      if (!selector) {
        if (outError)
          *outError =
              parseError ?: [NSString stringWithFormat:@"Unable to parse selector '%@'", token];
        return NO;
      }
      NSString* targetKey =
          SubsystemClauseKey(selector[@"kind"] ?: @"subsystem", selector[@"value"] ?: @"",
                             selector[@"match"] ?: @"exact");
      NSIndexSet* indexes = [selectors
          indexesOfObjectsPassingTest:^BOOL(NSDictionary* obj, NSUInteger idx, BOOL* stop) {
            NSString* key = SubsystemClauseKey(obj[@"kind"] ?: @"subsystem", obj[@"value"] ?: @"",
                                               obj[@"match"] ?: @"exact");
            return [key isEqualToString:targetKey];
          }];
      if (indexes.count > 0) {
        [selectors removeObjectsAtIndexes:indexes];
      }
    }

    [selectorKeys removeAllObjects];
    for (NSDictionary* entry in selectors) {
      NSString* key = SubsystemClauseKey(entry[@"kind"] ?: @"subsystem", entry[@"value"] ?: @"",
                                         entry[@"match"] ?: @"exact");
      [selectorKeys addObject:key];
    }
  }

  if (selectors.count == 0) {
    if (outError)
      *outError = @"All subsystem selectors were excluded";
    return NO;
  }

  if (outSelectors)
    *outSelectors = selectors;
  return YES;
}

static void PrintLogsUsage(void) {
  printf("dnshield-ctl logs usage:\n");
  printf("  dnshield-ctl logs [--last <duration>] [-f] [format plist|json|yaml]\n");
  printf("  dnshield-ctl logs subsystems [--last <duration>] [-f] [--filter <text>] "
         "[format plist|json|yaml]\n");
  printf("  dnshield-ctl logs categories [--last <duration>] [-f] [--filter <text>] "
         "[format plist|json|yaml]\n");
  printf("\n");
  printf("Options:\n");
  printf("  --last <duration>  e.g., 10m, 1h, 1d (default 1h)\n");
  printf("  -f                 Follow/stream live logs\n");
  printf("  --filter <text>    Filter subsystems/categories by substring (case-insensitive)\n");
  printf("  --include <item>   Limit to specific subsystem/category (repeatable). Use "
         "subsystem:VALUE or process:VALUE for subsystems\n");
  printf(
      "  --exclude <item>   Exclude subsystem/category (repeatable). Same format as --include\n");
  printf("  --show-logs        Show actual log messages (default)\n");
  printf("  --summary          Show aggregated summary instead of log messages\n");
  printf("  format <fmt>       Output format: plist | json | yaml\n");
  printf("\nExamples:\n");
  printf("  dnshield-ctl logs --last 1d\n");
  printf("  dnshield-ctl logs -f format json\n");
  printf("  dnshield-ctl logs subsystems --include subsystem:%s\n",
         kDNShieldPreferenceDomain.UTF8String);
  printf("  dnshield-ctl logs categories --exclude general\n");
}

static NSString* BasePredicate(void) {
  return [NSString stringWithFormat:@"subsystem BEGINSWITH \"%@\" OR "
                                     "subsystem BEGINSWITH \"%@\" OR "
                                     "subsystem BEGINSWITH \"%@\" OR "
                                     "process == \"DNShield\" OR "
                                     "process == \"%@\" OR "
                                     "process == \"dnshield-daemon\"",
                                    kDNShieldPreferenceDomain, kDefaultExtensionBundleID,
                                    kDNShieldDaemonBundleID, kDefaultExtensionBundleID];
}

void DNCTLCommandLogs(NSArray<NSString*>* args) {
  // Help for logs
  for (NSString* tok in args) {
    NSString* t = tok.lowercaseString;
    if ([t isEqualToString:@"--help"] || [t isEqualToString:@"-h"] || [t isEqualToString:@"help"]) {
      PrintLogsUsage();
      return;
    }
  }

  // Subcommand: subsystems
  if (args.count > 0 && [args[0] isEqualToString:@"subsystems"]) {
    NSArray<NSString*>* rest =
        args.count > 1 ? [args subarrayWithRange:NSMakeRange(1, args.count - 1)] : @[];
    DNOutputFormat fmt = DNOutputFormatText;
    NSArray<NSString*>* remaining = rest;
    if (DNCTLParseFormatFromArgs(rest, &fmt, (NSArray<NSString*>**)&remaining)) {
      DNCTLSetOutputFormat(fmt);
    }

    BOOL follow = NO;
    BOOL showLogs = YES;
    NSString* last = @"1h";
    NSString* filter = nil;
    NSMutableArray<NSString*>* includeSelectors = [NSMutableArray array];
    NSMutableArray<NSString*>* excludeSelectors = [NSMutableArray array];

    for (NSInteger i = 0; i < (NSInteger)remaining.count; i++) {
      NSString* t = remaining[i];
      if ([t isEqualToString:@"--last"]) {
        if (i + 1 < (NSInteger)remaining.count) {
          last = remaining[i + 1];
          i++;
        }
      } else if ([t isEqualToString:@"-f"]) {
        follow = YES;
      } else if ([t isEqualToString:@"--filter"]) {
        if (i + 1 < (NSInteger)remaining.count) {
          filter = remaining[i + 1];
          i++;
        }
      } else if ([t isEqualToString:@"--show-logs"]) {
        showLogs = YES;
      } else if ([t isEqualToString:@"--summary"]) {
        showLogs = NO;
      } else if ([t isEqualToString:@"--include"]) {
        if (i + 1 >= (NSInteger)remaining.count) {
          DNCTLLogError(@"Missing value for --include");
          return;
        }
        [includeSelectors addObject:remaining[++i]];
      } else if ([t isEqualToString:@"--exclude"]) {
        if (i + 1 >= (NSInteger)remaining.count) {
          DNCTLLogError(@"Missing value for --exclude");
          return;
        }
        [excludeSelectors addObject:remaining[++i]];
      }
    }

    NSSet* known = [NSSet setWithArray:@[
      @"--last", @"-f", @"--filter", @"--show-logs", @"--summary", @"--include", @"--exclude",
      @"--help", @"-h", @"help", @"format"
    ]];
    if (DNCTLContainsUnknownFlag(remaining, known)) {
      DNCTLLogError(@"Unknown option for 'logs subsystems'");
      PrintLogsUsage();
      return;
    }

    NSMutableArray<NSDictionary*>* selectors = nil;
    NSString* selectorError = nil;
    if (!ResolveSubsystemSelectors(includeSelectors, excludeSelectors, &selectors,
                                   &selectorError)) {
      DNCTLLogError(selectorError ?: @"Failed to resolve subsystem selectors");
      return;
    }

    NSString* baseClause = PredicateClauseForSubsystemSelectors(selectors);
    if (!baseClause.length) {
      DNCTLLogError(@"No subsystem selectors available");
      return;
    }

    NSString* predicate = [NSString stringWithFormat:@"(%@)", baseClause];
    if (filter.length) {
      predicate = [NSString
          stringWithFormat:@"(%@) AND (subsystem CONTAINS[c] \"%@\" OR process CONTAINS[c] \"%@\")",
                           predicate, filter, filter];
    }

    NSMutableDictionary<NSString*, NSMutableDictionary*>* bySubsystem =
        [NSMutableDictionary dictionary];
    NSString* filterLower = filter.lowercaseString;

    if (follow) {
      if (DNCTLGetOutputFormat() == DNOutputFormatYAML ||
          DNCTLGetOutputFormat() == DNOutputFormatPlist) {
        DNCTLLogWarning(@"YAML/PLIST not supported for streaming; using JSON lines");
        DNCTLSetOutputFormat(DNOutputFormatJSON);
      }
      if (DNCTLGetOutputFormat() == DNOutputFormatText) {
        if (filter.length) {
          DNCTLLogInfo([NSString
              stringWithFormat:@"Streaming subsystems (filter: %@). Ctrl+C to stop...", filter]);
        } else {
          DNCTLLogInfo(@"Streaming subsystems. Ctrl+C to stop...");
        }
      }

      DNCTLInstallSignalHandlersIfNeeded();
      NSTask* task = [NSTask new];
      task.launchPath = @"/usr/bin/log";
      task.arguments = @[ @"stream", @"--predicate", predicate, @"--info", @"--style", @"json" ];
      NSPipe* pipe = [NSPipe pipe];
      task.standardOutput = pipe;
      task.standardError = pipe;
      [task launch];
      DNCTLSetActiveChildPID(task.processIdentifier);

      NSFileHandle* fh = pipe.fileHandleForReading;
      NSMutableData* buffer = [NSMutableData data];
      fh.readabilityHandler = ^(NSFileHandle* h) {
        NSData* chunk = h.availableData;
        if (!chunk.length) {
          h.readabilityHandler = nil;
          return;
        }
        [buffer appendData:chunk];
        while (true) {
          const void* bytes = buffer.bytes;
          NSUInteger length = buffer.length;
          const void* nl = memchr(bytes, '\n', length);
          if (!nl)
            break;
          NSUInteger lineLen = (const char*)nl - (const char*)bytes;
          NSData* lineData = [NSData dataWithBytes:bytes length:lineLen];
          NSString* line = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
          [buffer replaceBytesInRange:NSMakeRange(0, lineLen + 1) withBytes:NULL length:0];

          NSString* trim = DNCTLTrimmedString(line);
          if (!trim.length)
            continue;
          NSData* d = [trim dataUsingEncoding:NSUTF8StringEncoding];
          if (!d)
            continue;
          NSDictionary* obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
          if (![obj isKindOfClass:[NSDictionary class]])
            continue;

          NSString* subsystem = (obj[@"subsystem"] ?: @"");
          NSString* category = (obj[@"category"] ?: @"");
          NSString* process = (obj[@"process"] ?: @"");
          NSString* timestamp = (obj[@"timestamp"] ?: @"");

          if (!EntryMatchesSubsystemSelectors(selectors, subsystem, process))
            continue;

          if (filterLower.length) {
            NSString* subLower = [subsystem lowercaseString];
            NSString* procLower = [process lowercaseString];
            if (![subLower containsString:filterLower] && ![procLower containsString:filterLower]) {
              continue;
            }
          }

          if (subsystem.length == 0)
            subsystem = process.length ? process : @"(none)";
          if (category.length == 0)
            category = @"(none)";
          if (process.length == 0)
            process = @"(unknown)";

          NSMutableDictionary* entry = bySubsystem[subsystem];
          BOOL isNewSubsystem = NO;
          BOOL newInfo = NO;
          if (!entry) {
            entry = [@{
              @"categories" : [NSMutableSet set],
              @"processes" : [NSMutableSet set],
              @"count" : @(0),
              @"first" : timestamp ?: @"",
              @"last" : timestamp ?: @""
            } mutableCopy];
            bySubsystem[subsystem] = entry;
            isNewSubsystem = YES;
          }
          if (timestamp.length) {
            NSString* first = entry[@"first"] ?: @"";
            NSString* lastTs = entry[@"last"] ?: @"";
            if (first.length == 0 || [timestamp compare:first] == NSOrderedAscending)
              entry[@"first"] = timestamp;
            if (lastTs.length == 0 || [timestamp compare:lastTs] == NSOrderedDescending)
              entry[@"last"] = timestamp;
          }
          NSNumber* cnt = entry[@"count"] ?: @(0);
          entry[@"count"] = @(cnt.longLongValue + 1);
          NSMutableSet* cats = entry[@"categories"];
          NSMutableSet* procs = entry[@"processes"];
          if (category.length && ![cats containsObject:category]) {
            [cats addObject:category];
            newInfo = YES;
          }
          if (process.length && ![procs containsObject:process]) {
            [procs addObject:process];
            newInfo = YES;
          }

          if (DNCTLGetOutputFormat() == DNOutputFormatJSON) {
            NSDictionary* update = @{
              @"type" : isNewSubsystem ? @"new" : (newInfo ? @"updated" : @"event"),
              @"subsystem" : subsystem,
              @"category" : category,
              @"process" : process,
              @"count" : entry[@"count"],
              @"firstTimestamp" : entry[@"first"] ?: @"",
              @"lastTimestamp" : entry[@"last"] ?: @""
            };
            printf("%s\n", [DNCTLJSONStringFromObject(update) UTF8String]);
          } else {
            if (filterLower.length) {
              NSString* msg = obj[@"eventMessage"] ?: obj[@"composedMessage"] ?: @"";
              printf("%s %s [%s:%s] %s\n", [timestamp UTF8String], [process UTF8String],
                     [subsystem UTF8String], [category UTF8String], [msg UTF8String]);
            } else if (isNewSubsystem) {
              printf("[+] subsystem: %s  category: %s  process: %s  time: %s\n",
                     subsystem.UTF8String, category.UTF8String, process.UTF8String,
                     timestamp.UTF8String);
            } else if (newInfo) {
              printf("[*] subsystem: %s  categories: %lu  processes: %lu  events: %lld  last: %s\n",
                     subsystem.UTF8String, (unsigned long)cats.count, (unsigned long)procs.count,
                     ((NSNumber*)entry[@"count"]).longLongValue,
                     [(entry[@"last"] ?: @"") UTF8String]);
            }
          }
        }
      };
      while (!DNCTLIsInterrupted() && task.isRunning) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
      }
      fh.readabilityHandler = nil;
      if (task.isRunning)
        [task terminate];
      DNCTLClearActiveChildPID();
      return;
    }

    if (showLogs || DNCTLGetOutputFormat() != DNOutputFormatText) {
      NSMutableArray<NSString*>* rawArgs = [NSMutableArray
          arrayWithArray:@[ @"show", @"--predicate", predicate, @"--last", last, @"--info" ]];
      [rawArgs addObject:@"--style"];
      [rawArgs addObject:(DNCTLGetOutputFormat() == DNOutputFormatJSON ? @"json" : @"compact")];
      CommandResult* result = DNCTLRunEnvCommand(@"/usr/bin/log", rawArgs);
      if (result.status != 0) {
        DNCTLLogError(result.stderrString ?: @"Failed to read logs for subsystem listing");
        exit(EXIT_FAILURE);
      }
      printf("%s\n", result.stdoutString.UTF8String);
      return;
    }

    if (DNCTLGetOutputFormat() == DNOutputFormatText) {
      if (filter.length) {
        DNCTLLogInfo([NSString
            stringWithFormat:@"Querying subsystems from unified log (last %@, filter: %@)...", last,
                             filter]);
      } else {
        DNCTLLogInfo(
            [NSString stringWithFormat:@"Querying subsystems from unified log (last %@)...", last]);
      }
    }

    NSArray<NSString*>* jsonArgs =
        @[ @"show", @"--predicate", predicate, @"--last", last, @"--info", @"--style", @"json" ];
    CommandResult* summary = DNCTLRunEnvCommand(@"/usr/bin/log", jsonArgs);
    if (summary.status != 0) {
      DNCTLLogError(summary.stderrString ?: @"Failed to read logs for subsystem summary");
      exit(EXIT_FAILURE);
    }

    NSArray<NSString*>* lines = [summary.stdoutString
        componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString* line in lines) {
      NSString* trim = DNCTLTrimmedString(line);
      if (!trim.length)
        continue;
      NSData* d = [trim dataUsingEncoding:NSUTF8StringEncoding];
      if (!d)
        continue;
      NSDictionary* obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
      if (![obj isKindOfClass:[NSDictionary class]])
        continue;

      NSString* subsystem = (obj[@"subsystem"] ?: @"");
      NSString* process = (obj[@"process"] ?: @"");
      NSString* category = (obj[@"category"] ?: @"");
      NSString* timestamp = (obj[@"timestamp"] ?: @"");

      if (!EntryMatchesSubsystemSelectors(selectors, subsystem, process))
        continue;

      if (filterLower.length) {
        NSString* subLower = [subsystem lowercaseString];
        NSString* procLower = [process lowercaseString];
        if (![subLower containsString:filterLower] && ![procLower containsString:filterLower])
          continue;
      }

      if (subsystem.length == 0)
        subsystem = process.length ? process : @"(none)";
      if (category.length == 0)
        category = @"(none)";
      if (process.length == 0)
        process = @"(unknown)";

      NSMutableDictionary* entry = bySubsystem[subsystem];
      if (!entry) {
        entry = [@{
          @"categories" : [NSMutableSet set],
          @"processes" : [NSMutableSet set],
          @"count" : @(0),
          @"first" : timestamp ?: @"",
          @"last" : timestamp ?: @""
        } mutableCopy];
        bySubsystem[subsystem] = entry;
      }
      if (timestamp.length) {
        NSString* first = entry[@"first"] ?: @"";
        NSString* lastTs = entry[@"last"] ?: @"";
        if (first.length == 0 || [timestamp compare:first] == NSOrderedAscending)
          entry[@"first"] = timestamp;
        if (lastTs.length == 0 || [timestamp compare:lastTs] == NSOrderedDescending)
          entry[@"last"] = timestamp;
      }
      if (category.length)
        [(NSMutableSet*)entry[@"categories"] addObject:category];
      if (process.length)
        [(NSMutableSet*)entry[@"processes"] addObject:process];
      NSNumber* cnt = entry[@"count"] ?: @(0);
      entry[@"count"] = @(cnt.longLongValue + 1);
    }

    printf("DNShield Subsystems (last %s)\n", last.UTF8String);
    if (bySubsystem.count == 0) {
      printf("No matching DNShield subsystem entries found. Try adjusting selectors or increasing "
             "--last.\n");
      return;
    }

    NSArray<NSString*>* sortedKeys = [[bySubsystem allKeys]
        sortedArrayUsingComparator:^NSComparisonResult(NSString* a, NSString* b) {
          long long ac = [bySubsystem[a][@"count"] longLongValue];
          long long bc = [bySubsystem[b][@"count"] longLongValue];
          if (ac == bc)
            return [a compare:b];
          return ac > bc ? NSOrderedAscending : NSOrderedDescending;
        }];

    for (NSString* subsystem in sortedKeys) {
      NSDictionary* entry = bySubsystem[subsystem];
      NSUInteger cats = [(NSSet*)entry[@"categories"] count];
      NSUInteger procs = [(NSSet*)entry[@"processes"] count];
      long long count = [entry[@"count"] longLongValue];
      NSString* lastTs = entry[@"last"] ?: @"";
      printf("[*] subsystem: %s  categories: %lu  processes: %lu  events: %lld  last: %s\n",
             subsystem.UTF8String, (unsigned long)cats, (unsigned long)procs, count,
             lastTs.UTF8String);
    }
    return;
  }
  if (args.count > 0 && [args[0] isEqualToString:@"categories"]) {
    NSArray<NSString*>* rest =
        args.count > 1 ? [args subarrayWithRange:NSMakeRange(1, args.count - 1)] : @[];
    DNOutputFormat fmt = DNOutputFormatText;
    NSArray<NSString*>* remaining = rest;
    if (DNCTLParseFormatFromArgs(rest, &fmt, (NSArray<NSString*>**)&remaining)) {
      DNCTLSetOutputFormat(fmt);
    }
    BOOL follow = NO;
    BOOL showLogs = YES;
    NSString* last = @"1h";
    NSString* filter = nil;
    NSMutableArray<NSString*>* includeCategoryTokens = [NSMutableArray array];
    NSMutableArray<NSString*>* excludeCategoryTokens = [NSMutableArray array];
    NSMutableArray<NSString*>* includeSubsystemSelectors = [NSMutableArray array];
    NSMutableArray<NSString*>* excludeSubsystemSelectors = [NSMutableArray array];

    for (NSInteger i = 0; i < (NSInteger)remaining.count; i++) {
      NSString* t = remaining[i];
      if ([t isEqualToString:@"--last"]) {
        if (i + 1 < (NSInteger)remaining.count) {
          last = remaining[i + 1];
          i++;
        }
      } else if ([t isEqualToString:@"-f"]) {
        follow = YES;
      } else if ([t isEqualToString:@"--filter"]) {
        if (i + 1 < (NSInteger)remaining.count) {
          filter = remaining[i + 1];
          i++;
        }
      } else if ([t isEqualToString:@"--show-logs"]) {
        showLogs = YES;
      } else if ([t isEqualToString:@"--summary"]) {
        showLogs = NO;
      } else if ([t isEqualToString:@"--include"]) {
        if (i + 1 >= (NSInteger)remaining.count) {
          DNCTLLogError(@"Missing value for --include");
          return;
        }
        NSString* value = remaining[++i];
        NSString* trim = DNCTLTrimmedString(value);
        NSString* lower = trim.lowercaseString;
        if ([lower hasPrefix:@"subsystem:"] || [lower hasPrefix:@"process:"]) {
          [includeSubsystemSelectors addObject:trim];
        } else if ([lower hasPrefix:@"category:"]) {
          [includeCategoryTokens addObject:NormalizeCategoryToken(trim)];
        } else {
          [includeCategoryTokens addObject:trim];
        }
      } else if ([t isEqualToString:@"--exclude"]) {
        if (i + 1 >= (NSInteger)remaining.count) {
          DNCTLLogError(@"Missing value for --exclude");
          return;
        }
        NSString* value = remaining[++i];
        NSString* trim = DNCTLTrimmedString(value);
        NSString* lower = trim.lowercaseString;
        if ([lower hasPrefix:@"subsystem:"] || [lower hasPrefix:@"process:"]) {
          [excludeSubsystemSelectors addObject:trim];
        } else if ([lower hasPrefix:@"category:"]) {
          [excludeCategoryTokens addObject:NormalizeCategoryToken(trim)];
        } else {
          [excludeCategoryTokens addObject:trim];
        }
      }
    }

    NSSet* known2 = [NSSet setWithArray:@[
      @"--last", @"-f", @"--filter", @"--show-logs", @"--summary", @"--include", @"--exclude",
      @"--help", @"-h", @"help", @"format"
    ]];
    if (DNCTLContainsUnknownFlag(remaining, known2)) {
      DNCTLLogError(@"Unknown option for 'logs categories'");
      PrintLogsUsage();
      return;
    }

    NSMutableArray<NSDictionary*>* selectors = nil;
    NSString* selectorError = nil;
    if (!ResolveSubsystemSelectors(includeSubsystemSelectors, excludeSubsystemSelectors, &selectors,
                                   &selectorError)) {
      DNCTLLogError(selectorError ?: @"Failed to resolve subsystem selectors");
      return;
    }

    NSMutableArray<NSString*>* categoryIncludes = [NSMutableArray array];
    NSMutableSet<NSString*>* categoryIncludeSet = [NSMutableSet set];
    for (NSString* token in includeCategoryTokens) {
      NSString* value = NormalizeCategoryToken(token);
      if (!value.length)
        continue;
      [categoryIncludes addObject:value];
      [categoryIncludeSet addObject:value.lowercaseString];
    }

    NSMutableArray<NSString*>* categoryExcludes = [NSMutableArray array];
    NSMutableSet<NSString*>* categoryExcludeSet = [NSMutableSet set];
    for (NSString* token in excludeCategoryTokens) {
      NSString* value = NormalizeCategoryToken(token);
      if (!value.length)
        continue;
      [categoryExcludes addObject:value];
      [categoryExcludeSet addObject:value.lowercaseString];
    }

    NSString* baseClause = PredicateClauseForSubsystemSelectors(selectors);
    if (!baseClause.length) {
      DNCTLLogError(@"No subsystem selectors available");
      return;
    }

    NSString* predicate = [NSString stringWithFormat:@"(%@)", baseClause];

    NSString* categoryIncludeClause = PredicateClauseForValues(@"category", categoryIncludes);
    if (categoryIncludeClause.length) {
      predicate = [NSString stringWithFormat:@"(%@) AND %@", predicate, categoryIncludeClause];
    }

    NSString* categoryExcludeClause = PredicateClauseForValues(@"category", categoryExcludes);
    if (categoryExcludeClause.length) {
      predicate = [NSString stringWithFormat:@"(%@) AND NOT %@", predicate, categoryExcludeClause];
    }

    if (filter.length) {
      NSString* filterClause =
          [NSString stringWithFormat:@"(category CONTAINS[c] \"%@\" OR subsystem CONTAINS[c] "
                                     @"\"%@\" OR process CONTAINS[c] \"%@\")",
                                     filter, filter, filter];
      predicate = [NSString stringWithFormat:@"(%@) AND %@", predicate, filterClause];
    }

    NSMutableDictionary<NSString*, NSMutableDictionary*>* byCategory =
        [NSMutableDictionary dictionary];
    NSString* filterLower = filter.lowercaseString;

    if (follow) {
      if (DNCTLGetOutputFormat() == DNOutputFormatYAML ||
          DNCTLGetOutputFormat() == DNOutputFormatPlist) {
        DNCTLLogWarning(@"YAML/PLIST not supported for streaming; using JSON lines");
        DNCTLSetOutputFormat(DNOutputFormatJSON);
      }
      if (DNCTLGetOutputFormat() == DNOutputFormatText) {
        if (filter.length) {
          DNCTLLogInfo([NSString
              stringWithFormat:@"Streaming categories (filter: %@). Ctrl+C to stop...", filter]);
        } else {
          DNCTLLogInfo(@"Streaming categories. Ctrl+C to stop...");
        }
      }
      NSTask* task = [NSTask new];
      task.launchPath = @"/usr/bin/log";
      task.arguments = @[ @"stream", @"--predicate", predicate, @"--info", @"--style", @"json" ];
      NSPipe* pipe = [NSPipe pipe];
      task.standardOutput = pipe;
      task.standardError = pipe;
      [task launch];

      NSFileHandle* fh = pipe.fileHandleForReading;
      NSMutableData* buffer = [NSMutableData data];
      fh.readabilityHandler = ^(NSFileHandle* h) {
        NSData* chunk = h.availableData;
        if (!chunk.length) {
          h.readabilityHandler = nil;
          return;
        }
        [buffer appendData:chunk];
        while (true) {
          const void* bytes = buffer.bytes;
          NSUInteger length = buffer.length;
          const void* nl = memchr(bytes, '\n', length);
          if (!nl)
            break;
          NSUInteger lineLen = (const char*)nl - (const char*)bytes;
          NSData* lineData = [NSData dataWithBytes:bytes length:lineLen];
          NSString* line = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
          [buffer replaceBytesInRange:NSMakeRange(0, lineLen + 1) withBytes:NULL length:0];

          NSString* trim = DNCTLTrimmedString(line);
          if (!trim.length)
            continue;
          NSData* d = [trim dataUsingEncoding:NSUTF8StringEncoding];
          if (!d)
            continue;
          NSDictionary* obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
          if (![obj isKindOfClass:[NSDictionary class]])
            continue;
          NSString* category = (obj[@"category"] ?: @"");
          if (category.length == 0)
            category = @"(none)";
          NSString* categoryLower = category.lowercaseString;
          if (categoryIncludeSet.count && ![categoryIncludeSet containsObject:categoryLower])
            continue;
          if (categoryExcludeSet.count && [categoryExcludeSet containsObject:categoryLower])
            continue;
          NSString* subsystem = (obj[@"subsystem"] ?: @"");
          if (subsystem.length == 0)
            subsystem = @"(none)";
          NSString* process = (obj[@"process"] ?: @"");
          if (process.length == 0)
            process = @"(unknown)";
          if (!EntryMatchesSubsystemSelectors(selectors, subsystem, process))
            continue;
          NSString* processLower = process.lowercaseString;
          BOOL matchesFilter = YES;
          if (filterLower.length) {
            matchesFilter = ([categoryLower containsString:filterLower] ||
                             [[subsystem lowercaseString] containsString:filterLower] ||
                             [processLower containsString:filterLower]);
          }
          if (!matchesFilter)
            continue;
          NSString* timestamp = (obj[@"timestamp"] ?: @"");

          NSMutableDictionary* entry = byCategory[category];
          BOOL isNew = NO;
          BOOL changed = NO;
          if (!entry) {
            entry = [@{
              @"subsystems" : [NSMutableSet set],
              @"processes" : [NSMutableSet set],
              @"count" : @(0),
              @"first" : timestamp ?: @"",
              @"last" : timestamp ?: @""
            } mutableCopy];
            byCategory[category] = entry;
            isNew = YES;
          }
          NSNumber* cnt = entry[@"count"] ?: @(0);
          entry[@"count"] = @(cnt.longLongValue + 1);
          if (timestamp.length) {
            NSString* first = entry[@"first"] ?: @"";
            NSString* lastS = entry[@"last"] ?: @"";
            if (first.length == 0 || [timestamp compare:first] == NSOrderedAscending)
              entry[@"first"] = timestamp;
            if (lastS.length == 0 || [timestamp compare:lastS] == NSOrderedDescending)
              entry[@"last"] = timestamp;
          }
          NSMutableSet* subs = entry[@"subsystems"];
          NSMutableSet* procs = entry[@"processes"];
          if (![subs containsObject:subsystem]) {
            [subs addObject:subsystem];
            changed = YES;
          }
          if (![procs containsObject:process]) {
            [procs addObject:process];
            changed = YES;
          }

          if (DNCTLGetOutputFormat() == DNOutputFormatJSON) {
            NSDictionary* update = @{
              @"type" : isNew ? @"new" : (changed ? @"updated" : @"event"),
              @"category" : category,
              @"subsystems" : [subs allObjects],
              @"processes" : [procs allObjects],
              @"count" : entry[@"count"],
              @"firstTimestamp" : entry[@"first"] ?: @"",
              @"lastTimestamp" : entry[@"last"] ?: @""
            };
            printf("%s\n", [DNCTLJSONStringFromObject(update) UTF8String]);
          } else {
            if (filterLower.length) {
              NSString* msg = obj[@"eventMessage"] ?: obj[@"composedMessage"] ?: @"";
              printf("%s %s [%s:%s] %s\n", [timestamp UTF8String], [process UTF8String],
                     [subsystem UTF8String], [category UTF8String], [msg UTF8String]);
            } else if (isNew) {
              printf("[+] category: %s  subsystem: %s  process: %s  time: %s\n",
                     category.UTF8String, subsystem.UTF8String, process.UTF8String,
                     timestamp.UTF8String);
            } else if (changed) {
              printf("[*] category: %s  subsystems: %lu  processes: %lu  events: %lld  last: %s\n",
                     category.UTF8String, (unsigned long)[(NSSet*)entry[@"subsystems"] count],
                     (unsigned long)[(NSSet*)entry[@"processes"] count],
                     ((NSNumber*)entry[@"count"]).longLongValue,
                     [(entry[@"last"] ?: @"") UTF8String]);
            }
          }
        }
      };
      while (!DNCTLIsInterrupted() && task.isRunning) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
      }
      fh.readabilityHandler = nil;
      if (task.isRunning)
        [task terminate];
      DNCTLClearActiveChildPID();
      return;
    }

    if (showLogs || DNCTLGetOutputFormat() != DNOutputFormatText) {
      NSMutableArray<NSString*>* rawArgs = [NSMutableArray
          arrayWithArray:@[ @"show", @"--predicate", predicate, @"--last", last, @"--info" ]];
      [rawArgs addObject:@"--style"];
      [rawArgs addObject:(DNCTLGetOutputFormat() == DNOutputFormatJSON ? @"json" : @"compact")];
      CommandResult* res = DNCTLRunEnvCommand(@"/usr/bin/log", rawArgs);
      if (res.status != 0) {
        DNCTLLogError(res.stderrString ?: @"Failed to read logs for categories");
        exit(EXIT_FAILURE);
      }
      printf("%s\n", res.stdoutString.UTF8String);
      return;
    }

    if (DNCTLGetOutputFormat() == DNOutputFormatText) {
      if (filter.length) {
        DNCTLLogInfo([NSString
            stringWithFormat:@"Querying categories from unified log (last %@, filter: %@)...", last,
                             filter]);
      } else {
        DNCTLLogInfo(
            [NSString stringWithFormat:@"Querying categories from unified log (last %@)...", last]);
      }
    }

    NSArray<NSString*>* jsonArgs =
        @[ @"show", @"--predicate", predicate, @"--last", last, @"--info", @"--style", @"json" ];
    CommandResult* summary = DNCTLRunEnvCommand(@"/usr/bin/log", jsonArgs);
    if (summary.status != 0) {
      DNCTLLogError(summary.stderrString ?: @"Failed to read logs for category summary");
      exit(EXIT_FAILURE);
    }

    NSArray<NSString*>* lines = [summary.stdoutString
        componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString* line in lines) {
      NSString* trim = DNCTLTrimmedString(line);
      if (!trim.length)
        continue;
      NSData* d = [trim dataUsingEncoding:NSUTF8StringEncoding];
      if (!d)
        continue;
      NSDictionary* obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
      if (![obj isKindOfClass:[NSDictionary class]])
        continue;

      NSString* category = (obj[@"category"] ?: @"");
      if (category.length == 0)
        category = @"(none)";
      NSString* categoryLower = category.lowercaseString;
      if (categoryIncludeSet.count && ![categoryIncludeSet containsObject:categoryLower])
        continue;
      if (categoryExcludeSet.count && [categoryExcludeSet containsObject:categoryLower])
        continue;

      NSString* subsystem = (obj[@"subsystem"] ?: @"");
      if (subsystem.length == 0)
        subsystem = @"(none)";
      NSString* process = (obj[@"process"] ?: @"");
      if (process.length == 0)
        process = @"(unknown)";
      if (!EntryMatchesSubsystemSelectors(selectors, subsystem, process))
        continue;
      NSString* processLower = process.lowercaseString;
      BOOL matchesFilter = YES;
      if (filterLower.length) {
        matchesFilter = ([categoryLower containsString:filterLower] ||
                         [[subsystem lowercaseString] containsString:filterLower] ||
                         [processLower containsString:filterLower]);
      }
      if (!matchesFilter)
        continue;
      NSString* timestamp = (obj[@"timestamp"] ?: @"");

      NSMutableDictionary* entry = byCategory[category];
      if (!entry) {
        entry = [@{
          @"subsystems" : [NSMutableSet set],
          @"processes" : [NSMutableSet set],
          @"count" : @(0),
          @"first" : timestamp ?: @"",
          @"last" : timestamp ?: @""
        } mutableCopy];
        byCategory[category] = entry;
      }
      NSNumber* cnt = entry[@"count"] ?: @(0);
      entry[@"count"] = @(cnt.longLongValue + 1);
      if (timestamp.length) {
        NSString* first = entry[@"first"] ?: @"";
        NSString* lastS = entry[@"last"] ?: @"";
        if (first.length == 0 || [timestamp compare:first] == NSOrderedAscending)
          entry[@"first"] = timestamp;
        if (lastS.length == 0 || [timestamp compare:lastS] == NSOrderedDescending)
          entry[@"last"] = timestamp;
      }
      [(NSMutableSet*)entry[@"subsystems"] addObject:subsystem];
      [(NSMutableSet*)entry[@"processes"] addObject:process];
    }

    printf("DNShield Categories (last %s)\n", last.UTF8String);
    if (byCategory.count == 0) {
      printf("No matching DNShield category entries found. Try adjusting selectors or increasing "
             "--last.\n");
      return;
    }

    NSArray<NSString*>* sortedCategories = [[byCategory allKeys]
        sortedArrayUsingComparator:^NSComparisonResult(NSString* a, NSString* b) {
          long long ac = [byCategory[a][@"count"] longLongValue];
          long long bc = [byCategory[b][@"count"] longLongValue];
          if (ac == bc)
            return [a compare:b];
          return ac > bc ? NSOrderedAscending : NSOrderedDescending;
        }];

    for (NSString* category in sortedCategories) {
      NSDictionary* entry = byCategory[category];
      NSUInteger subs = [(NSSet*)entry[@"subsystems"] count];
      NSUInteger procs = [(NSSet*)entry[@"processes"] count];
      long long count = [entry[@"count"] longLongValue];
      NSString* lastS = entry[@"last"] ?: @"";
      printf("[*] category: %s  subsystems: %lu  processes: %lu  events: %lld  last: %s\n",
             category.UTF8String, (unsigned long)subs, (unsigned long)procs, count,
             lastS.UTF8String);
    }
    return;
  }
  // Options: -f (follow), --last <duration>, format <fmt>
  BOOL follow = NO;
  NSString* last = @"1h";  // default last 1 hour

  DNOutputFormat fmt = DNOutputFormatText;
  NSArray<NSString*>* remaining = args;
  if (DNCTLParseFormatFromArgs(args, &fmt, (NSArray<NSString*>**)&remaining)) {
    DNCTLSetOutputFormat(fmt);
  }

  for (NSInteger i = 0; i < (NSInteger)remaining.count; i++) {
    NSString* t = remaining[i];
    if ([t isEqualToString:@"-f"]) {
      follow = YES;
    } else if ([t isEqualToString:@"--last"]) {
      if (i + 1 < (NSInteger)remaining.count) {
        last = remaining[i + 1];
        i++;
      }
    }
  }

  NSSet* known3 = [NSSet setWithArray:@[ @"-f", @"--last", @"--help", @"-h", @"help", @"format" ]];
  if (DNCTLContainsUnknownFlag(remaining, known3)) {
    DNCTLLogError(@"Unknown option for 'logs'");
    PrintLogsUsage();
    return;
  }

  // Unified logging via `/usr/bin/log`
  NSString* predicate = BasePredicate();

  NSMutableArray<NSString*>* logArgs = [NSMutableArray array];
  if (follow) {
    [logArgs addObject:@"stream"];
  } else {
    [logArgs addObject:@"show"];
  }
  [logArgs addObject:@"--predicate"];
  [logArgs addObject:predicate];
  if (!follow) {
    [logArgs addObject:@"--last"];
    [logArgs addObject:last];
  }
  [logArgs addObject:@"--info"];
  [logArgs addObject:@"--style"];
  [logArgs addObject:(DNCTLGetOutputFormat() == DNOutputFormatJSON ? @"json" : @"compact")];

  if (follow) {
    if (DNCTLGetOutputFormat() == DNOutputFormatYAML ||
        DNCTLGetOutputFormat() == DNOutputFormatPlist) {
      DNCTLLogWarning(@"YAML/PLIST output not supported for streaming; using JSON lines");
      [logArgs removeLastObject];
      [logArgs addObject:@"json"];
    }
    if (DNCTLGetOutputFormat() == DNOutputFormatText) {
      DNCTLLogInfo(@"Streaming unified logs. Ctrl+C to stop...");
    }
    DNCTLRunStreamingCommand(@"/usr/bin/log", logArgs);
    return;
  }

  if (DNCTLGetOutputFormat() == DNOutputFormatText) {
    DNCTLLogInfo([NSString
        stringWithFormat:@"Querying unified log (last %@)... This may take a while.", last]);
  }
  CommandResult* res = DNCTLRunEnvCommand(@"/usr/bin/log", logArgs);
  if (res.status != 0) {
    DNCTLLogError(res.stderrString ?: @"Failed to read logs from unified log");
    exit(EXIT_FAILURE);
  }

  if (DNCTLGetOutputFormat() == DNOutputFormatText ||
      DNCTLGetOutputFormat() == DNOutputFormatJSON) {
    printf("%s\n", res.stdoutString.UTF8String);
    return;
  }

  // Convert JSONL to array then emit YAML/PLIST
  NSMutableArray* events = [NSMutableArray array];
  NSArray<NSString*>* lines =
      [res.stdoutString componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
  for (NSString* line in lines) {
    NSString* trim = DNCTLTrimmedString(line);
    if (!trim.length)
      continue;
    NSData* d = [trim dataUsingEncoding:NSUTF8StringEncoding];
    if (!d)
      continue;
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (obj)
      [events addObject:obj];
  }
  DNCTLPrintObject(events, DNCTLGetOutputFormat());
}
