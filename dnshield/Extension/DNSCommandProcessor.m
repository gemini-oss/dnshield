//
//  DNSCommandProcessor.m
//  DNShield Network Extension
//
//  Filesystem-based command processing with FSEvents monitoring
//

#import <os/log.h>

#import <Common/Defaults.h>
#import <Common/LoggingManager.h>

#import "DNSCommandProcessor.h"

static os_log_t logHandle;

@interface DNSCommandProcessor ()
@property(nonatomic, assign) FSEventStreamRef eventStream;
@property(nonatomic, strong) dispatch_queue_t processingQueue;
@property(nonatomic, strong) NSDateFormatter* dateFormatter;
@property(nonatomic, strong) NSMutableSet<NSString*>* processedCommands;
@property(nonatomic, strong) dispatch_queue_t deduplicationQueue;
@property(nonatomic, strong) dispatch_source_t cleanupTimer;
@end

@implementation DNSCommandProcessor

+ (void)initialize {
  if (self == [DNSCommandProcessor class]) {
    logHandle = DNCreateLogHandle(kDefaultExtensionBundleID, @"CommandProcessor");
  }
}

+ (instancetype)sharedProcessor {
  static DNSCommandProcessor* sharedProcessor = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedProcessor = [[DNSCommandProcessor alloc] init];
  });
  return sharedProcessor;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    // Create command directories
    NSString* baseDir = @"/Library/Application Support/DNShield/Commands";
    _commandDirectory = [baseDir stringByAppendingPathComponent:@"incoming"];
    _responseDirectory = [baseDir stringByAppendingPathComponent:@"responses"];

    NSFileManager* fm = [NSFileManager defaultManager];
    NSError* error = nil;

    // Create directories with proper permissions
    NSDictionary* attrs = @{
      NSFilePosixPermissions : @(0755),
      NSFileOwnerAccountName : @"root",
      NSFileGroupOwnerAccountName : @"wheel"
    };

    if (![fm createDirectoryAtPath:_commandDirectory
            withIntermediateDirectories:YES
                             attributes:attrs
                                  error:&error]) {
      os_log_error(logHandle, "Failed to create command directory: %{public}@", error);
    }

    if (![fm createDirectoryAtPath:_responseDirectory
            withIntermediateDirectories:YES
                             attributes:attrs
                                  error:&error]) {
      os_log_error(logHandle, "Failed to create response directory: %{public}@", error);
    }

    _processingQueue =
        dispatch_queue_create("com.dnshield.commandprocessor", DISPATCH_QUEUE_SERIAL);
    _deduplicationQueue =
        dispatch_queue_create("com.dnshield.commandprocessor.dedup", DISPATCH_QUEUE_SERIAL);
    _processedCommands = [[NSMutableSet alloc] init];

    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy-MM-dd_HH-mm-ss-SSS";

    // Set up cleanup timer to run every 10 minutes using GCD
    _cleanupTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _processingQueue);
    dispatch_source_set_timer(
        _cleanupTimer,
        dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC),  // Start after 10 minutes
        600 * NSEC_PER_SEC,                                    // Repeat every 10 minutes
        60 * NSEC_PER_SEC);                                    // 1 minute leeway
    dispatch_source_set_event_handler(_cleanupTimer, ^{
      [self cleanupOldFiles];
    });
    dispatch_resume(_cleanupTimer);

    os_log_info(logHandle, "Command processor initialized. Commands: %{public}@",
                _commandDirectory);
  }
  return self;
}

- (void)dealloc {
  [self stopMonitoring];
  if (_cleanupTimer) {
    dispatch_source_cancel(_cleanupTimer);
    _cleanupTimer = nil;
  }
}

#pragma mark - FSEvents Monitoring

static void FSEventCallback(ConstFSEventStreamRef streamRef, void* clientCallBackInfo,
                            size_t numEvents, void* eventPaths,
                            const FSEventStreamEventFlags eventFlags[],
                            const FSEventStreamEventId eventIds[]) {
  DNSCommandProcessor* processor = (__bridge DNSCommandProcessor*)clientCallBackInfo;
  NSArray* paths = (__bridge NSArray*)eventPaths;

  for (NSUInteger i = 0; i < numEvents; i++) {
    NSString* path = paths[i];
    FSEventStreamEventFlags flags = eventFlags[i];

    // Check if it's a new file in our command directory
    if ((flags & kFSEventStreamEventFlagItemCreated) ||
        (flags & kFSEventStreamEventFlagItemModified)) {
      if ([path hasPrefix:processor.commandDirectory] && [path hasSuffix:@".json"]) {
        os_log_info(logHandle, "New command file detected: %{public}@", path);
        [processor processCommandFile:path];
      }
    }
  }
}

- (BOOL)startMonitoring {
  if (self.eventStream) {
    os_log_info(logHandle, "Monitoring already started");
    return YES;
  }

  // Process any existing command files first
  [self processExistingCommands];

  // Set up FSEvents
  NSArray* pathsToWatch = @[ self.commandDirectory ];
  FSEventStreamContext context = {0, (__bridge void*)self, NULL, NULL, NULL};

  self.eventStream =
      FSEventStreamCreate(NULL, &FSEventCallback, &context, (__bridge CFArrayRef)pathsToWatch,
                          kFSEventStreamEventIdSinceNow,
                          0.1,  // 100ms latency
                          kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes);

  if (!self.eventStream) {
    os_log_error(logHandle, "Failed to create FSEventStream");
    return NO;
  }

  FSEventStreamSetDispatchQueue(self.eventStream, self.processingQueue);

  if (!FSEventStreamStart(self.eventStream)) {
    os_log_error(logHandle, "Failed to start FSEventStream");
    FSEventStreamRelease(self.eventStream);
    self.eventStream = NULL;
    return NO;
  }

  os_log_info(logHandle, "Started monitoring command directory");
  return YES;
}

- (void)stopMonitoring {
  if (self.eventStream) {
    FSEventStreamStop(self.eventStream);
    FSEventStreamInvalidate(self.eventStream);
    FSEventStreamRelease(self.eventStream);
    self.eventStream = NULL;
    os_log_info(logHandle, "Stopped monitoring command directory");
  }
}

#pragma mark - Command Processing

- (void)processExistingCommands {
  dispatch_async(self.processingQueue, ^{
    NSFileManager* fm = [NSFileManager defaultManager];
    NSError* error = nil;

    NSArray* files = [fm contentsOfDirectoryAtPath:self.commandDirectory error:&error];
    if (error) {
      os_log_error(logHandle, "Failed to list command directory: %{public}@", error);
      return;
    }

    // Sort files by creation date to process in order
    NSMutableArray* commandFiles = [NSMutableArray array];
    for (NSString* file in files) {
      if ([file hasSuffix:@".json"]) {
        NSString* fullPath = [self.commandDirectory stringByAppendingPathComponent:file];
        [commandFiles addObject:fullPath];
      }
    }

    [commandFiles sortUsingComparator:^NSComparisonResult(NSString* path1, NSString* path2) {
      NSDictionary* attrs1 = [fm attributesOfItemAtPath:path1 error:nil];
      NSDictionary* attrs2 = [fm attributesOfItemAtPath:path2 error:nil];
      NSDate* date1 = attrs1[NSFileCreationDate];
      NSDate* date2 = attrs2[NSFileCreationDate];
      return [date1 compare:date2];
    }];

    for (NSString* commandFile in commandFiles) {
      [self processCommandFile:commandFile];
    }
  });
}

- (void)processCommandFile:(NSString*)path {
  // Extract command ID from filename for deduplication
  NSString* filename = [path lastPathComponent];
  NSString* commandId = [filename stringByDeletingPathExtension];

  // Use deduplication queue to check/mark command as processed atomically
  dispatch_async(self.deduplicationQueue, ^{
    // Check if we've already processed this command
    if ([self.processedCommands containsObject:commandId]) {
      os_log_info(logHandle, "Command %{public}@ already processed, skipping duplicate", commandId);
      return;
    }

    // Mark command as being processed
    [self.processedCommands addObject:commandId];

    // Clean up old processed commands to prevent memory growth (keep last 100)
    if (self.processedCommands.count > 100) {
      NSArray* allCommands = [self.processedCommands allObjects];
      NSArray* sorted = [allCommands
          sortedArrayUsingComparator:^NSComparisonResult(NSString* obj1, NSString* obj2) {
            return [obj1 compare:obj2];
          }];
      NSRange rangeToRemove = NSMakeRange(0, sorted.count - 50);
      for (NSString* oldCommand in [sorted subarrayWithRange:rangeToRemove]) {
        [self.processedCommands removeObject:oldCommand];
      }
    }

    // Now process the command
    dispatch_async(self.processingQueue, ^{
      NSFileManager* fm = [NSFileManager defaultManager];
      NSError* error = nil;

      // Read command file
      NSData* data = [NSData dataWithContentsOfFile:path options:0 error:&error];
      if (!data) {
        os_log_error(logHandle, "Failed to read command file %{public}@: %{public}@", path, error);
        // Remove file if it exists (might have been deleted by another thread)
        if ([fm fileExistsAtPath:path]) {
          [fm removeItemAtPath:path error:nil];
        }
        return;
      }

      // Parse JSON
      NSDictionary* command = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
      if (!command || error) {
        os_log_error(logHandle, "Failed to parse command file %{public}@: %{public}@", path, error);
        [fm removeItemAtPath:path error:nil];
        return;
      }

      os_log_info(logHandle, "Processing command %{public}@ of type: %{public}@", commandId,
                  command[@"type"]);

      // Delete command file immediately to prevent reprocessing
      [fm removeItemAtPath:path error:nil];

      // Process command via delegate
      if ([self.delegate respondsToSelector:@selector(processCommand:)]) {
        NSMutableDictionary* commandWithId = [command mutableCopy];
        commandWithId[@"commandId"] = commandId;

        dispatch_async(dispatch_get_main_queue(), ^{
          [self.delegate processCommand:commandWithId];
        });
      }
    });
  });
}

#pragma mark - Response Writing

- (BOOL)writeResponse:(NSDictionary*)response
           forCommand:(NSString*)commandId
                error:(NSError**)error {
  NSString* filename = [NSString stringWithFormat:@"%@_response.json", commandId];
  NSString* path = [self.responseDirectory stringByAppendingPathComponent:filename];

  NSData* data = [NSJSONSerialization dataWithJSONObject:response
                                                 options:NSJSONWritingPrettyPrinted
                                                   error:error];
  if (!data) {
    return NO;
  }

  BOOL success = [data writeToFile:path options:NSDataWritingAtomic error:error];

  if (success) {
    // Set permissions so app can read it
    NSDictionary* attrs = @{NSFilePosixPermissions : @(0644)};
    [[NSFileManager defaultManager] setAttributes:attrs ofItemAtPath:path error:nil];

    os_log_info(logHandle, "Wrote response for command %{public}@ to %{public}@", commandId, path);
  } else {
    os_log_error(logHandle, "Failed to write response for command %{public}@: %{public}@",
                 commandId, *error);
  }

  return success;
}

#pragma mark - Cleanup

- (void)cleanupOldFiles {
  dispatch_async(self.processingQueue, ^{
    //        NSFileManager *fm = [NSFileManager defaultManager];
    NSDate* cutoffDate = [NSDate dateWithTimeIntervalSinceNow:-3600];  // 1 hour old

    // Clean up old command files
    [self cleanupFilesInDirectory:self.commandDirectory olderThan:cutoffDate];

    // Clean up old response files
    [self cleanupFilesInDirectory:self.responseDirectory olderThan:cutoffDate];
  });
}

- (void)cleanupFilesInDirectory:(NSString*)directory olderThan:(NSDate*)cutoffDate {
  NSFileManager* fm = [NSFileManager defaultManager];
  NSError* error = nil;

  NSArray* files = [fm contentsOfDirectoryAtPath:directory error:&error];
  if (error) {
    os_log_error(logHandle, "Failed to list directory %{public}@: %{public}@", directory, error);
    return;
  }

  NSUInteger deletedCount = 0;

  for (NSString* file in files) {
    NSString* fullPath = [directory stringByAppendingPathComponent:file];
    NSDictionary* attrs = [fm attributesOfItemAtPath:fullPath error:nil];
    NSDate* creationDate = attrs[NSFileCreationDate];

    if (creationDate && [creationDate compare:cutoffDate] == NSOrderedAscending) {
      if ([fm removeItemAtPath:fullPath error:&error]) {
        deletedCount++;
      } else {
        os_log_error(logHandle, "Failed to delete old file %{public}@: %{public}@", fullPath,
                     error);
      }
    }
  }

  if (deletedCount > 0) {
    os_log_info(logHandle, "Cleaned up %lu old files from %{public}@", (unsigned long)deletedCount,
                directory);
  }
}

@end
