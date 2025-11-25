//
//  FileRuleFetcher.m
//  DNShield Network Extension
//
//  File-based rule fetching with file system monitoring
//

#import "FileRuleFetcher.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <CoreServices/CoreServices.h>

// Configuration keys
NSString* const FileRuleFetcherConfigKeyPath = @"path";
NSString* const FileRuleFetcherConfigKeyWatchForChanges = @"watchForChanges";
NSString* const FileRuleFetcherConfigKeyCheckInterval = @"checkInterval";
NSString* const FileRuleFetcherConfigKeyFollowSymlinks = @"followSymlinks";
NSString* const FileRuleFetcherConfigKeyMaxFileSize = @"maxFileSize";

// Notifications
NSString* const FileRuleFetcherFileDidChangeNotification =
    @"FileRuleFetcherFileDidChangeNotification";
NSString* const FileRuleFetcherNotificationKeyPath = @"path";

@interface FileRuleFetcher ()
@property(nonatomic, strong) NSFileManager* fileManager;
@property(nonatomic, strong) dispatch_queue_t fileQueue;
@property(nonatomic, strong) dispatch_source_t fileWatcher;
@property(nonatomic, strong) dispatch_source_t pollingTimer;
@property(nonatomic, assign) BOOL followSymlinks;
@property(nonatomic, assign) NSUInteger maxFileSize;
@property(nonatomic, assign) NSTimeInterval checkInterval;
@property(nonatomic, strong) NSDate* lastFetchModificationDate;
@property(nonatomic, assign) FSEventStreamRef eventStream;
@property(nonatomic, strong) NSString* resolvedFilePath;
@end

@implementation FileRuleFetcher

#pragma mark - Initialization

- (instancetype)initWithFilePath:(NSString*)filePath {
  return [self initWithFilePath:filePath configuration:nil];
}

- (instancetype)initWithFilePath:(NSString*)filePath
                   configuration:(nullable NSDictionary*)configuration {
  NSMutableDictionary* config = [NSMutableDictionary dictionaryWithDictionary:configuration ?: @{}];
  config[FileRuleFetcherConfigKeyPath] = filePath;

  self = [super initWithConfiguration:config];
  if (self) {
    _filePath = filePath;
    _fileManager = [[NSFileManager alloc] init];
    _followSymlinks = YES;
    _watchForChanges = NO;
    _checkInterval = 5.0;              // Default 5 seconds
    _maxFileSize = 100 * 1024 * 1024;  // Default 100MB

    NSString* queueLabel =
        [NSString stringWithFormat:@"com.dnshield.filefetcher.%@", self.identifier];
    _fileQueue = dispatch_queue_create([queueLabel UTF8String], DISPATCH_QUEUE_SERIAL);

    [self applyFileConfiguration:configuration];

    DNSLogDebug(LogCategoryRuleFetching, "FileRuleFetcher initialized for path: %@", filePath);
  }
  return self;
}

- (void)dealloc {
  [self stopWatching];
}

#pragma mark - Configuration

- (void)applyFileConfiguration:(NSDictionary*)config {
  if (!config)
    return;

  NSNumber* watchForChanges = config[FileRuleFetcherConfigKeyWatchForChanges];
  if (watchForChanges) {
    _watchForChanges = [watchForChanges boolValue];
  }

  NSNumber* checkInterval = config[FileRuleFetcherConfigKeyCheckInterval];
  if (checkInterval) {
    self.checkInterval = [checkInterval doubleValue];
  }

  NSNumber* followSymlinks = config[FileRuleFetcherConfigKeyFollowSymlinks];
  if (followSymlinks) {
    self.followSymlinks = [followSymlinks boolValue];
  }

  NSNumber* maxFileSize = config[FileRuleFetcherConfigKeyMaxFileSize];
  if (maxFileSize) {
    self.maxFileSize = [maxFileSize unsignedIntegerValue];
  }
}

#pragma mark - File Validation

- (BOOL)fileExists {
  NSString* path = [self resolvedPath];
  return path && [self.fileManager fileExistsAtPath:path];
}

- (BOOL)isFileReadable {
  NSString* path = [self resolvedPath];
  return path && [self.fileManager isReadableFileAtPath:path];
}

- (nullable NSString*)resolvedPath {
  if (self.resolvedFilePath) {
    return self.resolvedFilePath;
  }

  if (!self.filePath) {
    return nil;
  }

  NSString* expandedPath = [self.filePath stringByExpandingTildeInPath];

  if (!self.followSymlinks) {
    self.resolvedFilePath = expandedPath;
    return expandedPath;
  }

  // Resolve symlinks
  NSError* error;
  NSString* resolvedPath = [self.fileManager destinationOfSymbolicLinkAtPath:expandedPath
                                                                       error:&error];

  if (error) {
    // Not a symlink or error reading it, use original path
    self.resolvedFilePath = expandedPath;
  } else {
    // Make absolute if relative
    if (![resolvedPath isAbsolutePath]) {
      NSString* directory = [expandedPath stringByDeletingLastPathComponent];
      resolvedPath = [directory stringByAppendingPathComponent:resolvedPath];
    }
    self.resolvedFilePath = resolvedPath;
  }

  return self.resolvedFilePath;
}

- (BOOL)validateConfiguration:(NSError**)error {
  if (!self.filePath || self.filePath.length == 0) {
    if (error) {
      *error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorInvalidURL,
                            @"File path is required");
    }
    return NO;
  }

  if (![self fileExists]) {
    if (error) {
      *error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorFileMissing,
                            [NSString stringWithFormat:@"File not found: %@", self.filePath]);
    }
    return NO;
  }

  if (![self isFileReadable]) {
    if (error) {
      *error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorPermissionDenied,
                            [NSString stringWithFormat:@"File not readable: %@", self.filePath]);
    }
    return NO;
  }

  return YES;
}

#pragma mark - File Attributes

- (NSDictionary*)fileAttributes {
  NSString* path = [self resolvedPath];
  if (!path)
    return nil;

  NSError* error;
  NSDictionary* attributes = [self.fileManager attributesOfItemAtPath:path error:&error];

  if (error) {
    DNSLogError(LogCategoryRuleFetching, "Failed to get file attributes: %@", error);
    return nil;
  }

  return attributes;
}

- (NSDate*)lastModifiedDate {
  return self.fileAttributes[NSFileModificationDate];
}

- (NSUInteger)fileSize {
  NSNumber* size = self.fileAttributes[NSFileSize];
  return size ? [size unsignedIntegerValue] : 0;
}

- (BOOL)hasFileChangedSinceLastFetch {
  if (!self.lastFetchModificationDate) {
    return YES;  // Never fetched
  }

  NSDate* currentModDate = self.lastModifiedDate;
  if (!currentModDate) {
    return NO;  // Can't determine
  }

  return [currentModDate compare:self.lastFetchModificationDate] == NSOrderedDescending;
}

#pragma mark - RuleFetcher Override

- (void)performFetchWithCompletion:(RuleFetcherCompletionBlock)completion {
  dispatch_async(self.fileQueue, ^{
    NSString* path = [self resolvedPath];
    if (!path) {
      NSError* error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorFileMissing,
                                    @"Invalid file path");
      completion(nil, error);
      return;
    }

    // Check file size
    NSUInteger fileSize = [self fileSize];
    if (fileSize > self.maxFileSize) {
      NSError* error = DNSMakeError(
          DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorDataCorrupted,
          [NSString stringWithFormat:@"File too large: %lu bytes (max: %lu)",
                                     (unsigned long)fileSize, (unsigned long)self.maxFileSize]);
      completion(nil, error);
      return;
    }

    DNSLogInfo(LogCategoryRuleFetching, "Reading file: %@ (%lu bytes)", path,
               (unsigned long)fileSize);

    // Read file
    NSError* error;
    NSData* data = [NSData dataWithContentsOfFile:path
                                          options:NSDataReadingMappedIfSafe
                                            error:&error];

    if (error) {
      DNSLogError(LogCategoryRuleFetching, "Failed to read file: %@", error);
      completion(nil, error);
      return;
    }

    // Update last fetch date
    self.lastFetchModificationDate = self.lastModifiedDate;

    // Simulate progress for consistency
    [self notifyProgress:0.5];
    [self notifyProgress:1.0];

    DNSLogInfo(LogCategoryRuleFetching, "File read successfully: %lu bytes",
               (unsigned long)data.length);

    completion(data, nil);
  });
}

- (void)performCancelFetch {
  // File reads are typically fast and non-cancellable
  // But we can set a flag if needed for future implementation
}

- (BOOL)supportsResume {
  return NO;  // File reads don't support resume
}

#pragma mark - File Watching

- (void)startWatching {
  if (self.isWatching) {
    return;
  }

  NSString* path = [self resolvedPath];
  if (!path) {
    DNSLogError(LogCategoryRuleFetching, "Cannot watch invalid file path");
    return;
  }

  DNSLogInfo(LogCategoryRuleFetching, "Starting file watch for: %@", path);

  // Try FSEvents first (preferred on macOS)
  if ([self setupFSEventsForPath:path]) {
    return;
  }

  // Fallback to dispatch source
  if ([self setupDispatchSourceForPath:path]) {
    return;
  }

  // Final fallback to polling
  [self setupPollingForPath:path];
}

- (void)stopWatching {
  DNSLogInfo(LogCategoryRuleFetching, "Stopping file watch");

  if (self.eventStream) {
    FSEventStreamStop(self.eventStream);
    FSEventStreamInvalidate(self.eventStream);
    FSEventStreamRelease(self.eventStream);
    self.eventStream = NULL;
  }

  if (self.fileWatcher) {
    dispatch_source_cancel(self.fileWatcher);
    self.fileWatcher = nil;
  }

  if (self.pollingTimer) {
    dispatch_source_cancel(self.pollingTimer);
    self.pollingTimer = nil;
  }
}

- (BOOL)isWatching {
  return (self.eventStream != NULL || self.fileWatcher != nil || self.pollingTimer != nil);
}

#pragma mark - File Watching Implementation

- (BOOL)setupFSEventsForPath:(NSString*)path {
  // FSEvents watches directories, not files
  NSString* directory = [path stringByDeletingLastPathComponent];
  // NSString *filename = [path lastPathComponent]; // Not used

  FSEventStreamContext context = {0, (__bridge void*)self, NULL, NULL, NULL};

  NSArray* pathsToWatch = @[ directory ];

  self.eventStream =
      FSEventStreamCreate(NULL, &FileSystemEventCallback, &context,
                          (__bridge CFArrayRef)pathsToWatch, kFSEventStreamEventIdSinceNow,
                          1.0,  // Latency in seconds
                          kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot);

  if (!self.eventStream) {
    DNSLogError(LogCategoryRuleFetching, "Failed to create FSEventStream");
    return NO;
  }

  FSEventStreamSetDispatchQueue(self.eventStream, self.fileQueue);

  if (!FSEventStreamStart(self.eventStream)) {
    FSEventStreamInvalidate(self.eventStream);
    FSEventStreamRelease(self.eventStream);
    self.eventStream = NULL;
    DNSLogError(LogCategoryRuleFetching, "Failed to start FSEventStream");
    return NO;
  }

  DNSLogDebug(LogCategoryRuleFetching, "Started FSEvents monitoring for directory: %@", directory);
  return YES;
}

static void FileSystemEventCallback(ConstFSEventStreamRef streamRef, void* clientCallBackInfo,
                                    size_t numEvents, void* eventPaths,
                                    const FSEventStreamEventFlags eventFlags[],
                                    const FSEventStreamEventId eventIds[]) {
  FileRuleFetcher* fetcher = (__bridge FileRuleFetcher*)clientCallBackInfo;
  NSArray* paths = (__bridge NSArray*)eventPaths;

  NSString* watchedPath = [fetcher resolvedPath];
  NSString* watchedFilename = [watchedPath lastPathComponent];

  for (NSUInteger i = 0; i < numEvents; i++) {
    NSString* eventPath = paths[i];

    // Check if this event is for our file
    if ([eventPath isEqualToString:watchedPath] ||
        [[eventPath lastPathComponent] isEqualToString:watchedFilename]) {
      FSEventStreamEventFlags flags = eventFlags[i];

      if (flags & kFSEventStreamEventFlagItemModified ||
          flags & kFSEventStreamEventFlagItemCreated ||
          flags & kFSEventStreamEventFlagItemRenamed) {
        DNSLogInfo(LogCategoryRuleFetching, "File change detected: %@", eventPath);
        [fetcher fileDidChange];
        break;
      }
    }
  }
}

- (BOOL)setupDispatchSourceForPath:(NSString*)path {
  int fd = open([path UTF8String], O_EVTONLY);
  if (fd < 0) {
    DNSLogError(LogCategoryRuleFetching, "Failed to open file for monitoring: %s", strerror(errno));
    return NO;
  }

  dispatch_source_t source = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_VNODE, fd,
      DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_ATTRIB |
          DISPATCH_VNODE_LINK | DISPATCH_VNODE_RENAME | DISPATCH_VNODE_REVOKE,
      self.fileQueue);

  if (!source) {
    close(fd);
    DNSLogError(LogCategoryRuleFetching, "Failed to create dispatch source");
    return NO;
  }

  __weak typeof(self) weakSelf = self;

  dispatch_source_set_event_handler(source, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    unsigned long flags = dispatch_source_get_data(source);

    DNSLogDebug(LogCategoryRuleFetching, "File event flags: 0x%lx", flags);

    if (flags & DISPATCH_VNODE_DELETE) {
      DNSLogInfo(LogCategoryRuleFetching, "Watched file was deleted");
      dispatch_source_cancel(source);
    } else if (flags & (DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND)) {
      DNSLogInfo(LogCategoryRuleFetching, "File content changed");
      [strongSelf fileDidChange];
    } else if (flags & DISPATCH_VNODE_RENAME) {
      DNSLogInfo(LogCategoryRuleFetching, "File was renamed");
      [strongSelf fileDidChange];
    }
  });

  dispatch_source_set_cancel_handler(source, ^{
    close(fd);
  });

  self.fileWatcher = source;
  dispatch_resume(source);

  DNSLogDebug(LogCategoryRuleFetching, "Started dispatch source monitoring for: %@", path);
  return YES;
}

- (void)setupPollingForPath:(NSString*)path {
  DNSLogInfo(LogCategoryRuleFetching, "Using polling fallback with interval: %.1f seconds",
             self.checkInterval);

  dispatch_source_t timer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.fileQueue);

  dispatch_source_set_timer(
      timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.checkInterval * NSEC_PER_SEC)),
      (int64_t)(self.checkInterval * NSEC_PER_SEC),
      (int64_t)(0.1 * NSEC_PER_SEC));  // 10% leeway

  __weak typeof(self) weakSelf = self;
  dispatch_source_set_event_handler(timer, ^{
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    if ([strongSelf hasFileChangedSinceLastFetch]) {
      DNSLogInfo(LogCategoryRuleFetching, "Polling detected file change");
      [strongSelf fileDidChange];
    }
  });

  self.pollingTimer = timer;
  dispatch_resume(timer);
}

- (void)fileDidChange {
  dispatch_async(self.fileQueue, ^{
    // Update modification date
    self.lastFetchModificationDate = nil;  // Force re-fetch

    // Notify delegate
    if ([self.delegate respondsToSelector:@selector(ruleFetcher:didUpdateProgress:)]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self.delegate ruleFetcher:self didUpdateProgress:0.0];
      });
    }

    // Post notification
    [[NSNotificationCenter defaultCenter]
        postNotificationName:FileRuleFetcherFileDidChangeNotification
                      object:self
                    userInfo:@{
                      FileRuleFetcherNotificationKeyPath : self.filePath,
                      RuleFetcherNotificationKeyIdentifier : self.identifier
                    }];
  });
}

@end
