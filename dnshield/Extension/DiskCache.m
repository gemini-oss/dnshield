//
//  DiskCache.m
//  DNShield Network Extension
//
//  Implementation of persistent disk cache
//

#import "DiskCache.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <CommonCrypto/CommonDigest.h>

static NSString* const kDiskCacheMetadataFile = @"cache_metadata.plist";
static NSString* const kDiskCacheVersion = @"1.0";

@interface DiskCacheMetadata : NSObject <NSCoding, NSSecureCoding>
@property(nonatomic, strong) NSString* version;
@property(nonatomic, strong) NSDate* createdDate;
@property(nonatomic, strong) NSDate* lastMaintenanceDate;
@property(nonatomic, assign) NSUInteger totalSize;
@property(nonatomic, assign) NSUInteger entryCount;
@end

@implementation DiskCacheMetadata

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.version forKey:@"version"];
  [coder encodeObject:self.createdDate forKey:@"createdDate"];
  [coder encodeObject:self.lastMaintenanceDate forKey:@"lastMaintenanceDate"];
  [coder encodeInteger:self.totalSize forKey:@"totalSize"];
  [coder encodeInteger:self.entryCount forKey:@"entryCount"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  self = [super init];
  if (self) {
    _version = [coder decodeObjectOfClass:[NSString class] forKey:@"version"];
    _createdDate = [coder decodeObjectOfClass:[NSDate class] forKey:@"createdDate"];
    _lastMaintenanceDate = [coder decodeObjectOfClass:[NSDate class] forKey:@"lastMaintenanceDate"];
    _totalSize = [coder decodeIntegerForKey:@"totalSize"];
    _entryCount = [coder decodeIntegerForKey:@"entryCount"];
  }
  return self;
}

@end

@interface DiskCache ()
@property(nonatomic, strong) NSString* cacheDirectory;
@property(nonatomic, assign) NSUInteger maxSize;
@property(nonatomic, strong) dispatch_queue_t diskQueue;
@property(nonatomic, strong) NSFileManager* fileManager;
@property(nonatomic, strong) DiskCacheMetadata* metadata;
@end

@implementation DiskCache

- (instancetype)initWithDirectory:(NSString*)directory maxSize:(NSUInteger)maxSize {
  self = [super init];
  if (self) {
    _cacheDirectory = directory;
    _maxSize = maxSize;
    _diskQueue = dispatch_queue_create("com.dnshield.diskcache", DISPATCH_QUEUE_SERIAL);
    _fileManager = [[NSFileManager alloc] init];

    [self setupCacheDirectory];
    [self loadMetadata];

    DNSLogInfo(LogCategoryCache, "DiskCache initialized at: %@, max size: %lu MB", directory,
               (unsigned long)(maxSize / (1024 * 1024)));
  }
  return self;
}

- (void)setupCacheDirectory {
  dispatch_sync(self.diskQueue, ^{
    NSError* error = nil;
    BOOL isDirectory = NO;

    if (![self.fileManager fileExistsAtPath:self.cacheDirectory isDirectory:&isDirectory]) {
      [self.fileManager createDirectoryAtPath:self.cacheDirectory
                  withIntermediateDirectories:YES
                                   attributes:nil
                                        error:&error];

      if (error) {
        DNSLogError(LogCategoryCache, "Failed to create cache directory: %@", error);
      } else {
        DNSLogInfo(LogCategoryCache, "Created cache directory: %@", self.cacheDirectory);
      }
    }
  });
}

- (void)loadMetadata {
  dispatch_sync(self.diskQueue, ^{
    NSString* metadataPath =
        [self.cacheDirectory stringByAppendingPathComponent:kDiskCacheMetadataFile];

    if ([self.fileManager fileExistsAtPath:metadataPath]) {
      NSData* data = [NSData dataWithContentsOfFile:metadataPath];
      if (data) {
        NSError* error = nil;
        self.metadata = [NSKeyedUnarchiver unarchivedObjectOfClass:[DiskCacheMetadata class]
                                                          fromData:data
                                                             error:&error];
        if (error) {
          DNSLogError(LogCategoryCache, "Failed to load cache metadata: %@", error);
        }
      }
    }

    if (!self.metadata) {
      self.metadata = [[DiskCacheMetadata alloc] init];
      self.metadata.version = kDiskCacheVersion;
      self.metadata.createdDate = [NSDate date];
      self.metadata.lastMaintenanceDate = [NSDate date];
      [self saveMetadata];
    }
  });
}

- (void)saveMetadata {
  NSString* metadataPath =
      [self.cacheDirectory stringByAppendingPathComponent:kDiskCacheMetadataFile];
  NSError* error = nil;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:self.metadata
                                       requiringSecureCoding:YES
                                                       error:&error];

  if (data && !error) {
    [data writeToFile:metadataPath atomically:YES];
  } else {
    DNSLogError(LogCategoryCache, "Failed to save cache metadata: %@", error);
  }
}

#pragma mark - Store Operations

- (BOOL)storeEntry:(CacheEntry*)entry forKey:(NSString*)key error:(NSError**)error {
  if (!entry || !key) {
    if (error) {
      *error =
          DNSMakeError(DNSRuleCacheErrorDomain, DNSRuleCacheErrorUnknown, @"Invalid entry or key");
    }
    return NO;
  }

  __block BOOL success = NO;
  __block NSError* storeError = nil;

  dispatch_sync(self.diskQueue, ^{
    @autoreleasepool {
      NSString* filePath = [self filePathForKey:key];

      // Serialize entry
      NSData* data = [NSKeyedArchiver archivedDataWithRootObject:entry
                                           requiringSecureCoding:YES
                                                           error:&storeError];

      if (!data || storeError) {
        DNSLogError(LogCategoryCache, "Failed to serialize cache entry: %@", storeError);
        return;
      }

      // Check if we need to make room
      if (self.metadata.totalSize + data.length > self.maxSize) {
        [self evictOldestEntriesForSize:data.length];
      }

      // Remove old entry if exists
      if ([self.fileManager fileExistsAtPath:filePath]) {
        [self removeFileAtPath:filePath];
      }

      // Write new data
      success = [data writeToFile:filePath options:NSDataWritingAtomic error:&storeError];

      if (success) {
        self.metadata.totalSize += data.length;
        self.metadata.entryCount++;
        [self saveMetadata];

        DNSLogDebug(LogCategoryCache, "Disk cache stored: %@, size: %lu bytes", key,
                    (unsigned long)data.length);
      } else {
        DNSLogError(LogCategoryCache, "Failed to write cache entry: %@", storeError);
      }
    }
  });

  if (error && storeError) {
    *error = storeError;
  }

  return success;
}

#pragma mark - Retrieve Operations

- (nullable CacheEntry*)entryForKey:(NSString*)key error:(NSError**)error {
  if (!key)
    return nil;

  __block CacheEntry* entry = nil;
  __block NSError* readError = nil;

  dispatch_sync(self.diskQueue, ^{
    NSString* filePath = [self filePathForKey:key];

    if ([self.fileManager fileExistsAtPath:filePath]) {
      NSData* data = [NSData dataWithContentsOfFile:filePath options:0 error:&readError];

      if (data && !readError) {
        entry = [NSKeyedUnarchiver unarchivedObjectOfClass:[CacheEntry class]
                                                  fromData:data
                                                     error:&readError];

        if (entry && !readError) {
          // Check if expired
          if ([entry isExpired]) {
            [self removeFileAtPath:filePath];
            entry = nil;
            DNSLogDebug(LogCategoryCache, "Disk cache entry expired: %@", key);
          } else {
            // Update access time
            [[NSFileManager defaultManager] setAttributes:@{NSFileModificationDate : [NSDate date]}
                                             ofItemAtPath:filePath
                                                    error:nil];
            DNSLogDebug(LogCategoryCache, "Disk cache hit: %@", key);
          }
        }
      }
    }
  });

  if (error && readError) {
    *error = readError;
  }

  return entry;
}

#pragma mark - Remove Operations

- (BOOL)removeEntryForKey:(NSString*)key error:(NSError**)error {
  if (!key)
    return NO;

  __block BOOL success = NO;
  __block NSError* removeError = nil;

  dispatch_sync(self.diskQueue, ^{
    NSString* filePath = [self filePathForKey:key];

    if ([self.fileManager fileExistsAtPath:filePath]) {
      success = [self removeFileAtPath:filePath];
      if (success) {
        DNSLogDebug(LogCategoryCache, "Disk cache removed: %@", key);
      } else {
        removeError = DNSMakeError(DNSRuleCacheErrorDomain, DNSRuleCacheErrorWriteFailed,
                                   @"Failed to remove cache file");
      }
    } else {
      success = YES;  // Already removed
    }
  });

  if (error && removeError) {
    *error = removeError;
  }

  return success;
}

- (NSUInteger)removeExpiredEntriesWithError:(NSError**)error {
  __block NSUInteger removedCount = 0;
  __block NSError* cleanupError = nil;

  dispatch_sync(self.diskQueue, ^{
    NSArray* files = [self allCacheFiles];

    for (NSString* file in files) {
      @autoreleasepool {
        NSString* filePath = [self.cacheDirectory stringByAppendingPathComponent:file];
        NSData* data = [NSData dataWithContentsOfFile:filePath];

        if (data) {
          NSError* unarchiveError = nil;
          CacheEntry* entry = [NSKeyedUnarchiver unarchivedObjectOfClass:[CacheEntry class]
                                                                fromData:data
                                                                   error:&unarchiveError];

          if (entry && !unarchiveError && [entry isExpired]) {
            if ([self removeFileAtPath:filePath]) {
              removedCount++;
            }
          }
        }
      }
    }

    if (removedCount > 0) {
      [self recalculateMetadata];
      DNSLogInfo(LogCategoryCache, "Removed %lu expired entries from disk cache",
                 (unsigned long)removedCount);
    }
  });

  if (error && cleanupError) {
    *error = cleanupError;
  }

  return removedCount;
}

- (BOOL)removeAllEntriesWithError:(NSError**)error {
  __block BOOL success = YES;
  __block NSError* removeError = nil;

  dispatch_sync(self.diskQueue, ^{
    NSArray* files = [self allCacheFiles];

    for (NSString* file in files) {
      NSString* filePath = [self.cacheDirectory stringByAppendingPathComponent:file];
      NSError* fileError = nil;

      if (![self.fileManager removeItemAtPath:filePath error:&fileError]) {
        success = NO;
        removeError = fileError;
        DNSLogError(LogCategoryCache, "Failed to remove cache file: %@", fileError);
      }
    }

    if (success) {
      self.metadata.totalSize = 0;
      self.metadata.entryCount = 0;
      [self saveMetadata];
      DNSLogInfo(LogCategoryCache, "Disk cache cleared");
    }
  });

  if (error && removeError) {
    *error = removeError;
  }

  return success;
}

#pragma mark - Query Operations

- (NSArray<NSString*>*)allKeysWithError:(NSError**)error {
  __block NSMutableArray<NSString*>* keys = [NSMutableArray array];

  dispatch_sync(self.diskQueue, ^{
    NSArray* files = [self allCacheFiles];

    for (NSString* file in files) {
      NSString* key = [self keyFromFileName:file];
      if (key) {
        [keys addObject:key];
      }
    }
  });

  return [keys copy];
}

- (NSUInteger)currentSize {
  __block NSUInteger size = 0;
  dispatch_sync(self.diskQueue, ^{
    size = self.metadata.totalSize;
  });
  return size;
}

- (NSUInteger)entryCount {
  __block NSUInteger count = 0;
  dispatch_sync(self.diskQueue, ^{
    count = self.metadata.entryCount;
  });
  return count;
}

#pragma mark - Maintenance

- (BOOL)synchronizeWithError:(NSError**)error {
  dispatch_sync(self.diskQueue, ^{
    [self saveMetadata];
  });
  return YES;
}

- (BOOL)performMaintenanceWithError:(NSError**)error {
  __block BOOL success = YES;
  __block NSError* blockError = nil;

  dispatch_sync(self.diskQueue, ^{
    DNSLogInfo(LogCategoryCache, "Starting disk cache maintenance");

    // Remove expired entries
    NSError* cleanupError = nil;
    NSUInteger removed = [self removeExpiredEntriesWithError:&cleanupError];

    if (cleanupError) {
      success = NO;
      blockError = cleanupError;
      return;
    }

    // Recalculate metadata
    [self recalculateMetadata];

    // Update maintenance date
    self.metadata.lastMaintenanceDate = [NSDate date];
    [self saveMetadata];

    DNSLogInfo(LogCategoryCache, "Disk cache maintenance completed. Removed %lu entries",
               (unsigned long)removed);
  });

  if (blockError && error) {
    *error = blockError;
  }

  return success;
}

#pragma mark - Migration

- (BOOL)migrateCacheIfNeededWithError:(NSError**)error {
  // Check if migration is needed
  if (![self.metadata.version isEqualToString:kDiskCacheVersion]) {
    DNSLogInfo(LogCategoryCache, "Cache migration needed from version %@ to %@",
               self.metadata.version, kDiskCacheVersion);

    // For now, just clear old cache
    BOOL success = [self removeAllEntriesWithError:error];
    if (success) {
      self.metadata.version = kDiskCacheVersion;
      [self saveMetadata];
    }
    return success;
  }

  return YES;
}

#pragma mark - Private Helpers

- (NSString*)filePathForKey:(NSString*)key {
  NSString* fileName = [self fileNameForKey:key];
  return [self.cacheDirectory stringByAppendingPathComponent:fileName];
}

- (NSString*)fileNameForKey:(NSString*)key {
  // Create SHA256 hash of key for filename (secure replacement for deprecated MD5)
  const char* cStr = [key UTF8String];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(cStr, (CC_LONG)strlen(cStr), digest);

  NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
    [output appendFormat:@"%02x", digest[i]];
  }

  return [output stringByAppendingString:@".cache"];
}

- (NSString*)keyFromFileName:(NSString*)fileName {
  // This is a one-way hash, so we can't recover the original key
  // In a real implementation, we might store a key mapping
  return [fileName stringByDeletingPathExtension];
}

- (NSArray<NSString*>*)allCacheFiles {
  NSError* error = nil;
  NSArray* files = [self.fileManager contentsOfDirectoryAtPath:self.cacheDirectory error:&error];

  if (error) {
    DNSLogError(LogCategoryCache, "Failed to list cache files: %@", error);
    return @[];
  }

  NSPredicate* predicate = [NSPredicate predicateWithFormat:@"SELF ENDSWITH '.cache'"];
  return [files filteredArrayUsingPredicate:predicate];
}

- (BOOL)removeFileAtPath:(NSString*)path {
  NSDictionary* attributes = [self.fileManager attributesOfItemAtPath:path error:nil];
  NSUInteger fileSize = [attributes[NSFileSize] unsignedIntegerValue];

  NSError* error = nil;
  BOOL success = [self.fileManager removeItemAtPath:path error:&error];

  if (success) {
    self.metadata.totalSize -= fileSize;
    self.metadata.entryCount--;
  } else {
    DNSLogError(LogCategoryCache, "Failed to remove file: %@", error);
  }

  return success;
}

- (void)evictOldestEntriesForSize:(NSUInteger)requiredSize {
  NSArray* files = [self allCacheFiles];

  // Sort by modification date (oldest first)
  NSMutableArray* fileInfos = [NSMutableArray array];
  for (NSString* file in files) {
    NSString* path = [self.cacheDirectory stringByAppendingPathComponent:file];
    NSDictionary* attributes = [self.fileManager attributesOfItemAtPath:path error:nil];
    if (attributes) {
      [fileInfos addObject:@{
        @"path" : path,
        @"date" : attributes[NSFileModificationDate] ?: [NSDate distantPast],
        @"size" : attributes[NSFileSize] ?: @0
      }];
    }
  }

  [fileInfos sortUsingComparator:^NSComparisonResult(NSDictionary* obj1, NSDictionary* obj2) {
    return [obj1[@"date"] compare:obj2[@"date"]];
  }];

  // Remove oldest entries until we have enough space
  NSUInteger freedSpace = 0;
  for (NSDictionary* info in fileInfos) {
    if (self.metadata.totalSize + requiredSize - freedSpace <= self.maxSize) {
      break;
    }

    if ([self removeFileAtPath:info[@"path"]]) {
      freedSpace += [info[@"size"] unsignedIntegerValue];
      DNSLogDebug(LogCategoryCache, "Evicted old cache entry to make room");
    }
  }
}

- (void)recalculateMetadata {
  NSUInteger totalSize = 0;
  NSUInteger entryCount = 0;

  NSArray* files = [self allCacheFiles];
  for (NSString* file in files) {
    NSString* path = [self.cacheDirectory stringByAppendingPathComponent:file];
    NSDictionary* attributes = [self.fileManager attributesOfItemAtPath:path error:nil];
    if (attributes) {
      totalSize += [attributes[NSFileSize] unsignedIntegerValue];
      entryCount++;
    }
  }

  self.metadata.totalSize = totalSize;
  self.metadata.entryCount = entryCount;
}

@end
