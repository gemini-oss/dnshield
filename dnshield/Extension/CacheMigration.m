//
//  CacheMigration.m
//  DNShield Network Extension
//
//  Implementation of cache migration system
//

#import "CacheMigration.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import "RuleCache.h"
#import "RuleSet.h"

static NSString* const kCacheMigrationErrorDomain = @"com.dnshield.cachemigration";

@interface CacheMigrationStatistics ()
@property(nonatomic, assign) NSUInteger totalEntries;
@property(nonatomic, assign) NSUInteger migratedEntries;
@property(nonatomic, assign) NSUInteger failedEntries;
@property(nonatomic, assign) NSUInteger deletedEntries;
@property(nonatomic, assign) NSTimeInterval duration;
@end

@implementation CacheMigrationStatistics
@end

@interface CacheMigration ()
@property(nonatomic, strong) dispatch_queue_t migrationQueue;
@property(nonatomic, strong) NSFileManager* fileManager;
@property(nonatomic, strong) CacheMigrationStatistics* currentStats;
@property(nonatomic, strong) NSDate* migrationStartTime;
@end

@implementation CacheMigration

- (instancetype)init {
  self = [super init];
  if (self) {
    _migrationQueue = dispatch_queue_create("com.dnshield.cachemigration", DISPATCH_QUEUE_SERIAL);
    _fileManager = [[NSFileManager alloc] init];
  }
  return self;
}

#pragma mark - Version Checking

+ (BOOL)isMigrationNeededFromVersion:(NSString*)currentVersion toVersion:(NSString*)targetVersion {
  if (!currentVersion || !targetVersion) {
    return NO;
  }

  // Simple version comparison
  NSComparisonResult result = [currentVersion compare:targetVersion options:NSNumericSearch];
  return result == NSOrderedAscending;
}

+ (NSArray<NSString*>*)migrationPathFromVersion:(NSString*)fromVersion
                                      toVersion:(NSString*)toVersion {
  // Define migration path
  NSArray* allVersions = @[ @"1.0", @"1.1", @"2.0" ];

  NSUInteger fromIndex = [allVersions indexOfObject:fromVersion];
  NSUInteger toIndex = [allVersions indexOfObject:toVersion];

  if (fromIndex == NSNotFound || toIndex == NSNotFound || fromIndex >= toIndex) {
    return @[];
  }

  NSRange range = NSMakeRange(fromIndex + 1, toIndex - fromIndex);
  return [allVersions subarrayWithRange:range];
}

#pragma mark - Migration Operations

- (CacheMigrationResult)migrateFromPath:(NSString*)sourcePath
                                 toPath:(NSString*)destinationPath
                            fromVersion:(NSString*)fromVersion
                              toVersion:(NSString*)toVersion
                                  error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Starting cache migration from v%@ to v%@", fromVersion, toVersion);

  self.migrationStartTime = [NSDate date];
  self.currentStats = [[CacheMigrationStatistics alloc] init];

  // Notify delegate
  if ([self.delegate respondsToSelector:@selector(cacheMigrationDidStart:toVersion:)]) {
    [self.delegate cacheMigrationDidStart:fromVersion toVersion:toVersion];
  }

  __block CacheMigrationResult result = CacheMigrationResultSuccess;
  __block NSError* migrationError = nil;

  dispatch_sync(self.migrationQueue, ^{
    // Create backup first
    NSString* backupPath = [sourcePath stringByAppendingString:@".backup"];
    if (![self createBackupAtPath:backupPath fromPath:sourcePath error:&migrationError]) {
      result = CacheMigrationResultFailed;
      return;
    }

    // Get migration path
    NSArray* migrationPath = [[self class] migrationPathFromVersion:fromVersion
                                                          toVersion:toVersion];

    if (migrationPath.count == 0) {
      result = CacheMigrationResultNotNeeded;
      return;
    }

    // Perform incremental migrations
    NSString* currentPath = sourcePath;
    NSString* currentVersion = fromVersion;

    for (NSString* nextVersion in migrationPath) {
      DNSLogInfo(LogCategoryCache, "Migrating from v%@ to v%@", currentVersion, nextVersion);

      if (![self performMigrationFromVersion:currentVersion
                                   toVersion:nextVersion
                                      atPath:currentPath
                                       error:&migrationError]) {
        result = CacheMigrationResultFailed;

        // Restore from backup
        [self restoreFromBackupPath:backupPath toPath:sourcePath error:nil];
        break;
      }

      currentVersion = nextVersion;

      // Notify progress
      float progress = (float)[migrationPath indexOfObject:nextVersion] / migrationPath.count;
      if ([self.delegate respondsToSelector:@selector(cacheMigrationDidProgress:)]) {
        [self.delegate cacheMigrationDidProgress:progress];
      }
    }

    // Clean up backup if successful
    if (result == CacheMigrationResultSuccess) {
      [self.fileManager removeItemAtPath:backupPath error:nil];
    }

    // Clean up old format files
    [CacheMigrationUtilities cleanupOldFormatAtPath:sourcePath version:fromVersion error:nil];
  });

  // Calculate duration
  self.currentStats.duration = -[self.migrationStartTime timeIntervalSinceNow];

  // Notify completion
  if ([self.delegate respondsToSelector:@selector(cacheMigrationDidComplete:statistics:)]) {
    [self.delegate cacheMigrationDidComplete:result statistics:self.currentStats];
  }

  if (result == CacheMigrationResultFailed && migrationError) {
    if ([self.delegate respondsToSelector:@selector(cacheMigrationDidFailWithError:)]) {
      [self.delegate cacheMigrationDidFailWithError:migrationError];
    }

    if (error) {
      *error = migrationError;
    }
  }

  DNSLogInfo(LogCategoryCache, "Cache migration completed with result: %ld", (long)result);

  return result;
}

#pragma mark - Backup Operations

- (BOOL)createBackupAtPath:(NSString*)backupPath
                  fromPath:(NSString*)sourcePath
                     error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Creating backup at: %@", backupPath);

  // Remove existing backup
  if ([self.fileManager fileExistsAtPath:backupPath]) {
    [self.fileManager removeItemAtPath:backupPath error:nil];
  }

  // Copy source to backup
  NSError* copyError = nil;
  BOOL success = [self.fileManager copyItemAtPath:sourcePath toPath:backupPath error:&copyError];

  if (!success) {
    DNSLogError(LogCategoryCache, "Failed to create backup: %@", copyError);
    if (error) {
      *error = copyError;
    }
  }

  return success;
}

- (BOOL)restoreFromBackupPath:(NSString*)backupPath
                       toPath:(NSString*)destinationPath
                        error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Restoring from backup: %@", backupPath);

  // Remove current destination
  if ([self.fileManager fileExistsAtPath:destinationPath]) {
    [self.fileManager removeItemAtPath:destinationPath error:nil];
  }

  // Copy backup to destination
  NSError* copyError = nil;
  BOOL success = [self.fileManager copyItemAtPath:backupPath
                                           toPath:destinationPath
                                            error:&copyError];

  if (!success) {
    DNSLogError(LogCategoryCache, "Failed to restore from backup: %@", copyError);
    if (error) {
      *error = copyError;
    }
  }

  return success;
}

#pragma mark - Version-Specific Migrations

- (BOOL)performMigrationFromVersion:(NSString*)fromVersion
                          toVersion:(NSString*)toVersion
                             atPath:(NSString*)path
                              error:(NSError**)error {
  // Route to specific migration method
  if ([fromVersion isEqualToString:@"1.0"] && [toVersion isEqualToString:@"1.1"]) {
    return [self migrateFromV1_0ToV1_1:path error:error];
  } else if ([fromVersion isEqualToString:@"1.1"] && [toVersion isEqualToString:@"2.0"]) {
    return [self migrateFromV1_1ToV2_0:path error:error];
  }

  // Unknown migration path
  if (error) {
    *error = [NSError
        errorWithDomain:kCacheMigrationErrorDomain
                   code:1001
               userInfo:@{
                 NSLocalizedDescriptionKey : [NSString
                     stringWithFormat:@"No migration path from v%@ to v%@", fromVersion, toVersion]
               }];
  }

  return NO;
}

- (BOOL)migrateFromV1_0ToV1_1:(NSString*)path error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Migrating cache from v1.0 to v1.1");

  // Example migration: Add metadata to cache entries
  NSArray* cacheFiles = [self cacheFilesAtPath:path];
  self.currentStats.totalEntries = cacheFiles.count;

  for (NSString* file in cacheFiles) {
    @autoreleasepool {
      NSString* filePath = [path stringByAppendingPathComponent:file];

      // Read old format
      NSData* data = [NSData dataWithContentsOfFile:filePath];
      if (!data) {
        self.currentStats.failedEntries++;
        continue;
      }

      // Migrate data structure
      // This is a simplified example - real migration would transform the data
      BOOL success = [data writeToFile:filePath atomically:YES];

      if (success) {
        self.currentStats.migratedEntries++;
      } else {
        self.currentStats.failedEntries++;
      }
    }
  }

  return self.currentStats.failedEntries == 0;
}

- (BOOL)migrateFromV1_1ToV2_0:(NSString*)path error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Migrating cache from v1.1 to v2.0");

  // Example migration: Change file format
  NSArray* cacheFiles = [self cacheFilesAtPath:path];
  self.currentStats.totalEntries = cacheFiles.count;

  for (NSString* file in cacheFiles) {
    @autoreleasepool {
      NSString* filePath = [path stringByAppendingPathComponent:file];

      // Read v1.1 format
      NSData* oldData = [NSData dataWithContentsOfFile:filePath];
      if (!oldData) {
        self.currentStats.failedEntries++;
        continue;
      }

      @try {
        // Unarchive old format using the new API
        NSError* unarchiveError = nil;
        id oldObject = [NSKeyedUnarchiver unarchivedObjectOfClass:[NSObject class]
                                                         fromData:oldData
                                                            error:&unarchiveError];

        if (!oldObject || unarchiveError) {
          self.currentStats.failedEntries++;
          if (unarchiveError) {
            DNSLogError(LogCategoryCache, "Unarchive error: %@", unarchiveError);
          }
          continue;
        }

        // Convert to new format
        NSError* archiveError = nil;
        NSData* newData = [NSKeyedArchiver archivedDataWithRootObject:oldObject
                                                requiringSecureCoding:YES
                                                                error:&archiveError];

        if (newData && !archiveError) {
          [newData writeToFile:filePath atomically:YES];
          self.currentStats.migratedEntries++;
        } else {
          self.currentStats.failedEntries++;
        }
      } @catch (NSException* exception) {
        self.currentStats.failedEntries++;
        DNSLogError(LogCategoryCache, "Migration exception: %@", exception);
      }
    }
  }

  return self.currentStats.failedEntries == 0;
}

- (BOOL)migrateFromV1ToV2:(NSString*)path error:(NSError**)error {
  // Legacy method for compatibility
  return [self migrateFromV1_0ToV1_1:path error:error];
}

#pragma mark - Helper Methods

- (NSArray<NSString*>*)cacheFilesAtPath:(NSString*)path {
  NSError* error = nil;
  NSArray* files = [self.fileManager contentsOfDirectoryAtPath:path error:&error];

  if (error) {
    DNSLogError(LogCategoryCache, "Failed to list cache files: %@", error);
    return @[];
  }

  // Filter cache files
  NSPredicate* predicate = [NSPredicate predicateWithFormat:@"SELF ENDSWITH '.cache'"];
  return [files filteredArrayUsingPredicate:predicate];
}

@end

#pragma mark - Migration Utilities

@implementation CacheMigrationUtilities

+ (BOOL)validateCacheAtPath:(NSString*)path version:(NSString*)version error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Validating cache at path: %@ for version: %@", path, version);

  NSFileManager* fileManager = [[NSFileManager alloc] init];

  // Check if path exists
  BOOL isDirectory = NO;
  if (![fileManager fileExistsAtPath:path isDirectory:&isDirectory] || !isDirectory) {
    if (error) {
      *error =
          [NSError errorWithDomain:kCacheMigrationErrorDomain
                              code:1002
                          userInfo:@{NSLocalizedDescriptionKey : @"Cache directory not found"}];
    }
    return NO;
  }

  // Check metadata file
  NSString* metadataPath = [path stringByAppendingPathComponent:@"cache_metadata.plist"];
  if ([fileManager fileExistsAtPath:metadataPath]) {
    NSDictionary* metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
    NSString* cacheVersion = metadata[@"version"];

    if (![cacheVersion isEqualToString:version]) {
      if (error) {
        *error = [NSError errorWithDomain:kCacheMigrationErrorDomain
                                     code:1003
                                 userInfo:@{
                                   NSLocalizedDescriptionKey : [NSString
                                       stringWithFormat:@"Version mismatch: expected %@, found %@",
                                                        version, cacheVersion]
                                 }];
      }
      return NO;
    }
  }

  // Validate sample of cache files
  NSArray* files = [fileManager contentsOfDirectoryAtPath:path error:nil];
  NSPredicate* predicate = [NSPredicate predicateWithFormat:@"SELF ENDSWITH '.cache'"];
  NSArray* cacheFiles = [files filteredArrayUsingPredicate:predicate];

  NSUInteger sampleSize = MIN(10, cacheFiles.count);
  for (NSUInteger i = 0; i < sampleSize; i++) {
    NSString* filePath = [path stringByAppendingPathComponent:cacheFiles[i]];
    NSData* data = [NSData dataWithContentsOfFile:filePath];

    if (!data) {
      continue;
    }

    // Try to unarchive
    @try {
      NSError* unarchiveError = nil;
      id object = [NSKeyedUnarchiver unarchivedObjectOfClass:[CacheEntry class]
                                                    fromData:data
                                                       error:&unarchiveError];

      if (!object || unarchiveError) {
        DNSLogError(LogCategoryCache, "Invalid cache file: %@", cacheFiles[i]);
        if (error) {
          *error =
              unarchiveError
                  ?: [NSError errorWithDomain:kCacheMigrationErrorDomain
                                         code:1004
                                     userInfo:@{
                                       NSLocalizedDescriptionKey : @"Cache file validation failed"
                                     }];
        }
        return NO;
      }
    } @catch (NSException* exception) {
      DNSLogError(LogCategoryCache, "Exception validating cache: %@", exception);
      if (error) {
        *error = [NSError
            errorWithDomain:kCacheMigrationErrorDomain
                       code:1005
                   userInfo:@{NSLocalizedDescriptionKey : exception.reason ?: @"Unknown error"}];
      }
      return NO;
    }
  }

  DNSLogInfo(LogCategoryCache, "Cache validation successful");
  return YES;
}

+ (BOOL)cleanupOldFormatAtPath:(NSString*)path version:(NSString*)version error:(NSError**)error {
  DNSLogInfo(LogCategoryCache, "Cleaning up old format files for version: %@", version);

  NSFileManager* fileManager = [[NSFileManager alloc] init];
  NSError* listError = nil;
  NSArray* files = [fileManager contentsOfDirectoryAtPath:path error:&listError];

  if (listError) {
    if (error)
      *error = listError;
    return NO;
  }

  NSUInteger cleanedCount = 0;

  // Define old format patterns based on version
  NSArray* oldPatterns = @[];
  if ([version isEqualToString:@"2.0"]) {
    oldPatterns = @[ @".old", @".v1", @".tmp" ];
  }

  for (NSString* file in files) {
    for (NSString* pattern in oldPatterns) {
      if ([file hasSuffix:pattern]) {
        NSString* filePath = [path stringByAppendingPathComponent:file];
        if ([fileManager removeItemAtPath:filePath error:nil]) {
          cleanedCount++;
        }
      }
    }
  }

  if (cleanedCount > 0) {
    DNSLogInfo(LogCategoryCache, "Cleaned up %lu old format files", (unsigned long)cleanedCount);
  }

  return YES;
}

+ (NSTimeInterval)estimatedMigrationTimeForPath:(NSString*)path
                                    fromVersion:(NSString*)fromVersion
                                      toVersion:(NSString*)toVersion {
  NSFileManager* fileManager = [[NSFileManager alloc] init];

  // Get directory size
  NSUInteger totalSize = 0;
  NSUInteger fileCount = 0;

  NSArray* files = [fileManager contentsOfDirectoryAtPath:path error:nil];
  for (NSString* file in files) {
    NSString* filePath = [path stringByAppendingPathComponent:file];
    NSDictionary* attributes = [fileManager attributesOfItemAtPath:filePath error:nil];
    if (attributes) {
      totalSize += [attributes[NSFileSize] unsignedIntegerValue];
      fileCount++;
    }
  }

  // Estimate based on file count and size
  // Rough estimate: 10ms per file + 1ms per MB
  NSTimeInterval baseTime = fileCount * 0.01;                         // 10ms per file
  NSTimeInterval sizeTime = (totalSize / (1024.0 * 1024.0)) * 0.001;  // 1ms per MB

  // Add overhead for different version jumps
  NSTimeInterval versionOverhead = 1.0;  // 1 second base
  if ([fromVersion isEqualToString:@"1.0"] && [toVersion isEqualToString:@"2.0"]) {
    versionOverhead = 5.0;  // Major version jump
  }

  return baseTime + sizeTime + versionOverhead;
}

@end
