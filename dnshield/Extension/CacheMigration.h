//
//  CacheMigration.h
//  DNShield Network Extension
//
//  Handles migration of cache data between versions
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Migration result
typedef NS_ENUM(NSInteger, CacheMigrationResult) {
  CacheMigrationResultSuccess = 0,
  CacheMigrationResultNotNeeded,
  CacheMigrationResultPartialSuccess,
  CacheMigrationResultFailed
};

// Migration statistics
@interface CacheMigrationStatistics : NSObject
@property(nonatomic, readonly) NSUInteger totalEntries;
@property(nonatomic, readonly) NSUInteger migratedEntries;
@property(nonatomic, readonly) NSUInteger failedEntries;
@property(nonatomic, readonly) NSUInteger deletedEntries;
@property(nonatomic, readonly) NSTimeInterval duration;
@end

// Migration delegate
@protocol CacheMigrationDelegate <NSObject>
@optional
- (void)cacheMigrationDidStart:(NSString*)fromVersion toVersion:(NSString*)toVersion;
- (void)cacheMigrationDidProgress:(float)progress;
- (void)cacheMigrationDidComplete:(CacheMigrationResult)result
                       statistics:(CacheMigrationStatistics*)stats;
- (void)cacheMigrationDidFailWithError:(NSError*)error;
@end

// Main migration class
@interface CacheMigration : NSObject

@property(nonatomic, weak) id<CacheMigrationDelegate> delegate;

// Check if migration is needed
+ (BOOL)isMigrationNeededFromVersion:(NSString*)currentVersion toVersion:(NSString*)targetVersion;

// Get migration path
+ (NSArray<NSString*>*)migrationPathFromVersion:(NSString*)fromVersion
                                      toVersion:(NSString*)toVersion;

// Perform migration
- (CacheMigrationResult)migrateFromPath:(NSString*)sourcePath
                                 toPath:(NSString*)destinationPath
                            fromVersion:(NSString*)fromVersion
                              toVersion:(NSString*)toVersion
                                  error:(NSError**)error;

// Backup operations
- (BOOL)createBackupAtPath:(NSString*)backupPath
                  fromPath:(NSString*)sourcePath
                     error:(NSError**)error;

- (BOOL)restoreFromBackupPath:(NSString*)backupPath
                       toPath:(NSString*)destinationPath
                        error:(NSError**)error;

// Version-specific migrations
- (BOOL)migrateFromV1ToV2:(NSString*)path error:(NSError**)error;

@end

// Migration utilities
@interface CacheMigrationUtilities : NSObject

// Validate cache integrity
+ (BOOL)validateCacheAtPath:(NSString*)path version:(NSString*)version error:(NSError**)error;

// Clean up old format files
+ (BOOL)cleanupOldFormatAtPath:(NSString*)path version:(NSString*)version error:(NSError**)error;

// Estimate migration time
+ (NSTimeInterval)estimatedMigrationTimeForPath:(NSString*)path
                                    fromVersion:(NSString*)fromVersion
                                      toVersion:(NSString*)toVersion;

@end

NS_ASSUME_NONNULL_END
