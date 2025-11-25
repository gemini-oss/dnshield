//
//  FileRuleFetcher.h
//  DNShield Network Extension
//
//  Fetcher implementation for monitoring and loading rule lists from local files
//  Supports file watching for automatic updates when files change
//

#import "Fetcher.h"

NS_ASSUME_NONNULL_BEGIN

// File-specific configuration keys
extern NSString* const FileRuleFetcherConfigKeyPath;  // NSString (required) - file path
extern NSString* const
    FileRuleFetcherConfigKeyWatchForChanges;  // NSNumber (BOOL) - enable file watching
extern NSString* const FileRuleFetcherConfigKeyCheckInterval;  // NSNumber (seconds) - polling
                                                               // interval if FSEvents unavailable
extern NSString* const
    FileRuleFetcherConfigKeyFollowSymlinks;  // NSNumber (BOOL) - follow symbolic links
extern NSString* const
    FileRuleFetcherConfigKeyMaxFileSize;  // NSNumber (bytes) - maximum file size to read

// File change notification
extern NSString* const FileRuleFetcherFileDidChangeNotification;
extern NSString* const FileRuleFetcherNotificationKeyPath;

@interface FileRuleFetcher : RuleFetcherBase

// File path to monitor
@property(nonatomic, strong, readonly) NSString* filePath;

// Whether file watching is enabled
@property(nonatomic, assign, readonly) BOOL watchForChanges;

// File attributes
@property(nonatomic, strong, readonly, nullable) NSDictionary* fileAttributes;
@property(nonatomic, strong, readonly, nullable) NSDate* lastModifiedDate;
@property(nonatomic, readonly) NSUInteger fileSize;

// Initialize with file path
- (instancetype)initWithFilePath:(NSString*)filePath;
- (instancetype)initWithFilePath:(NSString*)filePath
                   configuration:(nullable NSDictionary*)configuration;

// File watching control
- (void)startWatching;
- (void)stopWatching;
@property(nonatomic, readonly) BOOL isWatching;

// Check if file exists and is readable
- (BOOL)fileExists;
- (BOOL)isFileReadable;

// Get resolved path (following symlinks if enabled)
- (nullable NSString*)resolvedPath;

// Manual file change check
- (BOOL)hasFileChangedSinceLastFetch;

@end

NS_ASSUME_NONNULL_END
