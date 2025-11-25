//
//  LogEntry.h
//  DNShield
//
//  log viewer
//

#import <Foundation/Foundation.h>
#import <OSLog/OSLog.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LogEntryType) {
  LogEntryTypeRegular = 1,
  LogEntryTypeActivity = 2,
  LogEntryTypeBoundary = 3,
  LogEntryTypeSignpost = 4
};

typedef NS_ENUM(NSInteger, LogEntryLevel) {
  LogEntryLevelDefault,
  LogEntryLevelInfo,
  LogEntryLevelDebug,
  LogEntryLevelError,
  LogEntryLevelFault
};

@interface LogEntry : NSObject

@property(nonatomic, strong) NSDate* date;
@property(nonatomic, assign) LogEntryType type;
@property(nonatomic, assign) LogEntryLevel level;
@property(nonatomic, strong, nullable) NSString* category;
@property(nonatomic, strong, nullable) NSString* subsystem;
@property(nonatomic, strong, nullable) NSString* sender;
@property(nonatomic, strong, nullable) NSString* process;
@property(nonatomic, assign) int processID;
@property(nonatomic, assign) uint64_t threadID;
@property(nonatomic, assign) uint64_t activityID;
@property(nonatomic, assign) uint64_t parentActivityID;
@property(nonatomic, strong, nullable) NSString* message;

// Signpost-specific fields
@property(nonatomic, assign) uint64_t signpostID;
@property(nonatomic, strong, nullable) NSString* signpostName;
@property(nonatomic, strong, nullable) NSString* signpostType;

+ (instancetype)entryFromOSLogEntry:(id)osLogEntry;
- (NSString*)formattedString;
- (NSString*)compactFormattedString;
- (NSDictionary*)toDictionary;

@end

NS_ASSUME_NONNULL_END
