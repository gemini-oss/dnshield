//
//  LogStore.h
//  DNShield
//
//  log viewer
//

#import <Foundation/Foundation.h>
#import "LogEntry.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, PredicateType) {
  PredicateTypeNone,
  PredicateTypeAllDNShield,
  PredicateTypeDNShieldApp,
  PredicateTypeDNShieldExtension,
  PredicateTypeDNShieldSubsystem,
  PredicateTypeCustom
};

@interface LogStore : NSObject

@property(nonatomic, assign) NSTimeInterval timeRange;
@property(nonatomic, strong, nullable) NSDate* startDate;
@property(nonatomic, strong, nullable) NSDate* endDate;
@property(nonatomic, assign) NSUInteger maxEntries;
@property(nonatomic, assign) BOOL includeSignposts;
@property(nonatomic, assign) BOOL showAllFields;
@property(nonatomic, assign) BOOL useStreamMode;
@property(nonatomic, assign) PredicateType predicateType;
@property(nonatomic, strong, nullable) NSString* predicateText;
@property(nonatomic, strong, nullable) NSString* customPredicate;

+ (instancetype)defaultStore;

- (void)fetchLogEntriesWithCompletion:(void (^)(NSArray<LogEntry*>* entries,
                                                NSError* _Nullable error))completion;
- (void)fetchLogEntriesFromArchive:(NSURL*)archiveURL
                        completion:(void (^)(NSArray<LogEntry*>* entries,
                                             NSError* _Nullable error))completion;

- (NSArray<LogEntry*>*)filterEntries:(NSArray<LogEntry*>*)entries
                      withSearchText:(NSString*)searchText
                             inField:(NSString*)field;
- (NSString*)exportEntriesToJSON:(NSArray<LogEntry*>*)entries;
- (NSString*)exportEntriesToRTF:(NSArray<LogEntry*>*)entries;

@end

NS_ASSUME_NONNULL_END
