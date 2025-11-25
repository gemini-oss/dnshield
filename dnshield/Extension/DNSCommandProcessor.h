//
//  DNSCommandProcessor.h
//  DNShield Network Extension
//
//  Filesystem-based command processing with FSEvents monitoring
//

#import <CoreServices/CoreServices.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Command types
typedef NS_ENUM(NSInteger, DNSCommandType) {
  DNSCommandTypeUpdateRules = 0,
  DNSCommandTypeGetStatus = 1,
  DNSCommandTypeClearCache = 2,
  DNSCommandTypeReloadConfiguration = 3
};

@protocol DNSCommandProcessorDelegate <NSObject>
@required
- (void)processCommand:(NSDictionary*)command;
@end

@interface DNSCommandProcessor : NSObject

@property(nonatomic, weak) id<DNSCommandProcessorDelegate> delegate;
@property(nonatomic, readonly) NSString* commandDirectory;
@property(nonatomic, readonly) NSString* responseDirectory;

// Singleton instance
+ (instancetype)sharedProcessor;

// Start/stop monitoring
- (BOOL)startMonitoring;
- (void)stopMonitoring;

// Response writing
- (BOOL)writeResponse:(NSDictionary*)response
           forCommand:(NSString*)commandId
                error:(NSError**)error;

// Cleanup old files
- (void)cleanupOldFiles;

@end

NS_ASSUME_NONNULL_END
