#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, DNOutputFormat) {
  DNOutputFormatText = 0,
  DNOutputFormatPlist = 1,
  DNOutputFormatJSON = 2,
  DNOutputFormatYAML = 3
};

@interface CommandResult : NSObject
@property(nonatomic, copy, nullable) NSString* stdoutString;
@property(nonatomic, copy, nullable) NSString* stderrString;
@property(nonatomic, assign) int status;
@end

FOUNDATION_EXPORT NSString* const DNCTLColorRed;
FOUNDATION_EXPORT NSString* const DNCTLColorGreen;
FOUNDATION_EXPORT NSString* const DNCTLColorYellow;
FOUNDATION_EXPORT NSString* const DNCTLColorBlue;
FOUNDATION_EXPORT NSString* const DNCTLColorReset;

DNOutputFormat DNCTLGetOutputFormat(void);
void DNCTLSetOutputFormat(DNOutputFormat format);

NSString* DNCTLTrimmedString(NSString* _Nullable value);
BOOL DNCTLContainsUnknownFlag(NSArray<NSString*>* tokens, NSSet<NSString*>* knownFlags);
BOOL DNCTLParseFormatFromArgs(
    NSArray<NSString*>* args, DNOutputFormat* outFormat,
    NSArray<NSString*>* __autoreleasing _Nullable* _Nullable outRemaining);

void DNCTLLogInfo(NSString* message);
void DNCTLLogWarning(NSString* message);
void DNCTLLogError(NSString* message);
void DNCTLLogSuccess(NSString* message);

void DNCTLPrintObject(id obj, DNOutputFormat format);
NSString* DNCTLJSONStringFromObject(id obj);
NSString* DNCTLPlistStringFromObject(id obj);

CommandResult* DNCTLRunEnvCommand(NSString* program, NSArray<NSString*>* arguments);
CommandResult* DNCTLRunStreamingCommand(NSString* path, NSArray<NSString*>* arguments);

BOOL DNCTLProcessExists(pid_t pid);
NSNumber* _Nullable DNCTLReadPID(void);
void DNCTLEnsureRoot(void);
pid_t DNCTLFindDaemonPID(void);
void DNCTLCleanupStalePID(void);
void DNCTLSendCommandFile(NSString* command, pid_t pid);
NSString* DNCTLFindExecutable(NSString* name);

void DNCTLInstallSignalHandlersIfNeeded(void);
void DNCTLSetActiveChildPID(pid_t pid);
void DNCTLClearActiveChildPID(void);
BOOL DNCTLIsInterrupted(void);

NS_ASSUME_NONNULL_END
