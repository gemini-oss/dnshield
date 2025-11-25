#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

void DNCTLCommandStatus(void);
void DNCTLCommandStart(void);
void DNCTLCommandStop(void);
void DNCTLCommandRestart(void);
void DNCTLCommandEnable(void);
void DNCTLCommandDisable(void);
void DNCTLCommandConfig(NSArray<NSString*>* args);
void DNCTLCommandLogs(NSArray<NSString*>* args);
void DNCTLCommandVersion(void);

void DNCTLPrintUsage(void);

NS_ASSUME_NONNULL_END
