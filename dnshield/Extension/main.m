//
//  main.m
//  DNShield Network Extension
//
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <os/log.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Common/LoggingUtils.h>

// Main logger
os_log_t logHandle = nil;

// Log to file flag
BOOL logToFile = NO;

// Initialize logging
void initLogging(void) {
  // Create log handle
  logHandle = os_log_create(DNUTF8(kDefaultExtensionBundleID), "main");

  // Check for file logging preference using the proper preference domain
  DNPreferenceAppSynchronize(kDNShieldPreferenceDomain);
  Boolean keyExists = false;
  logToFile = CFPreferencesGetAppBooleanValue(
      CFSTR("LogToFile"), (__bridge CFStringRef)kDNShieldPreferenceDomain, &keyExists);
  if (!keyExists) {
    logToFile = NO;  // Default to no file logging
  }

  // Create log directory if needed
  if (logToFile) {
    NSError* error = nil;
    [[NSFileManager defaultManager]
              createDirectoryAtPath:[kDefaultLogFilePath stringByDeletingLastPathComponent]
        withIntermediateDirectories:YES
                         attributes:nil
                              error:&error];
    if (error) {
      DNSLogError(LogCategoryGeneral, "Failed to create log directory: %{public}@",
                  error.localizedDescription);
    }
  }
}

// Log to file if enabled
void logToFileIfEnabled(NSString* message) {
  if (!logToFile)
    return;

  @autoreleasepool {
    NSString* timestamp = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                         dateStyle:NSDateFormatterShortStyle
                                                         timeStyle:NSDateFormatterMediumStyle];
    NSString* logEntry = [NSString stringWithFormat:@"[%@] %@\n", timestamp, message];

    // Append to file
    NSFileHandle* fileHandle = [NSFileHandle fileHandleForWritingAtPath:kDefaultLogFilePath];
    if (fileHandle) {
      [fileHandle seekToEndOfFile];
      [fileHandle writeData:[logEntry dataUsingEncoding:NSUTF8StringEncoding]];
      [fileHandle closeFile];
    } else {
      // Create file if it doesn't exist
      [logEntry writeToFile:kDefaultLogFilePath
                 atomically:YES
                   encoding:NSUTF8StringEncoding
                      error:nil];
    }
  }
}

int main(int argc, char* argv[]) {
  @autoreleasepool {
    // Initialize logging first
    initLogging();

    // Log startup
    DNSLogInfo(LogCategoryGeneral, "DNShield Network Extension starting...");
    logToFileIfEnabled(@"DNShield Network Extension starting...");

    // Start system extension mode early (as per LuLu pattern)
    // This must be called before any other code
    [NEProvider startSystemExtensionMode];

    DNSLogInfo(LogCategoryGeneral, "System extension mode started");
    logToFileIfEnabled(@"System extension mode started");

    // Dispatch main never returns
    dispatch_main();
  }

  return 0;
}
