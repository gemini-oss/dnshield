//
//  main.m
//  DNShield
//
//

#import <Cocoa/Cocoa.h>
#import <SystemExtensions/SystemExtensions.h>
#import <os/log.h>
#import "LoggingManager.h"

// Globals
os_log_t logHandle = nil;

// System Extension Delegate
@interface DNShieldSystemExtensionDelegate : NSObject <OSSystemExtensionRequestDelegate>
@end

@implementation DNShieldSystemExtensionDelegate

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest*)request
                  actionForReplacingExtension:(OSSystemExtensionProperties*)oldExt
                                withExtension:(OSSystemExtensionProperties*)newExt {
  DNSLogInfo(LogCategoryGeneral, "SystemExtension \"%{public}@\" request for replacement",
             request.identifier);
  // Always replace - let macOS handle version comparison
  return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest*)request {
  DNSLogInfo(LogCategoryGeneral, "SystemExtension \"%{public}@\" request needs user approval",
             request.identifier);
  // Exit with code 1 to indicate user approval needed
  exit(1);
}

- (void)request:(OSSystemExtensionRequest*)request didFailWithError:(NSError*)error {
  DNSLogError(LogCategoryGeneral, "SystemExtension \"%{public}@\" request failed: %{public}@",
              request.identifier, error);
  exit((int)error.code);
}

- (void)request:(OSSystemExtensionRequest*)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
  DNSLogInfo(LogCategoryGeneral, "SystemExtension \"%{public}@\" request finished: %ld",
             request.identifier, (long)result);
  exit(0);
}

@end

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    // Init log
    logHandle = os_log_create("com.dnshield", "application");

    // Debug message
    DNSLogDebug(LogCategoryGeneral, "DNShield started: %{public}@ (pid: %d / uid: %d)",
                NSProcessInfo.processInfo.arguments.firstObject, getpid(), getuid());

    // Check for command-line arguments
    if (NSProcessInfo.processInfo.arguments.count > 1) {
      NSString* arg = NSProcessInfo.processInfo.arguments[1];

      if ([arg isEqualToString:@"--load-system-extension"]) {
        DNSLogInfo(LogCategoryGeneral, "Requesting SystemExtension activation");

        NSString* extensionID = @"com.dnshield.extension";
        dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);

        OSSystemExtensionRequest* request =
            [OSSystemExtensionRequest activationRequestForExtension:extensionID queue:queue];
        if (request) {
          DNShieldSystemExtensionDelegate* delegate =
              [[DNShieldSystemExtensionDelegate alloc] init];
          request.delegate = delegate;
          [[OSSystemExtensionManager sharedManager] submitRequest:request];

          // Wait up to 60 seconds for completion
          dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 60), queue, ^{
            DNSLogError(LogCategoryGeneral, "SystemExtension activation timeout");
            exit(1);
          });

          // Run the main loop
          [[NSRunLoop mainRunLoop] run];
        }
        return 1;
      }

      if ([arg isEqualToString:@"extension"]) {
        // Extension command - handled by the Go binary
        // This shouldn't happen in the app bundle context
        DNSLogError(LogCategoryGeneral,
                    "Extension commands should be run from the command line binary");
        return 1;
      }
    }

    // Launch the app
    return NSApplicationMain(argc, argv);
  }
}
