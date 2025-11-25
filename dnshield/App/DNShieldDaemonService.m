//
//  DNShieldDaemonService.m
//  DNShield
//

#import "DNShieldDaemonService.h"

#import "DNShieldPreferences.h"
#import "LoggingManager.h"

#import <os/log.h>

#include <errno.h>
#include <signal.h>
#include <unistd.h>

extern os_log_t logHandle;

static NSString* const kDNShieldDaemonServiceName = @"com.dnshield.daemon.xpc";

@interface DNShieldDaemonService ()

@property(nonatomic, assign) BOOL daemonAvailable;
@property(nonatomic, assign) BOOL hasStalePidFile;
@property(nonatomic) xpc_connection_t daemonConnection;

@end

@implementation DNShieldDaemonService

- (void)dealloc {
  [self stop];
}

- (void)start {
  [self stop];

  self.daemonConnection = xpc_connection_create_mach_service(kDNShieldDaemonServiceName.UTF8String,
                                                             dispatch_get_main_queue(), 0);

  __weak typeof(self) weakSelf = self;
  xpc_connection_set_event_handler(self.daemonConnection, ^(xpc_object_t event) {
    __strong typeof(self) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    xpc_type_t type = xpc_get_type(event);
    if (type == XPC_TYPE_ERROR) {
      if (event == XPC_ERROR_CONNECTION_INVALID || event == XPC_ERROR_CONNECTION_INTERRUPTED) {
        DNSLogInfo(LogCategoryGeneral, "Daemon connection not available");
        [strongSelf updateDaemonAvailability:NO];
      }
    }
  });

  xpc_connection_resume(self.daemonConnection);

  xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(message, "command", "status");

  xpc_connection_send_message_with_reply(
      self.daemonConnection, message, dispatch_get_main_queue(), ^(xpc_object_t reply) {
        __strong typeof(self) strongSelf = weakSelf;
        if (!strongSelf)
          return;

        if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
          BOOL daemonRunning = xpc_dictionary_get_bool(reply, "daemonRunning");
          [strongSelf updateDaemonAvailability:daemonRunning];
        } else {
          [strongSelf updateDaemonAvailability:NO];
        }
      });
}

- (void)stop {
  if (self.daemonConnection) {
    xpc_connection_cancel(self.daemonConnection);
    self.daemonConnection = nil;
  }
  [self updateDaemonAvailability:NO];
}

- (void)sendCommand:(NSString*)command {
  if (!self.daemonAvailable || !self.daemonConnection) {
    DNSLogError(LogCategoryGeneral, "Cannot send command to daemon - not available");
    return;
  }

  xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(message, "command", command.UTF8String);

  xpc_connection_send_message_with_reply(
      self.daemonConnection, message, dispatch_get_main_queue(), ^(xpc_object_t reply) {
        xpc_type_t type = xpc_get_type(reply);
        if (type == XPC_TYPE_DICTIONARY) {
          BOOL success = xpc_dictionary_get_bool(reply, "success");
          const char* error = xpc_dictionary_get_string(reply, "error");

          if (success) {
            DNSLogInfo(LogCategoryGeneral, "Daemon command '%{public}@' succeeded", command);
          } else if (error) {
            DNSLogError(LogCategoryGeneral, "Daemon command '%{public}@' failed: %{public}s",
                        command, error);
          }
        }
      });
}

- (void)requestStatusWithReply:(void (^)(NSDictionary* _Nullable, NSError* _Nullable))replyBlock {
  if (!self.daemonAvailable || !self.daemonConnection) {
    if (replyBlock) {
      replyBlock(nil, [NSError errorWithDomain:NSPOSIXErrorDomain code:ECONNREFUSED userInfo:nil]);
    }
    return;
  }

  xpc_object_t statusMsg = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(statusMsg, "command", "status");

  xpc_connection_send_message_with_reply(
      self.daemonConnection, statusMsg,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(xpc_object_t reply) {
        NSMutableDictionary* result = nil;
        NSError* error = nil;

        if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
          result = [NSMutableDictionary dictionary];
          result[@"extensionInstalled"] = @(xpc_dictionary_get_bool(reply, "extensionInstalled"));
          result[@"filterEnabled"] = @(xpc_dictionary_get_bool(reply, "filterEnabled"));
          result[@"daemonRunning"] = @(xpc_dictionary_get_bool(reply, "daemonRunning"));
        } else {
          error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
        }

        if (replyBlock) {
          replyBlock([result copy], error);
        }
      });
}

- (BOOL)writeCommand:(NSDictionary*)command error:(NSError**)error {
  NSFileManager* fm = [NSFileManager defaultManager];
  NSString* commandDir = @"/Library/Application Support/DNShield/Commands/incoming";

  if (![fm isWritableFileAtPath:commandDir] && ![fm fileExistsAtPath:commandDir]) {
    DNSLogInfo(LogCategoryGeneral,
               "System command directory not writable, using shared defaults method");
    NSUserDefaults* sharedDefaults = DNSharedDefaults();
    [sharedDefaults setObject:command[@"type"] ?: @"unknown" forKey:@"DNSProxyCommand"];
    [sharedDefaults synchronize];
    return YES;
  }

  if (![fm fileExistsAtPath:commandDir]) {
    if (![fm createDirectoryAtPath:commandDir
            withIntermediateDirectories:YES
                             attributes:nil
                                  error:error]) {
      DNSLogError(LogCategoryError, "Failed to create command directory: %{public}@", *error);
      NSUserDefaults* sharedDefaults = DNSharedDefaults();
      [sharedDefaults setObject:@"clearCache" forKey:@"DNSProxyCommand"];
      [sharedDefaults synchronize];
      return YES;
    }
  }

  NSString* filename = [NSString
      stringWithFormat:@"command_%@_%@.json", @((NSInteger)[[NSDate date] timeIntervalSince1970]),
                       command[@"commandId"] ?: [[NSUUID UUID] UUIDString]];
  NSString* filePath = [commandDir stringByAppendingPathComponent:filename];

  NSData* jsonData = [NSJSONSerialization dataWithJSONObject:command options:0 error:error];
  if (!jsonData) {
    DNSLogError(LogCategoryError, "Failed to serialize command JSON: %{public}@", *error);
    return NO;
  }

  if (![jsonData writeToFile:filePath options:NSDataWritingAtomic error:error]) {
    DNSLogError(LogCategoryError, "Failed to write command file: %{public}@", *error);
    return NO;
  }

  os_log(logHandle, "Wrote DNS command file to %{public}@", filePath);
  return YES;
}

- (void)checkForStalePidFile {
  NSString* pidFilePath = @"/var/run/dnshield.pid";

  if (![[NSFileManager defaultManager] fileExistsAtPath:pidFilePath]) {
    [self updateStalePidState:NO];
    return;
  }

  NSError* error = nil;
  NSString* pidString = [NSString stringWithContentsOfFile:pidFilePath
                                                  encoding:NSUTF8StringEncoding
                                                     error:&error];
  if (error || pidString.length == 0) {
    DNSLogInfo(LogCategoryGeneral, "PID file exists but cannot read contents: %@", error);
    [self markPidFileAsStale];
    return;
  }

  NSString* trimmedPidString =
      [pidString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  pid_t pid = (pid_t)[trimmedPidString intValue];
  if (pid <= 0) {
    DNSLogInfo(LogCategoryGeneral, "PID file contains invalid PID: %@", pidString);
    [self markPidFileAsStale];
    return;
  }

  errno = 0;
  int killResult = kill(pid, 0);

  if (killResult == 0) {
    NSTask* task = [[NSTask alloc] init];
    task.launchPath = @"/bin/ps";
    task.arguments = @[ @"-p", [NSString stringWithFormat:@"%d", pid], @"-o", @"comm=" ];

    NSPipe* pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;

    @try {
      [task launch];
      [task waitUntilExit];

      if (task.terminationStatus == 0) {
        NSData* data = [[pipe fileHandleForReading] readDataToEndOfFile];
        NSString* processName = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        processName = [processName
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        if ([processName containsString:@"dnshield-daemon"]) {
          [self updateStalePidState:NO];
          return;
        } else {
          DNSLogInfo(LogCategoryGeneral, "PID %d belongs to different process: %@", pid,
                     processName);
          [self markPidFileAsStale];
          return;
        }
      }
    } @catch (NSException* exception) {
      DNSLogError(LogCategoryError, "Error checking process: %@", exception);
    }
  } else if (errno == EPERM) {
    DNSLogInfo(LogCategoryGeneral,
               "PID %d appears to be running but access is denied (EPERM). Assuming daemon is "
               "healthy.",
               pid);
    [self updateStalePidState:NO];
    return;
  } else {
    DNSLogInfo(LogCategoryGeneral, "Process with PID %d does not exist", pid);
    [self markPidFileAsStale];
    return;
  }
}

- (void)showStalePidWarning {
  DNSLogInfo(LogCategoryGeneral, "User clicked stale PID warning menu item");

  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Stale Daemon PID Detected";
  alert.informativeText =
      @"DNShield detected a leftover daemon PID file. This prevents the daemon from starting "
      @"correctly and keeps System Settings in a warning state. Try the automatic cleanup first or "
      @"run the Terminal commands if that fails.";
  alert.alertStyle = NSAlertStyleWarning;

  [alert addButtonWithTitle:@"Fix Automatically"];
  [alert addButtonWithTitle:@"Show Terminal Commands"];
  [alert addButtonWithTitle:@"Cancel"];

  [[alert buttons][0] setKeyEquivalent:@"\r"];

  NSModalResponse response = [alert runModal];

  if (response == NSAlertFirstButtonReturn) {
    [self attemptAutomaticCleanup];
  } else if (response == NSAlertSecondButtonReturn) {
    [self showManualCleanupInstructions:nil];
  }
}

- (void)attemptAutomaticCleanup {
  DNSLogInfo(LogCategoryGeneral,
             "Attempting automatic cleanup of stale PID file using dnshield-ctl status");

  NSString* ctlPath = @"/usr/local/bin/dnshield-ctl";
  if (![[NSFileManager defaultManager] isExecutableFileAtPath:ctlPath]) {
    [self showManualCleanupInstructions:@"dnshield-ctl utility not found or not executable."];
    return;
  }

  NSTask* task = [[NSTask alloc] init];
  task.launchPath = ctlPath;
  task.arguments = @[ @"status" ];

  NSPipe* outputPipe = [NSPipe pipe];
  NSPipe* errorPipe = [NSPipe pipe];
  task.standardOutput = outputPipe;
  task.standardError = errorPipe;

  @try {
    [task launch];
    [task waitUntilExit];
  } @catch (NSException* exception) {
    DNSLogError(LogCategoryError, "Failed to run dnshield-ctl: %@", exception);
    [self showManualCleanupInstructions:exception.reason];
    return;
  }

  NSData* errorData = [[errorPipe fileHandleForReading] readDataToEndOfFile];
  NSString* errorOutput =
      [[NSString alloc] initWithData:errorData encoding:NSUTF8StringEncoding] ?: @"";
  if (task.terminationStatus != 0) {
    NSString* message = errorOutput.length > 0 ? errorOutput : @"dnshield-ctl returned non-zero";
    [self showManualCleanupInstructions:message];
    return;
  }

  // Re-check PID file
  if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/run/dnshield.pid"]) {
    DNSLogInfo(LogCategoryGeneral,
               "PID file still exists after dnshield-ctl status; prompting manual cleanup");
    [self showManualCleanupInstructions:@"Automatic cleanup could not remove the PID file."];
    return;
  }

  [self updateStalePidState:NO];
  DNSLogInfo(LogCategoryGeneral, "Automatic cleanup removed stale PID file");

  NSAlert* successAlert = [[NSAlert alloc] init];
  successAlert.messageText = @"Cleanup Complete";
  successAlert.informativeText =
      @"The stale daemon PID file was removed. If DNS protection is still disabled, restart the "
      @"daemon using: sudo /usr/local/bin/dnshield-ctl restart";
  successAlert.alertStyle = NSAlertStyleInformational;
  [successAlert addButtonWithTitle:@"OK"];
  [successAlert runModal];
}

- (void)showManualCleanupInstructions:(NSString*)errorMessage {
  NSString* removeCommand = @"sudo rm -f /var/run/dnshield.pid";
  NSString* restartCommand = @"sudo /usr/local/bin/dnshield-ctl restart";

  NSMutableString* details = [NSMutableString
      stringWithFormat:@"DNShield detected a stale daemon PID file that must be cleaned up "
                       @"manually.\n\nRun these commands in Terminal:\n%@\n%@",
                       removeCommand, restartCommand];
  if (errorMessage.length > 0) {
    [details appendFormat:@"\n\nAdditional information: %@", errorMessage];
  }

  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Manual Cleanup Required";
  alert.informativeText = details;
  alert.alertStyle = NSAlertStyleWarning;
  [alert addButtonWithTitle:@"Copy Commands"];
  [alert addButtonWithTitle:@"OK"];

  NSModalResponse response = [alert runModal];
  if (response == NSAlertFirstButtonReturn) {
    NSString* commands = [NSString stringWithFormat:@"%@\n%@", removeCommand, restartCommand];
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
    [pasteboard clearContents];
    [pasteboard setString:commands forType:NSPasteboardTypeString];

    NSAlert* copiedAlert = [[NSAlert alloc] init];
    copiedAlert.messageText = @"Commands Copied";
    copiedAlert.informativeText =
        @"The cleanup commands have been copied to your clipboard. Paste them into Terminal to "
        @"remove the stale PID file and restart the daemon.";
    [copiedAlert addButtonWithTitle:@"OK"];
    [copiedAlert runModal];
  }
}

- (void)markPidFileAsStale {
  if (!self.hasStalePidFile) {
    DNSLogError(LogCategoryGeneral, "Stale PID file detected, showing warning menu item");
  }
  [self updateStalePidState:YES];
}

- (void)updateDaemonAvailability:(BOOL)available {
  if (_daemonAvailable == available) {
    return;
  }

  _daemonAvailable = available;
  if ([self.delegate respondsToSelector:@selector(daemonService:didUpdateAvailability:)]) {
    [self.delegate daemonService:self didUpdateAvailability:available];
  }
}

- (void)updateStalePidState:(BOOL)hasStale {
  if (_hasStalePidFile == hasStale) {
    return;
  }

  _hasStalePidFile = hasStale;
  if ([self.delegate respondsToSelector:@selector(daemonService:didDetectStalePidFile:)]) {
    [self.delegate daemonService:self didDetectStalePidFile:hasStale];
  }
}

@end
