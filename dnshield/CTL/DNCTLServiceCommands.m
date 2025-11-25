#import "DNCTLCommands.h"

#import <signal.h>

#import "Common/Defaults.h"
#import "DNCTLCommon.h"

void DNCTLCommandStart(void) {
  DNCTLEnsureRoot();
  DNCTLLogInfo(@"Starting DNShield daemon...");
  DNCTLCleanupStalePID();
  pid_t pid = DNCTLFindDaemonPID();
  if (pid > 0) {
    DNCTLLogWarning([NSString stringWithFormat:@"Daemon is already running (PID: %d)", pid]);
    return;
  }
  DNCTLRunEnvCommand(@"launchctl", @[ @"load", @"-w", kDNShieldDaemonPlistPath ]);
  DNCTLRunEnvCommand(@"launchctl", @[ @"start", kDNShieldDaemonBundleID ]);
  sleep(1);
  pid = DNCTLFindDaemonPID();
  if (pid > 0) {
    DNCTLLogSuccess([NSString stringWithFormat:@"Daemon started (PID: %d)", pid]);
  } else {
    DNCTLLogError(@"Failed to start daemon. Check logs for more information.");
  }
}

void DNCTLCommandStop(void) {
  DNCTLEnsureRoot();
  DNCTLLogInfo(@"Stopping DNShield daemon...");
  pid_t pid = DNCTLFindDaemonPID();
  if (pid <= 0) {
    DNCTLLogWarning(@"Daemon is not running");
    return;
  }
  DNCTLRunEnvCommand(@"launchctl", @[ @"stop", kDNShieldDaemonBundleID ]);
  sleep(1);
  if (DNCTLProcessExists(pid)) {
    kill(pid, SIGTERM);
  }
  DNCTLCleanupStalePID();
  DNCTLLogSuccess(@"Daemon stopped");
}

void DNCTLCommandRestart(void) {
  DNCTLCommandStop();
  sleep(1);
  DNCTLCommandStart();
}

void DNCTLCommandEnable(void) {
  DNCTLEnsureRoot();
  pid_t pid = DNCTLFindDaemonPID();
  if (pid <= 0) {
    DNCTLLogError(@"Daemon is not running. Start it before enabling.");
    exit(EXIT_FAILURE);
  }

  if ([[NSFileManager defaultManager] isExecutableFileAtPath:kDNShieldXPCBinaryPath]) {
    DNCTLLogInfo(@"Requesting enable via dnshield-xpc");
    CommandResult* result = DNCTLRunStreamingCommand(kDNShieldXPCBinaryPath, @[ @"enable" ]);
    if (result.status != 0) {
      DNCTLLogError(result.stderrString ?: @"dnshield-xpc enable failed");
      exit(EXIT_FAILURE);
    }
    return;
  }

  DNCTLLogInfo(@"Signaling daemon to enable filtering");
  DNCTLSendCommandFile(@"enable", pid);
}

void DNCTLCommandDisable(void) {
  DNCTLEnsureRoot();
  pid_t pid = DNCTLFindDaemonPID();
  if (pid <= 0) {
    DNCTLLogError(@"Daemon is not running. Nothing to disable.");
    exit(EXIT_FAILURE);
  }
  DNCTLSendCommandFile(@"disable", pid);
  DNCTLLogSuccess(@"Disable signal sent");
}
