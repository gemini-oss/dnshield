//
//  AppDelegate.m
//  DNShield
//

#import "AppDelegate.h"
#import "DNRuleDataProvider.h"
#import "DNSProxyConfigurationManager.h"
#import "DNSStateColorPreferencesController.h"
#import "DNShieldDaemonService.h"
#import "Defaults.h"
#import "Extension.h"
#import "LoggingManager.h"
#import "StatusMenuController.h"

#import <os/log.h>
#import <unistd.h>

extern os_log_t logHandle;

#define ACTION_ACTIVATE 1

@interface AppDelegate ()

@property(strong) Extension* extensionManager;
@property(strong) DNSProxyConfigurationManager* proxyManager;
@property(strong) DNShieldDaemonService* daemonService;
@property(strong) DNRuleDataProvider* ruleDataProvider;
@property(strong) DNSStateColorPreferencesController* colorController;
@property(strong) StatusMenuController* statusMenuController;
@property(assign) BOOL isDaemonMode;

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification*)aNotification {
  os_log(logHandle, "DNShield app launched");

  self.extensionManager = [[Extension alloc] init];
  self.daemonService = [[DNShieldDaemonService alloc] init];
  [self.daemonService start];

  self.proxyManager =
      [[DNSProxyConfigurationManager alloc] initWithExtensionManager:self.extensionManager];
  [self.proxyManager migrateUserPreferencesToAppGroupIfNeeded];
  [self.proxyManager updateDNSProxyConfigurationAsync];

  self.ruleDataProvider = [[DNRuleDataProvider alloc] initWithProxyManager:self.proxyManager];
  self.colorController = [[DNSStateColorPreferencesController alloc] init];

  self.statusMenuController =
      [[StatusMenuController alloc] initWithProxyManager:self.proxyManager
                                           daemonService:self.daemonService
                                        ruleDataProvider:self.ruleDataProvider
                                        extensionManager:self.extensionManager
                              colorPreferencesController:self.colorController];

  [self detectLaunchContext];

  if (self.isDaemonMode && ![self wasLaunchedByUser]) {
    [NSApp terminate:nil];
    return;
  }

  if ([self isAnotherInstanceRunning]) {
    [NSApp terminate:nil];
    return;
  }

  if ([self shouldShowUI]) {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [self.statusMenuController setupStatusBar];
  } else {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
  }

  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                 dispatch_get_main_queue(), ^{
                   [self.proxyManager checkAndEnableMDMDNSProxy];
                 });

  if (!self.isDaemonMode) {
    [self requestSystemExtensionActivation];
  }
}

- (void)applicationWillTerminate:(NSNotification*)aNotification {
  [self.statusMenuController invalidate];
  [self.daemonService stop];
}

#pragma mark - Launch Context Detection

- (void)detectLaunchContext {
  NSDictionary* env = [[NSProcessInfo processInfo] environment];

  NSString* launchdPID = env[@"LaunchInstanceID"];
  if (launchdPID) {
    self.isDaemonMode = YES;
    DNSLogInfo(LogCategoryGeneral, "Detected launchd environment: %{public}@", launchdPID);
  }

  pid_t ppid = getppid();
  if (ppid == 1) {
    self.isDaemonMode = YES;
    DNSLogInfo(LogCategoryGeneral, "Parent process is launchd (PID 1)");
  }

  NSString* execPath = [[NSBundle mainBundle] executablePath];
  if ([execPath containsString:@"/Library/"] || [execPath containsString:@"/System/"]) {
    self.isDaemonMode = YES;
    DNSLogInfo(LogCategoryGeneral, "Launched from system path: %{public}@", execPath);
  }
}

- (BOOL)isAnotherInstanceRunning {
  NSArray* runningApps = [[NSWorkspace sharedWorkspace] runningApplications];
  NSString* bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
  int instanceCount = 0;

  for (NSRunningApplication* app in runningApps) {
    if ([app.bundleIdentifier isEqualToString:bundleIdentifier]) {
      instanceCount++;
    }
  }

  if (instanceCount > 1) {
    os_log(logHandle, "Another instance of DNShield is already running, terminating this instance");

    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"DNShield Already Running";
    alert.informativeText =
        @"Another instance of DNShield is already running. This instance will now quit.";
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
    return YES;
  }

  return NO;
}

- (BOOL)wasLaunchedByUser {
  NSAppleEventDescriptor* event = [[NSAppleEventManager sharedAppleEventManager] currentAppleEvent];
  if (event) {
    AEEventID eventID = [event eventID];
    if (eventID == kAEOpenApplication || eventID == kAEReopenApplication) {
      return YES;
    }
  }

  NSArray* args = [[NSProcessInfo processInfo] arguments];
  if ([args containsObject:@"--show-ui"] || [args containsObject:@"--menu-bar"]) {
    return YES;
  }

  NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
  if ([bundlePath hasPrefix:@"/Applications/"] && ![bundlePath containsString:@"/System/"]) {
    return YES;
  }

  return NO;
}

- (BOOL)shouldShowUI {
  NSArray* args = [[NSProcessInfo processInfo] arguments];
  if ([args containsObject:@"--show-ui"] || [args containsObject:@"--menu-bar"]) {
    return YES;
  }

  if (self.isDaemonMode && ![self wasLaunchedByUser]) {
    return NO;
  }

  return YES;
}

#pragma mark - System Extension Activation

- (void)requestSystemExtensionActivation {
  DNSLogInfo(LogCategoryGeneral, "Requesting system extension activation");

  if (!self.extensionManager) {
    DNSLogError(LogCategoryGeneral, "No extension manager available");
    return;
  }

  [self.extensionManager
      toggleExtension:ACTION_ACTIVATE
                reply:^(BOOL success) {
                  if (success) {
                    DNSLogInfo(LogCategoryGeneral, "System extension activation request succeeded");
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2.0 * NSEC_PER_SEC),
                                   dispatch_get_main_queue(), ^{
                                     DNSLogInfo(LogCategoryConfiguration,
                                                "Configuring and enabling DNS proxy");
                                     [self.extensionManager toggleNetworkExtension:ACTION_ACTIVATE];
                                   });
                  } else {
                    DNSLogError(LogCategoryGeneral, "System extension activation request failed");
                  }
                }];
}

@end
