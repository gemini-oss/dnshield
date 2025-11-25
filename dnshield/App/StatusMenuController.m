//
//  StatusMenuController.m
//  DNShield
//

#import "StatusMenuController.h"

#import "AdvancedNetworkSettingsWindowController.h"
#import "CacheSettingsWindowController.h"
#import "DNShieldPreferences.h"
#import "Defaults.h"
#import "Extension.h"
#import "LogGatheringWindowController.h"
#import "LoggingManager.h"
#import "ManifestsWindowController.h"
#import "ModernLogViewerController.h"
#import "RulesWindowController.h"

#import <NetworkExtension/NetworkExtension.h>
#import <os/log.h>

#define ACTION_ACTIVATE 1
#define ACTION_DEACTIVATE 0

extern os_log_t logHandle;

@interface StatusMenuController ()

@property(nonatomic, strong) Extension* extensionManager;
@property(nonatomic, strong) DNSProxyConfigurationManager* proxyManager;
@property(nonatomic, strong) DNShieldDaemonService* daemonService;
@property(nonatomic, strong) DNRuleDataProvider* ruleDataProvider;
@property(nonatomic, strong) DNSStateColorPreferencesController* colorController;

@property(nonatomic, strong) NSMenu* statusMenu;
@property(nonatomic, strong) NSMenuItem* stalePidWarningItem;
@property(nonatomic, strong) NSTimer* pidCheckTimer;

@property(nonatomic, strong) RulesWindowController* rulesWindowController;
@property(nonatomic, strong) ManifestsWindowController* manifestsWindowController;
@property(nonatomic, strong) CacheSettingsWindowController* cacheSettingsWindowController;
@property(nonatomic, strong)
    AdvancedNetworkSettingsWindowController* advancedNetworkSettingsWindowController;
@property(nonatomic, strong) LogGatheringWindowController* logGatheringWindowController;
@property(nonatomic, strong) ModernLogViewerController* modernLogViewerController;

@end

@implementation StatusMenuController

- (instancetype)initWithProxyManager:(DNSProxyConfigurationManager*)proxyManager
                       daemonService:(DNShieldDaemonService*)daemonService
                    ruleDataProvider:(DNRuleDataProvider*)ruleDataProvider
                    extensionManager:(Extension*)extensionManager
          colorPreferencesController:(DNSStateColorPreferencesController*)colorController {
  self = [super init];
  if (self) {
    _proxyManager = proxyManager;
    _daemonService = daemonService;
    _ruleDataProvider = ruleDataProvider;
    _extensionManager = extensionManager;
    _colorController = colorController;

    _proxyManager.delegate = self;
    _daemonService.delegate = self;
    _colorController.delegate = self;
  }
  return self;
}

- (void)dealloc {
  [self invalidate];
}

- (void)setupStatusBar {
  self->_statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
  if (!self.statusItem)
    return;

  [self.colorController start];

  [self updateMenuBarIconColor];

  self.statusMenu = [[NSMenu alloc] init];
  self.statusMenu.delegate = self;

  [self.statusMenu addItemWithTitle:@"DNShield" action:nil keyEquivalent:@""];

  NSString* version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  NSString* versionString = [NSString stringWithFormat:@"Version %@", version ?: @"0"];
  NSMenuItem* versionItem = [[NSMenuItem alloc] initWithTitle:versionString
                                                       action:nil
                                                keyEquivalent:@""];
  versionItem.enabled = NO;
  [self.statusMenu addItem:versionItem];

  [self.statusMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* statusItem = [[NSMenuItem alloc] initWithTitle:@"Status"
                                                      action:@selector(showStatus)
                                               keyEquivalent:@""];
  statusItem.target = self;
  [self.statusMenu addItem:statusItem];

  [self.statusMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* rulesMenuItem = [[NSMenuItem alloc] initWithTitle:@"Rules"
                                                         action:nil
                                                  keyEquivalent:@""];
  NSMenu* rulesMenu = [[NSMenu alloc] init];

  NSMenuItem* viewRulesItem = [[NSMenuItem alloc] initWithTitle:@"View Rules"
                                                         action:@selector(viewCurrentRules)
                                                  keyEquivalent:@""];
  viewRulesItem.target = self;
  [rulesMenu addItem:viewRulesItem];

  NSMenuItem* syncRulesItem = [[NSMenuItem alloc] initWithTitle:@"Sync Rules"
                                                         action:@selector(syncRules)
                                                  keyEquivalent:@""];
  syncRulesItem.target = self;
  [rulesMenu addItem:syncRulesItem];

  rulesMenuItem.submenu = rulesMenu;
  [self.statusMenu addItem:rulesMenuItem];

  NSMenuItem* manifestsItem = [[NSMenuItem alloc] initWithTitle:@"Manifests"
                                                         action:@selector(showManifests)
                                                  keyEquivalent:@""];
  manifestsItem.target = self;
  [self.statusMenu addItem:manifestsItem];

  NSMenuItem* cacheMenuItem = [[NSMenuItem alloc] initWithTitle:@"Cache"
                                                         action:nil
                                                  keyEquivalent:@""];
  NSMenu* cacheMenu = [[NSMenu alloc] init];

  NSMenuItem* toggleCacheItem = [[NSMenuItem alloc] initWithTitle:@"Toggle DNS Cache"
                                                           action:@selector(toggleDNSCache:)
                                                    keyEquivalent:@""];
  toggleCacheItem.target = self;
  toggleCacheItem.tag = 1003;
  [cacheMenu addItem:toggleCacheItem];

  NSMenuItem* clearCacheItem = [[NSMenuItem alloc] initWithTitle:@"Clear Cache"
                                                          action:@selector(clearDNSCache)
                                                   keyEquivalent:@""];
  clearCacheItem.target = self;
  clearCacheItem.tag = 3003;
  [cacheMenu addItem:clearCacheItem];

  NSMenuItem* cacheSettingsItem = [[NSMenuItem alloc] initWithTitle:@"Settings..."
                                                             action:@selector(showCacheSettings)
                                                      keyEquivalent:@""];
  cacheSettingsItem.target = self;
  cacheSettingsItem.tag = 3004;
  [cacheMenu addItem:cacheSettingsItem];

  cacheMenuItem.submenu = cacheMenu;
  [self.statusMenu addItem:cacheMenuItem];

  [self.statusMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* advancedMenuItem = [[NSMenuItem alloc] initWithTitle:@"Advanced"
                                                            action:nil
                                                     keyEquivalent:@""];
  NSMenu* advancedMenu = [[NSMenu alloc] init];

  NSMenuItem* networkSettingsItem =
      [[NSMenuItem alloc] initWithTitle:@"Network Settings..."
                                 action:@selector(showAdvancedNetworkSettings)
                          keyEquivalent:@""];
  networkSettingsItem.target = self;
  [advancedMenu addItem:networkSettingsItem];

  NSMenuItem* gatherLogsItem = [[NSMenuItem alloc] initWithTitle:@"Logs"
                                                          action:@selector(showLogGathering)
                                                   keyEquivalent:@""];
  gatherLogsItem.target = self;
  [advancedMenu addItem:gatherLogsItem];

  advancedMenuItem.submenu = advancedMenu;
  [self.statusMenu addItem:advancedMenuItem];

  [self.statusMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* settingsMenuItem = [[NSMenuItem alloc] initWithTitle:@"Settings"
                                                            action:nil
                                                     keyEquivalent:@""];
  NSMenu* settingsMenu = [[NSMenu alloc] init];

  NSMenuItem* iconColorMenuItem = [[NSMenuItem alloc] initWithTitle:@"Icon Color"
                                                             action:nil
                                                      keyEquivalent:@""];
  NSMenu* colorMenu = [[NSMenu alloc] init];

  NSArray* colorOptions = @[
    @{@"title" : @"Default Orange", @"color" : [NSColor systemOrangeColor]}, @{
      @"title" : @"DNShield Blue",
      @"color" : [NSColor colorWithCalibratedRed:0.0 green:0.31 blue:0.78 alpha:1.0]
    },
    @{@"title" : @"Security Green", @"color" : [NSColor systemGreenColor]},
    @{@"title" : @"Alert Red", @"color" : [NSColor systemRedColor]},
    @{@"title" : @"Neutral Gray", @"color" : [NSColor systemGrayColor]}
  ];

  for (NSDictionary* option in colorOptions) {
    NSMenuItem* colorItem = [[NSMenuItem alloc] initWithTitle:option[@"title"]
                                                       action:@selector(handleIconColorMenu:)
                                                keyEquivalent:@""];
    colorItem.target = self;
    colorItem.representedObject = option[@"color"];
    [colorMenu addItem:colorItem];
  }

  [colorMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* colorModeItem = [[NSMenuItem alloc] initWithTitle:@"Automatic State Colors"
                                                         action:@selector(toggleStateColorMode:)
                                                  keyEquivalent:@""];
  colorModeItem.target = self;
  colorModeItem.tag = 1000;
  colorModeItem.state = (self.colorController.stateColorManager.colorMode == DNSColorModeStateBased)
                            ? NSControlStateValueOn
                            : NSControlStateValueOff;
  [colorMenu addItem:colorModeItem];

  NSMenuItem* colorTargetItem = [[NSMenuItem alloc] initWithTitle:@"Apply To"
                                                           action:nil
                                                    keyEquivalent:@""];
  NSMenu* targetSubmenu = [[NSMenu alloc] init];
  NSArray* targets = @[
    @{@"title" : @"Both", @"tag" : @0}, @{@"title" : @"Shield Only", @"tag" : @1},
    @{@"title" : @"Globe Only", @"tag" : @2}
  ];
  for (NSDictionary* target in targets) {
    NSMenuItem* targetItem = [[NSMenuItem alloc] initWithTitle:target[@"title"]
                                                        action:@selector(changeColorTarget:)
                                                 keyEquivalent:@""];
    targetItem.target = self;
    targetItem.tag = [target[@"tag"] integerValue];
    targetItem.state = (targetItem.tag == self.colorController.colorTargetSelection)
                           ? NSControlStateValueOn
                           : NSControlStateValueOff;
    [targetSubmenu addItem:targetItem];
  }
  colorTargetItem.submenu = targetSubmenu;
  [colorMenu addItem:colorTargetItem];

  [colorMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* customColorItem = [[NSMenuItem alloc] initWithTitle:@"Custom Color…"
                                                           action:@selector(openColorPicker)
                                                    keyEquivalent:@""];
  customColorItem.target = self;
  [colorMenu addItem:customColorItem];

  [colorMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* configureStatesItem =
      [[NSMenuItem alloc] initWithTitle:@"Configure State Colors…"
                                 action:@selector(openStateColorConfiguration)
                          keyEquivalent:@""];
  configureStatesItem.target = self;
  [colorMenu addItem:configureStatesItem];

  iconColorMenuItem.submenu = colorMenu;
  [settingsMenu addItem:iconColorMenuItem];

  settingsMenuItem.submenu = settingsMenu;
  [self.statusMenu addItem:settingsMenuItem];

  NSMenuItem* installItem = [[NSMenuItem alloc] initWithTitle:@"Install Extension"
                                                       action:@selector(installExtension)
                                                keyEquivalent:@""];
  installItem.target = self;
  installItem.tag = 3001;
  [self.statusMenu addItem:installItem];

  NSMenuItem* uninstallItem = [[NSMenuItem alloc] initWithTitle:@"Uninstall Extension"
                                                         action:@selector(uninstallExtension)
                                                  keyEquivalent:@""];
  uninstallItem.target = self;
  uninstallItem.tag = 3002;
  [self.statusMenu addItem:uninstallItem];

  [self.statusMenu addItem:[NSMenuItem separatorItem]];

  NSMenuItem* quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit"
                                                    action:@selector(quit)
                                             keyEquivalent:@"q"];
  quitItem.target = self;
  [self.statusMenu addItem:quitItem];

  self.stalePidWarningItem =
      [[NSMenuItem alloc] initWithTitle:@"⚠️ Stale Daemon Process Detected - Click to Fix"
                                 action:@selector(showStalePidWarning)
                          keyEquivalent:@""];
  self.stalePidWarningItem.target = self;
  self.stalePidWarningItem.hidden = YES;
  [self.statusMenu addItem:self.stalePidWarningItem];

  self.statusItem.menu = self.statusMenu;

  [self updateMenuBarForMDMState];

  self.pidCheckTimer = [NSTimer scheduledTimerWithTimeInterval:15.0
                                                        target:self
                                                      selector:@selector(runPidCheck)
                                                      userInfo:nil
                                                       repeats:YES];
  [self.pidCheckTimer fire];
}

- (void)invalidate {
  [self.pidCheckTimer invalidate];
  self.pidCheckTimer = nil;
  [self.colorController stop];
  [self.daemonService stop];
}

- (void)runPidCheck {
  [self.daemonService checkForStalePidFile];
}

- (void)updateMenuBarForMDMState {
  BOOL shouldHideExtensionItems =
      self.proxyManager.isMDMManaged && self.proxyManager.cachedDNSProxyConfigured;

  for (NSMenuItem* item in self.statusMenu.itemArray) {
    if (item.tag == 3001 || item.tag == 3002) {
      item.hidden = shouldHideExtensionItems;
    }
  }
}

#pragma mark - Menu Actions

- (void)showStatus {
  os_log(logHandle, "Showing status");

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    __block BOOL extensionRunning = NO;
    __block BOOL networkExtensionEnabled = NO;
    __block NSDictionary* syncInfo = nil;

    dispatch_group_t group = dispatch_group_create();

    if (self.daemonService.daemonAvailable) {
      dispatch_group_enter(group);
      [self.daemonService
          requestStatusWithReply:^(NSDictionary* _Nullable reply, NSError* _Nullable error) {
            if (reply) {
              extensionRunning = [reply[@"extensionInstalled"] boolValue];
              networkExtensionEnabled = [reply[@"filterEnabled"] boolValue];
            }
            dispatch_group_leave(group);
          }];
    } else {
      dispatch_group_enter(group);
      dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        extensionRunning = [self.extensionManager isExtensionRunning];
        dispatch_group_leave(group);
      });

      dispatch_group_enter(group);
      dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        networkExtensionEnabled = [self.extensionManager isNetworkExtensionEnabled];
        dispatch_group_leave(group);
      });
    }

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
      syncInfo = [self.ruleDataProvider syncStatusDirectly];
      dispatch_group_leave(group);
    });

    dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));

    [NEDNSProxyManager.sharedManager
        loadFromPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
          dispatch_async(dispatch_get_main_queue(), ^{
            NSString* status = @"Unknown";
            NSMutableString* details = [NSMutableString string];

            if (error) {
              status = [NSString stringWithFormat:@"Error: %@", error.localizedDescription];
            } else if (NEDNSProxyManager.sharedManager.isEnabled) {
              status = @"DNS Proxy is active";
            } else {
              status = @"DNS Proxy is not active";
            }

            [details appendFormat:@"\nExtension running: %@\nNetwork filter enabled: %@",
                                  extensionRunning ? @"Yes" : @"No",
                                  networkExtensionEnabled ? @"Yes" : @"No"];

            if (syncInfo) {
              NSNumber* ruleCount = syncInfo[@"ruleCount"];
              if (ruleCount) {
                [details appendFormat:@"\nActive rules: %@", ruleCount];
              }
            }

            NSAlert* alert = [[NSAlert alloc] init];
            alert.messageText = @"DNShield Status";
            alert.informativeText = [status stringByAppendingString:details];
            [alert addButtonWithTitle:@"OK"];
            [alert addButtonWithTitle:@"Last Sync"];
            [alert addButtonWithTitle:@"DNS Servers"];

            NSModalResponse response = [alert runModal];
            if (response == NSAlertSecondButtonReturn) {
              [self showLastSyncStatus:syncInfo];
            } else if (response == NSAlertThirdButtonReturn) {
              [self showDNSServersStatus:syncInfo];
            }
          });
        }];
  });
}

- (void)showLastSyncStatus:(NSDictionary*)syncInfo {
  NSMutableString* details = [NSMutableString string];

  if (syncInfo && !syncInfo[@"error"]) {
    NSDate* lastRuleSync = syncInfo[@"lastRuleSync"];
    NSString* syncNote = syncInfo[@"syncNote"];

    if (lastRuleSync) {
      NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
      formatter.dateStyle = NSDateFormatterMediumStyle;
      formatter.timeStyle = NSDateFormatterMediumStyle;
      [details appendFormat:@"Last rule sync: %@", [formatter stringFromDate:lastRuleSync]];

      if (syncNote) {
        [details appendFormat:@" (%@)", syncNote];
      }
    } else if (syncNote) {
      [details appendString:syncNote];
    } else {
      [details appendString:@"Last rule sync: Never"];
    }

    NSNumber* ruleCount = syncInfo[@"ruleCount"];
    if (ruleCount) {
      [details appendFormat:@"\n\nActive rules: %@", ruleCount];
    }
  } else {
    [details appendString:@"Sync information unavailable - no connection to extension"];
  }

  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Last Sync Status";
  alert.informativeText = details;
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];
}

- (void)showDNSServersStatus:(NSDictionary*)syncInfo {
  NSMutableString* details = [NSMutableString string];

  if (syncInfo && !syncInfo[@"error"]) {
    NSArray* resolvers = syncInfo[@"dnsResolvers"];
    if (resolvers.count > 0) {
      [details appendString:@"System DNS Servers:"];
      for (NSString* resolver in resolvers) {
        [details appendFormat:@"\n• %@", resolver];
      }
    } else {
      [details appendString:@"System DNS Servers: Not available"];
    }

    NSArray* upstreamServers = syncInfo[@"upstreamDNSServers"];
    if (upstreamServers.count > 0) {
      [details appendString:@"\n\nUpstream DNS Servers (forwarded to):"];
      for (NSString* server in upstreamServers) {
        [details appendFormat:@"\n• %@", server];
      }
    } else {
      [details appendString:@"\n\nUpstream DNS Servers: Not configured"];
    }
  } else {
    [details appendString:@"DNS server information unavailable - no connection to extension"];
  }

  NSArray* systemServers = [self.ruleDataProvider systemDNSServersFallback];
  if (systemServers.count > 0) {
    [details appendString:@"\n\nFallback - System DNS Servers (from scutil):"];
    for (NSString* server in systemServers) {
      [details appendFormat:@"\n• %@", server];
    }
  }

  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"DNS Servers";
  alert.informativeText = details;
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];
}

- (void)viewCurrentRules {
  __weak typeof(self) weakSelf = self;
  [self.ruleDataProvider fetchRulesWithCompletion:^(
                             NSArray* blockedDomains, NSArray* allowedDomains,
                             NSDictionary* ruleSources, NSDictionary* configInfo,
                             NSDictionary* syncInfo, NSError* _Nullable error) {
    dispatch_async(dispatch_get_main_queue(), ^{
      __strong typeof(self) strongSelf = weakSelf;
      if (!strongSelf)
        return;

      if (error && blockedDomains.count == 0 && allowedDomains.count == 0) {
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"Unable to Load Rules";
        alert.informativeText =
            error.localizedDescription ?: @"The rules database could not be read.";
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
        return;
      }

      if (strongSelf.rulesWindowController) {
        [strongSelf.rulesWindowController close];
        strongSelf.rulesWindowController = nil;
      }

      strongSelf.rulesWindowController = [[RulesWindowController alloc] initWithRules:blockedDomains
                                                                       allowedDomains:allowedDomains
                                                                          ruleSources:ruleSources
                                                                           configInfo:configInfo
                                                                             syncInfo:syncInfo];
      [strongSelf.rulesWindowController showWindow:nil];
      [strongSelf.rulesWindowController.window makeKeyAndOrderFront:nil];
      [NSApp activateIgnoringOtherApps:YES];
    });
  }];
}

- (void)syncRules {
  DNSLogInfo(LogCategoryRuleFetching, "Manual rule sync requested by user");

  NSString* commandId = [[NSUUID UUID] UUIDString];
  NSDictionary* command = @{
    @"commandId" : commandId,
    @"type" : @"syncRules",
    @"timestamp" : @([[NSDate date] timeIntervalSince1970]),
    @"source" : @"menu_bar_app"
  };

  NSError* error = nil;
  if ([self.daemonService writeCommand:command error:&error]) {
    DNSLogInfo(LogCategoryRuleFetching, "Wrote syncRules command file successfully");

    NSAlert* progressAlert = [[NSAlert alloc] init];
    progressAlert.messageText = @"Sync Initiated";
    progressAlert.informativeText =
        @"Rule sync has been initiated. The rules will be updated momentarily.";
    [progressAlert addButtonWithTitle:@"OK"];
    [progressAlert runModal];

    [self logTelemetryEvent:@"sync_rules_initiated"
                   metadata:@{
                     @"event_id" : [[NSUUID UUID] UUIDString],
                     @"command_id" : commandId,
                     @"method" : @"file_based_command"
                   }];
  } else {
    DNSLogError(LogCategoryError, "Failed to write syncRules command: %{public}@", error);

    NSAlert* failAlert = [[NSAlert alloc] init];
    failAlert.messageText = @"Sync Failed";
    failAlert.informativeText =
        [NSString stringWithFormat:@"Failed to initiate rule sync: %@", error.localizedDescription];
    failAlert.alertStyle = NSAlertStyleWarning;
    [failAlert addButtonWithTitle:@"OK"];
    [failAlert runModal];
  }
}

- (void)showManifests {
  DNSLogInfo(LogCategoryGeneral, "Showing manifests view");

  NSString* manifestURL = nil;
  NSError* error = nil;
  NSArray* manifestData = [self.ruleDataProvider manifestEntriesWithURL:&manifestURL error:&error];

  if (!manifestData) {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"No Manifests Found";
    alert.informativeText =
        error.localizedDescription ?: @"No manifest cache found. Please sync rules first.";
    alert.alertStyle = NSAlertStyleWarning;
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
    return;
  }

  if (self.manifestsWindowController) {
    [self.manifestsWindowController close];
    self.manifestsWindowController = nil;
  }

  self.manifestsWindowController =
      [[ManifestsWindowController alloc] initWithManifestData:manifestData manifestURL:manifestURL];
  [self.manifestsWindowController showWindow:nil];
  [self.manifestsWindowController.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)installExtension {
  os_log(logHandle, "Installing system extension");

  if (self.daemonService.daemonAvailable) {
    [self.daemonService sendCommand:@"enable"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                     [self showStatus];
                   });
  } else {
    [self.extensionManager
        toggleExtension:ACTION_ACTIVATE
                  reply:^(BOOL success) {
                    if (success) {
                      os_log(logHandle, "Extension installation succeeded");
                      dispatch_async(dispatch_get_main_queue(), ^{
                        [self configureNetworkFilter];
                      });
                    } else {
                      DNSLogError(LogCategoryGeneral, "Extension installation failed");
                    }
                  }];
  }
}

- (void)uninstallExtension {
  os_log(logHandle, "Uninstalling system extension");

  if (self.daemonService.daemonAvailable) {
    [self.daemonService sendCommand:@"disable"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                     NSAlert* alert = [[NSAlert alloc] init];
                     alert.messageText = @"Extension Uninstallation";
                     alert.informativeText = @"Extension uninstall request sent to daemon";
                     [alert addButtonWithTitle:@"OK"];
                     [alert runModal];
                   });
  } else {
    if ([self.extensionManager toggleNetworkExtension:ACTION_DEACTIVATE]) {
      os_log(logHandle, "Network extension disabled successfully");
    }

    [self.extensionManager toggleExtension:ACTION_DEACTIVATE
                                     reply:^(BOOL success) {
                                       dispatch_async(dispatch_get_main_queue(), ^{
                                         NSAlert* alert = [[NSAlert alloc] init];
                                         alert.messageText = @"Extension Uninstallation";
                                         alert.informativeText =
                                             success ? @"Extension uninstalled successfully"
                                                     : @"Extension uninstallation failed";
                                         [alert addButtonWithTitle:@"OK"];
                                         [alert runModal];
                                       });
                                     }];
  }
}

- (void)configureNetworkFilter {
  os_log(logHandle, "Configuring DNS proxy");

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    if ([self.extensionManager toggleNetworkExtension:ACTION_ACTIVATE]) {
      os_log(logHandle, "Network extension enabled successfully");
      dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"DNS Proxy Configured";
        alert.informativeText = @"DNShield is now protecting your DNS queries.";
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
      });
    } else {
      DNSLogError(LogCategoryConfiguration, "Failed to enable network extension");
      dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"Configuration Failed";
        alert.informativeText = @"Failed to enable the network extension.";
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
      });
    }
  });
}

- (void)showCacheSettings {
  if (self.cacheSettingsWindowController) {
    [self.cacheSettingsWindowController close];
    self.cacheSettingsWindowController = nil;
  }

  self.cacheSettingsWindowController = [[CacheSettingsWindowController alloc] init];
  [self.cacheSettingsWindowController showWindow:nil];
  [self.cacheSettingsWindowController.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)showAdvancedNetworkSettings {
  if (self.advancedNetworkSettingsWindowController) {
    [self.advancedNetworkSettingsWindowController close];
    self.advancedNetworkSettingsWindowController = nil;
  }

  self.advancedNetworkSettingsWindowController =
      [[AdvancedNetworkSettingsWindowController alloc] init];
  [self.advancedNetworkSettingsWindowController showWindow:nil];
  [self.advancedNetworkSettingsWindowController.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)showLogGathering {
  if (self.logGatheringWindowController) {
    [self.logGatheringWindowController close];
    self.logGatheringWindowController = nil;
  }

  if (self.modernLogViewerController) {
    [self.modernLogViewerController close];
    self.modernLogViewerController = nil;
  }

  self.modernLogViewerController = [[ModernLogViewerController alloc] init];
  [self.modernLogViewerController showWindow:nil];
  [self.modernLogViewerController.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)toggleDNSCache:(NSMenuItem*)sender {
  BOOL legacyValueExists = DNPreferenceHasUserValue(kDNShieldEnableDNSCache);
  if (legacyValueExists) {
    DNPreferenceRemoveValue(kDNShieldEnableDNSCache);
  }

  BOOL currentState = DNPreferenceGetBool(kDNShieldUserCanAdjustCache, NO);
  BOOL newState = !currentState;

  DNSLogInfo(LogCategoryCache, "Toggling user DNS cache preference from %d to %d", currentState,
             newState);

  DNPreferenceSetBool(kDNShieldUserCanAdjustCache, newState);

  NSString* message = newState ? @"DNS caching has been enabled" : @"DNS caching has been disabled";
  NSString* detail = newState
                         ? @"DNS responses will be cached to improve performance. You may need to "
                           @"clear the cache if you experience issues with VPN services."
                         : @"DNS responses will not be cached. This may reduce performance but "
                           @"improves compatibility with VPN and authentication services.";

  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = message;
  alert.informativeText = detail;
  alert.alertStyle = NSAlertStyleInformational;
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];

  [self logTelemetryEvent:@"dns_cache_toggled"
                 metadata:@{@"enabled" : @(newState), @"source" : @"menu_bar"}];
}

- (void)clearDNSCache {
  DNSLogInfo(LogCategoryCache, "Clear DNS cache requested by user");

  NSString* eventId = [[NSUUID UUID] UUIDString];
  [self logTelemetryEvent:@"cache_clear_requested"
                 metadata:@{@"event_id" : eventId, @"source" : @"menu_bar_button"}];

  NSString* commandId = [[NSUUID UUID] UUIDString];
  NSDictionary* command = @{
    @"commandId" : commandId,
    @"type" : @"clearCache",
    @"timestamp" : @([[NSDate date] timeIntervalSince1970]),
    @"source" : @"menu_bar_app"
  };

  NSError* error = nil;
  if ([self.daemonService writeCommand:command error:&error]) {
    DNSLogInfo(LogCategoryCache, "Wrote clearCache command file successfully");

    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"Cache Cleared";
    alert.informativeText =
        @"DNS cache clear request sent successfully. The cache will be refreshed momentarily.";
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];

    [self logTelemetryEvent:@"cache_clear_succeeded"
                   metadata:@{@"event_id" : eventId, @"command_id" : commandId}];
  } else {
    DNSLogError(LogCategoryCache, "Failed to write clearCache command: %{public}@", error);

    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"Cache Clear Failed";
    alert.informativeText =
        [NSString stringWithFormat:@"Failed to clear DNS cache: %@", error.localizedDescription];
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];

    [self logTelemetryEvent:@"cache_clear_failed"
                   metadata:@{
                     @"event_id" : eventId,
                     @"command_id" : commandId,
                     @"error" : error.localizedDescription ?: @"unknown"
                   }];
  }
}

- (void)quit {
  [NSApp terminate:nil];
}

- (void)openColorPicker {
  [self.colorController showColorPicker];
}

- (void)openStateColorConfiguration {
  [self.colorController showStateColorConfiguration];
}

- (void)handleIconColorMenu:(NSMenuItem*)sender {
  [self.colorController changeIconColorWithMenuItem:sender];
}

- (void)toggleStateColorMode:(NSMenuItem*)sender {
  [self.colorController toggleStateColorMode];
  sender.state = (self.colorController.stateColorManager.colorMode == DNSColorModeStateBased)
                     ? NSControlStateValueOn
                     : NSControlStateValueOff;
  [self updateMenuBarIconColor];
}

- (void)changeColorTarget:(NSMenuItem*)sender {
  [self.colorController selectColorTarget:sender.tag];
  for (NSMenuItem* item in sender.menu.itemArray) {
    item.state = (item.tag == sender.tag) ? NSControlStateValueOn : NSControlStateValueOff;
  }
}

- (void)showStalePidWarning {
  [self.daemonService showStalePidWarning];
}

#pragma mark - Icon Handling

- (void)updateMenuBarIconColor {
  if (!self.statusItem)
    return;

  NSColor* iconColor = [self.colorController.stateColorManager currentColor];
  NSImage* menuBarIcon = [NSImage imageWithSystemSymbolName:@"network.badge.shield.half.filled"
                                   accessibilityDescription:@"DNShield"];

  if (menuBarIcon) {
    NSImage* finalIcon = nil;
    if (@available(macOS 12.0, *)) {
      NSArray<NSColor*>* paletteColors = [self.colorController
          paletteColorsForStateColor:iconColor ?: [NSColor systemOrangeColor]];
      NSImageSymbolConfiguration* config =
          [NSImageSymbolConfiguration configurationWithPaletteColors:paletteColors];
      finalIcon = [menuBarIcon imageWithSymbolConfiguration:config];
    }

    if (!finalIcon) {
      finalIcon = [menuBarIcon copy];
      [finalIcon setTemplate:NO];

      NSColor* shieldColor = self.colorController.stateColorManager.manualShieldColor ?: iconColor;
      NSColor* globeColor =
          self.colorController.stateColorManager.manualGlobeColor
              ?: [self.colorController
                     complementaryColorForColor:iconColor ?: [NSColor systemOrangeColor]];

      NSImage* tintedIcon = [finalIcon copy];
      [tintedIcon lockFocus];
      [shieldColor set];
      NSRectFillUsingOperation(
          NSMakeRect(0, 0, tintedIcon.size.width / 2.0, tintedIcon.size.height),
          NSCompositingOperationSourceOver);
      [globeColor set];
      NSRectFillUsingOperation(NSMakeRect(tintedIcon.size.width / 2.0, 0,
                                          tintedIcon.size.width / 2.0, tintedIcon.size.height),
                               NSCompositingOperationSourceOver);
      [tintedIcon unlockFocus];
      finalIcon = tintedIcon;
    }

    self.statusItem.button.image = finalIcon;
  }
}

#pragma mark - NSMenuDelegate

- (void)menuNeedsUpdate:(NSMenu*)menu {
  if (menu != self.statusMenu)
    return;

  if (!self.proxyManager.lastDNSProxyCheck ||
      [[NSDate date] timeIntervalSinceDate:self.proxyManager.lastDNSProxyCheck] > 30.0) {
    [self.proxyManager updateDNSProxyConfigurationAsync];
  }

  BOOL cacheManaged = DNPreferenceIsManaged(kDNShieldEnableDNSCache);
  BOOL managedValue = DNPreferenceGetBool(kDNShieldEnableDNSCache, NO);

  BOOL userOverrideExists = DNPreferenceHasUserValue(kDNShieldUserCanAdjustCache);
  BOOL legacyOverrideExists = DNPreferenceHasUserValue(kDNShieldEnableDNSCache);
  BOOL userCachePreference = NO;
  if (userOverrideExists) {
    userCachePreference = DNPreferenceGetBool(kDNShieldUserCanAdjustCache, NO);
  } else if (legacyOverrideExists) {
    userCachePreference = DNPreferenceGetBool(kDNShieldEnableDNSCache, NO);
  }

  BOOL cacheEnabled = cacheManaged ? managedValue : userCachePreference;
  BOOL userCanAdjustCache = DNPreferenceGetBool(kDNShieldUserCanAdjustCacheTTL, NO);

  for (NSMenuItem* item in menu.itemArray) {
    if ([item.title isEqualToString:@"Cache"] && item.submenu) {
      for (NSMenuItem* subItem in item.submenu.itemArray) {
        if (subItem.tag == 1003) {
          subItem.state = cacheEnabled ? NSControlStateValueOn : NSControlStateValueOff;
          subItem.enabled = !cacheManaged;
        } else if (subItem.tag == 3004) {
          subItem.enabled = userCanAdjustCache;
        }
      }
    }
  }
}

#pragma mark - Delegates

- (void)stateColorPreferencesControllerDidUpdateColors:
    (DNSStateColorPreferencesController*)controller {
  [self updateMenuBarIconColor];
}

- (void)daemonService:(DNShieldDaemonService*)service didUpdateAvailability:(BOOL)available {
  [self updateMenuBarForMDMState];
}

- (void)daemonService:(DNShieldDaemonService*)service didDetectStalePidFile:(BOOL)hasStale {
  self.stalePidWarningItem.hidden = !hasStale;
}

- (void)dnsProxyConfigurationManagerDidUpdateState:
    (DNSProxyConfigurationManager*)configurationManager {
  [self updateMenuBarForMDMState];
}

#pragma mark - Telemetry

- (void)logTelemetryEvent:(NSString*)eventType metadata:(NSDictionary*)metadata {
  DNSLogInfo(LogCategoryTelemetry, "Telemetry Event: %{public}@ - %{public}@", eventType, metadata);
}

@end
