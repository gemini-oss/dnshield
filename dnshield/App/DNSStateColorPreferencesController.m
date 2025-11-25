//
//  DNSStateColorPreferencesController.m
//  DNShield
//

#import "DNSStateColorPreferencesController.h"

#import "LoggingManager.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

@interface DNSStateColorPreferencesController () <DNSStateColorManagerDelegate>

@property(nonatomic, strong) NSTimer* networkStateCheckTimer;
@property(nonatomic, strong) NSArray* cachedVPNResolvers;
@property(nonatomic, strong) NSDate* vpnResolversCacheTime;
@property(nonatomic, weak) NSView* stateColorConfigView;
@property(nonatomic, assign, readwrite) NSInteger colorTargetSelection;

@end

@implementation DNSStateColorPreferencesController

- (instancetype)init {
  self = [super init];
  if (self) {
    _stateColorManager = [DNSStateColorManager sharedManager];
    _stateColorManager.delegate = self;
    _colorTargetSelection =
        [[NSUserDefaults standardUserDefaults] integerForKey:@"DNSIconColorTarget"];
    if (_colorTargetSelection < 0 || _colorTargetSelection > 2) {
      _colorTargetSelection = 0;
    }
  }
  return self;
}

- (void)start {
  [self startNetworkStateMonitoring];
}

- (void)stop {
  [self.networkStateCheckTimer invalidate];
  self.networkStateCheckTimer = nil;
}

- (void)showColorPicker {
  DNSLogInfo(LogCategoryGeneral, "showColorPicker called");

  NSColorPanel* colorPanel = [NSColorPanel sharedColorPanel];
  colorPanel.target = self;
  colorPanel.action = @selector(colorPanelChanged:);
  [colorPanel setShowsAlpha:NO];

  NSColor* currentColor = [self.stateColorManager currentColor];
  if (currentColor) {
    [colorPanel setColor:currentColor];
  }

  [colorPanel makeKeyAndOrderFront:nil];
  dispatch_async(dispatch_get_main_queue(), ^{
    [colorPanel makeKeyWindow];
  });
}

- (void)colorPanelChanged:(NSColorPanel*)sender {
  NSColor* selectedColor = sender.color;

  DNSLogInfo(LogCategoryGeneral, "colorPanelChanged called with color: %{public}@",
             [DNSStateColorManager hexStringFromColor:selectedColor]);

  switch (self.colorTargetSelection) {
    case 0:
      self.stateColorManager.manualShieldColor = selectedColor;
      self.stateColorManager.manualGlobeColor = selectedColor;
      self.stateColorManager.manualColor = selectedColor;
      break;
    case 1:
      self.stateColorManager.manualShieldColor = selectedColor;
      if (!self.stateColorManager.manualGlobeColor) {
        self.stateColorManager.manualGlobeColor = [NSColor systemBlueColor];
      }
      break;
    case 2:
      self.stateColorManager.manualGlobeColor = selectedColor;
      if (!self.stateColorManager.manualShieldColor) {
        self.stateColorManager.manualShieldColor = [NSColor systemBlueColor];
      }
      break;
  }

  [self.stateColorManager setManualOverrideState:YES];
  [self notifyDelegateOfColorUpdate];
}

- (void)toggleStateColorMode {
  BOOL isCurrentlyStateBased = (self.stateColorManager.colorMode == DNSColorModeStateBased);
  [self.stateColorManager setManualOverrideState:isCurrentlyStateBased];
  [self notifyDelegateOfColorUpdate];
  DNSLogInfo(LogCategoryGeneral, "Color mode toggled. Now state-based: %d",
             self.stateColorManager.colorMode == DNSColorModeStateBased);
}

- (void)selectColorTarget:(NSInteger)target {
  self.colorTargetSelection = target;
  [[NSUserDefaults standardUserDefaults] setInteger:target forKey:@"DNSIconColorTarget"];
  DNSLogInfo(LogCategoryGeneral, "Color target changed to: %ld", (long)target);
}

- (void)changeIconColorWithMenuItem:(NSMenuItem*)sender {
  NSColor* selectedColor = sender.representedObject;
  if (!selectedColor)
    return;

  for (NSMenuItem* item in sender.menu.itemArray) {
    if (item.representedObject && [item.representedObject isKindOfClass:[NSColor class]]) {
      item.state = NSControlStateValueOff;
    }
  }
  sender.state = NSControlStateValueOn;

  switch (self.colorTargetSelection) {
    case 0:
      self.stateColorManager.manualShieldColor = selectedColor;
      self.stateColorManager.manualGlobeColor = selectedColor;
      self.stateColorManager.manualColor = selectedColor;
      break;
    case 1:
      self.stateColorManager.manualShieldColor = selectedColor;
      if (!self.stateColorManager.manualGlobeColor) {
        self.stateColorManager.manualGlobeColor = [NSColor systemBlueColor];
      }
      self.stateColorManager.manualColor = selectedColor;
      break;
    case 2:
      self.stateColorManager.manualGlobeColor = selectedColor;
      if (!self.stateColorManager.manualShieldColor) {
        self.stateColorManager.manualShieldColor = [NSColor systemBlueColor];
      }
      self.stateColorManager.manualColor = self.stateColorManager.manualShieldColor;
      break;
  }

  [self.stateColorManager setManualOverrideState:YES];
  [self notifyDelegateOfColorUpdate];
}

- (void)showStateColorConfiguration {
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Configure State Colors";
  alert.informativeText = @"Set shield and globe colors for each network state. Click Apply next "
                          @"to each state to save its colors.";
  alert.alertStyle = NSAlertStyleInformational;

  NSView* configView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 520, 150)];

  NSTextField* stateHeader = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 120, 120, 20)];
  stateHeader.stringValue = @"Network State";
  stateHeader.bordered = NO;
  stateHeader.editable = NO;
  stateHeader.backgroundColor = [NSColor clearColor];
  stateHeader.font = [NSFont boldSystemFontOfSize:12];
  [configView addSubview:stateHeader];

  NSTextField* shieldHeader = [[NSTextField alloc] initWithFrame:NSMakeRect(180, 120, 60, 20)];
  shieldHeader.stringValue = @"Shield";
  shieldHeader.bordered = NO;
  shieldHeader.editable = NO;
  shieldHeader.backgroundColor = [NSColor clearColor];
  shieldHeader.font = [NSFont boldSystemFontOfSize:12];
  shieldHeader.alignment = NSTextAlignmentCenter;
  [configView addSubview:shieldHeader];

  NSTextField* globeHeader = [[NSTextField alloc] initWithFrame:NSMakeRect(260, 120, 60, 20)];
  globeHeader.stringValue = @"Globe";
  globeHeader.bordered = NO;
  globeHeader.editable = NO;
  globeHeader.backgroundColor = [NSColor clearColor];
  globeHeader.font = [NSFont boldSystemFontOfSize:12];
  globeHeader.alignment = NSTextAlignmentCenter;
  [configView addSubview:globeHeader];

  NSBox* separator = [[NSBox alloc] initWithFrame:NSMakeRect(15, 110, 490, 1)];
  separator.boxType = NSBoxSeparator;
  [configView addSubview:separator];

  NSArray<NSNumber*>* states =
      @[ @(DNSNetworkStateOnline), @(DNSNetworkStateOffline), @(DNSNetworkStateVPNConnected) ];
  CGFloat yOffset = 85;
  for (NSNumber* stateNumber in states) {
    DNSNetworkState state = stateNumber.integerValue;
    NSString* stateName = [DNSStateColorManager displayNameForState:state];

    NSTextField* label = [[NSTextField alloc] initWithFrame:NSMakeRect(20, yOffset + 2, 140, 20)];
    label.stringValue = stateName;
    label.bordered = NO;
    label.editable = NO;
    label.backgroundColor = [NSColor clearColor];
    label.font = [NSFont systemFontOfSize:13];
    [configView addSubview:label];

    NSColorWell* shieldColorWell =
        [[NSColorWell alloc] initWithFrame:NSMakeRect(180, yOffset, 50, 24)];
    shieldColorWell.color = [self.stateColorManager shieldColorForState:state];
    shieldColorWell.tag = state + 2000;
    shieldColorWell.bordered = YES;
    [configView addSubview:shieldColorWell];

    NSColorWell* globeColorWell =
        [[NSColorWell alloc] initWithFrame:NSMakeRect(260, yOffset, 50, 24)];
    globeColorWell.color = [self.stateColorManager globeColorForState:state];
    globeColorWell.tag = state + 3000;
    globeColorWell.bordered = YES;
    [configView addSubview:globeColorWell];

    NSTextField* hexLabel =
        [[NSTextField alloc] initWithFrame:NSMakeRect(330, yOffset + 2, 100, 20)];
    NSString* shieldHex = [DNSStateColorManager hexStringFromColor:shieldColorWell.color];
    NSString* globeHex = [DNSStateColorManager hexStringFromColor:globeColorWell.color];
    hexLabel.stringValue = [NSString stringWithFormat:@"#%@|#%@", [shieldHex substringFromIndex:1],
                                                      [globeHex substringFromIndex:1]];
    hexLabel.bordered = NO;
    hexLabel.editable = NO;
    hexLabel.backgroundColor = [NSColor clearColor];
    hexLabel.font = [NSFont monospacedSystemFontOfSize:10 weight:NSFontWeightRegular];
    hexLabel.textColor = [NSColor secondaryLabelColor];
    hexLabel.tag = state + 1000;
    [configView addSubview:hexLabel];

    NSButton* applyButton = [[NSButton alloc] initWithFrame:NSMakeRect(440, yOffset, 60, 24)];
    applyButton.title = @"Apply";
    applyButton.bezelStyle = NSBezelStyleRounded;
    applyButton.tag = state + 4000;
    applyButton.target = self;
    applyButton.action = @selector(applyStateColor:);
    [configView addSubview:applyButton];

    yOffset -= 35;
  }

  alert.accessoryView = configView;
  [alert addButtonWithTitle:@"Done"];

  self.stateColorConfigView = configView;
  [alert runModal];
  self.stateColorConfigView = nil;
}

- (NSArray<NSColor*>*)paletteColorsForStateColor:(NSColor*)primaryColor {
  if (!self.stateColorManager || self.stateColorManager.colorMode == DNSColorModeManual) {
    NSColor* shieldColor = self.stateColorManager.manualShieldColor ?: primaryColor;
    NSColor* globeColor = self.stateColorManager.manualGlobeColor ?: primaryColor;
    if (!self.stateColorManager.manualShieldColor && !self.stateColorManager.manualGlobeColor) {
      shieldColor = primaryColor;
      globeColor = primaryColor;
    }
    return @[ shieldColor, globeColor ];
  }

  DNSNetworkState currentState = self.stateColorManager.currentState;
  NSColor* shieldColor = [self.stateColorManager shieldColorForState:currentState];
  NSColor* globeColor = [self.stateColorManager globeColorForState:currentState];

  DNSLogInfo(LogCategoryGeneral,
             "State-based palette for %{public}@ - Shield: %{public}@, Globe: %{public}@",
             [DNSStateColorManager displayNameForState:currentState],
             [DNSStateColorManager hexStringFromColor:shieldColor],
             [DNSStateColorManager hexStringFromColor:globeColor]);

  return @[ shieldColor, globeColor ];
}

- (NSColor*)complementaryColorForColor:(NSColor*)color {
  NSColor* rgbColor = [color colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
  if (!rgbColor)
    return [NSColor systemGrayColor];

  CGFloat red, green, blue, alpha;
  [rgbColor getRed:&red green:&green blue:&blue alpha:&alpha];

  CGFloat compRed = 1.0 - red;
  CGFloat compGreen = 1.0 - green;
  CGFloat compBlue = 1.0 - blue;

  CGFloat brightness = (compRed + compGreen + compBlue) / 3.0;
  if (brightness < 0.3) {
    compRed = MIN(1.0, compRed + 0.4);
    compGreen = MIN(1.0, compGreen + 0.4);
    compBlue = MIN(1.0, compBlue + 0.4);
  } else if (brightness > 0.7) {
    compRed = MAX(0.0, compRed - 0.4);
    compGreen = MAX(0.0, compGreen - 0.4);
    compBlue = MAX(0.0, compBlue - 0.4);
  }

  return [NSColor colorWithRed:compRed green:compGreen blue:compBlue alpha:alpha];
}

- (void)applyStateColor:(NSButton*)sender {
  if (!self.stateColorConfigView)
    return;

  DNSNetworkState state = sender.tag - 4000;
  NSColorWell* shieldWell = (NSColorWell*)[self.stateColorConfigView viewWithTag:state + 2000];
  NSColorWell* globeWell = (NSColorWell*)[self.stateColorConfigView viewWithTag:state + 3000];
  NSTextField* hexLabel = (NSTextField*)[self.stateColorConfigView viewWithTag:state + 1000];

  if (shieldWell && globeWell) {
    NSColor* shieldColor = shieldWell.color;
    NSColor* globeColor = globeWell.color;

    [self.stateColorManager setShieldColor:shieldColor forState:state];
    [self.stateColorManager setGlobeColor:globeColor forState:state];

    if (hexLabel) {
      NSString* shieldHex = [DNSStateColorManager hexStringFromColor:shieldColor];
      NSString* globeHex = [DNSStateColorManager hexStringFromColor:globeColor];
      hexLabel.stringValue =
          [NSString stringWithFormat:@"#%@|#%@", [shieldHex substringFromIndex:1],
                                     [globeHex substringFromIndex:1]];
    }

    if (self.stateColorManager.colorMode != DNSColorModeStateBased) {
      [self.stateColorManager setManualOverrideState:NO];
    }

    if (state == self.stateColorManager.currentState) {
      [self notifyDelegateOfColorUpdate];
    }

    DNSLogInfo(LogCategoryGeneral,
               "Applied colors to state %{public}@ - Shield: %{public}@, Globe: %{public}@",
               [DNSStateColorManager displayNameForState:state],
               [DNSStateColorManager hexStringFromColor:shieldColor],
               [DNSStateColorManager hexStringFromColor:globeColor]);

    sender.enabled = NO;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                     sender.enabled = YES;
                   });
  }
}

- (void)notifyDelegateOfColorUpdate {
  if ([self.delegate
          respondsToSelector:@selector(stateColorPreferencesControllerDidUpdateColors:)]) {
    [self.delegate stateColorPreferencesControllerDidUpdateColors:self];
  }
}

#pragma mark - Network State Monitoring

- (void)startNetworkStateMonitoring {
  self.networkStateCheckTimer = [NSTimer scheduledTimerWithTimeInterval:5.0
                                                                 target:self
                                                               selector:@selector(checkNetworkState)
                                                               userInfo:nil
                                                                repeats:YES];
  [self checkNetworkState];
}

- (void)checkNetworkState {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    BOOL isVPNConnected = [self isVPNConnected];
    NSInteger networkStatus = [self getNetworkStatus];

    DNSLogDebug(LogCategoryGeneral,
                "Network state check - Status: %ld, VPN: %d, Current state: %{public}@",
                (long)networkStatus, isVPNConnected,
                [DNSStateColorManager displayNameForState:self.stateColorManager.currentState]);

    dispatch_async(dispatch_get_main_queue(), ^{
      [self.stateColorManager updateStateBasedOnNetworkStatus:networkStatus
                                               isVPNConnected:isVPNConnected];
    });
  });
}

- (BOOL)isVPNConnected {
  NSArray* vpnResolvers = nil;

  if (self.cachedVPNResolvers && self.vpnResolversCacheTime &&
      [[NSDate date] timeIntervalSinceDate:self.vpnResolversCacheTime] < 60.0) {
    vpnResolvers = self.cachedVPNResolvers;
  } else {
    NSFileManager* fileManager = [NSFileManager defaultManager];
    NSString* managedPrefsPath = @"/Library/Managed Preferences";
    NSArray* managedPrefFiles = [fileManager contentsOfDirectoryAtPath:managedPrefsPath error:nil];

    if (managedPrefFiles) {
      for (NSString* dirName in managedPrefFiles) {
        NSString* plistPath =
            [NSString stringWithFormat:@"%@/%@/com.dnshield.app.plist", managedPrefsPath, dirName];
        NSDictionary* managedPrefs = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (managedPrefs[@"VPNResolvers"]) {
          vpnResolvers = managedPrefs[@"VPNResolvers"];
          break;
        }
      }
    }

    if (!vpnResolvers) {
      NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
      vpnResolvers = [defaults arrayForKey:@"VPNResolvers"];
    }

    self.cachedVPNResolvers = vpnResolvers;
    self.vpnResolversCacheTime = [NSDate date];
  }

  struct ifaddrs* interfaces;
  if (getifaddrs(&interfaces) != 0) {
    DNSLogError(LogCategoryGeneral, "Failed to get network interfaces");
    return NO;
  }

  BOOL vpnConnected = NO;

  for (struct ifaddrs* interface = interfaces; interface; interface = interface->ifa_next) {
    NSString* interfaceName = @(interface->ifa_name);
    if (!((interface->ifa_flags & IFF_UP) && (interface->ifa_flags & IFF_RUNNING))) {
      continue;
    }

    BOOL isVPNInterface = NO;
    if ([interfaceName hasPrefix:@"ipsec"] || [interfaceName hasPrefix:@"ppp"]) {
      isVPNInterface = YES;
    } else if ([interfaceName hasPrefix:@"utun"]) {
      NSString* numberPart = [interfaceName substringFromIndex:4];
      NSInteger utunNumber = [numberPart integerValue];
      if (utunNumber >= 4 && interface->ifa_addr && interface->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)interface->ifa_addr;
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), str, INET_ADDRSTRLEN);
        NSString* ipAddress = @(str);

        if (vpnResolvers.count > 0) {
          if ([self isIPAddress:ipAddress inRanges:vpnResolvers]) {
            isVPNInterface = YES;
          }
        } else if (![ipAddress hasPrefix:@"169.254."] && ![ipAddress hasPrefix:@"127."]) {
          isVPNInterface = YES;
        }
      }
    } else if ([interfaceName hasPrefix:@"tun"] || [interfaceName hasPrefix:@"tap"]) {
      isVPNInterface = YES;
    }

    if (isVPNInterface) {
      vpnConnected = YES;
      break;
    }
  }

  freeifaddrs(interfaces);
  return vpnConnected;
}

- (BOOL)isIPAddress:(NSString*)ipAddress inRanges:(NSArray*)ranges {
  struct in_addr addr;
  if (inet_pton(AF_INET, [ipAddress UTF8String], &addr) != 1) {
    return NO;
  }
  uint32_t ip = ntohl(addr.s_addr);

  for (NSString* range in ranges) {
    NSArray* parts = [range componentsSeparatedByString:@"/"];
    if (parts.count != 2)
      continue;

    NSString* networkStr = parts[0];
    NSInteger prefixLength = [parts[1] integerValue];

    struct in_addr networkAddr;
    if (inet_pton(AF_INET, [networkStr UTF8String], &networkAddr) != 1) {
      continue;
    }
    uint32_t network = ntohl(networkAddr.s_addr);
    uint32_t mask = prefixLength > 0 ? (0xFFFFFFFF << (32 - prefixLength)) : 0;

    if ((ip & mask) == (network & mask)) {
      return YES;
    }
  }

  return NO;
}

- (NSInteger)getNetworkStatus {
  struct ifaddrs* interfaces;
  if (getifaddrs(&interfaces) != 0) {
    return 1;
  }

  BOOL hasActiveInterface = NO;
  for (struct ifaddrs* interface = interfaces; interface; interface = interface->ifa_next) {
    NSString* interfaceName = @(interface->ifa_name);
    if ([interfaceName hasPrefix:@"lo"] || [interfaceName hasPrefix:@"tun"] ||
        [interfaceName hasPrefix:@"tap"] || [interfaceName hasPrefix:@"utun"]) {
      continue;
    }

    if ((interface->ifa_flags & IFF_UP) && (interface->ifa_flags & IFF_RUNNING) &&
        interface->ifa_addr && interface->ifa_addr->sa_family == AF_INET) {
      hasActiveInterface = YES;
      break;
    }
  }

  freeifaddrs(interfaces);
  return hasActiveInterface ? 2 : 1;
}

#pragma mark - DNSStateColorManagerDelegate

- (void)stateColorManager:(DNSStateColorManager*)manager didChangeToState:(DNSNetworkState)state {
  DNSLogInfo(LogCategoryGeneral, "Network state changed to: %{public}@",
             [DNSStateColorManager displayNameForState:state]);
  [self notifyDelegateOfColorUpdate];
}

- (void)stateColorManager:(DNSStateColorManager*)manager
           didUpdateColor:(NSColor*)color
                 forState:(DNSNetworkState)state {
  DNSLogDebug(LogCategoryGeneral, "Color updated for state %{public}@: %{public}@",
              [DNSStateColorManager displayNameForState:state],
              [DNSStateColorManager hexStringFromColor:color]);
  [self notifyDelegateOfColorUpdate];
}

@end
