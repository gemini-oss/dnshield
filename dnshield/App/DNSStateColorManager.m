//
//  DNSStateColorManager.m
//  DNShield
//
//  Implementation of state-based color management system
//

#import "DNSStateColorManager.h"
#import "LoggingManager.h"

// User defaults keys
static NSString* const kDNSStateColorModeKey = @"DNSStateColorMode";
static NSString* const kDNSStateColorsKey = @"DNSStateColors";
static NSString* const kDNSManualColorKey = @"DNSManualColor";
static NSString* const kDNSStateShieldColorsKey = @"DNSStateShieldColors";
static NSString* const kDNSStateGlobeColorsKey = @"DNSStateGlobeColors";

@interface DNSStateColorManager ()
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, NSColor*>* stateColors;
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, NSColor*>* stateShieldColors;
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, NSColor*>* stateGlobeColors;
@property(nonatomic, assign) DNSNetworkState currentState;
@end

@implementation DNSStateColorManager

#pragma mark - Singleton

+ (instancetype)sharedManager {
  static DNSStateColorManager* sharedInstance = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedInstance = [[DNSStateColorManager alloc] init];
  });
  return sharedInstance;
}

#pragma mark - Initialization

- (instancetype)init {
  self = [super init];
  if (self) {
    _stateColors = [NSMutableDictionary dictionary];
    _stateShieldColors = [NSMutableDictionary dictionary];
    _stateGlobeColors = [NSMutableDictionary dictionary];
    _currentState = DNSNetworkStateOffline;
    _colorMode = DNSColorModeManual;

    [self resetToDefaultColors];
    [self loadConfiguration];

    DNSLogInfo(LogCategoryGeneral, "DNSStateColorManager initialized with mode: %@",
               _colorMode == DNSColorModeManual ? @"Manual" : @"State-based");
  }
  return self;
}

#pragma mark - Color Management

- (void)setColor:(NSColor*)color forState:(DNSNetworkState)state {
  if (!color) {
    DNSLogError(LogCategoryGeneral, "Attempted to set nil color for state %ld", (long)state);
    return;
  }

  self.stateColors[@(state)] = color;

  DNSLogDebug(LogCategoryGeneral, "Set color %@ for state %@",
              [DNSStateColorManager hexStringFromColor:color],
              [DNSStateColorManager displayNameForState:state]);

  // Notify delegate if this affects current state
  if (state == self.currentState && self.colorMode == DNSColorModeStateBased) {
    [self.delegate stateColorManager:self didUpdateColor:color forState:state];
  }

  [self saveConfiguration];
}

- (NSColor*)colorForState:(DNSNetworkState)state {
  NSColor* color = self.stateColors[@(state)];
  if (!color) {
    // Fallback to default orange color
    color = [NSColor systemOrangeColor];
    DNSLogInfo(LogCategoryGeneral, "No color configured for state %@, using default orange",
               [DNSStateColorManager displayNameForState:state]);
  }
  return color;
}

- (NSDictionary<NSNumber*, NSColor*>*)allStateColors {
  return [self.stateColors copy];
}

- (NSColor*)currentColor {
  switch (self.colorMode) {
    case DNSColorModeManual: return self.manualColor ?: [NSColor systemOrangeColor];
    case DNSColorModeStateBased: return [self colorForState:self.currentState];
  }
}

#pragma mark - Color Utilities

+ (NSColor*)colorFromHexString:(NSString*)hexString {
  if (!hexString || hexString.length == 0) {
    return nil;
  }

  // Remove # if present
  NSString* cleanString = [hexString hasPrefix:@"#"] ? [hexString substringFromIndex:1] : hexString;

  // Validate hex string
  NSCharacterSet* hexSet =
      [NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEFabcdef"];
  NSCharacterSet* invalidChars = [hexSet invertedSet];
  if ([cleanString rangeOfCharacterFromSet:invalidChars].location != NSNotFound) {
    DNSLogError(LogCategoryGeneral, "Invalid hex color string: %@", hexString);
    return nil;
  }

  // Support 3-digit and 6-digit hex
  if (cleanString.length == 3) {
    cleanString = [NSString
        stringWithFormat:@"%c%c%c%c%c%c", [cleanString characterAtIndex:0],
                         [cleanString characterAtIndex:0], [cleanString characterAtIndex:1],
                         [cleanString characterAtIndex:1], [cleanString characterAtIndex:2],
                         [cleanString characterAtIndex:2]];
  } else if (cleanString.length != 6) {
    DNSLogError(LogCategoryGeneral, "Hex color string must be 3 or 6 characters: %@", hexString);
    return nil;
  }

  // Parse RGB values
  unsigned int rgbValue = 0;
  NSScanner* scanner = [NSScanner scannerWithString:cleanString];
  [scanner scanHexInt:&rgbValue];

  CGFloat red = ((rgbValue & 0xFF0000) >> 16) / 255.0;
  CGFloat green = ((rgbValue & 0xFF00) >> 8) / 255.0;
  CGFloat blue = (rgbValue & 0xFF) / 255.0;

  return [NSColor colorWithRed:red green:green blue:blue alpha:1.0];
}

+ (NSString*)hexStringFromColor:(NSColor*)color {
  if (!color) {
    return @"#000000";
  }

  // Convert to RGB color space
  NSColor* rgbColor = [color colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
  if (!rgbColor) {
    DNSLogError(LogCategoryGeneral, "Failed to convert color to RGB color space");
    return @"#000000";
  }

  CGFloat red, green, blue, alpha;
  [rgbColor getRed:&red green:&green blue:&blue alpha:&alpha];

  int r = (int)(red * 255.0);
  int g = (int)(green * 255.0);
  int b = (int)(blue * 255.0);

  return [NSString stringWithFormat:@"#%02X%02X%02X", r, g, b];
}

+ (NSColor*)colorFromRGB:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue {
  // Clamp values to valid range
  red = MAX(0.0, MIN(1.0, red));
  green = MAX(0.0, MIN(1.0, green));
  blue = MAX(0.0, MIN(1.0, blue));

  return [NSColor colorWithRed:red green:green blue:blue alpha:1.0];
}

#pragma mark - State Management

- (void)updateStateBasedOnNetworkStatus:(NSInteger)networkStatus isVPNConnected:(BOOL)vpnConnected {
  DNSNetworkState newState;

  // Always determine the current state, even in manual mode (for future reference)
  // Determine new state based on network status and VPN
  if (networkStatus == 0) {  // NetworkStatusNotReachable
    newState = DNSNetworkStateOffline;
  } else if (vpnConnected) {
    newState = DNSNetworkStateVPNConnected;
  } else {
    // Online but no VPN
    newState = DNSNetworkStateOnline;
  }

  // Update state if changed
  if (newState != self.currentState) {
    DNSNetworkState previousState = self.currentState;
    self.currentState = newState;

    DNSLogInfo(LogCategoryGeneral, "Network state changed from %@ to %@",
               [DNSStateColorManager displayNameForState:previousState],
               [DNSStateColorManager displayNameForState:newState]);

    [self.delegate stateColorManager:self didChangeToState:newState];

    // Also notify color update for state-based mode
    if (self.colorMode == DNSColorModeStateBased) {
      NSColor* stateColor = [self colorForState:newState];
      [self.delegate stateColorManager:self didUpdateColor:stateColor forState:newState];
    }
  }
}

- (void)setManualOverrideState:(BOOL)enabled {
  DNSColorMode previousMode = self.colorMode;
  self.colorMode = enabled ? DNSColorModeManual : DNSColorModeStateBased;

  DNSLogInfo(LogCategoryGeneral, "Color mode changed from %@ to %@",
             previousMode == DNSColorModeManual ? @"Manual" : @"State-based",
             enabled ? @"Manual Override" : @"State-based");

  [self saveConfiguration];

  // Always notify delegate of color change when mode changes
  NSColor* newColor = self.currentColor;
  DNSLogInfo(LogCategoryGeneral, "Mode change - notifying delegate with color %@ for state %@",
             [DNSStateColorManager hexStringFromColor:newColor],
             [DNSStateColorManager displayNameForState:self.currentState]);

  [self.delegate stateColorManager:self didUpdateColor:newColor forState:self.currentState];
}

#pragma mark - Persistence

- (void)saveConfiguration {
  NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];

  // Save color mode
  [defaults setInteger:self.colorMode forKey:kDNSStateColorModeKey];

  // Save manual color
  if (self.manualColor) {
    NSData* colorData = [NSKeyedArchiver archivedDataWithRootObject:self.manualColor
                                              requiringSecureCoding:NO
                                                              error:nil];
    [defaults setObject:colorData forKey:kDNSManualColorKey];
  }

  // Save state colors
  NSMutableDictionary* colorStrings = [NSMutableDictionary dictionary];
  for (NSNumber* stateNumber in self.stateColors) {
    NSColor* color = self.stateColors[stateNumber];
    colorStrings[stateNumber.stringValue] = [DNSStateColorManager hexStringFromColor:color];
  }
  [defaults setObject:colorStrings forKey:kDNSStateColorsKey];

  // Save shield colors
  NSMutableDictionary* shieldColorStrings = [NSMutableDictionary dictionary];
  for (NSNumber* stateNumber in self.stateShieldColors) {
    NSColor* color = self.stateShieldColors[stateNumber];
    shieldColorStrings[stateNumber.stringValue] = [DNSStateColorManager hexStringFromColor:color];
  }
  [defaults setObject:shieldColorStrings forKey:kDNSStateShieldColorsKey];

  // Save globe colors
  NSMutableDictionary* globeColorStrings = [NSMutableDictionary dictionary];
  for (NSNumber* stateNumber in self.stateGlobeColors) {
    NSColor* color = self.stateGlobeColors[stateNumber];
    globeColorStrings[stateNumber.stringValue] = [DNSStateColorManager hexStringFromColor:color];
  }
  [defaults setObject:globeColorStrings forKey:kDNSStateGlobeColorsKey];

  [defaults synchronize];

  DNSLogDebug(LogCategoryGeneral, "Saved color configuration");
}

- (void)loadConfiguration {
  NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];

  // Load color mode
  self.colorMode = [defaults integerForKey:kDNSStateColorModeKey];

  // Load manual color
  NSData* colorData = [defaults objectForKey:kDNSManualColorKey];
  if (colorData) {
    NSError* unarchiveError = nil;
    NSColor* color = [NSKeyedUnarchiver unarchivedObjectOfClass:[NSColor class]
                                                       fromData:colorData
                                                          error:&unarchiveError];
    if (color) {
      self.manualColor = color;
    }
  }

  // Load state colors
  NSDictionary* colorStrings = [defaults objectForKey:kDNSStateColorsKey];
  if (colorStrings) {
    for (NSString* stateString in colorStrings) {
      NSString* hexString = colorStrings[stateString];
      NSColor* color = [DNSStateColorManager colorFromHexString:hexString];
      if (color) {
        NSNumber* stateNumber = @(stateString.integerValue);
        self.stateColors[stateNumber] = color;
      }
    }
  }

  // Load shield colors
  NSDictionary* shieldColorStrings = [defaults objectForKey:kDNSStateShieldColorsKey];
  if (shieldColorStrings) {
    for (NSString* stateString in shieldColorStrings) {
      NSString* hexString = shieldColorStrings[stateString];
      NSColor* color = [DNSStateColorManager colorFromHexString:hexString];
      if (color) {
        NSNumber* stateNumber = @(stateString.integerValue);
        self.stateShieldColors[stateNumber] = color;
      }
    }
  }

  // Load globe colors
  NSDictionary* globeColorStrings = [defaults objectForKey:kDNSStateGlobeColorsKey];
  if (globeColorStrings) {
    for (NSString* stateString in globeColorStrings) {
      NSString* hexString = globeColorStrings[stateString];
      NSColor* color = [DNSStateColorManager colorFromHexString:hexString];
      if (color) {
        NSNumber* stateNumber = @(stateString.integerValue);
        self.stateGlobeColors[stateNumber] = color;
      }
    }
  }

  DNSLogDebug(
      LogCategoryGeneral,
      "Loaded color configuration with %lu state colors, %lu shield colors, %lu globe colors",
      (unsigned long)self.stateColors.count, (unsigned long)self.stateShieldColors.count,
      (unsigned long)self.stateGlobeColors.count);
}

#pragma mark - Defaults and Utilities

- (void)resetToDefaultColors {
  [self.stateColors removeAllObjects];

  // Set default colors for each state using specified hex colors
  self.stateColors[@(DNSNetworkStateOffline)] =
      [DNSStateColorManager colorFromHexString:@"#FF453A"];  // Red
  self.stateColors[@(DNSNetworkStateOnline)] =
      [DNSStateColorManager colorFromHexString:@"#0A84FF"];  // Blue
  self.stateColors[@(DNSNetworkStateVPNConnected)] =
      [DNSStateColorManager colorFromHexString:@"#32D74B"];  // Green
  self.stateColors[@(DNSNetworkStateVPNDisconnected)] =
      [DNSStateColorManager colorFromHexString:@"#FFD60A"];  // Yellow
  self.stateColors[@(DNSNetworkStateRestricted)] =
      [DNSStateColorManager colorFromHexString:@"#BF5AF2"];  // Purple
  self.stateColors[@(DNSNetworkStateManualOverride)] = [NSColor systemOrangeColor];

  // Set default manual color
  self.manualColor = [NSColor systemOrangeColor];

  DNSLogInfo(LogCategoryGeneral, "Reset to default colors");
}

+ (NSString*)displayNameForState:(DNSNetworkState)state {
  switch (state) {
    case DNSNetworkStateOffline: return @"Offline";
    case DNSNetworkStateOnline: return @"Online";
    case DNSNetworkStateVPNConnected: return @"VPN Connected";
    case DNSNetworkStateVPNDisconnected: return @"VPN Disconnected";
    case DNSNetworkStateRestricted: return @"Restricted Network";
    case DNSNetworkStateManualOverride: return @"Manual Override";
  }
}

+ (NSArray<NSNumber*>*)allNetworkStates {
  return @[
    @(DNSNetworkStateOffline), @(DNSNetworkStateOnline), @(DNSNetworkStateVPNConnected),
    @(DNSNetworkStateVPNDisconnected), @(DNSNetworkStateRestricted),
    @(DNSNetworkStateManualOverride)
  ];
}

#pragma mark - Separate Shield/Globe Colors

- (void)setShieldColor:(NSColor*)color forState:(DNSNetworkState)state {
  if (!color) {
    DNSLogError(LogCategoryGeneral, "Attempted to set nil shield color for state %ld", (long)state);
    return;
  }

  self.stateShieldColors[@(state)] = color;

  DNSLogDebug(LogCategoryGeneral, "Set shield color %@ for state %@",
              [DNSStateColorManager hexStringFromColor:color],
              [DNSStateColorManager displayNameForState:state]);

  // Also update the main color to the shield color for compatibility
  [self setColor:color forState:state];

  // Notify delegate if this affects current state and we're in state-based mode
  if (state == self.currentState && self.colorMode == DNSColorModeStateBased) {
    [self.delegate stateColorManager:self didUpdateColor:color forState:state];
  }

  [self saveConfiguration];
}

- (void)setGlobeColor:(NSColor*)color forState:(DNSNetworkState)state {
  if (!color) {
    DNSLogError(LogCategoryGeneral, "Attempted to set nil globe color for state %ld", (long)state);
    return;
  }

  self.stateGlobeColors[@(state)] = color;

  DNSLogDebug(LogCategoryGeneral, "Set globe color %@ for state %@",
              [DNSStateColorManager hexStringFromColor:color],
              [DNSStateColorManager displayNameForState:state]);

  // Notify delegate if this affects current state and we're in state-based mode
  if (state == self.currentState && self.colorMode == DNSColorModeStateBased) {
    // Use the shield color for the main notification (or the general state color)
    NSColor* mainColor = [self colorForState:state];
    [self.delegate stateColorManager:self didUpdateColor:mainColor forState:state];
  }

  [self saveConfiguration];
}

- (NSColor*)shieldColorForState:(DNSNetworkState)state {
  NSColor* color = self.stateShieldColors[@(state)];
  if (!color) {
    // Fall back to the general state color
    color = [self colorForState:state];
  }
  return color;
}

- (NSColor*)globeColorForState:(DNSNetworkState)state {
  NSColor* color = self.stateGlobeColors[@(state)];
  if (!color) {
    // Fall back to the general state color
    color = [self colorForState:state];
  }
  return color;
}

@end
