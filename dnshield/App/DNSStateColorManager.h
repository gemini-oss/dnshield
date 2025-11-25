//
//  DNSStateColorManager.h
//  DNShield
//
//  State-based color management for menu bar icon
//  Supports custom colors, hex codes, and network state detection
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

// Network states for color mapping
typedef NS_ENUM(NSInteger, DNSNetworkState) {
  DNSNetworkStateOffline = 0,      // No network connection
  DNSNetworkStateOnline,           // Connected to network
  DNSNetworkStateVPNConnected,     // VPN is active
  DNSNetworkStateVPNDisconnected,  // VPN was disconnected
  DNSNetworkStateRestricted,       // Expensive/constrained network
  DNSNetworkStateManualOverride    // User manual color override
};

// Color configuration mode
typedef NS_ENUM(NSInteger, DNSColorMode) {
  DNSColorModeManual = 0,  // User sets single color (current behavior)
  DNSColorModeStateBased   // Automatic color based on network state
};

// Delegate protocol for state changes
@protocol DNSStateColorManagerDelegate <NSObject>
@optional
- (void)stateColorManager:(id)manager didChangeToState:(DNSNetworkState)state;
- (void)stateColorManager:(id)manager
           didUpdateColor:(NSColor*)color
                 forState:(DNSNetworkState)state;
@end

@interface DNSStateColorManager : NSObject

// Delegate for notifications
@property(nonatomic, unsafe_unretained) id<DNSStateColorManagerDelegate> delegate;

// Current configuration
@property(nonatomic, assign) DNSColorMode colorMode;
@property(nonatomic, assign, readonly) DNSNetworkState currentState;
@property(nonatomic, strong, readonly) NSColor* currentColor;

// Manual override colors for shield and globe
@property(nonatomic, strong) NSColor* manualColor;  // Primary color (shield)
@property(nonatomic, strong) NSColor* manualShieldColor;
@property(nonatomic, strong) NSColor* manualGlobeColor;

// Singleton instance
+ (instancetype)sharedManager;

// Color configuration for states
- (void)setColor:(NSColor*)color forState:(DNSNetworkState)state;
- (NSColor*)colorForState:(DNSNetworkState)state;
- (NSDictionary<NSNumber*, NSColor*>*)allStateColors;

// Separate shield and globe color configuration
- (void)setShieldColor:(NSColor*)color forState:(DNSNetworkState)state;
- (void)setGlobeColor:(NSColor*)color forState:(DNSNetworkState)state;
- (NSColor*)shieldColorForState:(DNSNetworkState)state;
- (NSColor*)globeColorForState:(DNSNetworkState)state;

// Color creation utilities
+ (NSColor* _Nullable)colorFromHexString:(NSString*)hexString;
+ (NSString*)hexStringFromColor:(NSColor*)color;
+ (NSColor* _Nullable)colorFromRGB:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue;

// State management
- (void)updateStateBasedOnNetworkStatus:(NSInteger)networkStatus isVPNConnected:(BOOL)vpnConnected;
- (void)setManualOverrideState:(BOOL)enabled;

// Persistence
- (void)saveConfiguration;
- (void)loadConfiguration;

// Utility methods
+ (NSString*)displayNameForState:(DNSNetworkState)state;
+ (NSArray<NSNumber*>*)allNetworkStates;

// Default colors
- (void)resetToDefaultColors;

@end

NS_ASSUME_NONNULL_END
