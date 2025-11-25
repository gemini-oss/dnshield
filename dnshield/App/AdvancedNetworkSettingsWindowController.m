//
//  AdvancedNetworkSettingsWindowController.m
//  DNShield
//
//  Window controller for advanced network configuration settings
//

#import <os/log.h>

#import "AdvancedNetworkSettingsWindowController.h"
#import "DNShieldPreferences.h"
#import "LoggingManager.h"

static os_log_t logHandle = nil;

@implementation AdvancedNetworkSettingsWindowController {
  NSPopUpButton* bindInterfaceStrategyPopup;
  NSButton* stickyInterfaceCheckbox;
  NSTextField* maxRetriesField;
  NSTextField* initialBackoffField;
  NSButton* userCanAdjustCacheTTLCheckbox;
  NSButton* saveButton;
  NSButton* cancelButton;
  NSTextField* statusLabel;
}

- (instancetype)init {
  self = [super initWithWindowNibName:@""];
  if (self) {
    if (!logHandle) {
      logHandle = os_log_create([kDNShieldClientIdentifier UTF8String], "AdvancedNetworkSettings");
    }
    [self setupWindow];
    [self loadCurrentSettings];
  }
  return self;
}

- (void)setupWindow {
  // Create window
  NSRect windowRect = NSMakeRect(0, 0, 520, 420);
  NSUInteger styleMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
  NSWindow* window = [[NSWindow alloc] initWithContentRect:windowRect
                                                 styleMask:styleMask
                                                   backing:NSBackingStoreBuffered
                                                     defer:NO];

  window.title = @"Advanced Network Settings";
  window.minSize = NSMakeSize(500, 380);
  [window center];

  self.window = window;

  // Create main container view
  NSView* contentView = window.contentView;

  // Y position tracker for UI elements (following 8pt grid)
  CGFloat yPos = 368;

  // Title
  NSTextField* titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 480, 24)];
  titleLabel.stringValue = @"Advanced Network Configuration";
  titleLabel.font = [NSFont boldSystemFontOfSize:16];
  titleLabel.bezeled = NO;
  titleLabel.drawsBackground = NO;
  titleLabel.editable = NO;
  titleLabel.selectable = NO;
  [contentView addSubview:titleLabel];

  yPos -= 40;

  // === CONNECTION STRATEGY SECTION ===
  NSTextField* connectionSectionLabel =
      [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 200, 20)];
  connectionSectionLabel.stringValue = @"Connection Strategy";
  connectionSectionLabel.font = [NSFont boldSystemFontOfSize:14];
  connectionSectionLabel.bezeled = NO;
  connectionSectionLabel.drawsBackground = NO;
  connectionSectionLabel.editable = NO;
  connectionSectionLabel.selectable = NO;
  [contentView addSubview:connectionSectionLabel];

  // Help button for connection strategy section
  NSButton* connectionHelpButton =
      [[NSButton alloc] initWithFrame:NSMakeRect(480, yPos - 2, 24, 24)];
  connectionHelpButton.title = @"?";
  connectionHelpButton.bezelStyle = NSBezelStyleCircular;
  connectionHelpButton.font = [NSFont systemFontOfSize:12];
  connectionHelpButton.target = self;
  connectionHelpButton.action = @selector(showConnectionStrategyHelp:);
  [contentView addSubview:connectionHelpButton];

  yPos -= 32;

  // Network Interface
  NSTextField* bindStrategyLabel =
      [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 140, 20)];
  bindStrategyLabel.stringValue = @"Network Interface";
  bindStrategyLabel.bezeled = NO;
  bindStrategyLabel.drawsBackground = NO;
  bindStrategyLabel.editable = NO;
  bindStrategyLabel.selectable = NO;
  [contentView addSubview:bindStrategyLabel];

  bindInterfaceStrategyPopup =
      [[NSPopUpButton alloc] initWithFrame:NSMakeRect(170, yPos - 2, 250, 24)];
  [bindInterfaceStrategyPopup addItemWithTitle:@"Default"];
  [bindInterfaceStrategyPopup addItemWithTitle:@"CIDR-based"];
  [bindInterfaceStrategyPopup addItemWithTitle:@"Interface Index"];
  [bindInterfaceStrategyPopup addItemWithTitle:@"Adaptive"];
  [contentView addSubview:bindInterfaceStrategyPopup];

  // Inline explanation
  NSTextField* bindStrategyDesc =
      [[NSTextField alloc] initWithFrame:NSMakeRect(170, yPos - 18, 330, 16)];
  bindStrategyDesc.stringValue = @"Use system default interface selection";
  bindStrategyDesc.font = [NSFont systemFontOfSize:11];
  bindStrategyDesc.textColor = [NSColor secondaryLabelColor];
  bindStrategyDesc.bezeled = NO;
  bindStrategyDesc.drawsBackground = NO;
  bindStrategyDesc.editable = NO;
  bindStrategyDesc.selectable = NO;
  [contentView addSubview:bindStrategyDesc];

  yPos -= 40;

  stickyInterfaceCheckbox = [[NSButton alloc] initWithFrame:NSMakeRect(20, yPos, 350, 20)];
  stickyInterfaceCheckbox.title = @"Maintain interface per request";
  [stickyInterfaceCheckbox setButtonType:NSButtonTypeSwitch];
  [contentView addSubview:stickyInterfaceCheckbox];

  // Inline explanation
  NSTextField* stickyInterfaceDesc =
      [[NSTextField alloc] initWithFrame:NSMakeRect(38, yPos - 18, 450, 16)];
  stickyInterfaceDesc.stringValue = @"Keeps the same network interface for related operations";
  stickyInterfaceDesc.font = [NSFont systemFontOfSize:11];
  stickyInterfaceDesc.textColor = [NSColor secondaryLabelColor];
  stickyInterfaceDesc.bezeled = NO;
  stickyInterfaceDesc.drawsBackground = NO;
  stickyInterfaceDesc.editable = NO;
  stickyInterfaceDesc.selectable = NO;
  [contentView addSubview:stickyInterfaceDesc];

  yPos -= 48;

  // === RETRY BEHAVIOR SECTION ===
  NSTextField* retrySectionLabel =
      [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 200, 20)];
  retrySectionLabel.stringValue = @"Retry Behavior";
  retrySectionLabel.font = [NSFont boldSystemFontOfSize:14];
  retrySectionLabel.bezeled = NO;
  retrySectionLabel.drawsBackground = NO;
  retrySectionLabel.editable = NO;
  retrySectionLabel.selectable = NO;
  [contentView addSubview:retrySectionLabel];

  // Help button for retry behavior section
  NSButton* retryHelpButton = [[NSButton alloc] initWithFrame:NSMakeRect(480, yPos - 2, 24, 24)];
  retryHelpButton.title = @"?";
  retryHelpButton.bezelStyle = NSBezelStyleCircular;
  retryHelpButton.font = [NSFont systemFontOfSize:12];
  retryHelpButton.target = self;
  retryHelpButton.action = @selector(showRetryBehaviorHelp:);
  [contentView addSubview:retryHelpButton];

  yPos -= 32;

  // Max Retries
  NSTextField* maxRetriesLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 100, 20)];
  maxRetriesLabel.stringValue = @"Max Retries";
  maxRetriesLabel.bezeled = NO;
  maxRetriesLabel.drawsBackground = NO;
  maxRetriesLabel.editable = NO;
  maxRetriesLabel.selectable = NO;
  [contentView addSubview:maxRetriesLabel];

  maxRetriesField = [[NSTextField alloc] initWithFrame:NSMakeRect(130, yPos, 60, 24)];
  maxRetriesField.placeholderString = @"3";
  [contentView addSubview:maxRetriesField];

  NSTextField* maxRetriesDesc =
      [[NSTextField alloc] initWithFrame:NSMakeRect(200, yPos + 3, 200, 20)];
  maxRetriesDesc.stringValue = @"(0-10, default: 3)";
  maxRetriesDesc.font = [NSFont systemFontOfSize:11];
  maxRetriesDesc.textColor = [NSColor secondaryLabelColor];
  maxRetriesDesc.bezeled = NO;
  maxRetriesDesc.drawsBackground = NO;
  maxRetriesDesc.editable = NO;
  maxRetriesDesc.selectable = NO;
  [contentView addSubview:maxRetriesDesc];

  yPos -= 32;

  // Initial Backoff
  NSTextField* backoffLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 100, 20)];
  backoffLabel.stringValue = @"Initial Backoff";
  backoffLabel.bezeled = NO;
  backoffLabel.drawsBackground = NO;
  backoffLabel.editable = NO;
  backoffLabel.selectable = NO;
  [contentView addSubview:backoffLabel];

  initialBackoffField = [[NSTextField alloc] initWithFrame:NSMakeRect(130, yPos, 60, 24)];
  initialBackoffField.placeholderString = @"250";
  [contentView addSubview:initialBackoffField];

  NSTextField* backoffMsLabel =
      [[NSTextField alloc] initWithFrame:NSMakeRect(200, yPos + 3, 30, 20)];
  backoffMsLabel.stringValue = @"ms";
  backoffMsLabel.font = [NSFont systemFontOfSize:12];
  backoffMsLabel.textColor = [NSColor labelColor];
  backoffMsLabel.bezeled = NO;
  backoffMsLabel.drawsBackground = NO;
  backoffMsLabel.editable = NO;
  backoffMsLabel.selectable = NO;
  [contentView addSubview:backoffMsLabel];

  NSTextField* backoffDesc = [[NSTextField alloc] initWithFrame:NSMakeRect(240, yPos + 3, 200, 20)];
  backoffDesc.stringValue = @"(50-5000, default: 250)";
  backoffDesc.font = [NSFont systemFontOfSize:11];
  backoffDesc.textColor = [NSColor secondaryLabelColor];
  backoffDesc.bezeled = NO;
  backoffDesc.drawsBackground = NO;
  backoffDesc.editable = NO;
  backoffDesc.selectable = NO;
  [contentView addSubview:backoffDesc];

  yPos -= 40;

  // CACHE SETTINGS SECTION
  NSTextField* cacheSectionLabel =
      [[NSTextField alloc] initWithFrame:NSMakeRect(20, yPos, 200, 20)];
  cacheSectionLabel.stringValue = @"Cache Settings";
  cacheSectionLabel.font = [NSFont boldSystemFontOfSize:14];
  cacheSectionLabel.bezeled = NO;
  cacheSectionLabel.drawsBackground = NO;
  cacheSectionLabel.editable = NO;
  cacheSectionLabel.selectable = NO;
  [contentView addSubview:cacheSectionLabel];

  yPos -= 32;

  // Cache TTL setting
  userCanAdjustCacheTTLCheckbox = [[NSButton alloc] initWithFrame:NSMakeRect(20, yPos, 280, 20)];
  userCanAdjustCacheTTLCheckbox.title = @"Allow cache TTL adjustment";
  [userCanAdjustCacheTTLCheckbox setButtonType:NSButtonTypeSwitch];
  [contentView addSubview:userCanAdjustCacheTTLCheckbox];

  //    NSTextField *cacheTTLDesc = [[NSTextField alloc] initWithFrame:NSMakeRect(38, yPos - 18,
  //    450, 16)]; cacheTTLDesc.stringValue = @"Permits modification of DNS cache timing";
  //    cacheTTLDesc.font = [NSFont systemFontOfSize:11];
  //    cacheTTLDesc.textColor = [NSColor secondaryLabelColor];
  //    cacheTTLDesc.bezeled = NO;
  //    cacheTTLDesc.drawsBackground = NO;
  //    cacheTTLDesc.editable = NO;
  //    cacheTTLDesc.selectable = NO;
  //    [contentView addSubview:cacheTTLDesc];

  yPos -= 48;

  // Buttons
  cancelButton = [[NSButton alloc] initWithFrame:NSMakeRect(340, 20, 80, 30)];
  cancelButton.title = @"Cancel";
  cancelButton.bezelStyle = NSBezelStyleRounded;
  cancelButton.target = self;
  cancelButton.action = @selector(cancelClicked:);
  [contentView addSubview:cancelButton];

  saveButton = [[NSButton alloc] initWithFrame:NSMakeRect(430, 20, 80, 30)];
  saveButton.title = @"Save";
  saveButton.bezelStyle = NSBezelStyleRounded;
  saveButton.keyEquivalent = @"\r";
  saveButton.target = self;
  saveButton.action = @selector(saveClicked:);
  [contentView addSubview:saveButton];

  // Status label
  //    statusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 80, 310, 20)];
  //    statusLabel.bezeled = NO;
  //    statusLabel.drawsBackground = NO;
  //    statusLabel.editable = NO;
  //    statusLabel.selectable = NO;
  //    statusLabel.stringValue = @"Configure advanced network connection settings";
  //    statusLabel.font = [NSFont systemFontOfSize:12];
  //    statusLabel.textColor = [NSColor secondaryLabelColor];
  //    [contentView addSubview:statusLabel];
}

- (void)loadCurrentSettings {
  // Load BindInterfaceStrategy
  NSString* bindStrategy = DNPreferenceCopyValue(kDNShieldBindInterfaceStrategy);
  if (!bindStrategy || [bindStrategy isEqualToString:@"default"]) {
    [bindInterfaceStrategyPopup selectItemAtIndex:0];  // Default
  } else if ([bindStrategy isEqualToString:@"resolver_cidr"]) {
    [bindInterfaceStrategyPopup selectItemAtIndex:1];  // CIDR-based
  } else if ([bindStrategy isEqualToString:@"interface_index"]) {
    [bindInterfaceStrategyPopup selectItemAtIndex:2];  // Interface Index
  } else if ([bindStrategy isEqualToString:@"adaptive"]) {
    [bindInterfaceStrategyPopup selectItemAtIndex:3];  // Adaptive
  } else {
    [bindInterfaceStrategyPopup selectItemAtIndex:0];  // Default fallback
  }

  // Load StickyInterfacePerTransaction
  BOOL stickyInterface = DNPreferenceGetBool(
      kDNShieldStickyInterfacePerTransaction,
      [DNShieldPreferences boolDefaultForKey:kDNShieldStickyInterfacePerTransaction fallback:YES]);
  stickyInterfaceCheckbox.state = stickyInterface ? NSControlStateValueOn : NSControlStateValueOff;

  // Load MaxRetries
  NSInteger maxRetries = DNPreferenceGetInteger(
      kDNShieldMaxRetries, [DNShieldPreferences integerDefaultForKey:kDNShieldMaxRetries
                                                            fallback:3]);
  if (maxRetries == 0)
    maxRetries = 3;  // Default value
  maxRetriesField.stringValue = [NSString stringWithFormat:@"%ld", (long)maxRetries];

  // Load InitialBackoffMs
  NSInteger initialBackoff = DNPreferenceGetInteger(
      kDNShieldInitialBackoffMs, [DNShieldPreferences integerDefaultForKey:kDNShieldInitialBackoffMs
                                                                  fallback:250]);
  if (initialBackoff == 0)
    initialBackoff = 250;  // Default value
  initialBackoffField.stringValue = [NSString stringWithFormat:@"%ld", (long)initialBackoff];

  // Load UserCanAdjustCacheTTL
  BOOL userCanAdjustCacheTTL = DNPreferenceGetBool(
      kDNShieldUserCanAdjustCacheTTL,
      [DNShieldPreferences boolDefaultForKey:kDNShieldUserCanAdjustCacheTTL fallback:NO]);
  userCanAdjustCacheTTLCheckbox.state =
      userCanAdjustCacheTTL ? NSControlStateValueOn : NSControlStateValueOff;
}

- (void)saveClicked:(id)sender {
  if (![self validateInputs]) {
    return;
  }

  // Save BindInterfaceStrategy
  NSString* bindStrategy;
  switch (bindInterfaceStrategyPopup.indexOfSelectedItem) {
    case 1:
      bindStrategy = @"resolver_cidr";  // CIDR-based
      break;
    case 2:
      bindStrategy = @"interface_index";  // Interface Index
      break;
    case 3:
      bindStrategy = @"adaptive";  // Adaptive
      break;
    default:
      bindStrategy = @"default";  // Default
      break;
  }
  DNPreferenceSetValue(kDNShieldBindInterfaceStrategy, bindStrategy);

  // Save StickyInterfacePerTransaction
  BOOL stickyInterface = (stickyInterfaceCheckbox.state == NSControlStateValueOn);
  DNPreferenceSetBool(kDNShieldStickyInterfacePerTransaction, stickyInterface);

  // Save MaxRetries
  NSInteger maxRetries = [maxRetriesField.stringValue integerValue];
  DNPreferenceSetInteger(kDNShieldMaxRetries, maxRetries);

  // Save InitialBackoffMs
  NSInteger initialBackoff = [initialBackoffField.stringValue integerValue];
  DNPreferenceSetInteger(kDNShieldInitialBackoffMs, initialBackoff);

  // Save UserCanAdjustCacheTTL
  BOOL userCanAdjustCacheTTL = (userCanAdjustCacheTTLCheckbox.state == NSControlStateValueOn);
  DNPreferenceSetBool(kDNShieldUserCanAdjustCacheTTL, userCanAdjustCacheTTL);

  DNSLogInfo(LogCategoryConfiguration,
             "Saved advanced network settings: BindStrategy=%{public}@, StickyInterface=%d, "
             "MaxRetries=%ld, InitialBackoff=%ld, UserCanAdjustCacheTTL=%d",
             bindStrategy, stickyInterface, (long)maxRetries, (long)initialBackoff,
             userCanAdjustCacheTTL);

  // Show success message
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Settings Saved";
  alert.informativeText = @"Advanced network settings have been saved successfully. Changes will "
                          @"take effect after restarting the DNS proxy.";
  alert.alertStyle = NSAlertStyleInformational;
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];

  [self.window close];
}

- (void)cancelClicked:(id)sender {
  [self.window close];
}

- (BOOL)validateInputs {
  // Validate MaxRetries
  NSInteger maxRetries = [maxRetriesField.stringValue integerValue];
  if (maxRetriesField.stringValue.length > 0 && (maxRetries < 0 || maxRetries > 10)) {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"Invalid Max Retries";
    alert.informativeText = @"Max Retries must be between 0 and 10.";
    alert.alertStyle = NSAlertStyleWarning;
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
    return NO;
  }

  // Validate InitialBackoffMs
  NSInteger initialBackoff = [initialBackoffField.stringValue integerValue];
  if (initialBackoffField.stringValue.length > 0 &&
      (initialBackoff < 50 || initialBackoff > 5000)) {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"Invalid Initial Backoff";
    alert.informativeText = @"Initial Backoff must be between 50 and 5000 milliseconds.";
    alert.alertStyle = NSAlertStyleWarning;
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
    return NO;
  }

  return YES;
}

#pragma mark - Help Actions

- (void)showConnectionStrategyHelp:(id)sender {
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Connection Strategy";
  alert.informativeText = @"These settings control how DNShield connects to DNS servers:\n\n"
                          @"Network Interface:\n"
                          @"• Default: Use system's automatic interface selection\n"
                          @"• CIDR-based: Choose interface based on resolver IP range\n"
                          @"• Interface Index: Use specific interface by system index\n"
                          @"• Adaptive: Dynamically select optimal interface\n\n"
                          @"Maintain Interface Per Request:\n"
                          @"Uses the same network interface for all parts of a DNS transaction, "
                          @"improving consistency on multi-interface systems.";
  alert.alertStyle = NSAlertStyleInformational;
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];
}

- (void)showRetryBehaviorHelp:(id)sender {
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Retry Behavior";
  alert.informativeText =
      @"Controls how DNShield handles failed DNS queries:\n\n"
      @"Max Retries (0-10, default: 3):\n"
      @"• Higher values: Better reliability on unstable networks\n"
      @"• Lower values: Faster failure detection, less overhead\n\n"
      @"Initial Backoff (50-5000ms, default: 250ms):\n"
      @"The delay before first retry. Subsequent retries use exponential backoff.\n"
      @"• Lower values: Faster recovery, more network traffic\n"
      @"• Higher values: Gentler on congested networks";
  alert.alertStyle = NSAlertStyleInformational;
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];
}

@end
