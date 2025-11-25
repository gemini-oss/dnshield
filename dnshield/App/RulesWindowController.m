//
//  RulesWindowController.m
//  DNShield
//
//  Window controller for displaying and searching DNS rules
//

#import "RulesWindowController.h"

@interface RulesWindowController () {
  NSArray* _blockedDomains;
  NSArray* _allowedDomains;
  NSDictionary* _ruleSources;
  NSInteger _currentFilter;  // 0 = All, 1 = Blocked, 2 = Allowed
}
@end

@implementation RulesWindowController

- (instancetype)initWithRules:(NSArray*)blockedDomains
               allowedDomains:(NSArray*)allowedDomains
                  ruleSources:(NSDictionary*)ruleSources
                   configInfo:(NSDictionary*)configInfo {
  return [self initWithRules:blockedDomains
              allowedDomains:allowedDomains
                 ruleSources:ruleSources
                  configInfo:configInfo
                    syncInfo:nil];
}

- (instancetype)initWithRules:(NSArray*)blockedDomains
               allowedDomains:(NSArray*)allowedDomains
                  ruleSources:(NSDictionary*)ruleSources
                   configInfo:(NSDictionary*)configInfo
                     syncInfo:(NSDictionary*)syncInfo {
  self = [super init];
  if (self) {
    _blockedDomains = [blockedDomains copy];
    _allowedDomains = [allowedDomains copy];
    _ruleSources = [ruleSources copy];
    _configInfo = [configInfo copy];
    _syncInfo = [syncInfo copy];
    _currentFilter = 0;  // Show all by default

    // Combine all rules
    NSMutableArray* allRules = [NSMutableArray array];
    for (NSDictionary* rule in blockedDomains) {
      NSMutableDictionary* ruleWithType = [rule mutableCopy];
      ruleWithType[@"ruleType"] = @"Blocked";
      [allRules addObject:ruleWithType];
    }
    for (NSDictionary* rule in allowedDomains) {
      NSMutableDictionary* ruleWithType = [rule mutableCopy];
      ruleWithType[@"ruleType"] = @"Allowed";
      [allRules addObject:ruleWithType];
    }
    self.allRules = allRules;
    self.filteredRules = allRules;

    [self setupWindow];
  }
  return self;
}

- (void)setupWindow {
  // Create window
  NSRect frame = NSMakeRect(0, 0, 800, 600);
  NSUInteger styleMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                         NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
  NSWindow* window = [[NSWindow alloc] initWithContentRect:frame
                                                 styleMask:styleMask
                                                   backing:NSBackingStoreBuffered
                                                     defer:NO];
  window.title = @"DNShield Rules";
  [window center];

  self.window = window;

  NSView* contentView = window.contentView;

  // Create search field
  self.searchField =
      [[NSSearchField alloc] initWithFrame:NSMakeRect(20, frame.size.height - 50, 400, 30)];
  self.searchField.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
  self.searchField.placeholderString = @"Search domains...";
  self.searchField.delegate = self;
  self.searchField.target = self;
  self.searchField.action = @selector(searchFieldDidChange:);
  [contentView addSubview:self.searchField];

  // Create filter segment control
  self.filterSegment = [[NSSegmentedControl alloc]
      initWithFrame:NSMakeRect(frame.size.width - 220, frame.size.height - 50, 200, 30)];
  self.filterSegment.autoresizingMask = NSViewMinXMargin | NSViewMinYMargin;
  self.filterSegment.segmentCount = 3;
  [self.filterSegment setLabel:@"All" forSegment:0];
  [self.filterSegment setLabel:@"Blocked" forSegment:1];
  [self.filterSegment setLabel:@"Allowed" forSegment:2];
  self.filterSegment.selectedSegment = 0;
  self.filterSegment.target = self;
  self.filterSegment.action = @selector(filterChanged:);
  [contentView addSubview:self.filterSegment];

  // Create scroll view and table view
  NSRect scrollFrame = NSMakeRect(20, 50, frame.size.width - 40, frame.size.height - 120);
  self.scrollView = [[NSScrollView alloc] initWithFrame:scrollFrame];
  self.scrollView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  self.scrollView.hasVerticalScroller = YES;
  self.scrollView.borderType = NSBezelBorder;

  self.tableView = [[NSTableView alloc] initWithFrame:self.scrollView.bounds];
  self.tableView.delegate = self;
  self.tableView.dataSource = self;
  self.tableView.allowsColumnReordering = NO;
  self.tableView.usesAlternatingRowBackgroundColors = YES;

  // Create columns
  NSTableColumn* domainColumn = [[NSTableColumn alloc] initWithIdentifier:@"domain"];
  domainColumn.title = @"Domain";
  domainColumn.width = 350;
  [self.tableView addTableColumn:domainColumn];

  NSTableColumn* typeColumn = [[NSTableColumn alloc] initWithIdentifier:@"type"];
  typeColumn.title = @"Type";
  typeColumn.width = 80;
  [self.tableView addTableColumn:typeColumn];

  NSTableColumn* priorityColumn = [[NSTableColumn alloc] initWithIdentifier:@"priority"];
  priorityColumn.title = @"Priority";
  priorityColumn.width = 80;
  [self.tableView addTableColumn:priorityColumn];

  self.scrollView.documentView = self.tableView;
  [contentView addSubview:self.scrollView];

  // Create status label
  self.statusLabel =
      [[NSTextField alloc] initWithFrame:NSMakeRect(20, 15, frame.size.width - 40, 20)];
  self.statusLabel.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;
  self.statusLabel.editable = NO;
  self.statusLabel.bordered = NO;
  self.statusLabel.backgroundColor = [NSColor clearColor];
  self.statusLabel.font = [NSFont systemFontOfSize:12];
  [self updateStatusLabel];
  [contentView addSubview:self.statusLabel];

  // Add configuration info if managed by profile
  if ([self.configInfo[@"isManagedByProfile"] boolValue]) {
    NSTextField* configLabel = [[NSTextField alloc]
        initWithFrame:NSMakeRect(20, frame.size.height - 80, frame.size.width - 40, 20)];
    configLabel.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    configLabel.editable = NO;
    configLabel.bordered = NO;
    configLabel.backgroundColor = [NSColor clearColor];
    configLabel.font = [NSFont systemFontOfSize:11];
    configLabel.textColor = [NSColor secondaryLabelColor];

    if (![self.configInfo[@"allowRuleEditing"] boolValue]) {
      configLabel.stringValue =
          @"These rules are managed by your organization and cannot be modified locally.";
    } else {
      configLabel.stringValue =
          [NSString stringWithFormat:@"Managed by profile. Manifest: %@",
                                     self.configInfo[@"manifestIdentifier"] ?: @"default"];
    }
    [contentView addSubview:configLabel];
  }
}

- (void)searchFieldDidChange:(id)sender {
  [self performSearch];
}

- (void)filterChanged:(id)sender {
  _currentFilter = self.filterSegment.selectedSegment;
  [self performSearch];
}

- (void)performSearch {
  NSString* searchText = self.searchField.stringValue.lowercaseString;

  NSMutableArray* filtered = [NSMutableArray array];

  for (NSDictionary* rule in self.allRules) {
    // Apply type filter first
    if (_currentFilter == 1 && ![rule[@"ruleType"] isEqualToString:@"Blocked"])
      continue;
    if (_currentFilter == 2 && ![rule[@"ruleType"] isEqualToString:@"Allowed"])
      continue;

    // Apply search filter
    if (searchText.length > 0) {
      NSString* domain = [rule[@"domain"] lowercaseString];
      if (![domain containsString:searchText])
        continue;
    }

    [filtered addObject:rule];
  }

  self.filteredRules = filtered;
  [self.tableView reloadData];
  [self updateStatusLabel];
}

- (void)updateStatusLabel {
  NSUInteger totalRules = self.allRules.count;
  NSUInteger visibleRules = self.filteredRules.count;
  NSUInteger blockedCount = 0;
  NSUInteger allowedCount = 0;

  for (NSDictionary* rule in self.filteredRules) {
    if ([rule[@"ruleType"] isEqualToString:@"Blocked"]) {
      blockedCount++;
    } else {
      allowedCount++;
    }
  }

  NSMutableString* statusText = [NSMutableString string];

  if (self.searchField.stringValue.length > 0 || _currentFilter != 0) {
    [statusText appendFormat:@"Showing %lu of %lu rules (%lu blocked, %lu allowed)", visibleRules,
                             totalRules, blockedCount, allowedCount];
  } else {
    [statusText appendFormat:@"Total: %lu rules (%lu blocked, %lu allowed)", totalRules,
                             blockedCount, allowedCount];
  }

  // Add sync timestamp information if available
  if (self.syncInfo) {
    NSDate* lastRuleSync = self.syncInfo[@"lastRuleSync"];
    NSString* syncNote = self.syncInfo[@"syncNote"];

    if (lastRuleSync) {
      NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
      formatter.dateStyle = NSDateFormatterMediumStyle;
      formatter.timeStyle = NSDateFormatterShortStyle;
      [statusText appendFormat:@" • Last sync: %@", [formatter stringFromDate:lastRuleSync]];

      if (syncNote) {
        [statusText appendFormat:@" (%@)", syncNote];
      }
    } else if (syncNote) {
      [statusText appendFormat:@" • %@", syncNote];
    } else {
      [statusText appendString:@" • Last sync: Never"];
    }

    // Add sync error if present
    NSString* lastError = self.syncInfo[@"lastSyncError"];
    if (lastError) {
      [statusText appendFormat:@" • Error: %@", lastError];
    }
  }

  self.statusLabel.stringValue = statusText;
}

#pragma mark - NSTableViewDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView {
  return self.filteredRules.count;
}

- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                          row:(NSInteger)row {
  if (row >= self.filteredRules.count)
    return nil;

  NSDictionary* rule = self.filteredRules[row];
  NSString* identifier = tableColumn.identifier;

  if ([identifier isEqualToString:@"domain"]) {
    return rule[@"domain"];
  } else if ([identifier isEqualToString:@"type"]) {
    return rule[@"ruleType"];
  } else if ([identifier isEqualToString:@"priority"]) {
    return [NSString stringWithFormat:@"%@", rule[@"priority"]];
  }

  return nil;
}

#pragma mark - NSTableViewDelegate

- (void)tableView:(NSTableView*)tableView
    willDisplayCell:(id)cell
     forTableColumn:(NSTableColumn*)tableColumn
                row:(NSInteger)row {
  if (row >= self.filteredRules.count)
    return;

  NSDictionary* rule = self.filteredRules[row];

  if ([tableColumn.identifier isEqualToString:@"type"]) {
    NSTextFieldCell* textCell = (NSTextFieldCell*)cell;
    if ([rule[@"ruleType"] isEqualToString:@"Blocked"]) {
      textCell.textColor = [NSColor systemRedColor];
    } else {
      textCell.textColor = [NSColor systemGreenColor];
    }
  }
}

#pragma mark - NSSearchFieldDelegate

- (void)controlTextDidChange:(NSNotification*)notification {
  if (notification.object == self.searchField) {
    [self performSearch];
  }
}

@end
