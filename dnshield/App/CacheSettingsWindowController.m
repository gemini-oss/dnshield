//
//  CacheSettingsWindowController.m
//  DNShield
//
//  Window controller for DNS cache settings with tabbed interface
//

#import <os/log.h>
#import <sqlite3.h>

#import "CacheSettingsWindowController.h"
#import "DNShieldPreferences.h"
#import "Defaults.h"
#import "LoggingManager.h"

static os_log_t logHandle = nil;

@interface CacheRuleEntry : NSObject
@property(nonatomic, strong) NSString* domain;
@property(nonatomic, strong) NSString* action;
@property(nonatomic, strong) NSNumber* ttl;
@property(nonatomic, readonly) BOOL isFromRules;
@end

@implementation CacheRuleEntry
- (instancetype)initWithDomain:(NSString*)domain
                        action:(NSString*)action
                           ttl:(NSNumber*)ttl
                     fromRules:(BOOL)fromRules {
  self = [super init];
  if (self) {
    _domain = domain;
    _action = action;
    _ttl = ttl;
    _isFromRules = fromRules;
  }
  return self;
}
@end

@implementation CacheSettingsWindowController {
  NSButton* saveButton;
  NSButton* cancelButton;
  NSTextField* statusLabel;
}

- (instancetype)init {
  self = [super initWithWindowNibName:@""];
  if (self) {
    if (!logHandle) {
      logHandle = os_log_create("com.dnshield.app", "CacheSettings");
    }
    [self setupWindow];
    [self loadData];
  }
  return self;
}

- (void)setupWindow {
  // Create window
  NSRect windowRect = NSMakeRect(0, 0, 700, 500);
  NSUInteger styleMask =
      NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable;
  NSWindow* window = [[NSWindow alloc] initWithContentRect:windowRect
                                                 styleMask:styleMask
                                                   backing:NSBackingStoreBuffered
                                                     defer:NO];

  window.title = @"DNS Cache Settings";
  window.minSize = NSMakeSize(600, 400);
  [window center];

  self.window = window;

  // Create main container view
  NSView* contentView = window.contentView;

  // Create tab view
  self.tabView = [[NSTabView alloc] initWithFrame:NSMakeRect(20, 60, 660, 380)];
  self.tabView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  [contentView addSubview:self.tabView];

  // Create tabs
  [self setupRulesTab];
  [self setupCustomTab];

  // Create buttons
  cancelButton = [[NSButton alloc] initWithFrame:NSMakeRect(520, 15, 80, 30)];
  cancelButton.autoresizingMask = NSViewMinXMargin | NSViewMaxYMargin;
  cancelButton.title = @"Cancel";
  cancelButton.bezelStyle = NSBezelStyleRounded;
  cancelButton.target = self;
  cancelButton.action = @selector(cancelClicked:);
  [contentView addSubview:cancelButton];

  saveButton = [[NSButton alloc] initWithFrame:NSMakeRect(600, 15, 80, 30)];
  saveButton.autoresizingMask = NSViewMinXMargin | NSViewMaxYMargin;
  saveButton.title = @"Save";
  saveButton.bezelStyle = NSBezelStyleRounded;
  saveButton.keyEquivalent = @"\r";
  saveButton.target = self;
  saveButton.action = @selector(saveClicked:);
  [contentView addSubview:saveButton];

  // Status label
  statusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 20, 400, 20)];
  statusLabel.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;
  statusLabel.bezeled = NO;
  statusLabel.drawsBackground = NO;
  statusLabel.editable = NO;
  statusLabel.selectable = NO;
  statusLabel.stringValue = @"Configure domain-specific cache rules";
  statusLabel.font = [NSFont systemFontOfSize:12];
  statusLabel.textColor = [NSColor secondaryLabelColor];
  [contentView addSubview:statusLabel];
}

- (void)setupRulesTab {
  NSTabViewItem* rulesTab = [[NSTabViewItem alloc] init];
  rulesTab.label = @"Rule Domains";

  NSView* rulesView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 640, 340)];

  // Create table view for rules
  NSScrollView* scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(10, 10, 620, 320)];
  scrollView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  scrollView.hasVerticalScroller = YES;
  scrollView.autohidesScrollers = YES;
  scrollView.borderType = NSBezelBorder;

  self.rulesTableView = [[NSTableView alloc] initWithFrame:scrollView.bounds];
  self.rulesTableView.allowsColumnReordering = NO;
  self.rulesTableView.allowsColumnResizing = YES;
  self.rulesTableView.columnAutoresizingStyle = NSTableViewSequentialColumnAutoresizingStyle;
  self.rulesTableView.usesAlternatingRowBackgroundColors = YES;

  // Domain column
  NSTableColumn* domainColumn = [[NSTableColumn alloc] initWithIdentifier:@"domain"];
  domainColumn.title = @"Domain";
  domainColumn.width = 400;
  domainColumn.editable = NO;
  [self.rulesTableView addTableColumn:domainColumn];

  // Action column with popup
  NSTableColumn* actionColumn = [[NSTableColumn alloc] initWithIdentifier:@"action"];
  actionColumn.title = @"Cache Action";
  actionColumn.width = 150;

  NSPopUpButtonCell* popupCell = [[NSPopUpButtonCell alloc] init];
  [popupCell setBordered:NO];
  [popupCell addItemWithTitle:@"Default"];
  [popupCell addItemWithTitle:@"Never Cache"];
  [popupCell addItemWithTitle:@"Always Cache"];
  [popupCell addItemWithTitle:@"Custom TTL"];
  actionColumn.dataCell = popupCell;

  [self.rulesTableView addTableColumn:actionColumn];

  // TTL column (shows effective TTL)
  NSTableColumn* ttlColumn = [[NSTableColumn alloc] initWithIdentifier:@"ttl"];
  ttlColumn.title = @"TTL (seconds)";
  ttlColumn.width = 100;
  ttlColumn.hidden = NO;
  ttlColumn.editable = NO;  // Only editable for custom entries
  [self.rulesTableView addTableColumn:ttlColumn];

  scrollView.documentView = self.rulesTableView;
  [rulesView addSubview:scrollView];

  // Add help text at the bottom
  NSTextField* helpText = [[NSTextField alloc] initWithFrame:NSMakeRect(10, 5, 600, 20)];
  helpText.bezeled = NO;
  helpText.drawsBackground = NO;
  helpText.editable = NO;
  helpText.selectable = NO;
  helpText.stringValue =
      @"Default cache action uses 300 second TTL. Never=0s, Always=max TTL, Custom=user defined.";
  helpText.font = [NSFont systemFontOfSize:11];
  helpText.textColor = [NSColor secondaryLabelColor];
  [rulesView addSubview:helpText];

  // Set up array controller for rules
  self.rulesArrayController = [[NSArrayController alloc] init];
  self.rulesTableView.dataSource = self;
  self.rulesTableView.delegate = self;

  rulesTab.view = rulesView;
  [self.tabView addTabViewItem:rulesTab];
}

- (void)setupCustomTab {
  NSTabViewItem* customTab = [[NSTabViewItem alloc] init];
  customTab.label = @"Custom Entries";

  NSView* customView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 640, 340)];

  // Create table view for custom entries
  NSScrollView* scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(10, 40, 620, 290)];
  scrollView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  scrollView.hasVerticalScroller = YES;
  scrollView.autohidesScrollers = YES;
  scrollView.borderType = NSBezelBorder;

  self.customTableView = [[NSTableView alloc] initWithFrame:scrollView.bounds];
  self.customTableView.allowsColumnReordering = NO;
  self.customTableView.allowsColumnResizing = YES;
  self.customTableView.columnAutoresizingStyle = NSTableViewSequentialColumnAutoresizingStyle;
  self.customTableView.usesAlternatingRowBackgroundColors = YES;

  // Domain column (editable)
  NSTableColumn* domainColumn = [[NSTableColumn alloc] initWithIdentifier:@"domain"];
  domainColumn.title = @"Domain";
  domainColumn.width = 400;
  domainColumn.editable = YES;
  [self.customTableView addTableColumn:domainColumn];

  // Action column with popup
  NSTableColumn* actionColumn = [[NSTableColumn alloc] initWithIdentifier:@"action"];
  actionColumn.title = @"Cache Action";
  actionColumn.width = 150;

  NSPopUpButtonCell* popupCell = [[NSPopUpButtonCell alloc] init];
  [popupCell setBordered:NO];
  [popupCell addItemWithTitle:@"Never Cache"];
  [popupCell addItemWithTitle:@"Always Cache"];
  [popupCell addItemWithTitle:@"Custom TTL"];
  actionColumn.dataCell = popupCell;

  [self.customTableView addTableColumn:actionColumn];

  // TTL column
  NSTableColumn* ttlColumn = [[NSTableColumn alloc] initWithIdentifier:@"ttl"];
  ttlColumn.title = @"TTL (seconds)";
  ttlColumn.width = 100;
  [self.customTableView addTableColumn:ttlColumn];

  scrollView.documentView = self.customTableView;
  [customView addSubview:scrollView];

  // Add/Remove buttons
  NSButton* addButton = [[NSButton alloc] initWithFrame:NSMakeRect(10, 5, 30, 25)];
  addButton.autoresizingMask = NSViewMaxYMargin;
  addButton.title = @"+";
  addButton.bezelStyle = NSBezelStyleRounded;
  addButton.target = self;
  addButton.action = @selector(addCustomEntry:);
  [customView addSubview:addButton];

  NSButton* removeButton = [[NSButton alloc] initWithFrame:NSMakeRect(45, 5, 30, 25)];
  removeButton.autoresizingMask = NSViewMaxYMargin;
  removeButton.title = @"-";
  removeButton.bezelStyle = NSBezelStyleRounded;
  removeButton.target = self;
  removeButton.action = @selector(removeCustomEntry:);
  [customView addSubview:removeButton];

  // Help text
  NSTextField* helpText = [[NSTextField alloc] initWithFrame:NSMakeRect(90, 5, 500, 25)];
  helpText.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;
  helpText.bezeled = NO;
  helpText.drawsBackground = NO;
  helpText.editable = NO;
  helpText.selectable = NO;
  helpText.stringValue = @"Use wildcards (*) for domain patterns. Example: *.example.com";
  helpText.font = [NSFont systemFontOfSize:11];
  helpText.textColor = [NSColor secondaryLabelColor];
  [customView addSubview:helpText];

  // Set up array controller for custom entries
  self.customArrayController = [[NSArrayController alloc] init];
  self.customTableView.dataSource = self;
  self.customTableView.delegate = self;

  customTab.view = customView;
  [self.tabView addTabViewItem:customTab];
}

- (void)loadData {
  self.ruleDomains = [NSMutableArray array];
  self.customDomains = [NSMutableArray array];

  // Load rule domains from database
  [self loadRuleDomains];

  // Load custom cache rules from preferences
  NSDictionary* savedRules = DNPreferenceGetDictionary(kDNShieldDomainCacheRules);

  DNSLogInfo(LogCategoryCache, "Loading cache data. Retrieved %lu cache rules from preferences",
             (unsigned long)savedRules.count);

  // Start with defaults and merge saved rules to preserve custom entries
  NSMutableDictionary* cacheRules = [NSMutableDictionary dictionary];

  // Add defaults first
  NSDictionary* defaultRules = [DNShieldPreferences defaultValueForKey:kDNShieldDomainCacheRules];
  if (defaultRules) {
    [cacheRules addEntriesFromDictionary:defaultRules];
    DNSLogInfo(LogCategoryCache, "Added %lu default rules", (unsigned long)defaultRules.count);
  }

  // Override with saved rules (this preserves custom entries)
  if (savedRules) {
    [cacheRules addEntriesFromDictionary:savedRules];
    DNSLogInfo(LogCategoryCache, "Merged %lu saved rules (total: %lu)",
               (unsigned long)savedRules.count, (unsigned long)cacheRules.count);
  } else {
    DNSLogInfo(LogCategoryCache, "No saved rules found, using only defaults: %lu rules",
               (unsigned long)cacheRules.count);
  }

  // Separate rules into rule-based and custom
  for (NSString* domain in cacheRules) {
    NSDictionary* rule = cacheRules[domain];
    NSString* action = rule[@"action"];
    NSNumber* ttl = rule[@"ttl"];

    DNSLogInfo(LogCategoryCache,
               "Processing cached rule: %{public}@ -> action:%{public}@ ttl:%{public}@", domain,
               action ?: @"(nil)", ttl ?: @"(nil)");

    CacheRuleEntry* entry = [[CacheRuleEntry alloc] initWithDomain:domain
                                                            action:action
                                                               ttl:ttl
                                                         fromRules:NO];

    // Check if this domain exists in rules
    BOOL foundInRules = NO;
    for (CacheRuleEntry* ruleEntry in self.ruleDomains) {
      if ([ruleEntry.domain isEqualToString:domain]) {
        // Update the rule entry with the cache settings
        ruleEntry.action = action;
        ruleEntry.ttl = ttl;
        foundInRules = YES;
        DNSLogInfo(LogCategoryCache, "Updated rule domain: %{public}@", domain);
        break;
      }
    }

    if (!foundInRules) {
      [self.customDomains addObject:entry];
      DNSLogInfo(LogCategoryCache, "Added as custom domain: %{public}@", domain);
    }
  }

  DNSLogInfo(LogCategoryCache, "Load completed. Rule domains: %lu, Custom domains: %lu",
             (unsigned long)self.ruleDomains.count, (unsigned long)self.customDomains.count);

  [self.rulesTableView reloadData];
  [self.customTableView reloadData];
}

- (void)loadRuleDomains {
  // Open the rules database
  NSString* dbPath = @"/var/db/dnshield/rules.db";
  sqlite3* db;

  if (sqlite3_open([dbPath UTF8String], &db) == SQLITE_OK) {
    // Query for unique domains from rules
    NSString* query = @"SELECT DISTINCT domain FROM dns_rules ORDER BY domain";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* domainCStr = (const char*)sqlite3_column_text(stmt, 0);
        if (domainCStr) {
          NSString* domain = [NSString stringWithUTF8String:domainCStr];

          // Create entry with default action
          CacheRuleEntry* entry = [[CacheRuleEntry alloc] initWithDomain:domain
                                                                  action:@"default"
                                                                     ttl:nil
                                                               fromRules:YES];
          [self.ruleDomains addObject:entry];
        }
      }
      sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
  } else {
    DNSLogError(LogCategoryError, "Failed to open rules database at %{public}@", dbPath);
  }
}

#pragma mark - NSTableViewDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView {
  if (tableView == self.rulesTableView) {
    return self.ruleDomains.count;
  } else {
    return self.customDomains.count;
  }
}

- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                          row:(NSInteger)row {
  CacheRuleEntry* entry;
  if (tableView == self.rulesTableView) {
    entry = self.ruleDomains[row];
  } else {
    entry = self.customDomains[row];
  }

  NSString* identifier = tableColumn.identifier;

  if ([identifier isEqualToString:@"domain"]) {
    return entry.domain;
  } else if ([identifier isEqualToString:@"action"]) {
    // Map action to popup index
    if ([entry.action isEqualToString:@"default"]) {
      return @0;
    } else if ([entry.action isEqualToString:@"never"]) {
      return tableView == self.rulesTableView ? @1 : @0;
    } else if ([entry.action isEqualToString:@"always"]) {
      return tableView == self.rulesTableView ? @2 : @1;
    } else if ([entry.action isEqualToString:@"custom"]) {
      return tableView == self.rulesTableView ? @3 : @2;
    }
    return @0;
  } else if ([identifier isEqualToString:@"ttl"]) {
    if ([entry.action isEqualToString:@"custom"] && entry.ttl) {
      return entry.ttl;
    } else if ([entry.action isEqualToString:@"default"]) {
      // Show default TTL (5 minutes as per kMaxTTL in DNSCache.m)
      return @"300";
    } else if ([entry.action isEqualToString:@"never"]) {
      // Never cache = 0 TTL
      return @"0";
    } else if ([entry.action isEqualToString:@"always"]) {
      // Always cache = max TTL (300 seconds)
      return @"300";
    }
    return @"";
  }

  return nil;
}

- (void)tableView:(NSTableView*)tableView
    setObjectValue:(id)object
    forTableColumn:(NSTableColumn*)tableColumn
               row:(NSInteger)row {
  CacheRuleEntry* entry;
  NSMutableArray* array;

  if (tableView == self.rulesTableView) {
    entry = self.ruleDomains[row];
    array = self.ruleDomains;
  } else {
    entry = self.customDomains[row];
    array = self.customDomains;
  }

  NSString* identifier = tableColumn.identifier;

  if ([identifier isEqualToString:@"domain"]) {
    entry.domain = object;
  } else if ([identifier isEqualToString:@"action"]) {
    NSInteger index = [object integerValue];

    if (tableView == self.rulesTableView) {
      // Rules table: Default, Never, Always, Custom
      switch (index) {
        case 0: entry.action = @"default"; break;
        case 1: entry.action = @"never"; break;
        case 2: entry.action = @"always"; break;
        case 3: entry.action = @"custom"; break;
      }
    } else {
      // Custom table: Never, Always, Custom
      switch (index) {
        case 0: entry.action = @"never"; break;
        case 1: entry.action = @"always"; break;
        case 2: entry.action = @"custom"; break;
      }
    }

    // Clear TTL if not custom
    if (![entry.action isEqualToString:@"custom"]) {
      entry.ttl = nil;
    } else if (!entry.ttl) {
      // Set default TTL for custom
      entry.ttl = @300;  // 5 minutes
    }

    [tableView reloadDataForRowIndexes:[NSIndexSet indexSetWithIndex:row]
                         columnIndexes:[NSIndexSet indexSetWithIndexesInRange:NSMakeRange(0, 3)]];

  } else if ([identifier isEqualToString:@"ttl"]) {
    if ([entry.action isEqualToString:@"custom"]) {
      NSInteger ttlValue = [object integerValue];
      if (ttlValue > 0) {
        entry.ttl = @(ttlValue);
      }
    }
  }
}

#pragma mark - NSTableViewDelegate

- (BOOL)tableView:(NSTableView*)tableView
    shouldEditTableColumn:(NSTableColumn*)tableColumn
                      row:(NSInteger)row {
  NSString* identifier = tableColumn.identifier;

  if (tableView == self.rulesTableView) {
    // Rules table: only action and TTL are editable
    if ([identifier isEqualToString:@"domain"]) {
      return NO;
    } else if ([identifier isEqualToString:@"ttl"]) {
      CacheRuleEntry* entry = self.ruleDomains[row];
      return [entry.action isEqualToString:@"custom"];
    }
    return YES;
  } else {
    // Custom table: all columns editable
    if ([identifier isEqualToString:@"ttl"]) {
      CacheRuleEntry* entry = self.customDomains[row];
      return [entry.action isEqualToString:@"custom"];
    }
    return YES;
  }
}

#pragma mark - Actions

- (void)addCustomEntry:(id)sender {
  CacheRuleEntry* newEntry = [[CacheRuleEntry alloc] initWithDomain:@"*.example.com"
                                                             action:@"never"
                                                                ttl:nil
                                                          fromRules:NO];
  [self.customDomains addObject:newEntry];
  [self.customTableView reloadData];

  // Select and edit the new row
  NSInteger newRow = self.customDomains.count - 1;
  [self.customTableView selectRowIndexes:[NSIndexSet indexSetWithIndex:newRow]
                    byExtendingSelection:NO];
  [self.customTableView editColumn:0 row:newRow withEvent:nil select:YES];
}

- (void)removeCustomEntry:(id)sender {
  NSInteger selectedRow = self.customTableView.selectedRow;
  if (selectedRow >= 0 && selectedRow < self.customDomains.count) {
    [self.customDomains removeObjectAtIndex:selectedRow];
    [self.customTableView reloadData];
  }
}

- (void)saveClicked:(id)sender {
  // Combine all entries into a single dictionary
  NSMutableDictionary* allRules = [NSMutableDictionary dictionary];

  // Add rule-based entries (only non-default ones)
  for (CacheRuleEntry* entry in self.ruleDomains) {
    if (![entry.action isEqualToString:@"default"]) {
      NSMutableDictionary* rule = [NSMutableDictionary dictionaryWithObject:entry.action
                                                                     forKey:@"action"];
      if (entry.ttl) {
        rule[@"ttl"] = entry.ttl;
      }
      allRules[entry.domain] = rule;
    }
  }

  // Add custom entries
  DNSLogInfo(LogCategoryCache, "Processing %lu custom entries for save",
             (unsigned long)self.customDomains.count);
  for (CacheRuleEntry* entry in self.customDomains) {
    DNSLogInfo(LogCategoryCache,
               "Custom entry: domain='%{public}@' action='%{public}@' ttl=%{public}@",
               entry.domain ?: @"(nil)", entry.action ?: @"(nil)", entry.ttl ?: @"(nil)");
    if (entry.domain.length > 0) {
      NSMutableDictionary* rule = [NSMutableDictionary dictionaryWithObject:entry.action
                                                                     forKey:@"action"];
      if (entry.ttl) {
        rule[@"ttl"] = entry.ttl;
      }
      allRules[entry.domain] = rule;
      DNSLogInfo(LogCategoryCache, "Added custom rule: %{public}@ -> %{public}@", entry.domain,
                 rule);
    } else {
      DNSLogInfo(LogCategoryCache, "Skipping empty domain entry");
    }
  }

  // Save to preferences
  DNPreferenceSetValue(kDNShieldDomainCacheRules, allRules);

  DNSLogInfo(LogCategoryCache, "Saved %lu cache rules", (unsigned long)allRules.count);

  [self.window close];
}

- (void)cancelClicked:(id)sender {
  [self.window close];
}

@end
