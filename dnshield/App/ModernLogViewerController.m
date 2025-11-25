//
//  ModernLogViewerController.m
//  DNShield
//
//  modern log viewer
//

#import "ModernLogViewerController.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface ModernLogViewerController ()
@property(nonatomic, assign) BOOL isLoadingLogs;
@end

@implementation ModernLogViewerController

- (instancetype)init {
  self = [super initWithWindowNibName:@"ModernLogViewer"];
  if (self) {
    _logStore = [LogStore defaultStore];
    _allLogEntries = @[];
    _filteredLogEntries = @[];
  }
  return self;
}

- (void)windowDidLoad {
  [super windowDidLoad];

  [self setupWindow];
  [self setupToolbar];
  [self setupSearchControls];
  [self setupLogSettings];
  [self setupTableView];
  [self updateUI];
}

- (void)setupWindow {
  self.window.title = @"DNShield Log Viewer";
  self.window.minSize = NSMakeSize(800, 600);

  // Hide progress indicator initially
  self.progressIndicator.hidden = YES;
  self.statusLabel.hidden = YES;
}

- (void)setupToolbar {
  // Configure toolbar buttons with icons if available
  self.getLogButton.toolTip = @"Fetch and display log entries";
  self.logLevelPopup.toolTip = @"Filter logs by level";
  self.saveButton.toolTip = @"Save current entries";
  self.saveFormatPopup.toolTip = @"Select save format";
}

- (void)setupSearchControls {
  // Setup search field popup
  [self.searchFieldPopup removeAllItems];
  [self.searchFieldPopup
      addItemsWithTitles:@[ @"Messages", @"Processes", @"Senders", @"Subsystems" ]];
  [self.searchFieldPopup selectItemAtIndex:0];

  // Configure search field
  self.searchField.delegate = self;
  self.searchField.sendsSearchStringImmediately = NO;
}

- (void)setupLogSettings {
  // Setup predicate popup
  [self.predicatePopup removeAllItems];
  [self.predicatePopup addItemsWithTitles:@[
    @"All DNShield", @"DNShield App Only", @"Extension Only", @"Subsystem Only", @"Custom Predicate"
  ]];
  [self.predicatePopup selectItemAtIndex:0];  // Default to All DNShield

  // Set default values
  NSDate* now = [NSDate date];
  NSDate* oneHourAgo = [now dateByAddingTimeInterval:-3600];

  // Default to --last mode (not time range)
  self.timeRangeToggle.state = NSControlStateValueOff;
  self.startDatePicker.dateValue = oneHourAgo;
  self.endDatePicker.dateValue = now;
  self.periodField.stringValue = @"3600";  // Default to 1 hour (3600 seconds)
  self.maxEntriesField.stringValue = @"1000";

  // Set default predicate text (hidden by default)
  self.predicateTextField.stringValue = @"";
  self.predicateTextField.hidden = YES;  // Hide by default since "All DNShield" is selected

  [self updateTimeRangeControls];
  [self syncSettingsToLogStore];
}

- (void)setupTableView {
  // Configure table view
  self.logTableView.dataSource = self;
  self.logTableView.delegate = self;

  // Ensure headers are visible
  self.logTableView.headerView = [[NSTableHeaderView alloc] init];

  // Create columns
  [self setupTableColumns];

  // Configure selection
  self.logTableView.allowsMultipleSelection = YES;
  self.logTableView.allowsColumnSelection = NO;
  self.logTableView.allowsEmptySelection = YES;
}

- (void)setupTableColumns {
  // Remove existing columns
  while (self.logTableView.tableColumns.count > 0) {
    [self.logTableView removeTableColumn:self.logTableView.tableColumns.firstObject];
  }

  // Always use compact columns for now
  [self setupCompactColumns];
}

- (void)setupFullFieldColumns {
  NSArray* columns = @[
    @{@"id" : @"date", @"title" : @"Timestamp", @"width" : @180},
    @{@"id" : @"level", @"title" : @"Level", @"width" : @60},
    @{@"id" : @"process", @"title" : @"Process", @"width" : @120},
    @{@"id" : @"pid", @"title" : @"PID", @"width" : @60},
    @{@"id" : @"subsystem", @"title" : @"Subsystem", @"width" : @180},
    @{@"id" : @"category", @"title" : @"Category", @"width" : @100},
    @{@"id" : @"message", @"title" : @"Message", @"width" : @300}
  ];

  [self createColumns:columns];
}

- (void)setupCompactColumns {
  NSArray* columns = @[
    @{@"id" : @"date", @"title" : @"Timestamp", @"width" : @180},
    @{@"id" : @"process", @"title" : @"Process", @"width" : @120},
    @{@"id" : @"subsystem", @"title" : @"Subsystem", @"width" : @180},
    @{@"id" : @"message", @"title" : @"Message", @"width" : @400}
  ];

  [self createColumns:columns];
}

- (void)createColumns:(NSArray*)columnDefinitions {
  for (NSDictionary* def in columnDefinitions) {
    NSTableColumn* column = [[NSTableColumn alloc] initWithIdentifier:def[@"id"]];
    column.title = def[@"title"];
    column.width = [def[@"width"] floatValue];
    column.minWidth = 50;
    column.resizingMask = NSTableColumnUserResizingMask;

    NSTextFieldCell* cell = [[NSTextFieldCell alloc] init];
    cell.font = [NSFont fontWithName:@"Menlo" size:11];
    cell.selectable = YES;  // Make text selectable
    cell.editable = NO;     // But not editable
    column.dataCell = cell;

    [self.logTableView addTableColumn:column];
  }
}

- (void)updateUI {
  self.entriesCountLabel.stringValue =
      [NSString stringWithFormat:@"%lu entries", self.filteredLogEntries.count];

  // Update window title to show current state
  NSString* title = @"DNShield Log Viewer";
  if (self.currentLogarchive) {
    title = [title stringByAppendingFormat:@" - %@", self.currentLogarchive.lastPathComponent];
  }
  if (self.filteredLogEntries.count > 0) {
    LogEntry* firstEntry = self.filteredLogEntries.firstObject;
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateStyle = NSDateFormatterShortStyle;
    formatter.timeStyle = NSDateFormatterShortStyle;
    title = [title stringByAppendingFormat:@" (%@)", [formatter stringFromDate:firstEntry.date]];
  }
  self.window.title = title;
}

- (void)syncSettingsToLogStore {
  self.logStore.maxEntries = [self.maxEntriesField.stringValue integerValue];
  self.logStore.includeSignposts = NO;
  self.logStore.showAllFields = NO;

  // Handle time range vs --last mode
  BOOL useTimeRange = (self.timeRangeToggle.state == NSControlStateValueOn);
  if (useTimeRange) {
    // Use specific start/end dates
    self.logStore.startDate = self.startDatePicker.dateValue;
    self.logStore.endDate = self.endDatePicker.dateValue;
    self.logStore.timeRange = 0;  // Disable --last mode
  } else {
    // Use --last mode with period
    self.logStore.timeRange = [self.periodField.stringValue doubleValue];
    self.logStore.startDate = nil;
    self.logStore.endDate = nil;
  }

  NSInteger predicateIndex = [self.predicatePopup indexOfSelectedItem];
  switch (predicateIndex) {
    case 0: self.logStore.predicateType = PredicateTypeAllDNShield; break;
    case 1: self.logStore.predicateType = PredicateTypeDNShieldApp; break;
    case 2: self.logStore.predicateType = PredicateTypeDNShieldExtension; break;
    case 3: self.logStore.predicateType = PredicateTypeDNShieldSubsystem; break;
    case 4:
      self.logStore.predicateType = PredicateTypeCustom;
      self.logStore.customPredicate = self.predicateTextField.stringValue;
      break;
  }
}

- (void)updateTimeRangeControls {
  BOOL useTimeRange = (self.timeRangeToggle.state == NSControlStateValueOn);

  // Show/hide appropriate controls
  self.startDatePicker.hidden = !useTimeRange;
  self.endDatePicker.hidden = !useTimeRange;
  self.periodField.hidden = useTimeRange;

  // Update checkbox title to reflect current mode
  if (useTimeRange) {
    self.timeRangeToggle.title = @"Using Time Range";
  } else {
    self.timeRangeToggle.title = @"Use Time Range";
  }
}

- (IBAction)timeRangeToggled:(id)sender {
  [self updateTimeRangeControls];
}

#pragma mark - Actions

- (IBAction)getLog:(id)sender {
  if (self.isLoadingLogs)
    return;

  [self syncSettingsToLogStore];
  [self startLoading:@"Fetching logs..."];

  [self.logStore fetchLogEntriesWithCompletion:^(NSArray<LogEntry*>* entries, NSError* error) {
    [self stopLoading];

    if (error) {
      [self showError:@"Failed to fetch logs" message:error.localizedDescription];
      return;
    }

    self.allLogEntries = entries;
    self.filteredLogEntries = entries;
    [self.logTableView reloadData];
    [self updateUI];

    NSLog(@"Fetched %lu log entries", entries.count);
  }];
}

- (IBAction)saveWithFormat:(id)sender {
  if (self.filteredLogEntries.count == 0) {
    NSBeep();
    return;
  }

  BOOL isJSON = (self.saveFormatPopup.indexOfSelectedItem == 0);
  NSSavePanel* savePanel = [NSSavePanel savePanel];

  if (isJSON) {
    if (@available(macOS 12.0, *)) {
      savePanel.allowedContentTypes = @[ [UTType typeWithIdentifier:@"public.json"] ];
    } else {
      savePanel.allowedFileTypes = @[ @"json" ];
    }
    savePanel.nameFieldStringValue = @"DNShield_Logs.json";
  } else {
    if (@available(macOS 12.0, *)) {
      savePanel.allowedContentTypes = @[ [UTType typeWithIdentifier:@"public.rtf"] ];
    } else {
      savePanel.allowedFileTypes = @[ @"rtf" ];
    }
    savePanel.nameFieldStringValue = @"DNShield_Logs.rtf";
  }

  [savePanel beginSheetModalForWindow:self.window
                    completionHandler:^(NSModalResponse result) {
                      if (result == NSModalResponseOK) {
                        if (isJSON) {
                          [self exportToJSON:savePanel.URL];
                        } else {
                          [self exportToRTF:savePanel.URL];
                        }
                      }
                    }];
}

- (void)exportToJSON:(NSURL*)fileURL {
  NSString* jsonString = [self.logStore exportEntriesToJSON:self.filteredLogEntries];
  if (!jsonString) {
    [self showError:@"Export Failed" message:@"Failed to create JSON export"];
    return;
  }

  NSError* error;
  BOOL success = [jsonString writeToURL:fileURL
                             atomically:YES
                               encoding:NSUTF8StringEncoding
                                  error:&error];
  if (!success) {
    [self showError:@"Export Failed" message:error.localizedDescription];
  }
}

- (void)exportToRTF:(NSURL*)fileURL {
  NSString* rtfString = [self.logStore exportEntriesToRTF:self.filteredLogEntries];
  if (!rtfString) {
    [self showError:@"Export Failed" message:@"Failed to create RTF export"];
    return;
  }

  NSError* error;
  BOOL success = [rtfString writeToURL:fileURL
                            atomically:YES
                              encoding:NSUTF8StringEncoding
                                 error:&error];
  if (!success) {
    [self showError:@"Export Failed" message:error.localizedDescription];
  }
}

- (IBAction)predicateChanged:(id)sender {
  // Update predicate text field visibility based on selection
  NSInteger index = [self.predicatePopup indexOfSelectedItem];
  self.predicateTextField.hidden = (index != 4);  // Only show for "Custom Predicate"

  if (index == 4) {
    // Set placeholder text for custom predicate
    if (self.predicateTextField.stringValue.length == 0) {
      self.predicateTextField.stringValue = @"process == \"DNShield\"";
    }
  }
}

- (IBAction)settingsChanged:(id)sender {
  // Settings changed - no specific UI updates needed for now
}

#pragma mark - Search

- (void)controlTextDidChange:(NSNotification*)obj {
  if (obj.object == self.searchField) {
    [self performSearch];
  }
}

- (IBAction)searchFieldChanged:(id)sender {
  [self performSearch];
}

- (void)performSearch {
  NSString* searchText = self.searchField.stringValue;

  if (searchText.length == 0) {
    self.filteredLogEntries = self.allLogEntries;
  } else {
    NSString* searchField = [self.searchFieldPopup titleOfSelectedItem];
    self.filteredLogEntries = [self.logStore filterEntries:self.allLogEntries
                                            withSearchText:searchText
                                                   inField:searchField];
  }

  [self.logTableView reloadData];
  [self updateUI];
}

#pragma mark - Table View Data Source

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView {
  return self.filteredLogEntries.count;
}

- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                          row:(NSInteger)row {
  if (row >= self.filteredLogEntries.count)
    return @"";

  LogEntry* entry = self.filteredLogEntries[row];
  NSString* identifier = tableColumn.identifier;

  if ([identifier isEqualToString:@"date"]) {
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSSSSS";
    return [formatter stringFromDate:entry.date];
  } else if ([identifier isEqualToString:@"type"]) {
    return @(entry.type);
  } else if ([identifier isEqualToString:@"activity"]) {
    return @(entry.activityID);
  } else if ([identifier isEqualToString:@"category"]) {
    return entry.category ?: @"";
  } else if ([identifier isEqualToString:@"level"]) {
    return @(entry.level);
  } else if ([identifier isEqualToString:@"process"]) {
    return entry.process ?: @"";
  } else if ([identifier isEqualToString:@"sender"]) {
    return entry.sender ?: @"";
  } else if ([identifier isEqualToString:@"pid"]) {
    return @(entry.processID);
  } else if ([identifier isEqualToString:@"subsystem"]) {
    return entry.subsystem ?: @"";
  } else if ([identifier isEqualToString:@"thread"]) {
    return @(entry.threadID);
  } else if ([identifier isEqualToString:@"message"]) {
    return entry.message ?: @"";
  }

  return @"";
}

#pragma mark - Table View Delegate

- (void)tableView:(NSTableView*)tableView
    willDisplayCell:(id)cell
     forTableColumn:(NSTableColumn*)tableColumn
                row:(NSInteger)row {
  if (row >= self.filteredLogEntries.count)
    return;

  LogEntry* entry = self.filteredLogEntries[row];
  NSTextFieldCell* textCell = (NSTextFieldCell*)cell;

  // Set colors based on log level
  switch (entry.level) {
    case LogEntryLevelError:
    case LogEntryLevelFault: textCell.textColor = [NSColor redColor]; break;
    case LogEntryLevelDebug: textCell.textColor = [NSColor blueColor]; break;
    case LogEntryLevelInfo:
      textCell.textColor = [NSColor colorWithRed:0.0 green:0.5 blue:0.0 alpha:1.0];  // Dark green
      break;
    default: textCell.textColor = [NSColor textColor]; break;
  }
}

#pragma mark - Utility Methods

- (void)startLoading:(NSString*)message {
  self.isLoadingLogs = YES;
  self.progressIndicator.hidden = NO;
  self.statusLabel.hidden = NO;
  self.statusLabel.stringValue = message;
  [self.progressIndicator startAnimation:nil];

  self.getLogButton.enabled = NO;
}

- (void)stopLoading {
  self.isLoadingLogs = NO;
  [self.progressIndicator stopAnimation:nil];
  self.progressIndicator.hidden = YES;
  self.statusLabel.hidden = YES;

  self.getLogButton.enabled = YES;
}

- (void)showError:(NSString*)title message:(NSString*)message {
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = title;
  alert.informativeText = message;
  [alert addButtonWithTitle:@"OK"];
  [alert beginSheetModalForWindow:self.window completionHandler:nil];
}

@end
