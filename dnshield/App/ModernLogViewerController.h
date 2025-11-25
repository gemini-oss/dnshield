//
//  ModernLogViewerController.h
//  DNShield
//
//  modern log viewer
//

#import <Cocoa/Cocoa.h>
#import "LogEntry.h"
#import "LogStore.h"

NS_ASSUME_NONNULL_BEGIN

@interface ModernLogViewerController
    : NSWindowController <NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate>

// Toolbar controls
@property(weak) IBOutlet NSButton* getLogButton;
@property(weak) IBOutlet NSPopUpButton* logLevelPopup;
@property(weak) IBOutlet NSButton* saveButton;
@property(weak) IBOutlet NSPopUpButton* saveFormatPopup;

// Search controls
@property(weak) IBOutlet NSPopUpButton* searchFieldPopup;
@property(weak) IBOutlet NSSearchField* searchField;

// Log settings
@property(weak) IBOutlet NSButton* timeRangeToggle;
@property(weak) IBOutlet NSDatePicker* startDatePicker;
@property(weak) IBOutlet NSDatePicker* endDatePicker;
@property(weak) IBOutlet NSTextField* periodField;
@property(weak) IBOutlet NSTextField* maxEntriesField;
@property(weak) IBOutlet NSPopUpButton* predicatePopup;
@property(weak) IBOutlet NSTextField* predicateTextField;
@property(weak) IBOutlet NSTextField* entriesCountLabel;

// Main display
@property(weak) IBOutlet NSTableView* logTableView;
@property(weak) IBOutlet NSScrollView* logScrollView;
@property(weak) IBOutlet NSProgressIndicator* progressIndicator;
@property(weak) IBOutlet NSTextField* statusLabel;

// Data
@property(nonatomic, strong) LogStore* logStore;
@property(nonatomic, strong) NSArray<LogEntry*>* allLogEntries;
@property(nonatomic, strong) NSArray<LogEntry*>* filteredLogEntries;
@property(nonatomic, strong, nullable) NSURL* currentLogarchive;

// Actions
- (IBAction)getLog:(id)sender;
- (IBAction)saveWithFormat:(id)sender;
- (IBAction)predicateChanged:(id)sender;
- (IBAction)settingsChanged:(id)sender;
- (IBAction)timeRangeToggled:(id)sender;

@end

NS_ASSUME_NONNULL_END
