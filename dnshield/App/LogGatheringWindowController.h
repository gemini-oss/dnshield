//
//  LogGatheringWindowController.h
//  DNShield
//
//

#import <Cocoa/Cocoa.h>

@interface LogGatheringWindowController : NSWindowController

@property(weak) IBOutlet NSMatrix* timeRangeMatrix;
@property(weak) IBOutlet NSTextField* minutesTextField;
@property(weak) IBOutlet NSDatePicker* startDatePicker;
@property(weak) IBOutlet NSDatePicker* endDatePicker;
@property(weak) IBOutlet NSMatrix* logLevelMatrix;
@property(weak) IBOutlet NSPopUpButton* outputLocationPopup;
@property(weak) IBOutlet NSButton* gatherButton;
@property(weak) IBOutlet NSButton* cancelButton;
@property(weak) IBOutlet NSProgressIndicator* progressIndicator;
@property(weak) IBOutlet NSTextField* statusLabel;

- (IBAction)timeRangeChanged:(id)sender;
- (IBAction)gatherLogs:(id)sender;
- (IBAction)cancel:(id)sender;
- (IBAction)selectOutputLocation:(id)sender;

@end
