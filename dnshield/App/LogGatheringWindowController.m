//
//  LogGatheringWindowController.m
//  DNShield
//
//

#import "LogGatheringWindowController.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <os/log.h>

@interface LogGatheringWindowController ()
@property(strong) NSString* selectedOutputPath;
@end

@implementation LogGatheringWindowController

- (instancetype)init {
  self = [super initWithWindowNibName:@"LogGatheringWindow"];
  if (self) {
    _selectedOutputPath =
        [NSHomeDirectory() stringByAppendingPathComponent:@"Desktop/DNShield_Logs.txt"];
  }
  return self;
}

- (void)windowDidLoad {
  [super windowDidLoad];

  // Set window title
  self.window.title = @"Gather DNShield Logs";

  // Configure default selections
  [self.timeRangeMatrix selectCellAtRow:0 column:0];  // Last X minutes
  self.minutesTextField.stringValue = @"60";

  [self.logLevelMatrix selectCellAtRow:0 column:0];  // Info level

  // Configure output location popup
  [self.outputLocationPopup removeAllItems];
  [self.outputLocationPopup addItemWithTitle:@"Desktop"];
  [self.outputLocationPopup addItemWithTitle:@"Downloads"];
  [self.outputLocationPopup addItemWithTitle:@"Choose Location..."];

  // Set default date range to last hour
  NSDate* now = [NSDate date];
  NSDate* oneHourAgo = [now dateByAddingTimeInterval:-3600];
  self.startDatePicker.dateValue = oneHourAgo;
  self.endDatePicker.dateValue = now;

  // Initially hide date pickers
  self.startDatePicker.hidden = YES;
  self.endDatePicker.hidden = YES;

  // Hide progress indicator initially
  self.progressIndicator.hidden = YES;
  self.statusLabel.hidden = YES;

  [self timeRangeChanged:nil];
}

- (IBAction)timeRangeChanged:(id)sender {
  NSInteger selectedRow = [self.timeRangeMatrix selectedRow];

  // Show/hide controls based on selection
  if (selectedRow == 0) {  // Last X minutes
    self.minutesTextField.hidden = NO;
    self.startDatePicker.hidden = YES;
    self.endDatePicker.hidden = YES;
  } else {  // Between specific times
    self.minutesTextField.hidden = YES;
    self.startDatePicker.hidden = NO;
    self.endDatePicker.hidden = NO;
  }
}

- (IBAction)selectOutputLocation:(id)sender {
  NSString* selectedTitle = [self.outputLocationPopup titleOfSelectedItem];

  if ([selectedTitle isEqualToString:@"Desktop"]) {
    self.selectedOutputPath =
        [NSHomeDirectory() stringByAppendingPathComponent:@"Desktop/DNShield_Logs.txt"];
  } else if ([selectedTitle isEqualToString:@"Downloads"]) {
    self.selectedOutputPath =
        [NSHomeDirectory() stringByAppendingPathComponent:@"Downloads/DNShield_Logs.txt"];
  } else if ([selectedTitle isEqualToString:@"Choose Location..."]) {
    NSSavePanel* savePanel = [NSSavePanel savePanel];
    if (@available(macOS 12.0, *)) {
      savePanel.allowedContentTypes = @[ [UTType typeWithFilenameExtension:@"txt"] ];
    } else {
      savePanel.allowedFileTypes = @[ @"txt" ];
    }
    savePanel.nameFieldStringValue = @"DNShield_Logs.txt";

    [savePanel beginSheetModalForWindow:self.window
                      completionHandler:^(NSInteger result) {
                        if (result == NSModalResponseOK) {
                          self.selectedOutputPath = savePanel.URL.path;
                        } else {
                          // Reset to Desktop if user cancelled
                          [self.outputLocationPopup selectItemWithTitle:@"Desktop"];
                          self.selectedOutputPath = [NSHomeDirectory()
                              stringByAppendingPathComponent:@"Desktop/DNShield_Logs.txt"];
                        }
                      }];
  }
}

- (IBAction)gatherLogs:(id)sender {
  // Disable gather button and show progress
  self.gatherButton.enabled = NO;
  self.progressIndicator.hidden = NO;
  self.statusLabel.hidden = NO;
  [self.progressIndicator startAnimation:nil];
  self.statusLabel.stringValue = @"Gathering logs...";

  // Build the log arguments directly
  NSArray* logArguments = [self buildLogArguments];

  // Execute command in background
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSTask* task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/log";
    task.arguments = logArguments;

    NSPipe* pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;

    [task launch];
    [task waitUntilExit];

    NSData* data = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString* output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    // Write to file
    NSError* writeError;
    BOOL success = [output writeToFile:self.selectedOutputPath
                            atomically:YES
                              encoding:NSUTF8StringEncoding
                                 error:&writeError];

    dispatch_async(dispatch_get_main_queue(), ^{
      [self.progressIndicator stopAnimation:nil];
      self.progressIndicator.hidden = YES;

      if (success && output.length > 0) {
        self.statusLabel.stringValue =
            [NSString stringWithFormat:@"Logs saved to: %@", self.selectedOutputPath];

        // Show success alert with option to reveal file
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"Logs Gathered Successfully";
        alert.informativeText =
            [NSString stringWithFormat:@"Logs have been saved to:\n%@\n\nSize: %ld bytes",
                                       self.selectedOutputPath, output.length];
        [alert addButtonWithTitle:@"Reveal in Finder"];
        [alert addButtonWithTitle:@"OK"];

        [alert beginSheetModalForWindow:self.window
                      completionHandler:^(NSModalResponse returnCode) {
                        if (returnCode == NSAlertFirstButtonReturn) {
                          [[NSWorkspace sharedWorkspace] selectFile:self.selectedOutputPath
                                           inFileViewerRootedAtPath:@""];
                        }
                      }];
      } else {
        NSString* errorMessage;
        if (!success) {
          errorMessage = writeError.localizedDescription;
        } else if (output.length == 0) {
          errorMessage = @"No logs found for the specified criteria. Try a longer time range or "
                         @"different log level.";
        } else {
          errorMessage = @"Unknown error occurred";
        }

        self.statusLabel.stringValue = [NSString stringWithFormat:@"Error: %@", errorMessage];

        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"Error Gathering Logs";
        alert.informativeText = errorMessage;
        [alert addButtonWithTitle:@"OK"];
        [alert beginSheetModalForWindow:self.window completionHandler:nil];
      }

      self.gatherButton.enabled = YES;
    });
  });
}

- (IBAction)cancel:(id)sender {
  [self.window performClose:nil];
}

- (NSArray<NSString*>*)buildLogArguments {
  // Start with the basic log show command
  NSMutableArray* arguments = [[NSMutableArray alloc] initWithObjects:@"show", nil];

  // Add predicate for DNShield processes
  [arguments addObject:@"--predicate"];
  [arguments addObject:@"process == \"DNShield\" OR subsystem == \"com.dnshield\" OR subsystem == "
                       @"\"com.dnshield.app\" OR process == \"com.dnshield.extension\""];

  // Add log level
  NSInteger logLevelRow = [self.logLevelMatrix selectedRow];
  if (logLevelRow == 1) {  // Debug
    [arguments addObject:@"--debug"];
  } else if (logLevelRow == 2) {  // Both (info + debug)
    [arguments addObject:@"--debug"];
  } else {
    [arguments addObject:@"--info"];
  }

  // Add style
  [arguments addObject:@"--style"];
  [arguments addObject:@"compact"];

  // Add time range arguments
  NSInteger timeRangeRow = [self.timeRangeMatrix selectedRow];
  if (timeRangeRow == 0) {  // Last X minutes
    NSInteger minutes = [self.minutesTextField.stringValue integerValue];
    if (minutes <= 0)
      minutes = 60;  // Default to 60 if invalid
    [arguments addObject:@"--last"];
    [arguments addObject:[NSString stringWithFormat:@"%ldm", (long)minutes]];
  } else {  // Between specific times
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";

    NSString* startTime = [formatter stringFromDate:self.startDatePicker.dateValue];
    NSString* endTime = [formatter stringFromDate:self.endDatePicker.dateValue];

    [arguments addObject:@"--start"];
    [arguments addObject:startTime];
    [arguments addObject:@"--end"];
    [arguments addObject:endTime];
  }

  return [arguments copy];
}

@end
