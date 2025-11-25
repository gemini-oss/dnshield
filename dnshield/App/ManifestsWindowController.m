//
//  ManifestsWindowController.m
//  DNShield
//
//  Window controller for displaying manifest hierarchy and information
//

#import "ManifestsWindowController.h"

@interface ManifestItem : NSObject
@property(nonatomic, strong) NSString* name;
@property(nonatomic, strong) NSString* type;
@property(nonatomic, strong) NSArray* children;
@property(nonatomic, assign) NSInteger ruleCount;
@property(nonatomic, strong) NSDate* lastUpdated;
@end

@implementation ManifestItem
@end

@interface ManifestsWindowController () {
  NSMutableArray* _rootItems;
}
@end

@implementation ManifestsWindowController

- (instancetype)initWithManifestData:(NSArray*)data manifestURL:(NSString*)url {
  self = [super init];
  if (self) {
    self.manifestData = data;
    self.manifestURL = url;
    [self parseManifestData];
    [self setupWindow];
  }
  return self;
}

- (void)parseManifestData {
  _rootItems = [NSMutableArray array];

  for (NSDictionary* manifest in self.manifestData) {
    ManifestItem* item = [[ManifestItem alloc] init];
    item.name = manifest[@"identifier"];
    item.type = manifest[@"type"];
    item.ruleCount = [manifest[@"ruleCount"] integerValue];
    item.lastUpdated = manifest[@"lastUpdated"];

    // Handle included manifests
    NSArray* included = manifest[@"included"];
    if (included && included.count > 0) {
      NSMutableArray* children = [NSMutableArray array];
      for (NSString* includedManifest in included) {
        ManifestItem* child = [[ManifestItem alloc] init];
        child.name = includedManifest;
        child.type = @"included";
        [children addObject:child];
      }
      item.children = children;
    }

    [_rootItems addObject:item];
  }
}

- (void)setupWindow {
  // Create window
  NSRect frame = NSMakeRect(0, 0, 700, 500);
  NSUInteger styleMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                         NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
  NSWindow* window = [[NSWindow alloc] initWithContentRect:frame
                                                 styleMask:styleMask
                                                   backing:NSBackingStoreBuffered
                                                     defer:NO];
  window.title = @"DNShield Manifests";
  [window center];

  self.window = window;

  NSView* contentView = window.contentView;

  // Create header label
  NSTextField* headerLabel = [[NSTextField alloc]
      initWithFrame:NSMakeRect(20, frame.size.height - 40, frame.size.width - 40, 20)];
  headerLabel.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
  headerLabel.editable = NO;
  headerLabel.bordered = NO;
  headerLabel.backgroundColor = [NSColor clearColor];
  headerLabel.font = [NSFont boldSystemFontOfSize:14];
  headerLabel.stringValue = @"Manifest Hierarchy";
  [contentView addSubview:headerLabel];

  // Create manifest URL label if available
  if (self.manifestURL && self.manifestURL.length > 0) {
    self.manifestURLLabel = [[NSTextField alloc]
        initWithFrame:NSMakeRect(20, frame.size.height - 65, frame.size.width - 40, 20)];
    self.manifestURLLabel.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    self.manifestURLLabel.editable = NO;
    self.manifestURLLabel.bordered = NO;
    self.manifestURLLabel.backgroundColor = [NSColor clearColor];
    self.manifestURLLabel.font = [NSFont systemFontOfSize:11];
    self.manifestURLLabel.textColor = [NSColor secondaryLabelColor];
    self.manifestURLLabel.stringValue =
        [NSString stringWithFormat:@"Manifest URL: %@", self.manifestURL];
    [contentView addSubview:self.manifestURLLabel];
  }

  // Create scroll view and outline view
  CGFloat topOffset = self.manifestURLLabel ? 75 : 50;
  NSRect scrollFrame =
      NSMakeRect(20, 50, frame.size.width - 40, frame.size.height - topOffset - 50);
  NSScrollView* scrollView = [[NSScrollView alloc] initWithFrame:scrollFrame];
  scrollView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  scrollView.hasVerticalScroller = YES;
  scrollView.borderType = NSBezelBorder;

  self.outlineView = [[NSOutlineView alloc] initWithFrame:scrollView.bounds];
  self.outlineView.delegate = self;
  self.outlineView.dataSource = self;
  self.outlineView.usesAlternatingRowBackgroundColors = YES;
  self.outlineView.indentationPerLevel = 16;

  // Create columns
  NSTableColumn* nameColumn = [[NSTableColumn alloc] initWithIdentifier:@"name"];
  nameColumn.title = @"Manifest";
  nameColumn.width = 250;
  [self.outlineView addTableColumn:nameColumn];

  NSTableColumn* typeColumn = [[NSTableColumn alloc] initWithIdentifier:@"type"];
  typeColumn.title = @"Type";
  typeColumn.width = 80;
  [self.outlineView addTableColumn:typeColumn];

  NSTableColumn* ruleCountColumn = [[NSTableColumn alloc] initWithIdentifier:@"ruleCount"];
  ruleCountColumn.title = @"Rule Count";
  ruleCountColumn.width = 100;
  [self.outlineView addTableColumn:ruleCountColumn];

  NSTableColumn* lastUpdatedColumn = [[NSTableColumn alloc] initWithIdentifier:@"lastUpdated"];
  lastUpdatedColumn.title = @"Last Updated";
  lastUpdatedColumn.width = 150;
  [self.outlineView addTableColumn:lastUpdatedColumn];

  scrollView.documentView = self.outlineView;
  [contentView addSubview:scrollView];

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

  // Expand all items
  [self.outlineView expandItem:nil expandChildren:YES];
}

- (void)updateStatusLabel {
  NSUInteger totalManifests = _rootItems.count;
  NSUInteger totalIncluded = 0;

  for (ManifestItem* item in _rootItems) {
    if (item.children) {
      totalIncluded += item.children.count;
    }
  }

  if (totalIncluded > 0) {
    self.statusLabel.stringValue =
        [NSString stringWithFormat:@"%lu active manifests, %lu included manifests", totalManifests,
                                   totalIncluded];
  } else {
    self.statusLabel.stringValue =
        [NSString stringWithFormat:@"%lu active manifests", totalManifests];
  }
}

#pragma mark - NSOutlineViewDataSource

- (NSInteger)outlineView:(NSOutlineView*)outlineView numberOfChildrenOfItem:(id)item {
  if (item == nil) {
    return _rootItems.count;
  }
  if ([item isKindOfClass:[ManifestItem class]]) {
    ManifestItem* manifestItem = item;
    return manifestItem.children.count;
  }
  return 0;
}

- (id)outlineView:(NSOutlineView*)outlineView child:(NSInteger)index ofItem:(id)item {
  if (item == nil) {
    return _rootItems[index];
  }
  if ([item isKindOfClass:[ManifestItem class]]) {
    ManifestItem* manifestItem = item;
    return manifestItem.children[index];
  }
  return nil;
}

- (BOOL)outlineView:(NSOutlineView*)outlineView isItemExpandable:(id)item {
  if ([item isKindOfClass:[ManifestItem class]]) {
    ManifestItem* manifestItem = item;
    return manifestItem.children && manifestItem.children.count > 0;
  }
  return NO;
}

- (id)outlineView:(NSOutlineView*)outlineView
    objectValueForTableColumn:(NSTableColumn*)tableColumn
                       byItem:(id)item {
  if ([item isKindOfClass:[ManifestItem class]]) {
    ManifestItem* manifestItem = item;
    NSString* identifier = tableColumn.identifier;

    if ([identifier isEqualToString:@"name"]) {
      return manifestItem.name;
    } else if ([identifier isEqualToString:@"type"]) {
      return [self displayTypeForType:manifestItem.type];
    } else if ([identifier isEqualToString:@"ruleCount"]) {
      if (manifestItem.ruleCount > 0) {
        return [NSString stringWithFormat:@"%ld", manifestItem.ruleCount];
      } else {
        return @"0";
      }
    } else if ([identifier isEqualToString:@"lastUpdated"]) {
      if (manifestItem.lastUpdated) {
        NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
        formatter.dateStyle = NSDateFormatterShortStyle;
        formatter.timeStyle = NSDateFormatterShortStyle;
        return [formatter stringFromDate:manifestItem.lastUpdated];
      } else {
        return @"";
      }
    }
  }
  return nil;
}

#pragma mark - NSOutlineViewDelegate

- (void)outlineView:(NSOutlineView*)outlineView
    willDisplayCell:(id)cell
     forTableColumn:(NSTableColumn*)tableColumn
               item:(id)item {
  if ([item isKindOfClass:[ManifestItem class]]) {
    ManifestItem* manifestItem = item;

    if ([tableColumn.identifier isEqualToString:@"name"]) {
      NSTextFieldCell* textCell = (NSTextFieldCell*)cell;

      // Bold for primary manifest
      if ([manifestItem.type isEqualToString:@"primary"]) {
        textCell.font = [NSFont boldSystemFontOfSize:13];
      } else if ([manifestItem.type isEqualToString:@"included"]) {
        textCell.font = [NSFont systemFontOfSize:12];
        textCell.textColor = [NSColor secondaryLabelColor];
      } else {
        textCell.font = [NSFont systemFontOfSize:13];
      }
    } else if ([tableColumn.identifier isEqualToString:@"type"]) {
      NSTextFieldCell* textCell = (NSTextFieldCell*)cell;

      // Color code by type
      if ([manifestItem.type isEqualToString:@"primary"]) {
        textCell.textColor = [NSColor systemBlueColor];
      } else if ([manifestItem.type isEqualToString:@"team"]) {
        textCell.textColor = [NSColor systemPurpleColor];
      } else if ([manifestItem.type isEqualToString:@"domain"]) {
        textCell.textColor = [NSColor systemGreenColor];
      } else if ([manifestItem.type isEqualToString:@"global"]) {
        textCell.textColor = [NSColor systemOrangeColor];
      } else {
        textCell.textColor = [NSColor secondaryLabelColor];
      }
    }
  }
}

#pragma mark - Helper Methods

- (NSString*)displayTypeForType:(NSString*)type {
  if ([type isEqualToString:@"primary"]) {
    return @"Device";
  } else if ([type isEqualToString:@"team"]) {
    return @"Team";
  } else if ([type isEqualToString:@"domain"]) {
    return @"Domain";
  } else if ([type isEqualToString:@"global"]) {
    return @"Global";
  } else if ([type isEqualToString:@"included"]) {
    return @"Included";
  }
  return type;
}

@end
