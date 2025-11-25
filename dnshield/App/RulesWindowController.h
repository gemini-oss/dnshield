//
//  RulesWindowController.h
//  DNShield
//
//  Window controller for displaying and searching DNS rules
//

#import <Cocoa/Cocoa.h>

@interface RulesWindowController
    : NSWindowController <NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate>

@property(nonatomic, strong) NSArray* allRules;
@property(nonatomic, strong) NSArray* filteredRules;
@property(nonatomic, strong) NSDictionary* configInfo;
@property(nonatomic, strong) NSDictionary* syncInfo;

@property(nonatomic, strong) NSSearchField* searchField;
@property(nonatomic, strong) NSTableView* tableView;
@property(nonatomic, strong) NSScrollView* scrollView;
@property(nonatomic, strong) NSSegmentedControl* filterSegment;
@property(nonatomic, strong) NSTextField* statusLabel;

- (instancetype)initWithRules:(NSArray*)blockedDomains
               allowedDomains:(NSArray*)allowedDomains
                  ruleSources:(NSDictionary*)ruleSources
                   configInfo:(NSDictionary*)configInfo;

- (instancetype)initWithRules:(NSArray*)blockedDomains
               allowedDomains:(NSArray*)allowedDomains
                  ruleSources:(NSDictionary*)ruleSources
                   configInfo:(NSDictionary*)configInfo
                     syncInfo:(NSDictionary*)syncInfo;

@end
