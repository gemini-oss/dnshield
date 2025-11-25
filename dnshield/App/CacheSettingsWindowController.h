//
//  CacheSettingsWindowController.h
//  DNShield
//
//  Window controller for DNS cache settings with tabbed interface
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@interface CacheSettingsWindowController
    : NSWindowController <NSTabViewDelegate, NSTableViewDataSource, NSTableViewDelegate>

@property(nonatomic, strong) NSTabView* tabView;
@property(nonatomic, strong) NSTableView* rulesTableView;
@property(nonatomic, strong) NSTableView* customTableView;
@property(nonatomic, strong) NSArrayController* rulesArrayController;
@property(nonatomic, strong) NSArrayController* customArrayController;

@property(nonatomic, strong) NSMutableArray* ruleDomains;
@property(nonatomic, strong) NSMutableArray* customDomains;

- (instancetype)init;

@end

NS_ASSUME_NONNULL_END
