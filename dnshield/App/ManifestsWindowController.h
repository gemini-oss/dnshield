//
//  ManifestsWindowController.h
//  DNShield
//
//  Window controller for displaying manifest hierarchy and information
//

#import <Cocoa/Cocoa.h>

@interface ManifestsWindowController
    : NSWindowController <NSOutlineViewDelegate, NSOutlineViewDataSource>

@property(nonatomic, strong) NSOutlineView* outlineView;
@property(nonatomic, strong) NSTextField* statusLabel;
@property(nonatomic, strong) NSTextField* manifestURLLabel;
@property(nonatomic, strong) NSArray* manifestData;
@property(nonatomic, strong) NSString* manifestURL;

- (instancetype)initWithManifestData:(NSArray*)data manifestURL:(NSString*)url;

@end
