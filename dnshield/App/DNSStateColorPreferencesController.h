//
//  DNSStateColorPreferencesController.h
//  DNShield
//

#import <Cocoa/Cocoa.h>
#import "DNSStateColorManager.h"

NS_ASSUME_NONNULL_BEGIN

@class DNSStateColorPreferencesController;

@protocol DNSStateColorPreferencesControllerDelegate <NSObject>
- (void)stateColorPreferencesControllerDidUpdateColors:
    (DNSStateColorPreferencesController*)controller;
@end

@interface DNSStateColorPreferencesController : NSObject

@property(nonatomic, weak) id<DNSStateColorPreferencesControllerDelegate> delegate;
@property(nonatomic, strong, readonly) DNSStateColorManager* stateColorManager;
@property(nonatomic, assign, readonly) NSInteger colorTargetSelection;  // 0=Both,1=Shield,2=Globe

- (void)start;
- (void)stop;
- (void)showColorPicker;
- (void)colorPanelChanged:(NSColorPanel*)panel;
- (void)toggleStateColorMode;
- (void)selectColorTarget:(NSInteger)target;
- (void)changeIconColorWithMenuItem:(NSMenuItem*)sender;
- (void)showStateColorConfiguration;
- (NSArray<NSColor*>*)paletteColorsForStateColor:(NSColor*)primaryColor;
- (NSColor*)complementaryColorForColor:(NSColor*)color;

@end

NS_ASSUME_NONNULL_END
