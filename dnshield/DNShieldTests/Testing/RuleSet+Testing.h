//
//  RuleSet+Testing.h
//  DNShield Tests
//

#import "RuleSet.h"

NS_ASSUME_NONNULL_BEGIN

@interface RuleSet (Testing)

+ (RuleSet*)dns_ruleSetWithAllow:(nullable NSArray<NSString*>*)allow
                           block:(nullable NSArray<NSString*>*)block
                            name:(nullable NSString*)name
                         version:(nullable NSString*)version;

@end

NS_ASSUME_NONNULL_END
