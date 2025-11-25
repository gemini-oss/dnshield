//
//  RuleSet+Testing.m
//  DNShield Tests
//

#import "RuleSet+Testing.h"

@implementation RuleSet (Testing)

+ (RuleSet*)dns_ruleSetWithAllow:(NSArray<NSString*>*)allow
                           block:(NSArray<NSString*>*)block
                            name:(NSString*)name
                         version:(NSString*)version {
  NSMutableArray<RuleEntry*>* entries = [NSMutableArray array];
  for (NSString* d in (allow ?: @[])) {
    [entries addObject:[RuleEntry allowRuleForDomain:d]];
  }
  for (NSString* d in (block ?: @[])) {
    [entries addObject:[RuleEntry blockRuleForDomain:d]];
  }
  RuleSetMetadata* meta =
      [RuleSetMetadata metadataWithName:(name ?: @"Test Rules") version:(version ?: @"1.0")];
  RuleSet* set = [[RuleSet alloc] initWithRules:entries metadata:meta];
  [set buildIndex];
  return set;
}

@end
