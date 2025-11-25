//
//  DNSManifest+Testing.m
//  DNShield Tests
//

#import "DNSManifest+Testing.h"

@implementation DNSManifest (Testing)

+ (DNSManifestMetadata*)dns_metadataWithAuthor:(NSString*)author version:(NSString*)version {
  return [[DNSManifestMetadata alloc] initWithAuthor:author
                                         description:@"Test manifest"
                                        lastModified:[NSDate date]
                                             version:version
                                        customFields:nil];
}

+ (NSDictionary<NSString*, NSArray<NSString*>*>*)dns_rulesWithAllow:(NSArray<NSString*>*)allow
                                                              block:(NSArray<NSString*>*)block {
  NSMutableDictionary* rules = [NSMutableDictionary dictionary];
  if (allow)
    rules[@"allow"] = allow;
  if (block)
    rules[@"block"] = block;
  return [rules copy];
}

+ (DNSManifest*)dns_manifestWithIdentifier:(NSString*)identifier
                               displayName:(NSString*)displayName
                                     allow:(NSArray<NSString*>*)allow
                                     block:(NSArray<NSString*>*)block {
  DNSManifestMetadata* metadata = [self dns_metadataWithAuthor:@"Test" version:@"1.0"];
  NSDictionary* rules = [self dns_rulesWithAllow:allow block:block];
  return [[DNSManifest alloc] initWithIdentifier:identifier
                                     displayName:displayName
                               includedManifests:@[]
                                     ruleSources:@[]
                                    managedRules:rules
                                conditionalItems:@[]
                                        metadata:metadata];
}

+ (DNSManifest*)dns_manifestWithIdentifier:(NSString*)identifier
                              managedRules:
                                  (NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules
                                  metadata:(DNSManifestMetadata*)metadata {
  return [[DNSManifest alloc] initWithIdentifier:identifier
                                     displayName:nil
                               includedManifests:@[]
                                     ruleSources:@[]
                                    managedRules:managedRules
                                conditionalItems:@[]
                                        metadata:metadata];
}

@end
