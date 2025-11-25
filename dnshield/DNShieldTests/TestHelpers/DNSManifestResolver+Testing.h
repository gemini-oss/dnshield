//
//  DNSManifestResolver+Testing.h
//  DNShield Tests
//
//  Exposes internal helpers for unit testing.
//

#import "Extension/DNSManifestResolver.h"

@interface DNSManifestResolver (Testing)
- (NSArray<NSString*>*)orderedExtensionsWithDotForIdentifier:(NSString*)identifier;
@end
