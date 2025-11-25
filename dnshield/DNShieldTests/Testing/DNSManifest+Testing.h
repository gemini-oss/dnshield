//
//  DNSManifest+Testing.h
//  DNShield Tests
//

#import "DNSManifest.h"

NS_ASSUME_NONNULL_BEGIN

@interface DNSManifest (Testing)

+ (DNSManifestMetadata*)dns_metadataWithAuthor:(nullable NSString*)author
                                       version:(nullable NSString*)version;

+ (NSDictionary<NSString*, NSArray<NSString*>*>*)
    dns_rulesWithAllow:(nullable NSArray<NSString*>*)allow
                 block:(nullable NSArray<NSString*>*)block;

+ (DNSManifest*)dns_manifestWithIdentifier:(NSString*)identifier
                               displayName:(nullable NSString*)displayName
                                     allow:(nullable NSArray<NSString*>*)allow
                                     block:(nullable NSArray<NSString*>*)block;

+ (DNSManifest*)dns_manifestWithIdentifier:(NSString*)identifier
                              managedRules:
                                  (NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules
                                  metadata:(DNSManifestMetadata*)metadata;

@end

NS_ASSUME_NONNULL_END
