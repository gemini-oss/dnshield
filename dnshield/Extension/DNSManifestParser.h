//
//  DNSManifestParser.h
//  DNShield Network Extension
//
//  Parser for DNS manifest files in YAML, JSON, and Plist formats
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class DNSManifest;

typedef NS_ENUM(NSInteger, DNSManifestFormat) {
  DNSManifestFormatUnknown = 0,
  DNSManifestFormatJSON,
  DNSManifestFormatYAML,
  DNSManifestFormatPlist
};

@interface DNSManifestParser : NSObject

// Parse manifest from data
+ (nullable DNSManifest*)parseManifestFromData:(NSData*)data
                                        format:(DNSManifestFormat)format
                                         error:(NSError**)error;

// Parse manifest from file
+ (nullable DNSManifest*)parseManifestFromFile:(NSString*)filePath error:(NSError**)error;

// Auto-detect format and parse
+ (nullable DNSManifest*)parseManifestFromData:(NSData*)data error:(NSError**)error;

// Validate manifest data without fully parsing
+ (BOOL)validateManifestData:(NSData*)data format:(DNSManifestFormat)format error:(NSError**)error;

// Export manifest to data
+ (nullable NSData*)dataFromManifest:(DNSManifest*)manifest
                              format:(DNSManifestFormat)format
                               error:(NSError**)error;

// Write manifest to file
+ (BOOL)writeManifest:(DNSManifest*)manifest
               toFile:(NSString*)filePath
               format:(DNSManifestFormat)format
                error:(NSError**)error;

// Detect format from file extension or content
+ (DNSManifestFormat)detectFormatFromFile:(NSString*)filePath;
+ (DNSManifestFormat)detectFormatFromData:(NSData*)data;

@end

NS_ASSUME_NONNULL_END
