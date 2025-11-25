//
//  DNSManifestParser.m
//  DNShield Network Extension
//

#import "DNSManifestParser.h"
#import <Common/LoggingManager.h>
#import "DNSManifest.h"
#import "YAMLRuleParser.h"

@implementation DNSManifestParser

#pragma mark - Parsing

+ (DNSManifest*)parseManifestFromData:(NSData*)data
                               format:(DNSManifestFormat)format
                                error:(NSError**)error {
  if (!data || data.length == 0) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorInvalidFormat
                               userInfo:@{NSLocalizedDescriptionKey : @"Empty manifest data"}];
    }
    return nil;
  }

  NSDictionary* dictionary = nil;

  switch (format) {
    case DNSManifestFormatJSON: dictionary = [self parseJSONData:data error:error]; break;

    case DNSManifestFormatYAML: dictionary = [self parseYAMLData:data error:error]; break;

    case DNSManifestFormatPlist: dictionary = [self parsePlistData:data error:error]; break;

    case DNSManifestFormatUnknown: {
      // Try to auto-detect
      DNSManifest* autoDetectedManifest = [self parseManifestFromData:data error:error];
      return autoDetectedManifest;
    }

    default:
      if (error) {
        *error =
            [NSError errorWithDomain:DNSManifestErrorDomain
                                code:DNSManifestErrorInvalidFormat
                            userInfo:@{NSLocalizedDescriptionKey : @"Unsupported manifest format"}];
      }
      return nil;
  }

  if (!dictionary) {
    return nil;
  }

  DNSManifest* manifest = [[DNSManifest alloc] initWithDictionary:dictionary error:error];

  if (manifest) {
    NSError* validationError = nil;
    if (![manifest validateWithError:&validationError]) {
      [[LoggingManager sharedManager] logError:validationError
                                      category:LogCategoryRuleParsing
                                       context:@"Manifest validation failed"];
      if (error) {
        *error = validationError;
      }
      return nil;
    }
  }

  return manifest;
}

+ (DNSManifest*)parseManifestFromFile:(NSString*)filePath error:(NSError**)error {
  if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorManifestNotFound
                               userInfo:@{NSLocalizedDescriptionKey : @"Manifest file not found"}];
    }
    return nil;
  }

  NSData* data = [NSData dataWithContentsOfFile:filePath options:0 error:error];
  if (!data) {
    return nil;
  }

  DNSManifestFormat format = [self detectFormatFromFile:filePath];
  if (format == DNSManifestFormatUnknown) {
    format = [self detectFormatFromData:data];
  }

  return [self parseManifestFromData:data format:format error:error];
}

+ (DNSManifest*)parseManifestFromData:(NSData*)data error:(NSError**)error {
  DNSManifestFormat format = [self detectFormatFromData:data];
  return [self parseManifestFromData:data format:format error:error];
}

#pragma mark - Format Detection

+ (DNSManifestFormat)detectFormatFromFile:(NSString*)filePath {
  NSString* extension = [filePath pathExtension].lowercaseString;

  if ([extension isEqualToString:@"json"]) {
    return DNSManifestFormatJSON;
  } else if ([extension isEqualToString:@"yaml"] || [extension isEqualToString:@"yml"]) {
    return DNSManifestFormatYAML;
  } else if ([extension isEqualToString:@"plist"]) {
    return DNSManifestFormatPlist;
  }

  return DNSManifestFormatUnknown;
}

+ (DNSManifestFormat)detectFormatFromData:(NSData*)data {
  if (!data || data.length == 0) {
    return DNSManifestFormatUnknown;
  }

  // Try JSON first
  NSError* jsonError = nil;
  id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
  if (jsonObject && [jsonObject isKindOfClass:[NSDictionary class]]) {
    return DNSManifestFormatJSON;
  }

  // Try Plist
  NSError* plistError = nil;
  NSPropertyListFormat format;
  id plistObject = [NSPropertyListSerialization propertyListWithData:data
                                                             options:NSPropertyListImmutable
                                                              format:&format
                                                               error:&plistError];
  if (plistObject && [plistObject isKindOfClass:[NSDictionary class]]) {
    return DNSManifestFormatPlist;
  }

  // Try YAML by checking for YAML-like content
  NSString* stringContent = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (stringContent && ([stringContent hasPrefix:@"---"] || [stringContent containsString:@":\n"] ||
                        [stringContent containsString:@": "])) {
    return DNSManifestFormatYAML;
  }

  return DNSManifestFormatUnknown;
}

#pragma mark - Format-Specific Parsing

+ (NSDictionary*)parseJSONData:(NSData*)data error:(NSError**)error {
  NSError* jsonError = nil;
  id jsonObject = [NSJSONSerialization JSONObjectWithData:data
                                                  options:NSJSONReadingMutableContainers
                                                    error:&jsonError];

  if (jsonError) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorInvalidFormat
                               userInfo:@{
                                 NSLocalizedDescriptionKey : @"Invalid JSON format",
                                 NSUnderlyingErrorKey : jsonError
                               }];
    }
    return nil;
  }

  if (![jsonObject isKindOfClass:[NSDictionary class]]) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorInvalidFormat
                 userInfo:@{NSLocalizedDescriptionKey : @"Manifest must be a JSON object"}];
    }
    return nil;
  }

  return jsonObject;
}

+ (NSDictionary*)parseYAMLData:(NSData*)data error:(NSError**)error {
  // Use the existing YAML parser functionality
  NSString* yamlString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (!yamlString) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorInvalidFormat
                               userInfo:@{NSLocalizedDescriptionKey : @"Invalid YAML encoding"}];
    }
    return nil;
  }

  // Parse YAML using simple parser (we'll need to enhance this)
  return [self parseSimpleYAML:yamlString error:error];
}

+ (NSDictionary*)parsePlistData:(NSData*)data error:(NSError**)error {
  NSError* plistError = nil;
  NSPropertyListFormat format;
  id plistObject = [NSPropertyListSerialization propertyListWithData:data
                                                             options:NSPropertyListImmutable
                                                              format:&format
                                                               error:&plistError];

  if (plistError) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorInvalidFormat
                               userInfo:@{
                                 NSLocalizedDescriptionKey : @"Invalid Plist format",
                                 NSUnderlyingErrorKey : plistError
                               }];
    }
    return nil;
  }

  if (![plistObject isKindOfClass:[NSDictionary class]]) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorInvalidFormat
                 userInfo:@{NSLocalizedDescriptionKey : @"Manifest must be a Plist dictionary"}];
    }
    return nil;
  }

  return plistObject;
}

+ (NSDictionary*)parseSimpleYAML:(NSString*)yamlString error:(NSError**)error {
  // This is a simplified YAML parser for manifest files
  // In production, we'd use a proper YAML library

  NSMutableDictionary* result = [NSMutableDictionary dictionary];
  NSArray* lines = [yamlString componentsSeparatedByString:@"\n"];

  NSString* currentKey = nil;
  NSMutableArray* currentArray = nil;
  NSMutableDictionary* currentDict = nil;
  NSInteger indentLevel = 0;

  for (NSString* line in lines) {
    NSString* trimmedLine =
        [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

    // Skip empty lines and comments
    if (trimmedLine.length == 0 || [trimmedLine hasPrefix:@"#"]) {
      continue;
    }

    // Document start marker
    if ([trimmedLine isEqualToString:@"---"]) {
      continue;
    }

    // Calculate indent level
    NSInteger currentIndent = 0;
    for (NSInteger i = 0; i < line.length; i++) {
      if ([line characterAtIndex:i] == ' ') {
        currentIndent++;
      } else {
        break;
      }
    }

    // Array item
    if ([trimmedLine hasPrefix:@"- "]) {
      NSString* value = [trimmedLine substringFromIndex:2];
      value = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

      if (currentKey && currentIndent > indentLevel) {
        if (!currentArray) {
          currentArray = [NSMutableArray array];
          result[currentKey] = currentArray;
        }
        [currentArray addObject:value];
      }
    }
    // Key-value pair
    else if ([trimmedLine containsString:@": "]) {
      NSArray* parts = [trimmedLine componentsSeparatedByString:@": "];
      if (parts.count >= 2) {
        NSString* key = parts[0];
        NSString* value = [[parts subarrayWithRange:NSMakeRange(1, parts.count - 1)]
            componentsJoinedByString:@": "];

        // Remove quotes if present
        if ([value hasPrefix:@"\""] && [value hasSuffix:@"\""]) {
          value = [value substringWithRange:NSMakeRange(1, value.length - 2)];
        }

        if (currentIndent == 0) {
          currentKey = key;
          currentArray = nil;
          indentLevel = 0;

          if (value.length > 0) {
            result[key] = value;
          }
        } else if (currentDict) {
          currentDict[key] = value;
        }
      }
    }
  }

  return result;
}

#pragma mark - Validation

+ (BOOL)validateManifestData:(NSData*)data format:(DNSManifestFormat)format error:(NSError**)error {
  DNSManifest* manifest = [self parseManifestFromData:data format:format error:error];
  return manifest != nil;
}

#pragma mark - Export

+ (NSData*)dataFromManifest:(DNSManifest*)manifest
                     format:(DNSManifestFormat)format
                      error:(NSError**)error {
  if (!manifest) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorInvalidFormat
                               userInfo:@{NSLocalizedDescriptionKey : @"Nil manifest"}];
    }
    return nil;
  }

  NSDictionary* dictionary = [manifest toDictionary];

  switch (format) {
    case DNSManifestFormatJSON:
      return [NSJSONSerialization dataWithJSONObject:dictionary
                                             options:NSJSONWritingPrettyPrinted
                                               error:error];

    case DNSManifestFormatYAML: return [self exportToYAML:dictionary error:error];

    case DNSManifestFormatPlist: return [self exportToPlist:dictionary error:error];

    default:
      if (error) {
        *error =
            [NSError errorWithDomain:DNSManifestErrorDomain
                                code:DNSManifestErrorInvalidFormat
                            userInfo:@{NSLocalizedDescriptionKey : @"Unsupported export format"}];
      }
      return nil;
  }
}

+ (BOOL)writeManifest:(DNSManifest*)manifest
               toFile:(NSString*)filePath
               format:(DNSManifestFormat)format
                error:(NSError**)error {
  NSData* data = [self dataFromManifest:manifest format:format error:error];
  if (!data) {
    return NO;
  }

  return [data writeToFile:filePath options:NSDataWritingAtomic error:error];
}

+ (NSData*)exportToYAML:(NSDictionary*)dictionary error:(NSError**)error {
  // Simple YAML export
  NSMutableString* yaml = [NSMutableString stringWithString:@"---\n"];

  // Add manifest version first
  if (dictionary[@"manifest_version"]) {
    [yaml appendFormat:@"manifest_version: \"%@\"\n", dictionary[@"manifest_version"]];
  }

  // Add other top-level keys
  for (NSString* key in dictionary) {
    if ([key isEqualToString:@"manifest_version"])
      continue;

    id value = dictionary[key];

    if ([value isKindOfClass:[NSString class]]) {
      [yaml appendFormat:@"%@: \"%@\"\n", key, value];
    } else if ([value isKindOfClass:[NSNumber class]]) {
      [yaml appendFormat:@"%@: %@\n", key, value];
    } else if ([value isKindOfClass:[NSArray class]]) {
      [yaml appendFormat:@"%@:\n", key];
      for (id item in value) {
        if ([item isKindOfClass:[NSString class]]) {
          [yaml appendFormat:@"  - \"%@\"\n", item];
        } else if ([item isKindOfClass:[NSDictionary class]]) {
          // Handle nested dictionaries in arrays
          [yaml appendString:@"  - "];
          BOOL first = YES;
          for (NSString* subKey in item) {
            if (first) {
              [yaml appendFormat:@"%@: \"%@\"\n", subKey, item[subKey]];
              first = NO;
            } else {
              [yaml appendFormat:@"    %@: \"%@\"\n", subKey, item[subKey]];
            }
          }
        }
      }
    } else if ([value isKindOfClass:[NSDictionary class]]) {
      [yaml appendFormat:@"%@:\n", key];
      for (NSString* subKey in value) {
        id subValue = value[subKey];
        if ([subValue isKindOfClass:[NSString class]]) {
          [yaml appendFormat:@"  %@: \"%@\"\n", subKey, subValue];
        } else if ([subValue isKindOfClass:[NSArray class]]) {
          [yaml appendFormat:@"  %@:\n", subKey];
          for (NSString* item in subValue) {
            [yaml appendFormat:@"    - \"%@\"\n", item];
          }
        }
      }
    }
  }

  return [yaml dataUsingEncoding:NSUTF8StringEncoding];
}

+ (NSData*)exportToPlist:(NSDictionary*)dictionary error:(NSError**)error {
  // Export to XML Plist format
  NSError* plistError = nil;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:dictionary
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&plistError];

  if (plistError) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorInvalidFormat
                               userInfo:@{
                                 NSLocalizedDescriptionKey : @"Failed to export to Plist format",
                                 NSUnderlyingErrorKey : plistError
                               }];
    }
    return nil;
  }

  return plistData;
}

@end
