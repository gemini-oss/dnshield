//
//  DNSManifest.m
//  DNShield Network Extension
//

#import "DNSManifest.h"
#import <Common/LoggingManager.h>
#import "ConfigurationManager.h"

NSString* const DNSManifestErrorDomain = @"com.dnshield.manifest.error";

#pragma mark - DNS Manifest Metadata

@implementation DNSManifestMetadata

- (instancetype)initWithAuthor:(NSString*)author
                   description:(NSString*)description
                  lastModified:(NSDate*)lastModified
                       version:(NSString*)version
                  customFields:(NSDictionary*)customFields {
  if (self = [super init]) {
    _author = [author copy];
    _manifestDescription = [description copy];
    _lastModified = lastModified;
    _version = [version copy];
    _customFields = [customFields copy];
  }
  return self;
}

- (instancetype)initWithDictionary:(NSDictionary*)dictionary {
  NSString* author = dictionary[@"author"];
  NSString* description = dictionary[@"description"];
  NSString* version = dictionary[@"version"];

  NSDate* lastModified = nil;
  if (dictionary[@"last_modified"]) {
    if ([dictionary[@"last_modified"] isKindOfClass:[NSDate class]]) {
      lastModified = dictionary[@"last_modified"];
    } else if ([dictionary[@"last_modified"] isKindOfClass:[NSString class]]) {
      // Parse ISO 8601 date string
      NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
      formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZ";
      lastModified = [formatter dateFromString:dictionary[@"last_modified"]];
    }
  }

  // Collect any additional fields
  NSMutableDictionary* customFields = [NSMutableDictionary dictionary];
  for (NSString* key in dictionary) {
    if (![key isEqualToString:@"author"] && ![key isEqualToString:@"description"] &&
        ![key isEqualToString:@"last_modified"] && ![key isEqualToString:@"version"]) {
      customFields[key] = dictionary[key];
    }
  }

  return [self initWithAuthor:author
                  description:description
                 lastModified:lastModified
                      version:version
                 customFields:customFields.count > 0 ? customFields : nil];
}

- (NSDictionary*)toDictionary {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  if (_author)
    dict[@"author"] = _author;
  if (_manifestDescription)
    dict[@"description"] = _manifestDescription;
  if (_version)
    dict[@"version"] = _version;

  if (_lastModified) {
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZ";
    dict[@"last_modified"] = [formatter stringFromDate:_lastModified];
  }

  if (_customFields) {
    [dict addEntriesFromDictionary:_customFields];
  }

  return dict;
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:_author forKey:@"author"];
  [coder encodeObject:_manifestDescription forKey:@"description"];
  [coder encodeObject:_lastModified forKey:@"lastModified"];
  [coder encodeObject:_version forKey:@"version"];
  [coder encodeObject:_customFields forKey:@"customFields"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  NSString* author = [coder decodeObjectOfClass:[NSString class] forKey:@"author"];
  NSString* description = [coder decodeObjectOfClass:[NSString class] forKey:@"description"];
  NSDate* lastModified = [coder decodeObjectOfClass:[NSDate class] forKey:@"lastModified"];
  NSString* version = [coder decodeObjectOfClass:[NSString class] forKey:@"version"];
  NSDictionary* customFields = [coder decodeObjectOfClass:[NSDictionary class]
                                                   forKey:@"customFields"];

  return [self initWithAuthor:author
                  description:description
                 lastModified:lastModified
                      version:version
                 customFields:customFields];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  return [[DNSManifestMetadata allocWithZone:zone] initWithAuthor:_author
                                                      description:_manifestDescription
                                                     lastModified:_lastModified
                                                          version:_version
                                                     customFields:_customFields];
}

@end

#pragma mark - DNS Conditional Item

@implementation DNSConditionalItem

- (instancetype)initWithCondition:(NSString*)condition
                     managedRules:(NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules
                      ruleSources:(NSArray<RuleSource*>*)ruleSources
                includedManifests:(NSArray<NSString*>*)includedManifests {
  if (self = [super init]) {
    _condition = [condition copy];
    _managedRules = [managedRules copy];
    _ruleSources = [ruleSources copy];
    _includedManifests = [includedManifests copy];
  }
  return self;
}

- (instancetype)initWithDictionary:(NSDictionary*)dictionary error:(NSError**)error {
  NSString* condition = dictionary[@"condition"];
  if (!condition || ![condition isKindOfClass:[NSString class]]) {
    if (error) {
      *error = [NSError errorWithDomain:DNSManifestErrorDomain
                                   code:DNSManifestErrorMissingRequired
                               userInfo:@{
                                 NSLocalizedDescriptionKey :
                                     @"Conditional item missing required 'condition' field"
                               }];
    }
    return nil;
  }

  // Parse managed rules
  NSDictionary* managedRules = dictionary[@"managed_rules"];

  // Parse rule sources
  NSMutableArray* ruleSources = nil;
  if (dictionary[@"rule_sources"]) {
    ruleSources = [NSMutableArray array];
    for (NSDictionary* sourceDict in dictionary[@"rule_sources"]) {
      RuleSource* source = [RuleSource sourceFromDictionary:sourceDict];
      if (source) {
        [ruleSources addObject:source];
      }
    }
  }

  // Parse included manifests
  NSArray* includedManifests = dictionary[@"included_manifests"];

  return [self initWithCondition:condition
                    managedRules:managedRules
                     ruleSources:ruleSources.count > 0 ? ruleSources : nil
               includedManifests:includedManifests];
}

- (BOOL)validateWithError:(NSError**)error {
  // Validate condition syntax
  if (!_condition || _condition.length == 0) {
    if (error) {
      *error =
          [NSError errorWithDomain:DNSManifestErrorDomain
                              code:DNSManifestErrorInvalidCondition
                          userInfo:@{NSLocalizedDescriptionKey : @"Condition cannot be empty"}];
    }
    return NO;
  }

  // Must have at least one action
  if (!_managedRules && !_ruleSources && !_includedManifests) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorValidationFailed
                 userInfo:@{
                   NSLocalizedDescriptionKey : @"Conditional item must specify at least one action"
                 }];
    }
    return NO;
  }

  return YES;
}

- (NSDictionary*)toDictionary {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  dict[@"condition"] = _condition;

  if (_managedRules) {
    dict[@"managed_rules"] = _managedRules;
  }

  if (_ruleSources) {
    NSMutableArray* sources = [NSMutableArray array];
    for (RuleSource* source in _ruleSources) {
      [sources addObject:[source toDictionary]];
    }
    dict[@"rule_sources"] = sources;
  }

  if (_includedManifests) {
    dict[@"included_manifests"] = _includedManifests;
  }

  return dict;
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:_condition forKey:@"condition"];
  [coder encodeObject:_managedRules forKey:@"managedRules"];
  [coder encodeObject:_ruleSources forKey:@"ruleSources"];
  [coder encodeObject:_includedManifests forKey:@"includedManifests"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  NSString* condition = [coder decodeObjectOfClass:[NSString class] forKey:@"condition"];
  NSDictionary* managedRules = [coder decodeObjectOfClass:[NSDictionary class]
                                                   forKey:@"managedRules"];
  NSArray* ruleSources = [coder decodeObjectOfClass:[NSArray class] forKey:@"ruleSources"];
  NSArray* includedManifests = [coder decodeObjectOfClass:[NSArray class]
                                                   forKey:@"includedManifests"];

  return [self initWithCondition:condition
                    managedRules:managedRules
                     ruleSources:ruleSources
               includedManifests:includedManifests];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  return [[DNSConditionalItem allocWithZone:zone] initWithCondition:_condition
                                                       managedRules:_managedRules
                                                        ruleSources:_ruleSources
                                                  includedManifests:_includedManifests];
}

@end

#pragma mark - DNS Manifest

@implementation DNSManifest

- (instancetype)initWithIdentifier:(NSString*)identifier
                       displayName:(NSString*)displayName
                 includedManifests:(NSArray<NSString*>*)includedManifests
                       ruleSources:(NSArray<RuleSource*>*)ruleSources
                      managedRules:(NSDictionary<NSString*, NSArray<NSString*>*>*)managedRules
                  conditionalItems:(NSArray<DNSConditionalItem*>*)conditionalItems
                          metadata:(DNSManifestMetadata*)metadata {
  if (self = [super init]) {
    _identifier = [identifier copy];
    _displayName = [displayName copy];
    _includedManifests = [includedManifests copy] ?: @[];
    _ruleSources = [ruleSources copy] ?: @[];
    _managedRules = [managedRules copy] ?: @{};
    _conditionalItems = [conditionalItems copy] ?: @[];
    _metadata = metadata;
    _manifestVersion = @"1.0";
  }
  return self;
}

- (instancetype)initWithDictionary:(NSDictionary*)dictionary error:(NSError**)error {
  // Check manifest version
  NSString* version = dictionary[@"manifest_version"];
  if (!version || ![version isEqualToString:@"1.0"]) {
    if (error) {
      *error =
          [NSError errorWithDomain:DNSManifestErrorDomain
                              code:DNSManifestErrorInvalidVersion
                          userInfo:@{NSLocalizedDescriptionKey : @"Unsupported manifest version"}];
    }
    return nil;
  }

  // Extract required fields
  NSString* identifier = dictionary[@"identifier"];
  if (!identifier || ![identifier isKindOfClass:[NSString class]]) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorMissingRequired
                 userInfo:@{NSLocalizedDescriptionKey : @"Missing required 'identifier' field"}];
    }
    return nil;
  }

  // Extract optional fields
  NSString* displayName = dictionary[@"display_name"];
  NSArray* includedManifests = dictionary[@"included_manifests"];
  NSDictionary* managedRules = dictionary[@"managed_rules"];

  // Parse rule sources
  NSMutableArray* ruleSources = [NSMutableArray array];
  if (dictionary[@"rule_sources"]) {
    for (NSDictionary* sourceDict in dictionary[@"rule_sources"]) {
      RuleSource* source = [RuleSource sourceFromDictionary:sourceDict];
      if (source) {
        [ruleSources addObject:source];
      } else {
        [[LoggingManager sharedManager] logEvent:@"RuleSourceParseError"
                                        category:LogCategoryRuleParsing
                                           level:LogLevelError
                                      attributes:@{@"source" : sourceDict}];
      }
    }
  }

  // Parse conditional items
  NSMutableArray* conditionalItems = [NSMutableArray array];
  if (dictionary[@"conditional_items"]) {
    for (NSDictionary* itemDict in dictionary[@"conditional_items"]) {
      NSError* itemError = nil;
      DNSConditionalItem* item = [[DNSConditionalItem alloc] initWithDictionary:itemDict
                                                                          error:&itemError];
      if (item) {
        [conditionalItems addObject:item];
      } else {
        [[LoggingManager sharedManager] logError:itemError
                                        category:LogCategoryRuleParsing
                                         context:@"Failed to parse conditional item"];
      }
    }
  }

  // Parse metadata
  DNSManifestMetadata* metadata = nil;
  if (dictionary[@"metadata"]) {
    metadata = [[DNSManifestMetadata alloc] initWithDictionary:dictionary[@"metadata"]];
  }

  self = [self initWithIdentifier:identifier
                      displayName:displayName
                includedManifests:includedManifests
                      ruleSources:ruleSources
                     managedRules:managedRules
                 conditionalItems:conditionalItems
                         metadata:metadata];

  if (self) {
    _manifestVersion = version;
  }

  return self;
}

- (BOOL)validateWithError:(NSError**)error {
  // Validate identifier
  if (!_identifier || _identifier.length == 0) {
    if (error) {
      *error = [NSError
          errorWithDomain:DNSManifestErrorDomain
                     code:DNSManifestErrorMissingRequired
                 userInfo:@{NSLocalizedDescriptionKey : @"Manifest identifier cannot be empty"}];
    }
    return NO;
  }

  // Validate rule sources
  for (RuleSource* source in _ruleSources) {
    NSError* sourceError = nil;
    if (![source isValid:&sourceError]) {
      if (error) {
        *error = sourceError;
      }
      return NO;
    }
  }

  // Validate conditional items
  for (DNSConditionalItem* item in _conditionalItems) {
    NSError* itemError = nil;
    if (![item validateWithError:&itemError]) {
      if (error) {
        *error = itemError;
      }
      return NO;
    }
  }

  return YES;
}

- (NSDictionary*)toDictionary {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  dict[@"manifest_version"] = _manifestVersion;
  dict[@"identifier"] = _identifier;

  if (_displayName) {
    dict[@"display_name"] = _displayName;
  }

  if (_includedManifests.count > 0) {
    dict[@"included_manifests"] = _includedManifests;
  }

  if (_ruleSources.count > 0) {
    NSMutableArray* sources = [NSMutableArray array];
    for (RuleSource* source in _ruleSources) {
      [sources addObject:[source toDictionary]];
    }
    dict[@"rule_sources"] = sources;
  }

  if (_managedRules.count > 0) {
    dict[@"managed_rules"] = _managedRules;
  }

  if (_conditionalItems.count > 0) {
    NSMutableArray* items = [NSMutableArray array];
    for (DNSConditionalItem* item in _conditionalItems) {
      [items addObject:[item toDictionary]];
    }
    dict[@"conditional_items"] = items;
  }

  if (_metadata) {
    dict[@"metadata"] = [_metadata toDictionary];
  }

  return dict;
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:_identifier forKey:@"identifier"];
  [coder encodeObject:_displayName forKey:@"displayName"];
  [coder encodeObject:_manifestVersion forKey:@"manifestVersion"];
  [coder encodeObject:_includedManifests forKey:@"includedManifests"];
  [coder encodeObject:_ruleSources forKey:@"ruleSources"];
  [coder encodeObject:_managedRules forKey:@"managedRules"];
  [coder encodeObject:_conditionalItems forKey:@"conditionalItems"];
  [coder encodeObject:_metadata forKey:@"metadata"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  NSString* identifier = [coder decodeObjectOfClass:[NSString class] forKey:@"identifier"];
  NSString* displayName = [coder decodeObjectOfClass:[NSString class] forKey:@"displayName"];
  NSArray* includedManifests = [coder decodeObjectOfClass:[NSArray class]
                                                   forKey:@"includedManifests"];
  NSArray* ruleSources = [coder decodeObjectOfClass:[NSArray class] forKey:@"ruleSources"];
  NSDictionary* managedRules = [coder decodeObjectOfClass:[NSDictionary class]
                                                   forKey:@"managedRules"];
  NSArray* conditionalItems = [coder decodeObjectOfClass:[NSArray class]
                                                  forKey:@"conditionalItems"];
  DNSManifestMetadata* metadata = [coder decodeObjectOfClass:[DNSManifestMetadata class]
                                                      forKey:@"metadata"];

  self = [self initWithIdentifier:identifier
                      displayName:displayName
                includedManifests:includedManifests
                      ruleSources:ruleSources
                     managedRules:managedRules
                 conditionalItems:conditionalItems
                         metadata:metadata];

  if (self) {
    _manifestVersion = [coder decodeObjectOfClass:[NSString class] forKey:@"manifestVersion"];
  }

  return self;
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  DNSManifest* copy = [[DNSManifest allocWithZone:zone] initWithIdentifier:_identifier
                                                               displayName:_displayName
                                                         includedManifests:_includedManifests
                                                               ruleSources:_ruleSources
                                                              managedRules:_managedRules
                                                          conditionalItems:_conditionalItems
                                                                  metadata:_metadata];
  copy->_manifestVersion = _manifestVersion;
  return copy;
}

@end

#pragma mark - DNS Resolved Manifest

@interface DNSResolvedManifest ()
@property(nonatomic, strong, readwrite) DNSManifest* primaryManifest;
@property(nonatomic, strong, readwrite) NSArray<DNSManifest*>* manifestChain;
@property(nonatomic, strong, readwrite) NSArray<RuleSource*>* resolvedRuleSources;
@property(nonatomic, strong, readwrite)
    NSDictionary<NSString*, NSArray<NSString*>*>* resolvedManagedRules;
@property(nonatomic, strong, readwrite) NSDate* resolvedAt;
@property(nonatomic, strong, readwrite) NSArray<NSError*>* warnings;
@end

@implementation DNSResolvedManifest

- (instancetype)init {
  if (self = [super init]) {
    _resolvedAt = [NSDate date];
    _warnings = @[];
  }
  return self;
}

@end
