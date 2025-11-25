//
//  PlistRuleParser.m
//  DNShield Network Extension
//
//  Parser for Property List (plist) format rule lists implementation
//

#import "PlistRuleParser.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>

@interface PlistRuleParser ()
@property(nonatomic, strong) NSMutableArray<RuleEntry*>* parsedRules;
@property(nonatomic, strong) RuleSetMetadata* parsedMetadata;
@end

@implementation PlistRuleParser

+ (void)load {
  // Register parser with factory when class is loaded
  [RuleParserFactory registerParserClass:[PlistRuleParser class] forFormat:@"plist"];
}

#pragma mark - Initialization

- (instancetype)init {
  return [self initWithOptions:nil];
}

- (instancetype)initWithOptions:(nullable RuleParserOptions*)options {
  self = [super init];
  if (self) {
    _options = options ?: [RuleParserOptions defaultOptions];
    _parsedRules = [NSMutableArray array];

    // Registration now handled in +load method
  }
  return self;
}

#pragma mark - RuleParser Protocol

- (NSString*)formatIdentifier {
  return @"plist";
}

- (RuleParserCapabilities)capabilities {
  return RuleParserCapabilityMetadata | RuleParserCapabilityValidation |
         RuleParserCapabilityComments | RuleParserCapabilityPriorities |
         RuleParserCapabilityWildcards;
}

- (NSArray<NSString*>*)supportedExtensions {
  return @[ @"plist" ];
}

- (NSArray<NSString*>*)supportedMIMETypes {
  return @[ @"application/x-plist", @"application/plist", @"text/xml" ];
}

- (BOOL)canParseData:(NSData*)data {
  if (data.length == 0) {
    return NO;
  }

  // Try to detect if this is a valid plist
  NSError* error;
  NSPropertyListFormat format;
  id plist = [NSPropertyListSerialization propertyListWithData:data
                                                       options:NSPropertyListImmutable
                                                        format:&format
                                                         error:&error];

  if (!plist || error) {
    return NO;
  }

  // Must be a dictionary at the root
  if (![plist isKindOfClass:[NSDictionary class]]) {
    return NO;
  }

  // Check for minimum required structure
  return [PlistValidation hasRequiredFields:plist];
}

- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error {
  [self reportProgress:0.0];

  if (data.length == 0) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorEmptyData
                              description:@"Empty data provided"];
    }
    return nil;
  }

  // Parse the plist data
  NSPropertyListFormat format;
  NSError* plistError;
  id plist = [NSPropertyListSerialization propertyListWithData:data
                                                       options:NSPropertyListImmutable
                                                        format:&format
                                                         error:&plistError];

  if (!plist) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                              description:@"Failed to parse plist data"
                          underlyingError:plistError];
    }
    return nil;
  }

  // Must be a dictionary
  if (![plist isKindOfClass:[NSDictionary class]]) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                              description:@"Plist root must be a dictionary"];
    }
    return nil;
  }

  [self reportProgress:0.2];

  NSDictionary* plistDict = (NSDictionary*)plist;

  // Validate structure
  NSError* validationError;
  if (![PlistValidation validatePlistStructure:plistDict error:&validationError]) {
    if (error) {
      *error = validationError;
    }
    return nil;
  }

  [self reportProgress:0.3];

  // Clear previous results
  [self.parsedRules removeAllObjects];
  self.parsedMetadata = [[RuleSetMetadata alloc] initWithName:nil
                                                      version:nil
                                                  updatedDate:nil
                                                       author:nil
                                                    sourceURL:nil
                                                  description:nil
                                                      license:nil
                                                 customFields:nil];

  // Extract metadata
  [self extractMetadata:plistDict];
  [self reportProgress:0.4];

  // Parse blocked domains
  if ([self parseBlockedDomainsFromPlist:plistDict error:error] == NO) {
    return nil;
  }
  [self reportProgress:0.7];

  // Parse whitelisted domains
  if ([self parseWhitelistedDomainsFromPlist:plistDict error:error] == NO) {
    return nil;
  }
  [self reportProgress:0.9];

  // Create and return RuleSet
  RuleSet* ruleSet = [[RuleSet alloc] initWithRules:[self.parsedRules copy]
                                           metadata:self.parsedMetadata];

  [self reportProgress:1.0];
  DNSLogInfo(LogCategoryRuleParsing, "Parsed %lu rules from plist format",
             (unsigned long)self.parsedRules.count);

  return ruleSet;
}

#pragma mark - Parsing Helpers

- (void)extractMetadata:(NSDictionary*)plistDict {
  NSString* name = plistDict[@"name"];
  NSString* version = plistDict[@"version"];
  NSString* author = plistDict[@"author"];
  NSString* description = plistDict[@"description"];
  NSString* sourceURL = plistDict[@"source"];
  NSString* license = plistDict[@"license"];

  // Handle date parsing
  NSDate* updatedDate = nil;
  id updatedValue = plistDict[@"updated"];
  if ([updatedValue isKindOfClass:[NSDate class]]) {
    updatedDate = updatedValue;
  } else if ([updatedValue isKindOfClass:[NSString class]]) {
    updatedDate = [self parseDateString:updatedValue];
  }

  // Extract custom metadata
  NSDictionary* customFields = nil;
  NSDictionary* metadata = plistDict[@"metadata"];
  if ([metadata isKindOfClass:[NSDictionary class]]) {
    NSMutableDictionary* customMetadata = [NSMutableDictionary dictionary];
    [metadata enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL* stop) {
      if ([key isKindOfClass:[NSString class]]) {
        customMetadata[key] = obj;
      }
    }];
    customFields = [customMetadata copy];
  }

  // Create metadata object
  self.parsedMetadata = [[RuleSetMetadata alloc] initWithName:name
                                                      version:version
                                                  updatedDate:updatedDate
                                                       author:author
                                                    sourceURL:sourceURL
                                                  description:description
                                                      license:license
                                                 customFields:customFields];
}

- (BOOL)parseBlockedDomainsFromPlist:(NSDictionary*)plistDict error:(NSError**)error {
  NSArray* blocked = plistDict[@"blocked"];
  if (!blocked) {
    return YES;  // Not required
  }

  if (![blocked isKindOfClass:[NSArray class]]) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                              description:@"'blocked' must be an array"];
    }
    return NO;
  }

  return [self parseRulesFromArray:blocked action:RuleActionBlock error:error];
}

- (BOOL)parseWhitelistedDomainsFromPlist:(NSDictionary*)plistDict error:(NSError**)error {
  NSArray* whitelist = plistDict[@"whitelist"];
  if (!whitelist) {
    return YES;  // Not required
  }

  if (![whitelist isKindOfClass:[NSArray class]]) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                              description:@"'whitelist' must be an array"];
    }
    return NO;
  }

  return [self parseRulesFromArray:whitelist action:RuleActionAllow error:error];
}

- (BOOL)parseRulesFromArray:(NSArray*)rules action:(RuleAction)action error:(NSError**)error {
  NSUInteger processedRules = 0;

  for (id ruleEntry in rules) {
    NSString* domain = nil;
    RulePriority priority = self.options.defaultPriority;
    NSString* comment = nil;

    if ([ruleEntry isKindOfClass:[NSString class]]) {
      // Simple string domain
      domain = ruleEntry;
    } else if ([ruleEntry isKindOfClass:[NSDictionary class]]) {
      // Dictionary with additional properties
      NSDictionary* ruleDict = ruleEntry;
      domain = ruleDict[@"domain"];

      if (![domain isKindOfClass:[NSString class]]) {
        if (self.options.strictMode) {
          if (error) {
            *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                                    description:@"Rule entry missing 'domain' field"];
          }
          return NO;
        }
        continue;  // Skip invalid entry
      }

      // Extract priority
      NSNumber* priorityNumber = ruleDict[@"priority"];
      if ([priorityNumber isKindOfClass:[NSNumber class]]) {
        priority = [priorityNumber intValue];
      }

      // Extract comment
      comment = ruleDict[@"comment"];
      if (![comment isKindOfClass:[NSString class]]) {
        comment = nil;
      }
    } else {
      // Invalid rule entry type
      if (self.options.strictMode) {
        if (error) {
          *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                                  description:@"Rule entry must be string or dictionary"];
        }
        return NO;
      }
      continue;  // Skip invalid entry
    }

    // Validate and normalize domain
    if (self.options.validateDomains && ![self isValidDomain:domain]) {
      if (self.options.strictMode) {
        if (error) {
          *error =
              [self parsingErrorWithCode:DNSRuleParserErrorInvalidDomain
                             description:[NSString stringWithFormat:@"Invalid domain: %@", domain]];
        }
        return NO;
      }
      continue;  // Skip invalid domain
    }

    if (self.options.normalizeCase) {
      domain = [self normalizeDomain:domain];
    }

    // Check for duplicates if not allowed
    if (!self.options.allowDuplicates) {
      BOOL isDuplicate = NO;
      for (RuleEntry* existingRule in self.parsedRules) {
        if ([existingRule.domain isEqualToString:domain]) {
          isDuplicate = YES;
          break;
        }
      }
      if (isDuplicate) {
        continue;  // Skip duplicate
      }
    }

    // Create rule entry
    RuleEntry* rule = [[RuleEntry alloc] initWithDomain:domain
                                                 action:action
                                               priority:priority
                                                comment:comment
                                              addedDate:nil
                                                 source:@"plist"];

    [self.parsedRules addObject:rule];

    processedRules++;

    // Check max rule count limit
    if (self.options.maxRuleCount > 0 && self.parsedRules.count >= self.options.maxRuleCount) {
      DNSLogInfo(LogCategoryRuleParsing, "Reached maximum rule count limit: %lu",
                 (unsigned long)self.options.maxRuleCount);
      break;
    }
  }

  return YES;
}

@end

#pragma mark - Plist Validation Implementation

@implementation PlistValidation

+ (BOOL)validatePlistStructure:(id)plist error:(NSError**)error {
  if (![plist isKindOfClass:[NSDictionary class]]) {
    if (error) {
      NSError* validationError =
          [NSError errorWithDomain:DNSRuleParserErrorDomain
                              code:DNSRuleParserErrorInvalidFormat
                          userInfo:@{NSLocalizedDescriptionKey : @"Plist must be a dictionary"}];
      *error = validationError;
    }
    return NO;
  }

  NSDictionary* plistDict = (NSDictionary*)plist;

  // Check for at least one of blocked or whitelist arrays
  if (![self hasRequiredFields:plistDict]) {
    if (error) {
      NSError* validationError = [NSError
          errorWithDomain:DNSRuleParserErrorDomain
                     code:DNSRuleParserErrorInvalidFormat
                 userInfo:@{
                   NSLocalizedDescriptionKey : @"Plist must contain 'blocked' or 'whitelist' array"
                 }];
      *error = validationError;
    }
    return NO;
  }

  return YES;
}

+ (BOOL)hasRequiredFields:(NSDictionary*)plist {
  // Must have at least blocked or whitelist
  NSArray* blocked = plist[@"blocked"];
  NSArray* whitelist = plist[@"whitelist"];

  BOOL hasBlocked = [blocked isKindOfClass:[NSArray class]] && blocked.count > 0;
  BOOL hasWhitelist = [whitelist isKindOfClass:[NSArray class]] && whitelist.count > 0;

  return hasBlocked || hasWhitelist;
}

+ (nullable NSString*)extractVersion:(NSDictionary*)plist {
  id version = plist[@"version"];
  if ([version isKindOfClass:[NSString class]]) {
    return version;
  }
  return nil;
}

+ (NSPropertyListFormat)detectPlistFormat:(NSData*)data {
  if (data.length == 0) {
    return NSPropertyListOpenStepFormat;  // Invalid
  }

  NSPropertyListFormat format;
  NSError* error;
  [NSPropertyListSerialization propertyListWithData:data
                                            options:NSPropertyListImmutable
                                             format:&format
                                              error:&error];

  return error ? NSPropertyListOpenStepFormat : format;
}

@end
