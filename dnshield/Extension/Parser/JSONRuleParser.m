//
//  JSONRuleParser.m
//  DNShield Network Extension
//
//  Parser for JSON format rule lists implementation
//

#import "JSONRuleParser.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>

@interface JSONRuleParser ()
@property(nonatomic, strong) NSMutableArray<RuleEntry*>* parsedRules;
@property(nonatomic, strong) RuleSetMetadata* parsedMetadata;
@end

@implementation JSONRuleParser

+ (void)load {
  // Register parser with factory when class is loaded
  [RuleParserFactory registerParserClass:[JSONRuleParser class] forFormat:@"json"];
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
  return @"json";
}

- (RuleParserCapabilities)capabilities {
  return RuleParserCapabilityMetadata | RuleParserCapabilityValidation |
         RuleParserCapabilityComments | RuleParserCapabilityPriorities |
         RuleParserCapabilityWildcards;
}

- (NSArray<NSString*>*)supportedExtensions {
  return @[ @"json", @"jsonl" ];
}

- (NSArray<NSString*>*)supportedMIMETypes {
  return @[ @"application/json", @"text/json", @"application/x-json" ];
}

#pragma mark - Parsing

- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error {
  DNSLogPerformanceStart(@"JSONRuleParser.parseData");

  // Reset state
  [self.parsedRules removeAllObjects];
  self.parsedMetadata = nil;

  // Validate data
  if (!data || data.length == 0) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorEmptyData
                              description:@"Empty data provided"];
    }
    DNSLogPerformanceEnd(@"JSONRuleParser.parseData");
    return nil;
  }

  // Parse JSON
  NSError* jsonError = nil;
  id jsonObject = [NSJSONSerialization JSONObjectWithData:data
                                                  options:NSJSONReadingAllowFragments
                                                    error:&jsonError];

  if (!jsonObject) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorSyntaxError
                              description:@"Invalid JSON format"
                          underlyingError:jsonError];
    }
    DNSLogError(LogCategoryRuleParsing, "JSON parsing failed: %@", jsonError.localizedDescription);
    DNSLogPerformanceEnd(@"JSONRuleParser.parseData");
    return nil;
  }

  // Handle different JSON structures
  RuleSet* ruleSet = nil;

  if ([jsonObject isKindOfClass:[NSDictionary class]]) {
    // Standard format with metadata
    ruleSet = [self parseJSONDictionary:jsonObject error:error];
  } else if ([jsonObject isKindOfClass:[NSArray class]]) {
    // Simple array format (assume all are blocked domains)
    ruleSet = [self parseJSONArray:jsonObject error:error];
  } else {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                              description:@"JSON must be an object or array"];
    }
    DNSLogPerformanceEnd(@"JSONRuleParser.parseData");
    return nil;
  }

  DNSLogPerformanceEnd(@"JSONRuleParser.parseData");

  if (ruleSet) {
    DNSLogInfo(LogCategoryRuleParsing, "Successfully parsed JSON with %lu rules",
               (unsigned long)ruleSet.rules.count);

    // Build index if requested
    if (self.options.buildIndexWhileParsing) {
      [ruleSet buildIndex];
    }
  }

  return ruleSet;
}

#pragma mark - JSON Parsing Helpers

- (nullable RuleSet*)parseJSONDictionary:(NSDictionary*)json error:(NSError**)error {
  // Validate structure
  if (![JSONRuleSchema validateJSONStructure:json error:error]) {
    return nil;
  }

  // Extract metadata
  self.parsedMetadata = [self extractMetadataFromJSON:json];

  // Parse blocked domains
  NSArray* blocked = json[@"blocked"];
  if ([blocked isKindOfClass:[NSArray class]]) {
    [self parseRuleArray:blocked action:RuleActionBlock];
  }

  // Parse whitelisted domains
  NSArray* whitelist = json[@"whitelist"] ?: json[@"allowlist"] ?: json[@"allowed"];
  if ([whitelist isKindOfClass:[NSArray class]]) {
    [self parseRuleArray:whitelist action:RuleActionAllow];
  }

  // Report progress
  [self reportProgress:1.0];

  // Create rule set
  if (self.parsedRules.count == 0 && !self.options.strictMode) {
    DNSLogInfo(LogCategoryRuleParsing, "No rules found in JSON");
  }

  return [[RuleSet alloc] initWithRules:[self.parsedRules copy] metadata:self.parsedMetadata];
}

- (nullable RuleSet*)parseJSONArray:(NSArray*)jsonArray error:(NSError**)error {
  // Simple array format - treat all as blocked domains
  [self parseRuleArray:jsonArray action:RuleActionBlock];

  // Create minimal metadata
  RuleSetMetadata* metadata = [RuleSetMetadata metadataWithName:@"JSON Rules" version:@"1.0"];

  return [[RuleSet alloc] initWithRules:[self.parsedRules copy] metadata:metadata];
}

- (void)parseRuleArray:(NSArray*)array action:(RuleAction)action {
  NSUInteger totalCount = array.count;
  NSUInteger processedCount = 0;

  for (id item in array) {
    @autoreleasepool {
      RuleEntry* rule = nil;

      if ([item isKindOfClass:[NSString class]]) {
        // Simple string format
        rule = [self parseStringRule:item action:action];
      } else if ([item isKindOfClass:[NSDictionary class]]) {
        // Extended format with metadata
        rule = [self parseDictionaryRule:item action:action];
      } else {
        DNSLogDebug(LogCategoryRuleParsing, "Skipping invalid rule type: %@",
                    NSStringFromClass([item class]));
      }

      if (rule) {
        // Check for duplicates if not allowed
        if (!self.options.allowDuplicates) {
          BOOL isDuplicate = NO;
          for (RuleEntry* existingRule in self.parsedRules) {
            if ([existingRule.domain isEqualToString:rule.domain] &&
                existingRule.action == rule.action) {
              isDuplicate = YES;
              break;
            }
          }

          if (!isDuplicate) {
            [self.parsedRules addObject:rule];
          }
        } else {
          [self.parsedRules addObject:rule];
        }
      }

      // Report progress periodically
      processedCount++;
      if (processedCount % self.options.batchSize == 0) {
        [self reportProgress:(double)processedCount / totalCount];
      }

      // Check max rule count
      if (self.options.maxRuleCount > 0 && self.parsedRules.count >= self.options.maxRuleCount) {
        DNSLogInfo(LogCategoryRuleParsing, "Reached max rule count: %lu",
                   (unsigned long)self.options.maxRuleCount);
        break;
      }
    }
  }
}

- (nullable RuleEntry*)parseStringRule:(NSString*)domain action:(RuleAction)action {
  // Normalize domain
  NSString* normalizedDomain = domain;
  if (self.options.normalizeCase) {
    normalizedDomain = [self normalizeDomain:domain];
  }

  // Validate domain
  if (self.options.validateDomains && ![self isValidDomain:normalizedDomain]) {
    if (self.options.strictMode) {
      DNSLogError(LogCategoryRuleParsing, "Invalid domain: %@", domain);
      return nil;
    } else {
      DNSLogDebug(LogCategoryRuleParsing, "Skipping invalid domain: %@", domain);
      return nil;
    }
  }

  return [[RuleEntry alloc] initWithDomain:normalizedDomain
                                    action:action
                                  priority:self.options.defaultPriority
                                   comment:nil
                                 addedDate:nil
                                    source:self.parsedMetadata.sourceURL];
}

- (nullable RuleEntry*)parseDictionaryRule:(NSDictionary*)dict action:(RuleAction)action {
  NSString* domain = dict[@"domain"];
  if (![domain isKindOfClass:[NSString class]]) {
    DNSLogDebug(LogCategoryRuleParsing, "Rule dictionary missing domain field");
    return nil;
  }

  // Normalize domain
  if (self.options.normalizeCase) {
    domain = [self normalizeDomain:domain];
  }

  // Validate domain
  if (self.options.validateDomains && ![self isValidDomain:domain]) {
    if (self.options.strictMode) {
      DNSLogError(LogCategoryRuleParsing, "Invalid domain in rule: %@", domain);
      return nil;
    } else {
      DNSLogDebug(LogCategoryRuleParsing, "Skipping invalid domain: %@", domain);
      return nil;
    }
  }

  // Extract optional fields
  NSNumber* priorityNum = dict[@"priority"];
  RulePriority priority = priorityNum ? priorityNum.integerValue : self.options.defaultPriority;

  NSString* comment = dict[@"comment"];
  if (![comment isKindOfClass:[NSString class]]) {
    comment = nil;
  }

  NSDate* addedDate = nil;
  id dateValue = dict[@"added"] ?: dict[@"date"];
  if ([dateValue isKindOfClass:[NSString class]]) {
    addedDate = [self parseDateString:dateValue];
  } else if ([dateValue isKindOfClass:[NSNumber class]]) {
    addedDate = [NSDate dateWithTimeIntervalSince1970:[dateValue doubleValue]];
  }

  NSString* source = dict[@"source"];
  if (![source isKindOfClass:[NSString class]]) {
    source = self.parsedMetadata.sourceURL;
  }

  // Override action if specified
  NSString* actionStr = dict[@"action"];
  if ([actionStr isKindOfClass:[NSString class]]) {
    if ([actionStr isEqualToString:@"block"]) {
      action = RuleActionBlock;
    } else if ([actionStr isEqualToString:@"allow"]) {
      action = RuleActionAllow;
    }
  }

  return [[RuleEntry alloc] initWithDomain:domain
                                    action:action
                                  priority:priority
                                   comment:comment
                                 addedDate:addedDate
                                    source:source];
}

#pragma mark - Metadata Extraction

- (RuleSetMetadata*)extractMetadataFromJSON:(NSDictionary*)json {
  NSString* name = json[@"name"];
  NSString* version = json[@"version"] ?: [JSONRuleSchema extractVersion:json];

  NSDate* updatedDate = nil;
  id updated = json[@"updated"] ?: json[@"lastUpdated"] ?: json[@"modified"];
  if ([updated isKindOfClass:[NSString class]]) {
    updatedDate = [self parseDateString:updated];
  } else if ([updated isKindOfClass:[NSNumber class]]) {
    updatedDate = [NSDate dateWithTimeIntervalSince1970:[updated doubleValue]];
  }

  NSString* author = json[@"author"] ?: json[@"maintainer"];
  NSString* sourceURL = json[@"source"] ?: json[@"url"] ?: json[@"homepage"];
  NSString* description = json[@"description"];
  NSString* license = json[@"license"];

  NSDictionary* customFields = json[@"metadata"];
  if (![customFields isKindOfClass:[NSDictionary class]]) {
    customFields = nil;
  }

  return [[RuleSetMetadata alloc] initWithName:name
                                       version:version
                                   updatedDate:updatedDate
                                        author:author
                                     sourceURL:sourceURL
                                   description:description
                                       license:license
                                  customFields:customFields];
}

@end

#pragma mark - JSON Schema Validation

@implementation JSONRuleSchema

+ (BOOL)validateJSONStructure:(NSDictionary*)json error:(NSError**)error {
  // Check for at least one rule array
  if (![self hasRequiredFields:json]) {
    if (error) {
      *error = DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorMissingRequiredField,
                            @"JSON must contain 'blocked' or 'whitelist' array");
    }
    return NO;
  }

  // Validate array types
  id blocked = json[@"blocked"];
  if (blocked && ![blocked isKindOfClass:[NSArray class]]) {
    if (error) {
      *error = DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorInvalidFormat,
                            @"'blocked' must be an array");
    }
    return NO;
  }

  id whitelist = json[@"whitelist"] ?: json[@"allowlist"] ?: json[@"allowed"];
  if (whitelist && ![whitelist isKindOfClass:[NSArray class]]) {
    if (error) {
      *error = DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorInvalidFormat,
                            @"'whitelist' must be an array");
    }
    return NO;
  }

  return YES;
}

+ (BOOL)hasRequiredFields:(NSDictionary*)json {
  return json[@"blocked"] != nil || json[@"whitelist"] != nil || json[@"allowlist"] != nil ||
         json[@"allowed"] != nil;
}

+ (nullable NSString*)extractVersion:(NSDictionary*)json {
  // Try direct version field
  NSString* version = json[@"version"];
  if ([version isKindOfClass:[NSString class]]) {
    return version;
  }

  // Try metadata
  NSDictionary* metadata = json[@"metadata"];
  if ([metadata isKindOfClass:[NSDictionary class]]) {
    version = metadata[@"version"];
    if ([version isKindOfClass:[NSString class]]) {
      return version;
    }
  }

  return nil;
}

@end
