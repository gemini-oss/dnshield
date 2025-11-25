//
//  YAMLRuleParser.m
//  DNShield Network Extension
//
//  Parser for YAML format rule lists implementation
//

#import "YAMLRuleParser.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>

@interface YAMLRuleParser ()
@property(nonatomic, strong) NSMutableArray<RuleEntry*>* parsedRules;
@property(nonatomic, strong) RuleSetMetadata* parsedMetadata;
@end

@implementation YAMLRuleParser

+ (void)load {
  // Register parser with factory when class is loaded
  [RuleParserFactory registerParserClass:[YAMLRuleParser class] forFormat:@"yaml"];
  [RuleParserFactory registerParserClass:[YAMLRuleParser class] forFormat:@"yml"];
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
  return @"yaml";
}

- (RuleParserCapabilities)capabilities {
  return RuleParserCapabilityMetadata | RuleParserCapabilityValidation |
         RuleParserCapabilityComments | RuleParserCapabilityPriorities |
         RuleParserCapabilityWildcards | RuleParserCapabilityStreaming;
}

- (NSArray<NSString*>*)supportedExtensions {
  return @[ @"yaml", @"yml" ];
}

- (NSArray<NSString*>*)supportedMIMETypes {
  return @[ @"application/x-yaml", @"text/yaml", @"text/x-yaml", @"application/yaml" ];
}

#pragma mark - Parsing

- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error {
  DNSLogPerformanceStart(@"YAMLRuleParser.parseData");

  // Reset state
  [self.parsedRules removeAllObjects];
  self.parsedMetadata = nil;

  // Validate data
  if (!data || data.length == 0) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorEmptyData
                              description:@"Empty data provided"];
    }
    DNSLogPerformanceEnd(@"YAMLRuleParser.parseData");
    return nil;
  }

  // Convert to string
  NSString* yamlString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (!yamlString) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorEncodingError
                              description:@"Failed to decode YAML data as UTF-8"];
    }
    DNSLogPerformanceEnd(@"YAMLRuleParser.parseData");
    return nil;
  }

  // Parse YAML
  NSError* parseError = nil;
  id yamlObject = [YAMLParseHelper parseYAMLString:yamlString error:&parseError];

  if (!yamlObject) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorSyntaxError
                              description:@"Invalid YAML format"
                          underlyingError:parseError];
    }
    DNSLogError(LogCategoryRuleParsing, "YAML parsing failed: %@", parseError.localizedDescription);
    DNSLogPerformanceEnd(@"YAMLRuleParser.parseData");
    return nil;
  }

  // Parse the YAML structure
  RuleSet* ruleSet = nil;

  if ([yamlObject isKindOfClass:[NSDictionary class]]) {
    ruleSet = [self parseYAMLDictionary:yamlObject error:error];
  } else if ([yamlObject isKindOfClass:[NSArray class]]) {
    // Simple array format
    ruleSet = [self parseYAMLArray:yamlObject error:error];
  } else {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorInvalidFormat
                              description:@"YAML must be a mapping or sequence"];
    }
    DNSLogPerformanceEnd(@"YAMLRuleParser.parseData");
    return nil;
  }

  DNSLogPerformanceEnd(@"YAMLRuleParser.parseData");

  if (ruleSet) {
    DNSLogInfo(LogCategoryRuleParsing, "Successfully parsed YAML with %lu rules",
               (unsigned long)ruleSet.rules.count);

    // Build index if requested
    if (self.options.buildIndexWhileParsing) {
      [ruleSet buildIndex];
    }
  }

  return ruleSet;
}

#pragma mark - YAML Parsing Helpers

- (nullable RuleSet*)parseYAMLDictionary:(NSDictionary*)yaml error:(NSError**)error {
  // Extract metadata
  self.parsedMetadata = [self extractMetadataFromYAML:yaml];

  // Parse blocked domains
  id blocked = yaml[@"blocked"] ?: yaml[@"blocklist"];
  if (blocked) {
    [self parseRuleValue:blocked action:RuleActionBlock];
  }

  // Parse whitelisted domains
  id whitelist = yaml[@"whitelist"] ?: yaml[@"allowlist"] ?: yaml[@"allowed"];
  if (whitelist) {
    [self parseRuleValue:whitelist action:RuleActionAllow];
  }

  // Report progress
  [self reportProgress:1.0];

  // Create rule set
  if (self.parsedRules.count == 0 && !self.options.strictMode) {
    DNSLogInfo(LogCategoryRuleParsing, "No rules found in YAML");
  }

  return [[RuleSet alloc] initWithRules:[self.parsedRules copy] metadata:self.parsedMetadata];
}

- (nullable RuleSet*)parseYAMLArray:(NSArray*)yamlArray error:(NSError**)error {
  // Simple array format - treat all as blocked domains
  [self parseRuleArray:yamlArray action:RuleActionBlock];

  // Create minimal metadata
  RuleSetMetadata* metadata = [RuleSetMetadata metadataWithName:@"YAML Rules" version:@"1.0"];

  return [[RuleSet alloc] initWithRules:[self.parsedRules copy] metadata:metadata];
}

- (void)parseRuleValue:(id)value action:(RuleAction)action {
  if ([value isKindOfClass:[NSArray class]]) {
    [self parseRuleArray:value action:action];
  } else if ([value isKindOfClass:[NSString class]]) {
    // Single value
    RuleEntry* rule = [self parseStringRule:value action:action];
    if (rule) {
      [self.parsedRules addObject:rule];
    }
  } else {
    DNSLogDebug(LogCategoryRuleParsing, "Unexpected rule value type: %@",
                NSStringFromClass([value class]));
  }
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
  // Trim whitespace
  domain =
      [domain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

  // Skip empty lines
  if (domain.length == 0) {
    return nil;
  }

  // Skip comments
  if ([domain hasPrefix:@"#"]) {
    return nil;
  }

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

- (RuleSetMetadata*)extractMetadataFromYAML:(NSDictionary*)yaml {
  NSString* name = yaml[@"name"];
  NSString* version = yaml[@"version"];

  NSDate* updatedDate = nil;
  id updated = yaml[@"updated"] ?: yaml[@"lastUpdated"] ?: yaml[@"modified"];
  if ([updated isKindOfClass:[NSString class]]) {
    updatedDate = [self parseDateString:updated];
  } else if ([updated isKindOfClass:[NSNumber class]]) {
    updatedDate = [NSDate dateWithTimeIntervalSince1970:[updated doubleValue]];
  }

  NSString* author = yaml[@"author"] ?: yaml[@"maintainer"];
  NSString* sourceURL = yaml[@"source"] ?: yaml[@"url"] ?: yaml[@"homepage"];
  NSString* description = yaml[@"description"];
  NSString* license = yaml[@"license"];

  NSDictionary* customFields = yaml[@"metadata"];
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

#pragma mark - YAML Parse Helper Implementation

@implementation YAMLParseHelper

+ (nullable id)parseYAMLString:(NSString*)yamlString error:(NSError**)error {
  // This is a simplified YAML parser
  // In production, you'd want to use a proper YAML library

  if (![self isLikelyYAML:yamlString]) {
    if (error) {
      *error = DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorInvalidFormat,
                            @"String does not appear to be YAML");
    }
    return nil;
  }

  NSMutableDictionary* result = [NSMutableDictionary dictionary];
  NSMutableArray* currentArray = nil;
  NSString* currentKey = nil;
  NSInteger currentIndent = 0;

  NSArray* lines = [yamlString componentsSeparatedByString:@"\n"];

  for (NSString* line in lines) {
    // Skip empty lines and comments
    NSString* trimmedLine =
        [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (trimmedLine.length == 0 || [trimmedLine hasPrefix:@"#"] ||
        [trimmedLine isEqualToString:@"---"]) {
      continue;
    }

    NSInteger indent = [self indentationLevel:line];

    // Handle array items
    if ([trimmedLine hasPrefix:@"- "]) {
      NSString* value = [trimmedLine substringFromIndex:2];
      value = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

      if (currentKey && indent > currentIndent) {
        // This is an array item for the current key
        if (!currentArray) {
          currentArray = [NSMutableArray array];
          result[currentKey] = currentArray;
        }

        // Check if it's a nested structure
        if ([value containsString:@":"]) {
          // Parse as dictionary
          NSDictionary* dictValue = [self parseDictionaryLine:value];
          [currentArray addObject:dictValue ?: value];
        } else {
          id parsedValue = [self parseYAMLValue:value];
          [currentArray addObject:parsedValue];
        }
      }
    }
    // Handle key-value pairs
    else if ([trimmedLine containsString:@":"]) {
      NSRange colonRange = [trimmedLine rangeOfString:@":"];
      NSString* key = [trimmedLine substringToIndex:colonRange.location];
      key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

      NSString* value = [trimmedLine substringFromIndex:colonRange.location + 1];
      value = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

      if (value.length > 0) {
        // Direct value
        result[key] = [self parseYAMLValue:value];
        currentKey = nil;
        currentArray = nil;
      } else {
        // Value will be on following lines
        currentKey = key;
        currentArray = nil;
        currentIndent = indent;
      }
    }
  }

  return result;
}

+ (BOOL)isLikelyYAML:(NSString*)string {
  // Simple heuristics to check if string looks like YAML
  return [string containsString:@":"] || [string containsString:@"- "] || [string hasPrefix:@"---"];
}

+ (NSInteger)indentationLevel:(NSString*)line {
  NSInteger indent = 0;
  for (NSUInteger i = 0; i < line.length; i++) {
    unichar ch = [line characterAtIndex:i];
    if (ch == ' ') {
      indent++;
    } else if (ch == '\t') {
      indent += 4;  // Treat tab as 4 spaces
    } else {
      break;
    }
  }
  return indent;
}

+ (nullable id)parseYAMLValue:(NSString*)value {
  if (!value || value.length == 0) {
    return nil;
  }

  // Remove quotes if present
  if ((([value hasPrefix:@"\""] && [value hasSuffix:@"\""]) ||
       ([value hasPrefix:@"'"] && [value hasSuffix:@"'"])) &&
      value.length >= 2) {
    value = [value substringWithRange:NSMakeRange(1, value.length - 2)];
  }

  // Check for boolean values
  NSString* lowerValue = [value lowercaseString];
  if ([lowerValue isEqualToString:@"true"] || [lowerValue isEqualToString:@"yes"]) {
    return @YES;
  } else if ([lowerValue isEqualToString:@"false"] || [lowerValue isEqualToString:@"no"]) {
    return @NO;
  }

  // Check for null
  if ([lowerValue isEqualToString:@"null"] || [lowerValue isEqualToString:@"~"]) {
    return [NSNull null];
  }

  // Check for numbers
  NSNumberFormatter* formatter = [[NSNumberFormatter alloc] init];
  formatter.numberStyle = NSNumberFormatterDecimalStyle;
  NSNumber* number = [formatter numberFromString:value];
  if (number) {
    return number;
  }

  // Return as string
  return value;
}

+ (nullable NSDictionary*)parseDictionaryLine:(NSString*)line {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  // Simple parsing for inline dictionary format: "key: value, key2: value2"
  NSArray* pairs = [line componentsSeparatedByString:@","];
  for (NSString* pair in pairs) {
    NSRange colonRange = [pair rangeOfString:@":"];
    if (colonRange.location != NSNotFound) {
      NSString* key = [[pair substringToIndex:colonRange.location]
          stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
      NSString* value = [[pair substringFromIndex:colonRange.location + 1]
          stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

      if (key.length > 0) {
        dict[key] = [self parseYAMLValue:value];
      }
    }
  }

  return dict.count > 0 ? dict : nil;
}

@end
