//
//  HostsFileParser.m
//  DNShield Network Extension
//
//  Parser for hosts file format rule lists implementation
//

#import "HostsFileParser.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>

@interface HostsFileParser ()
@property(nonatomic, strong) NSMutableArray<RuleEntry*>* parsedRules;
@property(nonatomic, strong) NSMutableDictionary* extractedMetadata;
@property(nonatomic) NSUInteger currentLineNumber;
@end

@implementation HostsFileParser

+ (void)load {
  // Register parser with factory when class is loaded
  [RuleParserFactory registerParserClass:[HostsFileParser class] forFormat:@"hosts"];
  [RuleParserFactory registerParserClass:[HostsFileParser class] forFormat:@"txt"];
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
    _extractedMetadata = [NSMutableDictionary dictionary];
    _parseWhitelistComments = YES;
    _parseMetadataComments = YES;
    _allowIPv6 = YES;
    _strictIPValidation = NO;
    _currentLineNumber = 0;
  }
  return self;
}

#pragma mark - RuleParser Protocol

- (NSString*)formatIdentifier {
  return @"hosts";
}

- (RuleParserCapabilities)capabilities {
  return RuleParserCapabilityValidation | RuleParserCapabilityComments |
         RuleParserCapabilityWildcards | RuleParserCapabilityStreaming;
}

- (NSArray<NSString*>*)supportedExtensions {
  return @[ @"hosts", @"txt", @"conf", @"list" ];
}

- (NSArray<NSString*>*)supportedMIMETypes {
  return @[ @"text/plain", @"text/hosts", @"application/x-hosts" ];
}

#pragma mark - Parsing

- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error {
  DNSLogPerformanceStart(@"HostsFileParser.parseData");

  // Reset state
  [self.parsedRules removeAllObjects];
  [self.extractedMetadata removeAllObjects];
  self.currentLineNumber = 0;

  // Validate data
  if (!data || data.length == 0) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorEmptyData
                              description:@"Empty data provided"];
    }
    DNSLogPerformanceEnd(@"HostsFileParser.parseData");
    return nil;
  }

  // Convert to string
  NSString* hostsString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (!hostsString) {
    // Try other encodings
    hostsString = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    if (!hostsString) {
      if (error) {
        *error = [self parsingErrorWithCode:DNSRuleParserErrorEncodingError
                                description:@"Failed to decode hosts file"];
      }
      DNSLogPerformanceEnd(@"HostsFileParser.parseData");
      return nil;
    }
  }

  // Parse line by line
  NSArray* lines =
      [hostsString componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
  NSUInteger totalLines = lines.count;

  for (NSString* line in lines) {
    @autoreleasepool {
      self.currentLineNumber++;
      [self parseLine:line];

      // Report progress periodically
      if (self.currentLineNumber % self.options.batchSize == 0) {
        [self reportProgress:(double)self.currentLineNumber / totalLines];
      }

      // Check max rule count
      if (self.options.maxRuleCount > 0 && self.parsedRules.count >= self.options.maxRuleCount) {
        DNSLogInfo(LogCategoryRuleParsing, "Reached max rule count: %lu",
                   (unsigned long)self.options.maxRuleCount);
        break;
      }
    }
  }

  // Report completion
  [self reportProgress:1.0];

  // Create metadata
  RuleSetMetadata* metadata = [self createMetadataFromExtracted];

  // Create rule set
  RuleSet* ruleSet = [[RuleSet alloc] initWithRules:[self.parsedRules copy] metadata:metadata];

  DNSLogPerformanceEnd(@"HostsFileParser.parseData");

  if (ruleSet) {
    DNSLogInfo(LogCategoryRuleParsing, "Successfully parsed hosts file with %lu rules",
               (unsigned long)ruleSet.rules.count);

    // Build index if requested
    if (self.options.buildIndexWhileParsing) {
      [ruleSet buildIndex];
    }
  }

  return ruleSet;
}

#pragma mark - Line Parsing

- (void)parseLine:(NSString*)line {
  // Trim whitespace
  NSString* trimmedLine =
      [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  // Skip empty lines
  if (trimmedLine.length == 0) {
    return;
  }

  // Handle comments
  if ([trimmedLine hasPrefix:@"#"]) {
    [self parseComment:trimmedLine];
    return;
  }

  // Remove inline comments
  NSRange commentRange = [trimmedLine rangeOfString:@"#"];
  if (commentRange.location != NSNotFound) {
    trimmedLine = [trimmedLine substringToIndex:commentRange.location];
    trimmedLine =
        [trimmedLine stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  // Parse hosts entry
  if ([HostsFileUtilities isValidHostsLine:trimmedLine]) {
    NSArray<NSString*>* domains = [HostsFileUtilities extractDomainsFromLine:trimmedLine];

    for (NSString* domain in domains) {
      RuleEntry* rule = [self createRuleForDomain:domain action:RuleActionBlock];
      if (rule) {
        [self addRuleIfValid:rule];
      }
    }
  }
}

- (void)parseComment:(NSString*)comment {
  // Check for whitelist entries
  if (self.parseWhitelistComments && [HostsFileUtilities isWhitelistComment:comment]) {
    NSString* domain = [HostsFileUtilities extractDomainFromWhitelistComment:comment];
    if (domain) {
      RuleEntry* rule = [self createRuleForDomain:domain action:RuleActionAllow];
      if (rule) {
        [self addRuleIfValid:rule];
      }
    }
    return;
  }

  // Parse metadata comments
  if (self.parseMetadataComments) {
    NSDictionary* metadata = [HostsFileUtilities parseMetadataComment:comment];
    if (metadata) {
      [self.extractedMetadata addEntriesFromDictionary:metadata];
    }
  }
}

#pragma mark - Rule Creation

- (nullable RuleEntry*)createRuleForDomain:(NSString*)domain action:(RuleAction)action {
  // Normalize domain
  NSString* normalizedDomain = domain;
  if (self.options.normalizeCase) {
    normalizedDomain = [self normalizeDomain:domain];
  }

  // Skip localhost entries
  if ([normalizedDomain isEqualToString:@"localhost"] ||
      [normalizedDomain isEqualToString:@"localhost.localdomain"] ||
      [normalizedDomain isEqualToString:@"local"] ||
      [normalizedDomain isEqualToString:@"broadcasthost"]) {
    return nil;
  }

  // Validate domain
  if (self.options.validateDomains && ![self isValidDomain:normalizedDomain]) {
    if (self.options.strictMode) {
      DNSLogError(LogCategoryRuleParsing, "Invalid domain at line %lu: %@",
                  (unsigned long)self.currentLineNumber, domain);
      return nil;
    } else {
      DNSLogDebug(LogCategoryRuleParsing, "Skipping invalid domain at line %lu: %@",
                  (unsigned long)self.currentLineNumber, domain);
      return nil;
    }
  }

  NSString* comment =
      [NSString stringWithFormat:@"Line %lu", (unsigned long)self.currentLineNumber];

  return [[RuleEntry alloc] initWithDomain:normalizedDomain
                                    action:action
                                  priority:self.options.defaultPriority
                                   comment:comment
                                 addedDate:nil
                                    source:self.extractedMetadata[@"source"]];
}

- (void)addRuleIfValid:(RuleEntry*)rule {
  // Check for duplicates if not allowed
  if (!self.options.allowDuplicates) {
    for (RuleEntry* existingRule in self.parsedRules) {
      if ([existingRule.domain isEqualToString:rule.domain] && existingRule.action == rule.action) {
        return;  // Skip duplicate
      }
    }
  }

  [self.parsedRules addObject:rule];
}

#pragma mark - Metadata Creation

- (RuleSetMetadata*)createMetadataFromExtracted {
  NSString *name = self.extractedMetadata[@"Title"] ?: 
                     self.extractedMetadata[@"Name"] ?: 
                     @"Hosts File Rules";

  NSString* version = self.extractedMetadata[@"Version"];

  NSDate* updatedDate = nil;
  NSString *dateStr = self.extractedMetadata[@"Updated"] ?: 
                        self.extractedMetadata[@"Last-Modified"] ?:
                        self.extractedMetadata[@"Date"];
  if (dateStr) {
    updatedDate = [self parseDateString:dateStr];
  }

  NSString* author = self.extractedMetadata[@"Author"] ?: self.extractedMetadata[@"Maintainer"];

  NSString *sourceURL = self.extractedMetadata[@"Homepage"] ?: 
                          self.extractedMetadata[@"URL"] ?:
                          self.extractedMetadata[@"Source"];

  NSString* description = self.extractedMetadata[@"Description"];
  NSString* license = self.extractedMetadata[@"License"];

  return [[RuleSetMetadata alloc] initWithName:name
                                       version:version
                                   updatedDate:updatedDate
                                        author:author
                                     sourceURL:sourceURL
                                   description:description
                                       license:license
                                  customFields:[self.extractedMetadata copy]];
}

@end

#pragma mark - Hosts File Utilities Implementation

@implementation HostsFileUtilities

+ (BOOL)isValidHostsLine:(NSString*)line {
  if (line.length == 0) {
    return NO;
  }

  // Must start with an IP address
  NSArray* components =
      [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  NSMutableArray* nonEmptyComponents = [NSMutableArray array];

  for (NSString* component in components) {
    if (component.length > 0) {
      [nonEmptyComponents addObject:component];
    }
  }

  if (nonEmptyComponents.count < 2) {
    return NO;
  }

  NSString* ipAddress = nonEmptyComponents[0];
  return [self isBlockingIP:ipAddress] || [self looksLikeIPAddress:ipAddress];
}

+ (nullable NSArray<NSString*>*)extractDomainsFromLine:(NSString*)line {
  NSArray* components =
      [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  NSMutableArray* domains = [NSMutableArray array];

  BOOL foundIP = NO;
  for (NSString* component in components) {
    if (component.length == 0) {
      continue;
    }

    if (!foundIP) {
      // First non-empty component should be IP
      if ([self isBlockingIP:component] || [self looksLikeIPAddress:component]) {
        foundIP = YES;
      }
    } else {
      // Subsequent components are domains
      [domains addObject:component];
    }
  }

  return foundIP && domains.count > 0 ? [domains copy] : nil;
}

+ (BOOL)isBlockingIP:(NSString*)ip {
  return [ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"127.0.0.1"] ||
         [ip isEqualToString:@"::1"] || [ip isEqualToString:@"::"] ||
         [ip isEqualToString:@"0:0:0:0:0:0:0:0"] || [ip isEqualToString:@"0:0:0:0:0:0:0:1"];
}

+ (BOOL)looksLikeIPAddress:(NSString*)string {
  // Simple check for IPv4
  if ([string rangeOfString:@"."].location != NSNotFound) {
    NSArray* parts = [string componentsSeparatedByString:@"."];
    if (parts.count == 4) {
      for (NSString* part in parts) {
        NSInteger value = [part integerValue];
        if (value < 0 || value > 255) {
          return NO;
        }
      }
      return YES;
    }
  }

  // Simple check for IPv6
  if ([string rangeOfString:@":"].location != NSNotFound) {
    return YES;  // Very basic check
  }

  return NO;
}

+ (nullable NSDictionary*)parseMetadataComment:(NSString*)comment {
  // Remove leading # and whitespace
  NSString* content = comment;
  if ([content hasPrefix:@"#"]) {
    content = [content substringFromIndex:1];
  }
  content = [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  // Look for key: value pattern
  NSRange colonRange = [content rangeOfString:@":"];
  if (colonRange.location != NSNotFound && colonRange.location > 0) {
    NSString* key = [[content substringToIndex:colonRange.location]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString* value = [[content substringFromIndex:colonRange.location + 1]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

    // Only accept known metadata keys
    NSSet* knownKeys =
        [NSSet setWithObjects:@"Title", @"Name", @"Version", @"Updated", @"Last-Modified", @"Date",
                              @"Author", @"Maintainer", @"Homepage", @"URL", @"Source",
                              @"Description", @"License", @"Expires", nil];

    if ([knownKeys containsObject:key] && value.length > 0) {
      return @{key : value};
    }
  }

  return nil;
}

+ (BOOL)isWhitelistComment:(NSString*)comment {
  NSString* trimmed =
      [comment stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  if ([trimmed hasPrefix:@"#"]) {
    trimmed = [[trimmed substringFromIndex:1]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  return [trimmed hasPrefix:@"@whitelist"] || [trimmed hasPrefix:@"@allow"] ||
         [trimmed hasPrefix:@"@allowlist"];
}

+ (nullable NSString*)extractDomainFromWhitelistComment:(NSString*)comment {
  NSString* trimmed =
      [comment stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  if ([trimmed hasPrefix:@"#"]) {
    trimmed = [[trimmed substringFromIndex:1]
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  // Remove the directive
  if ([trimmed hasPrefix:@"@whitelist"]) {
    trimmed = [trimmed substringFromIndex:10];
  } else if ([trimmed hasPrefix:@"@allow"]) {
    trimmed = [trimmed substringFromIndex:6];
  } else if ([trimmed hasPrefix:@"@allowlist"]) {
    trimmed = [trimmed substringFromIndex:10];
  }

  trimmed = [trimmed stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  return trimmed.length > 0 ? trimmed : nil;
}

@end
