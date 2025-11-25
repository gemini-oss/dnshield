//
//  RuleSet.m
//  DNShield Network Extension
//
//  Common output format for all rule parsers implementation
//

#import "RuleSet.h"
#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import "DNSWildcardConfig.h"

#pragma mark - RuleEntry Implementation

@interface RuleEntry ()
@property(nonatomic, readwrite) NSString* domain;
@property(nonatomic, readwrite) RuleAction action;
@property(nonatomic, readwrite) RulePriority priority;
@property(nonatomic, nullable, readwrite) NSString* comment;
@property(nonatomic, nullable, readwrite) NSDate* addedDate;
@property(nonatomic, nullable, readwrite) NSString* source;
@end

@implementation RuleEntry

- (instancetype)initWithDomain:(NSString*)domain
                        action:(RuleAction)action
                      priority:(RulePriority)priority
                       comment:(nullable NSString*)comment
                     addedDate:(nullable NSDate*)addedDate
                        source:(nullable NSString*)source {
  self = [super init];
  if (self) {
    _domain = [domain copy];
    _action = action;
    _priority = priority;
    _comment = [comment copy];
    _addedDate = addedDate ?: [NSDate date];
    _source = [source copy];
  }
  return self;
}

+ (instancetype)blockRuleForDomain:(NSString*)domain {
  return [[self alloc] initWithDomain:domain
                               action:RuleActionBlock
                             priority:RulePriorityMedium
                              comment:nil
                            addedDate:nil
                               source:nil];
}

+ (instancetype)allowRuleForDomain:(NSString*)domain {
  return [[self alloc] initWithDomain:domain
                               action:RuleActionAllow
                             priority:RulePriorityMedium
                              comment:nil
                            addedDate:nil
                               source:nil];
}

- (BOOL)matchesDomain:(NSString*)domain {
  if ([self.domain isEqualToString:domain]) {
    return YES;
  }

  // Handle wildcard matching
  if ([self isWildcard]) {
    NSString* pattern = self.domain;

    // Check if wildcard should match root domain based on configuration
    DNSWildcardConfig* config = [DNSWildcardConfig sharedConfig];
    BOOL matchRoot = [config wildcardShouldMatchRoot:self.domain];

    // Convert wildcard pattern to regex
    if (matchRoot && [pattern hasPrefix:@"*."]) {
      // Enhanced pattern: *.example.com -> ^(.*\.)?example\.com$
      // This matches both example.com and *.example.com
      NSString* rootDomain = [pattern substringFromIndex:2];
      rootDomain = [rootDomain stringByReplacingOccurrencesOfString:@"." withString:@"\\."];
      pattern = [NSString stringWithFormat:@"^(.*\\.)?%@$", rootDomain];
    } else {
      // Traditional pattern: *.example.com -> ^.*\.example\.com$
      pattern = [pattern stringByReplacingOccurrencesOfString:@"." withString:@"\\."];
      pattern = [pattern stringByReplacingOccurrencesOfString:@"*" withString:@".*"];
      pattern = [NSString stringWithFormat:@"^%@$", pattern];
    }

    NSError* error = nil;
    NSRegularExpression* regex =
        [NSRegularExpression regularExpressionWithPattern:pattern
                                                  options:NSRegularExpressionCaseInsensitive
                                                    error:&error];
    if (error) {
      DNSLogError(LogCategoryRuleParsing, "Failed to create regex for pattern %@: %@", self.domain,
                  error.localizedDescription);
      return NO;
    }

    NSRange range = [regex rangeOfFirstMatchInString:domain
                                             options:0
                                               range:NSMakeRange(0, domain.length)];
    return range.location != NSNotFound;
  }

  // Check if the domain ends with our rule domain (subdomain matching)
  // e.g., rule "example.com" matches "sub.example.com"
  if ([domain hasSuffix:self.domain]) {
    NSUInteger prefixLength = domain.length - self.domain.length;
    if (prefixLength == 0) {
      return YES;  // Exact match
    }
    // Check if it's a proper subdomain (has a dot before the suffix)
    if (prefixLength > 0 && [domain characterAtIndex:prefixLength - 1] == '.') {
      return YES;
    }
  }

  return NO;
}

- (BOOL)isWildcard {
  return [self.domain containsString:@"*"];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  return [[RuleEntry allocWithZone:zone] initWithDomain:self.domain
                                                 action:self.action
                                               priority:self.priority
                                                comment:self.comment
                                              addedDate:self.addedDate
                                                 source:self.source];
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.domain forKey:@"domain"];
  [coder encodeInteger:self.action forKey:@"action"];
  [coder encodeInteger:self.priority forKey:@"priority"];
  [coder encodeObject:self.comment forKey:@"comment"];
  [coder encodeObject:self.addedDate forKey:@"addedDate"];
  [coder encodeObject:self.source forKey:@"source"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  NSString* domain = [coder decodeObjectOfClass:[NSString class] forKey:@"domain"];
  if (!domain) {
    return nil;
  }

  return [self initWithDomain:domain
                       action:[coder decodeIntegerForKey:@"action"]
                     priority:[coder decodeIntegerForKey:@"priority"]
                      comment:[coder decodeObjectOfClass:[NSString class] forKey:@"comment"]
                    addedDate:[coder decodeObjectOfClass:[NSDate class] forKey:@"addedDate"]
                       source:[coder decodeObjectOfClass:[NSString class] forKey:@"source"]];
}

- (BOOL)isEqual:(id)object {
  if (self == object) {
    return YES;
  }

  if (![object isKindOfClass:[RuleEntry class]]) {
    return NO;
  }

  RuleEntry* other = (RuleEntry*)object;
  return [self.domain isEqualToString:other.domain] && self.action == other.action &&
         self.priority == other.priority;
}

- (NSUInteger)hash {
  return self.domain.hash ^ self.action ^ self.priority;
}

@end

#pragma mark - RuleSetMetadata Implementation

@interface RuleSetMetadata ()
@property(nonatomic, nullable, readwrite) NSString* name;
@property(nonatomic, nullable, readwrite) NSString* version;
@property(nonatomic, nullable, readwrite) NSDate* updatedDate;
@property(nonatomic, nullable, readwrite) NSString* author;
@property(nonatomic, nullable, readwrite) NSString* sourceURL;
@property(nonatomic, nullable, readwrite) NSString* ruleDescription;
@property(nonatomic, nullable, readwrite) NSString* license;
@property(nonatomic, nullable, readwrite) NSDictionary* customFields;
@end

@implementation RuleSetMetadata

// Remove synthesize - description will be handled by getter method

- (instancetype)initWithName:(nullable NSString*)name
                     version:(nullable NSString*)version
                 updatedDate:(nullable NSDate*)updatedDate
                      author:(nullable NSString*)author
                   sourceURL:(nullable NSString*)sourceURL
                 description:(nullable NSString*)description
                     license:(nullable NSString*)license
                customFields:(nullable NSDictionary*)customFields {
  self = [super init];
  if (self) {
    _name = [name copy];
    _version = [version copy];
    _updatedDate = updatedDate;
    _author = [author copy];
    _sourceURL = [sourceURL copy];
    _ruleDescription = [description copy];
    _license = [license copy];
    _customFields = [customFields copy];
  }
  return self;
}

+ (instancetype)metadataWithName:(NSString*)name version:(NSString*)version {
  return [[self alloc] initWithName:name
                            version:version
                        updatedDate:[NSDate date]
                             author:nil
                          sourceURL:nil
                        description:nil
                            license:nil
                       customFields:nil];
}

- (NSString*)description {
  return self.ruleDescription;
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  return [[RuleSetMetadata allocWithZone:zone] initWithName:self.name
                                                    version:self.version
                                                updatedDate:self.updatedDate
                                                     author:self.author
                                                  sourceURL:self.sourceURL
                                                description:self.description
                                                    license:self.license
                                               customFields:self.customFields];
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.name forKey:@"name"];
  [coder encodeObject:self.version forKey:@"version"];
  [coder encodeObject:self.updatedDate forKey:@"updatedDate"];
  [coder encodeObject:self.author forKey:@"author"];
  [coder encodeObject:self.sourceURL forKey:@"sourceURL"];
  [coder encodeObject:self.description forKey:@"description"];
  [coder encodeObject:self.license forKey:@"license"];
  [coder encodeObject:self.customFields forKey:@"customFields"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  return [self initWithName:[coder decodeObjectOfClass:[NSString class] forKey:@"name"]
                    version:[coder decodeObjectOfClass:[NSString class] forKey:@"version"]
                updatedDate:[coder decodeObjectOfClass:[NSDate class] forKey:@"updatedDate"]
                     author:[coder decodeObjectOfClass:[NSString class] forKey:@"author"]
                  sourceURL:[coder decodeObjectOfClass:[NSString class] forKey:@"sourceURL"]
                description:[coder decodeObjectOfClass:[NSString class] forKey:@"description"]
                    license:[coder decodeObjectOfClass:[NSString class] forKey:@"license"]
               customFields:[coder decodeObjectOfClass:[NSDictionary class]
                                                forKey:@"customFields"]];
}

@end

#pragma mark - RuleSetStatistics Implementation

@interface RuleSetStatistics ()
@property(nonatomic, readwrite) NSUInteger totalRules;
@property(nonatomic, readwrite) NSUInteger blockRules;
@property(nonatomic, readwrite) NSUInteger allowRules;
@property(nonatomic, readwrite) NSUInteger wildcardRules;
@property(nonatomic, readwrite) NSUInteger uniqueDomains;
@property(nonatomic, readwrite) NSUInteger duplicateRules;
@property(nonatomic, readwrite) NSUInteger invalidRules;
@end

@implementation RuleSetStatistics

- (instancetype)initWithRules:(NSArray<RuleEntry*>*)rules {
  self = [super init];
  if (self) {
    [self calculateStatisticsForRules:rules];
  }
  return self;
}

- (void)calculateStatisticsForRules:(NSArray<RuleEntry*>*)rules {
  self.totalRules = rules.count;

  NSMutableSet* uniqueDomainSet = [NSMutableSet set];
  NSMutableSet* seenRules = [NSMutableSet set];

  for (RuleEntry* rule in rules) {
    // Count by action type
    switch (rule.action) {
      case RuleActionBlock: self.blockRules++; break;
      case RuleActionAllow: self.allowRules++; break;
      default: break;
    }

    // Count wildcards
    if ([rule isWildcard]) {
      self.wildcardRules++;
    }

    // Track unique domains
    [uniqueDomainSet addObject:rule.domain];

    // Check for duplicates
    if ([seenRules containsObject:rule]) {
      self.duplicateRules++;
    } else {
      [seenRules addObject:rule];
    }
  }

  self.uniqueDomains = uniqueDomainSet.count;
}

@end

#pragma mark - RuleSet Implementation

@interface RuleSet () {
  NSMutableDictionary<NSString*, NSMutableArray<RuleEntry*>*>* _domainIndex;
  dispatch_queue_t _indexQueue;
}
@property(nonatomic, readwrite) NSArray<RuleEntry*>* rules;
@property(nonatomic, readwrite) RuleSetMetadata* metadata;
@property(nonatomic, readwrite) RuleSetStatistics* statistics;
@property(nonatomic, readwrite) NSDate* parseDate;
@end

@implementation RuleSet

- (instancetype)initWithRules:(NSArray<RuleEntry*>*)rules metadata:(RuleSetMetadata*)metadata {
  self = [super init];
  if (self) {
    _rules = [rules copy];
    _metadata = metadata;
    _statistics = [[RuleSetStatistics alloc] initWithRules:rules];
    _parseDate = [NSDate date];
    _indexQueue = dispatch_queue_create("com.dnshield.ruleset.index", DISPATCH_QUEUE_CONCURRENT);

    DNSLogInfo(LogCategoryRuleParsing, "Created RuleSet with %lu rules",
               (unsigned long)rules.count);
  }
  return self;
}

- (void)dealloc {
  _domainIndex = nil;
}

#pragma mark - Query Methods

- (nullable RuleEntry*)ruleForDomain:(NSString*)domain {
  NSArray<RuleEntry*>* matchingRules = [self rulesForDomain:domain];

  if (matchingRules.count == 0) {
    return nil;
  }

  // Return the highest priority rule
  RuleEntry* highestPriorityRule = matchingRules.firstObject;
  for (RuleEntry* rule in matchingRules) {
    if (rule.priority > highestPriorityRule.priority) {
      highestPriorityRule = rule;
    }
  }

  return highestPriorityRule;
}

- (NSArray<RuleEntry*>*)rulesForDomain:(NSString*)domain {
  NSMutableArray<RuleEntry*>* matchingRules = [NSMutableArray array];

  // Use index if available
  __block NSDictionary* index;
  dispatch_sync(_indexQueue, ^{
    index = _domainIndex;
  });

  if (index) {
    // Fast path: check exact match first
    NSArray<RuleEntry*>* exactMatches = index[domain];
    if (exactMatches) {
      [matchingRules addObjectsFromArray:exactMatches];
    }

    // Check parent domains
    NSArray* domainParts = [domain componentsSeparatedByString:@"."];
    for (NSUInteger i = 1; i < domainParts.count; i++) {
      NSString* parentDomain = [[domainParts
          subarrayWithRange:NSMakeRange(i, domainParts.count - i)] componentsJoinedByString:@"."];
      NSArray<RuleEntry*>* parentMatches = index[parentDomain];
      if (parentMatches) {
        [matchingRules addObjectsFromArray:parentMatches];
      }
    }

    // Check wildcard rules
    NSArray<RuleEntry*>* wildcardRules = index[@"*"];
    for (RuleEntry* rule in wildcardRules) {
      if ([rule matchesDomain:domain]) {
        [matchingRules addObject:rule];
      }
    }
  } else {
    // Slow path: linear search
    for (RuleEntry* rule in self.rules) {
      if ([rule matchesDomain:domain]) {
        [matchingRules addObject:rule];
      }
    }
  }

  return [matchingRules copy];
}

- (BOOL)shouldBlockDomain:(NSString*)domain {
  RuleEntry* rule = [self ruleForDomain:domain];
  return rule && rule.action == RuleActionBlock;
}

#pragma mark - Filtering and Manipulation

- (RuleSet*)ruleSetByFilteringWithPredicate:(NSPredicate*)predicate {
  NSArray* filteredRules = [self.rules filteredArrayUsingPredicate:predicate];
  return [[RuleSet alloc] initWithRules:filteredRules metadata:self.metadata];
}

- (RuleSet*)ruleSetByMergingWithRuleSet:(RuleSet*)otherRuleSet {
  NSMutableArray* mergedRules = [NSMutableArray arrayWithArray:self.rules];
  [mergedRules addObjectsFromArray:otherRuleSet.rules];

  // Simple merge - just combine metadata names
  NSString* mergedName = [NSString stringWithFormat:@"%@ + %@", self.metadata.name ?: @"Unknown",
                                                    otherRuleSet.metadata.name ?: @"Unknown"];

  RuleSetMetadata* mergedMetadata = [RuleSetMetadata metadataWithName:mergedName version:@"merged"];

  return [[RuleSet alloc] initWithRules:mergedRules metadata:mergedMetadata];
}

- (RuleSet*)ruleSetByRemovingDuplicates {
  NSMutableArray* uniqueRules = [NSMutableArray array];
  NSMutableSet* seenRules = [NSMutableSet set];

  for (RuleEntry* rule in self.rules) {
    if (![seenRules containsObject:rule]) {
      [uniqueRules addObject:rule];
      [seenRules addObject:rule];
    }
  }

  DNSLogInfo(LogCategoryRuleParsing, "Removed %lu duplicate rules",
             (unsigned long)(self.rules.count - uniqueRules.count));

  return [[RuleSet alloc] initWithRules:uniqueRules metadata:self.metadata];
}

#pragma mark - Export Methods

- (nullable NSData*)exportToJSONWithError:(NSError**)error {
  NSDictionary* dict = [self exportToDictionary];
  if (!dict) {
    if (error) {
      *error = DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorInvalidFormat,
                            @"Failed to export rule set to dictionary");
    }
    return nil;
  }

  return [NSJSONSerialization dataWithJSONObject:dict
                                         options:NSJSONWritingPrettyPrinted
                                           error:error];
}

- (nullable NSDictionary*)exportToDictionary {
  NSMutableDictionary* dict = [NSMutableDictionary dictionary];

  // Export metadata
  if (self.metadata) {
    NSMutableDictionary* metadataDict = [NSMutableDictionary dictionary];
    if (self.metadata.name)
      metadataDict[@"name"] = self.metadata.name;
    if (self.metadata.version)
      metadataDict[@"version"] = self.metadata.version;
    if (self.metadata.updatedDate) {
      metadataDict[@"updated"] = @([self.metadata.updatedDate timeIntervalSince1970]);
    }
    if (self.metadata.author)
      metadataDict[@"author"] = self.metadata.author;
    if (self.metadata.sourceURL)
      metadataDict[@"source"] = self.metadata.sourceURL;
    if (self.metadata.description)
      metadataDict[@"description"] = self.metadata.description;
    if (self.metadata.license)
      metadataDict[@"license"] = self.metadata.license;
    if (self.metadata.customFields)
      metadataDict[@"custom"] = self.metadata.customFields;

    dict[@"metadata"] = metadataDict;
  }

  // Export rules by action type
  NSMutableArray* blockedDomains = [NSMutableArray array];
  NSMutableArray* allowedDomains = [NSMutableArray array];

  for (RuleEntry* rule in self.rules) {
    NSDictionary* ruleDict = @{
      @"domain" : rule.domain,
      @"priority" : @(rule.priority),
      @"comment" : rule.comment ?: [NSNull null],
      @"source" : rule.source ?: [NSNull null]
    };

    switch (rule.action) {
      case RuleActionBlock: [blockedDomains addObject:ruleDict]; break;
      case RuleActionAllow: [allowedDomains addObject:ruleDict]; break;
      default: break;
    }
  }

  dict[@"blocked"] = blockedDomains;
  dict[@"whitelist"] = allowedDomains;
  dict[@"statistics"] = @{
    @"totalRules" : @(self.statistics.totalRules),
    @"blockRules" : @(self.statistics.blockRules),
    @"allowRules" : @(self.statistics.allowRules),
    @"wildcardRules" : @(self.statistics.wildcardRules),
    @"uniqueDomains" : @(self.statistics.uniqueDomains)
  };

  return dict;
}

#pragma mark - Validation

- (BOOL)validateWithError:(NSError**)error {
  // Basic validation
  if (self.rules.count == 0) {
    DNSLogInfo(LogCategoryRuleParsing, "Rule set is empty");
    // Empty rule set is valid, just has no rules
    return YES;
  }

  // Validate individual rules
  for (RuleEntry* rule in self.rules) {
    if (rule.domain.length == 0) {
      if (error) {
        *error = DNSMakeError(DNSRuleParserErrorDomain, DNSRuleParserErrorInvalidDomain,
                              @"Rule contains empty domain");
      }
      return NO;
    }

    // Basic domain validation - no spaces, valid characters
    NSCharacterSet* invalidChars = [NSCharacterSet characterSetWithCharactersInString:@" \t\n\r"];
    if ([rule.domain rangeOfCharacterFromSet:invalidChars].location != NSNotFound) {
      if (error) {
        *error = DNSMakeErrorWithInfo(DNSRuleParserErrorDomain, DNSRuleParserErrorInvalidDomain,
                                      @"Rule contains invalid domain", @{@"domain" : rule.domain});
      }
      return NO;
    }
  }

  return YES;
}

#pragma mark - Performance Optimization

- (void)buildIndex {
  DNSLogPerformanceStart(@"RuleSet.buildIndex");

  NSMutableDictionary<NSString*, NSMutableArray<RuleEntry*>*>* index =
      [NSMutableDictionary dictionary];
  NSMutableArray<RuleEntry*>* wildcardRules = [NSMutableArray array];

  for (RuleEntry* rule in self.rules) {
    if ([rule isWildcard]) {
      [wildcardRules addObject:rule];
    } else {
      NSMutableArray* rulesForDomain = index[rule.domain];
      if (!rulesForDomain) {
        rulesForDomain = [NSMutableArray array];
        index[rule.domain] = rulesForDomain;
      }
      [rulesForDomain addObject:rule];
    }
  }

  // Store wildcard rules under special key
  if (wildcardRules.count > 0) {
    index[@"*"] = wildcardRules;
  }

  // Update index atomically
  dispatch_barrier_async(_indexQueue, ^{
    self->_domainIndex = index;
  });

  DNSLogPerformanceEnd(@"RuleSet.buildIndex");
  DNSLogInfo(LogCategoryRuleParsing, "Built index for %lu rules with %lu unique domains",
             (unsigned long)self.rules.count, (unsigned long)index.count);
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone*)zone {
  return [[RuleSet allocWithZone:zone] initWithRules:self.rules metadata:[self.metadata copy]];
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.rules forKey:@"rules"];
  [coder encodeObject:self.metadata forKey:@"metadata"];
  [coder encodeObject:self.parseDate forKey:@"parseDate"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  NSArray* rules =
      [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [RuleEntry class], nil]
                            forKey:@"rules"];
  RuleSetMetadata* metadata = [coder decodeObjectOfClass:[RuleSetMetadata class]
                                                  forKey:@"metadata"];

  if (!rules) {
    return nil;
  }

  self = [self initWithRules:rules metadata:metadata];
  if (self) {
    _parseDate = [coder decodeObjectOfClass:[NSDate class] forKey:@"parseDate"];
  }
  return self;
}

@end

#pragma mark - RuleSetMerger Implementation

@implementation RuleSetMerger

+ (RuleSet*)mergeRuleSets:(NSArray<RuleSet*>*)ruleSets
                  options:(RuleSetMergeOptions)options
                    error:(NSError**)error {
  if (ruleSets.count == 0) {
    if (error) {
      *error = DNSMakeError(DNSRuleManagerErrorDomain, DNSRuleManagerErrorNoSources,
                            @"No rule sets to merge");
    }
    return nil;
  }

  if (ruleSets.count == 1) {
    return ruleSets.firstObject;
  }

  DNSLogPerformanceStart(@"RuleSetMerger.merge");

  NSMutableArray<RuleEntry*>* mergedRules = [NSMutableArray array];
  NSMutableDictionary<NSString*, RuleEntry*>* ruleMap = [NSMutableDictionary dictionary];

  // Process each rule set
  for (RuleSet* ruleSet in ruleSets) {
    for (RuleEntry* rule in ruleSet.rules) {
      NSString* key = [NSString stringWithFormat:@"%@:%ld", rule.domain, (long)rule.action];
      RuleEntry* existingRule = ruleMap[key];

      if (existingRule) {
        // Handle conflict based on options
        BOOL shouldReplace = NO;

        if (options & RuleSetMergeOptionPreferHigherPriority) {
          shouldReplace = rule.priority > existingRule.priority;
        } else if (options & RuleSetMergeOptionPreferNewer) {
          shouldReplace = [rule.addedDate compare:existingRule.addedDate] == NSOrderedDescending;
        }

        if (shouldReplace) {
          ruleMap[key] = rule;
        }
      } else {
        ruleMap[key] = rule;
      }
    }
  }

  // Convert map to array
  [mergedRules addObjectsFromArray:ruleMap.allValues];

  // Remove duplicates if requested
  RuleSet* mergedSet = [[RuleSet alloc] initWithRules:mergedRules
                                             metadata:[self mergeMetadata:ruleSets
                                                                  options:options]];

  if (!(options & RuleSetMergeOptionKeepDuplicates)) {
    mergedSet = [mergedSet ruleSetByRemovingDuplicates];
  }

  DNSLogPerformanceEnd(@"RuleSetMerger.merge");
  DNSLogInfo(LogCategoryRuleParsing, "Merged %lu rule sets into %lu rules",
             (unsigned long)ruleSets.count, (unsigned long)mergedSet.rules.count);

  return mergedSet;
}

+ (RuleSetMetadata*)mergeMetadata:(NSArray<RuleSet*>*)ruleSets
                          options:(RuleSetMergeOptions)options {
  if (!(options & RuleSetMergeOptionCombineMetadata) || ruleSets.count == 0) {
    return nil;
  }

  NSMutableArray* names = [NSMutableArray array];
  NSDate* latestUpdate = nil;

  for (RuleSet* ruleSet in ruleSets) {
    if (ruleSet.metadata.name) {
      [names addObject:ruleSet.metadata.name];
    }
    if (ruleSet.metadata.updatedDate) {
      if (!latestUpdate ||
          [ruleSet.metadata.updatedDate compare:latestUpdate] == NSOrderedDescending) {
        latestUpdate = ruleSet.metadata.updatedDate;
      }
    }
  }

  NSString* mergedName = [names componentsJoinedByString:@" + "];
  return [[RuleSetMetadata alloc] initWithName:mergedName
                                       version:@"merged"
                                   updatedDate:latestUpdate
                                        author:nil
                                     sourceURL:nil
                                   description:@"Merged rule set"
                                       license:nil
                                  customFields:nil];
}

@end
