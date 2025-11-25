//
//  RuleParser.m
//  DNShield Network Extension
//
//  Abstract base class/protocol for rule list parsers implementation
//

#import <Common/ErrorTypes.h>
#import <Common/LoggingManager.h>
#import <Rule/Parser.h>

#pragma mark - Parser Options Implementation

@implementation RuleParserOptions

- (instancetype)init {
  self = [super init];
  if (self) {
    // Default values
    _strictMode = NO;
    _allowDuplicates = NO;
    _normalizeCase = YES;
    _validateDomains = YES;
    _maxRuleCount = 0;  // Unlimited
    _parseTimeout = 30.0;
    _defaultAction = RuleActionBlock;
    _defaultPriority = RulePriorityMedium;
    _buildIndexWhileParsing = NO;
    _batchSize = 1000;
  }
  return self;
}

+ (instancetype)defaultOptions {
  return [[self alloc] init];
}

+ (instancetype)strictOptions {
  RuleParserOptions* options = [[self alloc] init];
  options.strictMode = YES;
  options.allowDuplicates = NO;
  options.validateDomains = YES;
  return options;
}

+ (instancetype)performanceOptions {
  RuleParserOptions* options = [[self alloc] init];
  options.strictMode = NO;
  options.validateDomains = NO;
  options.buildIndexWhileParsing = YES;
  options.batchSize = 5000;
  return options;
}

@end

#pragma mark - Base Parser Implementation

@implementation RuleParserBase

- (instancetype)init {
  self = [super init];
  if (self) {
    // Base initialization
  }
  return self;
}

#pragma mark - RuleParser Protocol Requirements

- (NSString*)formatIdentifier {
  [NSException raise:NSInternalInconsistencyException
              format:@"Subclasses must override formatIdentifier"];
  return nil;
}

- (RuleParserCapabilities)capabilities {
  return RuleParserCapabilityNone;
}

- (NSArray<NSString*>*)supportedExtensions {
  [NSException raise:NSInternalInconsistencyException
              format:@"Subclasses must override supportedExtensions"];
  return @[];
}

- (NSArray<NSString*>*)supportedMIMETypes {
  [NSException raise:NSInternalInconsistencyException
              format:@"Subclasses must override supportedMIMETypes"];
  return @[];
}

- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error {
  [NSException raise:NSInternalInconsistencyException
              format:@"Subclasses must override parseData:error:"];
  return nil;
}

#pragma mark - Default Implementations

- (nullable RuleSet*)parseFileAtURL:(NSURL*)fileURL error:(NSError**)error {
  DNSLogInfo(LogCategoryRuleParsing, "Parsing file at URL: %@", fileURL.path);

  // Check if file exists
  if (![[NSFileManager defaultManager] fileExistsAtPath:fileURL.path]) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorFileMissing
                              description:@"File does not exist"];
    }
    return nil;
  }

  // Read file data
  NSError* readError = nil;
  NSData* data = [NSData dataWithContentsOfURL:fileURL
                                       options:NSDataReadingMappedIfSafe
                                         error:&readError];

  if (!data) {
    if (error) {
      *error = [self parsingErrorWithCode:DNSRuleParserErrorFileMissing
                              description:@"Failed to read file"
                          underlyingError:readError];
    }
    return nil;
  }

  // Parse the data
  return [self parseData:data error:error];
}

- (BOOL)canParseData:(NSData*)data {
  // Default implementation - check if data is not empty
  return data && data.length > 0;
}

- (void)setProgressHandler:(void (^)(double))progressHandler {
  _progressHandler = progressHandler;
}

#pragma mark - Helper Methods

- (void)reportProgress:(double)progress {
  if (self.progressHandler) {
    dispatch_async(dispatch_get_main_queue(), ^{
      self.progressHandler(progress);
    });
  }
}

- (NSError*)parsingErrorWithCode:(NSInteger)code description:(NSString*)description {
  return DNSMakeError(DNSRuleParserErrorDomain, code, description);
}

- (NSError*)parsingErrorWithCode:(NSInteger)code
                     description:(NSString*)description
                 underlyingError:(nullable NSError*)underlyingError {
  return DNSMakeErrorWithUnderlying(DNSRuleParserErrorDomain, code, description, underlyingError);
}

#pragma mark - Domain Validation Helpers

- (BOOL)isValidDomain:(NSString*)domain {
  if (!domain || domain.length == 0) {
    return NO;
  }

  // Basic validation rules
  // - No spaces or special characters (except dot, dash, and wildcard)
  // - Must not start or end with dot
  // - No consecutive dots
  // - Valid characters: a-z, A-Z, 0-9, -, ., *

  NSCharacterSet* validChars =
      [NSCharacterSet characterSetWithCharactersInString:
                          @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.*"];
  NSCharacterSet* domainChars = [NSCharacterSet characterSetWithCharactersInString:domain];

  if (![validChars isSupersetOfSet:domainChars]) {
    return NO;
  }

  // Check for invalid patterns
  if ([domain hasPrefix:@"."] || [domain hasSuffix:@"."]) {
    return NO;
  }

  if ([domain containsString:@".."]) {
    return NO;
  }

  // Check individual labels
  NSArray* labels = [domain componentsSeparatedByString:@"."];
  for (NSString* label in labels) {
    if (label.length == 0) {
      return NO;
    }

    // Labels can't start or end with dash (except wildcard)
    if (![label isEqualToString:@"*"]) {
      if ([label hasPrefix:@"-"] || [label hasSuffix:@"-"]) {
        return NO;
      }
    }
  }

  return YES;
}

- (NSString*)normalizeDomain:(NSString*)domain {
  // Convert to lowercase and trim whitespace
  NSString* normalized = [[domain lowercaseString]
      stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

  // Remove trailing dot if present (FQDN notation)
  if ([normalized hasSuffix:@"."]) {
    normalized = [normalized substringToIndex:normalized.length - 1];
  }

  // Remove common prefixes that might be included
  if ([normalized hasPrefix:@"http://"]) {
    normalized = [normalized substringFromIndex:7];
  } else if ([normalized hasPrefix:@"https://"]) {
    normalized = [normalized substringFromIndex:8];
  }

  // Remove everything after first slash (path)
  NSRange slashRange = [normalized rangeOfString:@"/"];
  if (slashRange.location != NSNotFound) {
    normalized = [normalized substringToIndex:slashRange.location];
  }

  // Remove port number if present
  NSRange colonRange = [normalized rangeOfString:@":" options:NSBackwardsSearch];
  if (colonRange.location != NSNotFound) {
    NSString* possiblePort = [normalized substringFromIndex:colonRange.location + 1];
    if ([possiblePort
            rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]]
            .location == NSNotFound) {
      normalized = [normalized substringToIndex:colonRange.location];
    }
  }

  return normalized;
}

- (BOOL)isWildcardDomain:(NSString*)domain {
  return [domain containsString:@"*"];
}

#pragma mark - Metadata Extraction Helpers

- (nullable NSDate*)parseDateString:(NSString*)dateString {
  if (!dateString || dateString.length == 0) {
    return nil;
  }

  // Try common date formats
  NSArray* dateFormats = @[
    @"yyyy-MM-dd'T'HH:mm:ssZ",  // ISO 8601
    @"yyyy-MM-dd HH:mm:ss", @"yyyy-MM-dd", @"MM/dd/yyyy", @"dd/MM/yyyy",
    @"EEE, dd MMM yyyy HH:mm:ss zzz"  // RFC 822
  ];

  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];

  for (NSString* format in dateFormats) {
    formatter.dateFormat = format;
    NSDate* date = [formatter dateFromString:dateString];
    if (date) {
      return date;
    }
  }

  // Try timestamp
  NSTimeInterval timestamp = [dateString doubleValue];
  if (timestamp > 0) {
    // Check if it's a reasonable timestamp (between 2000 and 2100)
    NSDate* date = [NSDate dateWithTimeIntervalSince1970:timestamp];
    NSCalendar* calendar = [NSCalendar currentCalendar];
    NSInteger year = [calendar component:NSCalendarUnitYear fromDate:date];
    if (year >= 2000 && year <= 2100) {
      return date;
    }
  }

  return nil;
}

- (nullable NSString*)extractVersionFromString:(NSString*)string {
  if (!string || string.length == 0) {
    return nil;
  }

  // Look for common version patterns
  NSError* error = nil;
  NSRegularExpression* versionRegex =
      [NSRegularExpression regularExpressionWithPattern:@"v?\\d+\\.\\d+(\\.\\d+)?"
                                                options:NSRegularExpressionCaseInsensitive
                                                  error:&error];

  if (!error) {
    NSTextCheckingResult* match = [versionRegex firstMatchInString:string
                                                           options:0
                                                             range:NSMakeRange(0, string.length)];
    if (match) {
      return [string substringWithRange:match.range];
    }
  }

  return nil;
}

@end

#pragma mark - Parser Factory Implementation

@interface RuleParserFactory ()
@property(class, readonly) NSMutableDictionary<NSString*, Class>* parserRegistry;
@end

@implementation RuleParserFactory

static NSMutableDictionary<NSString*, Class>* _parserRegistry = nil;

+ (NSMutableDictionary<NSString*, Class>*)parserRegistry {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    _parserRegistry = [NSMutableDictionary dictionary];
  });
  return _parserRegistry;
}

+ (void)registerParserClass:(Class<RuleParser>)parserClass forFormat:(NSString*)format {
  if (!parserClass || !format) {
    DNSLogError(LogCategoryRuleParsing, "Cannot register nil parser class or format");
    return;
  }

  // Verify the class conforms to RuleParser protocol
  if (![parserClass conformsToProtocol:@protocol(RuleParser)]) {
    DNSLogError(LogCategoryRuleParsing, "Parser class %@ does not conform to RuleParser protocol",
                NSStringFromClass(parserClass));
    return;
  }

  @synchronized(self.parserRegistry) {
    self.parserRegistry[format.lowercaseString] = parserClass;
    DNSLogInfo(LogCategoryRuleParsing, "Registered parser %@ for format: %@",
               NSStringFromClass(parserClass), format);
  }
}

+ (nullable id<RuleParser>)parserForFormat:(NSString*)format {
  if (!format) {
    return nil;
  }

  Class parserClass = nil;
  @synchronized(self.parserRegistry) {
    parserClass = self.parserRegistry[format.lowercaseString];
  }

  if (parserClass) {
    return [[parserClass alloc] init];
  }

  DNSLogDebug(LogCategoryRuleParsing, "No parser registered for format: %@", format);
  return nil;
}

+ (nullable id<RuleParser>)parserForFileExtension:(NSString*)extension {
  if (!extension) {
    return nil;
  }

  NSString* ext = extension.lowercaseString;
  if ([ext hasPrefix:@"."]) {
    ext = [ext substringFromIndex:1];
  }

  // Check all registered parsers
  @synchronized(self.parserRegistry) {
    for (NSString* format in self.parserRegistry) {
      Class parserClass = self.parserRegistry[format];
      id<RuleParser> parser = [[parserClass alloc] init];

      if ([parser.supportedExtensions containsObject:ext]) {
        return parser;
      }
    }
  }

  return nil;
}

+ (nullable id<RuleParser>)parserForMIMEType:(NSString*)mimeType {
  if (!mimeType) {
    return nil;
  }

  // Check all registered parsers
  @synchronized(self.parserRegistry) {
    for (NSString* format in self.parserRegistry) {
      Class parserClass = self.parserRegistry[format];
      id<RuleParser> parser = [[parserClass alloc] init];

      if ([parser.supportedMIMETypes containsObject:mimeType]) {
        return parser;
      }
    }
  }

  return nil;
}

+ (nullable id<RuleParser>)parserForData:(NSData*)data {
  if (!data || data.length == 0) {
    return nil;
  }

  // Try to detect format from data content
  NSString* dataString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

  if (dataString) {
    // Check for JSON
    if ([dataString hasPrefix:@"{"] || [dataString hasPrefix:@"["]) {
      return [self parserForFormat:@"json"];
    }

    // Check for YAML
    if ([dataString hasPrefix:@"---"] || [dataString containsString:@"\n- "] ||
        [dataString containsString:@":\n"] || [dataString containsString:@": "]) {
      return [self parserForFormat:@"yaml"];
    }

    // Check for hosts file format
    if ([dataString containsString:@"0.0.0.0 "] || [dataString containsString:@"127.0.0.1 "]) {
      return [self parserForFormat:@"hosts"];
    }
  }

  return nil;
}

+ (NSArray<NSString*>*)registeredFormats {
  @synchronized(self.parserRegistry) {
    return [self.parserRegistry.allKeys copy];
  }
}

+ (BOOL)isFormatSupported:(NSString*)format {
  if (!format) {
    return NO;
  }

  @synchronized(self.parserRegistry) {
    return self.parserRegistry[format.lowercaseString] != nil;
  }
}

@end
