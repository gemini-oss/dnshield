//
//  Parser.h
//  DNShield Network Extension
//
//  Abstract base class/protocol for rule list parsers
//  Defines the interface that all format-specific parsers must implement
//

#import <Foundation/Foundation.h>
#import "RuleSet.h"

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Parser Capabilities

typedef NS_OPTIONS(NSUInteger, RuleParserCapabilities) {
  RuleParserCapabilityNone = 0,
  RuleParserCapabilityStreaming = 1 << 0,   // Can parse data in chunks
  RuleParserCapabilityMetadata = 1 << 1,    // Can extract metadata
  RuleParserCapabilityValidation = 1 << 2,  // Performs validation
  RuleParserCapabilityComments = 1 << 3,    // Preserves comments
  RuleParserCapabilityPriorities = 1 << 4,  // Supports rule priorities
  RuleParserCapabilityWildcards = 1 << 5,   // Supports wildcard domains
  RuleParserCapabilityCompressed = 1 << 6   // Can handle compressed data
};

#pragma mark - Parser Protocol

@protocol RuleParser <NSObject>

@required
// Parse data and return a RuleSet
- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error;

// Parser format identifier (e.g., "json", "yaml", "hosts")
@property(nonatomic, readonly) NSString* formatIdentifier;

// Parser capabilities
@property(nonatomic, readonly) RuleParserCapabilities capabilities;

// Supported file extensions
@property(nonatomic, readonly) NSArray<NSString*>* supportedExtensions;

// MIME types this parser can handle
@property(nonatomic, readonly) NSArray<NSString*>* supportedMIMETypes;

@optional
// Parse from file URL (default implementation uses parseData:)
- (nullable RuleSet*)parseFileAtURL:(NSURL*)fileURL error:(NSError**)error;

// Streaming parse support
- (void)beginStreamingParse;
- (BOOL)appendData:(NSData*)data error:(NSError**)error;
- (nullable RuleSet*)finishStreamingParseWithError:(NSError**)error;

// Validate data before parsing
- (BOOL)canParseData:(NSData*)data;

// Progress callback for large files
- (void)setProgressHandler:(nullable void (^)(double progress))progressHandler;

@end

#pragma mark - Base Parser Class

@interface RuleParserBase : NSObject <RuleParser>

// Subclasses must override these
@property(nonatomic, readonly) NSString* formatIdentifier;
@property(nonatomic, readonly) RuleParserCapabilities capabilities;
@property(nonatomic, readonly) NSArray<NSString*>* supportedExtensions;
@property(nonatomic, readonly) NSArray<NSString*>* supportedMIMETypes;

// Progress handling
@property(nonatomic, copy, nullable) void (^progressHandler)(double progress);

// Common initialization
- (instancetype)init NS_DESIGNATED_INITIALIZER;

// Subclasses must implement this
- (nullable RuleSet*)parseData:(NSData*)data error:(NSError**)error;

// Default implementation provided
- (nullable RuleSet*)parseFileAtURL:(NSURL*)fileURL error:(NSError**)error;

// Helper methods for subclasses
- (void)reportProgress:(double)progress;
- (NSError*)parsingErrorWithCode:(NSInteger)code description:(NSString*)description;
- (NSError*)parsingErrorWithCode:(NSInteger)code
                     description:(NSString*)description
                 underlyingError:(nullable NSError*)underlyingError;

// Domain validation helpers
- (BOOL)isValidDomain:(NSString*)domain;
- (NSString*)normalizeDomain:(NSString*)domain;
- (BOOL)isWildcardDomain:(NSString*)domain;

// Metadata extraction helpers
- (nullable NSDate*)parseDateString:(NSString*)dateString;
- (nullable NSString*)extractVersionFromString:(NSString*)string;

@end

#pragma mark - Parser Options

@interface RuleParserOptions : NSObject

// Parsing behavior
@property(nonatomic) BOOL strictMode;              // Fail on any error vs skip invalid entries
@property(nonatomic) BOOL allowDuplicates;         // Allow duplicate domains
@property(nonatomic) BOOL normalizeCase;           // Convert domains to lowercase
@property(nonatomic) BOOL validateDomains;         // Validate domain format
@property(nonatomic) NSUInteger maxRuleCount;      // Maximum rules to parse (0 = unlimited)
@property(nonatomic) NSTimeInterval parseTimeout;  // Timeout for parsing operation

// Default rules
@property(nonatomic) RuleAction defaultAction;  // Default action for rules without explicit action
@property(nonatomic) RulePriority defaultPriority;  // Default priority for rules

// Performance tuning
@property(nonatomic) BOOL buildIndexWhileParsing;  // Build domain index during parsing
@property(nonatomic) NSUInteger batchSize;         // Process rules in batches

+ (instancetype)defaultOptions;
+ (instancetype)strictOptions;
+ (instancetype)performanceOptions;

@end

#pragma mark - Parser Factory

@interface RuleParserFactory : NSObject

// Register a parser class for a format
+ (void)registerParserClass:(Class<RuleParser>)parserClass forFormat:(NSString*)format;

// Get parser for format
+ (nullable id<RuleParser>)parserForFormat:(NSString*)format;

// Get parser for file extension
+ (nullable id<RuleParser>)parserForFileExtension:(NSString*)extension;

// Get parser for MIME type
+ (nullable id<RuleParser>)parserForMIMEType:(NSString*)mimeType;

// Get parser by trying to detect format from data
+ (nullable id<RuleParser>)parserForData:(NSData*)data;

// Get all registered formats
+ (NSArray<NSString*>*)registeredFormats;

// Check if format is supported
+ (BOOL)isFormatSupported:(NSString*)format;

@end

#pragma mark - Parser Delegate

@protocol RuleParserDelegate <NSObject>

@optional
// Called when parser encounters a warning (non-fatal issue)
- (void)parser:(id<RuleParser>)parser
    didEncounterWarning:(NSString*)warning
                 atLine:(NSUInteger)lineNumber;

// Called when parser skips an invalid entry
- (void)parser:(id<RuleParser>)parser didSkipInvalidEntry:(NSString*)entry reason:(NSString*)reason;

// Called periodically during parsing
- (void)parser:(id<RuleParser>)parser didParseRules:(NSUInteger)ruleCount progress:(double)progress;

// Called when metadata is extracted
- (void)parser:(id<RuleParser>)parser didExtractMetadata:(RuleSetMetadata*)metadata;

@end

NS_ASSUME_NONNULL_END
