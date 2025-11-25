//
//  Manager+ParserIntegration.h
//  DNShield Network Extension
//
//  Enhanced parser integration additions for RuleManager
//  These methods should be added to RuleManager.h or implemented as a category
//

#import <Foundation/Foundation.h>
#import "RuleManager.h"
#import "RuleParser.h"
#import "RuleSet.h"

NS_ASSUME_NONNULL_BEGIN

// Error codes specific to parser integration
typedef NS_ENUM(NSInteger, DNSRuleManagerParserError) {
  DNSRuleManagerErrorParsingFailed = 2001,
  DNSRuleManagerErrorEmptyResponse = 2002,
  DNSRuleManagerErrorDataTooLarge = 2003,
  DNSRuleManagerErrorUnsupportedFormat = 2004,
  DNSRuleManagerErrorCorruptedData = 2005,
  DNSRuleManagerErrorValidationFailed = 2006
};

@interface RuleManager (ParserIntegration)

#pragma mark - Parser Management

// Create and configure parser for a specific source
- (nullable id<RuleParser>)createAndConfigureParserForSource:(RuleSource*)source;

#pragma mark - Data Parsing

// Parse data using appropriate parser for source
- (nullable RuleSet*)parseData:(NSData*)data forSource:(RuleSource*)source error:(NSError**)error;

#pragma mark - Validation

// Validate parsed rule set against source requirements
- (BOOL)validateRuleSet:(RuleSet*)ruleSet forSource:(RuleSource*)source error:(NSError**)error;

#pragma mark - Error Handling

// Convert parser errors to rule manager errors
- (NSError*)ruleManagerErrorFromParserError:(NSError*)error;

@end

#pragma mark - Configuration Extensions

// Additional configuration keys for parser integration
extern NSString* const RuleSourceConfigKeyParserOptions;  // NSDictionary
extern NSString* const RuleSourceConfigKeyValidation;     // NSDictionary

// Parser option keys
extern NSString* const ParserOptionKeyStrictMode;       // NSNumber (BOOL)
extern NSString* const ParserOptionKeyValidateDomains;  // NSNumber (BOOL)
extern NSString* const ParserOptionKeyMaxRules;         // NSNumber (NSUInteger)
extern NSString* const ParserOptionKeyMaxFileSize;      // NSNumber (NSUInteger)
extern NSString* const ParserOptionKeyExtractMetadata;  // NSNumber (BOOL)

// Validation option keys
extern NSString* const ValidationOptionKeyMinRules;     // NSNumber (NSUInteger)
extern NSString* const ValidationOptionKeyMaxAgeHours;  // NSNumber (double)

// Merge configuration keys
extern NSString* const MergeConfigKeyCombineMetadata;  // NSNumber (BOOL)
extern NSString* const MergeConfigKeyMergeStatistics;  // NSNumber (BOOL)

NS_ASSUME_NONNULL_END
