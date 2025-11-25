//
//  JSONRuleParser.h
//  DNShield Network Extension
//
//  Parser for JSON format rule lists
//  Supports standard JSON format with blocked/whitelist arrays
//

#import <Foundation/Foundation.h>
#import <Rule/Parser.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - JSON Format Support

/*
 * Expected JSON format:
 * {
 *   "version": "1.0",
 *   "name": "Rule List Name",
 *   "updated": "2024-01-01T00:00:00Z" or timestamp,
 *   "author": "Author Name",
 *   "description": "Description of the list",
 *   "source": "https://example.com/rules.json",
 *   "license": "MIT",
 *   "blocked": [
 *     "ad.example.com",
 *     "*.tracking.com",
 *     {"domain": "spam.com", "priority": 100, "comment": "Known spam domain"}
 *   ],
 *   "whitelist": [
 *     "safe.example.com",
 *     {"domain": "trusted.com", "priority": 100}
 *   ],
 *   "metadata": {
 *     "custom_field": "value"
 *   }
 * }
 */

@interface JSONRuleParser : RuleParserBase

// Parser options
@property(nonatomic, strong) RuleParserOptions* options;

// Initialize with custom options
- (instancetype)initWithOptions:(nullable RuleParserOptions*)options;

@end

#pragma mark - JSON Schema Validation

@interface JSONRuleSchema : NSObject

// Validate JSON structure
+ (BOOL)validateJSONStructure:(NSDictionary*)json error:(NSError**)error;

// Check if JSON has minimum required fields
+ (BOOL)hasRequiredFields:(NSDictionary*)json;

// Extract version from JSON
+ (nullable NSString*)extractVersion:(NSDictionary*)json;

@end

NS_ASSUME_NONNULL_END
