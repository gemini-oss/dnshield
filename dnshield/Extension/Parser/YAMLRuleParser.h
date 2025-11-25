//
//  YAMLRuleParser.h
//  DNShield Network Extension
//
//  Parser for YAML format rule lists
//  Supports standard YAML format with blocked/whitelist arrays
//

#import <Foundation/Foundation.h>
#import "Rule/Parser.h"

NS_ASSUME_NONNULL_BEGIN

#pragma mark - YAML Format Support

/*
 * Expected YAML format:
 * ---
 * version: "1.0"
 * name: "Rule List Name"
 * updated: "2024-01-01T00:00:00Z"
 * author: "Author Name"
 * description: "Description of the list"
 * source: "https://example.com/rules.yaml"
 * license: "MIT"
 *
 * blocked:
 *   - ad.example.com
 *   - "*.tracking.com"
 *   - domain: spam.com
 *     priority: 100
 *     comment: "Known spam domain"
 *
 * whitelist:
 *   - safe.example.com
 *   - domain: trusted.com
 *     priority: 100
 *
 * metadata:
 *   custom_field: value
 *
 * Minimal format:
 * ---
 * blocked:
 *   - ad.com
 *   - spam.com
 * whitelist:
 *   - good.com
 */

@interface YAMLRuleParser : RuleParserBase

// Parser options
@property(nonatomic, strong) RuleParserOptions* options;

// Initialize with custom options
- (instancetype)initWithOptions:(nullable RuleParserOptions*)options;

@end

#pragma mark - YAML Parsing Helpers

@interface YAMLParseHelper : NSObject

// Parse YAML string into native objects
+ (nullable id)parseYAMLString:(NSString*)yamlString error:(NSError**)error;

// Check if string looks like YAML
+ (BOOL)isLikelyYAML:(NSString*)string;

// Extract indentation level
+ (NSInteger)indentationLevel:(NSString*)line;

// Parse a YAML value (handles quotes, types)
+ (nullable id)parseYAMLValue:(NSString*)value;

@end

NS_ASSUME_NONNULL_END
