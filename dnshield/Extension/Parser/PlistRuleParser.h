//
//  PlistRuleParser.h
//  DNShield Network Extension
//
//  Parser for Property List (plist) format rule lists
//  Supports both XML and binary plist formats with blocked/whitelist arrays
//

#import <Extension/Rule/Parser.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Plist Format Support

/*
 * Expected Plist format (XML):
 * <?xml version="1.0" encoding="UTF-8"?>
 * <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 * "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0"> <dict> <key>version</key>
 *     <string>1.0</string>
 *     <key>name</key>
 *     <string>Rule List Name</string>
 *     <key>updated</key>
 *     <date>2024-01-01T00:00:00Z</date>
 *     <key>author</key>
 *     <string>Author Name</string>
 *     <key>description</key>
 *     <string>Description of the list</string>
 *     <key>source</key>
 *     <string>https://example.com/rules.plist</string>
 *     <key>license</key>
 *     <string>MIT</string>
 *     <key>blocked</key>
 *     <array>
 *         <string>ad.example.com</string>
 *         <string>*.tracking.com</string>
 *         <dict>
 *             <key>domain</key>
 *             <string>spam.com</string>
 *             <key>priority</key>
 *             <integer>100</integer>
 *             <key>comment</key>
 *             <string>Known spam domain</string>
 *         </dict>
 *     </array>
 *     <key>whitelist</key>
 *     <array>
 *         <string>safe.example.com</string>
 *         <dict>
 *             <key>domain</key>
 *             <string>trusted.com</string>
 *             <key>priority</key>
 *             <integer>100</integer>
 *         </dict>
 *     </array>
 *     <key>metadata</key>
 *     <dict>
 *         <key>custom_field</key>
 *         <string>value</string>
 *     </dict>
 * </dict>
 * </plist>
 *
 * Minimal format:
 * <dict>
 *     <key>blocked</key>
 *     <array>
 *         <string>ad.com</string>
 *         <string>spam.com</string>
 *     </array>
 *     <key>whitelist</key>
 *     <array>
 *         <string>good.com</string>
 *     </array>
 * </dict>
 */

@interface PlistRuleParser : RuleParserBase

// Parser options
@property(nonatomic, strong) RuleParserOptions* options;

// Initialize with custom options
- (instancetype)initWithOptions:(nullable RuleParserOptions*)options;

@end

#pragma mark - Plist Validation

@interface PlistValidation : NSObject

// Validate plist structure
+ (BOOL)validatePlistStructure:(id)plist error:(NSError**)error;

// Check if plist has minimum required fields
+ (BOOL)hasRequiredFields:(NSDictionary*)plist;

// Extract version from plist
+ (nullable NSString*)extractVersion:(NSDictionary*)plist;

// Detect plist format (XML or binary)
+ (NSPropertyListFormat)detectPlistFormat:(NSData*)data;

@end

NS_ASSUME_NONNULL_END
