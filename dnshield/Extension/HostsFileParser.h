//
//  HostsFileParser.h
//  DNShield Network Extension
//
//  Parser for hosts file format rule lists
//  Supports standard hosts file format with 0.0.0.0 or 127.0.0.1 entries
//

#import <Foundation/Foundation.h>
#import <Rule/Parser.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Hosts File Format Support

/*
 * Expected hosts file format:
 * # Comments start with hash
 * 0.0.0.0 ad.example.com
 * 127.0.0.1 tracker.example.com
 * 0.0.0.0 spam.example.com # inline comment
 *
 * # Whitelist entries (custom extension)
 * # @whitelist safe.example.com
 * # @allow trusted.example.com
 *
 * Also supports:
 * - Multiple domains per line: 0.0.0.0 ad1.com ad2.com ad3.com
 * - IPv6: ::1 ad.example.com
 * - Wildcards: 0.0.0.0 *.tracking.com
 * - Metadata in comments: # Title: My Blocklist
 */

@interface HostsFileParser : RuleParserBase

// Parser options
@property(nonatomic, strong) RuleParserOptions* options;

// Hosts-specific options
@property(nonatomic) BOOL parseWhitelistComments;  // Parse @whitelist/@allow comments
@property(nonatomic) BOOL parseMetadataComments;   // Extract metadata from comments
@property(nonatomic) BOOL allowIPv6;               // Accept ::1 entries
@property(nonatomic) BOOL strictIPValidation;      // Validate IP addresses

// Initialize with custom options
- (instancetype)initWithOptions:(nullable RuleParserOptions*)options;

@end

#pragma mark - Hosts File Utilities

@interface HostsFileUtilities : NSObject

// Check if line is a valid hosts entry
+ (BOOL)isValidHostsLine:(NSString*)line;

// Extract domains from a hosts line
+ (nullable NSArray<NSString*>*)extractDomainsFromLine:(NSString*)line;

// Check if IP address is a blocking address (0.0.0.0, 127.0.0.1, ::1)
+ (BOOL)isBlockingIP:(NSString*)ip;

// Parse metadata from comment
+ (nullable NSDictionary*)parseMetadataComment:(NSString*)comment;

// Check for whitelist directive
+ (BOOL)isWhitelistComment:(NSString*)comment;

// Extract domain from whitelist comment
+ (nullable NSString*)extractDomainFromWhitelistComment:(NSString*)comment;

@end

NS_ASSUME_NONNULL_END
