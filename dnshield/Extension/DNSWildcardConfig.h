//
//  DNSWildcardConfig.h
//  DNShield Network Extension
//
//  Configuration for wildcard domain matching behavior
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, DNSWildcardMode) {
  // Default mode: *.example.com only blocks subdomains
  DNSWildcardModeSubdomainsOnly = 0,

  // Enhanced mode: *.example.com blocks root domain AND subdomains
  DNSWildcardModeIncludeRoot = 1,

  // Smart mode: Automatically include root unless explicitly allowed
  DNSWildcardModeSmart = 2
};

@interface DNSWildcardConfig : NSObject

@property(nonatomic, readonly) DNSWildcardMode mode;
@property(nonatomic, readonly) BOOL respectAllowlistPrecedence;

+ (instancetype)sharedConfig;

- (void)setMode:(DNSWildcardMode)mode;
- (void)setRespectAllowlistPrecedence:(BOOL)respect;

// Check if a wildcard rule should match the root domain
- (BOOL)wildcardShouldMatchRoot:(NSString*)wildcardDomain;

// Load configuration from preferences
- (void)loadConfiguration;

// Save configuration to preferences
- (void)saveConfiguration;

@end

NS_ASSUME_NONNULL_END
