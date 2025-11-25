//
//  HTTPRuleFetcher.h
//  DNShield Network Extension
//
//  Fetcher implementation for downloading rule lists from HTTPS URLs
//  Supports authentication, resume, and progress tracking
//

#import <Extension/Rule/Fetcher.h>

NS_ASSUME_NONNULL_BEGIN

// HTTP-specific configuration keys
extern NSString* const HTTPRuleFetcherConfigKeyURL;  // NSString (required)
extern NSString* const
    HTTPRuleFetcherConfigKeyAuthType;  // NSString: "none", "basic", "bearer", "apikey"
extern NSString* const HTTPRuleFetcherConfigKeyAuthCredentials;  // NSDictionary with auth details
extern NSString* const HTTPRuleFetcherConfigKeyHeaders;          // NSDictionary of custom headers
extern NSString* const HTTPRuleFetcherConfigKeyFollowRedirects;  // NSNumber (BOOL)
extern NSString* const HTTPRuleFetcherConfigKeyMaxRedirects;     // NSNumber
extern NSString* const HTTPRuleFetcherConfigKeyAcceptedStatusCodes;  // NSArray<NSNumber>
extern NSString* const HTTPRuleFetcherConfigKeyValidateSSL;          // NSNumber (BOOL)
extern NSString* const
    HTTPRuleFetcherConfigKeyPinnedCertificates;  // NSArray<NSData> (certificate data)

// Authentication types
typedef NS_ENUM(NSInteger, HTTPAuthType) {
  HTTPAuthTypeNone = 0,
  HTTPAuthTypeBasic,
  HTTPAuthTypeBearer,
  HTTPAuthTypeAPIKey
};

// Authentication credential keys
extern NSString* const HTTPAuthCredentialKeyUsername;      // For basic auth
extern NSString* const HTTPAuthCredentialKeyPassword;      // For basic auth
extern NSString* const HTTPAuthCredentialKeyToken;         // For bearer auth
extern NSString* const HTTPAuthCredentialKeyAPIKey;        // For API key auth
extern NSString* const HTTPAuthCredentialKeyAPIKeyHeader;  // Header name for API key

@interface HTTPRuleFetcher : RuleFetcherBase <NSURLSessionDataDelegate, NSURLSessionTaskDelegate>

// URL to fetch from
@property(nonatomic, strong, readonly) NSURL* URL;

// Authentication settings
@property(nonatomic, assign, readonly) HTTPAuthType authType;

// SSL validation
@property(nonatomic, assign) BOOL validateSSL;

// Custom headers
@property(nonatomic, strong, nullable) NSDictionary<NSString*, NSString*>* customHeaders;

// Redirect settings
@property(nonatomic, assign) BOOL followRedirects;
@property(nonatomic, assign) NSUInteger maxRedirects;

// Initialize with URL
- (instancetype)initWithURL:(NSURL*)URL;
- (instancetype)initWithURL:(NSURL*)URL configuration:(nullable NSDictionary*)configuration;

// Configure authentication
- (void)configureBasicAuthWithUsername:(NSString*)username password:(NSString*)password;
- (void)configureBearerAuthWithToken:(NSString*)token;
- (void)configureAPIKeyAuth:(NSString*)apiKey headerName:(NSString*)headerName;

// Certificate pinning
- (void)addPinnedCertificate:(NSData*)certificateData;
- (void)clearPinnedCertificates;

// Get current download progress (0.0 - 1.0)
@property(nonatomic, readonly) float currentProgress;

// Get download speed in bytes per second
@property(nonatomic, readonly) NSUInteger downloadSpeed;

@end

NS_ASSUME_NONNULL_END
