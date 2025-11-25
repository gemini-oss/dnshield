//
//  HTTPRuleFetcher.m
//  DNShield Network Extension
//
//  Implementation of HTTPS-based rule fetching with authentication and SSL validation
//

#import "HTTPRuleFetcher.h"
#import <CommonCrypto/CommonDigest.h>
#import "../Common/ErrorTypes.h"
#import "../Common/LoggingManager.h"

// Configuration keys
NSString* const HTTPRuleFetcherConfigKeyURL = @"url";
NSString* const HTTPRuleFetcherConfigKeyAuthType = @"authType";
NSString* const HTTPRuleFetcherConfigKeyAuthCredentials = @"authCredentials";
NSString* const HTTPRuleFetcherConfigKeyHeaders = @"headers";
NSString* const HTTPRuleFetcherConfigKeyFollowRedirects = @"followRedirects";
NSString* const HTTPRuleFetcherConfigKeyMaxRedirects = @"maxRedirects";
NSString* const HTTPRuleFetcherConfigKeyAcceptedStatusCodes = @"acceptedStatusCodes";
NSString* const HTTPRuleFetcherConfigKeyValidateSSL = @"validateSSL";
NSString* const HTTPRuleFetcherConfigKeyPinnedCertificates = @"pinnedCertificates";

// Authentication credential keys
NSString* const HTTPAuthCredentialKeyUsername = @"username";
NSString* const HTTPAuthCredentialKeyPassword = @"password";
NSString* const HTTPAuthCredentialKeyToken = @"token";
NSString* const HTTPAuthCredentialKeyAPIKey = @"apiKey";
NSString* const HTTPAuthCredentialKeyAPIKeyHeader = @"apiKeyHeader";

@interface HTTPRuleFetcher ()
@property(nonatomic, strong) NSURLSession* session;
@property(nonatomic, strong) NSURLSessionTask* currentTask;
@property(nonatomic, strong) NSMutableData* downloadedData;
@property(nonatomic, strong) NSData* resumeData;
@property(nonatomic, strong) NSDictionary* authCredentials;
@property(nonatomic, strong) NSMutableArray<NSData*>* pinnedCertificates;
@property(nonatomic, strong) NSSet<NSNumber*>* acceptedStatusCodes;
@property(nonatomic, assign) NSUInteger redirectCount;
@property(nonatomic, assign) NSUInteger expectedContentLength;
@property(nonatomic, assign) NSUInteger bytesReceived;
@property(nonatomic, strong) NSDate* downloadStartTime;
@property(nonatomic, strong) NSDate* lastSpeedCalculationTime;
@property(nonatomic, assign) NSUInteger lastBytesReceived;
@property(nonatomic, copy) RuleFetcherCompletionBlock completionBlock;
@property(nonatomic, strong) NSMutableDictionary* statistics;
@property(nonatomic, assign) BOOL completionDelivered;
@end

@implementation HTTPRuleFetcher

#pragma mark - Initialization

- (instancetype)initWithURL:(NSURL*)URL {
  return [self initWithURL:URL configuration:nil];
}

- (instancetype)initWithURL:(NSURL*)URL configuration:(nullable NSDictionary*)configuration {
  // Add URL to configuration
  NSMutableDictionary* config = [NSMutableDictionary dictionaryWithDictionary:configuration ?: @{}];
  config[HTTPRuleFetcherConfigKeyURL] = URL.absoluteString;

  self = [super initWithConfiguration:config];
  if (self) {
    _URL = URL;
    _pinnedCertificates = [NSMutableArray array];
    _validateSSL = YES;
    _statistics = [NSMutableDictionary dictionary];
    _followRedirects = YES;
    _maxRedirects = 5;
    _acceptedStatusCodes = [NSSet setWithArray:@[ @200, @201, @202, @203, @204, @205, @206 ]];
    _completionDelivered = NO;

    // Apply configuration first so timeout is set before creating session
    [self applyHTTPConfiguration:configuration];
    [self setupSession];

    DNSLogDebug(LogCategoryRuleFetching, "HTTPRuleFetcher initialized for URL: %@", URL);
  }
  return self;
}

- (void)dealloc {
  [self.session invalidateAndCancel];
}

#pragma mark - Configuration

- (void)applyHTTPConfiguration:(NSDictionary*)config {
  if (!config)
    return;

  // Auth type
  NSString* authTypeString = config[HTTPRuleFetcherConfigKeyAuthType];
  if (authTypeString) {
    _authType = [self authTypeFromString:authTypeString];
  }

  // Auth credentials
  NSDictionary* authCreds = config[HTTPRuleFetcherConfigKeyAuthCredentials];
  if (authCreds) {
    self.authCredentials = authCreds;
  }

  // Custom headers
  NSDictionary* headers = config[HTTPRuleFetcherConfigKeyHeaders];
  if (headers) {
    self.customHeaders = headers;
  }

  // Redirect settings
  NSNumber* followRedirects = config[HTTPRuleFetcherConfigKeyFollowRedirects];
  if (followRedirects) {
    self.followRedirects = [followRedirects boolValue];
  }

  NSNumber* maxRedirects = config[HTTPRuleFetcherConfigKeyMaxRedirects];
  if (maxRedirects) {
    self.maxRedirects = [maxRedirects unsignedIntegerValue];
  }

  // SSL validation
  NSNumber* validateSSL = config[HTTPRuleFetcherConfigKeyValidateSSL];
  if (validateSSL) {
    self.validateSSL = [validateSSL boolValue];
  }

  // Pinned certificates
  NSArray* pinnedCerts = config[HTTPRuleFetcherConfigKeyPinnedCertificates];
  if (pinnedCerts) {
    [self.pinnedCertificates addObjectsFromArray:pinnedCerts];
  }

  // Accepted status codes
  NSArray* statusCodes = config[HTTPRuleFetcherConfigKeyAcceptedStatusCodes];
  if (statusCodes) {
    self.acceptedStatusCodes = [NSSet setWithArray:statusCodes];
  }
}

- (HTTPAuthType)authTypeFromString:(NSString*)authTypeString {
  if ([authTypeString isEqualToString:@"basic"])
    return HTTPAuthTypeBasic;
  if ([authTypeString isEqualToString:@"bearer"])
    return HTTPAuthTypeBearer;
  if ([authTypeString isEqualToString:@"apikey"])
    return HTTPAuthTypeAPIKey;
  return HTTPAuthTypeNone;
}

#pragma mark - Authentication Configuration

- (void)configureBasicAuthWithUsername:(NSString*)username password:(NSString*)password {
  _authType = HTTPAuthTypeBasic;
  self.authCredentials =
      @{HTTPAuthCredentialKeyUsername : username, HTTPAuthCredentialKeyPassword : password};
}

- (void)configureBearerAuthWithToken:(NSString*)token {
  _authType = HTTPAuthTypeBearer;
  self.authCredentials = @{HTTPAuthCredentialKeyToken : token};
}

- (void)configureAPIKeyAuth:(NSString*)apiKey headerName:(NSString*)headerName {
  _authType = HTTPAuthTypeAPIKey;
  self.authCredentials = @{
    HTTPAuthCredentialKeyAPIKey : apiKey,
    HTTPAuthCredentialKeyAPIKeyHeader : headerName ?: @"X-API-Key"
  };
}

#pragma mark - Certificate Pinning

- (void)addPinnedCertificate:(NSData*)certificateData {
  if (certificateData) {
    [self.pinnedCertificates addObject:certificateData];
  }
}

- (void)clearPinnedCertificates {
  [self.pinnedCertificates removeAllObjects];
}

#pragma mark - Session Setup

- (void)setupSession {
  NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
  config.timeoutIntervalForRequest = self.timeout;
  config.timeoutIntervalForResource = self.timeout * 3;  // Allow longer for total download
  config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
  config.URLCache = nil;
  config.waitsForConnectivity = NO;

  // Use standard HTTP/1.1 and HTTP/2 only - simpler and more reliable
  // HTTP/3 (QUIC) can cause delays with some CDNs

  // Create delegate queue
  NSOperationQueue* delegateQueue = [[NSOperationQueue alloc] init];
  delegateQueue.maxConcurrentOperationCount = 1;
  delegateQueue.name = [NSString stringWithFormat:@"com.dnshield.httpfetcher.%@", self.identifier];

  self.session = [NSURLSession sessionWithConfiguration:config
                                               delegate:self
                                          delegateQueue:delegateQueue];
}

#pragma mark - Request Building

- (NSMutableURLRequest*)buildRequest {
  NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:self.URL];
  request.timeoutInterval = self.timeout;
  request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;

  // Add authentication headers
  [self addAuthenticationToRequest:request];

  // Add custom headers
  if (self.customHeaders) {
    [self.customHeaders
        enumerateKeysAndObjectsUsingBlock:^(NSString* key, NSString* value, BOOL* stop) {
          [request setValue:value forHTTPHeaderField:key];
        }];
  }

  // Add user agent
  NSString* userAgent =
      [NSString stringWithFormat:@"DNShield/%@ (RuleFetcher; HTTP)",
                                 [[NSBundle mainBundle]
                                     objectForInfoDictionaryKey:@"CFBundleShortVersionString"]
                                     ?: @"1.0"];
  [request setValue:userAgent forHTTPHeaderField:@"User-Agent"];

  return request;
}

- (void)addAuthenticationToRequest:(NSMutableURLRequest*)request {
  switch (self.authType) {
    case HTTPAuthTypeBasic: {
      NSString* username = self.authCredentials[HTTPAuthCredentialKeyUsername];
      NSString* password = self.authCredentials[HTTPAuthCredentialKeyPassword];
      if (username && password) {
        NSString* authString = [NSString stringWithFormat:@"%@:%@", username, password];
        NSData* authData = [authString dataUsingEncoding:NSUTF8StringEncoding];
        NSString* authValue =
            [NSString stringWithFormat:@"Basic %@", [authData base64EncodedStringWithOptions:0]];
        [request setValue:authValue forHTTPHeaderField:@"Authorization"];
      }
      break;
    }

    case HTTPAuthTypeBearer: {
      NSString* token = self.authCredentials[HTTPAuthCredentialKeyToken];
      if (token) {
        NSString* authValue = [NSString stringWithFormat:@"Bearer %@", token];
        [request setValue:authValue forHTTPHeaderField:@"Authorization"];
      }
      break;
    }

    case HTTPAuthTypeAPIKey: {
      NSString* apiKey = self.authCredentials[HTTPAuthCredentialKeyAPIKey];
      NSString* headerName =
          self.authCredentials[HTTPAuthCredentialKeyAPIKeyHeader] ?: @"X-API-Key";
      if (apiKey) {
        [request setValue:apiKey forHTTPHeaderField:headerName];
      }
      break;
    }

    default: break;
  }
}

#pragma mark - RuleFetcher Override

- (void)performFetchWithCompletion:(RuleFetcherCompletionBlock)completion {
  // Don't overwrite completionBlock if it's already set by the base class
  if (!self.completionBlock) {
    self.completionBlock = completion;
  }
  self.completionDelivered = NO;
  self.downloadedData = [NSMutableData data];
  self.redirectCount = 0;
  self.bytesReceived = 0;
  self.expectedContentLength = 0;
  self.downloadStartTime = [NSDate date];
  self.lastSpeedCalculationTime = self.downloadStartTime;
  self.lastBytesReceived = 0;

  NSURLRequest* request = [self buildRequest];

  DNSLogInfo(LogCategoryRuleFetching, "Starting HTTP fetch from: %@", self.URL);

  self.currentTask = [self.session dataTaskWithRequest:request];
  [self.currentTask resume];
}

- (void)performCancelFetch {
  [self.currentTask cancel];
  self.currentTask = nil;
  self.downloadedData = nil;
}

- (BOOL)supportsResume {
  return YES;
}

- (void)resumeFetchWithCompletion:(RuleFetcherCompletionBlock)completion {
  if (!self.resumeData) {
    // No resume data, perform normal fetch
    [self fetchRulesWithCompletion:completion];
    return;
  }

  DNSLogInfo(LogCategoryRuleFetching, "Resuming HTTP fetch from: %@", self.URL);

  self.currentTask = [self.session downloadTaskWithResumeData:self.resumeData];
  [self.currentTask resume];
}

#pragma mark - Properties

- (float)currentProgress {
  if (self.expectedContentLength == 0) {
    return 0.0;
  }
  return (float)self.bytesReceived / (float)self.expectedContentLength;
}

- (NSUInteger)downloadSpeed {
  NSTimeInterval timeSinceLastCalculation =
      [[NSDate date] timeIntervalSinceDate:self.lastSpeedCalculationTime];
  if (timeSinceLastCalculation <= 0) {
    return 0;
  }

  NSUInteger bytesSinceLastCalculation = self.bytesReceived - self.lastBytesReceived;
  return (NSUInteger)(bytesSinceLastCalculation / timeSinceLastCalculation);
}

#pragma mark - Validation

- (BOOL)validateConfiguration:(NSError**)error {
  if (!self.URL) {
    if (error) {
      *error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorInvalidURL,
                            @"URL is required for HTTP fetcher");
    }
    return NO;
  }

  if (![self.URL.scheme isEqualToString:@"https"] && ![self.URL.scheme isEqualToString:@"http"]) {
    if (error) {
      *error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorInvalidURL,
                            @"Only HTTP/HTTPS URLs are supported");
    }
    return NO;
  }

  // Warn about non-HTTPS URLs
  if ([self.URL.scheme isEqualToString:@"http"]) {
    DNSLogInfo(LogCategoryRuleFetching, "Warning: Using non-secure HTTP URL: %@", self.URL);
  }

  return YES;
}

#pragma mark - NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession*)session
              dataTask:(NSURLSessionDataTask*)dataTask
    didReceiveResponse:(NSURLResponse*)response
     completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
  NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
  DNSLogDebug(LogCategoryRuleFetching, "Received HTTP response: %ld",
              (long)httpResponse.statusCode);

  // Check status code
  if (![self.acceptedStatusCodes containsObject:@(httpResponse.statusCode)]) {
    DNSLogError(LogCategoryRuleFetching, "HTTP error: %ld", (long)httpResponse.statusCode);
    completionHandler(NSURLSessionResponseCancel);

    NSError* error = DNSMakeErrorWithInfo(
        DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorHTTPError,
        [NSString stringWithFormat:@"HTTP error: %ld", (long)httpResponse.statusCode],
        @{@"statusCode" : @(httpResponse.statusCode)});
    if (!self.completionDelivered) {
      self.completionDelivered = YES;
      self.completionBlock(nil, error);
    }
    return;
  }

  // Get expected content length
  self.expectedContentLength = (NSUInteger)httpResponse.expectedContentLength;
  if (self.expectedContentLength == NSURLResponseUnknownLength) {
    self.expectedContentLength = 0;
  }

  completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession*)session
          dataTask:(NSURLSessionDataTask*)dataTask
    didReceiveData:(NSData*)data {
  [self.downloadedData appendData:data];
  self.bytesReceived += data.length;

  // Update progress
  if (self.expectedContentLength > 0) {
    float progress = [self currentProgress];
    [self notifyProgress:progress];
  }

  // Update speed calculation periodically
  NSTimeInterval timeSinceLastSpeed =
      [[NSDate date] timeIntervalSinceDate:self.lastSpeedCalculationTime];
  if (timeSinceLastSpeed >= 1.0) {
    self.lastSpeedCalculationTime = [NSDate date];
    self.lastBytesReceived = self.bytesReceived;

    DNSLogDebug(LogCategoryRuleFetching, "Download speed: %lu bytes/sec",
                (unsigned long)[self downloadSpeed]);
  }
}

- (void)URLSession:(NSURLSession*)session
                    task:(NSURLSessionTask*)task
    didCompleteWithError:(nullable NSError*)error {
  if (error) {
    // If we've already delivered a completion (e.g., due to HTTP error) and the task was
    // cancelled as a result, avoid double-calling the completion.
    if (self.completionDelivered && error.code == NSURLErrorCancelled &&
        [error.domain isEqualToString:NSURLErrorDomain]) {
      DNSLogDebug(LogCategoryRuleFetching, "Suppressing duplicate completion after cancellation");
      return;
    }
    // Check if task was cancelled and we have resume data
    if (error.code == NSURLErrorCancelled) {
      NSData* resumeData = error.userInfo[NSURLSessionDownloadTaskResumeData];
      if (resumeData) {
        self.resumeData = resumeData;
        DNSLogDebug(LogCategoryRuleFetching, "Download cancelled with resume data available");
      }
    }

    DNSLogError(LogCategoryRuleFetching, "HTTP fetch failed: %@", error);
    if (!self.completionDelivered) {
      self.completionDelivered = YES;
      self.completionBlock(nil, error);
    }
    return;
  }

  // Success
  DNSLogInfo(LogCategoryRuleFetching, "HTTP fetch completed successfully. Downloaded %lu bytes",
             (unsigned long)self.downloadedData.length);

  self.statistics[@"downloadSpeed"] = @([self downloadSpeed]);
  self.statistics[@"totalBytes"] = @(self.downloadedData.length);

  if (!self.completionDelivered) {
    self.completionDelivered = YES;
    self.completionBlock([self.downloadedData copy], nil);
  }
}

#pragma mark - NSURLSessionTaskDelegate

- (void)URLSession:(NSURLSession*)session
                          task:(NSURLSessionTask*)task
    willPerformHTTPRedirection:(NSHTTPURLResponse*)response
                    newRequest:(NSURLRequest*)request
             completionHandler:(void (^)(NSURLRequest* _Nullable))completionHandler {
  if (!self.followRedirects) {
    DNSLogInfo(LogCategoryRuleFetching, "Redirect blocked by configuration");
    completionHandler(nil);
    return;
  }

  self.redirectCount++;
  if (self.redirectCount > self.maxRedirects) {
    DNSLogError(LogCategoryRuleFetching, "Too many redirects (%lu)",
                (unsigned long)self.redirectCount);
    completionHandler(nil);

    NSError* error = DNSMakeError(DNSRuleFetcherErrorDomain, DNSRuleFetcherErrorRedirectLimit,
                                  @"Too many redirects");
    self.completionBlock(nil, error);
    return;
  }

  DNSLogInfo(LogCategoryRuleFetching, "Following redirect to: %@", request.URL);

  // Apply authentication to redirected request
  NSMutableURLRequest* mutableRequest = [request mutableCopy];
  [self addAuthenticationToRequest:mutableRequest];

  completionHandler(mutableRequest);
}

- (void)URLSession:(NSURLSession*)session
                   task:(NSURLSessionTask*)task
    didReceiveChallenge:(NSURLAuthenticationChallenge*)challenge
      completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition,
                                  NSURLCredential* _Nullable))completionHandler {
  if ([challenge.protectionSpace.authenticationMethod
          isEqualToString:NSURLAuthenticationMethodServerTrust]) {
    if (!self.validateSSL) {
      // Skip SSL validation if disabled (NOT RECOMMENDED)
      DNSLogInfo(LogCategoryRuleFetching, "WARNING: Skipping SSL validation");
      NSURLCredential* credential =
          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
      completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
      return;
    }

    // Certificate pinning
    if (self.pinnedCertificates.count > 0) {
      if ([self evaluatePinnedCertificates:challenge.protectionSpace.serverTrust]) {
        NSURLCredential* credential =
            [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
      } else {
        DNSLogError(LogCategoryRuleFetching, "Certificate pinning validation failed");
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
      }
      return;
    }

    // Default SSL validation
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
  } else {
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
  }
}

#pragma mark - Certificate Pinning

- (BOOL)evaluatePinnedCertificates:(SecTrustRef)serverTrust {
  // Get server certificate chain
  CFArrayRef certificateChain = SecTrustCopyCertificateChain(serverTrust);
  if (!certificateChain) {
    return NO;
  }

  CFIndex certificateCount = CFArrayGetCount(certificateChain);

  for (CFIndex i = 0; i < certificateCount; i++) {
    SecCertificateRef certificate = (SecCertificateRef)CFArrayGetValueAtIndex(certificateChain, i);
    NSData* certificateData = (__bridge_transfer NSData*)SecCertificateCopyData(certificate);

    // Check against pinned certificates
    for (NSData* pinnedCertData in self.pinnedCertificates) {
      if ([certificateData isEqualToData:pinnedCertData]) {
        DNSLogDebug(LogCategoryRuleFetching, "Certificate pinning match found");
        CFRelease(certificateChain);
        return YES;
      }

      // Also check public key
      if ([self publicKeyFromCertificate:certificateData matchesPinnedKey:pinnedCertData]) {
        DNSLogDebug(LogCategoryRuleFetching, "Public key pinning match found");
        CFRelease(certificateChain);
        return YES;
      }
    }
  }

  CFRelease(certificateChain);
  return NO;
}

- (BOOL)publicKeyFromCertificate:(NSData*)certificateData matchesPinnedKey:(NSData*)pinnedKeyData {
  // This is a simplified implementation
  // In production, you would extract and compare public keys properly
  // For now, we just compare certificate data
  return NO;
}

@end
