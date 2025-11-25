//
//  ErrorTypes.h
//  DNShield Network Extension
//
//  Common error definitions
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Error Domains

// Main error domains
extern NSString* const DNSRuleManagerErrorDomain;
extern NSString* const DNSRuleFetcherErrorDomain;
extern NSString* const DNSRuleParserErrorDomain;
extern NSString* const DNSRuleCacheErrorDomain;
extern NSString* const DNSSchedulerErrorDomain;

#pragma mark - Error Codes

// Rule Manager Errors (1000-1999)
typedef NS_ENUM(NSInteger, DNSRuleManagerError) {
  DNSRuleManagerErrorUnknown = 1000,
  DNSRuleManagerErrorNotInitialized,
  DNSRuleManagerErrorAlreadyRunning,
  DNSRuleManagerErrorNotRunning,
  DNSRuleManagerErrorNoSources,
  DNSRuleManagerErrorAllSourcesFailed,
  DNSRuleManagerErrorUpdateInProgress,
  DNSRuleManagerErrorOfflineMode,
  DNSRuleManagerErrorConfigurationInvalid
};

// Rule Fetcher Errors (2000-2999)
typedef NS_ENUM(NSInteger, DNSRuleFetcherError) {
  DNSRuleFetcherErrorUnknown = 2000,
  DNSRuleFetcherErrorNetworkUnavailable,
  DNSRuleFetcherErrorInvalidURL,
  DNSRuleFetcherErrorTimeout,
  DNSRuleFetcherErrorHTTPError,
  DNSRuleFetcherErrorAuthenticationFailed,
  DNSRuleFetcherErrorDataCorrupted,
  DNSRuleFetcherErrorFileMissing,
  DNSRuleFetcherErrorPermissionDenied,
  DNSRuleFetcherErrorS3Error,
  DNSRuleFetcherErrorCancelled,
  DNSRuleFetcherErrorSSLError,
  DNSRuleFetcherErrorRedirectLimit
};

// Rule Parser Errors (3000-3999)
typedef NS_ENUM(NSInteger, DNSRuleParserError) {
  DNSRuleParserErrorUnknown = 3000,
  DNSRuleParserErrorInvalidFormat,
  DNSRuleParserErrorEmptyData,
  DNSRuleParserErrorSyntaxError,
  DNSRuleParserErrorUnsupportedVersion,
  DNSRuleParserErrorMissingRequiredField,
  DNSRuleParserErrorInvalidDomain,
  DNSRuleParserErrorDataTooLarge,
  DNSRuleParserErrorEncodingError,
  DNSRuleParserErrorSchemaValidation,
  DNSRuleParserErrorFileMissing
};

// Rule Cache Errors (4000-4999)
typedef NS_ENUM(NSInteger, DNSRuleCacheError) {
  DNSRuleCacheErrorUnknown = 4000,
  DNSRuleCacheErrorDiskFull,
  DNSRuleCacheErrorCorruptedData,
  DNSRuleCacheErrorExpired,
  DNSRuleCacheErrorNotFound,
  DNSRuleCacheErrorWriteFailed,
  DNSRuleCacheErrorReadFailed,
  DNSRuleCacheErrorMigrationFailed,
  DNSRuleCacheErrorQuotaExceeded,
  DNSRuleCacheErrorLockFailed
};

// Scheduler Errors (5000-5999)
typedef NS_ENUM(NSInteger, DNSSchedulerError) {
  DNSSchedulerErrorUnknown = 5000,
  DNSSchedulerErrorInvalidInterval,
  DNSSchedulerErrorInvalidSchedule,
  DNSSchedulerErrorTimerFailed,
  DNSSchedulerErrorBackgroundTaskDenied,
  DNSSchedulerErrorMaxRetriesExceeded
};

#pragma mark - Error Creation Helpers

// Create error with code and description
static inline NSError* DNSMakeError(NSString* domain, NSInteger code, NSString* description) {
  return [NSError errorWithDomain:domain
                             code:code
                         userInfo:@{NSLocalizedDescriptionKey : description}];
}

// Create error with code, description and underlying error
static inline NSError* DNSMakeErrorWithUnderlying(NSString* domain, NSInteger code,
                                                  NSString* description, NSError* underlying) {
  NSMutableDictionary* userInfo = [NSMutableDictionary dictionary];
  userInfo[NSLocalizedDescriptionKey] = description;
  if (underlying) {
    userInfo[NSUnderlyingErrorKey] = underlying;
  }
  return [NSError errorWithDomain:domain code:code userInfo:userInfo];
}

// Create error with additional info
static inline NSError* DNSMakeErrorWithInfo(NSString* domain, NSInteger code, NSString* description,
                                            NSDictionary* additionalInfo) {
  NSMutableDictionary* userInfo = [NSMutableDictionary dictionaryWithDictionary:additionalInfo];
  userInfo[NSLocalizedDescriptionKey] = description;
  return [NSError errorWithDomain:domain code:code userInfo:userInfo];
}

#pragma mark - Error Category Detection

// Check if error is network related
static inline BOOL DNSIsNetworkError(NSError* error) {
  if ([error.domain isEqualToString:NSURLErrorDomain]) {
    return YES;
  }

  if ([error.domain isEqualToString:DNSRuleFetcherErrorDomain]) {
    switch (error.code) {
      case DNSRuleFetcherErrorNetworkUnavailable:
      case DNSRuleFetcherErrorTimeout:
      case DNSRuleFetcherErrorSSLError: return YES;
      default: break;
    }
  }

  return NO;
}

// Check if error is retryable
static inline BOOL DNSIsRetryableError(NSError* error) {
  // Treat user-cancelled tasks as non-retryable
  if ([error.domain isEqualToString:NSURLErrorDomain]) {
    if (error.code == NSURLErrorCancelled || error.code == NSURLErrorUserCancelledAuthentication) {
      return NO;
    }
    // Other CFNetwork errors are generally transient
    return YES;
  }

  // Check specific rule fetcher errors
  if ([error.domain isEqualToString:DNSRuleFetcherErrorDomain]) {
    switch (error.code) {
      case DNSRuleFetcherErrorTimeout:
      case DNSRuleFetcherErrorS3Error: return YES;

      case DNSRuleFetcherErrorHTTPError: {
        // Examine HTTP status code; treat 404 as non-retryable, retry 5xx
        NSNumber* status = error.userInfo[@"statusCode"];
        if (status) {
          NSInteger sc = status.integerValue;
          if (sc == 404)
            return NO;
          if (sc >= 500 && sc <= 599)
            return YES;
        }
        return NO;
      }

      case DNSRuleFetcherErrorAuthenticationFailed:
      case DNSRuleFetcherErrorPermissionDenied:
      case DNSRuleFetcherErrorInvalidURL:
      case DNSRuleFetcherErrorFileMissing:
      case DNSRuleFetcherErrorCancelled: return NO;

      default: break;
    }
  }

  if ([error.domain isEqualToString:DNSRuleCacheErrorDomain]) {
    switch (error.code) {
      case DNSRuleCacheErrorLockFailed: return YES;
      default: return NO;
    }
  }

  return NO;
}

// Check if error is fatal (should stop processing)
static inline BOOL DNSIsFatalError(NSError* error) {
  if ([error.domain isEqualToString:DNSRuleManagerErrorDomain]) {
    switch (error.code) {
      case DNSRuleManagerErrorConfigurationInvalid:
      case DNSRuleManagerErrorNotInitialized: return YES;
      default: break;
    }
  }

  if ([error.domain isEqualToString:DNSRuleParserErrorDomain]) {
    switch (error.code) {
      case DNSRuleParserErrorDataTooLarge:
      case DNSRuleParserErrorUnsupportedVersion: return YES;
      default: break;
    }
  }

  return NO;
}

#pragma mark - Error Recovery Suggestions

// Get recovery suggestion for error
static inline NSString* _Nullable DNSRecoverySuggestionForError(NSError* error) {
  if (DNSIsNetworkError(error)) {
    return @"Check your network connection and try again.";
  }

  if ([error.domain isEqualToString:DNSRuleFetcherErrorDomain]) {
    switch (error.code) {
      case DNSRuleFetcherErrorAuthenticationFailed:
        return @"Verify your authentication credentials.";
      case DNSRuleFetcherErrorPermissionDenied:
        return @"Ensure you have permission to access this resource.";
      case DNSRuleFetcherErrorFileMissing: return @"Verify the file path is correct.";
      default: break;
    }
  }

  if ([error.domain isEqualToString:DNSRuleCacheErrorDomain]) {
    switch (error.code) {
      case DNSRuleCacheErrorDiskFull: return @"Free up disk space and try again.";
      case DNSRuleCacheErrorQuotaExceeded: return @"Clear old cache data or increase cache quota.";
      default: break;
    }
  }

  return nil;
}

NS_ASSUME_NONNULL_END
