//
//  AuthCredentialManager.m
//  DNShield Network Extension
//
//  Implementation of secure credential storage for Basic Auth and mTLS
//

#import "AuthCredentialManager.h"
#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import <Security/Security.h>
#import "PreferenceManager.h"

static NSString* const kDNSAuthKeychainService = @"com.dnshield.auth";
static NSString* const kDNSAuthBasicPrefix = @"basic.";
static NSString* const kDNSAuthMTLSPrefix = @"mtls.";
static NSString* const kDNSAuthTypeKey = @"authType";

@implementation AuthCredentialManager

+ (instancetype)sharedManager {
  static AuthCredentialManager* sharedInstance = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedInstance = [[self alloc] init];
  });
  return sharedInstance;
}

#pragma mark - Basic Auth

- (BOOL)storeBasicAuthHeader:(NSString*)authHeader forHost:(NSString*)host error:(NSError**)error {
  DNSLogInfo(LogCategoryConfiguration, "Storing Basic Auth header for host: %{public}@", host);

  NSString* key = [NSString stringWithFormat:@"%@%@", kDNSAuthBasicPrefix, host];
  NSData* data = [authHeader dataUsingEncoding:NSUTF8StringEncoding];

  return [self storeData:data forKey:key error:error];
}

- (nullable NSString*)retrieveBasicAuthHeaderForHost:(NSString*)host error:(NSError**)error {
  NSString* key = [NSString stringWithFormat:@"%@%@", kDNSAuthBasicPrefix, host];
  NSData* data = [self retrieveDataForKey:key error:error];

  if (!data) {
    return nil;
  }

  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (BOOL)deleteBasicAuthForHost:(NSString*)host error:(NSError**)error {
  NSString* key = [NSString stringWithFormat:@"%@%@", kDNSAuthBasicPrefix, host];
  return [self deleteDataForKey:key error:error];
}

#pragma mark - mTLS Certificate

- (BOOL)storeMTLSCertificateName:(NSString*)certName
                         forHost:(NSString*)host
                           error:(NSError**)error {
  DNSLogInfo(LogCategoryConfiguration, "Storing mTLS certificate name for host: %{public}@", host);

  NSString* key = [NSString stringWithFormat:@"%@%@", kDNSAuthMTLSPrefix, host];
  NSData* data = [certName dataUsingEncoding:NSUTF8StringEncoding];

  return [self storeData:data forKey:key error:error];
}

- (nullable NSString*)retrieveMTLSCertificateNameForHost:(NSString*)host error:(NSError**)error {
  NSString* key = [NSString stringWithFormat:@"%@%@", kDNSAuthMTLSPrefix, host];
  NSData* data = [self retrieveDataForKey:key error:error];

  if (!data) {
    return nil;
  }

  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (BOOL)deleteMTLSCertificateForHost:(NSString*)host error:(NSError**)error {
  NSString* key = [NSString stringWithFormat:@"%@%@", kDNSAuthMTLSPrefix, host];
  return [self deleteDataForKey:key error:error];
}

#pragma mark - Auth Type Detection

- (DNSAuthType)authTypeForHost:(NSString*)host {
  // Check for mTLS first
  NSString* mtlsCert = [self retrieveMTLSCertificateNameForHost:host error:nil];
  if (mtlsCert) {
    return DNSAuthTypeMTLS;
  }

  // Check for Basic Auth
  NSString* basicAuth = [self retrieveBasicAuthHeaderForHost:host error:nil];
  if (basicAuth) {
    return DNSAuthTypeBasic;
  }

  return DNSAuthTypeNone;
}

#pragma mark - Migration

- (BOOL)migrateAuthCredentialsFromPreferencesWithError:(NSError**)error {
  DNSLogInfo(LogCategoryConfiguration,
             "Attempting to migrate auth credentials from preferences to Keychain");

  // Get shared defaults via preference manager
  PreferenceManager* prefManager = [PreferenceManager sharedManager];
  NSUserDefaults* sharedDefaults = prefManager.sharedDefaults;

  BOOL migrated = NO;

  // Look for Basic Auth headers in preferences
  NSDictionary* allPrefs = [sharedDefaults dictionaryRepresentation];
  for (NSString* key in allPrefs) {
    if ([key hasPrefix:@"S3BasicAuth_"]) {
      NSString* host = [key substringFromIndex:[@"S3BasicAuth_" length]];
      NSString* authHeader = allPrefs[key];

      if (authHeader && [authHeader isKindOfClass:[NSString class]]) {
        if ([self storeBasicAuthHeader:authHeader forHost:host error:error]) {
          [sharedDefaults removeObjectForKey:key];
          migrated = YES;
          DNSLogInfo(LogCategoryConfiguration, "Migrated Basic Auth for host: %{public}@", host);
        }
      }
    } else if ([key hasPrefix:@"S3MTLSCert_"]) {
      NSString* host = [key substringFromIndex:[@"S3MTLSCert_" length]];
      NSString* certName = allPrefs[key];

      if (certName && [certName isKindOfClass:[NSString class]]) {
        if ([self storeMTLSCertificateName:certName forHost:host error:error]) {
          [sharedDefaults removeObjectForKey:key];
          migrated = YES;
          DNSLogInfo(LogCategoryConfiguration, "Migrated mTLS cert for host: %{public}@", host);
        }
      }
    }
  }

  if (migrated) {
    [sharedDefaults synchronize];
    DNSLogInfo(LogCategoryConfiguration, "Successfully migrated auth credentials to Keychain");
  } else {
    DNSLogInfo(LogCategoryConfiguration, "No auth credentials found in preferences to migrate");
  }

  return YES;
}

#pragma mark - Keychain Operations

- (BOOL)storeData:(NSData*)data forKey:(NSString*)key error:(NSError**)error {
  NSMutableDictionary* query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = kDNSAuthKeychainService;
  query[(__bridge id)kSecAttrAccount] = key;
  query[(__bridge id)kSecAttrAccessible] =
      (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;

  // Add access group for sharing between app and extension
  query[(__bridge id)kSecAttrAccessGroup] =
      [NSString stringWithFormat:@"%@.com.gemini.dnshield", kDNShieldTeamIdentifier];

  // Delete existing item if any
  SecItemDelete((__bridge CFDictionaryRef)query);

  // Add new item
  query[(__bridge id)kSecValueData] = data;

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);

  if (status != errSecSuccess) {
    if (error) {
      *error = [NSError
          errorWithDomain:NSOSStatusErrorDomain
                     code:status
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to store item in Keychain"}];
    }
    DNSLogError(LogCategoryConfiguration, "Failed to store Keychain item: %{public}@",
                [self keychainErrorStringForStatus:status]);
    return NO;
  }

  return YES;
}

- (nullable NSData*)retrieveDataForKey:(NSString*)key error:(NSError**)error {
  NSMutableDictionary* query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = kDNSAuthKeychainService;
  query[(__bridge id)kSecAttrAccount] = key;
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

  // Add access group
  query[(__bridge id)kSecAttrAccessGroup] =
      [NSString stringWithFormat:@"%@.com.gemini.dnshield", kDNShieldTeamIdentifier];

  CFDataRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&result);

  if (status != errSecSuccess) {
    if (status != errSecItemNotFound && error) {
      *error = [NSError
          errorWithDomain:NSOSStatusErrorDomain
                     code:status
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to retrieve item from Keychain"}];
    }
    return nil;
  }

  return (__bridge_transfer NSData*)result;
}

- (BOOL)deleteDataForKey:(NSString*)key error:(NSError**)error {
  NSMutableDictionary* query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = kDNSAuthKeychainService;
  query[(__bridge id)kSecAttrAccount] = key;

  // Add access group
  query[(__bridge id)kSecAttrAccessGroup] =
      [NSString stringWithFormat:@"%@.com.gemini.dnshield", kDNShieldTeamIdentifier];

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

  if (status != errSecSuccess && status != errSecItemNotFound) {
    if (error) {
      *error = [NSError
          errorWithDomain:NSOSStatusErrorDomain
                     code:status
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to delete item from Keychain"}];
    }
    return NO;
  }

  return YES;
}

- (NSString*)keychainErrorStringForStatus:(OSStatus)status {
  switch (status) {
    case errSecSuccess: return @"Success";
    case errSecUnimplemented: return @"Function not implemented";
    case errSecParam: return @"Invalid parameter";
    case errSecAllocate: return @"Memory allocation failure";
    case errSecNotAvailable: return @"Keychain not available";
    case errSecReadOnly: return @"Read only";
    case errSecAuthFailed: return @"Authentication failed";
    case errSecNoSuchKeychain: return @"Keychain not found";
    case errSecInvalidKeychain: return @"Invalid keychain";
    case errSecDuplicateItem: return @"Duplicate item";
    case errSecItemNotFound: return @"Item not found";
    case errSecInteractionNotAllowed: return @"User interaction not allowed";
    case errSecDecode: return @"Decode error";
    case errSecDuplicateCallback: return @"Duplicate callback";
    default: return [NSString stringWithFormat:@"Unknown error: %d", (int)status];
  }
}

@end
