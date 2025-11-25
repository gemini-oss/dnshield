//
//  AuthCredentialManager.h
//  DNShield Network Extension
//
//  Secure storage for authentication credentials (Basic Auth, mTLS certs)
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, DNSAuthType) {
  DNSAuthTypeNone,
  DNSAuthTypeBasic,
  DNSAuthTypeMTLS,
  DNSAuthTypePresignedURL
};

@interface AuthCredentialManager : NSObject

+ (instancetype)sharedManager;

// Basic Auth Management
- (BOOL)storeBasicAuthHeader:(NSString*)authHeader forHost:(NSString*)host error:(NSError**)error;

- (nullable NSString*)retrieveBasicAuthHeaderForHost:(NSString*)host error:(NSError**)error;

- (BOOL)deleteBasicAuthForHost:(NSString*)host error:(NSError**)error;

// mTLS Certificate Management
- (BOOL)storeMTLSCertificateName:(NSString*)certName forHost:(NSString*)host error:(NSError**)error;

- (nullable NSString*)retrieveMTLSCertificateNameForHost:(NSString*)host error:(NSError**)error;

- (BOOL)deleteMTLSCertificateForHost:(NSString*)host error:(NSError**)error;

// Migration from preferences
- (BOOL)migrateAuthCredentialsFromPreferencesWithError:(NSError**)error;

// Generic auth configuration
- (DNSAuthType)authTypeForHost:(NSString*)host;

@end

NS_ASSUME_NONNULL_END
