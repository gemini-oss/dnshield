//
//  DNSPacket.h
//  DNShield Network Extension
//
//  DNS packet parsing and construction utilities
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// DNS query types
typedef NS_ENUM(uint16_t, DNSQueryType) {
  DNSQueryTypeA = 1,      // IPv4 address
  DNSQueryTypeAAAA = 28,  // IPv6 address
  DNSQueryTypeCNAME = 5,  // Canonical name
  DNSQueryTypeMX = 15,    // Mail exchange
  DNSQueryTypeTXT = 16,   // Text strings
  DNSQueryTypeNS = 2,     // Name server
  DNSQueryTypeSOA = 6,    // Start of authority
  DNSQueryTypePTR = 12,   // Pointer record
  DNSQueryTypeSRV = 33,   // Service record
};

// DNS response codes
typedef NS_ENUM(uint8_t, DNSResponseCode) {
  DNSResponseCodeNoError = 0,   // No error
  DNSResponseCodeFormErr = 1,   // Format error
  DNSResponseCodeServFail = 2,  // Server failure
  DNSResponseCodeNXDomain = 3,  // Non-existent domain
  DNSResponseCodeNotImp = 4,    // Not implemented
  DNSResponseCodeRefused = 5,   // Query refused
};

// DNS query info
@interface DNSQuery : NSObject
@property(nonatomic, strong) NSString* domain;
@property(nonatomic, assign) DNSQueryType queryType;
@property(nonatomic, assign) uint16_t transactionID;
@property(nonatomic, assign) uint16_t queryClass;
@property(nonatomic, strong) NSData* originalPacket;
@end

// DNS response info
@interface DNSResponse : NSObject
@property(nonatomic, strong) NSString* domain;
@property(nonatomic, assign) DNSQueryType queryType;
@property(nonatomic, assign) uint16_t transactionID;
@property(nonatomic, assign) DNSResponseCode responseCode;
@property(nonatomic, assign) uint32_t ttl;
@property(nonatomic, strong) NSArray<NSString*>* answers;
@property(nonatomic, strong) NSData* originalPacket;
@end

// DNS packet parser and builder
@interface DNSPacket : NSObject

// Parse DNS query packet
+ (nullable DNSQuery*)parseQuery:(NSData*)packet error:(NSError**)error;

// Parse DNS response packet
+ (nullable DNSResponse*)parseResponse:(NSData*)packet error:(NSError**)error;

// Create DNS responses
+ (NSData*)createBlockedAResponse:(NSData*)queryPacket;
+ (NSData*)createBlockedAAAAResponse:(NSData*)queryPacket;
+ (NSData*)createNXDOMAINResponse:(NSData*)queryPacket;
+ (NSData*)createServerFailureResponse:(NSData*)queryPacket;
+ (NSData*)createFormatErrorResponse:(NSData*)queryPacket;

// Create response with custom data
+ (NSData*)createResponseForQuery:(NSData*)queryPacket
                     responseCode:(DNSResponseCode)responseCode
                          answers:(nullable NSArray<NSData*>*)answers;

// Helper to create A record answer
+ (NSData*)createARecordAnswer:(NSString*)domain ip:(NSString*)ipAddress ttl:(uint32_t)ttl;

// Extract transaction ID for response matching
+ (NSData*)extractTransactionID:(NSData*)packet;

// Get TTL from DNS response
+ (uint32_t)extractTTLFromResponse:(NSData*)response;

// Update TTL values in DNS response
+ (nullable NSData*)updateTTLInResponse:(NSData*)response newTTL:(uint32_t)newTTL;

@end

NS_ASSUME_NONNULL_END
