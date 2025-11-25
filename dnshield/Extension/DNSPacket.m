//
//  DNSPacket.m
//  DNShield Network Extension
//
//  DNS packet parsing and construction implementation
//

#import <Common/LoggingManager.h>
#import <arpa/inet.h>  // For inet_pton

#import "DNSPacket.h"
// Default TTL for DNS responses (5 minutes)
#define DNS_DEFAULT_TTL 300

@implementation DNSQuery
@end

@implementation DNSResponse
@end

@implementation DNSPacket

#pragma mark - Parsing

+ (nullable DNSQuery*)parseQuery:(NSData*)packet error:(NSError**)error {
  // DNS UDP packets are limited to 512 bytes without EDNS
  if (packet.length < 12 || packet.length > 512) {
    if (error) {
      *error = [NSError errorWithDomain:@"DNSPacket"
                                   code:1
                               userInfo:@{NSLocalizedDescriptionKey : @"Invalid packet size"}];
    }
    return nil;
  }

  const uint8_t* bytes = packet.bytes;

  // Check if it's a query (QR bit = 0)
  if (bytes[2] & 0x80) {
    if (error) {
      *error = [NSError errorWithDomain:@"DNSPacket"
                                   code:2
                               userInfo:@{NSLocalizedDescriptionKey : @"Not a query packet"}];
    }
    return nil;
  }

  DNSQuery* query = [[DNSQuery alloc] init];
  query.originalPacket = packet;

  // Extract transaction ID
  query.transactionID = (bytes[0] << 8) | bytes[1];

  // Get question count
  uint16_t qdcount = (bytes[4] << 8) | bytes[5];
  if (qdcount == 0) {
    if (error) {
      *error = [NSError errorWithDomain:@"DNSPacket"
                                   code:3
                               userInfo:@{NSLocalizedDescriptionKey : @"No questions in query"}];
    }
    return nil;
  }

  // Parse the first question with strict bounds checking
  NSUInteger offset = 12;
  NSMutableString* domain = [NSMutableString new];
  NSUInteger domainLength = 0;
  const NSUInteger maxDomainLength = 253;  // RFC limit
  const NSUInteger maxLabels = 127;        // RFC limit
  NSUInteger labelCount = 0;

  while (offset < packet.length && labelCount < maxLabels) {
    // Bounds check before accessing byte
    if (offset >= packet.length) {
      if (error) {
        *error = [NSError errorWithDomain:@"DNSPacket"
                                     code:5
                                 userInfo:@{NSLocalizedDescriptionKey : @"Truncated packet"}];
      }
      return nil;
    }

    uint8_t labelLength = bytes[offset];

    if (labelLength == 0) {
      offset++;
      break;
    }

    // Check for compression pointer (not allowed in queries)
    if (labelLength > 63) {
      if (error) {
        *error = [NSError
            errorWithDomain:@"DNSPacket"
                       code:4
                   userInfo:@{
                     NSLocalizedDescriptionKey : @"Invalid label length or compression in query"
                   }];
      }
      return nil;
    }

    offset++;

    // Check for integer overflow before addition
    if (offset > packet.length - labelLength) {
      if (error) {
        *error = [NSError errorWithDomain:@"DNSPacket"
                                     code:5
                                 userInfo:@{NSLocalizedDescriptionKey : @"Truncated packet"}];
      }
      return nil;
    }

    // Validate total domain length
    domainLength += labelLength + 1;  // +1 for dot
    if (domainLength > maxDomainLength) {
      if (error) {
        *error = [NSError errorWithDomain:@"DNSPacket"
                                     code:8
                                 userInfo:@{NSLocalizedDescriptionKey : @"Domain name too long"}];
      }
      return nil;
    }

    // Add dot separator
    if (domain.length > 0) {
      [domain appendString:@"."];
    }

    // Extract label with encoding validation
    NSString* label = [[NSString alloc] initWithBytes:&bytes[offset]
                                               length:labelLength
                                             encoding:NSUTF8StringEncoding];
    if (!label) {
      // Try ASCII fallback for non-UTF8 domains
      label = [[NSString alloc] initWithBytes:&bytes[offset]
                                       length:labelLength
                                     encoding:NSASCIIStringEncoding];
    }

    if (!label) {
      if (error) {
        *error =
            [NSError errorWithDomain:@"DNSPacket"
                                code:6
                            userInfo:@{NSLocalizedDescriptionKey : @"Invalid domain encoding"}];
      }
      return nil;
    }

    [domain appendString:label];
    offset += labelLength;
    labelCount++;
  }

  // Validate we didn't exceed label count
  if (labelCount >= maxLabels) {
    if (error) {
      *error =
          [NSError errorWithDomain:@"DNSPacket"
                              code:9
                          userInfo:@{NSLocalizedDescriptionKey : @"Too many labels in domain"}];
    }
    return nil;
  }

  // Get query type and class with bounds check
  if (offset + 4 > packet.length) {
    if (error) {
      *error = [NSError errorWithDomain:@"DNSPacket"
                                   code:7
                               userInfo:@{NSLocalizedDescriptionKey : @"Missing query type/class"}];
    }
    return nil;
  }

  query.domain = [domain lowercaseString];
  query.queryType = (bytes[offset] << 8) | bytes[offset + 1];
  query.queryClass = (bytes[offset + 2] << 8) | bytes[offset + 3];

  return query;
}

+ (nullable NSString*)parseDomainNameFromOffset:(NSUInteger)offset
                                       inPacket:(NSData*)packet
                                          error:(NSError**)error {
  if (offset >= packet.length) {
    if (error) {
      *error = [NSError
          errorWithDomain:@"DNSPacket"
                     code:10
                 userInfo:@{NSLocalizedDescriptionKey : @"Invalid offset for domain parsing"}];
    }
    return nil;
  }

  const uint8_t* bytes = packet.bytes;
  NSMutableString* domain = [NSMutableString new];
  NSUInteger currentOffset = offset;
  int compressionJumps = 0;
  const int maxCompressionJumps = 5;  // Prevent infinite loops

  while (currentOffset < packet.length && compressionJumps < maxCompressionJumps) {
    uint8_t labelLength = bytes[currentOffset];

    if (labelLength == 0) {
      currentOffset++;
      break;
    }

    // Handle compression
    if ((labelLength & 0xC0) == 0xC0) {
      if (currentOffset + 1 >= packet.length) {
        if (error) {
          *error = [NSError
              errorWithDomain:@"DNSPacket"
                         code:11
                     userInfo:@{NSLocalizedDescriptionKey : @"Invalid compression pointer"}];
        }
        return nil;
      }

      uint16_t pointerOffset = ((labelLength & 0x3F) << 8) | bytes[currentOffset + 1];
      if (pointerOffset >= packet.length) {
        if (error) {
          *error = [NSError
              errorWithDomain:@"DNSPacket"
                         code:12
                     userInfo:@{NSLocalizedDescriptionKey : @"Invalid compression pointer offset"}];
        }
        return nil;
      }

      currentOffset = pointerOffset;
      compressionJumps++;
      continue;
    }

    if (labelLength > 63) {
      if (error) {
        *error =
            [NSError errorWithDomain:@"DNSPacket"
                                code:13
                            userInfo:@{
                              NSLocalizedDescriptionKey : @"Invalid label length in compressed name"
                            }];
      }
      return nil;
    }

    currentOffset++;

    if (currentOffset + labelLength > packet.length) {
      if (error) {
        *error = [NSError errorWithDomain:@"DNSPacket"
                                     code:14
                                 userInfo:@{NSLocalizedDescriptionKey : @"Truncated domain name"}];
      }
      return nil;
    }

    if (domain.length > 0) {
      [domain appendString:@"."];
    }

    NSString* label = [[NSString alloc] initWithBytes:&bytes[currentOffset]
                                               length:labelLength
                                             encoding:NSUTF8StringEncoding];
    if (!label) {
      label = [[NSString alloc] initWithBytes:&bytes[currentOffset]
                                       length:labelLength
                                     encoding:NSASCIIStringEncoding];
    }

    if (!label) {
      if (error) {
        *error = [NSError
            errorWithDomain:@"DNSPacket"
                       code:15
                   userInfo:@{
                     NSLocalizedDescriptionKey : @"Invalid domain encoding in compressed name"
                   }];
      }
      return nil;
    }

    [domain appendString:label];
    currentOffset += labelLength;
  }

  if (compressionJumps >= maxCompressionJumps) {
    if (error) {
      *error =
          [NSError errorWithDomain:@"DNSPacket"
                              code:16
                          userInfo:@{NSLocalizedDescriptionKey : @"Too many compression jumps"}];
    }
    return nil;
  }

  return [domain lowercaseString];
}

+ (nullable DNSResponse*)parseResponse:(NSData*)packet error:(NSError**)error {
  if (packet.length < 12) {
    if (error) {
      *error = [NSError errorWithDomain:@"DNSPacket"
                                   code:1
                               userInfo:@{NSLocalizedDescriptionKey : @"Packet too short"}];
    }
    return nil;
  }

  const uint8_t* bytes = packet.bytes;

  // Check if it's a response (QR bit = 1)
  if (!(bytes[2] & 0x80)) {
    if (error) {
      *error = [NSError errorWithDomain:@"DNSPacket"
                                   code:2
                               userInfo:@{NSLocalizedDescriptionKey : @"Not a response packet"}];
    }
    return nil;
  }

  DNSResponse* response = [[DNSResponse alloc] init];
  response.originalPacket = packet;

  // Extract transaction ID
  response.transactionID = (bytes[0] << 8) | bytes[1];

  // Extract response code (last 4 bits of byte 3)
  response.responseCode = bytes[3] & 0x0F;

  // Get counts
  uint16_t qdcount = (bytes[4] << 8) | bytes[5];
  uint16_t ancount = (bytes[6] << 8) | bytes[7];

  NSUInteger offset = 12;

  // Parse questions section to get domain and query type
  if (qdcount > 0) {
    NSMutableString* domain = [NSMutableString new];

    // Parse domain name
    while (offset < packet.length) {
      uint8_t labelLength = bytes[offset];

      if (labelLength == 0) {
        offset++;
        break;
      }

      // Handle compression
      if ((labelLength & 0xC0) == 0xC0) {
        // Compression pointer - resolve the domain name
        uint16_t pointerOffset = ((labelLength & 0x3F) << 8) | bytes[offset + 1];
        if (pointerOffset >= packet.length) {
          if (error) {
            *error = [NSError
                errorWithDomain:@"DNSPacket"
                           code:6
                       userInfo:@{NSLocalizedDescriptionKey : @"Invalid compression pointer"}];
          }
          return nil;
        }
        NSString* resolvedDomain = [self parseDomainNameFromOffset:pointerOffset
                                                          inPacket:packet
                                                             error:error];
        if (!resolvedDomain) {
          return nil;  // Error already set by parseDomainNameFromOffset
        }
        if (domain.length > 0) {
          [domain appendString:@"."];
        }
        [domain appendString:resolvedDomain];
        offset += 2;
        break;
      }

      if (labelLength > 63) {
        if (error) {
          *error = [NSError errorWithDomain:@"DNSPacket"
                                       code:4
                                   userInfo:@{NSLocalizedDescriptionKey : @"Invalid label length"}];
        }
        return nil;
      }

      offset++;

      if (offset + labelLength > packet.length) {
        if (error) {
          *error = [NSError errorWithDomain:@"DNSPacket"
                                       code:5
                                   userInfo:@{NSLocalizedDescriptionKey : @"Truncated packet"}];
        }
        return nil;
      }

      if (domain.length > 0) {
        [domain appendString:@"."];
      }

      NSString* label = [[NSString alloc] initWithBytes:&bytes[offset]
                                                 length:labelLength
                                               encoding:NSUTF8StringEncoding];
      if (!label) {
        NSString* invalidBytes = [[NSData dataWithBytes:&bytes[offset]
                                                 length:labelLength] description];
        label = [NSString stringWithFormat:@"[invalid: bytes=%@, offset=%lu]", invalidBytes,
                                           (unsigned long)offset];
      }

      [domain appendString:label];
      offset += labelLength;
    }

    response.domain = [domain copy];

    // Get query type and class
    if (offset + 4 <= packet.length) {
      response.queryType = (bytes[offset] << 8) | bytes[offset + 1];
      // Skip query class (offset + 2 and offset + 3)
      offset += 4;
    }
  }

  // Parse answers section to extract TTL and answer data
  NSMutableArray* answers = [NSMutableArray new];
  response.ttl = DNS_DEFAULT_TTL;  // Default TTL

  for (int i = 0; i < ancount && offset < packet.length; i++) {
    // Skip name (could be compressed)
    while (offset < packet.length) {
      uint8_t labelLength = bytes[offset];
      if (labelLength == 0) {
        offset++;
        break;
      } else if ((labelLength & 0xC0) == 0xC0) {
        offset += 2;  // Compression pointer
        break;
      } else {
        offset += labelLength + 1;
      }
    }

    if (offset + 10 > packet.length) {
      break;  // Not enough data for type, class, ttl, length
    }

    uint16_t answerType = (bytes[offset] << 8) | bytes[offset + 1];
    // uint16_t answerClass = (bytes[offset + 2] << 8) | bytes[offset + 3];
    uint32_t ttl = (bytes[offset + 4] << 24) | (bytes[offset + 5] << 16) |
                   (bytes[offset + 6] << 8) | bytes[offset + 7];
    uint16_t dataLength = (bytes[offset + 8] << 8) | bytes[offset + 9];

    offset += 10;

    if (offset + dataLength > packet.length) {
      break;  // Not enough data
    }

    // Store the minimum TTL from all answers
    if (i == 0 || ttl < response.ttl) {
      response.ttl = ttl;
    }

    // Extract answer data based on type
    if (answerType == DNSQueryTypeA && dataLength == 4) {
      // IPv4 address
      NSString* ipAddress =
          [NSString stringWithFormat:@"%d.%d.%d.%d", bytes[offset], bytes[offset + 1],
                                     bytes[offset + 2], bytes[offset + 3]];
      [answers addObject:ipAddress];
    } else if (answerType == DNSQueryTypeAAAA && dataLength == 16) {
      // IPv6 address - proper RFC 5952 formatting
      char ipv6Str[INET6_ADDRSTRLEN];
      struct in6_addr addr;
      memcpy(&addr, &bytes[offset], 16);

      if (inet_ntop(AF_INET6, &addr, ipv6Str, INET6_ADDRSTRLEN)) {
        [answers addObject:[NSString stringWithUTF8String:ipv6Str]];
      } else {
        // Fallback to simple formatting if inet_ntop fails
        NSMutableString* ipv6 = [NSMutableString new];
        for (int j = 0; j < 16; j += 2) {
          if (j > 0)
            [ipv6 appendString:@":"];
          [ipv6 appendFormat:@"%02x%02x", bytes[offset + j], bytes[offset + j + 1]];
        }
        [answers addObject:ipv6];
      }
    }

    offset += dataLength;
  }

  response.answers = [answers copy];

  return response;
}

#pragma mark - Response Creation

+ (NSData*)createBlockedAResponse:(NSData*)queryPacket {
  // Parse the query first
  NSError* error = nil;
  DNSQuery* query = [self parseQuery:queryPacket error:&error];
  if (!query) {
    return [self createFormatErrorResponse:queryPacket];
  }

  // Only respond with A record for A queries
  if (query.queryType != DNSQueryTypeA) {
    return [self createNXDOMAINResponse:queryPacket];
  }

  // Create A record answer pointing to 127.0.0.1
  NSData* answer = [self createARecordAnswer:query.domain ip:@"127.0.0.1" ttl:60];  // 1 minute TTL

  return [self createResponseForQuery:queryPacket
                         responseCode:DNSResponseCodeNoError
                              answers:@[ answer ]];
}

+ (NSData*)createBlockedAAAAResponse:(NSData*)queryPacket {
  // For AAAA queries, return ::1 (IPv6 loopback)
  DNSQuery* query = [self parseQuery:queryPacket error:nil];
  if (!query) {
    return [self createResponseForQuery:queryPacket
                           responseCode:DNSResponseCodeServFail
                                answers:nil];
  }

  // Create AAAA record answer pointing to ::1
  NSData* answer = [self createAAAARecordAnswer:query.domain ipv6:@"::1" ttl:60];  // 1 minute TTL

  return [self createResponseForQuery:queryPacket
                         responseCode:DNSResponseCodeNoError
                              answers:@[ answer ]];
}

+ (NSData*)createNXDOMAINResponse:(NSData*)queryPacket {
  return [self createResponseForQuery:queryPacket responseCode:DNSResponseCodeNXDomain answers:nil];
}

+ (NSData*)createServerFailureResponse:(NSData*)queryPacket {
  return [self createResponseForQuery:queryPacket responseCode:DNSResponseCodeServFail answers:nil];
}

+ (NSData*)createFormatErrorResponse:(NSData*)queryPacket {
  return [self createResponseForQuery:queryPacket responseCode:DNSResponseCodeFormErr answers:nil];
}

+ (NSData*)createResponseForQuery:(NSData*)queryPacket
                     responseCode:(DNSResponseCode)responseCode
                          answers:(nullable NSArray<NSData*>*)answers {
  if (queryPacket.length < 12) {
    return queryPacket;  // Invalid query
  }

  const uint8_t* queryBytes = queryPacket.bytes;

  // Get counts from header
  uint16_t qdcount = (queryBytes[4] << 8) | queryBytes[5];
  //    uint16_t ancount = (queryBytes[6] << 8) | queryBytes[7];
  //    uint16_t nscount = (queryBytes[8] << 8) | queryBytes[9];
  //    uint16_t arcount = (queryBytes[10] << 8) | queryBytes[11];

  // Find the end of all sections in the query
  NSUInteger offset = 12;

  // Skip questions
  for (int i = 0; i < qdcount && offset < queryPacket.length; i++) {
    // Skip domain name
    while (offset < queryPacket.length && queryBytes[offset] != 0) {
      if (queryBytes[offset] > 63) {
        offset += 2;  // Compression pointer
        break;
      } else {
        offset += queryBytes[offset] + 1;
      }
    }
    if (offset < queryPacket.length && queryBytes[offset] == 0) {
      offset++;  // Skip null terminator
    }
    offset += 4;  // Skip QTYPE and QCLASS
  }

  NSUInteger questionEnd = offset;

  // Create response starting with header
  NSMutableData* response = [NSMutableData dataWithLength:12];
  uint8_t* respBytes = response.mutableBytes;

  // Copy transaction ID
  respBytes[0] = queryBytes[0];
  respBytes[1] = queryBytes[1];

  // Set response flags
  respBytes[2] = (queryBytes[2] & 0x01) | 0x80;          // Keep RD, set QR=1 (removed AA flag)
  respBytes[3] = (queryBytes[3] & 0xF0) | responseCode;  // Keep RA, set RCODE

  // Set counts
  respBytes[4] = queryBytes[4];  // Keep question count
  respBytes[5] = queryBytes[5];

  uint16_t answerCount = answers ? (uint16_t)answers.count : 0;
  respBytes[6] = (answerCount >> 8) & 0xFF;
  respBytes[7] = answerCount & 0xFF;

  // Clear authority and additional counts (we'll re-add EDNS if needed)
  respBytes[8] = 0;
  respBytes[9] = 0;
  respBytes[10] = 0;
  respBytes[11] = 0;

  // Copy question section
  if (questionEnd <= queryPacket.length) {
    [response appendData:[queryPacket subdataWithRange:NSMakeRange(12, questionEnd - 12)]];
  }

  // Append answers if any
  if (answers) {
    for (NSData* answer in answers) {
      [response appendData:answer];
    }
  }

  return response;
}

+ (NSData*)createARecordAnswer:(NSString*)domain ip:(NSString*)ipAddress ttl:(uint32_t)ttl {
  NSMutableData* answer = [NSMutableData new];

  // Use compression pointer to question section (offset 12)
  // This assumes the domain in the answer matches the question
  uint16_t compressionPointer = htons(0xC00C);  // 0xC00C = compression pointer to offset 12
  [answer appendBytes:&compressionPointer length:2];

  // Type A (1)
  uint16_t type = htons(DNSQueryTypeA);
  [answer appendBytes:&type length:2];

  // Class IN (1)
  uint16_t class = htons(1);
  [answer appendBytes:&class length:2];

  // TTL
  uint32_t ttlNetwork = htonl(ttl);
  [answer appendBytes:&ttlNetwork length:4];

  // Data length (4 bytes for IPv4)
  uint16_t dataLength = htons(4);
  [answer appendBytes:&dataLength length:2];

  // IP address
  NSArray* octets = [ipAddress componentsSeparatedByString:@"."];
  if (octets.count == 4) {
    for (NSString* octet in octets) {
      uint8_t byte = (uint8_t)[octet intValue];
      [answer appendBytes:&byte length:1];
    }
  } else {
    // Default to 127.0.0.1 if invalid
    uint8_t localhost[4] = {127, 0, 0, 1};
    [answer appendBytes:localhost length:4];
  }

  return answer;
}

+ (NSData*)createAAAARecordAnswer:(NSString*)domain ipv6:(NSString*)ipv6Address ttl:(uint32_t)ttl {
  NSMutableData* answer = [NSMutableData data];

  // Use compression pointer to question section
  uint16_t compressionPointer = htons(0xC00C);  // 0xC00C = compression pointer to offset 12
  [answer appendBytes:&compressionPointer length:2];

  // Type AAAA (28)
  uint16_t type = htons(DNSQueryTypeAAAA);
  [answer appendBytes:&type length:2];

  // Class IN (1)
  uint16_t class = htons(1);
  [answer appendBytes:&class length:2];

  // TTL
  uint32_t ttlNetwork = htonl(ttl);
  [answer appendBytes:&ttlNetwork length:4];

  // Data length (16 bytes for IPv6)
  uint16_t dataLength = htons(16);
  [answer appendBytes:&dataLength length:2];

  // IPv6 address
  struct in6_addr ipv6_addr;
  if (inet_pton(AF_INET6, [ipv6Address UTF8String], &ipv6_addr) == 1) {
    [answer appendBytes:&ipv6_addr length:16];
  } else {
    // Default to ::1 (IPv6 loopback) if invalid
    uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    [answer appendBytes:loopback length:16];
  }

  return answer;
}

+ (NSData*)extractTransactionID:(NSData*)packet {
  if (packet.length < 2) {
    return nil;
  }
  return [packet subdataWithRange:NSMakeRange(0, 2)];
}

+ (uint32_t)extractTTLFromResponse:(NSData*)response {
  if (response.length < 12) {
    return 300;  // Default 5 minutes
  }

  const uint8_t* bytes = response.bytes;

  // Skip header
  NSUInteger offset = 12;

  // Skip questions
  uint16_t qdcount = (bytes[4] << 8) | bytes[5];
  for (int i = 0; i < qdcount; i++) {
    // Skip domain name
    while (offset < response.length && bytes[offset] != 0) {
      if (bytes[offset] > 63) {
        offset += 2;  // Compression pointer
        break;
      } else {
        offset += bytes[offset] + 1;
      }
    }
    if (bytes[offset] == 0)
      offset++;   // Skip null terminator
    offset += 4;  // Skip type and class
  }

  // Get answer count
  uint16_t ancount = (bytes[6] << 8) | bytes[7];
  if (ancount == 0) {
    return 300;  // No answers, default TTL
  }

  // Skip to TTL in first answer
  // Skip domain name
  while (offset < response.length && bytes[offset] != 0) {
    if (bytes[offset] > 63) {
      offset += 2;  // Compression pointer
      break;
    } else {
      offset += bytes[offset] + 1;
    }
  }
  if (bytes[offset] == 0)
    offset++;  // Skip null terminator

  offset += 4;  // Skip type and class

  // Extract TTL
  if (offset + 4 <= response.length) {
    uint32_t ttl = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) |
                   bytes[offset + 3];
    return ttl;
  }

  return 300;  // Default
}

+ (nullable NSData*)updateTTLInResponse:(NSData*)response newTTL:(uint32_t)newTTL {
  if (response.length < 12) {
    return nil;  // Invalid response
  }

  NSMutableData* modifiedResponse = [response mutableCopy];
  const uint8_t* bytes = response.bytes;
  uint8_t* mutableBytes = modifiedResponse.mutableBytes;

  // Get counts from header
  uint16_t qdcount = (bytes[4] << 8) | bytes[5];
  uint16_t ancount = (bytes[6] << 8) | bytes[7];
  uint16_t nscount = (bytes[8] << 8) | bytes[9];
  // uint16_t arcount = (bytes[10] << 8) | bytes[11]; // Not used

  NSUInteger offset = 12;

  // Skip questions
  for (int i = 0; i < qdcount && offset < response.length; i++) {
    // Skip domain name
    while (offset < response.length && bytes[offset] != 0) {
      if (bytes[offset] > 63) {
        offset += 2;  // Compression pointer
        break;
      } else {
        offset += bytes[offset] + 1;
      }
    }
    if (offset < response.length && bytes[offset] == 0) {
      offset++;  // Skip null terminator
    }
    offset += 4;  // Skip QTYPE and QCLASS
  }

  // Update TTL in answer section
  for (int i = 0; i < ancount && offset < response.length; i++) {
    // Skip domain name
    while (offset < response.length && bytes[offset] != 0) {
      if (bytes[offset] > 63) {
        offset += 2;  // Compression pointer
        break;
      } else {
        offset += bytes[offset] + 1;
      }
    }
    if (offset < response.length && bytes[offset] == 0) {
      offset++;  // Skip null terminator
    }

    // Skip TYPE and CLASS
    offset += 4;

    // Update TTL
    if (offset + 4 <= response.length) {
      mutableBytes[offset] = (newTTL >> 24) & 0xFF;
      mutableBytes[offset + 1] = (newTTL >> 16) & 0xFF;
      mutableBytes[offset + 2] = (newTTL >> 8) & 0xFF;
      mutableBytes[offset + 3] = newTTL & 0xFF;
    }
    offset += 4;

    // Skip RDLENGTH and RDATA
    if (offset + 2 <= response.length) {
      uint16_t rdlength = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 2 + rdlength;
    }
  }

  // Also update TTL in authority section
  for (int i = 0; i < nscount && offset < response.length; i++) {
    // Skip domain name
    while (offset < response.length && bytes[offset] != 0) {
      if (bytes[offset] > 63) {
        offset += 2;  // Compression pointer
        break;
      } else {
        offset += bytes[offset] + 1;
      }
    }
    if (offset < response.length && bytes[offset] == 0) {
      offset++;  // Skip null terminator
    }

    // Skip TYPE and CLASS
    offset += 4;

    // Update TTL
    if (offset + 4 <= response.length) {
      mutableBytes[offset] = (newTTL >> 24) & 0xFF;
      mutableBytes[offset + 1] = (newTTL >> 16) & 0xFF;
      mutableBytes[offset + 2] = (newTTL >> 8) & 0xFF;
      mutableBytes[offset + 3] = newTTL & 0xFF;
    }
    offset += 4;

    // Skip RDLENGTH and RDATA
    if (offset + 2 <= response.length) {
      uint16_t rdlength = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 2 + rdlength;
    }
  }

  return modifiedResponse;
}

@end
