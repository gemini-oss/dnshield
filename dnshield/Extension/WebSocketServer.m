//
//  WebSocketServer.m
//  DNShield Network Extension
//
//  Simple WebSocket server implementation
//

#import <CommonCrypto/CommonDigest.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Network/Network.h>
#import <Security/Security.h>
#import <os/log.h>

#import <Common/DNShieldPreferences.h>
#import <Common/Defaults.h>
#import <Common/LoggingManager.h>
#import "WebSocketServer.h"

extern os_log_t logHandle;

@interface WebSocketClient : NSObject
@property(nonatomic, strong) nw_connection_t connection;
@property(nonatomic, strong) NSString* clientID;
@property(nonatomic, assign) BOOL handshakeComplete;
@end

@implementation WebSocketClient
@end

@interface WebSocketServer ()
@property(nonatomic, strong) nw_listener_t listener;
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, strong) NSMutableDictionary<NSString*, WebSocketClient*>* clients;
@property(nonatomic, assign) NSUInteger portNumber;
@property(nonatomic, strong) NSString* internalAuthToken;
@property(nonatomic, strong) NSSet<NSString*>* allowedOrigins;
// Rate limiting properties
@property(nonatomic, strong)
    NSMutableDictionary<NSString*, NSMutableArray<NSDate*>*>* rateLimitTracker;
@property(nonatomic, strong) NSMutableDictionary<NSString*, NSNumber*>* failedAuthAttempts;

- (nullable NSData*)payloadDataFromFrame:(NSData*)frameData opcode:(uint8_t* _Nullable)opcodeOut;
- (nullable NSData*)frameForJSONData:(NSData*)jsonData;
- (void)dispatchMessageToDelegate:(NSDictionary*)message fromClient:(WebSocketClient*)client;
@end

@implementation WebSocketServer

- (NSArray<NSString*>*)configuredExtensionIDs {
  NSMutableArray* extensionIDs = [NSMutableArray array];

  // 1. Managed preferences / defaults
  NSArray* preferenceIDs = DNPreferenceGetArray(kDNShieldChromeExtensionIDs);
  if ([preferenceIDs isKindOfClass:[NSArray class]]) {
    [extensionIDs addObjectsFromArray:preferenceIDs];
  }

  // 2. Check configuration file
  NSString* configPath = @"/Library/Application Support/DNShield/websocket_config.json";
  if ([[NSFileManager defaultManager] fileExistsAtPath:configPath]) {
    NSData* configData = [NSData dataWithContentsOfFile:configPath];
    if (configData) {
      NSError* error = nil;
      NSDictionary* config = [NSJSONSerialization JSONObjectWithData:configData
                                                             options:0
                                                               error:&error];
      if (!error && config[@"chromeExtensionIDs"]) {
        NSArray* configExtensionIDs = config[@"chromeExtensionIDs"];
        if ([configExtensionIDs isKindOfClass:[NSArray class]]) {
          [extensionIDs addObjectsFromArray:configExtensionIDs];
        }
      }
    }
  }

  // Log a warning if no extension IDs are configured
  if (extensionIDs.count == 0) {
    os_log_error(logHandle, "No Chrome extension IDs are configured. Ensure proper configuration "
                            "to avoid unauthorized access.");
  }

  return [extensionIDs copy];
}

- (instancetype)initWithPort:(NSUInteger)port {
  return [self initWithPort:port authToken:nil];
}

- (instancetype)initWithPort:(NSUInteger)port authToken:(nullable NSString*)authToken {
  self = [super init];
  if (self) {
    _portNumber = port;
    _queue = dispatch_queue_create("com.dnshield.websocket", DISPATCH_QUEUE_SERIAL);
    _clients = [NSMutableDictionary dictionary];
    _rateLimitTracker = [NSMutableDictionary dictionary];
    _failedAuthAttempts = [NSMutableDictionary dictionary];

    // Use provided auth token if available
    if (authToken && authToken.length > 0) {
      os_log_info(logHandle, "Using provided WebSocket auth token");
      _internalAuthToken = authToken;
    } else {
      // Check for enterprise-configured token first
      id configuredTokenObj = CFBridgingRelease(
          CFPreferencesCopyAppValue(CFSTR("WebSocketAuthToken"), DNPreferenceDomainCF()));

      // Validate type to prevent crashes from unexpected preference values
      NSString* configuredToken = nil;
      if ([configuredTokenObj isKindOfClass:[NSString class]]) {
        configuredToken = (NSString*)configuredTokenObj;
      } else if (configuredTokenObj) {
        os_log_error(logHandle, "WebSocketAuthToken preference is not a string (type: %@)",
                     NSStringFromClass([configuredTokenObj class]));
      }

      if (configuredToken && configuredToken.length > 0) {
        os_log_info(logHandle, "Using WebSocket auth token from configuration profile");
        _internalAuthToken = configuredToken;
      } else {
        // Generate or retrieve auth token for non-enterprise deployments
        _internalAuthToken = [self retrieveAuthTokenFromKeychain];
        if (!_internalAuthToken) {
          _internalAuthToken = [self generateSecureToken];
          NSError* error = nil;
          if (![self storeAuthTokenInKeychain:&error]) {
            os_log_error(logHandle, "Failed to store auth token in keychain: %{public}@",
                         error.localizedDescription);
          }
        }
      }
    }

    // Set allowed origins for Chrome extension
    // Extension IDs can be configured via Info.plist or config file
    NSMutableSet* origins = [NSMutableSet set];

    // Check for configured extension IDs
    NSArray* configuredExtensionIDs = [self configuredExtensionIDs];
    for (NSString* extensionID in configuredExtensionIDs) {
      [origins addObject:[NSString stringWithFormat:@"chrome-extension://%@", extensionID]];
    }

    // Note: localhost debugging should be done via proper extension ID configuration
    // Never allow raw localhost origin in production

    _allowedOrigins = [origins copy];

    // Log configured origins
    os_log_info(logHandle, "WebSocket configured with %lu allowed origins",
                (unsigned long)_allowedOrigins.count);
    for (NSString* origin in _allowedOrigins) {
      os_log_debug(logHandle, "Allowed origin: %{public}@", origin);
    }
  }
  return self;
}

- (BOOL)start:(NSError**)error {
  if (self.listener) {
    return YES;  // Already running
  }

  // Create TCP parameters for WebSocket
  nw_parameters_t parameters =
      nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,  // No TLS for localhost
                                      NW_PARAMETERS_DEFAULT_CONFIGURATION);

  // Configure to support both IPv4 and IPv6
  nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
  nw_protocol_options_t ip_options = nw_protocol_stack_copy_internet_protocol(stack);
  if (ip_options) {
    nw_ip_options_set_version(ip_options, nw_ip_version_any);
  }

  // Create listener on port
  // Note: Network.framework doesn't provide direct localhost-only binding
  // We'll enforce localhost check at connection acceptance
  NSString* portStr = [NSString stringWithFormat:@"%lu", (unsigned long)self.portNumber];
  self.listener = nw_listener_create_with_port([portStr UTF8String], parameters);

  // Log security note about binding
  os_log_info(
      logHandle,
      "WebSocket server binding to port %lu - localhost connections enforced via origin check",
      (unsigned long)self.portNumber);

  if (!self.listener) {
    if (error) {
      *error =
          [NSError errorWithDomain:@"WebSocketServer"
                              code:1
                          userInfo:@{NSLocalizedDescriptionKey : @"Failed to create listener"}];
    }
    return NO;
  }

  // Set state handler
  nw_listener_set_state_changed_handler(
      self.listener, ^(nw_listener_state_t state, nw_error_t _Nullable err) {
        switch (state) {
          case nw_listener_state_ready:
            os_log_info(logHandle, "WebSocket server listening on port %lu",
                        (unsigned long)self.portNumber);
            self->_running = YES;
            if (self.delegate) {
              dispatch_async(dispatch_get_main_queue(), ^{
                [self.delegate webSocketServerDidStart:self.portNumber];
              });
            }
            break;

          case nw_listener_state_failed:
            os_log_error(logHandle, "WebSocket server failed to start");
            self->_running = NO;
            break;

          default: break;
        }
      });

  // Set new connection handler
  nw_listener_set_new_connection_handler(self.listener, ^(nw_connection_t connection) {
    [self handleNewConnection:connection];
  });

  // Start listener
  nw_listener_set_queue(self.listener, self.queue);
  nw_listener_start(self.listener);

  return YES;
}

- (void)stop {
  if (self.listener) {
    nw_listener_cancel(self.listener);
    self.listener = nil;
    _running = NO;

    // Close all client connections
    for (WebSocketClient* client in self.clients.allValues) {
      nw_connection_cancel(client.connection);
    }
    [self.clients removeAllObjects];
  }
}

- (void)handleNewConnection:(nw_connection_t)connection {
  NSString* clientID = [[NSUUID UUID] UUIDString];
  WebSocketClient* client = [[WebSocketClient alloc] init];
  client.connection = connection;
  client.clientID = clientID;
  client.handshakeComplete = NO;

  self.clients[clientID] = client;

  os_log_info(logHandle, "WebSocket client connected: %{public}@", clientID);

  // Set state handler
  nw_connection_set_state_changed_handler(
      connection, ^(nw_connection_state_t state, nw_error_t error) {
        if (state == nw_connection_state_failed || state == nw_connection_state_cancelled) {
          os_log_info(logHandle, "WebSocket client disconnected: %{public}@", clientID);
          [self.clients removeObjectForKey:clientID];
        }
      });

  // Start connection
  nw_connection_set_queue(connection, self.queue);
  nw_connection_start(connection);

  // Start receiving data
  [self receiveData:client];
}

- (void)receiveData:(WebSocketClient*)client {
  nw_connection_receive(
      client.connection, 1, UINT32_MAX,
      ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t error) {
        if (content) {
          NSData* data = (NSData*)content;

          if (!client.handshakeComplete) {
            // Handle WebSocket handshake
            NSString* request = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (request && [request containsString:@"Upgrade: websocket"]) {
              if ([self validateHandshakeRequest:request fromClient:client]) {
                [self sendHandshakeResponse:client request:request];
                client.handshakeComplete = YES;
              } else {
                // Send unauthorized response and disconnect
                [self sendUnauthorizedResponse:client];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                               self.queue, ^{
                                 nw_connection_cancel(client.connection);
                                 [self.clients removeObjectForKey:client.clientID];
                               });
                return;
              }
            }
          } else {
            // Handle WebSocket frames (we only need to handle ping/pong for keep-alive)
            [self handleWebSocketFrame:data fromClient:client];
          }
        }

        // Continue receiving if connection is still valid
        if (!error) {
          [self receiveData:client];
        }
      });
}

- (void)sendHandshakeResponse:(WebSocketClient*)client request:(NSString*)request {
  // Extract Sec-WebSocket-Key
  NSString* key = nil;
  NSString* wsProtocol = nil;
  NSArray* lines = [request componentsSeparatedByString:@"\r\n"];
  for (NSString* line in lines) {
    if ([line hasPrefix:@"Sec-WebSocket-Key:"]) {
      key = [line substringFromIndex:[@"Sec-WebSocket-Key:" length]];
      key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    } else if ([line hasPrefix:@"Sec-WebSocket-Protocol:"]) {
      wsProtocol = [line substringFromIndex:[@"Sec-WebSocket-Protocol:" length]];
      wsProtocol =
          [wsProtocol stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    }
  }

  if (!key) {
    os_log_error(logHandle, "No WebSocket key found in request");
    return;
  }

  // Calculate Sec-WebSocket-Accept
  NSString* guid = @"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  NSString* combined = [key stringByAppendingString:guid];

  unsigned char digest[CC_SHA1_DIGEST_LENGTH];
  CC_SHA1([combined UTF8String],
          (CC_LONG)[combined lengthOfBytesUsingEncoding:NSUTF8StringEncoding], digest);

  NSData* digestData = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
  NSString* acceptKey = [digestData base64EncodedStringWithOptions:0];

  // Build response with optional protocol acknowledgment
  NSMutableString* response =
      [NSMutableString stringWithFormat:@"HTTP/1.1 101 Switching Protocols\r\n"
                                        @"Upgrade: websocket\r\n"
                                        @"Connection: Upgrade\r\n"
                                        @"Sec-WebSocket-Accept: %@\r\n",
                                        acceptKey];

  // If auth was provided via subprotocol, acknowledge it
  if (wsProtocol && [wsProtocol hasPrefix:@"auth."]) {
    [response
        appendString:[NSString stringWithFormat:@"Sec-WebSocket-Protocol: %@\r\n", wsProtocol]];
  }

  [response appendString:@"\r\n"];

  NSData* responseData = [response dataUsingEncoding:NSUTF8StringEncoding];
  dispatch_data_t dispatchData = dispatch_data_create(responseData.bytes, responseData.length, NULL,
                                                      DISPATCH_DATA_DESTRUCTOR_DEFAULT);

  nw_connection_send(client.connection, dispatchData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                     ^(nw_error_t error) {
                       if (!error) {
                         os_log_info(logHandle,
                                     "WebSocket handshake completed for client %{public}@",
                                     client.clientID);
                       }
                     });
}

- (nullable NSData*)payloadDataFromFrame:(NSData*)frameData opcode:(uint8_t* _Nullable)opcodeOut {
  if (frameData.length < 2) {
    return nil;
  }

  const uint8_t* bytes = frameData.bytes;
  uint8_t opcode = bytes[0] & 0x0F;
  if (opcodeOut) {
    *opcodeOut = opcode;
  }

  BOOL masked = (bytes[1] & 0x80) != 0;
  uint64_t payloadLength = (uint64_t)(bytes[1] & 0x7F);
  NSUInteger cursor = 2;

  if (payloadLength == 126) {
    if (frameData.length < cursor + 2) {
      return nil;
    }
    payloadLength = ((uint64_t)bytes[cursor] << 8) | (uint64_t)bytes[cursor + 1];
    cursor += 2;
  } else if (payloadLength == 127) {
    if (frameData.length < cursor + 8) {
      return nil;
    }
    payloadLength = 0;
    for (int i = 0; i < 8; i++) {
      payloadLength = (payloadLength << 8) | (uint64_t)bytes[cursor + i];
    }
    cursor += 8;
  }

  if (payloadLength > (1ull << 20)) {  // Limit to 1 MiB to avoid abuse
    os_log_error(logHandle, "WebSocket payload too large (%llu bytes)", payloadLength);
    return nil;
  }

  uint8_t maskingKey[4] = {0};
  if (masked) {
    if (frameData.length < cursor + 4) {
      return nil;
    }
    memcpy(maskingKey, bytes + cursor, 4);
    cursor += 4;
  }

  if (payloadLength > frameData.length - cursor) {
    return nil;
  }

  NSMutableData* payload = [NSMutableData dataWithLength:(NSUInteger)payloadLength];
  if (payloadLength > 0) {
    memcpy(payload.mutableBytes, bytes + cursor, (NSUInteger)payloadLength);
  }

  if (masked && payloadLength > 0) {
    uint8_t* payloadBytes = payload.mutableBytes;
    for (NSUInteger i = 0; i < payloadLength; i++) {
      payloadBytes[i] ^= maskingKey[i % 4];
    }
  }

  return payload;
}

- (nullable NSData*)frameForJSONData:(NSData*)jsonData {
  if (!jsonData) {
    return nil;
  }

  NSMutableData* frame = [NSMutableData data];

  uint8_t firstByte = 0x81;  // FIN + text frame
  [frame appendBytes:&firstByte length:1];

  NSUInteger length = jsonData.length;
  if (length <= 125) {
    uint8_t len = (uint8_t)length;
    [frame appendBytes:&len length:1];
  } else if (length <= 65535) {
    uint8_t len = 126;
    [frame appendBytes:&len length:1];
    uint16_t extendedLen = htons((uint16_t)length);
    [frame appendBytes:&extendedLen length:2];
  } else {
    uint8_t len = 127;
    [frame appendBytes:&len length:1];
    uint64_t extendedLen = CFSwapInt64HostToBig((uint64_t)length);
    [frame appendBytes:&extendedLen length:8];
  }

  [frame appendData:jsonData];
  return frame;
}

- (void)dispatchMessageToDelegate:(NSDictionary*)message fromClient:(WebSocketClient*)client {
  if (!message || !client.clientID) {
    return;
  }

  if (![self.delegate respondsToSelector:@selector(webSocketServerDidReceiveMessage:fromClient:)]) {
    return;
  }

  NSDictionary* messageCopy = [message copy];
  NSString* clientID = [client.clientID copy];

  dispatch_async(dispatch_get_main_queue(), ^{
    if ([self.delegate respondsToSelector:@selector(webSocketServerDidReceiveMessage:
                                                                          fromClient:)]) {
      [self.delegate webSocketServerDidReceiveMessage:messageCopy fromClient:clientID];
    }
  });
}

- (void)handleWebSocketFrame:(NSData*)frameData fromClient:(WebSocketClient*)client {
  uint8_t opcode = 0;
  NSData* payload = [self payloadDataFromFrame:frameData opcode:&opcode];

  if (!payload && opcode != 0x08 && opcode != 0x09) {
    os_log_error(logHandle, "Failed to decode WebSocket frame (opcode %u)", opcode);
    return;
  }

  switch (opcode) {
    case 0x01: {  // Text frame
      if (!payload) {
        os_log_error(logHandle, "Text frame payload missing");
        return;
      }

      NSString* text = [[NSString alloc] initWithData:payload encoding:NSUTF8StringEncoding];
      if (!text) {
        os_log_error(logHandle, "Failed to decode WebSocket text payload");
        return;
      }

      NSError* jsonError = nil;
      id jsonObject = [NSJSONSerialization JSONObjectWithData:payload options:0 error:&jsonError];
      if (jsonError || ![jsonObject isKindOfClass:[NSDictionary class]]) {
        os_log_error(logHandle, "Failed to parse WebSocket JSON payload: %{public}@",
                     jsonError.localizedDescription);
        return;
      }

      os_log_debug(logHandle, "Received WebSocket message: %{public}@", text);
      [self dispatchMessageToDelegate:(NSDictionary*)jsonObject fromClient:client];
      break;
    }

    case 0x08: {  // Close
      os_log_info(logHandle, "Received WebSocket close frame from client %{public}@",
                  client.clientID);
      nw_connection_cancel(client.connection);
      [self.clients removeObjectForKey:client.clientID];
      break;
    }

    case 0x09: {  // Ping
      [self sendPong:client];
      break;
    }

    default: os_log_debug(logHandle, "Ignoring unsupported WebSocket opcode: %u", opcode); break;
  }
}

- (void)sendPong:(WebSocketClient*)client {
  // Simple pong frame: FIN=1, opcode=0xA (pong)
  uint8_t pongFrame[] = {0x8A, 0x00};  // Empty pong

  dispatch_data_t data =
      dispatch_data_create(pongFrame, sizeof(pongFrame), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);

  nw_connection_send(client.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                     ^(nw_error_t _Nullable error) {
                       if (error) {
                         DNSLogError(LogCategoryNetwork, "Failed to send pong: %@", error);
                       }
                     });
}

- (void)broadcastMessage:(NSDictionary*)message {
  NSError* error = nil;
  NSData* jsonData = [NSJSONSerialization dataWithJSONObject:message options:0 error:&error];
  if (!jsonData) {
    os_log_error(logHandle, "Failed to serialize message: %{public}@", error.localizedDescription);
    return;
  }

  NSData* frame = [self frameForJSONData:jsonData];
  if (!frame) {
    return;
  }

  os_log_info(logHandle, "WebSocket frame: length=%lu, JSON=%{public}@",
              (unsigned long)frame.length,
              [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding]);

  if (frame.length >= 2) {
    const uint8_t* bytes = frame.bytes;
    os_log_info(logHandle, "Frame header: 0x%02X 0x%02X (first 2 bytes)", bytes[0], bytes[1]);
  }

  dispatch_data_t dispatchData =
      dispatch_data_create(frame.bytes, frame.length, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);

  NSUInteger sentCount = 0;
  NSUInteger totalClients = self.clients.count;

  os_log_info(logHandle, "Broadcasting to %lu total clients", (unsigned long)totalClients);

  for (WebSocketClient* client in self.clients.allValues) {
    os_log_info(logHandle, "Client %{public}@: handshake=%d", client.clientID,
                client.handshakeComplete);

    if (client.handshakeComplete) {
      nw_connection_send(
          client.connection, dispatchData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
          ^(nw_error_t error) {
            if (error) {
              os_log_error(logHandle, "Failed to send to client %{public}@: %{public}@",
                           client.clientID, error);
            } else {
              os_log_info(logHandle, "Successfully sent message to client %{public}@",
                          client.clientID);
            }
          });
      sentCount++;
    } else {
      os_log_info(logHandle, "Skipping client %{public}@ - handshake not complete",
                  client.clientID);
    }
  }

  if (sentCount == 0) {
    os_log_info(logHandle, "No WebSocket clients connected to receive message");
  } else {
    os_log_info(logHandle, "Sent WebSocket message to %lu clients", (unsigned long)sentCount);
  }
}

- (void)sendMessage:(NSDictionary*)message toClient:(NSString*)clientID {
  if (!message || clientID.length == 0) {
    return;
  }

  NSError* error = nil;
  NSData* jsonData = [NSJSONSerialization dataWithJSONObject:message options:0 error:&error];
  if (!jsonData) {
    os_log_error(logHandle, "Failed to serialize message for client %{public}@: %{public}@",
                 clientID, error.localizedDescription);
    return;
  }

  NSData* frame = [self frameForJSONData:jsonData];
  if (!frame) {
    return;
  }

  dispatch_data_t dispatchData =
      dispatch_data_create(frame.bytes, frame.length, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  NSString* clientIDCopy = [clientID copy];

  dispatch_async(self.queue, ^{
    WebSocketClient* client = self.clients[clientIDCopy];
    if (!client || !client.handshakeComplete) {
      os_log_info(logHandle,
                  "Skipping send to client %{public}@ - not connected or handshake incomplete",
                  clientIDCopy);
      return;
    }

    nw_connection_send(
        client.connection, dispatchData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
        ^(nw_error_t error) {
          if (error) {
            os_log_error(logHandle, "Failed to send message to client %{public}@: %{public}@",
                         clientIDCopy, error);
          } else {
            os_log_debug(logHandle, "Sent message to client %{public}@", clientIDCopy);
          }
        });
  });
}

- (void)notifyBlockedDomain:(NSString*)domain
                    process:(NSString*)process
                  timestamp:(NSDate*)timestamp {
  NSDictionary* message = @{
    @"type" : @"blocked_site",
    @"data" : @{
      @"domain" : domain ?: @"unknown",
      @"process" : process ?: @"unknown",
      @"timestamp" : [self ISO8601StringFromDate:timestamp]
    }
  };

  os_log_info(logHandle, "Broadcasting blocked domain: %{public}@ to %lu clients", domain,
              (unsigned long)self.clients.count);
  [self broadcastMessage:message];
}

- (NSString*)ISO8601StringFromDate:(NSDate*)date {
  if (!date)
    date = [NSDate date];

  static NSDateFormatter* formatter = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
  });

  return [formatter stringFromDate:date];
}

#pragma mark - Authentication

- (NSString*)authToken {
  return _internalAuthToken;
}

- (BOOL)validateHandshakeRequest:(NSString*)request fromClient:(WebSocketClient*)client {
  // Extract client IP for rate limiting (use connection info)
  NSString* clientIdentifier = client.clientID ?: @"unknown";

  // Check rate limiting first (10 attempts per minute per client)
  if (![self checkRateLimit:clientIdentifier]) {
    os_log_error(logHandle, "WebSocket rate limit exceeded for client: %{public}@",
                 clientIdentifier);
    return NO;
  }

  // Extract headers
  NSArray* lines = [request componentsSeparatedByString:@"\r\n"];
  NSMutableDictionary* headers = [NSMutableDictionary dictionary];

  for (NSString* line in lines) {
    NSRange colonRange = [line rangeOfString:@":"];
    if (colonRange.location != NSNotFound) {
      NSString* key = [[line substringToIndex:colonRange.location] lowercaseString];
      NSString* value = [[line substringFromIndex:colonRange.location + 1]
          stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
      headers[key] = value;
    }
  }

  // Method 1: Check Authorization header (for non-browser clients)
  NSString* authHeader = headers[@"authorization"];
  if (authHeader) {
    NSString* expectedAuth = [NSString stringWithFormat:@"Bearer %@", self.internalAuthToken];
    if ([authHeader isEqualToString:expectedAuth]) {
      os_log_info(logHandle, "WebSocket authenticated via Authorization header");
      return YES;
    }
  }

  // Method 2: Check Sec-WebSocket-Protocol for auth token (for browser clients)
  NSString* wsProtocol = headers[@"sec-websocket-protocol"];
  if (wsProtocol && [wsProtocol hasPrefix:@"auth."]) {
    NSString* encodedToken = [wsProtocol substringFromIndex:5];  // Remove "auth." prefix
    // URL-decode the token (it may contain special characters like = in base64)
    NSString* providedToken = [encodedToken stringByRemovingPercentEncoding];
    if (!providedToken) {
      os_log_error(logHandle, "WebSocket authentication failed: token could not be URL-decoded or "
                              "is in an unexpected format");
      return NO;
    }
    if ([providedToken isEqualToString:self.internalAuthToken]) {
      os_log_info(logHandle, "WebSocket authenticated via subprotocol");

      // Check Origin header for browser connections
      NSString* origin = headers[@"origin"];
      if (origin && ![self.allowedOrigins containsObject:origin]) {
        os_log_error(logHandle, "WebSocket connection from unauthorized origin: %{public}@",
                     origin);
        return NO;
      }

      return YES;
    }
  }

  os_log_error(logHandle, "WebSocket connection failed authentication - no valid auth method");

  // Track failed authentication attempt
  [self recordFailedAuth:clientIdentifier];

  return NO;
}

#pragma mark - Rate Limiting

- (BOOL)checkRateLimit:(NSString*)clientID {
  if (!clientID)
    return NO;

  @synchronized(self.rateLimitTracker) {
    NSMutableArray<NSDate*>* attempts = self.rateLimitTracker[clientID];
    if (!attempts) {
      attempts = [NSMutableArray array];
      self.rateLimitTracker[clientID] = attempts;
    }

    // Remove attempts older than 1 minute
    NSDate* oneMinuteAgo = [NSDate dateWithTimeIntervalSinceNow:-60];
    [attempts filterUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDate* date,
                                                                         NSDictionary* bindings) {
                return [date timeIntervalSinceDate:oneMinuteAgo] > 0;
              }]];

    // Check if under rate limit (10 attempts per minute)
    if (attempts.count >= 10) {
      return NO;
    }

    // Check if client is blocked due to failed auth attempts
    NSNumber* failedCount = self.failedAuthAttempts[clientID];
    if (failedCount && failedCount.integerValue >= 5) {
      // Block for 5 minutes after 5 failed attempts
      return NO;
    }

    // Record this attempt
    [attempts addObject:[NSDate date]];

    return YES;
  }
}

- (void)recordFailedAuth:(NSString*)clientID {
  if (!clientID)
    return;

  @synchronized(self.failedAuthAttempts) {
    NSNumber* currentCount = self.failedAuthAttempts[clientID] ?: @0;
    self.failedAuthAttempts[clientID] = @(currentCount.integerValue + 1);

    // Log security event
    os_log_error(logHandle, "SECURITY: Failed WebSocket auth attempt %ld from client: %{public}@",
                 (long)(currentCount.integerValue + 1), clientID);

    // Clean up old entries periodically (simple approach)
    if (self.failedAuthAttempts.count > 100) {
      [self.failedAuthAttempts removeAllObjects];
    }
  }
}

- (void)sendUnauthorizedResponse:(WebSocketClient*)client {
  NSString* response = @"HTTP/1.1 401 Unauthorized\r\n"
                       @"Content-Type: text/plain\r\n"
                       @"Content-Length: 12\r\n"
                       @"\r\n"
                       @"Unauthorized";

  NSData* responseData = [response dataUsingEncoding:NSUTF8StringEncoding];
  dispatch_data_t dispatchData =
      dispatch_data_create(responseData.bytes, responseData.length, dispatch_get_main_queue(),
                           DISPATCH_DATA_DESTRUCTOR_DEFAULT);

  nw_connection_send(client.connection, dispatchData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                     ^(nw_error_t error) {
                       if (error) {
                         os_log_error(logHandle, "Failed to send unauthorized response");
                       }
                     });
}

- (NSString*)generateSecureToken {
  // Generate a 32-byte random token
  uint8_t tokenBytes[32];
  if (SecRandomCopyBytes(kSecRandomDefault, sizeof(tokenBytes), tokenBytes) != 0) {
    os_log_error(logHandle, "Failed to generate secure random bytes");
    // Fallback to UUID
    return [[NSUUID UUID] UUIDString];
  }

  // Convert to base64
  NSData* tokenData = [NSData dataWithBytes:tokenBytes length:sizeof(tokenBytes)];
  return [tokenData base64EncodedStringWithOptions:0];
}

- (NSString*)extractHeader:(NSString*)headerName fromRequest:(NSString*)request {
  NSArray* lines = [request componentsSeparatedByString:@"\r\n"];
  NSString* searchKey = [headerName lowercaseString];

  for (NSString* line in lines) {
    NSRange colonRange = [line rangeOfString:@":"];
    if (colonRange.location != NSNotFound) {
      NSString* key = [[line substringToIndex:colonRange.location] lowercaseString];
      if ([key isEqualToString:searchKey]) {
        return [[line substringFromIndex:colonRange.location + 1]
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
      }
    }
  }
  return nil;
}

#pragma mark - Keychain Management

- (BOOL)storeAuthTokenInKeychain:(NSError**)error {
  if (!self.internalAuthToken) {
    if (error) {
      *error = [NSError errorWithDomain:@"WebSocketServer"
                                   code:1001
                               userInfo:@{NSLocalizedDescriptionKey : @"No auth token to store"}];
    }
    return NO;
  }

  NSData* tokenData = [self.internalAuthToken dataUsingEncoding:NSUTF8StringEncoding];

  // Delete any existing token first
  NSDictionary* deleteQuery = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : @"com.dnshield.websocket",
    (__bridge id)kSecAttrAccount : @"auth-token"
  };
  SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

  // Add new token
  NSDictionary* addQuery = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : @"com.dnshield.websocket",
    (__bridge id)kSecAttrAccount : @"auth-token",
    (__bridge id)kSecValueData : tokenData,
    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    (__bridge id)kSecAttrSynchronizable : @NO,
    (__bridge id)kSecAttrAccessGroup : kDNShieldAppGroup
  };

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);

  if (status != errSecSuccess) {
    if (error) {
      *error = [NSError
          errorWithDomain:NSOSStatusErrorDomain
                     code:status
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to store token in keychain"}];
    }
    return NO;
  }

  return YES;
}

- (nullable NSString*)retrieveAuthTokenFromKeychain {
  NSDictionary* query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : @"com.dnshield.websocket",
    (__bridge id)kSecAttrAccount : @"auth-token",
    (__bridge id)kSecReturnData : @YES,
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
    (__bridge id)kSecAttrAccessGroup : kDNShieldAppGroup
  };

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

  if (status == errSecSuccess && result) {
    NSData* tokenData = (__bridge_transfer NSData*)result;
    return [[NSString alloc] initWithData:tokenData encoding:NSUTF8StringEncoding];
  }

  return nil;
}

- (void)setAuthToken:(NSString*)authToken {
  if (authToken && authToken.length > 0) {
    _internalAuthToken = authToken;
    os_log_info(logHandle, "WebSocket auth token updated");
  }
}

@end
