//
//  XPCClient.m
//  DNShield
//
//  XPC Client implementation
//

#import <os/log.h>

#import <Common/Defaults.h>

#import "LoggingManager.h"
#import "XPCClient.h"
#import "XPCProtocol.h"

extern os_log_t logHandle;

@interface XPCClient ()

@property(nonatomic, strong) NSXPCConnection* connection;
@property(nonatomic, strong) dispatch_queue_t connectionQueue;
@property(nonatomic, assign) NSInteger connectionRetryCount;
@property(nonatomic, assign) BOOL isRetrying;

@end

@implementation XPCClient

+ (instancetype)sharedClient {
  static XPCClient* sharedClient = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedClient = [[XPCClient alloc] init];
  });
  return sharedClient;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    self.connectionQueue = dispatch_queue_create("com.dnshield.xpc", DISPATCH_QUEUE_SERIAL);
    self.connectionRetryCount = 0;
    self.isRetrying = NO;
    [self setupConnection];
  }
  return self;
}

- (void)setupConnection {
  if (self.connection) {
    [self.connection invalidate];
    self.connection = nil;
  }

  // Get team identifier prefix
  NSString* teamID = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"TeamIdentifierPrefix"];
  if (!teamID) {
    // Try to extract from keychain access groups or app groups
    NSArray* appGroups =
        [[NSBundle mainBundle] objectForInfoDictionaryKey:@"com.apple.security.application-groups"];
    if (appGroups.count > 0) {
      NSString* firstGroup = appGroups.firstObject;
      // Extract team ID from group identifier (format: TEAMID.com.example)
      NSArray* components = [firstGroup componentsSeparatedByString:@"."];
      if (components.count > 0) {
        teamID = [NSString stringWithFormat:@"%@.", components.firstObject];
      }
    }
  }

  // Use the system extension's published mach service (matches Info.plist NEMachServiceName)
  NSString* serviceName = kDNShieldAppGroup;

  // Use NSXPCConnectionPrivileged for better security validation
  NSXPCConnectionOptions options = NSXPCConnectionPrivileged;
  self.connection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:options];

  self.connection.remoteObjectInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(XPCExtensionProtocol)];
  // Set up error handlers
  __weak typeof(self) weakSelf = self;
  self.connection.interruptionHandler = ^{
    DNSLogError(LogCategoryGeneral, "XPC connection interrupted");
    dispatch_async(weakSelf.connectionQueue, ^{
      weakSelf.connection = nil;
      [weakSelf retryConnectionWithDelay];
    });
  };

  self.connection.invalidationHandler = ^{
    DNSLogError(LogCategoryGeneral, "XPC connection invalidated");
    dispatch_async(weakSelf.connectionQueue, ^{
      weakSelf.connection = nil;
    });
  };

  [self.connection resume];
  DNSLogInfo(LogCategoryGeneral, "XPC connection setup initiated for service: %{public}@",
             serviceName);

  // Reset retry count on successful setup
  self.connectionRetryCount = 0;
}

- (void)retryConnectionWithDelay {
  if (self.isRetrying) {
    return;
  }

  self.isRetrying = YES;
  self.connectionRetryCount++;

  // Exponential backoff: 1s, 2s, 4s, 8s, max 16s
  NSTimeInterval delay = MIN(pow(2, self.connectionRetryCount - 1), 16);

  DNSLogInfo(LogCategoryGeneral, "Retrying XPC connection in %.0f seconds (attempt %ld)", delay,
             (long)self.connectionRetryCount);

  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                 self.connectionQueue, ^{
                   self.isRetrying = NO;
                   [self setupConnection];
                 });
}

- (id<XPCExtensionProtocol>)remoteObjectProxyWithErrorHandler:
    (void (^)(NSError* error))errorHandler {
  // Ensure we have a valid connection
  if (!self.connection) {
    DNSLogError(LogCategoryGeneral, "XPC connection is nil, attempting to reconnect");
    [self setupConnection];

    // If still no connection, report error
    if (!self.connection) {
      NSError* error = [NSError
          errorWithDomain:@"XPCClientErrorDomain"
                     code:1001
                 userInfo:@{NSLocalizedDescriptionKey : @"Failed to establish XPC connection"}];
      if (errorHandler) {
        errorHandler(error);
      }
      return nil;
    }
  }

  return [self.connection remoteObjectProxyWithErrorHandler:^(NSError* _Nonnull error) {
    DNSLogError(LogCategoryGeneral, "XPC remote object error: %{public}@",
                error.localizedDescription);

    // Check if this is a connection error
    if (error.code == 4099 ||
        error.code == 4097) {  // NSXPCConnectionInterrupted or NSXPCConnectionInvalid
      DNSLogError(LogCategoryGeneral, "XPC connection error detected, will attempt reconnection");
      dispatch_async(self.connectionQueue, ^{
        self.connection = nil;
        [self retryConnectionWithDelay];
      });
    }

    if (errorHandler) {
      errorHandler(error);
    }
  }];
}

#pragma mark - Public Methods

- (void)updateBlockedDomains:(NSArray<NSString*>*)domains
           completionHandler:(void (^_Nullable)(BOOL success, NSError* _Nullable error))completion {
  DNSLogInfo(LogCategoryRuleFetching, "XPCClient updateBlockedDomains called with %lu domains",
             (unsigned long)domains.count);

  dispatch_async(self.connectionQueue, ^{
    DNSLogInfo(LogCategoryGeneral, "Getting remote proxy for updateBlockedDomains");

    __block BOOL responseReceived = NO;

    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      DNSLogError(LogCategoryGeneral, "XPC remoteObjectProxy error: %{public}@",
                  error.localizedDescription);
      if (!responseReceived && completion) {
        responseReceived = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    if (!proxy) {
      DNSLogError(LogCategoryGeneral, "Failed to get remote proxy object");
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          NSError* error =
              [NSError errorWithDomain:@"XPCClientErrorDomain"
                                  code:1002
                              userInfo:@{
                                NSLocalizedDescriptionKey : @"Failed to create remote proxy object"
                              }];
          completion(NO, error);
        });
      }
      return;
    }

    DNSLogInfo(LogCategoryRuleFetching, "Calling proxy updateBlockedDomains with %lu domains",
               (unsigned long)domains.count);
    for (NSString* domain in domains) {
      DNSLogDebug(LogCategoryRuleFetching, "  - %{public}@", domain);
    }

    // Add timeout protection
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
    dispatch_after(timeout, self.connectionQueue, ^{
      if (!responseReceived) {
        DNSLogError(LogCategoryGeneral, "XPC call timed out after 5 seconds");
        responseReceived = YES;
        if (completion) {
          dispatch_async(dispatch_get_main_queue(), ^{
            NSError* error =
                [NSError errorWithDomain:@"XPCClientErrorDomain"
                                    code:1003
                                userInfo:@{NSLocalizedDescriptionKey : @"XPC call timed out"}];
            completion(NO, error);
          });
        }
      }
    });

    [proxy updateBlockedDomains:domains
              completionHandler:^(BOOL success) {
                DNSLogInfo(LogCategoryRuleFetching,
                           "Extension updateBlockedDomains returned: %{public}s",
                           success ? "success" : "failed");
                if (!responseReceived && completion) {
                  responseReceived = YES;
                  dispatch_async(dispatch_get_main_queue(), ^{
                    completion(success, nil);
                  });
                }
              }];
  });
}

- (void)updateDNSServers:(NSArray<NSString*>*)servers
       completionHandler:(void (^_Nullable)(BOOL success, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy updateDNSServers:servers
          completionHandler:^(BOOL success) {
            DNSLogInfo(LogCategoryDNS, "Updated DNS servers: %{public}s",
                       success ? "success" : "failed");
            if (completion) {
              dispatch_async(dispatch_get_main_queue(), ^{
                completion(success, nil);
              });
            }
          }];
  });
}

- (void)getStatisticsWithCompletionHandler:(void (^)(NSDictionary* _Nullable stats,
                                                     NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(nil, error);
        });
      }
    }];

    [proxy getStatisticsWithCompletionHandler:^(NSDictionary* _Nullable stats) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(stats, nil);
        });
      }
    }];
  });
}

- (void)clearCacheWithCompletionHandler:(void (^_Nullable)(BOOL success,
                                                           NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy clearCacheWithCompletionHandler:^(BOOL success) {
      DNSLogInfo(LogCategoryCache, "Clear cache: %{public}s", success ? "success" : "failed");
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(success, nil);
        });
      }
    }];
  });
}

- (void)updateConfiguration:(NSDictionary*)config
          completionHandler:(void (^_Nullable)(BOOL success, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy updateConfiguration:config
             completionHandler:^(BOOL success) {
               DNSLogInfo(LogCategoryConfiguration, "Update configuration: %{public}s",
                          success ? "success" : "failed");
               if (completion) {
                 dispatch_async(dispatch_get_main_queue(), ^{
                   completion(success, nil);
                 });
               }
             }];
  });
}

- (void)getManagedBlockedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(nil, error);
        });
      }
    }];

    [proxy getManagedBlockedDomainsWithCompletionHandler:^(NSArray<NSString*>* _Nullable domains) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(domains, nil);
        });
      }
    }];
  });
}

- (void)getManagedAllowedDomainsWithCompletionHandler:
    (void (^)(NSArray<NSString*>* _Nullable domains, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(nil, error);
        });
      }
    }];

    [proxy getManagedAllowedDomainsWithCompletionHandler:^(NSArray<NSString*>* _Nullable domains) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(domains, nil);
        });
      }
    }];
  });
}

- (void)getAllRulesWithCompletionHandler:(void (^)(NSArray* _Nullable rules,
                                                   NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(nil, error);
        });
      }
    }];

    [proxy getAllRulesWithCompletionHandler:^(NSArray* _Nullable rules) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(rules, nil);
        });
      }
    }];
  });
}

- (void)addUserBlockedDomain:(NSString*)domain
           completionHandler:(void (^)(BOOL success, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy addUserBlockedDomain:domain
              completionHandler:^(BOOL success) {
                if (completion) {
                  dispatch_async(dispatch_get_main_queue(), ^{
                    completion(success, nil);
                  });
                }
              }];
  });
}

- (void)removeUserBlockedDomain:(NSString*)domain
              completionHandler:(void (^)(BOOL success, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy removeUserBlockedDomain:domain
                 completionHandler:^(BOOL success) {
                   if (completion) {
                     dispatch_async(dispatch_get_main_queue(), ^{
                       completion(success, nil);
                     });
                   }
                 }];
  });
}

- (void)addUserAllowedDomain:(NSString*)domain
           completionHandler:(void (^)(BOOL success, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy addUserAllowedDomain:domain
              completionHandler:^(BOOL success) {
                if (completion) {
                  dispatch_async(dispatch_get_main_queue(), ^{
                    completion(success, nil);
                  });
                }
              }];
  });
}

- (void)removeUserAllowedDomain:(NSString*)domain
              completionHandler:(void (^)(BOOL success, NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    [proxy removeUserAllowedDomain:domain
                 completionHandler:^(BOOL success) {
                   if (completion) {
                     dispatch_async(dispatch_get_main_queue(), ^{
                       completion(success, nil);
                     });
                   }
                 }];
  });
}

- (void)getUserBlockedDomainsWithCompletionHandler:(void (^)(NSArray<NSString*>* _Nullable domains,
                                                             NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(nil, error);
        });
      }
    }];

    [proxy getUserBlockedDomainsWithCompletionHandler:^(NSArray<NSString*>* _Nullable domains) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(domains, nil);
        });
      }
    }];
  });
}

- (void)getUserAllowedDomainsWithCompletionHandler:(void (^)(NSArray<NSString*>* _Nullable domains,
                                                             NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(nil, error);
        });
      }
    }];

    [proxy getUserAllowedDomainsWithCompletionHandler:^(NSArray<NSString*>* _Nullable domains) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(domains, nil);
        });
      }
    }];
  });
}

- (void)verifyConnectionWithCompletionHandler:(void (^)(BOOL connected,
                                                        NSError* _Nullable error))completion {
  dispatch_async(self.connectionQueue, ^{
    DNSLogInfo(LogCategoryGeneral, "Verifying XPC connection");

    __block BOOL responseReceived = NO;

    // Try to get statistics as a simple connection test
    id<XPCExtensionProtocol> proxy = [self remoteObjectProxyWithErrorHandler:^(NSError* error) {
      DNSLogError(LogCategoryGeneral, "Connection verification failed: %{public}@",
                  error.localizedDescription);
      if (!responseReceived && completion) {
        responseReceived = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
          completion(NO, error);
        });
      }
    }];

    if (!proxy) {
      if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
          NSError* error = [NSError
              errorWithDomain:@"XPCClientErrorDomain"
                         code:1004
                     userInfo:@{NSLocalizedDescriptionKey : @"No XPC connection available"}];
          completion(NO, error);
        });
      }
      return;
    }

    // Add timeout
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC);
    dispatch_after(timeout, self.connectionQueue, ^{
      if (!responseReceived) {
        DNSLogError(LogCategoryGeneral, "Connection verification timed out");
        responseReceived = YES;
        if (completion) {
          dispatch_async(dispatch_get_main_queue(), ^{
            NSError* error =
                [NSError errorWithDomain:@"XPCClientErrorDomain"
                                    code:1005
                                userInfo:@{
                                  NSLocalizedDescriptionKey : @"Connection verification timed out"
                                }];
            completion(NO, error);
          });
        }
      }
    });

    // Call a simple method to test the connection
    [proxy getStatisticsWithCompletionHandler:^(NSDictionary* _Nullable stats) {
      if (!responseReceived) {
        responseReceived = YES;
        DNSLogInfo(LogCategoryGeneral, "XPC connection verified successfully");
        if (completion) {
          dispatch_async(dispatch_get_main_queue(), ^{
            completion(YES, nil);
          });
        }
      }
    }];
  });
}

- (void)dealloc {
  [self.connection invalidate];
}

@end
