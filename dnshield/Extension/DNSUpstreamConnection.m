//
//  DNSUpstreamConnection.m
//  DNShield Network Extension
//
//  Manages connections to upstream DNS servers
//

#import "DNSUpstreamConnection.h"
#import <Common/LoggingManager.h>
#import "DNSInterfaceManager.h"

@interface DNSUpstreamConnection ()
@property(nonatomic, strong) nw_connection_t connection;
@property(nonatomic, strong) dispatch_queue_t connectionQueue;
@property(nonatomic, readwrite) NSString* serverAddress;
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic, strong) NSTimer* connectionTimeoutTimer;
@property(nonatomic, assign) NSUInteger connectionAttempts;
@property(nonatomic, readwrite, nullable) DNSInterfaceBinding* interfaceBinding;
@end

@implementation DNSUpstreamConnection

- (instancetype)initWithServer:(NSString*)server {
  return [self initWithServer:server interfaceBinding:nil];
}

- (instancetype)initWithServer:(NSString*)server
              interfaceBinding:(nullable DNSInterfaceBinding*)binding {
  self = [super init];
  if (self) {
    _serverAddress = server;
    _interfaceBinding = binding;
    _connectionQueue = dispatch_queue_create("com.dnshield.upstream", DISPATCH_QUEUE_SERIAL);
    _isConnected = NO;

    if (binding) {
      DNSLogInfo(LogCategoryNetwork,
                 "Creating upstream connection to %{public}@ with interface binding: %{public}@",
                 server, binding.interfaceName);
    } else {
      DNSLogInfo(LogCategoryNetwork,
                 "Creating upstream connection to %{public}@ without interface binding", server);
    }

    [self setupConnection];
  }
  return self;
}

- (void)setupConnection {
  // Clear any existing timeout timer
  if (self.connectionTimeoutTimer) {
    [self.connectionTimeoutTimer invalidate];
    self.connectionTimeoutTimer = nil;
  }

  // Create endpoint
  nw_endpoint_t endpoint = nw_endpoint_create_host(self.serverAddress.UTF8String, "53");

  // Create UDP parameters with timeout
  nw_parameters_t parameters = nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                               NW_PARAMETERS_DEFAULT_CONFIGURATION);

  // Set connection timeout to 3 seconds
  nw_parameters_set_expired_dns_behavior(parameters, nw_parameters_expired_dns_behavior_allow);

  // Apply interface binding if available
  if (self.interfaceBinding && self.interfaceBinding.interfaceName) {
    // Find the interface by name using path enumeration
    nw_interface_t targetInterface = [self findInterfaceByName:self.interfaceBinding.interfaceName];
    if (targetInterface) {
      nw_parameters_require_interface(parameters, targetInterface);
      DNSLogInfo(LogCategoryNetwork, "Binding connection to interface %{public}@ (index: %u)",
                 self.interfaceBinding.interfaceName, self.interfaceBinding.interfaceIndex);
    } else {
      DNSLogError(LogCategoryNetwork, "Failed to find interface %{public}@",
                  self.interfaceBinding.interfaceName);
    }
  }

  // Create connection
  self.connection = nw_connection_create(endpoint, parameters);

  // Set up connection timeout
  __weak typeof(self) weakSelf = self;
  self.connectionTimeoutTimer =
      [NSTimer scheduledTimerWithTimeInterval:3.0
                                       target:self
                                     selector:@selector(connectionTimedOut)
                                     userInfo:nil
                                      repeats:NO];

  // Set up state handler
  nw_connection_set_state_changed_handler(self.connection, ^(nw_connection_state_t state,
                                                             nw_error_t error) {
    __strong typeof(weakSelf) strongSelf = weakSelf;
    if (!strongSelf)
      return;

    switch (state) {
      case nw_connection_state_ready:
        DNSLogInfo(LogCategoryNetwork, "Upstream connection to %{public}@ ready",
                   strongSelf.serverAddress);
        strongSelf.isConnected = YES;
        strongSelf.connectionAttempts = 0;
        [strongSelf.connectionTimeoutTimer invalidate];
        strongSelf.connectionTimeoutTimer = nil;
        [strongSelf startReceiving];
        break;

      case nw_connection_state_failed:
        DNSLogError(LogCategoryNetwork, "Upstream connection to %{public}@ failed (attempt %lu)",
                    strongSelf.serverAddress, (unsigned long)strongSelf.connectionAttempts);
        strongSelf.isConnected = NO;
        [strongSelf.connectionTimeoutTimer invalidate];
        strongSelf.connectionTimeoutTimer = nil;

        // Retry with backoff
        if (strongSelf.connectionAttempts < 3) {
          strongSelf.connectionAttempts++;
          NSTimeInterval delay = pow(2, strongSelf.connectionAttempts - 1);  // 1s, 2s, 4s
          dispatch_after(
              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
              strongSelf.connectionQueue, ^{
                DNSLogInfo(LogCategoryNetwork, "Retrying connection to %{public}@ (attempt %lu)",
                           strongSelf.serverAddress, (unsigned long)strongSelf.connectionAttempts);
                [strongSelf setupConnection];
              });
        } else if (error && strongSelf.delegate) {
          NSError* nsError = [NSError
              errorWithDomain:@"DNSUpstreamConnection"
                         code:-1
                     userInfo:@{NSLocalizedDescriptionKey : @"Connection failed after retries"}];
          [strongSelf.delegate upstreamConnection:strongSelf didFailWithError:nsError];
        }
        break;

      case nw_connection_state_cancelled:
        DNSLogInfo(LogCategoryNetwork, "Upstream connection to %{public}@ cancelled",
                   strongSelf.serverAddress);
        strongSelf.isConnected = NO;
        [strongSelf.connectionTimeoutTimer invalidate];
        strongSelf.connectionTimeoutTimer = nil;
        break;

      default: break;
    }
  });

  // Set queue and start
  nw_connection_set_queue(self.connection, self.connectionQueue);
  nw_connection_start(self.connection);
}

- (void)startReceiving {
  nw_connection_receive(
      self.connection, 1, 65535,
      ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t error) {
        if (content) {
          // Convert dispatch_data to NSData
          NSData* data = [self dataFromDispatchData:content];
          if (data && self.delegate) {
            [self.delegate upstreamConnection:self didReceiveResponse:data];
          }
        }

        if (error) {
          DNSLogError(LogCategoryNetwork, "Error receiving from upstream: %{public}@", error);
          if (self.delegate) {
            NSError* nsError =
                [NSError errorWithDomain:@"DNSUpstreamConnection"
                                    code:-2
                                userInfo:@{NSLocalizedDescriptionKey : @"Receive error"}];
            [self.delegate upstreamConnection:self didFailWithError:nsError];
          }
        }

        // Continue receiving
        if (!error && self.isConnected) {
          [self startReceiving];
        }
      });
}

- (void)sendQuery:(NSData*)queryData {
  if (!self.isConnected || !self.connection) {
    DNSLogError(LogCategoryNetwork, "Cannot send query - not connected to %{public}@",
                self.serverAddress);
    return;
  }

  dispatch_data_t dispatchData = dispatch_data_create(
      queryData.bytes, queryData.length, self.connectionQueue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);

  nw_connection_send(self.connection, dispatchData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                     ^(nw_error_t error) {
                       if (error) {
                         DNSLogError(LogCategoryNetwork,
                                     "Failed to send query to %{public}@: %{public}@",
                                     self.serverAddress, error);
                       }
                     });
}

- (void)close {
  if (self.connectionTimeoutTimer) {
    [self.connectionTimeoutTimer invalidate];
    self.connectionTimeoutTimer = nil;
  }

  if (self.connection) {
    nw_connection_cancel(self.connection);
    self.connection = nil;
    self.isConnected = NO;
  }
}

- (NSData*)dataFromDispatchData:(dispatch_data_t)dispatchData {
  __block NSMutableData* data = [[NSMutableData alloc] init];

  dispatch_data_apply(
      dispatchData, ^bool(dispatch_data_t region, size_t offset, const void* buffer, size_t size) {
        [data appendBytes:buffer length:size];
        return true;
      });

  return data;
}

- (void)connectionTimedOut {
  DNSLogError(LogCategoryNetwork, "Connection to %{public}@ timed out", self.serverAddress);

  // Cancel the connection
  if (self.connection) {
    nw_connection_cancel(self.connection);
  }

  // Notify delegate
  if (self.delegate) {
    NSError* timeoutError =
        [NSError errorWithDomain:@"DNSUpstreamConnection"
                            code:-3
                        userInfo:@{NSLocalizedDescriptionKey : @"Connection timeout"}];
    [self.delegate upstreamConnection:self didFailWithError:timeoutError];
  }
}

- (nw_interface_t)findInterfaceByName:(NSString*)interfaceName {
  // Create a path monitor to enumerate available interfaces
  nw_path_monitor_t monitor = nw_path_monitor_create();
  __block nw_interface_t foundInterface = nil;

  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

  nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
    nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
      const char* name = nw_interface_get_name(interface);
      if (name && strcmp(name, [interfaceName UTF8String]) == 0) {
        foundInterface = interface;
        return false;  // Stop enumeration
      }
      return true;  // Continue enumeration
    });
    dispatch_semaphore_signal(semaphore);
  });

  dispatch_queue_t queue =
      dispatch_queue_create("com.dnshield.interface-finder", DISPATCH_QUEUE_SERIAL);
  nw_path_monitor_set_queue(monitor, queue);
  nw_path_monitor_start(monitor);

  // Wait for the path update with timeout
  dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC);
  dispatch_semaphore_wait(semaphore, timeout);

  nw_path_monitor_cancel(monitor);

  return foundInterface;
}

- (void)dealloc {
  [self close];
}

@end
