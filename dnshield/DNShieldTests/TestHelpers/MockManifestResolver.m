//
//  MockManifestResolver.m
//  DNShield Tests
//
//  Mock manifest resolver implementation
//

#import "MockManifestResolver.h"

#import <Common/Defaults.h>
#import "DNSManifest.h"  // This contains DNSResolvedManifest definition
#import "LoggingManager.h"

@implementation MockManifestResolver

- (instancetype)init {
  self = [super init];
  if (self) {
    _mockManifests = [NSMutableDictionary dictionary];
    _mockErrors = [NSMutableDictionary dictionary];
    _resolveCallHistory = [NSMutableArray array];
    _shouldSimulateNetworkDelay = NO;
    _networkDelay = 0.1;
  }
  return self;
}

#pragma mark - Override DNSManifestResolver methods

- (DNSResolvedManifest*)resolveManifest:(NSString*)identifier error:(NSError**)error {
  // Record the call
  [self.resolveCallHistory addObject:identifier];

  // Simulate network delay if configured
  if (self.shouldSimulateNetworkDelay) {
    [NSThread sleepForTimeInterval:self.networkDelay];
  }

  // Check for configured error
  NSError* mockError = self.mockErrors[identifier];
  if (mockError) {
    if (error) {
      *error = mockError;
    }
    return nil;
  }

  // Return configured manifest
  return self.mockManifests[identifier];
}

- (DNSResolvedManifest*)resolveManifestWithFallback:(NSString*)initialIdentifier
                                              error:(NSError**)error {
  // Try primary identifier first
  NSError* primaryError = nil;
  DNSResolvedManifest* result = [self resolveManifest:initialIdentifier error:&primaryError];

  if (result) {
    return result;
  }

  // Simulate fallback logic
  NSArray<NSString*>* fallbackIdentifiers;
  NSString* serialNumber = [MockManifestResolver getMachineSerialNumber];

  if (serialNumber && ![initialIdentifier isEqualToString:serialNumber]) {
    fallbackIdentifiers = @[ initialIdentifier, serialNumber, @"default" ];
  } else {
    fallbackIdentifiers = @[ initialIdentifier, @"default" ];
  }

  NSError* lastError = primaryError;

  for (NSString* identifier in fallbackIdentifiers) {
    if ([identifier isEqualToString:initialIdentifier]) {
      continue;  // Already tried
    }

    NSError* fallbackError = nil;
    DNSResolvedManifest* manifest = [self resolveManifest:identifier error:&fallbackError];

    if (manifest) {
      return manifest;
    }

    lastError = fallbackError;
  }

  if (error) {
    *error = lastError
                 ?: [NSError errorWithDomain:@"MockManifestResolver"
                                        code:404
                                    userInfo:@{NSLocalizedDescriptionKey : @"No manifests found"}];
  }

  return nil;
}

+ (NSString*)getMachineSerialNumber {
  // Return a test serial number
  return @"TEST-SERIAL-123";
}

+ (NSString*)determineClientIdentifierWithPreferenceManager:(PreferenceManager*)preferenceManager {
  // Check preference first
  NSString* identifier = [preferenceManager preferenceValueForKey:@"ManifestIdentifier"
                                                         inDomain:kDNShieldPreferenceDomain];
  if (identifier) {
    return identifier;
  }

  // Try serial number
  NSString* serial = [self getMachineSerialNumber];
  if (serial) {
    return serial;
  }

  // Default fallback
  return @"default";
}

#pragma mark - Control Methods

- (void)setupManifest:(DNSResolvedManifest*)manifest forIdentifier:(NSString*)identifier {
  self.mockManifests[identifier] = manifest;
}

- (void)setupError:(NSError*)error forIdentifier:(NSString*)identifier {
  self.mockErrors[identifier] = error;
}

- (void)setupFallbackChain:(NSArray<NSString*>*)identifiers withSuccessAt:(NSInteger)index {
  for (NSInteger i = 0; i < identifiers.count; i++) {
    if (i < index) {
      // Setup errors for identifiers before success index
      NSError* error =
          [NSError errorWithDomain:@"MockManifestResolver"
                              code:404
                          userInfo:@{
                            NSLocalizedDescriptionKey :
                                [NSString stringWithFormat:@"Manifest %@ not found", identifiers[i]]
                          }];
      [self setupError:error forIdentifier:identifiers[i]];
    } else if (i == index) {
      // Setup success at the specified index
      DNSResolvedManifest* manifest = [[DNSResolvedManifest alloc] init];
      [self setupManifest:manifest forIdentifier:identifiers[i]];
    }
    // Leave others as nil (not configured)
  }
}

- (void)clearHistory {
  [self.resolveCallHistory removeAllObjects];
}

#pragma mark - Verification Methods

- (BOOL)wasIdentifierRequested:(NSString*)identifier {
  return [self.resolveCallHistory containsObject:identifier];
}

- (NSInteger)requestCountForIdentifier:(NSString*)identifier {
  NSInteger count = 0;
  for (NSString* requestedId in self.resolveCallHistory) {
    if ([requestedId isEqualToString:identifier]) {
      count++;
    }
  }
  return count;
}

- (NSArray<NSString*>*)fallbackChainUsed {
  return [self.resolveCallHistory copy];
}

@end
