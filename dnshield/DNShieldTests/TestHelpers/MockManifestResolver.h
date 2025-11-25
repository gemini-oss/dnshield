//
//  MockManifestResolver.h
//  DNShield Tests
//
//  Mock manifest resolver for testing fallback scenarios
//

#import <Foundation/Foundation.h>
#import "DNSManifestResolver.h"
#import "TestConfiguration.h"

NS_ASSUME_NONNULL_BEGIN

@interface MockManifestResolver : DNSManifestResolver

// Configuration for mock behavior
@property(nonatomic, strong) NSMutableDictionary<NSString*, DNSResolvedManifest*>* mockManifests;
@property(nonatomic, strong) NSMutableDictionary<NSString*, NSError*>* mockErrors;
@property(nonatomic, strong) NSMutableArray<NSString*>* resolveCallHistory;
@property(nonatomic, assign) BOOL shouldSimulateNetworkDelay;
@property(nonatomic, assign) NSTimeInterval networkDelay;

// Control methods
- (void)setupManifest:(DNSResolvedManifest*)manifest forIdentifier:(NSString*)identifier;
- (void)setupError:(NSError*)error forIdentifier:(NSString*)identifier;
- (void)setupFallbackChain:(NSArray<NSString*>*)identifiers withSuccessAt:(NSInteger)index;
- (void)clearHistory;

// Verification methods
- (BOOL)wasIdentifierRequested:(NSString*)identifier;
- (NSInteger)requestCountForIdentifier:(NSString*)identifier;
- (NSArray<NSString*>*)fallbackChainUsed;

@end

NS_ASSUME_NONNULL_END
