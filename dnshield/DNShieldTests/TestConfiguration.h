//
//  TestConfiguration.h
//  DNShield Tests
//
//  Test configuration and OCMock imports
//

#ifndef TestConfiguration_h
#define TestConfiguration_h

#import <XCTest/XCTest.h>

// OCMock framework - comment out if not using
#ifdef OCMOCK_AVAILABLE
#import <OCMock/OCMock.h>
#endif

// Test timeout constants
#define kTestTimeout 5.0
#define kNetworkTestTimeout 30.0

// Test data paths
#define kTestManifestPath @"TestData/Manifests"
#define kTestRulesPath @"TestData/Rules"

#endif /* TestConfiguration_h */
