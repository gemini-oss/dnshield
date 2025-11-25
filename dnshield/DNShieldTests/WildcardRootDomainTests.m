//
//  WildcardRootDomainTests.m
//  DNShield Tests
//
//  Tests for wildcard domain matching with root domain blocking
//

#import <Extension/Rule/Precedence.h>
#import <Extension/Rule/RuleDatabase.h>
#import <XCTest/XCTest.h>
#import "DNSWildcardConfig.h"
#import "RuleSet.h"
#import "Testing/DNSTestCase.h"

@interface WildcardRootDomainTests : DNSTestCase
@property(nonatomic, strong) RuleDatabase* database;
@property(nonatomic, strong) DNSWildcardConfig* config;
@end

@implementation WildcardRootDomainTests

- (void)setUp {
  [super setUp];

  // Initialize test database
  self.database = [[RuleDatabase alloc] init];
  [self.database openDatabase];

  // Get wildcard config
  self.config = [DNSWildcardConfig sharedConfig];
}

- (void)tearDown {
  // Clean up test database
  [self.database removeAllRulesFromSource:DNSRuleSourceUser error:nil];
  [self.database closeDatabase];

  [super tearDown];
}

#pragma mark - Wildcard Matching Tests

- (void)testWildcardSubdomainsOnlyMode {
  // Configure for subdomains-only mode
  [self.config setMode:DNSWildcardModeSubdomainsOnly];

  // Add wildcard rule
  DNSRule* wildcardRule = [DNSRule ruleWithDomain:@"*.example.com" action:DNSRuleActionBlock];
  wildcardRule.type = DNSRuleTypeWildcard;
  [self.database addRule:wildcardRule error:nil];

  // Test subdomain - should match
  BOOL subdomainMatch = [wildcardRule matchesDomain:@"login.example.com"];
  XCTAssertTrue(subdomainMatch, @"Wildcard should match subdomain");

  // Test root domain - should NOT match in subdomains-only mode
  BOOL rootMatch = [wildcardRule matchesDomain:@"example.com"];
  XCTAssertFalse(rootMatch, @"Wildcard should NOT match root domain in subdomains-only mode");
}

- (void)testWildcardIncludeRootMode {
  // Configure for include-root mode
  [self.config setMode:DNSWildcardModeIncludeRoot];

  // Add wildcard rule
  DNSRule* wildcardRule = [DNSRule ruleWithDomain:@"*.example.com" action:DNSRuleActionBlock];
  wildcardRule.type = DNSRuleTypeWildcard;
  [self.database addRule:wildcardRule error:nil];

  // Test subdomain - should match
  BOOL subdomainMatch = [wildcardRule matchesDomain:@"login.example.com"];
  XCTAssertTrue(subdomainMatch, @"Wildcard should match subdomain");

  // Test root domain - SHOULD match in include-root mode
  BOOL rootMatch = [wildcardRule matchesDomain:@"example.com"];
  XCTAssertTrue(rootMatch, @"Wildcard SHOULD match root domain in include-root mode");
}

- (void)testMultiLevelWildcardMatching {
  [self.config setMode:DNSWildcardModeIncludeRoot];

  DNSRule* wildcardRule = [DNSRule ruleWithDomain:@"*.foo.example.com" action:DNSRuleActionBlock];
  wildcardRule.type = DNSRuleTypeWildcard;

  // Should match
  XCTAssertTrue([wildcardRule matchesDomain:@"bar.foo.example.com"], @"Should match subdomain");
  XCTAssertTrue([wildcardRule matchesDomain:@"foo.example.com"], @"Should match root of wildcard");

  // Should NOT match
  XCTAssertFalse([wildcardRule matchesDomain:@"example.com"], @"Should not match parent domain");
  XCTAssertFalse([wildcardRule matchesDomain:@"other.example.com"],
                 @"Should not match sibling domain");
}

#pragma mark - Precedence Tests

- (void)testAllowlistPrecedence {
  [self.config setMode:DNSWildcardModeIncludeRoot];

  // Add wildcard block rule
  DNSRule* blockRule = [DNSRule ruleWithDomain:@"*.blocked.com" action:DNSRuleActionBlock];
  blockRule.type = DNSRuleTypeWildcard;
  blockRule.priority = 100;
  [self.database addRule:blockRule error:nil];

  // Add specific allow rule for subdomain
  DNSRule* allowRule = [DNSRule ruleWithDomain:@"allowed.blocked.com" action:DNSRuleActionAllow];
  allowRule.type = DNSRuleTypeExact;
  allowRule.priority = 150;
  [self.database addRule:allowRule error:nil];

  // Test conflict resolution
  NSArray<DNSRule*>* rulesForAllowed =
      [RulePrecedence allMatchingRulesForDomain:@"allowed.blocked.com" inDatabase:self.database];
  DNSRuleAction action = [RulePrecedence resolveConflictBetweenRules:rulesForAllowed
                                                           forDomain:@"allowed.blocked.com"];

  XCTAssertEqual(action, DNSRuleActionAllow, @"Specific allow rule should override wildcard block");

  // Test that other subdomains are still blocked
  NSArray<DNSRule*>* rulesForOther = [RulePrecedence allMatchingRulesForDomain:@"other.blocked.com"
                                                                    inDatabase:self.database];
  DNSRuleAction otherAction = [RulePrecedence resolveConflictBetweenRules:rulesForOther
                                                                forDomain:@"other.blocked.com"];

  XCTAssertEqual(otherAction, DNSRuleActionBlock, @"Other subdomains should still be blocked");
}

- (void)testRootDomainAllowWithWildcardBlock {
  [self.config setMode:DNSWildcardModeIncludeRoot];

  // Add wildcard block rule
  DNSRule* blockRule = [DNSRule ruleWithDomain:@"*.example.com" action:DNSRuleActionBlock];
  blockRule.type = DNSRuleTypeWildcard;
  blockRule.priority = 100;
  [self.database addRule:blockRule error:nil];

  // Add explicit allow for root domain
  DNSRule* allowRoot = [DNSRule ruleWithDomain:@"example.com" action:DNSRuleActionAllow];
  allowRoot.type = DNSRuleTypeExact;
  allowRoot.priority = 150;
  [self.database addRule:allowRoot error:nil];

  // Root should be allowed
  NSArray<DNSRule*>* rootRules = [RulePrecedence allMatchingRulesForDomain:@"example.com"
                                                                inDatabase:self.database];
  DNSRuleAction rootAction = [RulePrecedence resolveConflictBetweenRules:rootRules
                                                               forDomain:@"example.com"];
  XCTAssertEqual(rootAction, DNSRuleActionAllow, @"Root domain should be allowed");

  // Subdomains should still be blocked
  NSArray<DNSRule*>* subRules = [RulePrecedence allMatchingRulesForDomain:@"sub.example.com"
                                                               inDatabase:self.database];
  DNSRuleAction subAction = [RulePrecedence resolveConflictBetweenRules:subRules
                                                              forDomain:@"sub.example.com"];
  XCTAssertEqual(subAction, DNSRuleActionBlock, @"Subdomains should be blocked");
}

#pragma mark - RuleSet Integration Tests

- (void)testRuleSetWildcardMatching {
  [self.config setMode:DNSWildcardModeIncludeRoot];

  // Create rule set with wildcard
  RuleEntry* wildcardEntry = [RuleEntry blockRuleForDomain:@"*.malicious.com"];
  RuleSetMetadata* metadata = [RuleSetMetadata metadataWithName:@"Test Rules" version:@"1.0"];
  RuleSet* ruleSet = [[RuleSet alloc] initWithRules:@[ wildcardEntry ] metadata:metadata];

  // Test matching
  XCTAssertTrue([wildcardEntry matchesDomain:@"phishing.malicious.com"], @"Should match subdomain");
  XCTAssertTrue([wildcardEntry matchesDomain:@"malicious.com"],
                @"Should match root domain in include-root mode");

  // Test shouldBlockDomain
  XCTAssertTrue([ruleSet shouldBlockDomain:@"phishing.malicious.com"], @"Should block subdomain");
  XCTAssertTrue([ruleSet shouldBlockDomain:@"malicious.com"], @"Should block root domain");
}

#pragma mark - Security Gap Tests

- (void)testAccountGeminiSecurityGap {
  // This test verifies the specific security gap mentioned in the issue
  [self.config setMode:DNSWildcardModeIncludeRoot];

  // Add the wildcard rule that was missing root domain coverage
  DNSRule* wildcardRule = [DNSRule ruleWithDomain:@"*.account-gemini.com"
                                           action:DNSRuleActionBlock];
  wildcardRule.type = DNSRuleTypeWildcard;
  [self.database addRule:wildcardRule error:nil];

  // Verify subdomain is blocked
  BOOL subdomainBlocked = [wildcardRule matchesDomain:@"test.account-gemini.com"];
  XCTAssertTrue(subdomainBlocked, @"Subdomain should be blocked");

  // Verify root domain is NOW also blocked (security gap fixed)
  BOOL rootBlocked = [wildcardRule matchesDomain:@"account-gemini.com"];
  XCTAssertTrue(rootBlocked, @"Root domain should now be blocked (security gap fixed)");
}

- (void)testComplexScenarioWithMultipleRules {
  [self.config setMode:DNSWildcardModeIncludeRoot];

  // Global blocklist with wildcard
  DNSRule* globalBlock = [DNSRule ruleWithDomain:@"*.foo.com" action:DNSRuleActionBlock];
  globalBlock.type = DNSRuleTypeWildcard;
  globalBlock.priority = 50;
  globalBlock.source = DNSRuleSourceSystem;
  [self.database addRule:globalBlock error:nil];

  // User allowlist for specific subdomains
  DNSRule* allow1 = [DNSRule ruleWithDomain:@"allowed.foo.com" action:DNSRuleActionAllow];
  allow1.type = DNSRuleTypeExact;
  allow1.priority = 100;
  allow1.source = DNSRuleSourceUser;
  [self.database addRule:allow1 error:nil];

  DNSRule* allow2 = [DNSRule ruleWithDomain:@"bar.foo.com" action:DNSRuleActionAllow];
  allow2.type = DNSRuleTypeExact;
  allow2.priority = 100;
  allow2.source = DNSRuleSourceUser;
  [self.database addRule:allow2 error:nil];

  // Test resolution for each domain
  NSArray<NSString*>* testDomains = @[
    @"foo.com",          // Root - should be blocked
    @"allowed.foo.com",  // Explicitly allowed
    @"bar.foo.com",      // Explicitly allowed
    @"other.foo.com",    // Not explicitly allowed - should be blocked
    @"sub.bar.foo.com"   // Subdomain of allowed - should be blocked
  ];

  NSArray<NSNumber*>* expectedActions = @[
    @(DNSRuleActionBlock),  // foo.com
    @(DNSRuleActionAllow),  // allowed.foo.com
    @(DNSRuleActionAllow),  // bar.foo.com
    @(DNSRuleActionBlock),  // other.foo.com
    @(DNSRuleActionBlock)   // sub.bar.foo.com
  ];

  for (NSUInteger i = 0; i < testDomains.count; i++) {
    NSString* domain = testDomains[i];
    DNSRuleAction expectedAction = [expectedActions[i] integerValue];

    NSArray<DNSRule*>* rules = [RulePrecedence allMatchingRulesForDomain:domain
                                                              inDatabase:self.database];
    DNSRuleAction resolvedAction =
        rules.count > 0 ? [RulePrecedence resolveConflictBetweenRules:rules forDomain:domain]
                        : DNSRuleActionUnknown;

    XCTAssertEqual(resolvedAction, expectedAction, @"Domain %@ should have action %ld but got %ld",
                   domain, (long)expectedAction, (long)resolvedAction);
  }
}

@end
