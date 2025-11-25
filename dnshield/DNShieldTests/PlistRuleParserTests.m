//
//  PlistRuleParserTests.m
//  DNShield Network Extension Tests
//
//  Tests for PlistRuleParser functionality
//

#import <XCTest/XCTest.h>
#import "PlistRuleParser.h"
#import "RuleSet.h"
#import "Testing/DNSTestCase.h"

@interface PlistRuleParserTests : DNSTestCase
@property(nonatomic, strong) PlistRuleParser* parser;
@end

@implementation PlistRuleParserTests

- (void)setUp {
  [super setUp];
  self.parser = [[PlistRuleParser alloc] init];
}

- (void)tearDown {
  self.parser = nil;
  [super tearDown];
}

#pragma mark - Basic Functionality Tests

- (void)testParserIdentifier {
  XCTAssertEqualObjects(self.parser.formatIdentifier, @"plist",
                        @"Parser should identify as 'plist' format");
}

- (void)testSupportedExtensions {
  NSArray* extensions = self.parser.supportedExtensions;
  XCTAssertTrue([extensions containsObject:@"plist"], @"Parser should support .plist extension");
}

- (void)testSupportedMIMETypes {
  NSArray* mimeTypes = self.parser.supportedMIMETypes;
  XCTAssertTrue([mimeTypes containsObject:@"application/x-plist"] ||
                    [mimeTypes containsObject:@"application/plist"],
                @"Parser should support plist MIME types");
}

- (void)testCapabilities {
  RuleParserCapabilities capabilities = self.parser.capabilities;
  XCTAssertTrue((capabilities & RuleParserCapabilityMetadata) != 0,
                @"Parser should support metadata");
  XCTAssertTrue((capabilities & RuleParserCapabilityValidation) != 0,
                @"Parser should support validation");
  XCTAssertTrue((capabilities & RuleParserCapabilityWildcards) != 0,
                @"Parser should support wildcards");
}

#pragma mark - Parsing Tests

- (void)testParseValidPlistWithBlockedDomains {
  // Create a test plist
  NSDictionary* plistDict = @{
    @"version" : @"1.0",
    @"name" : @"Test Rules",
    @"blocked" : @[ @"ad.example.com", @"spam.test.com", @"*.tracking.com" ]
  };

  NSError* serializationError;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:plistDict
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serializationError];
  XCTAssertNil(serializationError, @"Should be able to create test plist data");
  XCTAssertNotNil(plistData, @"Plist data should not be nil");

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:plistData error:&parseError];

  XCTAssertNil(parseError, @"Parsing should succeed without error");
  XCTAssertNotNil(ruleSet, @"RuleSet should not be nil");
  XCTAssertEqual(ruleSet.rules.count, 3, @"Should parse 3 rules");

  // Check metadata
  XCTAssertEqualObjects(ruleSet.metadata.version, @"1.0", @"Version should be preserved");
  XCTAssertEqualObjects(ruleSet.metadata.name, @"Test Rules", @"Name should be preserved");

  // Check rules
  NSArray<RuleEntry*>* rules = ruleSet.rules;
  for (RuleEntry* rule in rules) {
    XCTAssertEqual(rule.action, RuleActionBlock, @"All rules should be block actions");
  }
}

- (void)testParseValidPlistWithWhitelistDomains {
  NSDictionary* plistDict =
      @{@"version" : @"1.0", @"whitelist" : @[ @"safe.example.com", @"trusted.test.com" ]};

  NSError* serializationError;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:plistDict
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serializationError];
  XCTAssertNotNil(plistData, @"Plist data should not be nil");

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:plistData error:&parseError];

  XCTAssertNil(parseError, @"Parsing should succeed");
  XCTAssertNotNil(ruleSet, @"RuleSet should not be nil");
  XCTAssertEqual(ruleSet.rules.count, 2, @"Should parse 2 rules");

  // Check rules
  NSArray<RuleEntry*>* rules = ruleSet.rules;
  for (RuleEntry* rule in rules) {
    XCTAssertEqual(rule.action, RuleActionAllow, @"All rules should be allow actions");
  }
}

- (void)testParseValidPlistWithAdvancedRules {
  NSDictionary* plistDict = @{
    @"version" : @"1.0",
    @"name" : @"Advanced Test Rules",
    @"author" : @"Test Author",
    @"blocked" : @[
      @"simple.com",
      @{@"domain" : @"advanced.com", @"priority" : @100, @"comment" : @"High priority block"}
    ],
    @"whitelist" : @[ @{@"domain" : @"trusted.com", @"priority" : @50} ],
    @"metadata" : @{@"custom_field" : @"custom_value"}
  };

  NSError* serializationError;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:plistDict
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serializationError];
  XCTAssertNotNil(plistData, @"Plist data should not be nil");

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:plistData error:&parseError];

  XCTAssertNil(parseError, @"Parsing should succeed");
  XCTAssertNotNil(ruleSet, @"RuleSet should not be nil");
  XCTAssertEqual(ruleSet.rules.count, 3, @"Should parse 3 rules");

  // Check metadata
  XCTAssertEqualObjects(ruleSet.metadata.name, @"Advanced Test Rules");
  XCTAssertEqualObjects(ruleSet.metadata.author, @"Test Author");
  XCTAssertNotNil(ruleSet.metadata.customFields[@"custom_field"]);

  // Find the advanced rule and check its properties
  RuleEntry* advancedRule = nil;
  for (RuleEntry* rule in ruleSet.rules) {
    if ([rule.domain isEqualToString:@"advanced.com"]) {
      advancedRule = rule;
      break;
    }
  }

  XCTAssertNotNil(advancedRule, @"Should find advanced rule");
  XCTAssertEqual(advancedRule.priority, 100, @"Priority should be preserved");
  XCTAssertEqualObjects(advancedRule.comment, @"High priority block",
                        @"Comment should be preserved");
}

- (void)testParseBinaryPlist {
  // Create a test plist and serialize as binary
  NSDictionary* plistDict = @{@"blocked" : @[ @"binary.test.com" ]};

  NSError* serializationError;
  NSData* binaryPlistData =
      [NSPropertyListSerialization dataWithPropertyList:plistDict
                                                 format:NSPropertyListBinaryFormat_v1_0
                                                options:0
                                                  error:&serializationError];
  XCTAssertNotNil(binaryPlistData, @"Binary plist data should not be nil");

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:binaryPlistData error:&parseError];

  XCTAssertNil(parseError, @"Should parse binary plist successfully");
  XCTAssertNotNil(ruleSet, @"RuleSet should not be nil");
  XCTAssertEqual(ruleSet.rules.count, 1, @"Should parse 1 rule");
  XCTAssertEqualObjects(ruleSet.rules.firstObject.domain, @"binary.test.com");
}

#pragma mark - Error Handling Tests

- (void)testParseEmptyData {
  NSData* emptyData = [NSData data];
  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:emptyData error:&parseError];

  XCTAssertNotNil(parseError, @"Should return error for empty data");
  XCTAssertNil(ruleSet, @"RuleSet should be nil for empty data");
}

- (void)testParseInvalidPlistData {
  NSString* invalidData = @"This is not a plist";
  NSData* data = [invalidData dataUsingEncoding:NSUTF8StringEncoding];

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:data error:&parseError];

  XCTAssertNotNil(parseError, @"Should return error for invalid plist data");
  XCTAssertNil(ruleSet, @"RuleSet should be nil for invalid data");
}

- (void)testParseNonDictionaryPlist {
  // Create a plist with array at root instead of dictionary
  NSArray* arrayPlist = @[ @"not", @"a", @"dictionary" ];

  NSError* serializationError;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:arrayPlist
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serializationError];
  XCTAssertNotNil(plistData, @"Should create array plist");

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:plistData error:&parseError];

  XCTAssertNotNil(parseError, @"Should return error for non-dictionary plist");
  XCTAssertNil(ruleSet, @"RuleSet should be nil for non-dictionary plist");
}

- (void)testParseEmptyPlistDictionary {
  NSDictionary* emptyDict = @{};

  NSError* serializationError;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:emptyDict
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serializationError];
  XCTAssertNotNil(plistData, @"Should create empty dict plist");

  NSError* parseError;
  RuleSet* ruleSet = [self.parser parseData:plistData error:&parseError];

  XCTAssertNotNil(parseError, @"Should return error for empty dictionary (no rules)");
  XCTAssertNil(ruleSet, @"RuleSet should be nil for empty dictionary");
}

#pragma mark - Data Format Detection Tests

- (void)testCanParseValidPlistData {
  NSDictionary* plistDict = @{@"blocked" : @[ @"test.com" ]};

  NSError* serializationError;
  NSData* plistData = [NSPropertyListSerialization dataWithPropertyList:plistDict
                                                                 format:NSPropertyListXMLFormat_v1_0
                                                                options:0
                                                                  error:&serializationError];
  XCTAssertNotNil(plistData, @"Should create plist data");

  BOOL canParse = [self.parser canParseData:plistData];
  XCTAssertTrue(canParse, @"Should detect that it can parse valid plist data");
}

- (void)testCannotParseInvalidData {
  NSString* invalidData = @"Not a plist at all";
  NSData* data = [invalidData dataUsingEncoding:NSUTF8StringEncoding];

  BOOL canParse = [self.parser canParseData:data];
  XCTAssertFalse(canParse, @"Should detect that it cannot parse invalid data");
}

- (void)testCannotParseEmptyData {
  NSData* emptyData = [NSData data];
  BOOL canParse = [self.parser canParseData:emptyData];
  XCTAssertFalse(canParse, @"Should detect that it cannot parse empty data");
}

@end
