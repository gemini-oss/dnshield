//
//  DNSPredicateEvaluator.m
//  DNShield Network Extension
//

#import <Common/LoggingManager.h>

#import "DNSManifest.h"
#import "DNSManifestResolver.h"
#import "DNSPredicateEvaluator.h"

@implementation DNSPredicateEvaluator

- (BOOL)evaluatePredicate:(NSString*)predicateString withContext:(DNSEvaluationContext*)context {
  if (!predicateString || predicateString.length == 0) {
    return YES;  // Empty predicate is always true
  }

  @try {
    // Replace custom function calls with NSPredicate-compatible expressions
    NSString* processedPredicate = [self preprocessPredicate:predicateString];

    // Create predicate
    NSPredicate* predicate = [NSPredicate predicateWithFormat:processedPredicate];

    // Get context properties
    NSDictionary* contextDict = [context allProperties];

    // Evaluate
    BOOL result = [predicate evaluateWithObject:contextDict];

    [[LoggingManager sharedManager]
          logEvent:@"PredicateEvaluated"
          category:LogCategoryRuleParsing
             level:LogLevelDebug
        attributes:@{@"predicate" : predicateString, @"result" : @(result)}];

    return result;
  } @catch (NSException* exception) {
    NSError* predicateError = [NSError errorWithDomain:DNSManifestErrorDomain
                                                  code:DNSManifestErrorInvalidCondition
                                              userInfo:@{
                                                NSLocalizedDescriptionKey : exception.reason,
                                                @"predicate" : predicateString
                                              }];
    [[LoggingManager sharedManager] logError:predicateError
                                    category:LogCategoryRuleParsing
                                     context:@"Error evaluating predicate"];
    return NO;
  }
}

- (BOOL)validatePredicate:(NSString*)predicateString error:(NSError**)error {
  if (!predicateString || predicateString.length == 0) {
    return YES;
  }

  @try {
    NSString* processedPredicate = [self preprocessPredicate:predicateString];
    NSPredicate* predicate = [NSPredicate predicateWithFormat:processedPredicate];

    // Try to evaluate with empty context to check for syntax errors
    NSDictionary* testContext = @{};
    [predicate evaluateWithObject:testContext];

    return YES;
  } @catch (NSException* exception) {
    if (error) {
      *error =
          [NSError errorWithDomain:DNSManifestErrorDomain
                              code:DNSManifestErrorInvalidCondition
                          userInfo:@{
                            NSLocalizedDescriptionKey : @"Invalid predicate syntax",
                            NSLocalizedFailureReasonErrorKey : exception.reason ?: @"Unknown error"
                          }];
    }
    return NO;
  }
}

- (NSArray<NSString*>*)variablesInPredicate:(NSString*)predicateString {
  NSMutableSet* variables = [NSMutableSet set];

  // Simple regex to find variable references
  NSError* error = nil;
  NSRegularExpression* regex =
      [NSRegularExpression regularExpressionWithPattern:@"\\b([a-zA-Z_][a-zA-Z0-9_]*)\\b"
                                                options:0
                                                  error:&error];

  if (!error) {
    NSArray* matches = [regex matchesInString:predicateString
                                      options:0
                                        range:NSMakeRange(0, predicateString.length)];

    for (NSTextCheckingResult* match in matches) {
      NSString* variable = [predicateString substringWithRange:[match rangeAtIndex:1]];

      // Filter out operators and constants
      if (![self isOperatorOrConstant:variable]) {
        [variables addObject:variable];
      }
    }
  }

  return variables.allObjects;
}

- (BOOL)predicateUsesTimeConditions:(NSString*)predicateString {
  NSArray* timeVariables = @[ @"time_of_day", @"day_of_week", @"is_weekend", @"current_date" ];

  for (NSString* variable in timeVariables) {
    if ([predicateString containsString:variable]) {
      return YES;
    }
  }

  return NO;
}

- (BOOL)predicateUsesNetworkConditions:(NSString*)predicateString {
  NSArray* networkVariables =
      @[ @"network_location", @"network_ssid", @"vpn_connected", @"vpn_identifier" ];

  for (NSString* variable in networkVariables) {
    if ([predicateString containsString:variable]) {
      return YES;
    }
  }

  return NO;
}

#pragma mark - Private Methods

- (NSString*)preprocessPredicate:(NSString*)predicateString {
  NSString* processed = predicateString;

  // Replace custom functions with compatible expressions
  // Example: time_between(time_of_day, "09:00", "17:00") -> time_of_day >= "09:00" AND time_of_day
  // <= "17:00"

  // Handle time comparisons
  processed = [self replaceTimeFunctions:processed];

  // Handle version comparisons
  processed = [self replaceVersionFunctions:processed];

  return processed;
}

- (NSString*)replaceTimeFunctions:(NSString*)predicate {
  // This is a simplified implementation
  // In production, we'd use a proper parser

  NSString* result = predicate;

  // Replace is_business_hours() with time range check
  result =
      [result stringByReplacingOccurrencesOfString:@"is_business_hours()"
                                        withString:@"(time_of_day >= \"09:00\" AND time_of_day <= "
                                                   @"\"17:00\" AND is_weekend == NO)"];

  // Replace is_weekday()
  result = [result stringByReplacingOccurrencesOfString:@"is_weekday()"
                                             withString:@"is_weekend == NO"];

  return result;
}

- (NSString*)replaceVersionFunctions:(NSString*)predicate {
  // Handle version comparison functions
  // This would need more sophisticated parsing in production
  return predicate;
}

- (BOOL)isOperatorOrConstant:(NSString*)token {
  NSArray* operators = @[
    @"AND", @"OR", @"NOT", @"IN", @"CONTAINS", @"BEGINSWITH", @"ENDSWITH", @"LIKE", @"MATCHES",
    @"ANY", @"ALL", @"NONE", @"TRUE", @"FALSE", @"YES", @"NO"
  ];

  return [operators containsObject:token.uppercaseString];
}

@end

#pragma mark - Predicate Functions

@implementation DNSPredicateFunctions

+ (BOOL)timeIsBetween:(NSString*)time start:(NSString*)startTime end:(NSString*)endTime {
  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"HH:mm";

  NSDate* timeDate = [formatter dateFromString:time];
  NSDate* startDate = [formatter dateFromString:startTime];
  NSDate* endDate = [formatter dateFromString:endTime];

  if (!timeDate || !startDate || !endDate) {
    return NO;
  }

  // Handle times that cross midnight
  if ([endDate compare:startDate] == NSOrderedAscending) {
    // End time is before start time, so range crosses midnight
    return ([timeDate compare:startDate] != NSOrderedAscending) ||
           ([timeDate compare:endDate] != NSOrderedDescending);
  } else {
    // Normal range
    return ([timeDate compare:startDate] != NSOrderedAscending) &&
           ([timeDate compare:endDate] != NSOrderedDescending);
  }
}

+ (BOOL)isBusinessHours {
  NSDate* now = [NSDate date];
  NSCalendar* calendar = [NSCalendar currentCalendar];
  NSDateComponents* components = [calendar components:NSCalendarUnitHour | NSCalendarUnitWeekday
                                             fromDate:now];

  // Monday = 2, Friday = 6
  BOOL isWeekday = (components.weekday >= 2 && components.weekday <= 6);
  BOOL isWorkingHours = (components.hour >= 9 && components.hour < 17);

  return isWeekday && isWorkingHours;
}

+ (BOOL)isWeekday {
  NSDate* now = [NSDate date];
  NSCalendar* calendar = [NSCalendar currentCalendar];
  NSDateComponents* components = [calendar components:NSCalendarUnitWeekday fromDate:now];

  // Sunday = 1, Saturday = 7
  return (components.weekday >= 2 && components.weekday <= 6);
}

+ (BOOL)isWeekend {
  return ![self isWeekday];
}

+ (BOOL)isOnNetwork:(NSString*)ssid {
  // This would need to check actual network SSID
  // For now, just a placeholder
  return NO;
}

+ (BOOL)isOnCorporateNetwork {
  // Check if on known corporate networks
  // Placeholder implementation
  return NO;
}

+ (BOOL)isUsingVPN {
  // Check VPN status
  // Placeholder implementation
  return NO;
}

+ (NSComparisonResult)compareVersion:(NSString*)version1 with:(NSString*)version2 {
  NSArray* components1 = [version1 componentsSeparatedByString:@"."];
  NSArray* components2 = [version2 componentsSeparatedByString:@"."];

  NSInteger maxCount = MAX(components1.count, components2.count);

  for (NSInteger i = 0; i < maxCount; i++) {
    NSInteger value1 = (i < components1.count) ? [components1[i] integerValue] : 0;
    NSInteger value2 = (i < components2.count) ? [components2[i] integerValue] : 0;

    if (value1 < value2) {
      return NSOrderedAscending;
    } else if (value1 > value2) {
      return NSOrderedDescending;
    }
  }

  return NSOrderedSame;
}

@end
