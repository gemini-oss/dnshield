//
//  DNSPredicateEvaluator.h
//  DNShield Network Extension
//
//  Evaluates predicates for conditional manifest items
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class DNSEvaluationContext;

@interface DNSPredicateEvaluator : NSObject

// Evaluate a predicate string with the given context
- (BOOL)evaluatePredicate:(NSString*)predicateString withContext:(DNSEvaluationContext*)context;

// Validate predicate syntax without evaluating
- (BOOL)validatePredicate:(NSString*)predicateString error:(NSError**)error;

// Get list of variables used in predicate
- (NSArray<NSString*>*)variablesInPredicate:(NSString*)predicateString;

// Check if predicate uses time-based conditions
- (BOOL)predicateUsesTimeConditions:(NSString*)predicateString;

// Check if predicate uses network conditions
- (BOOL)predicateUsesNetworkConditions:(NSString*)predicateString;

@end

#pragma mark - Predicate Functions

// Custom predicate functions that can be used in predicates
@interface DNSPredicateFunctions : NSObject

// Time-based functions
+ (BOOL)timeIsBetween:(NSString*)time start:(NSString*)startTime end:(NSString*)endTime;
+ (BOOL)isBusinessHours;  // Default 9-5 Mon-Fri
+ (BOOL)isWeekday;
+ (BOOL)isWeekend;

// Network functions
+ (BOOL)isOnNetwork:(NSString*)ssid;
+ (BOOL)isOnCorporateNetwork;
+ (BOOL)isUsingVPN;

// Version comparison
+ (NSComparisonResult)compareVersion:(NSString*)version1 with:(NSString*)version2;

@end

NS_ASSUME_NONNULL_END
