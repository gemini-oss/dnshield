//
//  ProxyProvider+Statistics.h
//  DNShield Network Extension
//
//  Category interface for statistics reporting utilities
//

#import "Provider.h"
#import "ProxyProvider+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProxyProvider (Statistics)

- (void)reportStatistics;

@end

NS_ASSUME_NONNULL_END
