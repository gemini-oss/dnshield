//
//  LoggingUtils.h
//  DNShield
//
//

#ifndef LoggingUtils_h
#define LoggingUtils_h
#import <Foundation/Foundation.h>

static inline const char* DNUTF8(NSString* s) {
  return [s UTF8String];
}

#endif /* LoggingUtils_h */
