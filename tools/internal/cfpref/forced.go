//go:build darwin
// +build darwin

package cfpref

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation
#import <CoreFoundation/CoreFoundation.h>

bool isPreferenceForced(CFStringRef key, CFStringRef applicationID) {
    return CFPreferencesAppValueIsForced(key, applicationID);
}
*/
import "C"

// IsValueForced reports whether the given key is managed by configuration profiles.
func IsValueForced(k, d string) bool {
	key := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(k), C.kCFStringEncodingUTF8)
	defer release(C.CFTypeRef(key))
	domain := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(d), C.kCFStringEncodingUTF8)
	defer release(C.CFTypeRef(domain))
	isForced := C.isPreferenceForced(key, domain)

	return bool(isForced)
}
