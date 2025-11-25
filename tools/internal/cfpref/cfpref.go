//go:build darwin
// +build darwin

package cfpref

/*
many thanks

	https://gist.githubusercontent.com/clburlison/62394d6b0950040ac95586642413f684/raw/fccbf14550cac1effd8868ff4651cbb94e4064a5/cfpref.go
*/

import (
	"unsafe"
)

/*
#cgo darwin CFLAGS: -DDARWIN -x objective-c
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
*/
import "C"

const (
	Unknown = "unknown"
)

// CFPreferencesCopyAppValue - Return a value from a preference.
func CFPreferencesCopyAppValue(key, domain string) interface{} {
	pref, _ := cFPreferencesCopyAppValue(key, domain)
	return pref
}

// CFPreferencesCopyAppValueAndType - Return a value from a preference and the type.
func CFPreferencesCopyAppValueAndType(key, domain string) (interface{}, string) {
	return cFPreferencesCopyAppValue(key, domain)
}

func cFPreferencesCopyAppValue(key string, domain string) (interface{}, string) {
	k := stringToCFString(key)
	defer release(C.CFTypeRef(k))
	d := stringToCFString(domain)
	defer release(C.CFTypeRef(d))

	// Get the preference value once
	ret := C.CFPreferencesCopyAppValue(k, d)
	if ret == 0 {
		return nil, Unknown
	}
	defer release(ret)

	typeID := C.CFGetTypeID(ret)

	if typeID == C.CFStringGetTypeID() {
		return cfstringToString(C.CFStringRef(ret)), "string"
	}
	if typeID == C.CFBooleanGetTypeID() {
		return cfbooleanToBoolean(C.CFBooleanRef(ret)), "boolean"
	}
	if typeID == C.CFDataGetTypeID() {
		return cfdataToData(C.CFDataRef(ret)), "data"
	}
	if typeID == C.CFNumberGetTypeID() {
		return cfInttoInt(C.CFNumberRef(ret)), "number"
	}
	return nil, Unknown
}

func release(ref C.CFTypeRef) {
	if ref != 0 {
		C.CFRelease(ref)
	}
}

// Convert a Go string to a CFString
// Make sure to release the CFString when finished.
func stringToCFString(s string) C.CFStringRef {
	return C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(s), C.kCFStringEncodingUTF8)
}

// Convert a CFString to a Go string.
func cfstringToString(s C.CFStringRef) string {
	// Try the direct method first
	if ptr := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8); ptr != nil {
		return C.GoString(ptr)
	}

	// Fallback to copying the string
	length := C.CFStringGetLength(s)
	if length == 0 {
		return ""
	}

	// Allocate buffer
	bufferSize := length*4 + 1 // UTF-8 max 4 bytes per char + null terminator
	buffer := (*C.char)(C.malloc(C.size_t(bufferSize)))
	defer C.free(unsafe.Pointer(buffer))

	if C.CFStringGetCString(s, buffer, bufferSize, C.kCFStringEncodingUTF8) != 0 {
		return C.GoString(buffer)
	}

	return ""
}

// Convert a CFBoolean to a Go bool.
func cfbooleanToBoolean(s C.CFBooleanRef) bool {
	return s == C.kCFBooleanTrue
}

// Convert a CFData to a Go byte.
func cfdataToData(s C.CFDataRef) []uint8 {
	d := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(s)), C.int(C.CFDataGetLength(s)))
	return d
}

func cfInttoInt(ref C.CFNumberRef) int {
	var n int
	numberType := C.CFNumberGetType(ref)
	C.CFNumberGetValue(ref, numberType, unsafe.Pointer(&n))
	return n
}
