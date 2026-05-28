//go:build darwin

package tpm

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static CFDictionaryRef buildSEKeyAttributes() {
	int bits = 256;
	CFNumberRef cfBits = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);

	const void *keys[] = {
		kSecAttrKeyType,
		kSecAttrKeySizeInBits,
		kSecAttrTokenID,
		kSecAttrIsPermanent,
	};

	const void *vals[] = {
		kSecAttrKeyTypeECSECPrimeRandom,
		cfBits,
		kSecAttrTokenIDSecureEnclave,
		kCFBooleanFalse,		// ephemeral: no Keychain storage, no entitlement needed
	};

	CFDictionaryRef dict = CFDictionaryCreate(
		kCFAllocatorDefault,
		keys,
		vals,
		4,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);

	CFRelease(cfBits);
	return dict;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func AvailableSE() error {

	attrs := C.buildSEKeyAttributes()
	defer C.CFRelease(C.CFTypeRef(attrs))

	var cfErr C.CFErrorRef
	secret := C.SecKeyCreateRandomKey(attrs, &cfErr)

	if unsafe.Pointer (secret) == nil {
		defer C.CFRelease(C.CFTypeRef(cfErr))
		return fmt.Errorf("Secure Enclave not available, code: %d", int(C.CFErrorGetCode(cfErr)))
	}

	// SE available, free the memory allocated for the dictionary 
	C.CFRelease(C.CFTypeRef(secret))
	return nil
}

