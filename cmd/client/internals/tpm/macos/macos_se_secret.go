//go:build darwin

package macos


/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static SecKeyRef createSEKeys(const char *label, CFErrorRef *err) {

	// create the ACL, rules for manage who can use and read this key
	// this key will be the Class Key type A
	SecAccessControlRef acl = SecAccessControlCreateWithFlash(
		kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,									// this is the parameter for the Class Key A
		kSecAccessControlPrivateKeyUsage,												// this specify that this key can use only for criptographic operations and cannot be read from anyone
		err																				// error variable that store error messages
	)
	if (!acl) return NULL;

	// cast for convert int into a CFNumberRef
	int bits = 256;
	CFNumberRef curveBits = CFNumberCreate (kCFAllocatorDefault, kCFNumberIntType, &bits)		// this contains bits for P-256 algorithm, SE only support P-256 curve 

	// cast for convert label into a CFStringRef
	CFStringRef cfLabel = CFStringCreateWithCString(kCFAllocatorDefault, label, kCFStringEncodingUTF8);

	// creation of dictionary 
	// definition of keys parameters
	const void *keys[] = {
		kSecAttrKeyType,							// type of key
		kSecAttrKeySizeInBits,						// key size
		kSecAttrTokenID,							// where generate key
		kSecAttrIsPermanent,						// is permanent ?
		kSecAttrLabel,								// label
		kSecAttrAccessControl,						// ACL 
	};

	// parameters
	const void *vals[] = {
		kSecAttrKeyTypeECSECPrimeRandom,			// define the P-256 Curve
		cfBits,										// sepcify how many bits	
		kSecAttrTokenIDSecureEnclave,				// generate the key inside the TPM
		kCFBooleanTrue,								// permanent
		cfLabel,									// value of label
		acl,										// ACL
	};

	// insert parameters inside the dictionary 
	CFDictionaryRef attrs = CFDictionaryCreate(
		kCFAllocatorDefault,
		keys, 
		vals, 
		6,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
}
*/
import "C"


import (

)

// Function that create a real secret that persist on the SE
func CreateSecret() {

}