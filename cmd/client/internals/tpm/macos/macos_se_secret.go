//go:build darwin

package macos

// CFLAGS : compiler
// LDFLAGS : linker

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

const char *label = "p2chat-secure-enclave-keys";

static CFDictionaryRef createCFDictionary(const char *label,CFErrorRef *err){

	// create the ACL, rules for manage who can use and read this key
	// this key will be the Class Key type A
	// LAContext + kSecAccessControlPrivateKeyUsage will be added when sign/ECDH operations are implemented
	SecAccessControlRef acl = SecAccessControlCreateWithFlags(
		kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		0,
		err
	);
	if (!acl) return NULL;

	// cast for convert int into a CFNumberRef
	int bits = 256;
	CFNumberRef curveBits = CFNumberCreate (kCFAllocatorDefault, kCFNumberIntType, &bits);		// this contains bits for P-256 algorithm, SE only support P-256 curve

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
		curveBits,									// specify how many bits
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

	// Free the variables memory space
	CFRelease(curveBits);
  	CFRelease(cfLabel);

	return attrs;
}


static SecKeyRef createSEKeys(CFErrorRef *err) {

	// Call the function for create the dictionary
	CFDictionaryRef dictionary = createCFDictionary(label,err);

	// Generate the key - return an handler to the private key P-256 generated inside the SE
	SecKeyRef privKey = SecKeyCreateRandomKey(dictionary, err);

	// Free dictionary space
	CFRelease(dictionary);

	// I return only the private key handler because i can derivate the public key from this everytime
	return privKey;

}

// Delete the private key stored in the SE
static OSStatus deleteSEKey() {

	CFStringRef cfLabel = CFStringCreateWithCString(
		kCFAllocatorDefault,
		label,
		kCFStringEncodingUTF8
	);

	const void *queryKeys[] = {
		kSecClass,								// where search the key
		kSecAttrKeyClass,						// what type of key
		kSecAttrLabel,							// the label (p2chat...)
		kSecAttrTokenID,						// where phisiqually
	};

	const void *queryVals[] = {
		kSecClassKey,							// cripthographic key
		kSecAttrKeyClassPrivate,				// private key P-256
		cfLabel,
		kSecAttrTokenIDSecureEnclave,
	};

	// Apple use dictionary for all type of operations with the SE, including search
	CFDictionaryRef query = CFDictionaryCreate(
		kCFAllocatorDefault,
		queryKeys,
		queryVals,
		4,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);

	OSStatus status = SecItemDelete(query);

	CFRelease(query);
	CFRelease(cfLabel);

	return status;
}

*/
import "C"

import (
	"P2Chat/pkg/apperr"
	"fmt"
	"unsafe"
)

// Function that create a real secret that persist on the SE
func CreateSecret() (error,unsafe.Pointer) {

	var cfErr C.CFErrorRef

	privKey := C.createSEKeys(&cfErr)
	if unsafe.Pointer(privKey) == nil {
		return fmt.Errorf("error during the creation of secret, error : %d", int(C.CFErrorGetCode(cfErr))),nil
	}

	return nil,unsafe.Pointer(privKey)

}


func DeleteAllSEKeys() error {

	status := C.deleteSEKey()
	value := int(status)

	if status != 0 {
		err := fmt.Errorf("Error during delete P2Chat keys inside the SE, code : %d",value)
		return apperr.Wrap("",err)
	}

	return nil

}
