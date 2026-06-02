//go:build darwin

package macos

// CFLAGS : compiler
// LDFLAGS : linker

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

const char *label = "p2chat-secure-enclave-keys";

// Create a default dictionary for the creation of P-256 key
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

// Create a dictionary for search and return the reference to the private key inside the SE
static CFDictionaryRef createSearchAndReturnDictionary() {

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
		kSecReturnRef,							// reference
	};

	const void *queryVals[] = {
		kSecClassKey,							// cripthographic key
		kSecAttrKeyClassPrivate,				// private key P-256
		cfLabel,								// name of the private key to search
		kSecAttrTokenIDSecureEnclave,
		kCFBooleanTrue,							// have to return the reference
	};

	// Apple use dictionary for all type of operations with the SE, including search
	CFDictionaryRef query = CFDictionaryCreate(
		kCFAllocatorDefault,
		queryKeys,
		queryVals,
		5,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);

	CFRelease(cfLabel);

	return query;
}

// Create a dictionary for only search the private key inside the SE
static CFDictionaryRef createSearchDictionary(){
	CFStringRef cfLabel = CFStringCreateWithCString(
		kCFAllocatorDefault,
		label,
		kCFStringEncodingUTF8
	);

	const void *queryKeys[] = {
		kSecClass,
		kSecAttrKeyClass,
		kSecAttrLabel,
		kSecAttrTokenID,
	};

	const void *queryVals[] = {
		kSecClassKey,
		kSecAttrKeyClassPrivate,
		cfLabel,
		kSecAttrTokenIDSecureEnclave,
	};

	CFDictionaryRef query = CFDictionaryCreate(
		kCFAllocatorDefault,
		queryKeys,
		queryVals,
		4,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);

	CFRelease(cfLabel);

	return query;
}


// Create the P-256 keys and automatically store the private in the SE
static SecKeyRef createSEKeys(CFErrorRef *err) {

	// Call the function for create the dictionary
	CFDictionaryRef dictionary = createCFDictionary(label,err);

	// Generate the key - return an handler to the private key P-256 generated inside the SE
	SecKeyRef privKey = SecKeyCreateRandomKey(dictionary, err);

	CFRelease(dictionary);

	return privKey;

}

// Delete the private key stored in the SE
static OSStatus deleteSEKey() {

	CFDictionaryRef query = createSearchDictionary();

	OSStatus status = SecItemDelete(query);

	CFRelease(query);

	return status;
}


static SecKeyRef searchPrivateKey() {

	CFDictionaryRef query = createSearchAndReturnDictionary();
	CFTypeRef result = NULL;

	OSStatus status = SecItemCopyMatching(query, &result);					// this function search an item in the keychain using a dictionary
	CFRelease(query);

	if (status == errSecSuccess) {											// OSStatus have a parameter status that contain a code, zero is successfull search (errSecSuccess)
		return (SecKeyRef)result;
	}else{
		return NULL;
	}

}

*/
import "C"

import (
	datacontrol "P2Chat/cmd/client/internals/datacontrol/mldsa"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"fmt"
	"unsafe"
	"github.com/awnumar/memguard"
)

// Function that create a real secret that persist on the SE
func CreateSEKeys() (error, C.SecKeyRef) {

	var cfErr C.CFErrorRef
	var privKey C.SecKeyRef		// default value: nil

	privKey = C.createSEKeys(&cfErr)
	if unsafe.Pointer(privKey) == nil {
		return fmt.Errorf("error during the creation of secret, error : %d", int(C.CFErrorGetCode(cfErr))), privKey
	}

	return nil, privKey

}

// Function that delete all the referimetns to keys stored in the SE
func DeleteAllSEKeys() error {

	status := C.deleteSEKey()
	value := int(status)

	if status != 0 {
		err := fmt.Errorf("Error during delete P2Chat keys inside the SE, code : %d", value)
		return apperr.Wrap("", err)
	}

	return nil

}

// Function that search inside the SE if present some key with a reference to p2chat
func SearchSEKey() (bool, C.SecKeyRef) {

	key := C.searchPrivateKey()

	if unsafe.Pointer(key) == nil {
		return false, key
	} else {
		return true, key
	}

}


func CreateSecretFromSE() error {

	// Create error handler
	var errorSE C.CFErrorRef

	// Search if is present a key inside the SE already 
	result, privHandler := SearchSEKey()

	// Private key is not present in the SE
	if result == false {
		var err error
		err, privHandler = CreateSEKeys()
		if err != nil {
			return apperr.Wrap("error during the creation of SE keys",err)
		}
	}

	// Get public key associated to the private key 
	pubKey := C.SecKeyCopyPublicKey(privHandler);

	// Generate 32 random bytes - not usable from Core Foundation
	randomBytes := make([]byte,32)
	rand.Read(randomBytes)

	// Converti i 32 bytes go in CFData
	plaintextData := C.CFDataCreate(
		C.kCFAllocatorDefault,
		(*C.UInt8)(&randomBytes[0]),
		C.CFIndex(len(randomBytes)),
	)
	defer C.CFRelease(C.CFTypeRef(plaintextData))


	// Chiper the 32 random bytes inside the SE using ECIES and return the public blob
	blob := C.SecKeyCreateEncryptedData(
		pubKey,
		C.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
		plaintextData,
		&errorSE,
	)
	defer C.CFRelease(C.CFTypeRef(blob))

	// Check if blob is NOT empty
	if unsafe.Pointer(blob) == nil {
		return apperr.New("error encrypt bytes into SE with public key ")
	}

	// Convert blob from CFDataRef to []byte type in GO for store phase - blobBytes is only a reference 
	blobBytes := C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(blob)),			// CFDataGetBytePtr -> get the pointer
		C.int(C.CFDataGetLength(blob)),						// get the lenght of the area in memory
	)

	// Save Bytes in memory
	err := datacontrol.SaveBytesOnFile(blobBytes,"data/","SE_BLOB.bin")
	if err != nil {
		return apperr.Wrap("error during storage of public blob generated from the SE",err)
	}

	// Cleanup 
	memguard.WipeBytes(blobBytes)

	return nil

}