//go:build darwin

package SE

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


// Search the private key in the SE
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
	datacontrol "P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"fmt"
	"unsafe"
	"github.com/awnumar/memguard"
)

// Function that create a real secret that persist on the SE
func createKeys() (C.SecKeyRef, error) {

	var cfErr C.CFErrorRef
	var privKey C.SecKeyRef // default value: nil

	privKey = C.createSEKeys(&cfErr)
	if unsafe.Pointer(privKey) == nil {
		return privKey, fmt.Errorf("error during the creation of secret, error : %d", int(C.CFErrorGetCode(cfErr)))
	}

	return privKey, nil

}

// Function that delete all the referimetns to keys stored in the SE
func DeleteAllKeys() error {

	status := C.deleteSEKey()
	value := int(status)

	if status != 0 {
		err := fmt.Errorf("Error during delete P2Chat keys inside the SE, code : %d", value)
		return apperr.Wrap("", err)
	}

	return nil

}

// Function that search inside the SE if present the private key
func SearchPrivateKey() (bool, C.SecKeyRef) {

	key := C.searchPrivateKey()

	if unsafe.Pointer(key) == nil {
		return false, key
	} else {
		return true, key
	}

}

// Function chiper bytes using the public key associated with the private key inside the SE
func Encrypt(bytes []byte) ([]byte, error) {

	// Create error handler
	var errorSE C.CFErrorRef

	if ( bytes == nil || len(bytes) == 0 ) {
		return nil, apperr.New("plaintext not valid during cipher with SE")
	}

	// Search if is present a key inside the SE already
	result, privHandler := SearchPrivateKey()

	// Private key is not present in the SE
	if result == false {
		var err error
		privHandler, err = createKeys()
		if err != nil {
			return nil, apperr.Wrap("error during the creation of SE keys", err)
		}
	}

	// Get public key associated to the private key
	pubKey := C.SecKeyCopyPublicKey(privHandler)
	defer GoCFRelease(unsafe.Pointer(pubKey))

	// Converti i 32 bytes go in CFData
	plaintextData := C.CFDataCreate(
		C.kCFAllocatorDefault,
		(*C.UInt8)(&bytes[0]),
		C.CFIndex(len(bytes)),
	)
	defer C.CFRelease(C.CFTypeRef(plaintextData))

	// Chiper the 32 random bytes inside the SE using ECIES and return the public blob
	blob := C.SecKeyCreateEncryptedData(
		pubKey,
		C.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
		plaintextData,
		&errorSE,
	)

	// Check if blob is NOT empty
	if unsafe.Pointer(blob) == nil {
		return nil, apperr.New("error encrypt bytes into SE with public key ")
	}
	defer GoCFRelease(unsafe.Pointer(blob))

	// Convert blob into []byte
	data, err := BytesConvert(blob)
	if err != nil {
		return nil, apperr.Wrap("error :", err)
	}

	return data, nil

}

// Decrypt the public blob 
func Decrypt(blob []byte) (*memguard.LockedBuffer, error) {

	if blob == nil {
		return nil, apperr.New("blob is null")
	}

	// Create error handler
	var errorSE C.CFErrorRef

	// convert the blob into CFDataRef
	blob_CFData,err := newCFData(blob)
	if err != nil {
		return nil, apperr.Wrap("error :",err)
	}
	defer GoCFRelease(unsafe.Pointer(blob_CFData))

	// get private handler from SE
	result, privKey := SearchPrivateKey()
	if result != true {
		return nil, apperr.New("Private key not present in the SE")
	}
	defer GoCFRelease(unsafe.Pointer(privKey))

	// Decrypt the data using SE
	dataRef := C.SecKeyCreateDecryptedData(
		privKey,
		C.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
		blob_CFData,
		&errorSE,
	)
	if unsafe.Pointer(dataRef) == nil {
		return nil, apperr.New("error decrypt in the SE")
	}
	defer GoCFRelease(unsafe.Pointer(dataRef))

	// Convert bytes from CFDataRef to []byte to put into a memguard.Lockedbuffer space
	plaintext := C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(dataRef)), // CFDataGetBytePtr -> get the pointer
		C.int(C.CFDataGetLength(dataRef)),           // get the lenght of the area in memory
	)
	if plaintext == nil {
		return nil, apperr.New("error during decrypt of file with SE")
	}

	// protect the plaintext and delete from memory bytes
	bufferLocked := memguard.NewBufferFromBytes(plaintext)
	defer memguard.WipeBytes(plaintext)

	return bufferLocked, nil

}

// SaveBlob writes the blob to disk at the given path and wipes the in-memory copy.
func SaveBlob(blob []byte, dir string) error {

	err := datacontrol.SaveBytesOnFile(blob, dir, "SE_BLOB.bin")
	if err != nil {
		return apperr.Wrap("error during storage of public blob generated from the SE", err)
	}

	return nil
}


// Wrap the function CFDataCreate
func newCFData(bytes []byte) (C.CFDataRef, error) {

	var CFData C.CFDataRef

	if ( bytes == nil || len(bytes) == 0 ) {
		return CFData, apperr.New("bytes are not valid")
	}

	// CFDataCreate does not return an error, if there is an error, CFData == NULL
	CFData = C.CFDataCreate(
		C.kCFAllocatorDefault,
		(*C.UInt8)(&bytes[0]),
		C.CFIndex(len(bytes)),
	)
	if unsafe.Pointer(CFData) == nil {
		return CFData, apperr.New("Error during conversion from []byte to CFDataRef")
	}
	
	return CFData, nil

}


// Wrap the function CFRelease - get in input  
func GoCFRelease(data unsafe.Pointer) {
	C.CFRelease(C.CFTypeRef(data))
}

// Wrap the function GoBytes
func BytesConvert(dataRef C.CFDataRef) ([]byte, error) {

	plaintext := C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(dataRef)), // CFDataGetBytePtr -> get the pointer
		C.int(C.CFDataGetLength(dataRef)),           // get the lenght of the area in memory
	)

	if plaintext == nil {
		return nil, apperr.New("Error during conversion from CFDataRef to []byte")
	}

	return plaintext, nil
}