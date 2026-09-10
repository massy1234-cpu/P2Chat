package x25519

import (
	"P2Chat/cmd/client/internals/argon"
	"P2Chat/cmd/client/internals/encryption"
	HSM "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/cmd/client/internals/p2version"
	struct_x25519 "P2Chat/cmd/client/internals/proto_generated/x25519/proto_struct_x25519"
	"P2Chat/pkg/apperr"
	"crypto/ecdh"
	"crypto/rand"
	"time"

	"github.com/awnumar/memguard"
	proto "google.golang.org/protobuf/proto"
)


// generate the private key X25519 (Curve) and put in an enclave
func CreateKey() (privateKeyEnclaved *memguard.Enclave,publicKey *ecdh.PublicKey,err error) {

	// generate the key
	privateKey,err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the creation of the X25519 private key",err)
	
	}
	defer memguard.WipeBytes(privateKey.Bytes())

	publicKey = privateKey.PublicKey()
	privateKeyEnclaved = memguard.NewEnclave(privateKey.Bytes())

	return privateKeyEnclaved,publicKey,nil

}


// Get the public key using the private key
func ExtractPublicKey(privateKeyEnclaved *memguard.Enclave) (publicKey *ecdh.PublicKey) {

	buffer, err := privateKeyEnclaved.Open()
	if err != nil {
		return nil
	}
	defer buffer.Destroy()

	key, err := ecdh.X25519().NewPrivateKey(buffer.Bytes())
	if err != nil {
		return nil
	}

	return key.PublicKey()

}


// derivate the shared_secret with the public key of the other user in the comunication
func DerivateSecret(privateKey *ecdh.PrivateKey, RemotePublicKey *ecdh.PublicKey) (shared_secret *memguard.Enclave,err error) {

	secret,err := privateKey.ECDH(RemotePublicKey)
	if err != nil {
		return nil, apperr.Wrap("error during the derivation of the shared secret with X25519 key",err)
	}

	shared_secret = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return shared_secret,nil

}


// EncryptPrivateKey encrypts the key based on useHSM bool and returns the filled struct.
// If useHSM is true, uses EncryptHSM (auto-detects SE on darwin, TPM on linux/windows).
// If useHSM is false, derives an AES key via Argon2id from the password and encrypts with AES-256-GCM.
// level must be between 1 and 3.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *memguard.Enclave, level int, useHSM bool) (*struct_x25519.PrivateKeyX25519, error) {

	if level < 1 || level > 3 {
		return nil, apperr.New("level must be between 1 and 3")
	}

	var ciphertext, nonce []byte
	var method uint32
	var err error

	buffer, keyErr := privateKey.Open()
	if keyErr != nil {
		return nil, apperr.Wrap("error ", keyErr)
	}
	defer buffer.Destroy()

	var salt []byte

	if useHSM {
		ciphertext, nonce, err = HSM.EncryptHSM(password, buffer)
		if err != nil {
			return nil, apperr.Wrap("hsm encrypt error", err)
		}
		method = uint32(HSM.WhichOS())
	} else {
		pwdBuf, pwdErr := password.Open()
		if pwdErr != nil {
			return nil, apperr.Wrap("open password enclave", pwdErr)
		}
		defer pwdBuf.Destroy()

		salt, err = encryption.GenerateSalt(32)
		if err != nil {
			return nil, apperr.Wrap("generate salt", err)
		}

		aesKey, err := argon.HashWithArgon(level, pwdBuf, salt)
		if err != nil {
			return nil, apperr.Wrap("derive encryption key with argon2id", err)
		}
		defer aesKey.Destroy()

		ciphertext, nonce, err = encryption.EncryptAes256(aesKey, buffer.Bytes())
		if err != nil {
			return nil, apperr.Wrap("error ", err)
		}
	}

	scheme := &struct_x25519.PrivateKeyX25519{
		P2ChatVersion: p2version.MagicByte(),
		Algorithm:     "X25519",
		Timestamp:     time.Now().Unix(),
		Key:           ciphertext,
		Nonce:         nonce,
		ArgonParams:   argon.CreateArgonParams(level),
		HsmMethod:     method,
	}
	scheme.ArgonParams.Salt = salt

	if err := scheme.SetChecksum(); err != nil {
		return nil, apperr.Wrap("error setting the checksum of the private key", err)
	}

	return scheme, nil

}

// SerializePrivateKey marshals the filled PrivateKeyX25519 struct to bytes.
func SerializePrivateKey(scheme *struct_x25519.PrivateKeyX25519) ([]byte, error) {

	serializedKey, err := proto.Marshal(scheme)
	if err != nil {
		return nil, apperr.Wrap("error during serialization ", err)
	}

	return serializedKey, nil

}

// DecryptPrivateKey decrypts a serialized PrivateKeyX25519 key and returns the raw key in a memguard Enclave.
func DecryptPrivateKey(password *memguard.Enclave, serialized []byte) (*memguard.Enclave, error) {

	var scheme struct_x25519.PrivateKeyX25519
	if err := proto.Unmarshal(serialized, &scheme); err != nil {
		return nil, apperr.Wrap("unmarshal private x25519 key", err)
	}

	var plaintext *memguard.LockedBuffer

	switch scheme.GetHsmMethod() {
	case 0:
		pwdBuf, err := password.Open()
		if err != nil {
			return nil, apperr.Wrap("open password enclave", err)
		}
		defer pwdBuf.Destroy()

		aesKey, err := argon.HashWithArgon(int(scheme.GetArgonParams().GetLevel()), pwdBuf, scheme.GetArgonParams().GetSalt())
		if err != nil {
			return nil, apperr.Wrap("derive argon key", err)
		}
		defer aesKey.Destroy()

		plaintext, err = encryption.DecryptAes256(aesKey, scheme.GetNonce(), scheme.GetKey())
		if err != nil {
			return nil, apperr.Wrap("decrypt x25519 private key", err)
		}
	case 1, 2:
		var err error
		plaintext, err = HSM.DecryptHSM(password, scheme.GetKey(), scheme.GetNonce(), int(scheme.GetHsmMethod()))
		if err != nil {
			return nil, apperr.Wrap("decrypt x25519 private key with HSM", err)
		}
	default:
		return nil, apperr.New("unknown encrypt method for x25519 private key")
	}

	enclave := memguard.NewEnclave(plaintext.Bytes())
	plaintext.Destroy()
	return enclave, nil

}