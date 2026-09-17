package x25519

import (
	"P2Chat/cmd/client/internals/argon"
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
func CreateKey() (privateKeyEnclaved *memguard.Enclave, publicKey *ecdh.PublicKey, err error) {

	// generate the key
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the creation of the X25519 private key", err)

	}
	defer memguard.WipeBytes(privateKey.Bytes())

	publicKey = privateKey.PublicKey()
	privateKeyEnclaved = memguard.NewEnclave(privateKey.Bytes())

	return privateKeyEnclaved, publicKey, nil

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
func DerivateSecret(privateKey *ecdh.PrivateKey, RemotePublicKey *ecdh.PublicKey) (shared_secret *memguard.Enclave, err error) {

	secret, err := privateKey.ECDH(RemotePublicKey)
	if err != nil {
		return nil, apperr.Wrap("error during the derivation of the shared secret with X25519 key", err)
	}

	shared_secret = memguard.NewEnclave(secret)
	memguard.WipeBytes(secret)

	return shared_secret, nil

}

// EncryptPrivateKey encrypts the key based on useHSM bool and returns the filled struct.
// If useHSM is true, uses EncryptHSM (auto-detects SE on darwin, TPM on linux/windows).
// If useHSM is false, derives an AES key via Argon2id from the password and encrypts with AES-256-GCM.
// level must be between 1 and 3.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *memguard.Enclave, level int, useHSM bool) (*struct_x25519.PrivateKeyX25519, error) {
	ciphertext, nonce, salt, method, err := HSM.Encrypt(password, privateKey, level, useHSM)
	if err != nil {
		return nil, apperr.Wrap("protect X25519 private key", err)
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

	if scheme.GetArgonParams() == nil {
		return nil, apperr.New("argon parameters are nil")
	}

	privateKey, err := HSM.Decrypt(password, scheme.GetKey(), scheme.GetNonce(), scheme.GetArgonParams().GetSalt(), int(scheme.GetArgonParams().GetLevel()), scheme.GetHsmMethod())
	if err != nil {
		return nil, apperr.Wrap("decrypt X25519 private key", err)
	}
	return privateKey, nil

}
