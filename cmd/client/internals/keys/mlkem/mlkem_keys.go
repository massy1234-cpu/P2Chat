package mlkem

import (
	HSM "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	"P2Chat/pkg/apperr"
	"crypto/mlkem"
	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
)

// every key have a different nonce, the key is shared between buckets
type PrivateKEM struct {
	PrivateKeyEncrypted []byte `msgpack:"private_key_encrypted"`
	Nonce               []byte `msgpack:"nonce"`
	Salt                []byte `msgpack:"salt"`
	ArgonLevel          int    `msgpack:"argon_level"`
	EncryptMethod       uint32 `msgpack:"encrypt_method"` // 0 = nessuno, 1 = SE, 2 = TPM
}

// generate the private key ML-KEM 768
func CreateKey() (privateKeyEnclaved *PrivateMLKEM, publicKey *PublicMLKEM, err error) {

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, apperr.Wrap("error during generation of ml-kem 768 keys", err)
	}
	defer memguard.WipeBytes(dk.Bytes())

	// put the private key in a secure area of RAM
	privateKeyEnclaved = &PrivateMLKEM{enclave: memguard.NewEnclave(dk.Bytes())}

	publicKey = &PublicMLKEM{key: dk.EncapsulationKey()}

	return privateKeyEnclaved, publicKey, nil

}

// get the public key from the private key
func ExtractPublicKey(privateKeyEnclaved *PrivateMLKEM) (publicKey *PublicMLKEM) {

	if privateKeyEnclaved == nil || privateKeyEnclaved.enclave == nil {
		return nil
	}
	buffer, err := privateKeyEnclaved.enclave.Open()
	if err != nil {
		return nil
	}
	defer buffer.Destroy()

	key, err := mlkem.NewDecapsulationKey768(buffer.Bytes())
	if err != nil {
		return nil
	}

	return &PublicMLKEM{key: key.EncapsulationKey()}

}

// use the public key to create the secret and chipertext
func EncapsulateSecret(publicKey *PublicMLKEM) (secretLocked *memguard.LockedBuffer, ciphertext []byte, err error) {

	// create the secret and the chipetext (secret incapsulated)
	if publicKey == nil || publicKey.key == nil {
		return nil, nil, apperr.New("public ML-KEM key is nil")
	}
	secret, ciphertext := publicKey.key.Encapsulate()

	// put the secret in locked RAM memory
	secretLocked = memguard.NewBufferFromBytes(secret)
	memguard.WipeBytes(secret)

	return secretLocked, ciphertext, nil
}

// get the secret from the ciphertext
func DecapsulateChipertext(privateKey *PrivateMLKEM, ciphertext []byte) (secretLocked *memguard.LockedBuffer, err error) {

	// get the shared secret
	if privateKey == nil || privateKey.enclave == nil {
		return nil, apperr.New("private ML-KEM key is nil")
	}
	buffer, err := privateKey.enclave.Open()
	if err != nil {
		return nil, apperr.Wrap("open ML-KEM private key", err)
	}
	defer buffer.Destroy()
	key, err := mlkem.NewDecapsulationKey768(buffer.Bytes())
	if err != nil {
		return nil, apperr.Wrap("decode ML-KEM private key", err)
	}
	secret, err := key.Decapsulate(ciphertext)
	if err != nil {
		return nil, apperr.Wrap("decapsulate ML-KEM ciphertext", err)
	}

	secretLocked = memguard.NewBufferFromBytes(secret)
	memguard.WipeBytes(secret)

	return secretLocked, nil
}

// EncryptPrivateKey encrypts the key based on useHSM bool and returns the filled struct.
// If useHSM is true, uses EncryptHSM (auto-detects SE on darwin, TPM on linux/windows).
// If useHSM is false, uses Argon2id + AES-256-GCM.
func EncryptPrivateKey(password *memguard.Enclave, privateKey *PrivateMLKEM, level int, useHSM bool) (*PrivateKEM, error) {
	if privateKey == nil || privateKey.enclave == nil {
		return nil, apperr.New("private ML-KEM key is nil")
	}
	ciphertext, params, err := HSM.Encrypt(password, privateKey.enclave, level, useHSM)
	if err != nil {
		return nil, apperr.Wrap("protect ML-KEM private key", err)
	}

	scheme := &PrivateKEM{
		PrivateKeyEncrypted: ciphertext,
		Nonce:               params.Nonce,
		Salt:                params.Salt,
		ArgonLevel:          params.ArgonLevel,
		EncryptMethod:       params.HSMMethod,
	}

	return scheme, nil

}

// SerializePrivateKey marshals the filled PrivateKEM struct to bytes.
func SerializePrivateKey(scheme *PrivateKEM) ([]byte, error) {

	bytes, err := messagepack.Marshal(scheme)
	if err != nil {
		return nil, apperr.Wrap("error during serialization of the private mlkem key", err)
	}

	return bytes, nil

}

// PrivateMLKEM keeps the operational key sealed until a key method needs it.
type PrivateMLKEM struct{ enclave *memguard.Enclave }
type PublicMLKEM struct{ key *mlkem.EncapsulationKey768 }

func NewPublicKey(data []byte) (*PublicMLKEM, error) {
	key, err := mlkem.NewEncapsulationKey768(data)
	if err != nil {
		return nil, apperr.Wrap("decode ML-KEM public key", err)
	}
	return &PublicMLKEM{key: key}, nil
}

func (key *PublicMLKEM) Bytes() []byte {
	if key == nil || key.key == nil {
		return nil
	}
	return key.key.Bytes()
}

func (key *PrivateMLKEM) PublicKey() *PublicMLKEM { return ExtractPublicKey(key) }
func (key *PublicMLKEM) Encapsulate() (*memguard.LockedBuffer, []byte, error) {
	return EncapsulateSecret(key)
}
func (key *PrivateMLKEM) Decapsulate(ciphertext []byte) (*memguard.LockedBuffer, error) {
	return DecapsulateChipertext(key, ciphertext)
}
func (key *PrivateMLKEM) Encrypt(password *memguard.Enclave, level int, useHSM bool) (*PrivateKEM, error) {
	return EncryptPrivateKey(password, key, level, useHSM)
}
func (key *PrivateMLKEM) SerializeAndEncrypt(password *memguard.Enclave, level int, useHSM bool) ([]byte, error) {
	encrypted, err := key.Encrypt(password, level, useHSM)
	if err != nil {
		return nil, err
	}
	return SerializePrivateKey(encrypted)
}
func DecryptPrivateKey(password *memguard.Enclave, serialized []byte) (*PrivateMLKEM, error) {
	var scheme PrivateKEM
	if err := messagepack.Unmarshal(serialized, &scheme); err != nil {
		return nil, apperr.Wrap("decode stored ML-KEM key", err)
	}
	enclave, err := HSM.Decrypt(password, scheme.PrivateKeyEncrypted, &HSM.EncryptParams{
		Nonce: scheme.Nonce, Salt: scheme.Salt, ArgonLevel: scheme.ArgonLevel, HSMMethod: scheme.EncryptMethod,
	})
	if err != nil {
		return nil, apperr.Wrap("decrypt ML-KEM private key", err)
	}
	return &PrivateMLKEM{enclave: enclave}, nil
}
