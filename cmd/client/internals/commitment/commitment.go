package commitment

import (
	"P2Chat/cmd/client/internals/argon"
	keyencryption "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	"P2Chat/pkg/apperr"
	"crypto/hmac"
	"crypto/rand"

	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

const (
	commitmentContext = "commitment_scheme_mldsa"
	commitmentDomain  = "P2Chat/commitment/v1"
	commitmentSize    = 32
	nonceSize         = 32
	saltSize          = 32
	argonOutputSize   = 32
	minPSKSize        = 16
)

// Commitment creates the public verifier and encrypts the PSK for local storage.
// commitmentLevel and storageLevel are independent Argon2id presets.
func Commitment(mldsaPublic *mldsa.PublicMLDSA, x25519Public *x25519.PublicX25519, mldsaPrivate *mldsa.PrivateMLDSA, x25519Private *x25519.PrivateX25519, psk *memguard.Enclave, commitmentLevel int, password *memguard.Enclave, storageLevel int, useHSM bool) (*commitmentproto.CommitmentSchemeUpload, *commitmentproto.CommitmentSchemePrivate, error) {
	if mldsaPublic == nil || x25519Public == nil || mldsaPrivate == nil || x25519Private == nil || psk == nil {
		return nil, nil, apperr.New("missing commitment key")
	}

	if commitmentLevel < 1 || commitmentLevel > 3 {
		return nil, nil, apperr.New("commitment Argon level must be between 1 and 3")
	}
	if storageLevel < 1 || storageLevel > 3 {
		return nil, nil, apperr.New("commitment storage Argon level must be between 1 and 3")
	}

	pskBuffer, err := psk.Open()
	if err != nil {
		return nil, nil, apperr.Wrap("open commitment PSK", err)
	}
	defer pskBuffer.Destroy()

	if len(pskBuffer.Bytes()) < minPSKSize {
		return nil, nil, apperr.New("commitment PSK must be at least 16 bytes")
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, apperr.Wrap("create commitment nonce", err)
	}

	outputArgon, params, err := argon.HashWithArgon(commitmentLevel, psk)
	if err != nil {
		return nil, nil, err
	}
	defer outputArgon.Destroy()

	// create the commitment (no signature)
	value, err := createValue(outputArgon, nonce, mldsaPublic, x25519Public)
	if err != nil {
		return nil, nil, err
	}

	signatureMLDSA, err := mldsaPrivate.Sign(value, []byte(commitmentContext), true)
	if err != nil {
		return nil, nil, apperr.Wrap("sign commitment with ML-DSA", err)
	}
	signatureX25519, err := x25519Private.Sign(value)
	if err != nil {
		return nil, nil, apperr.Wrap("sign commitment with X25519", err)
	}

	public := &commitmentproto.CommitmentSchemeUpload{
		Commitment:      value,
		SignatureMldsa:  signatureMLDSA,
		SignatureX25519: signatureX25519,
		Nonce:           nonce,
		ArgonParams:     params,
	}

	pskEncrypted, encryptionParams, err := keyencryption.Encrypt(password, psk, storageLevel, useHSM)
	if err != nil {
		return nil, nil, apperr.Wrap("encrypt commitment PSK", err)
	}
	b, err := messagepack.Marshal(encryptionParams)
	if err != nil {
		return nil, nil, apperr.Wrap("serialize commitment encryption parameters", err)
	}

	private := &commitmentproto.CommitmentSchemePrivate{
		Upload:           public,
		PskEncrypted:     pskEncrypted,
		EncryptionParams: b,
	}
	return public, private, nil
}

// DecryptPSK restores the locally stored PSK using the encryption parameters
// saved alongside its ciphertext.
func DecryptPSK(scheme *commitmentproto.CommitmentSchemePrivate, password *memguard.Enclave) (*memguard.Enclave, error) {
	if scheme == nil {
		return nil, apperr.New("private commitment scheme is missing")
	}
	if len(scheme.GetPskEncrypted()) == 0 || len(scheme.GetEncryptionParams()) == 0 {
		return nil, apperr.New("private commitment scheme is incomplete")
	}

	params := &keyencryption.EncryptParams{}
	if err := messagepack.Unmarshal(scheme.GetEncryptionParams(), params); err != nil {
		return nil, apperr.Wrap("deserialize commitment encryption parameters", err)
	}

	psk, err := keyencryption.Decrypt(password, scheme.GetPskEncrypted(), params)
	if err != nil {
		return nil, apperr.Wrap("decrypt commitment PSK", err)
	}
	return psk, nil
}

// VerifyCommitment checks the commitment value and both identity signatures.
func VerifyCommitment(scheme *commitmentproto.CommitmentSchemeUpload, mldsaPublic *mldsa.PublicMLDSA, x25519Public *x25519.PublicX25519, psk *memguard.Enclave) (bool, error) {
	if scheme == nil || mldsaPublic == nil || x25519Public == nil || psk == nil {
		return false, apperr.New("missing commitment verification data")
	}
	if err := ValidateUpload(scheme); err != nil {
		return false, nil
	}

	outputArgon, err := argon.HashUsingParams(psk, scheme.GetArgonParams())
	if err != nil {
		return false, apperr.Wrap("derive PSK from commitment params", err)
	}
	defer outputArgon.Destroy()

	expected, err := createValue(outputArgon, scheme.GetNonce(), mldsaPublic, x25519Public)
	if err != nil {
		return false, err
	}
	if !hmac.Equal(expected, scheme.GetCommitment()) {
		return false, nil
	}
	if !mldsaPublic.Verify(scheme.GetCommitment(), []byte(commitmentContext), scheme.GetSignatureMldsa()) {
		return false, nil
	}
	return x25519Public.Verify(scheme.GetCommitment(), scheme.GetSignatureX25519()), nil
}

// VerifyUpload checks the public structure and signatures without deriving the PSK.
func VerifyUpload(scheme *commitmentproto.CommitmentSchemeUpload, mldsaPublic *mldsa.PublicMLDSA, x25519Public *x25519.PublicX25519) (bool, error) {
	if err := ValidateUpload(scheme); err != nil {
		return false, err
	}
	if mldsaPublic == nil || x25519Public == nil {
		return false, apperr.New("missing commitment public keys")
	}
	if !mldsaPublic.Verify(scheme.GetCommitment(), []byte(commitmentContext), scheme.GetSignatureMldsa()) {
		return false, apperr.New("invalid commitment ML-DSA signature")
	}
	if !x25519Public.Verify(scheme.GetCommitment(), scheme.GetSignatureX25519()) {
		return false, apperr.New("invalid commitment X25519 signature")
	}
	return true, nil
}

// ValidateUpload validates the public commitment before any Argon2 work is performed.
func ValidateUpload(scheme *commitmentproto.CommitmentSchemeUpload) error {
	if scheme == nil {
		return apperr.New("commitment scheme is missing")
	}
	if len(scheme.GetCommitment()) != commitmentSize {
		return apperr.New("invalid commitment length")
	}
	if len(scheme.GetSignatureMldsa()) != mldsa.SignatureSize {
		return apperr.New("invalid commitment ML-DSA signature length")
	}
	if len(scheme.GetSignatureX25519()) != x25519.SignatureSize {
		return apperr.New("invalid commitment X25519 signature length")
	}
	if len(scheme.GetNonce()) != nonceSize {
		return apperr.New("invalid commitment nonce length")
	}

	params := scheme.GetArgonParams()
	if params == nil || params.GetLevel() < 1 || params.GetLevel() > 3 {
		return apperr.New("invalid commitment Argon level")
	}
	expected := argon.CreateArgonParams(int(params.GetLevel()))
	if params.GetTime() != expected.GetTime() || params.GetMemory() != expected.GetMemory() {
		return apperr.New("invalid commitment Argon preset")
	}
	if params.GetThreads() == 0 || params.GetThreads() > 255 {
		return apperr.New("invalid commitment Argon threads")
	}
	if params.GetLen() != argonOutputSize || params.GetVersion() != uint32(argon2.Version) {
		return apperr.New("invalid commitment Argon output parameters")
	}
	if len(params.GetSalt()) != saltSize {
		return apperr.New("invalid commitment Argon salt length")
	}
	return nil
}

// createValue creates the commitment hash putting together the domain, nonce, public keys and the psk
func createValue(pskBuffer *memguard.LockedBuffer, nonce []byte, mldsaPublic *mldsa.PublicMLDSA, x25519Public *x25519.PublicX25519) ([]byte, error) {
	if pskBuffer == nil {
		return nil, apperr.New("missing commitment PSK buffer")
	}
	if mldsaPublic == nil || x25519Public == nil {
		return nil, apperr.New("missing public keys")
	}

	domain := []byte(commitmentDomain)
	mldsaBytes := mldsaPublic.Bytes()
	x25519Bytes := x25519Public.Bytes()
	pskBytes := pskBuffer.Bytes()

	s := memguard.NewBuffer(len(domain) + len(nonce) + len(mldsaBytes) + len(x25519Bytes) + len(pskBytes))
	defer s.Destroy()

	offset := copy(s.Bytes(), domain)
	offset += copy(s.Bytes()[offset:], nonce)
	offset += copy(s.Bytes()[offset:], mldsaBytes)
	offset += copy(s.Bytes()[offset:], x25519Bytes)
	copy(s.Bytes()[offset:], pskBytes)

	value := blake2b.Sum256(s.Bytes())
	return value[:], nil
}
