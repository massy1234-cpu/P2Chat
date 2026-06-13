//go:build darwin

package HSM

import (
	"P2Chat/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/argon"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	macos "P2Chat/cmd/client/internals/HSM/macos"
	"P2Chat/cmd/client/internals/p2version"
	"testing"
	"time"
)

func TestSEEncryptKey(t *testing.T) {
	if !macos.Available() {
		t.Skip("SE not available on this machine")
	}

	publicKey, privateKeyExposed, err := mldsa87.GenerateKey(nil)
	if err != nil {
		t.Fatal("GenerateKey failed: ", err)
	}
	defer privateKeyExposed.Destroy()

	privateKey, err := privateKeyExposed.LockedBuffer()
	if err != nil {
		t.Fatal("LockedBuffer failed: ", err)
	}
	defer privateKey.Destroy()

	var packedPublic [mldsa87.PublicKeySize]byte
	publicKey.Pack(&packedPublic)

	argonParams := argon.CreateArgonParams(3)

	realKey := &struct_mldsa.PrivateKeyMLDSA{
		Algorithm:     "ML-DSA-87",
		P2ChatVersion: p2version.MagicByte(),
		Timestamp:     time.Now().Unix(),
		Nonce:         make([]byte, 12),
		Key:           privateKey.Bytes(),
		ArgonParams:   argonParams,
	}

	encrypted, err := SEEncryptKey(realKey)
	if err != nil {
		t.Fatal("SEEncryptKey failed: ", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encrypted blob is empty")
	}
	t.Logf("generated ML-DSA-87 keypair and encrypted it with SE: %d bytes", len(encrypted))
}
