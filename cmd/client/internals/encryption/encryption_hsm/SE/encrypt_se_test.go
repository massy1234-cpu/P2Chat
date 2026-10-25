//go:build darwin

package HSM

import (
	"P2Chat/cmd/client/internals/HSM/SE"
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	"github.com/awnumar/memguard"
	"testing"
)

func TestSEEncryptKey(t *testing.T) {
	if !SE.Available() {
		t.Skip("SE not available on this machine")
	}

	private, _, err := mldsa.CreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	realKey, err := private.Encrypt(memguard.NewBufferRandom(32).Seal(), 1, false)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptKey(realKey)
	if err != nil {
		t.Fatal("SEEncryptKey failed: ", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encrypted blob is empty")
	}
	t.Logf("generated ML-DSA-87 keypair and encrypted it with SE: %d bytes", len(encrypted))
}
