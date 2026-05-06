package mldsa87

import (
	"testing"
)

func TestPrivateKeyUnmarshalBinaryKeepsSigningBehavior(t *testing.T) {
	pk, sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal("generate keypair:", err)
	}
	defer sk.Destroy()

	packed := sk.Bytes()

	var decoded PrivateKey
	if err := decoded.UnmarshalBinary(packed); err != nil {
		t.Fatal("unmarshal private key:", err)
	}

	sig := make([]byte, SignatureSize)
	msg := []byte("roundtrip message")
	ctx := []byte("ctx")

	if err := SignTo(&decoded, msg, ctx, true, sig); err != nil {
		t.Fatal("sign with unmarshaled key:", err)
	}

	if !Verify(pk, msg, ctx, sig) {
		t.Fatal("signature generated from unmarshaled key is not valid")
	}
}
