package pqxdh

import (
	"crypto/rand"
	"testing"

	data "P2Chat/cmd/client/internals/storage"
	"github.com/awnumar/memguard"
)

func TestCreateBundlesNonHSM(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("generate key:", err)
	}
	password := memguard.NewEnclave(key)

	public, private, err := CreateBundles(password, 1, false, 1)
	if err != nil {
		t.Fatal("CreateBundles failed:", err)
	}
	if public == nil {
		t.Fatal("public bundle is nil")
	}
	if private == nil {
		t.Fatal("private bundle is nil")
	}
	if len(public.IK_mldsa) == 0 {
		t.Fatal("IK_mldsa is empty")
	}
	if len(public.IK_X25519) == 0 {
		t.Fatal("IK_X25519 is empty")
	}
	if len(public.SPK) == 0 {
		t.Fatal("SPK is empty")
	}
	if len(public.Last_resort_PQKEM) == 0 {
		t.Fatal("Last_resort_PQKEM is empty")
	}
	if len(private.SPK) == 0 {
		t.Fatal("private SPK is empty")
	}
	if len(private.Last_resort_PQKEM) == 0 {
		t.Fatal("private Last_resort_PQKEM is empty")
	}

	// verify that IK keys were saved on filesystem
	ikDir := bundleIKDir(1)
	if _, err := data.LoadByteFromFile(ikDir, "SK.bin"); err != nil {
		t.Fatal("SK.bin not found in bundle IK dir:", err)
	}
	if _, err := data.LoadByteFromFile(ikDir, "PK.bin"); err != nil {
		t.Fatal("PK.bin not found in bundle IK dir:", err)
	}
	if _, err := data.LoadByteFromFile(ikDir, "IK_X25519.bin"); err != nil {
		t.Fatal("IK_X25519.bin not found in bundle IK dir:", err)
	}
}
