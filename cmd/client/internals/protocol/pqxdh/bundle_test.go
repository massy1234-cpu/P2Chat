package pqxdh

import (
	"crypto/rand"
	"os"
	"testing"

	data "P2Chat/cmd/client/internals/storage"
	"github.com/awnumar/memguard"
)

const testBundleID = 99

func cleanupTestBundle() {
	os.RemoveAll(bundleIKDir(testBundleID))
}

func makeTestPassword(t *testing.T) *memguard.Enclave {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("generate key:", err)
	}
	return memguard.NewEnclave(key)
}

func TestCreateBundlesNonHSM(t *testing.T) {
	password := makeTestPassword(t)

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

func TestCreateCurveSetSingle(t *testing.T) {
	password := makeTestPassword(t)
	defer cleanupTestBundle()

	_, _, err := CreateBundles(password, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	privateMLDSA, _, privateX25519, err := loadIKKeys(password, data.BasePath)
	if err != nil {
		t.Fatal("loadIKKeys:", err)
	}

	privSet, pubSet, err := CreateCurveSet(privateMLDSA, privateX25519, password, false, 0)
	if err != nil {
		t.Fatal("CreateCurveSet:", err)
	}
	if len(privSet) == 0 {
		t.Fatal("private curve set is empty")
	}
	if len(pubSet) == 0 {
		t.Fatal("public curve set is empty")
	}
}

func TestCreatePQKEMSetSingle(t *testing.T) {
	password := makeTestPassword(t)
	defer cleanupTestBundle()

	_, _, err := CreateBundles(password, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	privateMLDSA, _, privateX25519, err := loadIKKeys(password, data.BasePath)
	if err != nil {
		t.Fatal("loadIKKeys:", err)
	}

	privSet, pubSet, err := CreatePQKEMSet(privateMLDSA, privateX25519, password, false, 0)
	if err != nil {
		t.Fatal("CreatePQKEMSet:", err)
	}
	if len(privSet) == 0 {
		t.Fatal("private KEM set is empty")
	}
	if len(pubSet) == 0 {
		t.Fatal("public KEM set is empty")
	}
}

func TestCreateCurveSetsBatch(t *testing.T) {
	password := makeTestPassword(t)
	defer cleanupTestBundle()

	_, _, err := CreateBundles(password, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	n := 5
	privSets, pubSets, err := CreateCurveSets(password, false, data.BasePath, n)
	if err != nil {
		t.Fatal("CreateCurveSets:", err)
	}
	if len(privSets) != n {
		t.Fatalf("expected %d private sets, got %d", n, len(privSets))
	}
	if len(pubSets) != n {
		t.Fatalf("expected %d public sets, got %d", n, len(pubSets))
	}
	for i := 0; i < n; i++ {
		if len(privSets[i]) == 0 {
			t.Fatalf("private set %d is empty", i)
		}
		if len(pubSets[i]) == 0 {
			t.Fatalf("public set %d is empty", i)
		}
	}
}

func TestCreateKEMsetsBatch(t *testing.T) {
	password := makeTestPassword(t)
	defer cleanupTestBundle()

	_, _, err := CreateBundles(password, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	n := 5
	privSets, pubSets, err := CreateKEMsets(password, false, data.BasePath, n)
	if err != nil {
		t.Fatal("CreateKEMsets:", err)
	}
	if len(privSets) != n {
		t.Fatalf("expected %d private KEM sets, got %d", n, len(privSets))
	}
	if len(pubSets) != n {
		t.Fatalf("expected %d public KEM sets, got %d", n, len(pubSets))
	}
	for i := 0; i < n; i++ {
		if len(privSets[i]) == 0 {
			t.Fatalf("private KEM set %d is empty", i)
		}
		if len(pubSets[i]) == 0 {
			t.Fatalf("public KEM set %d is empty", i)
		}
	}
}
