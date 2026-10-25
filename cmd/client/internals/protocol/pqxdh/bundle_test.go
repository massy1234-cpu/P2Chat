package pqxdh

import (
	"P2Chat/cmd/client/database"
	mlkem "P2Chat/cmd/client/internals/keys/mlkem"
	"P2Chat/cmd/client/internals/keys/x25519"
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	bundleproto "P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	data "P2Chat/cmd/client/internals/storage"

	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
)

const testBundleID = 99

func useTestIKStorage(t testing.TB) {
	t.Helper()
	previous := data.BasePath
	data.BasePath = t.TempDir()
	t.Cleanup(func() { data.BasePath = previous })
}

func makeTestPassword(t *testing.T) *memguard.Enclave {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("generate key:", err)
	}
	return memguard.NewEnclave(key)
}

func makeTestCommitmentSecret(t *testing.T) *memguard.Enclave {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal("generate commitment secret:", err)
	}
	return memguard.NewEnclave(secret)
}

func TestCreateBundlesNonHSM(t *testing.T) {
	password := makeTestPassword(t)
	useTestIKStorage(t)

	bundles, err := CreateBundles(password, makeTestCommitmentSecret(t), 1, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles failed:", err)
	}
	public := bundles.Public
	private := bundles.Private
	privateCommitment := bundles.PrivateCommitment
	if public == nil {
		t.Fatal("public bundle is nil")
	}
	if private == nil {
		t.Fatal("private bundle is nil")
	}
	if public.GetCommitmentScheme() == nil || privateCommitment == nil {
		t.Fatal("commitment scheme is missing")
	}
	if len(public.GetIkMldsa()) == 0 {
		t.Fatal("IK_mldsa is empty")
	}
	if len(public.GetIkX25519()) == 0 {
		t.Fatal("IK_X25519 is empty")
	}
	if len(public.GetSpk()) == 0 {
		t.Fatal("SPK is empty")
	}
	if len(public.GetLastResortPqkem()) == 0 {
		t.Fatal("Last_resort_PQKEM is empty")
	}
	if len(private.SPK) == 0 {
		t.Fatal("private SPK is empty")
	}
	if len(private.Last_resort_PQKEM) == 0 {
		t.Fatal("private Last_resort_PQKEM is empty")
	}

	if public.GetSpkId() <= 0 || public.GetLastResortId() <= 0 {
		t.Fatal("prekey identifiers were not generated")
	}
	if private.SPKID != int(public.GetSpkId()) || private.LastResortID != int(public.GetLastResortId()) {
		t.Fatal("public and private prekey identifiers differ")
	}
	decoded, err := public.DecodePublicBundle()
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SPKID != private.SPKID || decoded.LastResortID != private.LastResortID {
		t.Fatal("decoded prekey identifiers differ")
	}
	if ok, err := public.VerifyBundle(); !ok || err != nil {
		t.Fatalf("generated bundle failed verification: %v", err)
	}

	keys, err := data.LoadIKKeys(data.BasePath, testBundleID)
	if err != nil {
		t.Fatal("load stored IK:", err)
	}
	if len(keys.PrivateMLDSA) == 0 || len(keys.PublicMLDSA) == 0 || len(keys.PrivateX25519) == 0 {
		t.Fatal("incomplete stored IK")
	}
	identity, err := LoadIKKeys(password, data.BasePath, testBundleID)
	if err != nil {
		t.Fatal("decrypt stored IK:", err)
	}
	message := []byte("IK storage round trip")
	signature, err := identity.PrivateMLDSA.Sign(message, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(identity.PublicMLDSA.Bytes(), public.GetIkMldsa()) {
		t.Fatal("stored ML-DSA public identity changed")
	}
	if !identity.PublicMLDSA.Verify(message, nil, signature) {
		t.Fatal("stored ML-DSA identity cannot sign")
	}
	signature, err = identity.PrivateX25519.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(identity.PrivateX25519.PublicKey().Bytes(), public.GetIkX25519()) || !identity.PrivateX25519.PublicKey().Verify(message, signature) {
		t.Fatal("stored X25519 identity mismatch")
	}

}

func TestCreateBundlesRejectsInvalidArgonLevels(t *testing.T) {
	password := makeTestPassword(t)
	secret := makeTestCommitmentSecret(t)
	for _, level := range []int{0, 4} {
		if _, err := CreateBundles(password, secret, level, 1, false, testBundleID); err == nil {
			t.Fatalf("bundle level %d accepted", level)
		}
		if _, err := CreateBundles(password, secret, 1, level, false, testBundleID); err == nil {
			t.Fatalf("commitment level %d accepted", level)
		}
	}
}

func TestCreateCurveSetSingle(t *testing.T) {
	password := makeTestPassword(t)
	useTestIKStorage(t)

	_, err := CreateBundles(password, makeTestCommitmentSecret(t), 1, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	identity, err := LoadIKKeys(password, data.BasePath, testBundleID)
	if err != nil {
		t.Fatal("loadIKKeys:", err)
	}

	privSet, pubSet, err := CreateCurveSet(identity.PrivateMLDSA, identity.PrivateX25519, password, 1, false, 0)
	if err != nil {
		t.Fatal("CreateCurveSet:", err)
	}
	if len(privSet) == 0 {
		t.Fatal("private curve set is empty")
	}
	if pubSet == nil || len(pubSet.GetX25519Key()) == 0 {
		t.Fatal("public curve set is empty")
	}
	var stored structures.StoredPrivateCurveSet
	if err := messagepack.Unmarshal(privSet, &stored); err != nil {
		t.Fatal(err)
	}
	key, err := x25519.DecryptPrivateKey(password, stored.X25519_key)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Identifier != int(pubSet.Identifier) || !bytes.Equal(key.PublicKey().Bytes(), pubSet.X25519Key) {
		t.Fatal("stored curve set does not match the public set")
	}
}

func TestCreatePQKEMSetSingle(t *testing.T) {
	password := makeTestPassword(t)
	useTestIKStorage(t)

	_, err := CreateBundles(password, makeTestCommitmentSecret(t), 1, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	identity, err := LoadIKKeys(password, data.BasePath, testBundleID)
	if err != nil {
		t.Fatal("loadIKKeys:", err)
	}

	privSet, pubSet, err := CreatePQKEMSet(identity.PrivateMLDSA, identity.PrivateX25519, password, 1, false, 0)
	if err != nil {
		t.Fatal("CreatePQKEMSet:", err)
	}
	if len(privSet) == 0 {
		t.Fatal("private KEM set is empty")
	}
	if pubSet == nil || len(pubSet.GetPqkemKey()) == 0 {
		t.Fatal("public KEM set is empty")
	}
	var stored structures.StoredPrivatekemSet
	if err := messagepack.Unmarshal(privSet, &stored); err != nil {
		t.Fatal(err)
	}
	key, err := mlkem.DecryptPrivateKey(password, stored.Pqkem_key)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Identifier != int(pubSet.Identifier) || !bytes.Equal(key.PublicKey().Bytes(), pubSet.PqkemKey) {
		t.Fatal("stored KEM set does not match the public set")
	}
}

func TestCreateCurveSetsBatch(t *testing.T) {
	password := makeTestPassword(t)
	useTestIKStorage(t)

	_, err := CreateBundles(password, makeTestCommitmentSecret(t), 1, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	n := 5
	privSets, pubSets, err := CreateCurveSets(password, 1, false, data.BasePath, testBundleID, n)
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
		if pubSets[i] == nil || len(pubSets[i].GetX25519Key()) == 0 {
			t.Fatalf("public set %d is empty", i)
		}
	}
}

func TestCreateKEMsetsBatch(t *testing.T) {
	password := makeTestPassword(t)
	useTestIKStorage(t)

	_, err := CreateBundles(password, makeTestCommitmentSecret(t), 1, 1, false, testBundleID)
	if err != nil {
		t.Fatal("CreateBundles:", err)
	}

	n := 5
	privSets, pubSets, err := CreateKEMsets(password, 1, false, data.BasePath, testBundleID, n)
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
		if pubSets[i] == nil || len(pubSets[i].GetPqkemKey()) == 0 {
			t.Fatalf("public KEM set %d is empty", i)
		}
	}
}

func BenchmarkCreateBundleAndSets(b *testing.B) {
	useTestIKStorage(b)
	previousRoot := data.ProjectRoot
	data.ProjectRoot = b.TempDir()
	b.Cleanup(func() { data.ProjectRoot = previousRoot })
	if err := database.Init(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = database.CloseDB() })
	pw := make([]byte, 32)
	copy(pw, []byte("password"))
	commitmentSecret := make([]byte, 32)
	copy(commitmentSecret, []byte("shared commitment secret"))

	s := time.Now()
	pkg, err := InitializePQXDH(memguard.NewEnclave(pw), memguard.NewEnclave(commitmentSecret), 1, 1, false, data.BasePath, 100)
	tBundle := time.Since(s)
	if err != nil {
		b.Fatal(err)
	}

	s = time.Now()
	_, _ = proto.Marshal(pkg.PublicBundle)
	_, _ = messagepack.Marshal(pkg.CurvePublicSets)
	_, _ = messagepack.Marshal(pkg.KemPublicSets)
	tMarshal := time.Since(s)

	b.Log("timer bundle creation: ", tBundle)
	b.Log("timer marshal        : ", tMarshal)
}

func TestInitializePQXDHCreatesIndependentIdentities(t *testing.T) {
	useTestIKStorage(t)
	previousRoot := data.ProjectRoot
	data.ProjectRoot = t.TempDir()
	t.Cleanup(func() { data.ProjectRoot = previousRoot })
	if err := database.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.CloseDB(); err != nil {
			t.Error(err)
		}
	})
	path := t.TempDir()
	password, secret := makeTestPassword(t), makeTestCommitmentSecret(t)
	res1, err := InitializePQXDH(password, secret, 1, 1, false, path, 1)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := InitializePQXDH(password, secret, 1, 1, false, path, 1)
	if err != nil {
		t.Fatal(err)
	}
	first, second := res1.PublicBundle, res2.PublicBundle
	if first.Id != 0 || second.Id != 1 {
		t.Fatalf("unexpected bundle IDs: %d, %d", first.Id, second.Id)
	}
	if bytes.Equal(first.IkMldsa, second.IkMldsa) || bytes.Equal(first.IkX25519, second.IkX25519) {
		t.Fatal("new bundle reused an identity key")
	}
	if _, err := createBundles(password, secret, 1, 1, false, path, int(first.Id)); err == nil {
		t.Fatal("existing bundle identity replaced")
	}
	for _, bundle := range []*bundleproto.PublicBundle{first, second} {
		identity, err := LoadIKKeys(password, path, int(bundle.Id))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(identity.PublicMLDSA.Bytes(), bundle.IkMldsa) || !bytes.Equal(identity.PrivateX25519.PublicKey().Bytes(), bundle.IkX25519) {
			t.Fatal("stored identities differ from the published bundle")
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "identity_keys.db" {
		t.Fatal("identity creation wrote files outside the IK database")
	}
	if _, err := os.Stat(filepath.Join(data.BasePath, "identity_keys.db")); !os.IsNotExist(err) {
		t.Fatal("InitializePQXDH ignored its basePath")
	}
}
