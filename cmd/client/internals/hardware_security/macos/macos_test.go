//go:build darwin

package macos

import (
	data "P2Chat/cmd/client/internals/datacontrol"
	"os"
	"testing"
	"unsafe"

	"github.com/awnumar/memguard"
)

func TestAvailableSE(t *testing.T) {

	available := Available()
	if available == true {
		t.Log("Secure Enclave is available")
	} else {
		t.Fatal("SE not available: ", available)
	}
}

func TestCreateSecret(t *testing.T) {

	_, err := createKeys()
	if err != nil {
		t.Fatal("createKeys failed: ", err)
	}

	err = DeleteAllKeys()
	if err != nil {
		t.Fatal("DeleteAllKeys failed: ", err)
	}

	found, _ := SearchPrivateKey()
	if found {
		t.Fatal("keys still present after deletion")
	}
}

func TestSearchPrivateSEKey(t *testing.T) {

	_, err := createKeys()
	if err != nil {
		t.Fatal("createKeys failed: ", err)
	}

	found, ref := SearchPrivateKey()
	if !found {
		t.Fatal("private key not found after creation")
	}
	if unsafe.Pointer(ref) == nil {
		t.Fatal("private key reference is nil despite found=true")
	}
	t.Log("private key found and reference is valid")

	DeleteAllKeys()
}

func TestEncryptDecryptRoundTrip(t *testing.T) {

	plaintext := memguard.NewBuffer(32)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i)
	}

	blob, err := Encrypt(plaintext.Bytes())
	if err != nil {
		t.Fatal("Encrypt failed: ", err)
	}
	if blob == nil {
		t.Fatal("Encrypt returned nil blob")
	}

	decrypted, err := Decrypt(blob)
	if err != nil {
		t.Fatal("Decrypt failed: ", err)
	}
	if decrypted == nil {
		t.Fatal("Decrypt returned nil buffer")
	}

	if len(plaintext.Bytes()) != len(decrypted.Bytes()) {
		t.Fatalf("length mismatch: %d vs %d", len(plaintext.Bytes()), len(decrypted.Bytes()))
	}
	for i := range plaintext.Bytes() {
		if plaintext.Bytes()[i] != decrypted.Bytes()[i] {
			t.Fatalf("byte mismatch at %d: got %d, expected %d", i, decrypted.Bytes()[i], plaintext.Bytes()[i])
		}
	}
	t.Log("round-trip encrypt → decrypt: OK")

	DeleteAllKeys()
}

func TestEncryptDecryptLargeData(t *testing.T) {

	size := 5000
	plaintext := memguard.NewBuffer(size)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i % 256)
	}

	blob, err := Encrypt(plaintext.Bytes())
	if err != nil {
		t.Fatal("Encrypt failed for large data: ", err)
	}

	decrypted, err := Decrypt(blob)
	if err != nil {
		t.Fatal("Decrypt failed for large data: ", err)
	}

	if len(plaintext.Bytes()) != len(decrypted.Bytes()) {
		t.Fatalf("length mismatch: %d vs %d", len(plaintext.Bytes()), len(decrypted.Bytes()))
	}
	for i := range plaintext.Bytes() {
		if plaintext.Bytes()[i] != decrypted.Bytes()[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
	t.Logf("large data round-trip (%d bytes): OK", size)

	DeleteAllKeys()
}

func TestSaveBlobSE(t *testing.T) {

	plaintext := memguard.NewBuffer(32)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i)
	}

	blob, err := Encrypt(plaintext.Bytes())
	if err != nil {
		t.Fatal("Encrypt failed: ", err)
	}

	err = SaveBlob(blob)
	if err != nil {
		t.Fatal("SaveBlob failed: ", err)
	}

	if _, err := os.Stat("data/SE_BLOB.bin"); os.IsNotExist(err) {
		t.Fatal("SE_BLOB.bin was not created on disk")
	}
	info, _ := os.Stat("data/SE_BLOB.bin")
	if info.Size() == 0 {
		t.Fatal("SE_BLOB.bin is empty")
	}
	t.Logf("blob saved to data/SE_BLOB.bin (%d bytes)", info.Size())

	os.Remove("data/SE_BLOB.bin")
	DeleteAllKeys()
}

func TestDecryptUsingSE(t *testing.T) {

	plaintext := memguard.NewBuffer(32)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i)
	}

	blob, err := Encrypt(plaintext.Bytes())
	if err != nil {
		t.Fatal("Encrypt failed: ", err)
	}

	err = SaveBlob(blob)
	if err != nil {
		t.Fatal("SaveBlob failed: ", err)
	}
	defer os.Remove("data/SE_BLOB.bin")

	savedBlob, err := data.LoadByteFromFile("data/", "SE_BLOB.bin")
	if err != nil {
		t.Fatal("LoadByteFromFile failed: ", err)
	}
	if len(savedBlob) == 0 {
		t.Fatal("loaded blob is empty")
	}

	decrypted, err := Decrypt(savedBlob)
	if err != nil {
		t.Fatal("Decrypt from saved file blob failed: ", err)
	}
	if decrypted == nil {
		t.Fatal("Decrypt returned nil buffer")
	}

	if len(plaintext.Bytes()) != len(decrypted.Bytes()) {
		t.Fatalf("length mismatch: %d vs %d", len(plaintext.Bytes()), len(decrypted.Bytes()))
	}
	for i := range plaintext.Bytes() {
		if plaintext.Bytes()[i] != decrypted.Bytes()[i] {
			t.Fatalf("byte mismatch at %d after file round-trip: got %d, expected %d", i, decrypted.Bytes()[i], plaintext.Bytes()[i])
		}
	}
	t.Log("decrypt from saved file blob: OK")

	DeleteAllKeys()
}

func TestDeleteAllSEKeys(t *testing.T) {

	createKeys()

	err := DeleteAllKeys()
	if err != nil {
		t.Fatal("DeleteAllKeys failed: ", err)
	}

	found, _ := SearchPrivateKey()
	if found {
		t.Fatal("keys still present after deletion")
	}
	t.Log("all SE keys deleted successfully")
}
