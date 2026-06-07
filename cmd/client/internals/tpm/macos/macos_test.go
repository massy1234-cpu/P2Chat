//go:build darwin

package macos

import (
	datacontrol "P2Chat/cmd/client/internals/datacontrol/mldsa"
	"os"
	"testing"
	"unsafe"
	"github.com/awnumar/memguard"
)

func TestAvailableSE(t *testing.T) {

	available := AvailableSE()
	if available == nil {
		t.Log("Secure Enclave is available")
	} else {
		t.Fatal("SE not available: ", available)
	}
}

func TestCreateSecret(t *testing.T) {

	err, _ := CreateSEKeys()
	if err != nil {
		t.Fatal("CreateSEKeys failed: ", err)
	}

	err = DeleteAllSEKeys()
	if err != nil {
		t.Fatal("DeleteAllSEKeys failed: ", err)
	}

	found, _ := SearchPrivateSEKey()
	if found {
		t.Fatal("keys still present after deletion")
	}
}

func TestSearchPrivateSEKey(t *testing.T) {

	err, _ := CreateSEKeys()
	if err != nil {
		t.Fatal("CreateSEKeys failed: ", err)
	}

	found, ref := SearchPrivateSEKey()
	if !found {
		t.Fatal("private key not found after creation")
	}
	if unsafe.Pointer(ref) == nil {
		t.Fatal("private key reference is nil despite found=true")
	}
	t.Log("private key found and reference is valid")

	DeleteAllSEKeys()
}

func TestEncryptDecryptRoundTrip(t *testing.T) {

	plaintext := memguard.NewBuffer(32)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i)
	}

	err, blob := EncryptUsingSE(plaintext)
	if err != nil {
		t.Fatal("EncryptUsingSE failed: ", err)
	}
	if unsafe.Pointer(blob) == nil {
		t.Fatal("EncryptUsingSE returned nil blob")
	}

	err, decrypted := DecryptUsingSE(blob)
	if err != nil {
		t.Fatal("DecryptUsingSE failed: ", err)
	}
	if decrypted == nil {
		t.Fatal("DecryptUsingSE returned nil buffer")
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

	DeleteAllSEKeys()
}

func TestEncryptDecryptLargeData(t *testing.T) {

	size := 5000
	plaintext := memguard.NewBuffer(size)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i % 256)
	}

	err, blob := EncryptUsingSE(plaintext)
	if err != nil {
		t.Fatal("EncryptUsingSE failed for large data: ", err)
	}

	err, decrypted := DecryptUsingSE(blob)
	if err != nil {
		t.Fatal("DecryptUsingSE failed for large data: ", err)
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

	DeleteAllSEKeys()
}

func TestSaveBlobSE(t *testing.T) {

	plaintext := memguard.NewBuffer(32)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i)
	}

	err, blob := EncryptUsingSE(plaintext)
	if err != nil {
		t.Fatal("EncryptUsingSE failed: ", err)
	}

	err = SaveBlobSE(blob)
	if err != nil {
		t.Fatal("SaveBlobSE failed: ", err)
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
	DeleteAllSEKeys()
}

func TestDecryptUsingSE(t *testing.T) {

	plaintext := memguard.NewBuffer(32)
	for i := range plaintext.Bytes() {
		plaintext.Bytes()[i] = byte(i)
	}

	err, blob := EncryptUsingSE(plaintext)
	if err != nil {
		t.Fatal("EncryptUsingSE failed: ", err)
	}

	err = SaveBlobSE(blob)
	if err != nil {
		t.Fatal("SaveBlobSE failed: ", err)
	}
	defer os.Remove("data/SE_BLOB.bin")

	savedBlob, err := datacontrol.LoadByteFromFile("data/", "SE_BLOB.bin")
	if err != nil {
		t.Fatal("LoadByteFromFile failed: ", err)
	}
	if len(savedBlob) == 0 {
		t.Fatal("loaded blob is empty")
	}

	err, ciphertext := NewCFData(savedBlob)
	defer GoCFRelease(ciphertext)

	err, decrypted := DecryptUsingSE(ciphertext)
	if err != nil {
		t.Fatal("DecryptUsingSE from saved file blob failed: ", err)
	}
	if decrypted == nil {
		t.Fatal("DecryptUsingSE returned nil buffer")
	}

	if len(plaintext.Bytes()) != len(decrypted.Bytes()) {
		t.Fatalf("length mismatch after file round-trip: %d vs %d", len(plaintext.Bytes()), len(decrypted.Bytes()))
	}
	for i := range plaintext.Bytes() {
		if plaintext.Bytes()[i] != decrypted.Bytes()[i] {
			t.Fatalf("byte mismatch at %d after file round-trip: got %d, expected %d", i, decrypted.Bytes()[i], plaintext.Bytes()[i])
		}
	}
	t.Log("decrypt from saved file blob: OK")

	DeleteAllSEKeys()
}

func TestDeleteAllSEKeys(t *testing.T) {

	CreateSEKeys()

	err := DeleteAllSEKeys()
	if err != nil {
		t.Fatal("DeleteAllSEKeys failed: ", err)
	}

	found, _ := SearchPrivateSEKey()
	if found {
		t.Fatal("keys still present after deletion")
	}
	t.Log("all SE keys deleted successfully")
}
