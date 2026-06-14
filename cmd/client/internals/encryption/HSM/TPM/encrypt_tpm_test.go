//go:build linux || windows

package HSM

import (
	TPM "P2Chat/cmd/client/internals/HSM/TPM"
	"P2Chat/cmd/client/internals/encryption"
	"P2Chat/cmd/client/internals/storage"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"github.com/awnumar/memguard"
	"github.com/google/go-tpm/tpm2"
)

// create secret with TPM, save on disk, load again and try to corrupt some bits of the blob
func createAndCheckBlobs(t *testing.T) (tpm2.TPM2BPrivate, tpm2.TPM2BPublic) {
	t.Helper()

	// --- Generate TPM sealed secret ---
	t.Log("  [blob] Creating TPM sealed secret...")
	resp, err := TPM.CreateResponse()
	if err != nil {
		t.Fatal("CreateResponse:", err)
	}

	privateRaw := tpm2.Marshal(resp.OutPrivate)
	publicRaw := tpm2.Marshal(resp.OutPublic)
	t.Logf("  [blob] Generated: private %d bytes, public %d bytes", len(privateRaw), len(publicRaw))

	// --- Save blobs to temp directory ---
	dir := t.TempDir()
	if err := storage.SaveBytesOnFile(privateRaw, dir, "privateBlob.bin"); err != nil {
		t.Fatal("save private blob:", err)
	}
	if err := storage.SaveBytesOnFile(publicRaw, dir, "publicBlob.bin"); err != nil {
		t.Fatal("save public blob:", err)
	}
	t.Logf("  [blob] Saved to %s", dir)

	// --- Load blobs back and compare ---
	loadedPrivateRaw, err := storage.LoadByteFromFile(dir, "privateBlob.bin")
	if err != nil {
		t.Fatal("load private blob:", err)
	}
	loadedPublicRaw, err := storage.LoadByteFromFile(dir, "publicBlob.bin")
	if err != nil {
		t.Fatal("load public blob:", err)
	}

	if !bytes.Equal(privateRaw, loadedPrivateRaw) {
		t.Error("private blob bytes differ after reload")
	} else {
		t.Log("  [blob] private blob bytes: MATCH")
	}
	if !bytes.Equal(publicRaw, loadedPublicRaw) {
		t.Error("public blob bytes differ after reload")
	} else {
		t.Log("  [blob] public blob bytes: MATCH")
	}

	loadedPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](loadedPrivateRaw)
	if err != nil {
		t.Fatal("unmarshal private blob:", err)
	}
	loadedPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](loadedPublicRaw)
	if err != nil {
		t.Fatal("unmarshal public blob:", err)
	}
	t.Log("  [blob] Unmarshal after reload: OK")

	// --- Corrupt one byte and observe behaviour ---
	t.Log("  [blob] Corruption test: flipping one byte...")
	corrupted := make([]byte, len(loadedPrivateRaw))
	copy(corrupted, loadedPrivateRaw)
	corrupted[len(corrupted)/2] ^= 0xFF // is a XOR, invert all the bits

	_, err = tpm2.Unmarshal[tpm2.TPM2BPrivate](corrupted)
	if err != nil {
		t.Logf("  [blob] Corrupted blob rejected by Unmarshal: %v (expected)", err)
	} else {
		t.Log("  [blob] WARNING: corrupted blob passed Unmarshal (TPM may still reject at Load)")
	}

	return *loadedPrivate, *loadedPublic
}


// Load the blob from disk, encrypt and decrypt with TPM 
func encryptDecryptWithTPMSecret(t *testing.T, private tpm2.TPM2BPrivate, public tpm2.TPM2BPublic) {
	t.Helper()

	t.Log("  [enc] Unsealing TPM secret...")
	tpmSecret, err := TPM.UnsealSecret(private, public)
	if err != nil {
		t.Fatal("UnsealSecret:", err)
	}
	t.Logf("  [enc] Unsealed: %d bytes", tpmSecret.Size())

	tpmBuf, err := tpmSecret.Open()
	if err != nil {
		t.Fatal("Enclave.Open:", err)
	}
	defer tpmBuf.Destroy()

	t.Log("  [enc] Generating 32-byte random secret...")
	randomRaw := make([]byte, 32)
	if _, err := rand.Read(randomRaw); err != nil {
		t.Fatal("rand.Read:", err)
	}
	randomSecret := memguard.NewBuffer(32)
	copy(randomSecret.Bytes(), randomRaw)
	memguard.WipeBytes(randomRaw)
	defer randomSecret.Destroy()

	t.Log("  [enc] Combining TPM secret + random secret via HMAC-SHA256 → AES key...")
	mac := hmac.New(sha256.New, tpmBuf.Bytes())
	mac.Write(randomSecret.Bytes())
	combinedKey := memguard.NewBuffer(32)
	copy(combinedKey.Bytes(), mac.Sum(nil))
	defer combinedKey.Destroy()

	t.Log("  [enc] Encrypting known plaintext with AES-256-GCM...")
	original := []byte("P2Chat TPM integration test — secret message")
	plaintext := memguard.NewBuffer(len(original))
	copy(plaintext.Bytes(), original)
	defer plaintext.Destroy()

	ciphertext, nonce, err := encryption.EncryptAes256(combinedKey, plaintext)
	if err != nil {
		t.Fatal("EncryptAes256:", err)
	}
	t.Logf("  [enc] Encrypted %d bytes → ciphertext %d + nonce %d", len(original), len(ciphertext), len(nonce))

	t.Log("  [enc] Decrypting back...")
	decrypted, err := encryption.DecryptAes256(combinedKey, nonce, ciphertext)
	if err != nil {
		t.Fatal("DecryptAes256:", err)
	}
	defer decrypted.Destroy()

	if !bytes.Equal(decrypted.Bytes(), original) {
		t.Fatal("decrypted text does not match original")
	}
	t.Log("  [enc] Decryption: plaintext matches original")

	t.Log("  [enc] Verifying wrong-key rejection...")
	wrongKey := memguard.NewBuffer(32)
	if _, err := rand.Read(wrongKey.Bytes()); err != nil {
		t.Fatal("rand.Read wrong key:", err)
	}
	defer wrongKey.Destroy()

	_, err = encryption.DecryptAes256(wrongKey, nonce, ciphertext)
	if err != nil {
		t.Logf("  [enc] Wrong key correctly rejected: %v", err)
	} else {
		t.Error("SECURITY FAILURE: decryption with wrong key succeeded")
	}
}

// TestTPMBlobCreateAndStore generates TPM blobs, saves them to disk,
// reloads them, and verifies integrity. It also tests corruption detection.
func TestTPMBlobCreateAndStore(t *testing.T) {
	if ok, _ := TPM.Available(); !ok {
		t.Skip("TPM not available on this system")
	}

	t.Log("=== [TestTPMBlobCreateAndStore] Clean NV at start ===")
	if err := TPM.CleanupNV(); err != nil {
		t.Log("CleanupNV (start):", err)
	}

	t.Log("=== Creating blobs, storing, loading and checking ===")
	_, _ = createAndCheckBlobs(t)

	t.Log("=== [TestTPMBlobCreateAndStore] Clean NV at end ===")
	if err := TPM.CleanupNV(); err != nil {
		t.Log("CleanupNV (end):", err)
	}

	t.Log("=== TestTPMBlobCreateAndStore PASSED ===")
}

// TestTPMSecretEncryption unseals the TPM secret, combines it with a
// random secret, and performs an AES-256-GCM encrypt/decrypt round-trip.
func TestTPMSecretEncryption(t *testing.T) {
	if ok, _ := TPM.Available(); !ok {
		t.Skip("TPM not available on this system")
	}

	t.Log("=== [TestTPMSecretEncryption] Clean NV at start ===")
	if err := TPM.CleanupNV(); err != nil {
		t.Log("CleanupNV (start):", err)
	}

	t.Log("=== Creating blobs for encryption test ===")
	private, public := createAndCheckBlobs(t)

	t.Log("=== Encrypt/decrypt round-trip with TPM secret ===")
	encryptDecryptWithTPMSecret(t, private, public)

	t.Log("=== [TestTPMSecretEncryption] Clean NV at end ===")
	if err := TPM.CleanupNV(); err != nil {
		t.Log("CleanupNV (end):", err)
	}

	t.Log("=== TestTPMSecretEncryption PASSED ===")
}
