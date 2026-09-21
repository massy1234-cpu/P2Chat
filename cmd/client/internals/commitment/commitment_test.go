package commitment

import (
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"testing"

	"github.com/awnumar/memguard"
)

func TestCommitmentFlow(t *testing.T) {
	memguard.CatchInterrupt()

	// 1. Generate identity keys
	privMLDSA, pubMLDSA, err := mldsa.CreateKeys()
	if err != nil {
		t.Fatalf("create ML-DSA keys: %v", err)
	}
	privX25519, pubX25519, err := x25519.CreateKey()
	if err != nil {
		t.Fatalf("create X25519 keys: %v", err)
	}

	// 2. Secret passwords
	sharedPassword := memguard.NewEnclave([]byte("my-super-secret-contact-passphrase-1234"))
	userMasterPassword := memguard.NewEnclave([]byte("user-master-password-for-local-db-9876"))

	// 3. Create Commitment
	uploadScheme, privateScheme, err := Commitment(
		pubMLDSA,
		pubX25519,
		privMLDSA,
		privX25519,
		sharedPassword,
		2, // level 2 for faster unit test
		userMasterPassword,
		false, // no HSM for local test
	)
	if err != nil {
		t.Fatalf("Commitment failed: %v", err)
	}

	if uploadScheme == nil || privateScheme == nil {
		t.Fatalf("schemes are nil")
	}

	// 4. Verify with correct password
	ok, err := VerifyCommitment(uploadScheme, pubMLDSA, pubX25519, sharedPassword)
	if err != nil {
		t.Fatalf("VerifyCommitment returned error: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyCommitment failed for correct password")
	}

	// 5. Verify with WRONG password
	wrongPassword := memguard.NewEnclave([]byte("wrong-password-attempt-00000000000"))
	okWrong, err := VerifyCommitment(uploadScheme, pubMLDSA, pubX25519, wrongPassword)
	if err != nil {
		t.Fatalf("VerifyCommitment with wrong password returned error: %v", err)
	}
	if okWrong {
		t.Fatalf("VerifyCommitment unexpectedly succeeded with wrong password!")
	}

	// 6. Decrypt local PSK
	decryptedPSK, err := DecryptPSK(privateScheme, userMasterPassword)
	if err != nil {
		t.Fatalf("DecryptPSK failed: %v", err)
	}
	decBuf, err := decryptedPSK.Open()
	if err != nil {
		t.Fatalf("open decrypted PSK: %v", err)
	}
	defer decBuf.Destroy()

	origBuf, err := sharedPassword.Open()
	if err != nil {
		t.Fatalf("open original PSK: %v", err)
	}
	defer origBuf.Destroy()

	if string(decBuf.Bytes()) != string(origBuf.Bytes()) {
		t.Fatalf("decrypted PSK does not match original password")
	}
}
