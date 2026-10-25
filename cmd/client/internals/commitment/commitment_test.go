package commitment

import (
	"P2Chat/cmd/client/internals/argon"
	keyencryption "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	"testing"

	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
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
		2, // commitment level
		userMasterPassword,
		1,     // local storage level
		false, // no HSM for local test
	)
	if err != nil {
		t.Fatalf("Commitment failed: %v", err)
	}

	if uploadScheme == nil || privateScheme == nil {
		t.Fatalf("schemes are nil")
	}
	if uploadScheme.GetArgonParams().GetLevel() != 2 {
		t.Fatalf("commitment level mismatch: got %d", uploadScheme.GetArgonParams().GetLevel())
	}
	encryptionParams := &keyencryption.EncryptParams{}
	if err := messagepack.Unmarshal(privateScheme.GetEncryptionParams(), encryptionParams); err != nil {
		t.Fatalf("decode local encryption params: %v", err)
	}
	if encryptionParams.ArgonLevel != 1 {
		t.Fatalf("storage level mismatch: got %d", encryptionParams.ArgonLevel)
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

func TestValidateUploadRejectsInvalidLengthsAndArgonParams(t *testing.T) {
	privMLDSA, pubMLDSA, err := mldsa.CreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	privX25519, pubX25519, err := x25519.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	scheme, _, err := Commitment(
		pubMLDSA,
		pubX25519,
		privMLDSA,
		privX25519,
		memguard.NewEnclave(make([]byte, 32)),
		1,
		memguard.NewEnclave([]byte("user-master-password-for-local-db")),
		1,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateUpload(scheme); err != nil {
		t.Fatalf("valid upload rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*commitmentproto.CommitmentSchemeUpload)
	}{
		{name: "commitment length", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.Commitment = s.Commitment[:31] }},
		{name: "ML-DSA signature length", mutate: func(s *commitmentproto.CommitmentSchemeUpload) {
			s.SignatureMldsa = s.SignatureMldsa[:len(s.SignatureMldsa)-1]
		}},
		{name: "X25519 signature length", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.SignatureX25519 = s.SignatureX25519[:63] }},
		{name: "nonce length", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.Nonce = s.Nonce[:31] }},
		{name: "missing Argon params", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams = nil }},
		{name: "Argon level zero", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Level = 0 }},
		{name: "Argon level four", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Level = 4 }},
		{name: "Argon time", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Time++ }},
		{name: "Argon memory", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Memory++ }},
		{name: "Argon threads zero", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Threads = 0 }},
		{name: "Argon threads overflow", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Threads = 256 }},
		{name: "Argon output length", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Len = 31 }},
		{name: "Argon version", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Version++ }},
		{name: "Argon salt length", mutate: func(s *commitmentproto.CommitmentSchemeUpload) { s.ArgonParams.Salt = s.ArgonParams.Salt[:31] }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalid := proto.Clone(scheme).(*commitmentproto.CommitmentSchemeUpload)
			tt.mutate(invalid)
			if err := ValidateUpload(invalid); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateUploadAcceptsArgonLevels(t *testing.T) {
	for level := 1; level <= 3; level++ {
		params := argon.CreateArgonParams(level)
		params.Salt = make([]byte, 32)
		scheme := &commitmentproto.CommitmentSchemeUpload{
			Commitment:      make([]byte, 32),
			SignatureMldsa:  make([]byte, mldsa.SignatureSize),
			SignatureX25519: make([]byte, 64),
			Nonce:           make([]byte, 32),
			ArgonParams:     params,
		}
		if err := ValidateUpload(scheme); err != nil {
			t.Fatalf("level %d rejected: %v", level, err)
		}
	}
}

func TestCommitmentRejectsInvalidLevelsAndShortSecret(t *testing.T) {
	privMLDSA, pubMLDSA, err := mldsa.CreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	privX25519, pubX25519, err := x25519.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	password := memguard.NewEnclave([]byte("user-master-password-for-local-db"))
	secret := memguard.NewEnclave(make([]byte, 16))

	for _, level := range []int{0, 4} {
		if _, _, err := Commitment(pubMLDSA, pubX25519, privMLDSA, privX25519, secret, level, password, 1, false); err == nil {
			t.Fatalf("commitment level %d accepted", level)
		}
		if _, _, err := Commitment(pubMLDSA, pubX25519, privMLDSA, privX25519, secret, 1, password, level, false); err == nil {
			t.Fatalf("storage level %d accepted", level)
		}
	}

	if _, _, err := Commitment(pubMLDSA, pubX25519, privMLDSA, privX25519, secret, 1, password, 1, false); err != nil {
		t.Fatalf("16-byte commitment secret rejected: %v", err)
	}

	if _, _, err := Commitment(pubMLDSA, pubX25519, privMLDSA, privX25519, memguard.NewEnclave(make([]byte, 15)), 1, password, 1, false); err == nil {
		t.Fatal("short commitment secret accepted")
	}
}

func TestVerifyCommitmentRejectsTampering(t *testing.T) {
	privMLDSA, pubMLDSA, err := mldsa.CreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	privX25519, pubX25519, err := x25519.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := memguard.NewEnclave(make([]byte, 32))
	scheme, _, err := Commitment(pubMLDSA, pubX25519, privMLDSA, privX25519, secret, 1, memguard.NewEnclave([]byte("user-master-password-for-local-db")), 1, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"commitment", "mldsa signature", "x25519 signature"} {
		t.Run(field, func(t *testing.T) {
			tampered := proto.Clone(scheme).(*commitmentproto.CommitmentSchemeUpload)
			switch field {
			case "commitment":
				tampered.Commitment[0] ^= 1
			case "mldsa signature":
				tampered.SignatureMldsa[0] ^= 1
			case "x25519 signature":
				tampered.SignatureX25519[0] ^= 1
			}
			ok, err := VerifyCommitment(tampered, pubMLDSA, pubX25519, secret)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Fatal("tampered commitment accepted")
			}
		})
	}
}
