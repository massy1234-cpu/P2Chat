package encryption_test

import (
	"P2Chat/cmd/client/internals/encryption"
	"testing"
)

type commitmentTests struct {
	test       int
	key        []byte
	salt       []byte
	secret     string
	verifyKey  []byte
	verifySalt []byte
	verifyPass string
	wantMatch  bool
}

func TestCommitment(t *testing.T) {
	salt, err := encryption.GenerateSalt(32)
	if err != nil {
		t.Fatal("error during creation of salt", err)
	}

	keyExample := []byte("this is the key example")

	tests := []commitmentTests{
		{1, keyExample, salt, "password", keyExample, salt, "password", true},
		{2, keyExample, salt, "password", keyExample, salt, "wrong-password", false},
		{3, keyExample, salt, "password", []byte("wrong key"), salt, "password", false},
		{4, keyExample, salt, "password", keyExample, []byte("different salt"), "password", false},
		{5, []byte{}, salt, "password", []byte{}, salt, "password", true},
		{6, keyExample, []byte{}, "password", keyExample, []byte{}, "password", true},
		{7, keyExample, salt, "", keyExample, salt, "", true},
		{8, keyExample, salt, "password", keyExample, salt, "", false},
		{9, keyExample, salt, "", keyExample, salt, "password", false},
		{10, []byte("another key"), salt, "password", keyExample, salt, "password", false},
	}

	for i := range tests {
		input := tests[i]

		t.Run("commitment test", func(t *testing.T) {
			hash, err := encryption.Commitment(input.key, input.salt, []byte(input.secret))
			if err != nil {
				t.Fatal("error during creation of hash", input.test, err)
			}

			match, err := encryption.VerifyCommitment(hash, input.verifyKey, input.verifySalt, []byte(input.verifyPass))
			if err != nil {
				t.Fatal("error during verify the commitement", input.test, err)
			}

			if match != input.wantMatch {
				t.Fatal("commitment result does not match expected value", input.test)
			}
		})
	}
}
