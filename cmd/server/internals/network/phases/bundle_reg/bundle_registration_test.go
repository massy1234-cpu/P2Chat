package bundlereceive

import (
	"P2Chat/cmd/client/internals/argon"
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	x25519 "P2Chat/cmd/client/internals/keys/x25519"
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	upload "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"testing"

	"google.golang.org/protobuf/proto"
)

func validCommitmentBundle() *upload.PublicBundle {
	params := argon.CreateArgonParams(1)
	params.Salt = make([]byte, 32)
	return &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
		Commitment:      make([]byte, 32),
		SignatureMldsa:  make([]byte, mldsa.SignatureSize),
		SignatureX25519: make([]byte, x25519.SignatureSize),
		Nonce:           make([]byte, 32),
		ArgonParams:     params,
	}}
}

func TestValidateCommitmentRejectsMissingOrIncompleteCommitment(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*upload.PublicBundle)
	}{
		{name: "missing commitment scheme", mutate: func(bundle *upload.PublicBundle) { bundle.CommitmentScheme = nil }},
		{name: "invalid commitment length", mutate: func(bundle *upload.PublicBundle) { bundle.CommitmentScheme.Commitment = make([]byte, 31) }},
		{name: "invalid ML-DSA signature length", mutate: func(bundle *upload.PublicBundle) {
			bundle.CommitmentScheme.SignatureMldsa = make([]byte, mldsa.SignatureSize-1)
		}},
		{name: "invalid X25519 signature length", mutate: func(bundle *upload.PublicBundle) {
			bundle.CommitmentScheme.SignatureX25519 = make([]byte, x25519.SignatureSize-1)
		}},
		{name: "invalid nonce length", mutate: func(bundle *upload.PublicBundle) { bundle.CommitmentScheme.Nonce = make([]byte, 31) }},
		{name: "missing Argon parameters", mutate: func(bundle *upload.PublicBundle) { bundle.CommitmentScheme.ArgonParams = nil }},
		{name: "invalid Argon level", mutate: func(bundle *upload.PublicBundle) { bundle.CommitmentScheme.ArgonParams.Level = 4 }},
		{name: "invalid Argon salt length", mutate: func(bundle *upload.PublicBundle) { bundle.CommitmentScheme.ArgonParams.Salt = make([]byte, 31) }},
	}
	if err := validateCommitment(nil); err == nil {
		t.Fatal("expected missing public bundle validation to fail")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := proto.Clone(validCommitmentBundle()).(*upload.PublicBundle)
			tt.mutate(bundle)
			if err := validateCommitment(bundle); err == nil {
				t.Fatal("expected commitment validation to fail")
			}
		})
	}
}

func TestValidateCommitmentAcceptsCompleteCommitment(t *testing.T) {
	if err := validateCommitment(validCommitmentBundle()); err != nil {
		t.Fatalf("expected complete commitment to be accepted: %v", err)
	}
}
