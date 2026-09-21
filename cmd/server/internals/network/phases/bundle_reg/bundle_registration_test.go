package bundlereceive

import (
	argonparams "P2Chat/cmd/client/internals/proto_generated/argon/argon_params"
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	upload "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"testing"
)

func TestValidateCommitmentRejectsMissingOrIncompleteCommitment(t *testing.T) {
	tests := []struct {
		name   string
		bundle *upload.PublicBundle
	}{
		{name: "missing public bundle"},
		{name: "missing commitment scheme", bundle: &upload.PublicBundle{}},
		{
			name: "empty commitment",
			bundle: &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
				SignatureMldsa:  []byte{1},
				SignatureX25519: []byte{1},
				Nonce:           []byte{1},
				ArgonParams:     &argonparams.ArgonParams{Salt: []byte{1}},
			}},
		},
		{
			name: "empty ML-DSA signature",
			bundle: &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
				Commitment:      []byte{1},
				SignatureX25519: []byte{1},
				Nonce:           []byte{1},
				ArgonParams:     &argonparams.ArgonParams{Salt: []byte{1}},
			}},
		},
		{
			name: "empty X25519 signature",
			bundle: &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
				Commitment:     []byte{1},
				SignatureMldsa: []byte{1},
				Nonce:          []byte{1},
				ArgonParams:    &argonparams.ArgonParams{Salt: []byte{1}},
			}},
		},
		{
			name: "empty nonce",
			bundle: &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
				Commitment:      []byte{1},
				SignatureMldsa:  []byte{1},
				SignatureX25519: []byte{1},
				ArgonParams:     &argonparams.ArgonParams{Salt: []byte{1}},
			}},
		},
		{
			name: "missing Argon parameters",
			bundle: &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
				Commitment:      []byte{1},
				SignatureMldsa:  []byte{1},
				SignatureX25519: []byte{1},
				Nonce:           []byte{1},
			}},
		},
		{
			name: "empty Argon salt",
			bundle: &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
				Commitment:      []byte{1},
				SignatureMldsa:  []byte{1},
				SignatureX25519: []byte{1},
				Nonce:           []byte{1},
				ArgonParams:     &argonparams.ArgonParams{},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCommitment(tt.bundle); err == nil {
				t.Fatal("expected commitment validation to fail")
			}
		})
	}
}

func TestValidateCommitmentAcceptsCompleteCommitment(t *testing.T) {
	bundle := &upload.PublicBundle{CommitmentScheme: &commitmentproto.CommitmentSchemeUpload{
		Commitment:      []byte{1},
		SignatureMldsa:  []byte{1},
		SignatureX25519: []byte{1},
		Nonce:           []byte{1},
		ArgonParams:     &argonparams.ArgonParams{Salt: []byte{1}},
	}}

	if err := validateCommitment(bundle); err != nil {
		t.Fatalf("expected complete commitment to be accepted: %v", err)
	}
}
