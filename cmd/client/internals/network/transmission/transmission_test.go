package transmission

import (
	"bytes"
	"crypto/sha256"
	"net"
	"testing"
)

func sha256Of(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// TestWriteReadRoundTrip writes a message on one end of a pipe and reads it
// back from the other, checking that the payload survives padding removal and
// checksum verification.
func TestWriteReadRoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("hello, P2Chat - this is a test payload")

	go func() {
		if err := WriteMessage(client, payload); err != nil {
			t.Errorf("WriteMessage: %v", err)
		}
	}()

	got, err := ReadMessage(server)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}
}

// TestWriteReadLargePayload exercises a payload near the maximum message size.
func TestWriteReadLargePayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := bytes.Repeat([]byte{0xAB}, 60*1024)

	go func() {
		if err := WriteMessage(client, payload); err != nil {
			t.Errorf("WriteMessage: %v", err)
		}
	}()

	got, err := ReadMessage(server)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatal("large payload mismatch")
	}
}

// TestMatchChecksum checks the checksum comparison helper on both valid and
// corrupted inputs.
func TestMatchChecksum(t *testing.T) {
	data := []byte("checksum test")
	checksum := sha256Of(data)

	if !MatchChecksum(data, checksum) {
		t.Fatal("valid checksum should match")
	}

	corrupted := append([]byte(nil), data...)
	corrupted[0] ^= 0xFF
	if MatchChecksum(corrupted, checksum) {
		t.Fatal("corrupted data should not match")
	}
}

// TestCreatePaddingNonZero checks that padding is non-zero and extends the data.
func TestCreatePaddingNonZero(t *testing.T) {
	data := []byte("some data")
	padded, padLen := CreatePadding(data, 100)

	if padLen == 0 {
		t.Fatal("expected non-zero padding")
	}
	if len(padded) != len(data)+padLen {
		t.Fatalf("padded length = %d, want %d", len(padded), len(data)+padLen)
	}
	if !bytes.Equal(padded[:len(data)], data) {
		t.Fatal("padding must not modify the original data")
	}
}