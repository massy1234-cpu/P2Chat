package macos

import (
	"testing"
)

func TestAvailableSE(t *testing.T) {
	available := AvailableSE()
	if available == nil {
		t.Log("Secure Enclave is available")
	}else{
		t.Fatal("Errore nel test del SE ",available)
	}
}