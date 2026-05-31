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

func TestCreateSecret(t *testing.T) {
	
	err,Pointer := CreateSecret()
	if err != nil {
		t.Fatal("CreateSecret failed, error: ",err)
	}
	
	t.Log("SE key created successfully",Pointer)

	
	// Delete the private key stored in the SE
	err = DeleteAllSEKeys()

	if err != nil {
		t.Fatal("Error DeleteAllSEKeys: ",err)
	}


}