package macos

import (
	"testing"
	"unsafe"
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
	
	err,handler := CreateSEKeys()
	if err != nil {
		t.Fatal("CreateSecret failed, error: ",err)
	}
	
	t.Log("SE key created successfully",unsafe.Pointer(handler))

	
	// Delete the private key stored in the SE
	err = DeleteAllSEKeys()

	if err != nil {
		t.Fatal("Error DeleteAllSEKeys: ",err)
	}
}


func TestSearchKeySE(t *testing.T) {
	
	// Create a key inside the SE
	err,handler := CreateSEKeys()
	if err != nil {
		t.Fatal("CreateSecret failed, error: ",err)
	}
	
	t.Log("SE key created successfully",unsafe.Pointer(handler))

	// Searching 
	result,_ := SearchSEKey()
	if result == false {
		t.Fatal("key not found, error")
	}else{
		t.Log("key successfull found !")
	}

	// Cleanup
	DeleteAllSEKeys()
}

func TestCreateSecretFromSE(t *testing.T) {

	err := CreateSecretFromSE()
	if err != nil {
		t.Fatal("CreateSecretFromSE failed, error: ", err)
	}

	t.Log("Secret from SE created and saved successfully")

	// Cleanup
	DeleteAllSEKeys()
}