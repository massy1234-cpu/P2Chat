//go:build linux

// must test on a linux system

package linux_windows

import (
	"testing"
	"encoding/base64"
	"time"
)

// testing the function for create a Secret inside the TPM
func TestCreateTPMResponse(t *testing.T){

	// open connection
	tpm, err := openTPM()
	if err != nil {
		t.Fatal("apertura TPM", err)
	}

	// delete eventual primary template stored in NV
	DeletePrimaryNV(tpm)
	tpm.Close()

	resp, err := CreateResponse()
	if err != nil {
		t.Fatal("error during the creation of resp ",err)
	}

	buf, err := UnsealSecret(resp.OutPrivate,resp.OutPublic)
	if err != nil {
		t.Fatal("error during unseal the secret",err)
	}

	// expose the secret ( only in this use case, EXTREMELY dangerous, memory leak )
	t.Log(base64.StdEncoding.EncodeToString(buf.Bytes()))
}


// Benchmark first and second time with Unseal and primary template store 
func BenchmarkCreateResponse(b *testing.B) {

	// open connection
	tpm, err := openTPM()
	if err != nil {
		b.Fatal("apertura TPM", err)
	}

	// delete eventual primary template stored in NV
	DeletePrimaryNV(tpm)

	// start measuring
	start1 := time.Now()

	// i create the first time only one time because this needs about 15 seconds and do a for cycle is not convenient 
	resp, err := CreateResponse()
	if err != nil {
		b.Fatal("error during the creation of resp ",err)
	}
	buf, err := UnsealSecret(resp.OutPrivate,resp.OutPublic)
	if err != nil {
		b.Fatal("error during unseal the secret",err)
	}

	t1 := time.Since(start1)

	// expose the secret ( only in this use case, EXTREMELY dangerous, memory leak )
	b.Log(base64.StdEncoding.EncodeToString(buf.Bytes()))
	b.Log("First Creation needed ", t1, "\n")

	buf.Destroy()

	// testing average time nexts time
	var total time.Duration
	
	for range 10 {

		// Start
		iterStart := time.Now()
		resp, err := CreateResponse()
		if err != nil {
			b.Fatal("error during the creation of resp ",err)
		}
		buf, err := UnsealSecret(resp.OutPrivate,resp.OutPublic)
		if err != nil {
			b.Fatal("error during unseal the secret",err)
		}
		// End - Add time to total
		total += time.Since(iterStart)

		b.Log(base64.StdEncoding.EncodeToString(buf.Bytes()))
		buf.Destroy()
	}
	
	b.Logf("Other average subsequent %v", total/10)

	DeletePrimaryNV(tpm)
	tpm.Close()
}