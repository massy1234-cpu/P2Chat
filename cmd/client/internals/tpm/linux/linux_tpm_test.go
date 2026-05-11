// must test on a linux sysyem

package linux

import (
	"testing"
)

func TestCreateTPMResponse(t *testing.T){

	resp, err := CreateTPMResponse()
	if err != nil {
		t.Fatal("error during the creation of resp ",err)
	}

	buf, err := UnsealSecret(resp.OutPrivate,resp.OutPublic)
	if err != nil {
		t.Fatal("error during unseal the secret",err)
	}

	// expose the secret ( only in this use case, this is EXTREMELY dangerous )
	t.Log(buf.String())
}