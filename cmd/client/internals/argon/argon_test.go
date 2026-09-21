package argon

import (
	"fmt"
	"testing"

	"github.com/awnumar/memguard"
)

// table-driven tests
type tests struct {
	test      int
	input     *memguard.Enclave
	level     int
	wantError string
}

// Test edge cases
func TestHashWithArgon(t *testing.T) {

	//Generate 20 limit tests
	tests := []tests{
		{1, nil, 2, "password null"},                                         // nil password
		{2, memguard.NewEnclave([]byte{}), 2, "password null"},               // empty enclave is nil
		{3, memguard.NewEnclave([]byte("pass")), 0, "level not valid"},       // level too low
		{4, memguard.NewEnclave([]byte("pass")), 4, "level not valid"},       // level too high
		{5, memguard.NewEnclave([]byte("pass")), -1, "level not valid"},      // negative level
		{6, memguard.NewEnclave([]byte("pass")), 100, "level not valid"},     // very high level
		{7, memguard.NewEnclave([]byte("p")), 1, ""},                         // minimal valid
		{8, memguard.NewEnclave([]byte("verylongpassword123456789")), 3, ""}, // long password
		{9, memguard.NewEnclave([]byte("pass")), 2, ""},                      // valid
		{10, memguard.NewEnclave([]byte("pass")), 3, ""},                     // valid high level
		{11, memguard.NewEnclave([]byte("pass")), 1, ""},                     // valid low level
		{12, memguard.NewEnclave([]byte("123456")), 2, ""},                   // numeric password
		{13, memguard.NewEnclave([]byte("!@#$%^")), 2, ""},                   // special chars
		{14, memguard.NewEnclave([]byte("PASS")), 2, ""},                     // uppercase
		{15, memguard.NewEnclave([]byte(" ")), 2, ""},                        // space password
	}

	for i := range tests {
		input := tests[i]

		t.Run(fmt.Sprintf("test %d case 🧪", input.test), func(t *testing.T) {

			hash, params, err := HashWithArgon(input.level, input.input)
			if hash != nil {
				defer hash.Destroy()
			}

			if input.wantError != "" || err != nil {
				if (err == nil && input.wantError != "") || (err != nil && input.wantError == "") {
					t.Fatal("error case ", input.test)
				}

				if err != nil && err.Error() != input.wantError {
					t.Fatal("errors not match ", input.test)
				}
			} else {
				//check hash if is valid
				if len(hash.Bytes()) != 32 {
					t.Fatal("error with creation of hash")
				}
				if params == nil || len(params.GetSalt()) != 32 || params.GetLevel() != int32(input.level) {
					t.Fatal("invalid Argon parameters")
				}
			}
		})
	}

}
