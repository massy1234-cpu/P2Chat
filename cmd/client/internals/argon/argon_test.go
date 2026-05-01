package argon

import (
	"fmt"
	"testing"

	"github.com/awnumar/memguard"
)

//table-driven tests
type tests struct {
	test int
	input *memguard.LockedBuffer
	level int
	salt []byte
	wantError string
}


//Test edge cases 
func TestHashWithArgon(t *testing.T) {

	//Generate 20 limit tests
	tests := []tests{
		{1, nil, 2, []byte("salt"), "password null"}, // nil password
		{2, memguard.NewBufferFromBytes([]byte{}), 2, []byte("salt"), "password lenght 0"}, // empty password
		{3, memguard.NewBufferFromBytes([]byte("pass")), 2, nil, "salt is null"}, // nil salt
		{4, memguard.NewBufferFromBytes([]byte("pass")), 0, []byte("salt"), "level not valid"}, // level too low
		{5, memguard.NewBufferFromBytes([]byte("pass")), 4, []byte("salt"), "level not valid"}, // level too high
		{6, memguard.NewBufferFromBytes([]byte("pass")), -1, []byte("salt"), "level not valid"}, // negative level
		{7, memguard.NewBufferFromBytes([]byte("pass")), 100, []byte("salt"), "level not valid"}, // very high level
		{8, memguard.NewBufferFromBytes([]byte("pass")), 2, []byte{}, "salt lenght is zero"}, // empty salt 
		{9, memguard.NewBufferFromBytes([]byte("p")), 1, []byte("s"), ""}, // minimal valid
		{10, memguard.NewBufferFromBytes([]byte("verylongpassword123456789")), 3, []byte("salt"), ""}, // long password
		{11, memguard.NewBufferFromBytes([]byte("pass")), 1, []byte("verylongsaltvalue123456789"), ""}, // long salt
		{12, memguard.NewBufferFromBytes([]byte("pass")), 2, []byte("salt"), ""}, // valid
		{13, memguard.NewBufferFromBytes([]byte("pass")), 3, []byte("salt"), ""}, // valid high level
		{14, memguard.NewBufferFromBytes([]byte("pass")), 1, []byte("salt"), ""}, // valid low level
		{15, memguard.NewBufferFromBytes([]byte("123456")), 2, []byte("salt"), ""}, // numeric password
		{16, memguard.NewBufferFromBytes([]byte("!@#$%^")), 2, []byte("salt"), ""}, // special chars
		{17, memguard.NewBufferFromBytes([]byte("PASS")), 2, []byte("salt"), ""}, // uppercase
		{18, memguard.NewBufferFromBytes([]byte("pass")), 2, []byte("SALT"), ""}, // uppercase salt
		{19, memguard.NewBufferFromBytes([]byte(" "),  ), 2, []byte("salt"), ""}, // space password
		{20, memguard.NewBufferFromBytes([]byte("pass")), 2, []byte(" "), ""}, // space salt
	}

	for i := range tests {
		input := tests[i]

		t.Run(fmt.Sprintf("test %d case 🧪", input.test),func(t *testing.T) {

			hash , err := HashWithArgon(input.level,input.input,input.salt)
			if hash != nil {
				defer hash.Destroy()
			}

			if input.wantError != "" || err != nil {
				if ( err == nil && input.wantError != "" ) || ( err != nil && input.wantError == "" ){
					t.Fatal("error case ", input.test)
				}

				if err != nil && err.Error() != input.wantError {
					t.Fatal("errors not match ", input.test )
				} 
			}else{
				//check hash if is valid
				if len(hash.Bytes()) != 32 {
					t.Fatal("error with creation of hash")
				}
			}
		})
	}

}