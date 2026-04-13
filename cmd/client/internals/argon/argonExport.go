package argon

import (
	"fmt"
	"os"
	"strconv"
	"encoding/base64"
)

//save params with the argon2 encoded string
//es ->  $argon2id$v=19$m=65536$t=3$p=4$salt
//v is version
//m is memory
//t is time
//p is parallelism or threads
func ExportEncodedArgonString(level int, salt []byte)(error){

	params := argon2Params(level)

	//i dont save the hash because is contradiction
	encodedstring := "argon2id$v=" + strconv.Itoa(int(params.version)) + "$m=" + strconv.Itoa(int(params.memory)) + "$t=" + strconv.Itoa(int(params.time)) + "$p=" + strconv.Itoa(int(params.threads)) + "$l=" + strconv.Itoa(level)  + "$" + base64.StdEncoding.EncodeToString(salt)

	err := os.WriteFile("data/argonParams.dat", []byte(encodedstring), 0600)

	if err != nil {
		return fmt.Errorf("Exporting Argon Params : error in the writing the params %w", err)
	}

	return nil

}