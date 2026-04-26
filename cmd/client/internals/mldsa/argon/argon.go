package argon

import (
	pb "P2Chat/cmd/client/internals/mldsa/gen/mldsapb"
	"P2Chat/pkg/apperr"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

// Create the struct that contain the correct params for argon derivation func
func CreateArgonParams(level int) *pb.ArgonParams {

	params := &pb.ArgonParams{}

	switch level {
	case 1:
		params.Time = 10
		params.Memory = 1024 * 1024
		params.Threads = 8
	case 2:
		params.Time = 8
		params.Memory = 512 * 1024
		params.Threads = 6
	case 3:
		params.Time = 5
		params.Memory = 256 * 1024
		params.Threads = 4
	default:
		params.Time = 8
		params.Memory = 512 * 1024
		params.Threads = 6
	}

	params.Len = 32
	params.Version = uint32(argon2.Version)
	params.Level = int32(level)

	return params
}

// create the KDF with argon and store in a secure memory buffer
func HashWithArgon(level int, password *memguard.LockedBuffer, salt []byte) (*memguard.LockedBuffer, error) {

	//control the params
	if len(password.Bytes()) == 0 || salt == nil || level > 3 || level < 1 {
		return nil, apperr.New("input are not correct")
	}

	//create params for use Argon2Id
	argonParams := CreateArgonParams(level)

	//create secure buffer, 32 byte AES-256 friendly
	passwordHashed := memguard.NewBuffer(32)

	kdf := argon2.IDKey(password.Bytes(), salt, argonParams.Time, argonParams.Memory, uint8(argonParams.Threads), argonParams.Len)
	copy(passwordHashed.Bytes(), kdf)

	//cleanup clear hash in memory
	memguard.WipeBytes(kdf)

	return passwordHashed, nil
}
