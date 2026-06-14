package argon

import (
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"runtime"
)

// Create the struct that contain the correct parameters for argon
func CreateArgonParams(level int) *struct_mldsa.ArgonParams {

	params := &struct_mldsa.ArgonParams{}

	switch level {
	case 3: 										// High security, high computation but use a lot of resources  
		params.Time = 6
		params.Memory = 1024 * 1024
	case 2: 										// General use 
		params.Time = 4
		params.Memory = 256 * 1024
	case 1: 										// For device with computational power
		params.Time = 3
		params.Memory = 128 * 1024
	default:
		params.Time = 3
		params.Memory = 128 * 1024
	}

	// setting universal parameters 
	params.Threads = uint32(runtime.NumCPU())
	params.Len = 32
	params.Version = uint32(argon2.Version)
	params.Level = int32(level)

	return params
}

// create the KDF with argon and store the outout in a mlock() memory buffer using memguard
func HashWithArgon(level int, password *memguard.LockedBuffer, salt []byte) (*memguard.LockedBuffer, error) {

	// control cases 
	if password == nil {
		return nil, apperr.New("password null")
	}

	if len(password.Bytes()) == 0 {
		return nil, apperr.New("password lenght 0")
	}

	if salt == nil {
		return nil, apperr.New("salt is null")
	}

	if len(salt) == 0 {
		return nil, apperr.New("salt lenght is zero")
	}

	if level > 3 || level < 1 {
		return nil, apperr.New("level not valid")
	}

	// create params for use Argon2Id
	argonParams := CreateArgonParams(level)

	// create the KDF 
	kdf := argon2.IDKey(password.Bytes(), salt, argonParams.Time, argonParams.Memory, uint8(argonParams.Threads), argonParams.Len)
	passwordHashed := memguard.NewBufferFromBytes(kdf)

	// cleanup kdf
	memguard.WipeBytes(kdf)

	// return the locked buffer 
	return passwordHashed, nil
}
