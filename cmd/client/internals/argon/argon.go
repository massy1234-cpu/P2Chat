package argon

import (
	argonStruct "P2Chat/cmd/client/internals/proto_generated/argon/argon_params"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"runtime"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

// Create the protoc struct 'argon_params' that contain the correct parameters for argon
func CreateArgonParams(level int) *argonStruct.ArgonParams {

	params := &argonStruct.ArgonParams{}

	switch level {
	case 3: // High security, high computation but use a lot of resources
		params.Time = 6
		params.Memory = 1024 * 1024
	case 2: // General use
		params.Time = 4
		params.Memory = 256 * 1024
	case 1: // For device with computational power
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
func HashWithArgon(level int, password *memguard.Enclave) (*memguard.LockedBuffer, *argonStruct.ArgonParams, error) {
	if level > 3 || level < 1 {
		return nil, nil, apperr.New("level not valid")
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, apperr.Wrap("generate salt", err)
	}

	passwordHashed, err := DeriveWithArgon(level, password, salt)
	if err != nil {
		return nil, nil, err
	}

	argonParams := CreateArgonParams(level)
	argonParams.Salt = salt

	return passwordHashed, argonParams, nil
}

func HashUsingParams(password *memguard.Enclave, params *argonStruct.ArgonParams) (*memguard.LockedBuffer, error) {
	if password == nil {
		return nil, apperr.New("password null")
	}
	if params == nil {
		return nil, apperr.New("argon params is nil")
	}

	salt := params.GetSalt()
	if len(salt) == 0 {
		return nil, apperr.New("salt is empty")
	}
	if params.GetTime() == 0 || params.GetMemory() == 0 || params.GetThreads() == 0 || params.GetLen() == 0 {
		return nil, apperr.New("invalid argon params")
	}

	passwordBuffer, err := password.Open()
	if err != nil {
		return nil, apperr.Wrap("open password enclave", err)
	}
	defer passwordBuffer.Destroy()

	if len(passwordBuffer.Bytes()) == 0 {
		return nil, apperr.New("password length 0")
	}

	kdf := argon2.IDKey(passwordBuffer.Bytes(), salt, params.GetTime(), params.GetMemory(), uint8(params.GetThreads()), params.GetLen())
	passwordHashed := memguard.NewBufferFromBytes(kdf)
	memguard.WipeBytes(kdf)

	return passwordHashed, nil
}

func DeriveWithArgon(level int, password *memguard.Enclave, salt []byte) (*memguard.LockedBuffer, error) {

	// control cases
	if password == nil {
		return nil, apperr.New("password null")
	}

	passwordBuffer, err := password.Open()
	if err != nil {
		return nil, apperr.Wrap("open password enclave", err)
	}
	defer passwordBuffer.Destroy()

	if len(passwordBuffer.Bytes()) == 0 {
		return nil, apperr.New("password lenght 0")
	}

	if len(salt) == 0 {
		return nil, apperr.New("salt is empty")
	}

	if level > 3 || level < 1 {
		return nil, apperr.New("level not valid")
	}

	// create params for use Argon2Id
	argonParams := CreateArgonParams(level)

	// create the KDF
	kdf := argon2.IDKey(passwordBuffer.Bytes(), salt, argonParams.Time, argonParams.Memory, uint8(argonParams.Threads), argonParams.Len)
	passwordHashed := memguard.NewBufferFromBytes(kdf)

	// cleanup kdf
	memguard.WipeBytes(kdf)

	return passwordHashed, nil
}
