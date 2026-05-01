package argon

import (
	pb "P2Chat/cmd/client/internals/gen/mldsa/mldsapb"
	"P2Chat/pkg/apperr"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"runtime"
)

// Create the struct that contain the correct params for argon derivation func
func CreateArgonParams(level int) *pb.ArgonParams {

	params := &pb.ArgonParams{}

	switch level {
	case 3: // Alta sicurezz
		params.Time    = 6
		params.Memory  = 1024 * 1024  // 1 GB
	case 2: // Uso generale
		params.Time    = 4
		params.Memory  = 256 * 1024  // 256 MB
	case 1: // Dispositivi limitati
		params.Time    = 3
		params.Memory  = 128 * 1024   // 128 MB
	default:
		params.Time    = 3
		params.Memory  = 128 * 1024 
	}

	params.Threads = uint32(runtime.NumCPU())
	params.Len = 32
	params.Version = uint32(argon2.Version)
	params.Level = int32(level)

	return params
}

// create the KDF with argon and store in a secure memory buffer
func HashWithArgon(level int, password *memguard.LockedBuffer, salt []byte) (*memguard.LockedBuffer, error) {

	//params controls
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
