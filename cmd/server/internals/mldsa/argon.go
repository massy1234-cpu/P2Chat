package mldsa

import (
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

type ArgonParams struct {
	time    uint32
	memory  uint32
	threads uint8
	len     uint32
}

func argon2Params(level int) *ArgonParams {

	var params ArgonParams

	switch level {
	case 1:
		params.time = 10
		params.len = 32
		params.memory = 1024 * 1024
		params.threads = 8
	case 2:
		params.time = 8
		params.len = 32
		params.memory = 512 * 1024
		params.threads = 6
	case 3:
		params.time = 5
		params.len = 32
		params.memory = 256 * 1024
		params.threads = 4
	default:
		params.time = 8
		params.len = 32
		params.memory = 512 * 1024
		params.threads = 6
	}

	return &params
}

func hashWithArgon(level int, password *memguard.LockedBuffer, salt []byte) (*memguard.LockedBuffer, error) {

	//create params for use Argon2Id
	argonParams := argon2Params(level)

	//create secure buffer
	passwordHashed := memguard.NewBuffer(32)

	hash := argon2.IDKey(password.Bytes(), salt, argonParams.time, argonParams.memory, argonParams.threads, argonParams.len)
	copy(passwordHashed.Bytes(), hash)

	//cleanup hash in memory
	memguard.WipeBytes(hash)

	return passwordHashed, nil
}
