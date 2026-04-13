package argon

import (
	"fmt"
	pb "P2Chat/cmd/client/internals/gen/mldsapb"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)


func argon2Params(level int)(*pb.ArgonParams){

 	params := &pb.ArgonParams{}

	switch(level){
	case 1: 
		params.Time = 10
		params.Memory = 1024*1024
		params.Threads = 8
	case 2:
		params.Time = 8
		params.Memory = 512*1024
		params.Threads = 6
	case 3:
		params.Time = 5
		params.Memory = 256*1024
		params.Threads = 4
	default:
		params.Time = 8
		params.Memory = 512*1024
		params.Threads = 6
	}

	params.Len = 32
	params.Version = uint32(argon2.Version)
	params.Level = int32(level)

	return params
}


func HashWithArgon(level int, password *memguard.LockedBuffer, salt []byte) (*memguard.LockedBuffer, error){

	//create params for use Argon2Id
	argonParams := argon2Params(level)


	//create secure buffer
	passwordHashed := memguard.NewBuffer(32)

	hash := argon2.IDKey(password.Bytes(), salt, argonParams.Time, argonParams.Memory, uint8(argonParams.Threads), argonParams.Len )
	copy(passwordHashed.Bytes(), hash)

	//cleanup hash in memory
	memguard.WipeBytes(hash)

	return passwordHashed, nil
}