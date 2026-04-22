package encryption

import "github.com/awnumar/memguard"

//Create a memguard.LockedBuffer that contains the a string 
func Encaps(password string) (*memguard.LockedBuffer){
	pass := []byte(password)
	passwordLocked := memguard.NewBuffer(len(pass))
	copy(passwordLocked.Bytes(), pass)

	return passwordLocked
}