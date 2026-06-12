package encryption

import "github.com/awnumar/memguard"

// Encaps copies a Go string into a memguard protected buffer - NOT clear
func Encaps(password string) *memguard.LockedBuffer {
	pass := []byte(password)
	passwordLocked := memguard.NewBuffer(len(pass))
	copy(passwordLocked.Bytes(), pass)

	return passwordLocked
}