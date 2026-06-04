package encryption

import "github.com/awnumar/memguard"

// Encaps copies a Go string into a memguard protected buffer - NOT clear
func Encaps(password string) *memguard.LockedBuffer {
	pass := []byte(password)
	passwordLocked := memguard.NewBuffer(len(pass))
	copy(passwordLocked.Bytes(), pass)

	return passwordLocked
}

// ReturnCopy returns an ordinary byte-slice copy of a protected buffer.
func ReturnCopy(message *memguard.LockedBuffer, lenght int) []byte {
	var plain []byte

	if lenght != 0 {
		plain = make([]byte, lenght)
	} else {
		plain = make([]byte, len(message.Bytes()))
	}

	copy(plain, message.Bytes())

	return plain
}
