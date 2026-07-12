package encryption

import (
	"github.com/awnumar/memguard"
	"unsafe"
)

// Encaps copies a Go string into a memguard protected buffer - NOT clear
func Encaps(password string) *memguard.LockedBuffer {
	pass := []byte(password)
	passwordLocked := memguard.NewBuffer(len(pass))
	copy(passwordLocked.Bytes(), pass)

	return passwordLocked
}

// wipe the bytes manually 
func Wipe[T any](v *T) {
    b := unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v))
    memguard.WipeBytes(b)
}