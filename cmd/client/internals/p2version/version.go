package p2version

var p2version uint8 = 1

func MagicByte() ([]byte) {
	magicByte := []byte("P2CH")
	v := []byte("1")
	magicByte = append(magicByte, v...)

	return magicByte
}

func GetVersion() uint8 {
	return p2version
}