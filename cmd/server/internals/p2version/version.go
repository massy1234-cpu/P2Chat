package p2version

func MagicByte() []byte {
	magicByte := []byte("P2CH")
	v := []byte("1")
	magicByte = append(magicByte, v...)

	return magicByte
}
