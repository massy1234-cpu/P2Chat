package version

func Version() (int){
	return 1
}

func MagicByte()([]byte){
	magicByte := []byte("P2CH")
	magicByte = append(magicByte, byte(Version()) )

	return magicByte
}