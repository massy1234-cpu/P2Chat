package phases

// token registration bytecodes
const (
	Dummy             byte = 0x00
	RegisterTokenReq  byte = 0x01
	PowToken          byte = 0x02
	ChallengeResponse byte = 0x03
	SignatureRequest  byte = 0x04
	TokenEmission     byte = 0x05
	PoWVerified       byte = 0x06
	RegistrationError byte = 0x07
)

// bundle upload bytecodes (network, shared)
const (
	UploadBundleRequest byte = 0xa4
	TokenConfirmation   byte = 0xa5
	NicknameRequest     byte = 0xa6
	NicknameResponse    byte = 0xa7
	BundleUpload        byte = 0xa8
	BundleConfirmation  byte = 0xa9
	OriginalM           byte = 0xaa
)