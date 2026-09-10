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

// ---server identification---
const (
	ServerIdentificationRequest  byte = 0x08
	ServerIdentificationResponse byte = 0x09
)

// login bytecodes
const (
	LoginAccessRequest byte = 0x0a
	LoginPowChallenge  byte = 0x0b
	LoginPowResponse   byte = 0x0c
	LoginNonce         byte = 0x0d
	LoginProof         byte = 0x0e
	LoginToken         byte = 0x0f
	LoginTokenRequest  byte = 0x10
	LoginTokenAccepted byte = 0x11
	LoginError         byte = 0x12
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
