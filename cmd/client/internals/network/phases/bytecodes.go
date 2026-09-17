package phases

// registration bytecodes
const (
	DummyMessage                      byte = 0x00
	RegistrationStart                 byte = 0x01
	RegistrationPoWChallenge          byte = 0x02
	RegistrationPoWSolution           byte = 0x03
	RegistrationBlindSignatureRequest byte = 0x04
	RegistrationTokenIssued           byte = 0x05
	RegistrationPoWAccepted           byte = 0x06
	RegistrationRejected              byte = 0x07
)

// server identification bytecodes
const (
	ServerIdentityRequest  byte = 0x08
	ServerIdentityResponse byte = 0x09
)

// login bytecodes
const (
	LoginStart           byte = 0x0a
	LoginPoWChallenge    byte = 0x0b
	LoginPoWSolution     byte = 0x0c
	LoginChallengeNonce  byte = 0x0d
	LoginIdentityProof   byte = 0x0e
	LoginTokenIssued     byte = 0x0f
	LoginTokenRedemption byte = 0x10
	LoginTokenRedeemed   byte = 0x11
	LoginRejected        byte = 0x12
)

// bundle upload bytecodes (network, shared)
const (
	BundleRegistrationStart         byte = 0xa4
	BundleRegistrationTokenAccepted byte = 0xa5
	BundleNicknameRequest           byte = 0xa6
	BundleNicknameAvailability      byte = 0xa7
	BundleProofChallenge            byte = 0xaa
	BundleUpload                    byte = 0xa8
	BundleUploadAccepted            byte = 0xa9
)

// bundle request
const (
	BundleAcquisitionRequest      byte = 0xb1
	BundleAcquisitionResponse     byte = 0xb2
	BundleAcquisitionConfirmation byte = 0xb3
	BundleAvailabilityRequest     byte = 0xb4
	BundleAvailabilityResponse    byte = 0xb5
)
