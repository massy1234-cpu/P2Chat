package phases

const (
	Dummy             			byte = 0x00		// client -> server
	RegisterTokenReq 			byte = 0x01		// client -> server
	PowToken          			byte = 0x02		// server -> client
	ChallengeResponse 			byte = 0x03		// client -> server
	SignatureRequest			byte = 0x04		// client -> server
	TokenEmission				byte = 0x05		// server -> client
)