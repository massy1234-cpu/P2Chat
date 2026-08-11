package phases

const (
	Dummy             byte = 0x00
	RegisterTokenReq  byte = 0x01
	PowToken          byte = 0x02
	ChallengeResponse byte = 0x03
	SignatureRequest  byte = 0x04
	TokenEmission     byte = 0x05
)
