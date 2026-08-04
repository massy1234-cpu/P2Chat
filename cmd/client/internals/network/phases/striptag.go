package phases

const (
	Dummy             			byte = 0x00		// client -> server
	RegisterTokenReq 			byte = 0x01		// client -> server
	PowToken          			byte = 0x02		// server -> client
	ChallengeResponse 			byte = 0x03		// client -> server
	SignatureRequest			byte = 0x04		// client -> server
	TokenEmission				byte = 0x05		// server -> client
)

func StripTag(msg []byte, expected byte) ([]byte, bool) {
	if len(msg) < 1 || msg[0] != expected {
		return nil, false
	}
	return msg[1:], true
}

// check the size of the payload in base of the type of the message
func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case Dummy:
		return payloadLen >= 1
	case RegisterTokenReq:
		return payloadLen == 0
	case PowToken:
		return payloadLen >= 56 && payloadLen <= 65
case ChallengeResponse:
		return payloadLen == 8
	case SignatureRequest:
		return payloadLen == 48
	case TokenEmission:
		return payloadLen == 48
	default:
		return false
	}
}