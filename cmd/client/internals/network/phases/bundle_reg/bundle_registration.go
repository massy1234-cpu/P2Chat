package bundlereg

import (
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/p2log"
	powstruct "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	upload "P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"

	messagepack "github.com/vmihailenco/msgpack/v5"
	proto "google.golang.org/protobuf/proto"
)

// bytecodes to inject into the router with PutRouter()
const (
	RegistrationToken byte = 0xa1 // the registration token obtained from the token registration phase
	Nickname          byte = 0xa2 // the nickname chosen by the user
	Bundle            byte = 0xa3 // the bundle already prepared and ready in the chan
	SignedOriginalM   byte = 0xab // originalM signed by both identity keys (orchestrator)
)

// notification bytecodes emitted on the session Events chan to let the
// orchestrator know when to inject the next local event
const (
	NotifyTokenConfirmed byte = 0xb1 // server confirmed the token -> inject nickname
	NotifyNicknameReady  byte = 0xb2 // nickname chosen (available or not) -> orchestrator may act
	NotifySigned         byte = 0xb3 // challenge signed -> inject the bundle
	NotifyBundleUploaded byte = 0xb4 // bundle accepted by the server
)

// define the bundle registration phase states
type state uint8

const (
	stateAwaitToken              state = iota // client waits the RegistrationToken from the Local chan
	stateAwaitTokenConfirmation               // client waits the TokenConfirmation from the server
	stateAwaitNickname                        // client waits the Nickname from the Local chan
	stateAwaitNicknameResponse                // client waits the NicknameResponse from the server
	stateAwaitOriginalM                       // client waits the OriginalM from the server
	stateAwaitSigned                          // client waits the signed originalM from the Local chan
	stateAwaitBundle                          // client waits the Bundle from the Local chan
	stateAwaitBundleConfirmation              // client waits the BundleConfirmation from the server
	stateCompleted                            // process is completed
	stateFailed                               // process is not completed, some error occured
)

// this struct contains the only informations that must be saved for the bundle registration phase
type BundleClient struct {
	state     state
	tokenV    *powstruct.TokenVerification
	nickname  string
	originalM [32]byte
	sigMLDSA  []byte
	sigX25519 []byte
	payload   upload.BundleUploadPayload
}

func Handler(byteCode byte, msg []byte, state *any) *phases.Result {
	result := &phases.Result{}

	currentState, errResult := phases.GetPhase[BundleClient](byteCode, msg, state, CheckSize)
	if errResult != nil {
		return errResult
	}

	// not initialized yet -> create the right struct for this phase
	if currentState == nil {
		currentState = &BundleClient{state: stateAwaitToken}
		*state = currentState
	}

	switch currentState.state {

	case stateAwaitToken:
		return handleToken(result, currentState, byteCode, msg)

	case stateAwaitTokenConfirmation:
		return handleTokenConfirmation(result, currentState, byteCode, msg)

	case stateAwaitNickname:
		return handleNickname(result, currentState, byteCode, msg)

	case stateAwaitNicknameResponse:
		return handleNicknameResponse(result, currentState, byteCode, msg)

	case stateAwaitOriginalM:
		return handleOriginalM(result, currentState, byteCode, msg)

	case stateAwaitSigned:
		return handleSigned(result, currentState, byteCode, msg)

	case stateAwaitBundle:
		return handleBundle(result, currentState, byteCode, msg)

	case stateAwaitBundleConfirmation:
		return handleBundleConfirmation(result, currentState, byteCode, msg)

	case stateCompleted:
		p2log.Warning("bundle received a message after completion")
		return phases.FillResult(result, nil, 0, true, false, nil, nil)

	case stateFailed:
		p2log.Warning("bundle received a message after failure")
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle registration phase failed"))
	}

	return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle registration reached an invalid state"))
}

// handleToken receives the registration token from the Local chan and forwards
// it to the server to initialize the bundle upload.
func handleToken(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != RegistrationToken {
		p2log.Error("bundle received an invalid registration token")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid registration token"))
	}

	var tokenV powstruct.TokenVerification
	if err := proto.Unmarshal(msg, &tokenV); err != nil {
		p2log.Error("error decoding registration token", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("error decoding registration token", err))
	}
	if len(tokenV.GetToken()) != 48 {
		p2log.Error("registration token has an invalid size")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("registration token has an invalid size"))
	}
	currentState.tokenV = &tokenV
	currentState.state = stateAwaitTokenConfirmation
	p2log.Info("bundle registration token received, uploading the bundle request")

	// forward the whole TokenVerification (token + signature) to the server to initialize the bundle upload
	reply := append([]byte{phases.UploadBundleRequest}, msg...)
	return phases.FillResult(result, [][]byte{reply}, 0, false, false, nil, nil)
}

// handleTokenConfirmation checks the server confirmation about the token validity.
func handleTokenConfirmation(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.TokenConfirmation {
		p2log.Error("bundle received an invalid token confirmation")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid token confirmation"))
	}

	verified, err := decodeTokenConfirmation(msg)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}

	if !verified {
		p2log.Error("bundle registration token not verified by the server")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, [][]byte{[]byte("registration token not verified, cannot upload the bundle")}, apperr.New("registration token not verified"))
	}
	p2log.Info("bundle token verified, waiting for a nickname from the Local chan")
	currentState.state = stateAwaitNickname
	return phases.FillResult(result, nil, 0, false, false, [][]byte{{NotifyTokenConfirmed}}, nil)
}

// handleNickname receives the nickname from the Local chan and asks the server
// whether it is available.
func handleNickname(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != Nickname {
		p2log.Error("bundle received an invalid nickname")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid nickname"))
	}

	currentState.nickname = string(msg)
	currentState.state = stateAwaitNicknameResponse
	p2log.Info("bundle nickname chosen: ", currentState.nickname)

	// ask the server if the nickname is available
	reply := append([]byte{phases.NicknameRequest}, msg...)
	return phases.FillResult(result, [][]byte{reply}, 0, false, false, nil, nil)
}

// handleNicknameResponse handles the server availability reply, looping back to
// choose a new nickname if the requested one is taken.
func handleNicknameResponse(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.NicknameResponse {
		p2log.Error("bundle received an invalid nickname response")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid nickname response"))
	}

	available, err := decodeNicknameResponse(msg)
	if err != nil {
		p2log.Error("error decoding nickname response", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}

	var flag byte
	if available {
		p2log.Info("bundle nickname available: ", currentState.nickname)
		currentState.state = stateAwaitOriginalM
		flag = 1
	} else {
		p2log.Info("bundle nickname not available, waiting for a new one")
		currentState.state = stateAwaitNickname
		flag = 0
	}
	// notify the orchestrator whether the nickname was accepted, so it can pick
	// a new one or wait for the challenge
	return phases.FillResult(result, nil, 0, false, false, [][]byte{{NotifyNicknameReady, flag}}, nil)
}

// handleOriginalM saves the challenge (originalM) issued by the server and
// forwards it to the orchestrator (session Events) for signing with both identity keys.
func handleOriginalM(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.OriginalM {
		p2log.Error("bundle received an invalid challenge")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid challenge"))
	}

	currentState.originalM = [32]byte(msg)
	currentState.state = stateAwaitSigned
	p2log.Info("bundle challenge received, forwarding it to the orchestrator for signing")

	// send the challenge out; the orchestrator will sign it and inject the
	// signatures back through the Local chan (SignedOriginalM)
	return phases.FillResult(result, nil, 0, false, false, [][]byte{append([]byte(nil), currentState.originalM[:]...)}, nil)
}

// handleSigned receives the originalM signed by both identity keys from the
// Local chan and stores the signatures.
func handleSigned(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != SignedOriginalM {
		p2log.Error("bundle received an invalid signed challenge")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid signed challenge"))
	}

	sigMLDSA, sigX25519, err := UnpackSignatures(msg)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	currentState.sigMLDSA = sigMLDSA
	currentState.sigX25519 = sigX25519
	currentState.state = stateAwaitBundle
	p2log.Info("bundle challenge signed, waiting for the bundle from the Local chan")
	return phases.FillResult(result, nil, 0, false, false, [][]byte{{NotifySigned}}, nil)
}

// handleBundle builds the upload payload, adds the signatures already produced
// by the orchestrator and sends the bundle to the server.
func handleBundle(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != Bundle {
		p2log.Error("bundle received an invalid bundle payload")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid bundle payload"))
	}

	bundle, err := decodeBundle(msg)
	if err != nil {
		p2log.Error("error decoding bundle payload", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}

	currentState.payload.PublicBundle = bundle.GetPublicBundle()
	currentState.payload.CurvePublicSets = bundle.GetCurvePublicSets()
	currentState.payload.KemPublicSets = bundle.GetKemPublicSets()

	currentState.payload.Nickname = currentState.nickname
	currentState.payload.PrivateKeySignMLDSA = currentState.sigMLDSA
	currentState.payload.PrivateKeySignX25519 = currentState.sigX25519

	currentState.state = stateAwaitBundleConfirmation
	p2log.Info("bundle prepared, uploading it to the server")

	serialized, err := proto.Marshal(&currentState.payload)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.Wrap("error serializing bundle payload", err))
	}
	reply := append([]byte{phases.BundleUpload}, serialized...)
	return phases.FillResult(result, [][]byte{reply}, 0, false, false, nil, nil)
}

// handleBundleConfirmation handles the final server confirmation.
func handleBundleConfirmation(result *phases.Result, currentState *BundleClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.BundleConfirmation {
		p2log.Error("bundle received an invalid confirmation")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("bundle received an invalid confirmation"))
	}

	valid, err := decodeBundleConfirmation(msg)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}

	if !valid {
		p2log.Error("bundle not accepted by the server")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, [][]byte{[]byte("bundle not accepted by the server")}, apperr.New("bundle not accepted by the server"))
	}

	currentState.state = stateCompleted
	p2log.Info("bundle upload confirmed by the server")
	return phases.FillResult(result, nil, 0, true, false, [][]byte{{NotifyBundleUploaded}}, nil)
}

// decodeTokenConfirmation decodes the server response about the token verification.
func decodeTokenConfirmation(payload []byte) (bool, error) {
	if len(payload) < 1 {
		return false, apperr.New("token confirmation received with invalid size")
	}
	return payload[0] == 1, nil
}

// decodeNicknameResponse decodes the server response about the nickname availability.
func decodeNicknameResponse(payload []byte) (bool, error) {
	if len(payload) < 1 {
		return false, apperr.New("nickname response received with invalid size")
	}
	return payload[0] == 1, nil
}

// decodeBundleConfirmation decodes the server response about the bundle validity.
func decodeBundleConfirmation(payload []byte) (bool, error) {
	if len(payload) < 1 {
		return false, apperr.New("bundle confirmation received with invalid size")
	}
	return payload[0] == 1, nil
}

// Signatures carries the two identity-key signatures over originalM, exchanged
// between the orchestrator and the bundle handler through the Local chan.
type Signatures struct {
	MLDSA  []byte `msgpack:"mldsa"`
	X25519 []byte `msgpack:"x25519"`
}

// PackSignatures serializes the two signatures so the orchestrator can inject
// them into the router via the Local chan.
func PackSignatures(sigMLDSA, sigX25519 []byte) ([]byte, error) {
	payload, err := messagepack.Marshal(&Signatures{MLDSA: sigMLDSA, X25519: sigX25519})
	if err != nil {
		return nil, apperr.Wrap("error serializing signatures", err)
	}
	return payload, nil
}

// UnpackSignatures deserializes the signatures received on the Local chan.
func UnpackSignatures(payload []byte) (sigMLDSA, sigX25519 []byte, err error) {
	var sig Signatures
	if err := messagepack.Unmarshal(payload, &sig); err != nil {
		return nil, nil, apperr.Wrap("error deserializing signatures", err)
	}
	return sig.MLDSA, sig.X25519, nil
}

// decodeBundle unmarshals the bundle upload payload (PublicBundle + sets) received from the Local chan.
func decodeBundle(bundle []byte) (*upload.BundleUploadPayload, error) {
	var p upload.BundleUploadPayload
	if err := proto.Unmarshal(bundle, &p); err != nil {
		return nil, apperr.Wrap("error unmarshalling bundle payload", err)
	}
	return &p, nil
}

// check the size of the payload in base of the type of the message
// every phase has a CheckSize but is different for the bytecodes checked
func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case phases.Dummy:
		return payloadLen >= 1
	case RegistrationToken:
		return payloadLen >= 1
	case Nickname:
		return payloadLen >= 1
	case Bundle:
		return payloadLen >= 1
	case SignedOriginalM:
		return payloadLen >= 2
	case phases.UploadBundleRequest:
		return payloadLen >= 1
	case phases.TokenConfirmation:
		return payloadLen == 1
	case phases.NicknameRequest:
		return payloadLen >= 1
	case phases.NicknameResponse:
		return payloadLen == 1
	case phases.OriginalM:
		return payloadLen == 32
	case phases.BundleUpload:
		return payloadLen >= 1
	case phases.BundleConfirmation:
		return payloadLen == 1
	default:
		return false
	}
}
