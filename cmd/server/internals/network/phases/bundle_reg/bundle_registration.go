package bundlereceive

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/database"
	PQXDH "P2Chat/cmd/server/internals/PQXDH"
	mldsa_keys "P2Chat/cmd/server/internals/keys/mldsa"
	x25519_keys "P2Chat/cmd/server/internals/keys/x25519"
	blindsignature "P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/cmd/server/internals/network/dispatcher"
	"P2Chat/cmd/server/internals/network/phases"
	powstruct "P2Chat/cmd/server/internals/proto_generated/PoW/proto_struct_pow"
	upload "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"errors"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/dgraph-io/badger/v4"
	proto "google.golang.org/protobuf/proto"
)

// register the bundle registration phase handler for the UploadBundleRequest bytecode
func init() {
	dispatcher.RegistryByteCode(phases.BundleRegistrationStart, Handler)
}

type state uint8

const (
	stateTokenCheck    state = iota // server received UploadBundleRequest, checks the token
	stateAwaitNickname              // server waits a NicknameRequest
	stateAwaitBundle                // server sent originalM, waits a BundleUpload
	stateCompleted
	stateFailed
)

// BundleServer keeps the data required by one bundle registration flow.
type BundleServer struct {
	state       state
	tokenVer    bool
	nickname    string
	nicknameVer bool
	idUser      [32]byte
	originalM   [32]byte
	payload     upload.UserBundle
}

func Handler(byteCode byte, msg []byte, state *any) *phases.Result {
	result := &phases.Result{}

	currentState, errResult := phases.GetPhase[BundleServer](byteCode, msg, state, CheckSize)
	if errResult != nil {
		return errResult
	}

	// not initialized yet -> create the right struct for this phase
	if currentState == nil {
		currentState = &BundleServer{state: stateTokenCheck}
		*state = currentState
	}

	switch currentState.state {
	case stateTokenCheck:
		return handleTokenCheck(result, currentState, byteCode, msg)

	case stateAwaitNickname:
		return handleNickname(result, currentState, byteCode, msg)

	case stateAwaitBundle:
		return handleBundle(result, currentState, byteCode, msg)

	case stateCompleted:
		p2log.Warning("bundle received a message after completion")
		return phases.FillResult(result, nil, 0, true, false, nil)

	case stateFailed:
		p2log.Warning("bundle received a message after failure")
		return phases.FillResult(result, nil, 0, false, true, apperr.New("bundle registration phase failed"))
	}

	return phases.FillResult(result, nil, 0, false, false, nil)
}

// handleTokenCheck validates the registration token carried by the
// UploadBundleRequest, ensuring it is a valid, non-reused blind signature.
func handleTokenCheck(result *phases.Result, currentState *BundleServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.BundleRegistrationStart {
		p2log.Error("invalid bundle upload request")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle upload request"))
	}

	p2log.Info("Verify the token...")

	tokenScheme := &powstruct.TokenVerification{}
	if err := proto.Unmarshal(msg, tokenScheme); err != nil {
		p2log.Error("invalid token verification payload")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid token verification payload"))
	}

	token, err := decodeToken(tokenScheme.GetToken())
	if err != nil {
		p2log.Error("invalid token in verification payload")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid token in verification payload"))
	}

	signature := tokenScheme.GetSignature()
	if signature == nil || len(signature.GetHashPk()) == 0 {
		p2log.Error("token verification payload misses the signing key fingerprint")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("token verification payload misses the signing key fingerprint"))
	}

	// check the current key or in the database
	pk := blindsignature.GetPublicKeyByHash(signature.GetHashPk())
	if pk == nil {
		p2log.Error("no signing key matching the fingerprint")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("no signing key matching the fingerprint"))
	}

	ok, err := blindsignature.Verify(pk, tokenScheme.GetM(), token)
	if err != nil {
		p2log.Error("error verifying the registration token", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error verifying the registration token", err))
	}
	if !ok {
		p2log.Error("registration token verification failed")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration token verification failed"))
	}
	p2log.Info("Token verified ! ✅")

	currentState.tokenVer = true

	notUsed, err := blindsignature.SerializeAndSave(token)
	if err != nil {
		p2log.Error("error saving the registration token", err)
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error saving the registration token", err))
	}
	if !notUsed {
		p2log.Error("registration token already used")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registration token already used"))
	}

	// confirm the token to the client and wait for the nickname request
	currentState.state = stateAwaitNickname
	return phases.FillResult(result, [][]byte{append([]byte{phases.BundleRegistrationTokenAccepted}, 1)}, 0, false, false, nil)
}

// handleNickname reserves the requested nickname atomically; if available it
// issues originalM and moves on to the bundle wait, otherwise it asks for a
// new nickname.
func handleNickname(result *phases.Result, currentState *BundleServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.BundleNicknameRequest {
		p2log.Error("invalid nickname request")
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid nickname request"))
	}

	nickname, err := decodeNickname(msg)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error decoding nickname", err))
	}
	currentState.nickname = nickname

	taken, err := database.CheckAndReserve(nickname)
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error reserving nickname", err))
	}

	currentState.nicknameVer = !taken

	// nickname taken -> ask for a new one, stay in the same state
	if taken {
		p2log.Info("nickname not available: ", nickname)
		return phases.FillResult(result, [][]byte{append([]byte{phases.BundleNicknameAvailability}, 0)}, 0, false, false, nil)
	}

	// nickname available and reserved -> send originalM and wait for the bundle
	originalM, err := generateOriginalM()
	if err != nil {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.Wrap("error generating originalM", err))
	}
	currentState.originalM = originalM
	currentState.state = stateAwaitBundle
	p2log.Info("nickname available: ", nickname, ", originalM issued")

	return phases.FillResult(result, [][]byte{
		append([]byte{phases.BundleNicknameAvailability}, 1),
		append([]byte{phases.BundleProofChallenge}, originalM[:]...),
	}, 0, false, false, nil)
}

// handleOriginalM decodes the uploaded bundle, checks that the ID matches the
// public identity keys and that both identity signatures over originalM are
// valid, then accepts or rejects the bundle.
func handleBundle(result *phases.Result, currentState *BundleServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.BundleUpload {
		currentState.state = stateFailed
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid bundle upload"))
	}

	bundle, err := decodeBundle(msg)
	if err != nil {
		return bundleReject(result, currentState, apperr.Wrap("error decoding bundle", err))
	}

	currentState.payload.PublicBundle = bundle.GetPublicBundle()
	currentState.payload.CurvePublicSets = bundle.GetCurvePublicSets()
	currentState.payload.KemPublicSets = bundle.GetKemPublicSets()
	currentState.payload.Nickname = bundle.GetNickname()

	currentState.idUser = PQXDH.HashPublicIK(bundle.GetPublicBundle())
	if _, err := database.GetValue(currentState.idUser[:]); err == nil {
		return bundleReject(result, currentState, apperr.New("bundle ID already exists"))
	} else if !errors.Is(err, badger.ErrKeyNotFound) {
		return bundleReject(result, currentState, apperr.Wrap("error checking bundle ID", err))
	}

	// verify that the two identity-key signatures over originalM are valid ( user bundle validation )
	originalMsg := currentState.originalM[:]
	okMLDSA, err := mldsa_keys.VerifySignature(bundle.GetPublicBundle().GetIkMldsa(), originalMsg, nil, bundle.GetPrivateKeySignMLDSA())
	if err != nil {
		return bundleReject(result, currentState, apperr.Wrap("error verifying the ML-DSA identity signature", err))
	}
	if !okMLDSA {
		return bundleReject(result, currentState, apperr.New("invalid ML-DSA identity signature"))
	}

	if !x25519_keys.VerifySignature(bundle.GetPublicBundle().GetIkX25519(), originalMsg, bundle.GetPrivateKeySignX25519()) {
		return bundleReject(result, currentState, apperr.New("invalid X25519 identity signature"))
	}

	p2log.Info("bundle decoded and identity signatures verified, proceed with the bundle storage into the database")

	// save the bundle into the database
	if err := database.SaveBundle(bundle, currentState.idUser, []byte(currentState.nickname)); err != nil {
		if delErr := database.DeleteAllAssociation(bundle, currentState.idUser, []byte(currentState.nickname)); delErr != nil {
			p2log.Error("error deleting bundle associations: ", delErr)
		}
		return bundleReject(result, currentState, apperr.Wrap("error saving bundle", err))
	}

	currentState.state = stateCompleted
	return phases.FillResult(result, [][]byte{append([]byte{phases.BundleUploadAccepted}, 1)}, 0, true, false, nil)
}

// bundleReject releases the reserved nickname, marks the state as failed and
// sends a negative BundleConfirmation to the client.
func bundleReject(result *phases.Result, currentState *BundleServer, err error) *phases.Result {
	if delErr := database.DeleteNickname(currentState.nickname); delErr != nil {
		p2log.Error("error deleting the reserved nickname: ", delErr)
	}
	currentState.state = stateFailed
	return phases.FillResult(result, [][]byte{append([]byte{phases.BundleUploadAccepted}, 0)}, 0, false, true, err)
}

// generateOriginalM returns 32 random bytes used as the challenge the client
// must sign with both identity keys.
func generateOriginalM() ([32]byte, error) {
	var r [32]byte
	_, err := rand.Read(r[:])
	if err != nil {
		return [32]byte{}, apperr.Wrap("error in the OriginalM creation", err)
	}
	return r, nil
}

// check the size of the payload in base of the type of the message
func CheckSize(tag byte, payloadLen int) bool {
	switch tag {
	case phases.DummyMessage:
		return payloadLen >= 1
	case phases.BundleRegistrationStart:
		return payloadLen >= 1
	case phases.BundleRegistrationTokenAccepted:
		return payloadLen == 1
	case phases.BundleNicknameRequest:
		return payloadLen >= 1
	case phases.BundleNicknameAvailability:
		return payloadLen == 1
	case phases.BundleProofChallenge:
		return payloadLen == 32
	case phases.BundleUpload:
		return payloadLen >= 1
	case phases.BundleUploadAccepted:
		return payloadLen == 1
	default:
		return false
	}
}

// decodeToken decodes the registration token (48B compressed G1).
func decodeToken(payload []byte) (*bls.G1Affine, error) {
	var point bls.G1Affine
	if _, err := point.SetBytes(payload); err != nil {
		return nil, apperr.Wrap("error during token conversion", err)
	}
	return &point, nil
}

// decodeNickname decodes the nickname chosen by the client.
func decodeNickname(payload []byte) (string, error) {
	return string(payload), nil
}

// decodeBundle unmarshals the bundle upload payload (PublicBundle + sets).
func decodeBundle(payload []byte) (*upload.UserBundle, error) {
	var p upload.UserBundle
	if err := proto.Unmarshal(payload, &p); err != nil {
		return nil, apperr.Wrap("error unmarshalling bundle payload", err)
	}
	return &p, nil
}
