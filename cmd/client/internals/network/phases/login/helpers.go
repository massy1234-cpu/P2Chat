package login

import (
	"P2Chat/cmd/client/internals/keys/mldsa"
	blind "P2Chat/cmd/client/internals/network/blind_signature"
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/p2version"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	serverblind "P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/sha256"
	"github.com/awnumar/memguard"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"google.golang.org/protobuf/proto"
	"time"
)

func handleStart(result *phases.Result, current *LoginClient, tag byte) *phases.Result {
	if tag != StartLogin {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login start"))
	}
	current.state = stateAwaitParameters
	return phases.FillResult(result, nil, 30*time.Second, false, false, [][]byte{{NotifyReady}}, nil)
}

func handleRequest(result *phases.Result, current *LoginClient, tag byte, msg []byte) *phases.Result {
	if tag != Parameters || msg[96] > 1 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login parameters"))
	}
	current.binding = append([]byte(nil), msg[:32]...)
	current.serverID = append([]byte(nil), msg[32:64]...)
	current.bundleID = append([]byte(nil), msg[64:96]...)
	current.fast = msg[96] == 1

	if current.fast {
		current.state = stateAwaitPassToken
		return phases.FillResult(result, nil, 30*time.Second, false, false, [][]byte{{NotifyPassToken}}, nil)
	}
	request := &loginproto.LoginBlindRequest{}
	for range 3 {
		state, point, err := blind.CreateAndBlind()
		if err != nil {
			wipeBlindStates(current)
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		current.blindStates = append(current.blindStates, state)
		encoded := point.Bytes()
		blinded := append([]byte(nil), encoded[:]...)
		current.blinded = append(current.blinded, blinded)
		request.Blinded = append(request.Blinded, blinded)
	}
	serialized, err := proto.Marshal(request)
	if err != nil {
		wipeBlindStates(current)
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	current.state = stateAwaitPoW
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginStart}, serialized...)}, 30*time.Second, false, false, nil, nil)
}

func handlePassToken(result *phases.Result, current *LoginClient, tag byte, msg []byte) *phases.Result {
	defer memguard.WipeBytes(msg)
	if tag != PassToken {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid local login token"))
	}
	token := &loginproto.LoginToken{}
	if err := proto.Unmarshal(msg, token); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	defer memguard.WipeBytes(token.Message)
	defer memguard.WipeBytes(token.Signature)
	if !bytes.Equal(token.ServerId, current.serverID) {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login token belongs to another server"))
	}
	current.state = stateAwaitToken
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginTokenRedemption}, msg...)}, 30*time.Second, false, false, nil, nil)
}

func handlePoW(result *phases.Result, current *LoginClient, tag byte, msg []byte) *phases.Result {
	if tag != phases.LoginPoWChallenge {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login PoW challenge"))
	}
	if _, err := decodeChallenge(msg); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	current.state = stateAwaitSolution
	return phases.FillResult(result, nil, 10*time.Minute, false, false, [][]byte{append([]byte{NotifySolvePoW}, msg...)}, nil)
}

func handleSolution(result *phases.Result, current *LoginClient, tag byte, msg []byte) *phases.Result {
	if tag != PoWSolution {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid local PoW solution"))
	}
	current.state = stateAwaitNonce
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginPoWSolution}, msg...)}, 30*time.Second, false, false, nil, nil)
}

func handleNonce(result *phases.Result, current *LoginClient, tag byte, msg []byte) *phases.Result {
	if tag != phases.LoginChallengeNonce {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login nonce tag"))
	}
	nonce := &loginproto.LoginNonce{}
	if err := proto.Unmarshal(msg, nonce); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if len(nonce.Nonce) != 32 || nonce.Version != uint32(p2version.GetVersion()) || nonce.Timestamp <= 0 || len(current.blindStates) != 3 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login nonce"))
	}
	proof := &loginproto.LoginProof{BundleId: current.bundleID, Timestamp: nonce.Timestamp, Version: nonce.Version, Blinded: current.blinded}
	current.proof = proof
	message := loginproto.SigningMessage(current.serverID, current.binding, current.bundleID, nonce, current.blinded)
	current.state = stateAwaitSigned
	return phases.FillResult(result, nil, 30*time.Second, false, false, [][]byte{append([]byte{NotifySignProof}, message...)}, nil)
}

func handleSigned(result *phases.Result, current *LoginClient, tag byte, msg []byte) *phases.Result {
	if tag != SignedProof || current.proof == nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid signed login proof"))
	}
	signatures := &loginproto.LoginProof{}
	if err := proto.Unmarshal(msg, signatures); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if len(signatures.MldsaSignature) != mldsa_keys.SignatureSize || len(signatures.X25519Signature) != 64 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login signatures"))
	}
	current.proof.MldsaSignature = signatures.MldsaSignature
	current.proof.X25519Signature = signatures.X25519Signature
	serialized, err := proto.Marshal(current.proof)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	current.state = stateAwaitToken
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginIdentityProof}, serialized...)}, 30*time.Second, false, false, nil, nil)
}

func handleToken(result *phases.Result, currentState *LoginClient, byteCode byte, msg []byte) *phases.Result {
	if currentState.fast {
		if byteCode != phases.LoginTokenRedeemed || len(msg) != 0 {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid fast login response"))
		}
		currentState.state = stateCompleted
		p2log.Info("anonymous pass-token login completed")
		return phases.FillResult(result, nil, 0, true, false, [][]byte{{NotifyCompleted}}, nil)
	}
	defer wipeBlindStates(currentState)
	reply := &loginproto.LoginResult{}
	if err := proto.Unmarshal(msg, reply); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if byteCode != phases.LoginTokenIssued || len(currentState.blindStates) != 3 || len(reply.BlindSignatures) != 3 || len(reply.PublicKey) != 96 || len(reply.KeyHash) != 32 || reply.ExpiresAt <= time.Now().Unix() {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login token emission"))
	}
	hash := sha256.Sum256(reply.PublicKey)
	if !bytes.Equal(hash[:], reply.KeyHash) {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login public key hash mismatch"))
	}
	public, err := serverblind.NewPublicKey(reply.PublicKey)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login public key"))
	}
	batch := &loginproto.LoginTokenBatch{}
	for i, blindSignature := range reply.BlindSignatures {
		var point bls.G1Affine
		if _, err := point.SetBytes(blindSignature); err != nil || point.IsInfinity() || !point.IsInSubGroup() {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login blind signature"))
		}
		sig := currentState.blindStates[i].Unblind(&point)
		ok, err := serverblind.Verify(public, currentState.blindStates[i].Msg, &sig)
		if err != nil || !ok {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login token verification failed"))
		}
		encoded := sig.Bytes()
		batch.Tokens = append(batch.Tokens, &loginproto.LoginToken{Message: currentState.blindStates[i].Msg, Signature: encoded[:], KeyHash: reply.KeyHash, ExpiresAt: reply.ExpiresAt, ServerId: currentState.serverID})
	}
	serialized, err := proto.Marshal(batch)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	currentState.state = stateCompleted
	p2log.Info("full PoW login completed; three anonymous pass tokens issued")
	event := append([]byte{NotifyCompleted}, serialized...)
	memguard.WipeBytes(serialized)
	return phases.FillResult(result, nil, 0, true, false, [][]byte{event}, nil)
}

func EncodeParameters(binding, serverID, bundleID []byte, fast bool) ([]byte, error) {
	if len(binding) != 32 || len(serverID) != 32 || len(bundleID) != 32 {
		return nil, apperr.New("invalid login parameters")
	}
	data := append([]byte(nil), binding...)
	data = append(data, serverID...)
	data = append(data, bundleID...)
	if fast {
		return append(data, 1), nil
	}
	return append(data, 0), nil
}

func wipeBlindStates(current *LoginClient) {
	for _, state := range current.blindStates {
		if state != nil {
			memguard.WipeBytes(state.Msg)
		}
	}
	current.blindStates = nil
	current.blinded = nil
}

func handleRejected(result *phases.Result, current *LoginClient) *phases.Result {
	current.state = stateFailed
	return phases.FillResult(result, nil, 0, true, false, [][]byte{{NotifyTokenRejected}}, nil)
}
