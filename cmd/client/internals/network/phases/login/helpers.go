package login

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
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

	// check if the pass token is present for fast login
	if current.fast {
		current.state = stateAwaitPassToken
		return phases.FillResult(result, nil, 30*time.Second, false, false, [][]byte{{NotifyPassToken}}, nil)
	}
	current.state = stateAwaitPoW
	return phases.FillResult(result, [][]byte{{phases.LoginStart}}, 30*time.Second, false, false, nil, nil)
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
	if !bytes.Equal(token.ServerId, current.serverID) {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login token belongs to another server"))
	}
	current.state = stateAwaitNonce
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
	if len(nonce.Nonce) != 32 || nonce.Version != uint32(p2version.GetVersion()) || nonce.Timestamp <= 0 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login nonce"))
	}
	proof := &loginproto.LoginProof{BundleId: current.bundleID, Timestamp: nonce.Timestamp, Version: nonce.Version}
	if !current.fast {
		st, point, err := blind.CreateAndBlind()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		current.blindState = st
		encoded := point.Bytes()
		proof.Blinded = encoded[:]
	}
	current.proof = proof
	message := loginproto.SigningMessage(current.serverID, current.binding, current.bundleID, nonce, proof.Blinded)
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
	if len(signatures.MldsaSignature) != mldsa87.SignatureSize || len(signatures.X25519Signature) != 64 {
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
	var tokenBytes []byte
	reply := &loginproto.LoginResult{}
	if err := proto.Unmarshal(msg, reply); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if currentState.fast {
		if byteCode != phases.LoginTokenRedeemed || reply.RemainingUses > 2 {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid fast login response"))
		}
	} else {
		if byteCode != phases.LoginTokenIssued || currentState.blindState == nil || len(reply.BlindSignature) != 48 || len(reply.PublicKey) != 96 || len(reply.KeyHash) != 32 || reply.RemainingUses != 3 || reply.ExpiresAt <= time.Now().Unix() {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login token emission"))
		}
		hash := sha256.Sum256(reply.PublicKey)
		if !bytes.Equal(hash[:], reply.KeyHash) {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login public key hash mismatch"))
		}
		var point bls.G1Affine
		var public serverblind.PublicKey
		if _, err := point.SetBytes(reply.BlindSignature); err != nil || point.IsInfinity() || !point.IsInSubGroup() {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login blind signature"))
		}
		if _, err := public.Y.SetBytes(reply.PublicKey); err != nil || public.Y.IsInfinity() || !public.Y.IsInSubGroup() {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login public key"))
		}
		sig := currentState.blindState.Unblind(&point)
		ok, err := serverblind.Verify(&public, currentState.blindState.Msg, &sig)
		if err != nil || !ok {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login token verification failed"))
		}
		encoded := sig.Bytes()
		token := &loginproto.LoginToken{Message: currentState.blindState.Msg, Signature: encoded[:], KeyHash: reply.KeyHash, ExpiresAt: reply.ExpiresAt, ServerId: currentState.serverID}
		serialized, err := proto.Marshal(token)
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		tokenBytes = serialized
		memguard.WipeBytes(currentState.blindState.Msg)
		currentState.blindState = nil
	}
	currentState.state = stateCompleted
	p2log.Info("login completed; token uses remaining: ", reply.RemainingUses)
	event := append([]byte{NotifyCompleted, byte(reply.RemainingUses)}, tokenBytes...)
	memguard.WipeBytes(tokenBytes)
	return phases.FillResult(result, nil, 0, true, false, [][]byte{event}, nil)
}

func handleRejected(result *phases.Result, current *LoginClient) *phases.Result {
	current.state = stateFailed
	return phases.FillResult(result, nil, 0, true, false, [][]byte{{NotifyTokenRejected}}, nil)
}
