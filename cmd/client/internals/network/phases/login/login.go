package login

import (
	mldsa "P2Chat/cmd/client/internals/keys/mldsa"
	x25519 "P2Chat/cmd/client/internals/keys/x25519"
	pow "P2Chat/cmd/client/internals/network/PoW"
	blind "P2Chat/cmd/client/internals/network/blind_signature"
	"P2Chat/cmd/client/internals/network/phases"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/p2version"
	powproto "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	serverblind "P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/pkg/apperr"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"github.com/awnumar/memguard"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"google.golang.org/protobuf/proto"
	"time"
)

type state uint8

const (
	stateRequest state = iota
	stateAwaitPoW
	stateAwaitNonce
	stateAwaitToken
	stateCompleted
)

type LoginClient struct {
	Binding, ServerID, BundleID []byte
	MLDSA, X25519               *memguard.Enclave
	Token                       *memguard.Enclave
	Context                     context.Context
	SaveToken                   func(*memguard.Enclave)
	state                       state
	blindState                  *blind.BlindState
	fast                        bool
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, invalid := phases.GetPhase[LoginClient](byteCode, msg, phaseState, CheckSize)
	if invalid != nil {
		return invalid
	}
	if currentState == nil || len(currentState.Binding) != 32 || len(currentState.ServerID) != 32 || len(currentState.BundleID) != 32 || currentState.MLDSA == nil || currentState.X25519 == nil || currentState.SaveToken == nil {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid client login context"))
	}
	if byteCode == phases.LoginError && currentState.fast && currentState.state != stateCompleted {
		currentState.state = stateCompleted
		return phases.FillResult(result, nil, 0, true, false, [][]byte{{0}}, nil)
	}
	switch currentState.state {
	case stateRequest:
		return handleRequest(result, currentState, byteCode, msg)
	case stateAwaitPoW:
		return handlePoW(result, currentState, byteCode, msg)
	case stateAwaitNonce:
		return handleNonce(result, currentState, byteCode, msg)
	case stateAwaitToken:
		return handleToken(result, currentState, byteCode, msg)
	default:
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login already completed"))
	}
}

func handleRequest(result *phases.Result, currentState *LoginClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.LoginAccessRequest {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login start"))
	}
	if currentState.Token != nil {
		opened, err := currentState.Token.Open()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		defer opened.Destroy()
		token := &loginproto.LoginToken{}
		if err := proto.Unmarshal(opened.Bytes(), token); err != nil {
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		defer memguard.WipeBytes(token.Message)
		if !bytes.Equal(token.ServerId, currentState.ServerID) {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login token belongs to another server"))
		}
		reply := append([]byte{phases.LoginTokenRequest}, opened.Bytes()...)
		currentState.fast = true
		currentState.state = stateAwaitNonce
		return phases.FillResult(result, [][]byte{reply}, 30*time.Second, false, false, nil, nil)
	}
	currentState.state = stateAwaitPoW
	return phases.FillResult(result, [][]byte{{phases.LoginAccessRequest}}, 30*time.Second, false, false, nil, nil)
}

func handlePoW(result *phases.Result, currentState *LoginClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.LoginPowChallenge {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login PoW challenge"))
	}
	challenge := &powproto.Challenge{}
	if err := proto.Unmarshal(msg, challenge); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if challenge.Level < 1 || challenge.Level > 5 || len(challenge.Salt) != 16 || len(challenge.Mac) != 32 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid PoW parameters"))
	}
	ctx := currentState.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	p2log.Info("solving access PoW, level: ", challenge.Level)
	nonce, err := pow.SolveContext(ctx, challenge)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	reply := binary.BigEndian.AppendUint64([]byte{phases.LoginPowResponse}, nonce)
	currentState.state = stateAwaitNonce
	return phases.FillResult(result, [][]byte{reply}, 30*time.Second, false, false, nil, nil)
}

func handleNonce(result *phases.Result, currentState *LoginClient, byteCode byte, msg []byte) *phases.Result {
	if byteCode != phases.LoginNonce {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login nonce tag"))
	}
	nonce := &loginproto.LoginNonce{}
	if err := proto.Unmarshal(msg, nonce); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if len(nonce.Nonce) != 32 || nonce.Version != uint32(p2version.GetVersion()) || nonce.Timestamp <= 0 {
		return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid login nonce"))
	}
	proof := &loginproto.LoginProof{BundleId: currentState.BundleID, Timestamp: nonce.Timestamp, Version: nonce.Version}
	if !currentState.fast {
		st, point, err := blind.CreateAndBlind()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		currentState.blindState = st
		encoded := point.Bytes()
		proof.Blinded = encoded[:]
	}
	message := loginproto.SigningMessage(currentState.ServerID, currentState.Binding, currentState.BundleID, nonce, proof.Blinded)
	var err error
	proof.MldsaSignature, err = mldsa.Sign(currentState.MLDSA, message, nil, false)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	proof.X25519Signature, err = x25519.Sign(currentState.X25519, message)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	serialized, err := proto.Marshal(proof)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	currentState.state = stateAwaitToken
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginProof}, serialized...)}, 30*time.Second, false, false, nil, nil)
}

func handleToken(result *phases.Result, currentState *LoginClient, byteCode byte, msg []byte) *phases.Result {
	reply := &loginproto.LoginResult{}
	if err := proto.Unmarshal(msg, reply); err != nil {
		return phases.FillResult(result, nil, 0, false, true, nil, err)
	}
	if currentState.fast {
		if byteCode != phases.LoginTokenAccepted || reply.RemainingUses > 2 {
			return phases.FillResult(result, nil, 0, false, true, nil, apperr.New("invalid fast login response"))
		}
		if reply.RemainingUses == 0 {
			currentState.SaveToken(nil)
		} else {
			currentState.SaveToken(currentState.Token)
		}
	} else {
		if byteCode != phases.LoginToken || currentState.blindState == nil || len(reply.BlindSignature) != 48 || len(reply.PublicKey) != 96 || len(reply.KeyHash) != 32 || reply.RemainingUses != 3 || reply.ExpiresAt <= time.Now().Unix() {
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
		token := &loginproto.LoginToken{Message: currentState.blindState.Msg, Signature: encoded[:], KeyHash: reply.KeyHash, ExpiresAt: reply.ExpiresAt, ServerId: currentState.ServerID}
		serialized, err := proto.Marshal(token)
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, nil, err)
		}
		currentState.SaveToken(memguard.NewEnclave(serialized))
		memguard.WipeBytes(serialized)
		memguard.WipeBytes(currentState.blindState.Msg)
		currentState.blindState = nil
	}
	currentState.state = stateCompleted
	p2log.Info("login completed; token uses remaining: ", reply.RemainingUses)
	return phases.FillResult(result, nil, 0, true, false, [][]byte{{1}}, nil)
}

func CheckSize(tag byte, size int) bool {
	switch tag {
	case phases.LoginAccessRequest, phases.LoginError:
		return size == 0
	case phases.LoginPowChallenge:
		return size >= 50 && size <= 128
	case phases.LoginNonce:
		return size >= 34 && size <= 128
	case phases.LoginToken:
		return size > 0 && size <= 512
	case phases.LoginTokenAccepted:
		return size <= 32
	default:
		return false
	}
}
