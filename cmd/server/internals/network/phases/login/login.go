package login

import (
	"P2Chat/cmd/client/cirl-custom/circl/sign/mldsa/mldsa87"
	"P2Chat/cmd/client/internals/p2version"
	powproto "P2Chat/cmd/client/internals/proto_generated/PoW/proto_struct_pow"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	"P2Chat/cmd/server/database"
	idserver "P2Chat/cmd/server/internals/ID_server"
	mldsa "P2Chat/cmd/server/internals/keys/mldsa"
	x25519 "P2Chat/cmd/server/internals/keys/x25519"
	pow "P2Chat/cmd/server/internals/network/PoW"
	blind "P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/cmd/server/internals/network/dispatcher"
	"P2Chat/cmd/server/internals/network/phases"
	bundleproto "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/awnumar/memguard"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"google.golang.org/protobuf/proto"
	"time"
)

func init() {
	dispatcher.RegistryByteCode(phases.LoginAccessRequest, Handler)
	dispatcher.RegistryByteCode(phases.LoginTokenRequest, Handler)
}

type state uint8

var verificationSlots = make(chan struct{}, 4)

const (
	stateRequest state = iota
	stateAwaitPoW
	stateAwaitProof
	stateCompleted
)

type LoginServer struct {
	Binding      []byte
	Authenticate func([]byte, bool) error
	Level        pow.Level
	state        state
	secret       *memguard.Enclave
	challenge    *powproto.Challenge
	nonce        *loginproto.LoginNonce
	serverID     []byte
	token        *memguard.Enclave
	deadline     time.Time
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, invalid := phases.GetPhase[LoginServer](byteCode, msg, phaseState, CheckSize)
	if invalid != nil {
		return invalid
	}
	if currentState == nil || len(currentState.Binding) != 32 || currentState.Authenticate == nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("login requires connection context"))
	}
	if !currentState.deadline.IsZero() && time.Now().After(currentState.deadline) {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("login challenge expired"))
	}
	switch currentState.state {
	case stateRequest:
		return handleRequest(result, currentState, byteCode, msg)
	case stateAwaitPoW:
		return handlePoW(result, currentState, byteCode, msg)
	case stateAwaitProof:
		return handleProof(result, currentState, byteCode, msg)
	default:
		return phases.FillResult(result, nil, 0, false, true, apperr.New("login already completed"))
	}
}

func handleRequest(result *phases.Result, currentState *LoginServer, byteCode byte, msg []byte) *phases.Result {
	if byteCode == phases.LoginTokenRequest {
		select {
		case verificationSlots <- struct{}{}:
			defer func() { <-verificationSlots }()
		default:
			return phases.FillResult(result, nil, 0, false, true, apperr.New("login verification busy"))
		}
		defer memguard.WipeBytes(msg)
		token := &loginproto.LoginToken{}
		if err := proto.Unmarshal(msg, token); err != nil {
			return phases.FillResult(result, nil, 0, false, true, err)
		}
		defer memguard.WipeBytes(token.Message)
		if err := verifyToken(token); err != nil {
			// A stale token falls back to a fresh full login on a new stream.
			currentState.state = stateCompleted
			return phases.FillResult(result, [][]byte{{phases.LoginError}}, 0, true, false, nil)
		}
		currentState.token = memguard.NewEnclave(msg)
		return sendNonce(result, currentState)
	}
	if byteCode != phases.LoginAccessRequest {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid login start"))
	}
	level := currentState.Level
	if level == 0 {
		level = pow.Level5
	}
	secret := memguard.NewBufferRandom(32)
	challenge, err := pow.Issue(secret.Bytes(), level)
	currentState.secret = secret.Seal()
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	serialized, err := proto.Marshal(challenge)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	currentState.challenge = challenge
	currentState.deadline = time.Now().Add(level.MaxWaitTime())
	currentState.state = stateAwaitPoW
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginPowChallenge}, serialized...)}, level.MaxWaitTime(), false, false, nil)
}

func handlePoW(result *phases.Result, currentState *LoginServer, byteCode byte, msg []byte) *phases.Result {
	select {
	case verificationSlots <- struct{}{}:
		defer func() { <-verificationSlots }()
	default:
		return phases.FillResult(result, nil, 0, false, true, apperr.New("login verification busy"))
	}
	if byteCode != phases.LoginPowResponse || currentState.challenge == nil || currentState.secret == nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid login PoW response"))
	}
	secret, err := currentState.secret.Open()
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	defer secret.Destroy()
	currentState.secret = nil
	if !pow.Verify(secret.Bytes(), currentState.challenge, binary.BigEndian.Uint64(msg)) {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("login PoW failed"))
	}
	return sendNonce(result, currentState)
}

func sendNonce(result *phases.Result, currentState *LoginServer) *phases.Result {
	identity := idserver.GetCurrentID()
	if identity == nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("server identity not initialized"))
	}
	public := append(identity.PubMLDSA.Bytes(), identity.PubX25519.Bytes()...)
	id := sha256.Sum256(public)
	currentState.serverID = id[:]
	nonce := &loginproto.LoginNonce{Nonce: make([]byte, 32), Timestamp: time.Now().Unix(), Version: uint32(p2version.GetVersion())}
	if _, err := rand.Read(nonce.Nonce); err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	serialized, err := proto.Marshal(nonce)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	currentState.nonce = nonce
	currentState.state = stateAwaitProof
	currentState.deadline = time.Now().Add(30 * time.Second)
	return phases.FillResult(result, [][]byte{append([]byte{phases.LoginNonce}, serialized...)}, 30*time.Second, false, false, nil)
}

func handleProof(result *phases.Result, currentState *LoginServer, byteCode byte, msg []byte) *phases.Result {
	select {
	case verificationSlots <- struct{}{}:
		defer func() { <-verificationSlots }()
	default:
		return phases.FillResult(result, nil, 0, false, true, apperr.New("login verification busy"))
	}
	if byteCode != phases.LoginProof {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid login proof tag"))
	}
	proof := &loginproto.LoginProof{}
	if err := proto.Unmarshal(msg, proof); err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	if len(proof.BundleId) != 32 || len(proof.MldsaSignature) != mldsa87.SignatureSize || len(proof.X25519Signature) != 64 || proof.Version != currentState.nonce.Version || proof.Timestamp != currentState.nonce.Timestamp {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid login proof fields"))
	}
	if (currentState.token == nil && len(proof.Blinded) != 48) || (currentState.token != nil && len(proof.Blinded) != 0) {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid login blind request"))
	}
	stored, err := database.GetValue(proof.BundleId)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registered bundle not found"))
	}
	bundle := &bundleproto.BundleUploadPayload{}
	if err := proto.Unmarshal(stored, bundle); err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	if bundle.PublicBundle == nil {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("registered bundle is invalid"))
	}
	message := loginproto.SigningMessage(currentState.serverID, currentState.Binding, proof.BundleId, currentState.nonce, proof.Blinded)
	ok, err := mldsa.VerifySignature(bundle.PublicBundle.IkMldsa, message, nil, proof.MldsaSignature)
	if err != nil || !ok || !x25519.VerifySignature(bundle.PublicBundle.IkX25519, message, proof.X25519Signature) {
		return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid login identity signatures"))
	}
	reply := &loginproto.LoginResult{}
	tag := phases.LoginTokenAccepted
	if currentState.token != nil {
		opened, err := currentState.token.Open()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, err)
		}
		defer opened.Destroy()
		token := &loginproto.LoginToken{}
		if err := proto.Unmarshal(opened.Bytes(), token); err != nil {
			return phases.FillResult(result, nil, 0, false, true, err)
		}
		defer memguard.WipeBytes(token.Message)
		if err := verifyToken(token); err != nil {
			return phases.FillResult(result, [][]byte{{phases.LoginError}}, 0, true, false, nil)
		}
		remaining, err := database.ConsumeLoginToken(token.KeyHash, token.Message, proof.BundleId, token.ExpiresAt)
		if err != nil {
			return phases.FillResult(result, [][]byte{{phases.LoginError}}, 0, true, false, nil)
		}
		reply.RemainingUses = remaining
	} else {
		keys, err := blind.GetLoginKeys()
		if err != nil {
			return phases.FillResult(result, nil, 0, false, true, err)
		}
		var point bls.G1Affine
		if _, err := point.SetBytes(proof.Blinded); err != nil || point.IsInfinity() || !point.IsInSubGroup() {
			return phases.FillResult(result, nil, 0, false, true, apperr.New("invalid blinded login point"))
		}
		signed, _ := keys.Keys.Sk.SignBlind(&point)
		if signed == nil {
			return phases.FillResult(result, nil, 0, false, true, apperr.New("login token signature failed"))
		}
		sig := signed.Bytes()
		pk := keys.Keys.Pk.Y.Bytes()
		reply = &loginproto.LoginResult{BlindSignature: sig[:], PublicKey: pk[:], KeyHash: keys.Hash[:], ExpiresAt: keys.ExpiresAt, RemainingUses: 3}
		tag = phases.LoginToken
	}
	serialized, err := proto.Marshal(reply)
	if err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	if err := currentState.Authenticate(proof.BundleId, currentState.token == nil); err != nil {
		return phases.FillResult(result, nil, 0, false, true, err)
	}
	currentState.state = stateCompleted
	return phases.FillResult(result, [][]byte{append([]byte{tag}, serialized...)}, 0, true, false, nil)
}

func verifyToken(token *loginproto.LoginToken) error {
	if len(token.Message) != 64 || len(token.Signature) != 48 || len(token.KeyHash) != 32 {
		return apperr.New("invalid login token fields")
	}
	keys, err := blind.GetLoginKeys()
	if err != nil {
		return err
	}
	if token.ExpiresAt != keys.ExpiresAt || token.ExpiresAt <= time.Now().Unix() || !bytes.Equal(token.KeyHash, keys.Hash[:]) {
		return apperr.New("login token expired or unknown key")
	}
	var sig bls.G1Affine
	if _, err := sig.SetBytes(token.Signature); err != nil || sig.IsInfinity() || !sig.IsInSubGroup() {
		return apperr.New("invalid login token signature")
	}
	ok, err := blind.Verify(keys.Keys.Pk, token.Message, &sig)
	if err != nil || !ok {
		return apperr.New("login token signature rejected")
	}
	return nil
}

func CheckSize(tag byte, size int) bool {
	switch tag {
	case phases.LoginAccessRequest:
		return size == 0
	case phases.LoginPowResponse:
		return size == 8
	case phases.LoginProof:
		return size > 0 && size <= 8192
	case phases.LoginTokenRequest:
		return size > 0 && size <= 512
	default:
		return false
	}
}
