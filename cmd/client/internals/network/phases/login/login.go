package login

import (
	blind "P2Chat/cmd/client/internals/network/blind_signature"
	"P2Chat/cmd/client/internals/network/phases"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	"P2Chat/pkg/apperr"
)

const (
	StartLogin          byte = 0xc1
	NotifyCompleted     byte = 0xc2
	NotifyTokenRejected byte = 0xc3
	Parameters          byte = 0xc4
	PassToken           byte = 0xc5
	PoWSolution         byte = 0xc6
	SignedProof         byte = 0xc7
	NotifyReady         byte = 0xc8
	NotifyPassToken     byte = 0xc9
	NotifySolvePoW      byte = 0xca
	NotifySignProof     byte = 0xcb
)

type state uint8

const (
	stateRequest state = iota
	stateAwaitParameters
	stateAwaitPassToken
	stateAwaitPoW
	stateAwaitSolution
	stateAwaitNonce
	stateAwaitSigned
	stateAwaitToken
	stateCompleted
	stateFailed
)

type LoginClient struct {
	state                       state
	binding, serverID, bundleID []byte
	blindStates                 []*blind.BlindState
	blinded                     [][]byte
	proof                       *loginproto.LoginProof
	fast                        bool
}

func Handler(byteCode byte, msg []byte, phaseState *any) *phases.Result {
	result := &phases.Result{}
	currentState, invalid := phases.GetPhase[LoginClient](byteCode, msg, phaseState, CheckSize)
	if invalid != nil {
		return invalid
	}
	if currentState == nil {
		currentState = &LoginClient{state: stateRequest}
		*phaseState = currentState
	}
	if byteCode == phases.LoginRejected && currentState.fast && currentState.state != stateCompleted {
		return handleRejected(result, currentState)
	}
	var phaseResult *phases.Result
	switch currentState.state {
	case stateRequest:
		phaseResult = handleStart(result, currentState, byteCode)
	case stateAwaitParameters:
		phaseResult = handleRequest(result, currentState, byteCode, msg)
	case stateAwaitPassToken:
		phaseResult = handlePassToken(result, currentState, byteCode, msg)
	case stateAwaitPoW:
		phaseResult = handlePoW(result, currentState, byteCode, msg)
	case stateAwaitSolution:
		phaseResult = handleSolution(result, currentState, byteCode, msg)
	case stateAwaitNonce:
		phaseResult = handleNonce(result, currentState, byteCode, msg)
	case stateAwaitSigned:
		phaseResult = handleSigned(result, currentState, byteCode, msg)
	case stateAwaitToken:
		phaseResult = handleToken(result, currentState, byteCode, msg)
	case stateCompleted:
		phaseResult = phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login already completed"))
	case stateFailed:
		phaseResult = phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login phase failed"))
	default:
		currentState.state = stateFailed
		phaseResult = phases.FillResult(result, nil, 0, false, true, nil, apperr.New("login reached an invalid state"))
	}
	if phaseResult.Err != nil {
		currentState.state = stateFailed
	}
	return phaseResult
}

func CheckSize(tag byte, size int) bool {
	switch tag {
	case StartLogin, phases.LoginRejected:
		return size == 0
	case Parameters:
		return size == 97
	case PassToken:
		return size > 0 && size <= 512
	case PoWSolution:
		return size == 8
	case SignedProof:
		return size > 0 && size <= 8192
	case phases.LoginPoWChallenge:
		return size >= 50 && size <= 128
	case phases.LoginChallengeNonce:
		return size >= 34 && size <= 128
	case phases.LoginTokenIssued:
		return size > 0 && size <= 1024
	case phases.LoginTokenRedeemed:
		return size == 0
	default:
		return false
	}
}
