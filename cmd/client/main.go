package main

import (
	"P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/network/bootstrap"
	bundlereg "P2Chat/cmd/client/internals/network/phases/bundle_reg"
	"P2Chat/cmd/client/internals/network/session"
	"P2Chat/cmd/client/internals/p2chat_errors"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/cmd/client/internals/protocol/pqxdh"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"time"

	"github.com/awnumar/memguard"
	proto "google.golang.org/protobuf/proto"
)

// orchestration stub: connects, runs the token registration and the bundle
// upload phases end to end (no HSM). It creates a fresh PQXDH bundle, signs
// originalM with the IK keys and injects the local events into the bundle
// session following the GlobalOut notifications. In the future this logic moves
// to a dedicated orchestrator.
func main() {
	connManager, err := bootstrap.InitializeServerConn("151.64.101.30", 9000)
	if err != nil {
		p2log.Error("error initializing the server connection: ", err)
		return
	}
	defer connManager.Close()

	go p2chat_errors.Watchdog(connManager)

	// password enclave for the IK keys (Argon2-protected, no HSM here)
	password := makePassword()

	// create a fresh PQXDH bundle and the one-time public sets
	publicBundle, curveSets, kemSets, err := pqxdh.InitializePQXDH(password, 1, false, storage.BasePath, 2)
	if err != nil {
		p2log.Error("error creating the PQXDH bundle: ", err)
		return
	}
	ikID := int(publicBundle.GetId())

	// start the token registration phase; the token arrives on GlobalOut
	if err := connManager.Conn.TokenRegistration(); err != nil {
		p2log.Error("error during the token registration phase: ", err)
		return
	}

	token := readData(connManager.GlobalOut)
	p2log.Info("token received from the token registration phase")

	// start the bundle upload phase and get its session
	bundleSess, err := connManager.Conn.BundleUpload()
	if err != nil {
		p2log.Error("error during the bundle upload phase: ", err)
		return
	}

	// inject the token into the bundle handler (local bytecode RegistrationToken)
	bundleSess.PutRouter(bundlereg.RegistrationToken, token)

	// wait for the token confirmation, then inject the chosen nickname
	waitNotify(connManager.GlobalOut, bundlereg.NotifyTokenConfirmed)
	bundleSess.PutRouter(bundlereg.Nickname, []byte("p2chat_user"))

	// wait for the nickname result (must be available), then the originalM
	flag := waitNotify(connManager.GlobalOut, bundlereg.NotifyNicknameReady)
	if flag != 1 {
		p2log.Error("nickname not accepted by the server")
		return
	}
	p2log.Info("nickname accepted, waiting for the originalM challenge")

	// the challenge is the next binary data on GlobalOut
	originalM := readData(connManager.GlobalOut)
	p2log.Info("originalM challenge received, signing it with the IK keys")

	if err := signAndInject(bundleSess, password, ikID, originalM); err != nil {
		p2log.Error("error signing originalM: ", err)
		return
	}

	// wait for the "signed" notification, then inject the bundle
	waitNotify(connManager.GlobalOut, bundlereg.NotifySigned)
	uploadPayload := &proto_struct_bundle.BundleUploadPayload{
		PublicBundle:    publicBundle,
		CurvePublicSets: curveSets,
		KemPublicSets:   kemSets,
	}
	uploadBytes, err := proto.Marshal(uploadPayload)
	if err != nil {
		p2log.Error("error serializing the bundle payload: ", err)
		return
	}
	bundleSess.PutRouter(bundlereg.Bundle, uploadBytes)

	// wait for the final confirmation
	waitNotify(connManager.GlobalOut, bundlereg.NotifyBundleUploaded)
	p2log.Info("bundle uploaded and verified by the server")

	time.Sleep(2 * time.Second)
	connManager.Close()
}

// makePassword returns a random 32-byte key sealed in a memguard enclave.
func makePassword() *memguard.Enclave {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	return memguard.NewEnclave(key)
}

// readData blocks until a binary data message (non-notification) is available
// on GlobalOut.
func readData(globalOut <-chan []byte) []byte {
	for {
		select {
		case msg := <-globalOut:
			if isNotification(msg) {
				p2log.Warning("skipping unexpected notification")
				continue
			}
			return msg
		case <-time.After(2 * time.Minute):
			return nil
		}
	}
}

// waitNotify blocks until a notification with the given bytecode arrives and
// returns its first payload byte.
func waitNotify(globalOut <-chan []byte, bytecode byte) byte {
	for {
		select {
		case msg := <-globalOut:
			if len(msg) >= 1 && msg[0] == bytecode {
				if len(msg) > 1 {
					return msg[1]
				}
				return 0
			}
		case <-time.After(2 * time.Minute):
			return 0
		}
	}
}

// isNotification reports whether a GlobalOut message is a notification
// (first byte is one of the Notify* bytecodes) rather than binary data.
func isNotification(msg []byte) bool {
	if len(msg) == 0 {
		return true
	}
	switch msg[0] {
	case bundlereg.NotifyTokenConfirmed,
		bundlereg.NotifyNicknameReady,
		bundlereg.NotifySigned,
		bundlereg.NotifyBundleUploaded:
		return true
	}
	return false
}

// signAndInject loads the IK private keys, signs originalM with both of them
// and injects the packed signatures into the bundle session.
func signAndInject(bundleSess *session.SingleSession, password *memguard.Enclave, ikID int, originalM []byte) error {
	ikMLDSA, _, ikX25519, err := pqxdh.LoadIKKeys(password, storage.BasePath, ikID)
	if err != nil {
		return apperr.Wrap("error loading the IK keys", err)
	}

	sigMLDSA, err := mldsa_keys.Sign(ikMLDSA, originalM, nil, false)
	if err != nil {
		return apperr.Wrap("error signing with ML-DSA", err)
	}
	sigX25519, err := x25519.Sign(ikX25519, originalM)
	if err != nil {
		return apperr.Wrap("error signing with X25519", err)
	}

	// pack the signatures: [1B lenMLDSA][MLDSA][X25519] (see unpackSignatures)
	packed := append([]byte{byte(len(sigMLDSA))}, sigMLDSA...)
	packed = append(packed, sigX25519...)

	bundleSess.PutRouter(bundlereg.SignedOriginalM, packed)
	return nil
}
