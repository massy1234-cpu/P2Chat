package main

import (
	"P2Chat/cmd/client/database"
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
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
	proto "google.golang.org/protobuf/proto"
)

// The CLI verifies the server and logs in with its saved bundle association.
// New users register explicitly with -nickname before their first login.
func main() {
	address := flag.String("server", "151.64.120.32", "server address")
	port := flag.Int("port", 9000, "server port")
	nickname := flag.String("nickname", "", "nickname for a new registration")
	localBundle := flag.Int("bundle", -1, "existing local bundle number to log in with")
	flag.Parse()
	if err := database.Init(); err != nil {
		p2log.Error("error initializing the client database: ", err)
		return
	}
	defer database.CloseDB()

	password, err := readPassword()
	if err != nil {
		p2log.Error("error reading bundle password: ", err)
		return
	}
	connManager, binding, err := bootstrap.InitializeServerConn(*address, *port)
	if err != nil {
		p2log.Error("error initializing the server connection: ", err)
		return
	}
	defer connManager.Close()
	go connManager.CheckConnection()

	go p2chat_errors.Watchdog(connManager)

	identityEvents, err := connManager.Conn.ServerIdentification(binding)
	if err != nil {
		p2log.Error("error during server identification: ", err)
		return
	}
	if identity := readData(identityEvents); identity == nil {
		p2log.Error("server identification failed, connection lost or timeout")
		return
	}
	p2log.Info("server identification completed")
	knownBundle, err := database.LoadLoginBundle(connManager.Conn.ServerID)
	if err != nil {
		p2log.Error("load registered login bundle: ", err)
		return
	}
	if *localBundle >= 0 {
		knownBundle = &database.LoginBundle{LocalID: *localBundle}
	}
	if knownBundle != nil {
		loginToken, err := connManager.Conn.Login(binding, knownBundle, password, nil)
		if err != nil {
			p2log.Error("login failed: ", err)
			return
		}
		p2log.Info("authenticated connection ready; login token available: ", loginToken != nil)
		connManager.LoginToken = loginToken
		<-connManager.Done
		return
	}
	if *nickname == "" {
		p2log.Error("no registered bundle for this server; use -nickname for registration or -bundle to select existing keys")
		return
	}

	// start the token registration phase; the token arrives on the session Events
	tokenEvents, err := connManager.Conn.TokenRegistration()
	if err != nil {
		p2log.Error("error during the token registration phase: ", err)
		return
	}

	// read the token received
	token := readData(tokenEvents)
	if token == nil {
		p2log.Error("no token received, connection lost or timeout")
		return
	}
	p2log.Info("token received from the token registration phase")

	// Initialize the bundle PQXDH after obtaining the registration token
	publicBundle, curveSets, kemSets, err := pqxdh.InitializePQXDH(password, 1, false, storage.BasePath, 2)
	if err != nil {
		p2log.Error("error creating the PQXDH bundle: ", err)
		return
	}
	ikID := int(publicBundle.GetId())

	// start the bundle upload phase and get its session + Events chan
	bundleSess, bundleEvents, err := connManager.Conn.UploadBundle()
	if err != nil {
		p2log.Error("error during the bundle upload phase: ", err)
		return
	}

	// inject the token into the bundle handler (local bytecode RegistrationToken)
	bundleSess.PutRouter(bundlereg.RegistrationToken, token)

	// wait for the token confirmation, then inject the chosen nickname
	if ok, _ := waitNotify(bundleEvents, bundlereg.NotifyTokenConfirmed); !ok {
		p2log.Error("token not confirmed by the server, aborting")
		return
	}
	bundleSess.PutRouter(bundlereg.Nickname, []byte(*nickname))

	// wait for the nickname result (must be available), then the originalM
	ok, flag := waitNotify(bundleEvents, bundlereg.NotifyNicknameReady)
	if !ok || flag != 1 {
		p2log.Error("nickname not accepted by the server")
		return
	}
	p2log.Info("nickname accepted, waiting for the originalM challenge")

	// the challenge is the next binary data on the bundle Events chan
	originalM := readData(bundleEvents)
	if originalM == nil {
		p2log.Error("no originalM challenge received, connection lost or timeout")
		return
	}
	p2log.Info("originalM challenge received, signing it with the IK keys")

	if err := signAndInject(bundleSess, password, ikID, originalM); err != nil {
		p2log.Error("error signing originalM: ", err)
		return
	}

	// wait for the "signed" notification, then inject the bundle
	if ok, _ := waitNotify(bundleEvents, bundlereg.NotifySigned); !ok {
		p2log.Error("bundle signing not acknowledged, aborting")
		return
	}
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
	if ok, _ := waitNotify(bundleEvents, bundlereg.NotifyBundleUploaded); !ok {
		p2log.Error("bundle not confirmed by the server, aborting")
		return
	}
	p2log.Info("bundle uploaded and verified by the server")
	h1, h2 := sha256.Sum256(publicBundle.IkX25519), sha256.Sum256(publicBundle.IkMldsa)
	id := sha256.Sum256(append(h1[:], h2[:]...))
	registered := &database.LoginBundle{LocalID: ikID, BundleID: id[:]}
	if err := database.SaveLoginBundle(connManager.Conn.ServerID, registered); err != nil {
		p2log.Error("save registered login bundle: ", err)
		return
	}
	loginToken, err := connManager.Conn.Login(binding, registered, password, nil)
	if err != nil {
		p2log.Error("login failed: ", err)
		return
	}
	p2log.Info("authenticated connection ready; login token available: ", loginToken != nil)
	connManager.LoginToken = loginToken
	<-connManager.Done
}

// readPassword reads the bundle password without terminal echo and seals it.
func readPassword() (*memguard.Enclave, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("standard input is not a terminal")
	}
	fmt.Print("Bundle password (32 bytes): ")
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		memguard.WipeBytes(input)
		return nil, err
	}
	if len(input) != 32 {
		memguard.WipeBytes(input)
		return nil, fmt.Errorf("bundle password must be 32 bytes")
	}
	buffer := memguard.NewBufferFromBytes(input)
	memguard.WipeBytes(input)
	return buffer.Seal(), nil
}

// readData blocks until a binary data message (non-notification) is available
// on a session Events chan. It returns nil if the channel is closed (the
// connection is gone) or on timeout.
func readData(events <-chan []byte) []byte {
	for {
		select {
		case msg, ok := <-events:
			if !ok {
				p2log.Error("events channel closed, connection lost")
				return nil
			}
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
// returns (true, firstPayloadByte) on success, or (false, 0) if the channel is
// closed (connection gone) or on timeout.
func waitNotify(events <-chan []byte, bytecode byte) (bool, byte) {
	for {
		select {
		case msg, ok := <-events:
			if !ok {
				p2log.Error("events channel closed, connection lost")
				return false, 0
			}
			if len(msg) >= 1 && msg[0] == bytecode {
				if len(msg) > 1 {
					return true, msg[1]
				}
				return true, 0
			}
		case <-time.After(2 * time.Minute):
			return false, 0
		}
	}
}

// isNotification reports whether an Events message is a notification
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

	// pack the signatures into a serialized struct for the bundle handler
	packed, err := bundlereg.PackSignatures(sigMLDSA, sigX25519)
	if err != nil {
		return apperr.Wrap("error packing the signatures", err)
	}

	bundleSess.PutRouter(bundlereg.SignedOriginalM, packed)
	return nil
}
