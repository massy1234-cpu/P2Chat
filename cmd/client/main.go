package main

import (
	"P2Chat/cmd/client/database"
	"P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/network/bootstrap"
	"P2Chat/cmd/client/internals/network/connection"
	"P2Chat/cmd/client/internals/network/phases"
	bundlereg "P2Chat/cmd/client/internals/network/phases/bundle_reg"
	getuserbundle "P2Chat/cmd/client/internals/network/phases/get_user_bundle"
	"P2Chat/cmd/client/internals/network/phases/login"
	"P2Chat/cmd/client/internals/network/session"
	"P2Chat/cmd/client/internals/p2chat_errors"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/cmd/client/internals/protocol/pqxdh"
	"P2Chat/cmd/client/internals/storage"
	serverbundle "P2Chat/cmd/server/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/pkg/apperr"
	"bufio"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"
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
	requestedNickname := flag.String("get-nickname", "", "nickname whose bundle to retrieve and optionally store")
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
		loginToken, err := runLogin(connManager, binding, knownBundle, password)
		if err != nil {
			p2log.Error("login failed: ", err)
			return
		}
		p2log.Info("authenticated connection ready; login token available: ", loginToken != nil)
		connManager.LoginToken = loginToken
		if err := requestAndStoreUserBundle(connManager.Conn, *requestedNickname); err != nil {
			p2log.Error("user bundle request failed: ", err)
			return
		}
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
	uploadPayload := &proto_struct_bundle.UserBundle{
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
	loginToken, err := runLogin(connManager, binding, registered, password)
	if err != nil {
		p2log.Error("login failed: ", err)
		return
	}
	p2log.Info("authenticated connection ready; login token available: ", loginToken != nil)
	connManager.LoginToken = loginToken
	if err := requestAndStoreUserBundle(connManager.Conn, *requestedNickname); err != nil {
		p2log.Error("user bundle request failed: ", err)
		return
	}
	<-connManager.Done
}

// requestAndStoreUserBundle keeps bundle acquisition in the main orchestrator:
// it checks availability, asks the user for consent, downloads the bundle, and
// stores it under the authenticated server identity.
func requestAndStoreUserBundle(conn *connection.Connection, nickname string) error {
	if nickname == "" {
		return nil
	}

	availabilitySess, availabilityEvents, err := conn.CheckBundleAvailability()
	if err != nil {
		return err
	}
	availabilitySess.PutRouter(getuserbundle.AvailabilityNickname, []byte(nickname))
	availability := readData(availabilityEvents)
	if len(availability) != 2 || availability[0] != phases.BundleAvailabilityResponse {
		return apperr.New("invalid bundle availability response")
	}
	if availability[1] == 0 {
		p2log.Info("nickname not found on this server: ", nickname)
		return nil
	}

	if !confirmBundleStorage(nickname) {
		p2log.Info("user bundle download declined: ", nickname)
		return nil
	}

	bundleSess, bundleEvents, err := conn.GetUserBundle()
	if err != nil {
		return err
	}
	bundleSess.PutRouter(getuserbundle.AcquisitionNickname, []byte(nickname))
	serialized := readData(bundleEvents)
	if serialized == nil {
		return apperr.New("user bundle was not received")
	}

	bundle := &serverbundle.UserBundle{}
	if err := proto.Unmarshal(serialized, bundle); err != nil {
		return apperr.Wrap("decode received user bundle", err)
	}
	if err := database.SaveUserBundle(bundle, conn.ServerID); err != nil {
		return apperr.Wrap("save received user bundle", err)
	}
	p2log.Info("user bundle saved for nickname: ", nickname)
	return nil
}

func confirmBundleStorage(nickname string) bool {
	fmt.Printf("Download and save the bundle for %q? [y/N]: ", nickname)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

// runLogin orchestrates login events; identification is completed separately.
func runLogin(manager *connection.ConnectionManager, binding []byte, bundle *database.LoginBundle, password *memguard.Enclave) (*memguard.Enclave, error) {
	keys, err := login.LoadIdentity(bundle, password)
	if err != nil {
		return nil, err
	}
	token := manager.LoginToken
	for attempt := 0; attempt < 2; attempt++ {
		parameters, err := login.EncodeParameters(binding, manager.Conn.ServerID, keys.BundleID, token != nil)
		if err != nil {
			return nil, err
		}
		sess, events, err := manager.Conn.Login()
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-sess.Done:
				cancel()
			case <-ctx.Done():
			}
		}()
		next, retry, err := waitLogin(ctx, manager, sess, events, keys, parameters, token)
		cancel()
		if err != nil {
			sess.ForceClose()
			return nil, err
		}
		if retry {
			token = nil
			manager.LoginToken = nil
			continue
		}
		registered := &database.LoginBundle{LocalID: bundle.LocalID, BundleID: keys.BundleID}
		if err := database.SaveLoginBundle(manager.Conn.ServerID, registered); err != nil {
			return nil, err
		}
		return next, nil
	}
	return nil, apperr.New("login token rejected")
}

func waitLogin(ctx context.Context, manager *connection.ConnectionManager, sess *session.SingleSession, events <-chan []byte, keys *login.Credentials, parameters []byte, token *memguard.Enclave) (*memguard.Enclave, bool, error) {
	timer := time.NewTimer(11 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-events:
			if !ok || len(event) == 0 {
				return nil, false, apperr.New("login failed; check phase logs")
			}
			switch event[0] {
			case login.NotifyReady:
				sess.PutRouter(login.Parameters, parameters)
			case login.NotifyPassToken:
				if token == nil {
					return nil, false, apperr.New("missing login token")
				}
				opened, err := token.Open()
				if err != nil {
					return nil, false, err
				}
				sess.PutRouter(login.PassToken, opened.Bytes())
				opened.Destroy()
			case login.NotifySolvePoW:
				solution, err := login.SolveChallenge(ctx, event[1:])
				if err != nil {
					return nil, false, err
				}
				sess.PutRouter(login.PoWSolution, solution)
			case login.NotifySignProof:
				proof, err := login.SignProof(keys, event[1:])
				if err != nil {
					return nil, false, err
				}
				sess.PutRouter(login.SignedProof, proof)
			case login.NotifyCompleted:
				if len(event) < 2 {
					return nil, false, apperr.New("invalid login completion")
				}
				if len(event) > 2 {
					next := memguard.NewEnclave(event[2:])
					memguard.WipeBytes(event)
					return next, false, nil
				}
				if event[1] == 0 {
					return nil, false, nil
				}
				return token, false, nil
			case login.NotifyTokenRejected:
				if token == nil {
					return nil, false, apperr.New("full login rejected")
				}
				return nil, true, nil
			default:
				return nil, false, apperr.New("unexpected login event")
			}
		case <-timer.C:
			return nil, false, apperr.New("login timed out")
		case <-manager.Done:
			return nil, false, apperr.New("connection lost during login")
		}
	}
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
