package main

import (
	"P2Chat/cmd/client/database"
	cnnpassword "P2Chat/cmd/client/internals/cnn_password"
	"P2Chat/cmd/client/internals/commitment"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	"P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/network/bootstrap"
	"P2Chat/cmd/client/internals/network/connection"
	bundlereg "P2Chat/cmd/client/internals/network/phases/bundle_reg"
	getuserbundle "P2Chat/cmd/client/internals/network/phases/get_user_bundle"
	"P2Chat/cmd/client/internals/network/phases/login"
	nicknamecatalog "P2Chat/cmd/client/internals/network/phases/nickname_catalog"
	"P2Chat/cmd/client/internals/network/session"
	"P2Chat/cmd/client/internals/p2chat_errors"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	loginproto "P2Chat/cmd/client/internals/proto_generated/login/proto_struct_login"
	struct_mldsa "P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	"P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	"P2Chat/cmd/client/internals/protocol/pqxdh"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
	proto "google.golang.org/protobuf/proto"
)

// The CLI connects to and verifies the server, then lets the user choose the
// next operation.
func main() {
	address := flag.String("server", "151.48.238.152", "server address")
	port := flag.Int("port", 9000, "server port")
	localBundle := flag.Int("bundle", -1, "existing local bundle number to log in with")
	flag.Parse()
	if err := database.Init(); err != nil {
		p2log.Error("error initializing the client database: ", err)
		return
	}
	defer database.CloseDB()

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
	reader := bufio.NewReader(os.Stdin)
	for {
		choice, err := readMenuChoice(reader, "\n1) Login\n2) Register\n3) Exit\n\nChoice: ", 1, 3)
		if err != nil {
			p2log.Error("error reading menu choice: ", err)
			return
		}

		switch choice {
		case 1:
			if knownBundle == nil {
				p2log.Warning("no registered bundle is associated with this server")
				continue
			}
			password, err := readPassword()
			if err != nil {
				p2log.Error("error reading bundle password: ", err)
				continue
			}
			if err := runLogin(connManager, binding, knownBundle, password); err != nil {
				p2log.Error("login failed: ", err)
				continue
			}
			p2log.Info("authenticated connection ready")
			if err := runAuthenticatedMenu(reader, connManager.Conn); err != nil {
				p2log.Error("authenticated menu failed: ", err)
			}
			return

		case 2:
			nickname, err := readRequiredLine(reader, "Nickname: ")
			if err != nil {
				p2log.Error("error reading nickname: ", err)
				continue
			}
			password, err := readRegistrationPassword()
			if err != nil {
				p2log.Error("error reading bundle password: ", err)
				continue
			}
			registered, err := runRegistration(connManager, nickname, password)
			if err != nil {
				p2log.Error("registration failed: ", err)
				continue
			}
			knownBundle = registered
			p2log.Info("registration completed; select Login to authenticate")

		case 3:
			return
		}
	}
}

func readMenuChoice(reader *bufio.Reader, prompt string, minChoice, maxChoice int) (int, error) {
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		var choice int
		if _, err := fmt.Sscanf(strings.TrimSpace(input), "%d", &choice); err == nil && choice >= minChoice && choice <= maxChoice {
			return choice, nil
		}
		fmt.Println("Invalid choice.")
	}
}

func readRequiredLine(reader *bufio.Reader, prompt string) (string, error) {
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(input)
		if value != "" {
			return value, nil
		}
		fmt.Println("The value cannot be empty.")
	}
}

func runAuthenticatedMenu(reader *bufio.Reader, conn *connection.Connection) error {
	for {
		choice, err := readMenuChoice(reader, "\n1) Download a user bundle\n2) Exit\n\nChoice: ", 1, 2)
		if err != nil {
			return err
		}
		if choice == 2 {
			return nil
		}

		nickname, err := readRequiredLine(reader, "Nickname: ")
		if err != nil {
			return err
		}
		if err := requestAndStoreUserBundle(reader, conn, nickname); err != nil {
			p2log.Error("user bundle request failed: ", err)
		}
	}
}

func runRegistration(manager *connection.ConnectionManager, nickname string, password *memguard.Enclave) (*database.LoginBundle, error) {
	tokenEvents, err := manager.Conn.TokenRegistration()
	if err != nil {
		return nil, apperr.Wrap("start token registration phase", err)
	}
	token := readData(tokenEvents)
	if token == nil {
		return nil, apperr.New("no token received, connection lost or timeout")
	}
	p2log.Info("token received from the token registration phase")

	commitmentSecret, err := readCommitmentSecret()
	if err != nil {
		return nil, apperr.Wrap("read commitment secret", err)
	}
	pqxdhPackage, err := pqxdh.InitializePQXDH(password, commitmentSecret, 1, 2, false, storage.BasePath, 2)
	if err != nil {
		return nil, apperr.Wrap("create PQXDH bundle", err)
	}
	publicBundle := pqxdhPackage.PublicBundle
	curveSets := pqxdhPackage.CurvePublicSets
	kemSets := pqxdhPackage.KemPublicSets
	ikID := int(publicBundle.GetId())

	bundleSess, bundleEvents, err := manager.Conn.UploadBundle()
	if err != nil {
		return nil, apperr.Wrap("start bundle upload phase", err)
	}
	bundleSess.PutRouter(bundlereg.RegistrationToken, token)
	if ok, _ := waitNotify(bundleEvents, bundlereg.NotifyTokenConfirmed); !ok {
		return nil, apperr.New("token not confirmed by the server")
	}
	bundleSess.PutRouter(bundlereg.Nickname, []byte(nickname))

	ok, flag := waitNotify(bundleEvents, bundlereg.NotifyNicknameReady)
	if !ok || flag != 1 {
		return nil, apperr.New("nickname not accepted by the server")
	}
	p2log.Info("nickname accepted, waiting for the originalM challenge")
	originalM := readData(bundleEvents)
	if originalM == nil {
		return nil, apperr.New("no originalM challenge received, connection lost or timeout")
	}
	p2log.Info("originalM challenge received, signing it with the IK keys")
	if err := signAndInject(bundleSess, password, ikID, originalM); err != nil {
		return nil, err
	}
	if ok, _ := waitNotify(bundleEvents, bundlereg.NotifySigned); !ok {
		return nil, apperr.New("bundle signing not acknowledged")
	}

	uploadPayload := &proto_struct_bundle.UserBundle{
		PublicBundle:    publicBundle,
		CurvePublicSets: curveSets,
		KemPublicSets:   kemSets,
	}
	uploadBytes, err := proto.Marshal(uploadPayload)
	if err != nil {
		return nil, apperr.Wrap("serialize bundle payload", err)
	}
	bundleSess.PutRouter(bundlereg.Bundle, uploadBytes)
	if ok, _ := waitNotify(bundleEvents, bundlereg.NotifyBundleUploaded); !ok {
		return nil, apperr.New("bundle not confirmed by the server")
	}
	p2log.Info("bundle uploaded and verified by the server")

	h1, h2 := sha256.Sum256(publicBundle.IkX25519), sha256.Sum256(publicBundle.IkMldsa)
	id := sha256.Sum256(append(h1[:], h2[:]...))
	registered := &database.LoginBundle{LocalID: ikID, BundleID: id[:]}
	if err := database.SaveLoginBundle(manager.Conn.ServerID, registered); err != nil {
		return nil, apperr.Wrap("save registered login bundle", err)
	}
	return registered, nil
}

// requestNicknameCatalog obtains and decodes the server nickname catalog.
func requestNicknameCatalog(conn *connection.Connection) (*nicknamecatalog.PayloadJSON, error) {
	catalogSession, catalogEvents, err := conn.GetNicknameCatalog()
	if err != nil {
		return nil, err
	}
	catalogSession.PutRouter(nicknamecatalog.AcquisitionNicknames, nil)
	catalogJSON := readData(catalogEvents)
	if catalogJSON == nil {
		return nil, apperr.New("nickname catalog was not received")
	}

	catalog := &nicknamecatalog.PayloadJSON{}
	if err := json.Unmarshal(catalogJSON, catalog); err != nil {
		return nil, apperr.Wrap("decode nickname catalog event", err)
	}

	if err := database.SaveCatalogJSON(conn.ServerID, catalog); err != nil {
		return nil, apperr.Wrap("save nickname catalog", err)
	}

	return catalog, nil
}

func requestAndStoreUserBundle(reader *bufio.Reader, conn *connection.Connection, nickname string) error {
	catalog, err := catalogForNickname(conn, nickname)
	if err != nil {
		return err
	}
	nicknames, err := selectBundleRequestNicknames(catalog, nickname)
	if err != nil {
		return err
	}
	if !confirmBundleStorage(reader, nickname) {
		p2log.Info("user bundle download declined: ", nickname)
		return nil
	}

	request, err := getuserbundle.EncodeBundleRequest(nicknames)
	if err != nil {
		return err
	}
	sess, events, err := conn.GetUserBundle()
	if err != nil {
		return err
	}
	sess.PutRouter(getuserbundle.AcquisitionBundle, request)
	serialized := readData(events)
	if serialized == nil {
		return apperr.New("user bundles were not received")
	}

	response, err := getuserbundle.DecodeResponseBundles(serialized)
	if err != nil {
		return err
	}
	bundle, err := response.GetBundleUsingNickname(nickname)
	if err != nil {
		return err
	}
	publicBundle := bundle.GetPublicBundle()
	if publicBundle == nil || publicBundle.GetCommitmentScheme() == nil {
		return apperr.New("received bundle has no commitment scheme")
	}
	if err := commitment.ValidateUpload(publicBundle.GetCommitmentScheme()); err != nil {
		return apperr.Wrap("validate received commitment", err)
	}

	commitmentSecret, err := readCommitmentSecret()
	if err != nil {
		return apperr.Wrap("read commitment secret", err)
	}
	verified, err := verifyCommitment(
		publicBundle.GetCommitmentScheme(),
		publicBundle.GetIkMldsa(),
		publicBundle.GetIkX25519(),
		commitmentSecret,
	)
	if err != nil {
		return apperr.Wrap("verify received bundle commitment", err)
	}
	if err := database.SaveUserBundle(bundle, conn.ServerID, verified); err != nil {
		return apperr.Wrap("save received user bundle", err)
	}
	if verified {
		p2log.Info("user bundle saved with a verified commitment: ", nickname)
	} else {
		p2log.Warning("user bundle saved without commitment verification: ", nickname)
	}
	return nil
}

func catalogForNickname(conn *connection.Connection, nickname string) (*nicknamecatalog.PayloadJSON, error) {
	catalog, err := database.LoadCatalogJSON(conn.ServerID)
	if err == nil && catalogContainsRequest(catalog, nickname) {
		return catalog, nil
	}

	catalog, err = requestNicknameCatalog(conn)
	if err != nil {
		return nil, err
	}
	present, err := catalog.HasNickname(nickname)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, apperr.New("nickname is not present on the server")
	}
	if uniqueNicknameCount(catalog.Nicknames) < getuserbundle.BundleRequestCount {
		return nil, apperr.New("the server catalog does not contain enough nicknames for a private bundle request")
	}
	return catalog, nil
}

func catalogContainsRequest(catalog *nicknamecatalog.PayloadJSON, nickname string) bool {
	if catalog == nil || uniqueNicknameCount(catalog.Nicknames) < getuserbundle.BundleRequestCount {
		return false
	}
	present, err := catalog.HasNickname(nickname)
	return err == nil && present
}

func uniqueNicknameCount(nicknames []string) int {
	unique := make(map[string]struct{}, len(nicknames))
	for _, nickname := range nicknames {
		if nickname != "" {
			unique[nickname] = struct{}{}
		}
	}
	return len(unique)
}

func selectBundleRequestNicknames(catalog *nicknamecatalog.PayloadJSON, target string) ([]string, error) {
	if catalog == nil {
		return nil, apperr.New("nickname catalog is nil")
	}
	seen := map[string]struct{}{target: {}}
	decoys := make([]string, 0, len(catalog.Nicknames))
	for _, nickname := range catalog.Nicknames {
		if nickname == "" || nickname == target {
			continue
		}
		if _, exists := seen[nickname]; exists {
			continue
		}
		seen[nickname] = struct{}{}
		decoys = append(decoys, nickname)
	}
	if len(decoys) < getuserbundle.BundleRequestCount-1 {
		return nil, apperr.New("not enough distinct nicknames for bundle request decoys")
	}
	if err := secureShuffle(decoys); err != nil {
		return nil, err
	}
	selected := []string{target, decoys[0], decoys[1]}
	if err := secureShuffle(selected); err != nil {
		return nil, err
	}
	return selected, nil
}

func secureShuffle(values []string) error {
	for index := len(values) - 1; index > 0; index-- {
		position, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			return apperr.Wrap("shuffle bundle request nicknames", err)
		}
		other := int(position.Int64())
		values[index], values[other] = values[other], values[index]
	}
	return nil
}

func verifyCommitment(scheme *proto_struct_commitment.CommitmentSchemeUpload, mldsaPublic, x25519Public []byte, psk *memguard.Enclave) (bool, error) {
	publicMLDSA, err := mldsa_keys.DecodePublicKey(&struct_mldsa.PublicKeyMLDSA{Key: mldsaPublic})
	if err != nil {
		return false, apperr.Wrap("decode commitment ML-DSA public key", err)
	}
	publicX25519, err := x25519.NewPublicKey(x25519Public)
	if err != nil {
		return false, apperr.Wrap("decode commitment X25519 public key", err)
	}

	return commitment.VerifyCommitment(scheme, publicMLDSA, publicX25519, psk)
}

func confirmBundleStorage(reader *bufio.Reader, nickname string) bool {
	fmt.Printf("Download and save the bundle for %q? [y/N]: ", nickname)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

// runLogin orchestrates login events; identification is completed separately.
func runLogin(manager *connection.ConnectionManager, binding []byte, bundle *database.LoginBundle, password *memguard.Enclave) error {
	var keys *login.Credentials
	for attempt := 0; attempt < 4; attempt++ {
		stored, err := database.LoadPassToken(manager.Conn.ServerID)
		if err != nil {
			return err
		}
		var token *memguard.Enclave
		if stored != nil {
			token = memguard.NewEnclave(stored.Serialized)
			memguard.WipeBytes(stored.Serialized)
		}
		bundleID := bundle.BundleID
		if token == nil || len(bundleID) != 32 {
			if keys == nil {
				keys, err = login.LoadIdentity(bundle, password)
				if err != nil {
					return err
				}
			}
			bundleID = keys.BundleID
		}
		parameters, err := login.EncodeParameters(binding, manager.Conn.ServerID, bundleID, token != nil)
		if err != nil {
			return err
		}
		sess, events, err := manager.Conn.Login()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-sess.Done:
				cancel()
			case <-ctx.Done():
			}
		}()
		tokens, retry, err := waitLogin(ctx, manager, sess, events, keys, parameters, token)
		cancel()
		if err != nil {
			sess.ForceClose()
			return err
		}
		if stored != nil {
			if err := database.DeletePassToken(manager.Conn.ServerID, stored.Slot); err != nil {
				return err
			}
		}
		if retry {
			continue
		}
		if len(tokens) != 0 {
			batch := &loginproto.LoginTokenBatch{}
			if err := proto.Unmarshal(tokens, batch); err != nil {
				memguard.WipeBytes(tokens)
				return err
			}
			serialized := make([][]byte, 0, len(batch.Tokens))
			for _, pass := range batch.Tokens {
				value, err := proto.Marshal(pass)
				if err != nil {
					wipeLoginTokenBatch(batch)
					memguard.WipeBytes(tokens)
					return err
				}
				serialized = append(serialized, value)
			}
			wipeLoginTokenBatch(batch)
			memguard.WipeBytes(tokens)
			saveErr := database.SavePassTokens(manager.Conn.ServerID, serialized)
			for _, value := range serialized {
				memguard.WipeBytes(value)
			}
			if saveErr != nil {
				return saveErr
			}
		}
		if keys != nil {
			registered := &database.LoginBundle{LocalID: bundle.LocalID, BundleID: keys.BundleID}
			if err := database.SaveLoginBundle(manager.Conn.ServerID, registered); err != nil {
				return err
			}
		}
		return nil
	}
	return apperr.New("all pass tokens were rejected")
}

func wipeLoginTokenBatch(batch *loginproto.LoginTokenBatch) {
	if batch == nil {
		return
	}
	for _, token := range batch.Tokens {
		if token != nil {
			memguard.WipeBytes(token.Message)
			memguard.WipeBytes(token.Signature)
		}
	}
	batch.Tokens = nil
}

func waitLogin(ctx context.Context, manager *connection.ConnectionManager, sess *session.SingleSession, events <-chan []byte, keys *login.Credentials, parameters []byte, token *memguard.Enclave) ([]byte, bool, error) {
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
				p2log.Debug("login phase ready, sending connection parameters")
				sess.PutRouter(login.Parameters, parameters)
			case login.NotifyPassToken:
				if token == nil {
					return nil, false, apperr.New("missing login token")
				}
				p2log.Info("attempting quick login with a pass token")
				opened, err := token.Open()
				if err != nil {
					return nil, false, err
				}
				sess.PutRouter(login.PassToken, opened.Bytes())
				opened.Destroy()
			case login.NotifySolvePoW:
				p2log.Info("solving the proof of work required for login...")
				solution, err := login.SolveChallenge(ctx, event[1:])
				if err != nil {
					return nil, false, err
				}
				p2log.Info("login proof of work solved")
				sess.PutRouter(login.PoWSolution, solution)
			case login.NotifySignProof:
				p2log.Info("signing the login identity proof...")
				proof, err := login.SignProof(keys, event[1:])
				if err != nil {
					return nil, false, err
				}
				p2log.Info("login identity proof signed")
				sess.PutRouter(login.SignedProof, proof)
			case login.NotifyCompleted:
				p2log.Info("login phase completed successfully")
				if len(event) > 1 {
					tokens := append([]byte(nil), event[1:]...)
					memguard.WipeBytes(event)
					return tokens, false, nil
				}
				return nil, false, nil
			case login.NotifyTokenRejected:
				if token == nil {
					return nil, false, apperr.New("full login rejected")
				}
				p2log.Warning("pass token rejected, retrying with a full login")
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
	for {
		fmt.Print("Bundle password (minimum 16 bytes): ")
		input, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			memguard.WipeBytes(input)
			return nil, err
		}
		if len(input) < 16 {
			memguard.WipeBytes(input)
			p2log.Warning("bundle password must be at least 16 bytes")
			continue
		}
		buffer := memguard.NewBufferFromBytes(input)
		memguard.WipeBytes(input)
		return buffer.Seal(), nil
	}
}

func readRegistrationPassword() (*memguard.Enclave, error) {
	for {
		password, err := readPassword()
		if err != nil {
			return nil, err
		}

		output, err := cnnpassword.ExecuteModel(password)
		if err != nil {
			return nil, apperr.Wrap("classify bundle password", err)
		}

		classification := &cnnpassword.NeuralNetworkClassification{}
		if err := classification.ImportJSON(output); err != nil {
			return nil, apperr.Wrap("import password classification", err)
		}
		result, err := classification.Result()
		if err != nil {
			return nil, apperr.Wrap("read password classification", err)
		}
		if result.ClassID == cnnpassword.ClassWeak {
			p2log.Warning("password classified as weak; choose another password")
			continue
		}

		p2log.Info(fmt.Sprintf("password classified as %s", result.Class))
		return password, nil
	}
}

func readCommitmentSecret() (*memguard.Enclave, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("standard input is not a terminal")
	}
	fmt.Print("Shared commitment secret (minimum 16 bytes): ")
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		memguard.WipeBytes(input)
		return nil, err
	}
	if len(input) < 16 {
		memguard.WipeBytes(input)
		return nil, fmt.Errorf("commitment secret must be at least 16 bytes")
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
	identity, err := pqxdh.LoadIKKeys(password, storage.BasePath, ikID)
	if err != nil {
		return apperr.Wrap("error loading the IK keys", err)
	}

	sigMLDSA, err := identity.PrivateMLDSA.Sign(originalM, nil, false)
	if err != nil {
		return apperr.Wrap("error signing with ML-DSA", err)
	}
	sigX25519, err := identity.PrivateX25519.Sign(originalM)
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
