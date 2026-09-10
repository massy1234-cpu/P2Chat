package serverstart

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/database"
	idserver "P2Chat/cmd/server/internals/ID_server"
	"P2Chat/cmd/server/internals/network/blind_signature"
	"P2Chat/cmd/server/internals/network/bootstrap"
	"P2Chat/cmd/server/internals/network/certificate"
	"P2Chat/cmd/server/internals/network/client"
	loadreport "P2Chat/cmd/server/internals/network/load_report"
	"P2Chat/pkg/apperr"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/awnumar/memguard"
)

// ServerStart initializes the blind signature keys, the registry, the load
// report, the self-signed certificate and the TLS listener, then starts the
// accept loop in a goroutine. It returns the registry and the listener so the
// caller can shut them down cleanly on interruption.
func ServerStart(address string, port int, password *memguard.Enclave) (*client.RegistryClients, net.Listener, error) {
	if err := database.Init(); err != nil {
		p2log.Error("error during database initialization: ", err)
		return nil, nil, apperr.Wrap("error during database initialization", err)
	}

	if err := idserver.Init(3, password, false); err != nil {
		p2log.Error("error during server identity initialization: ", err)
		return nil, nil, apperr.Wrap("error during server identity initialization", err)
	}

	if err := blindsignature.InitBlindSignature(); err != nil {
		p2log.Error("error during blind signature initialization: ", err)
		return nil, nil, apperr.Wrap("error during blind signature initialization", err)
	}

	registry := client.NewRegistry()
	loadreport.Init(&registry.ClientsNumber)

	certDer, enclave, err := certificate.CreateCertificateSelf(true)
	if err != nil {
		p2log.Error("error during certificate creation: ", err)
		return nil, nil, apperr.Wrap("error during certificate creation", err)
	}

	tlsCert, err := buildTLS(certDer, enclave)
	if err != nil {
		p2log.Error("error building the TLS certificate: ", err)
		return nil, nil, apperr.Wrap("error building the TLS certificate", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", address, port), config)
	if err != nil {
		p2log.Error("error during server starting, error: ", err)
		return nil, nil, apperr.Wrap("error during server starting", err)
	}

	p2log.Info("server listening on ", ln.Addr().String())

	// accept loop in a goroutine
	go bootstrap.ListenClients(ln, registry)

	return registry, ln, nil
}

// buildTLS converts the self-signed certificate bytes and its private key
// enclave into a tls.Certificate usable by tls.Listen.
func buildTLS(certDer []byte, enclave *memguard.Enclave) (*tls.Certificate, error) {
	opened, err := enclave.Open()
	if err != nil {
		return nil, err
	}
	defer opened.Destroy()

	privDER := append([]byte{}, opened.Bytes()...)
	parsed, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, err
	}

	edKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected private key type")
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDer},
		PrivateKey:  edKey,
	}, nil
}
