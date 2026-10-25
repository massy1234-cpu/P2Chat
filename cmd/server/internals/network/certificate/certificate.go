package certificate

import (
	ed25519_keys "P2Chat/cmd/client/internals/keys/ed25519"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const fileDir = "certificate"

// create a certificate self-hosted
func CreateCertificateSelf(store bool) (certDer []byte, key *ed25519_keys.PrivateEd25519, err error) {
	key, err = ed25519_keys.CreateKey()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "P2Chat Server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,                  // define some use case
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // more detailed use cases
	}

	// certDer are the raw bytes and create the certificate, use the public key, the structure and the private key
	// for the signature
	certDer, err = key.CreateCertificate(template)
	if err != nil {
		return nil, nil, apperr.Wrap("error during creation of the x509 certificate", err)
	}

	if store {
		dir := filepath.Join(storage.BasePath, fileDir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, nil, apperr.Wrap("create certificate directory", err)
		}

		// save the certificate
		file, err := os.Create(filepath.Join(dir, "cert.pem"))
		if err != nil {
			return nil, nil, apperr.Wrap("create cert.pem", err)
		}
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certDer}); err != nil {
			file.Close()
			return nil, nil, apperr.Wrap("encode cert.pem", err)
		}
		file.Close()

		// save the private key
		keyFile, err := os.Create(filepath.Join(dir, "key.pem"))
		if err != nil {
			return nil, nil, apperr.Wrap("create key.pem", err)
		}
		if err := key.WritePEM(keyFile); err != nil {
			keyFile.Close()
			return nil, nil, apperr.Wrap("encode key.pem", err)
		}
		keyFile.Close()
	}

	return certDer, key, nil
}

// TODO: for a real certificate we have to have a real domain
//func CreateCertificate(store bool) {
//
//}
