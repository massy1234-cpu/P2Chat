package certificate


import (
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
	"github.com/awnumar/memguard"
)


const fileDir = "certificate"


// create a certificate self-hosted
func CreateCertificateSelf(store bool) (certDer []byte,enclave *memguard.Enclave, err error) {
	public,private,err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, apperr.Wrap("error during creation of self-hosted certificate",err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(private)

	enclave = memguard.NewEnclave(keyBytes)
	memguard.WipeBytes(keyBytes)


	template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{CommonName: "P2Chat Server"},
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(365 * 24 * time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature,						// define some use case 
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},	// more detailed use cases
    }

	// certDer are the raw bytes and create the certificate, use the public key, the structure and the private key
	// for the signature
	certDer,err = x509.CreateCertificate(rand.Reader,template,template,public,private)
	if err != nil {
		return nil,nil,apperr.Wrap("error during creation of the x509 certificate",err)
	}

	if store {
		dir := filepath.Join(storage.BasePath,fileDir)
		os.MkdirAll(dir,0700)

		// save the certificate
		file, _ := os.Create(filepath.Join(dir,"cert.pem"))
		pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certDer})
		file.Close()

		// save the private key
		opened,_ := enclave.Open()
		defer opened.Destroy()
		keyFile, _ := os.Create(filepath.Join(dir,"key.pem"))
		pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: opened.Bytes()})
		keyFile.Close()
	}

	return certDer,enclave,nil
}


// TODO: for a real certificate we have to have a real domain
//func CreateCertificate(store bool) {
//
//}