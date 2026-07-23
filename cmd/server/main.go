package main

import (
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/cmd/server/network"
	"P2Chat/cmd/server/network/certificate"
	"crypto/tls"
	"path/filepath"
)

func main() {
	p2log.InitializeLog()
	storage.BasePath = filepath.Join(storage.ProjectRoot, "cmd", "server", "data")

	certDir := filepath.Join(storage.BasePath, "certificate")
	certificate.CreateCertificateSelf(true)

	tlsCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "cert.pem"),
		filepath.Join(certDir, "key.pem"),
	)
	if err != nil {
		p2log.Error("load TLS cert:", err)
		return
	}

	network.InitializeTLS(tlsCert)
}
