package client_tor

import (
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
)

// Initialize the bootstrap Tor ( quite long process )
// create a temporary directory for data
// start the tor deamon
// open the control connection on 127.0.0.1
func TorProcess(dataDir ...string) (torObject *tor.Tor, err error) {

	dir := filepath.Join(storage.BasePath, "Tor")
	if len(dataDir) > 0 && dataDir[0] != "" {
		dir = dataDir[0]
	}

	// specify the path where store data
	conf := &tor.StartConf{
		DataDir:           dir,
		TempDataDirBase:   filepath.Join(dir, "Tmp"),
		RetainTempDataDir: false,
		DebugWriter:       os.Stdout,
		ExtraArgs: []string{
			"--ClientRejectInternalAddresses", "0",
		},
	}

	// start the bootstrap
	torObj, err := tor.Start(context.Background(), conf)
	if err != nil {
		return nil, apperr.Wrap("error during opening of a TOR connection", err)
	}

	bootstrapCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err = torObj.EnableNetwork(bootstrapCtx, true) // true = aspetta il bootstrap completo
	if err != nil {
		return nil, apperr.Wrap("error with EnableNetwork Tor deamon", err)
	}

	return torObj, nil

}

// connect the tor with the local proxy ( must use once )
func DialTor(torObject *tor.Tor) (dialer *tor.Dialer, err error) {

	// if the connection doesnt create in 2m the connection will close
	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// connect the Tor service with the local proxy SOCKS5 ( 127.0.0.1:9050 )
	dialer, err = torObject.Dialer(dialCtx, nil)
	if err != nil {
		return nil, apperr.Wrap("error with linked the local proxy ", err)
	}

	return dialer, nil
}

// initialize the tor process ( proxy + deamon )
// must call once
func InitializeTor() (dialer *tor.Dialer, torObj *tor.Tor, err error) {
	obj, err := TorProcess()
	if err != nil {
		return nil, nil, apperr.Wrap("error in Tor initialization", err)
	}

	dialer, err = DialTor(obj)
	if err != nil {
		obj.Close()
		return nil, nil, apperr.Wrap("error in Tor initialization", err)
	}

	return dialer, obj, err
}

// create the connection with the address using the tor network
func EstablishTor(dialer *tor.Dialer, address string, port int) (connection net.Conn, err error) {

	if dialer == nil {
		return nil, apperr.New("dialer is null, not valid")
	}

	// enstablish the tor connection using the tor nodes
	address = strings.TrimSpace(address)
	endpoint := fmt.Sprintf("%s:%d", address, port)
	conn, err := dialer.Dial("tcp", endpoint)

	return conn, err

}

// close the tor process if it is running
func CloseTor(torObj *tor.Tor) error {
	if torObj == nil {
		return nil
	}
	return torObj.Close()
}

// to use when the tor connection is closed and flag as dirty the middle and
// exit node TOR, this is not a warranty but is high probable that future nodes will change
func NewCircuit(torObj *tor.Tor) error {
	if torObj == nil || torObj.Control == nil {
		return apperr.New("error: torObj is nil")
	}

	err := torObj.Control.Signal("NEWNYM")
	if err != nil {
		return apperr.Wrap("errore nell'invio del segnale NEWNYM", err)
	}

	return nil
}

// CircuitPath returns guard, middle and exit of the first fully-built 3-hop
// circuit, polling until one is available or the timeout expires.
func CircuitPath(torObj *tor.Tor, timeout time.Duration) (guard, middle, exit string, err error) {
	if torObj == nil || torObj.Control == nil {
		return "", "", "", apperr.New("controller Tor non disponibile")
	}

	deadline := time.Now().Add(timeout)
	for {
		vals, err := torObj.Control.GetInfo("circuit-status")
		if err != nil {
			return "", "", "", apperr.Wrap("GETINFO circuit-status fallito", err)
		}

		if len(vals) > 0 {
			for _, line := range strings.Split(vals[0].Val, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) < 3 || (parts[1] != "BUILT" && parts[1] != "EXTENDED") {
					continue
				}
				path := strings.Split(strings.Trim(parts[2], ","), ",")
				if len(path) == 3 {
					return path[0], path[1], path[2], nil
				}
			}
		}

		if time.Now().After(deadline) {
			return "", "", "", apperr.New("nessun circuito 3-hop BUILT trovato")
		}
		time.Sleep(500 * time.Millisecond)
	}
}
