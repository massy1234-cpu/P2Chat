package client_tor

import (
	"os/exec"
	"testing"
)

// the test function need a temp dir because the TOR have a lock() inside the data path for avoid that another tor connection
// could corrupt his data, so i have to create temporary path for execute more connection 
func TestInitializeTor(t *testing.T) {
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("Tor non installato, skip")
	}

	// use a temp dir so each test has an unique data directory
	torObj, err := TorProcess(t.TempDir())
	if err != nil {
		t.Fatalf("TorProcess fallita: %v", err)
	}
	defer torObj.Close()

	dialer, err := DialTor(torObj)
	if err != nil {
		t.Fatalf("DialTor fallita: %v", err)
	}
	if dialer == nil {
		t.Fatal("dialer nil")
	}
	if torObj == nil {
		t.Fatal("torObject nil")
	}
}

func TestEstablishTor(t *testing.T) {
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("Tor non installato, skip")
	}

	// use a temp dir so each test has an unique data directory
	torObj, err := TorProcess(t.TempDir())
	if err != nil {
		t.Fatalf("TorProcess fallita: %v", err)
	}
	defer torObj.Close()

	dialer, err := DialTor(torObj)
	if err != nil {
		t.Fatalf("DialTor fallita: %v", err)
	}

	conn, err := EstablishTor(dialer, "www.google.com", 80)
	if err != nil {
		t.Fatalf("EstablishTor fallita: %v", err)
	}
	if conn == nil {
		t.Fatal("connessione nil")
	}
	(conn).Close()
}
