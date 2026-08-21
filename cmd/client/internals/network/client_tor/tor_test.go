package client_tor

import (
	"os/exec"
	"testing"
	"time"
)

// the test function need a temp dir because the TOR have a lock() inside the data path for avoid that another tor connection
// could corrupt his data, so i have to create temporary path for execute more connection
func TestInitializeTor(t *testing.T) {
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("Tor non installato, skip")
	}

	dialer, torObj, err := InitializeTor()
	if err != nil {
		t.Fatalf("InitializeTor fallita: %v", err)
	}
	defer torObj.Close()

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


func TestVerifyDifferentNodes(t *testing.T) {
	if _, err := exec.LookPath("tor"); err != nil {
		t.Skip("Tor non installato, skip")
	}

	dialer, torObj, err := InitializeTor()
	if err != nil {
		t.Fatalf("InitializeTor fallita: %v", err)
	}
	defer torObj.Close()

	conn, err := EstablishTor(dialer, "www.google.com", 80)
	if err != nil {
		t.Fatalf("EstablishTor fallita: %v", err)
	}
	if conn == nil {
		t.Fatal("connessione nil")
	}

	g1, m1, e1, err := CircuitPath(torObj, 15*time.Second)
	if err != nil {
		t.Fatalf("CircuitPath fallita: %v", err)
	}
	t.Logf("\n 1° circuito -> guard=%s middle=%s exit=%s \n", g1, m1, e1)

	conn.Close()

	t.Log("open another TOR connection")

	if err := NewCircuit(torObj); err != nil {
		t.Fatalf("NewCircuit fallita: %v", err)
	}

	conn, err = EstablishTor(dialer, "www.google.com", 80)
	if err != nil {
		t.Fatalf("EstablishTor fallita: %v", err)
	}
	if conn == nil {
		t.Fatal("connessione nil")
	}
	defer conn.Close()

	g2, m2, e2, err := CircuitPath(torObj, 15*time.Second)
	if err != nil {
		t.Fatalf("CircuitPath fallita: %v", err)
	}
	t.Logf("\n 2° circuito -> guard=%s middle=%s exit=%s \n", g2, m2, e2)

	if e1 == e2 {
		t.Fatalf("exit node non cambiato: %s", e1)
	}
	if m1 == m2 {
		t.Logf("middle node non cambiato: %s", m1)
	}
}