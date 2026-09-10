package database

import (
	"bytes"
	"github.com/dgraph-io/badger/v4"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginTokenConcurrentUsesAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	options := badger.DefaultOptions(path).WithLogger(nil)
	db, err := badger.Open(options)
	if err != nil {
		t.Fatal(err)
	}
	previous := db_manager
	db_manager = db
	t.Cleanup(func() { db_manager.Close(); db_manager = previous })
	key, message, bundle := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64), bytes.Repeat([]byte{3}, 32)
	expires := time.Now().Add(time.Hour).Unix()
	var count atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ConsumeLoginToken(key, message, bundle, expires); err == nil {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 3 {
		t.Fatalf("accepted %d uses", count.Load())
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db_manager, err = badger.Open(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ConsumeLoginToken(key, message, bundle, expires); err == nil {
		t.Fatal("restart reset spent token")
	}
	if _, err := ConsumeLoginToken(key, bytes.Repeat([]byte{9}, 64), bundle, time.Now().Unix()-1); err == nil {
		t.Fatal("accepted expired token")
	}
}
