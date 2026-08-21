package client

import (
	"P2Chat/cmd/server/network/connection"
	"net"
	"os"
	"sync"
	"time"
	"github.com/hashicorp/yamux"
)

// --- registry methods ---

// create a new registry and start the goroutine that remove the dead clients
func NewRegistry() *RegistryClients {
	registry := &RegistryClients{
		DeadClients: make(chan uint64, 64),
		Done:        make(chan struct{}),
	}
	registry.Init()
	return registry
}

// return the next available ID for a client, reuse the freed IDs if any
func (registry *RegistryClients) NextID() uint64 {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.freeIDs) > 0 {
		id := registry.freeIDs[len(registry.freeIDs)-1]
		registry.freeIDs = registry.freeIDs[:len(registry.freeIDs)-1]
		return id
	}
	registry.nextID++
	return registry.nextID
}

// put back the ID in the pool for reuse it
func (registry *RegistryClients) ReleaseID(number uint64) {
	registry.mu.Lock()
	registry.freeIDs = append(registry.freeIDs, number)
	registry.mu.Unlock()
}

// put the client in the registry and assign to it an ID (int)
func (registry *RegistryClients) AddClient(client *Client) {
	ID := registry.NextID()
	client.ID = ID
	registry.Clients.Store(ID, client)
	registry.ClientsNumber.Add(1)
}

// remove the client from the registry and close it
func (registry *RegistryClients) RemoveClient(ID uint64) {
	value, loaded := registry.Clients.LoadAndDelete(ID)
	if !loaded {
		return
	}

	// i do close() even if the client should send his ID in the chan
	client := value.(*Client)
	client.Close()

	registry.ClientsNumber.Add(^uint64(0))		// mod = 2^64 - 1 
	registry.ReleaseID(ID)
}

// RemoveDeadClient is a goroutine that drains the DeadClients channel
// and removes the corresponding clients from the registry
func (registry *RegistryClients) RemoveDeadClient() {
	for {
		select {
		case DeadID := <-registry.DeadClients:
			registry.RemoveClient(DeadID)
		case <-registry.Done:
			return
		}
	}
}

// start the goroutines of the registry
func (registry *RegistryClients) Init() {
	go registry.RemoveDeadClient()
}




// --- client methods ---





// create a new client from a TLS connection, wrap it in a yamux session and start it
func NewClient(conn net.Conn, deadClient chan<- uint64) *Client {
	if conn == nil {
		return nil
	}

	config := yamux.DefaultConfig()
	config.KeepAliveInterval = 15 * time.Second
	config.MaxStreamWindowSize = 512 * 1024
	config.LogOutput = os.Stdout

	sess, err := yamux.Server(conn, config)
	if err != nil {
		return nil
	}

	connScheme := &connection.Connection{
		MasterSession:  sess,
		ActiveSessions: sync.Map{},
		DeadSessions:   make(chan uint32, 64),
		Done:           make(chan struct{}),
	}

	connScheme.Init()

	client := &Client{
		Conn:       connScheme,
		DeadClient: deadClient,
		Done:       make(chan struct{}),
	}

	client.Init()

	return client
}

// close the client, the connection and signal the dead client to the registry
func (c *Client) Close() {
	c.Once.Do(func(){
		close(c.Done)
		c.Conn.Close()
		// blocking send: the ID MUST be registered in the dead clients list
		c.DeadClient <- c.ID
	})
}

// watchdog that close the client if the connection is dead
func (c *Client) ImDead() {
	select {
	case <- c.Conn.Done:
		c.Close()
	case <- c.Done:
		return
	}
}

// start the goroutines of the client
func (c *Client) Init() {
	go c.ImDead()
}