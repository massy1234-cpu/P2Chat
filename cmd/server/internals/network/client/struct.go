package client

import (
	"P2Chat/cmd/server/internals/network/connection"
	"sync"
	"sync/atomic"
)

type RegistryClients struct {
	Clients				sync.Map
	ClientsNumber		atomic.Uint64
	nextID				uint64
	freeIDs				[]uint64
	mu					sync.Mutex
	DeadClients			chan uint64
	Done 				chan struct{}
	Once				sync.Once
}

type Client struct {
	ID     			uint64
	Authed 			atomic.Bool
	Conn 			*connection.Connection
	DeadClient		chan<- uint64
	Done			chan struct{}
	Once 			sync.Once
}
