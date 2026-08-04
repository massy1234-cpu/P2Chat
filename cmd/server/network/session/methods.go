package session

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/network/transmission"
	"time"
	"github.com/hashicorp/yamux"
)

// create a new session with an unique ID and the stream, register it in the connection
func NewSession(ID uint32, stream *yamux.Stream, deadSessions chan<- uint32) *SingleSession {
	return &SingleSession{
		ID:           ID,
		Stream:       stream,
		Incoming:     make(chan []byte, 128),
		Outgoing:     make(chan []byte, 128),
		DeadSessions: deadSessions,
		Done:         make(chan struct{}),
		Handler:      nil,
	}
}

// start the goroutines of the session ( listener and writer )
func (s *SingleSession) Init() {
	p2log.Debug("server session init, ID:", s.ID)
	go s.Listener()
	go s.Writer()
}

// read the messages from the stream, strip the padding, discard the dummy requests and put the rest in the Incoming chan
func (s *SingleSession) Listener() {
	for {
		data, err := transmission.ReadMessage(s.Stream)
		if err != nil {
			s.Close()
			return
		}
		
		// ignore the dummy requests, doesnt even put it in the Incoming chan
		if data[0] == 0x00 {
			continue
		}

		select {
		case s.Incoming <- data:
		case <-s.Done:
			return
		}
	}
}

// wait a random amount of time for make the traffic pattern less predictable
func delay() {
	time.Sleep(time.Duration(network.CryptoInt(500)+200) * time.Millisecond)
}

// write the messages from the Outgoing chan into the stream, the header and the padding are added inside by WriteMessage
func (s *SingleSession) Writer() {
	s.DummyBase.Store(500)
	for {
		select {
		case msg := <-s.Outgoing:
			if msg[0] != 0x00 {
				s.DummyBase.Store(int64(len(msg)))
			}
			delay()
			p2log.Debug("server session sending tag:", string(msg[0]), "len:", len(msg))
			err := transmission.WriteMessage(s.Stream, msg)
			if err != nil {
				p2log.Error("error writing message", err)
				s.Close()
				return
			}
		case <-s.Done:
			return
		}
	}
}

// put the data in the Outgoing chan for send it, do not add the header or the padding here
func (session *SingleSession) PutOutgoing(data []byte) {
	if data == nil {
		return
	}
	select {
	case session.Outgoing <- data:
	case <-session.Done:
	}
}

// close the session, the stream and signal the dead session to the connection
func (s *SingleSession) Close() {
	s.Once.Do(func() {
		s.Stream.Close()
		close(s.Done)
		select {
		case s.DeadSessions <- s.ID:
		default:
		}
	})
}

// read the Incoming chan and route each message to the handler of the session
func (s *SingleSession) Dispatcher() {
	for {
		select {
		case msg := <-s.Incoming:
			s.Handler(s, msg)
		case <-s.Done:
			return
		}
	}
}
