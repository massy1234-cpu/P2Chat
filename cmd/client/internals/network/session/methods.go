package session

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/network/transmission"
	"P2Chat/cmd/client/internals/p2log"
	"crypto/rand"
	"time"
	"github.com/hashicorp/yamux"
)

// create a new session with an unique ID and the stream, register it in the connection
func NewSession(ID uint32, stream *yamux.Stream, globalOut chan<- []byte, deadSessions chan<- uint32) *SingleSession {
	return &SingleSession{
		ID:           ID,
		Tag:          "",
		Stream:       stream,
		Incoming:     make(chan []byte, 128),
		Outgoing:     make(chan []byte, 128),
		GlobalOut:    globalOut,
		DeadSessions: deadSessions,
		Done:         make(chan struct{}),
	}
}

// start the goroutines of the session ( listener, writer and dummy requests )
func (session *SingleSession) Init() {
	p2log.Debug("session init, ID:", session.ID)
	go session.Listener()
	go session.Writer()
	go session.dummyRequests()
}

// read the messages from the stream, strip the padding and put them in the Incoming chan
func (session *SingleSession) Listener() {
	for {
		data, err := transmission.ReadMessage(session.Stream)
		if err != nil {
			p2log.Debug("session listener closed, ID:", session.ID, err)
			session.Close()
			return
		}
		p2log.Debug("session received tag:", session.Tag, "len:", len(data))
		select {
		case session.Incoming <- data:
		case <-session.Done:
			return
		}
	}
}

// wait a random amount of time for make the traffic pattern less predictable
func delay() {
	time.Sleep(time.Duration(network.CryptoInt(500)+200) * time.Millisecond)
}

// write the messages from the Outgoing chan into the stream, the header and the padding are added inside by WriteMessage
func (session *SingleSession) Writer() {
	session.DummyBase.Store(500)			// base dimension for dummy requests
	for {
		select {
		case msg := <-session.Outgoing:
			if msg[0] != 0x00 {
				session.DummyBase.Store(int64(len(msg)))
			}
			delay()
			p2log.Debug("session sending tag:", string(msg[0]), "len:", len(msg))
			err := transmission.WriteMessage(session.Stream, msg)
			if err != nil {
				p2log.Error("error writing message", err)
				session.Close()
				return
			}
		case <-session.Done:
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
func (session *SingleSession) Close() {
	session.Once.Do(func() {
		p2log.Debug("session closed, ID:", session.ID)
		session.Stream.Close()
		close(session.Done)

		// this block avid deadlock in connection closing case
		select {
		case session.DeadSessions <- session.ID:
		default:
		}
	})
}

// return true if the session is already closed
func (session *SingleSession) IsClosed() bool {
    select {
    case <-session.Done:
        return true
    default:
        return false
    }
}

// generate dummy requests with random size for obfuscate the traffic, the receiver must discard them
func (session *SingleSession) dummyRequests() {
	var base int64
	var offset int64
	for {
		select {
		case <-session.Done:
			return
		case <-time.After(time.Duration(network.CryptoInt(1000)+400) * time.Millisecond):
			base = max(session.DummyBase.Load(), 32)
			offset = max(base+int64(network.CryptoInt(501)-250), 32)
			dummy := make([]byte, offset)
			dummy[0] = 0x00
			rand.Read(dummy[1:])
			session.PutOutgoing(dummy)
		}
	}
}