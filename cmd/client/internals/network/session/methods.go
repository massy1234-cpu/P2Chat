package session

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/network/transmission"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"fmt"
	"sync"
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
		phaseState: nil,
		WaitGroup: sync.WaitGroup{},
	}
}

// start the goroutines of the session ( listener, writer and dummy requests )
func (session *SingleSession) Init() {
	p2log.Debug("session init, ID:", session.ID)
	go session.Listener()
	go session.Writer()
	go session.dummyRequests()
	go session.Router()
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

// Router is the only process that can read from Incoming
// have the role to route the process
func (session *SingleSession) Router() error {
	var bytecode byte
	var slice []byte

	if session.Handler == nil {
		return apperr.New("Handler is nil")
	}

	// the timer is created and is stopped
	timer := time.NewTimer(time.Hour)
	timer.Stop()

	for {
		select {
		case <-session.Done:
			p2log.Warning("router session ID: %d closed",session.ID)
			return apperr.New("router session ID: " + fmt.Sprint(session.ID) + " closed")

		case <-timer.C:
			session.Close()
			return apperr.New("error timeout")

		case msg := <- session.Incoming:
			// stop the timer and drain (if present) the chan timer.C
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if len(msg) < 1 {
				session.Close()
				return apperr.New("router session ID: " + fmt.Sprint(session.ID) + " closed")
			}
			bytecode = msg[0]
			slice = msg[1:]

			result := session.Handler(bytecode,slice,&session.phaseState)		// call the protocol function

			// parse the result
			if result == nil {
				session.Close()
				return apperr.New("result is nil, something goes wrong")
			}

			if result.CloseStream {
				session.Close()
				p2log.Error("stream closed during the stream")
				return apperr.New("stream closed during the stream")
			}
			
			if result.Err != nil {
				session.Close()
				p2log.Error("phase generated an error: ", result.Err.Error())
				return apperr.New("router session ID: " + fmt.Sprint(session.ID) + " closed")
			}

			for _,value := range result.Replies {
				session.PutOutgoing(value)
			}

			if result.Completed {
				if len(result.Replies) > 0 {
					session.Flush(5 * time.Second)		// wait the transmission of all messages
				}
				session.Close()
				p2log.Info("Phase completed with success, session with ID :",fmt.Sprint(session.ID),",closed")
				return nil
			}

			// set the timeout only if the NextDeadLine have a time setted
			if result.NextDeadline > 0{
				timeout := result.NextDeadline.Abs()
				timer.Reset(timeout)
			}
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
			if len(msg) == 0 {
				continue
			}
			if msg[0] != 0x00 {
				session.DummyBase.Store(int64(len(msg)))
			}
			delay()
			p2log.Debug("session sending tag:", string(msg[0]), "len:", len(msg))
			err := transmission.WriteMessage(session.Stream, msg)
			session.WaitGroup.Done()		// keep track of the message if it's been transmitted
			if err != nil {
				session.NotTransmitted.Add(1)
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
	if len(data) == 0 {
		return
	}
	session.WaitGroup.Add(1)
    select {
	case session.Outgoing <- data:
	case <-session.Done:
		session.WaitGroup.Done()
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


// Flush wait until all the messages into the OutGoing are trasmitted using the WaitGroup
// the timeout avoid the deadlock in case the messages are NOT transmitted
func (session *SingleSession) Flush(timeout time.Duration) {
	done := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	go func() {
		session.WaitGroup.Wait()
		close(done)
	}()

	// if the WaitGroup last more than timeout the select-case enter in timer.C and terminate the Flush
	// avoid deadlock
	select {
	case <-timer.C:
		p2log.Warning("warning timeout, not all the messages were transmitted, ID:", session.ID)
	case <-done:
	}

	if n := session.NotTransmitted.Load(); n > 0 {
		p2log.Warning("messages NOT transmitted, ID:", session.ID, "count:", n)
	}
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
