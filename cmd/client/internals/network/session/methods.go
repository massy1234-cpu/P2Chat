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
		Local:        make(chan []byte, 64),
		GlobalOut:    globalOut,
		DeadSessions: deadSessions,
		Done:         make(chan struct{}),
		phaseState: nil,
		WaitGroup: sync.WaitGroup{},
		StopRead: make(chan struct{}),
		StopDummy: make(chan struct{}),
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
			select {
			case <- session.StopRead:
				p2log.Debug("session listener closed correctly")
				return
			default:
			}
			p2log.Error("error: session listener closed, ID:", session.ID, err)
			session.ForceClose()
			return
		}
		p2log.Debug("session received tag:", session.Tag, "\tlen:", len(data))

		select {
		case session.Incoming <- data:
		case <-session.Done:
			p2log.Warning("Listen force stopped")
			return
		case <-session.StopRead:
			p2log.Info("session listener closed correctly")
			return
		}
	}
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
			if err != nil {
				session.PutOutgoing(msg)
				p2log.Error("error writing message", err)
				session.ForceClose()
				return
			}
			
			if msg[0] != 0x00 {
				session.WaitGroup.Done()
			}

		case <-session.Done:
			return
		}
	}
}


// Router is the only process that can read from Incoming
// have the role to route the process
func (session *SingleSession) Router() error {
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
			session.ForceClose()
			return apperr.New("error timeout")

		case msg := <- session.Incoming:
			if len(msg) < 1 {
				session.ForceClose()
				return apperr.New("router session ID: " + fmt.Sprint(session.ID) + " closed")
			}
			if err := session.process(timer, msg[0], msg[1:]); err != nil {
				return err
			}

		case event := <- session.Local:
			if len(event) < 1 {
				continue
			}
			if err := session.process(timer, event[0], event[1:]); err != nil {
				return err
			}
		}
	}
}

// process handles one bytecode+payload through the phase handler, used both for
// network messages (Incoming) and local events (Local).
func (session *SingleSession) process(timer *time.Timer, bytecode byte, slice []byte) error {
	// stop the timer and drain (if present) the chan timer.C
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}

	p2log.Debug("router received tag: ", fmt.Sprintf("0x%02x", bytecode), "\tlen:", len(slice))

	result := session.Handler(bytecode,slice,&session.phaseState)		// call the protocol function

	// parse the result
	if result == nil {
		session.ForceClose()
		return apperr.New("result is nil, something goes wrong")
	}

	if result.Err != nil {
		session.ForceClose()
		p2log.Error("phase generated an error: ", result.Err.Error())
		return apperr.New("router session ID: " + fmt.Sprint(session.ID) + " closed")
	}

	if result.CloseStream {
		session.ForceClose()
		p2log.Error("stream closed during the stream")
		return apperr.New("stream closed during the stream")
	}

	for _,value := range result.Replies {
		p2log.Debug("router sending reply tag: 0x", fmt.Sprintf("%02x", value[0]), "len:", len(value))
		session.PutOutgoing(value)
	}

	// forward the user notification to the application, without blocking if the session is closed
	for _, value := range result.GlobalOut {
		select {
		case session.GlobalOut <- value:
		case <-session.Done:
		}
	}

	if result.Completed {
		for i := range result.Replies {
			session.PutOutgoing(result.Replies[i])
		}
		
		// close the connection after a random time
		timeRandom := network.CryptoInt(500) + 200
		time.Sleep(time.Duration(timeRandom) * time.Microsecond)

		session.GoodClose()
		p2log.Info("Phase completed with success, session with ID :",fmt.Sprint(session.ID),",closed")
		return nil
	}

	// set the timeout only if the NextDeadLine have a time setted
	if result.NextDeadline > 0{
		timeout := result.NextDeadline.Abs()
		timer.Reset(timeout)
	}

	return nil
}


// wait a random amount of time for make the traffic pattern less predictable
func delay() {
	time.Sleep(time.Duration(network.CryptoInt(500)+200) * time.Millisecond)
}


// PutRouter injects a local event (bytecode + payload) into the router's Local chan
func (session *SingleSession) PutRouter(bytecode byte, payload []byte) {
	select {
	case session.Local <- append([]byte{bytecode}, payload...):
	case <-session.Done:
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

// ForceClose abruptly terminates the session on error: it closes the stream and
// signals the shutdown to every goroutine. It only touches the session, never the
// connection or the shared GlobalOut channel.
func (session *SingleSession) ForceClose() {
	session.Once.Do(func() {
		p2log.Warning("force closing session, ID:", session.ID)
		session.Stream.Close()
		close(session.Done)

		// notify the connection that this session is dead, without blocking
		select {
		case session.DeadSessions <- session.ID:
		default:
		}
	})
}


func (session *SingleSession) GoodClose() {
	session.Once.Do(func ()  {
		close(session.StopRead)
		session.Stream.SetReadDeadline(time.Now())
		close(session.StopDummy)
		session.Flush(15 * time.Second)
		close(session.Done)
	})
}


// Drain empties the Outgoing channel before closing: it discards the dummy
// requests and returns how many real (non-dummy) messages were not transmitted.
func (session *SingleSession) Drain() (unsent int) {
	for element := range session.Outgoing {
		if len(element) > 0 && element[0] != 0x00 {
			unsent++
			session.WaitGroup.Done() 				// balance the Add done by PutOutgoing
		}
	}
	return unsent
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
		case <-session.StopDummy:
			return
		case <-time.After(time.Duration(network.CryptoInt(1000)+400) * time.Millisecond):
			base = max(session.DummyBase.Load(), 32)
			offset = max(base+int64(network.CryptoInt(501)-250), 32)
			dummy := make([]byte, offset)
			dummy[0] = 0x00
			rand.Read(dummy[1:])
			// send directly to Outgoing WITHOUT adding to the WaitGroup, so that
			// pending dummies do not keep the session from terminating
			select {
			case session.Outgoing <- dummy:
			case <-session.Done:
				return
			}
		}
	}
}
