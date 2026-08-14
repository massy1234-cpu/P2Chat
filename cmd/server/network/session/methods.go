package session

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/p2log"
	"P2Chat/cmd/server/network/phases"
	"P2Chat/cmd/server/network/transmission"
	"P2Chat/pkg/apperr"
	"fmt"
	"time"
	"github.com/hashicorp/yamux"
)

// create a new session with an unique ID and the stream, register it in the connection
func NewSession(ID uint32, stream *yamux.Stream, deadSessions chan<- uint32) *SingleSession {
	return &SingleSession{
		ID:           ID,
		Tag:          "",
		Stream:       stream,
		Incoming:     make(chan []byte, 128),
		Outgoing:     make(chan []byte, 128),
		DeadSessions: deadSessions,
		Done:         make(chan struct{}),
		Handler:      nil,
		phaseState:   nil,
		StopRead:     make(chan struct{}),
	}
}

// start the goroutines of the session ( listener and writer )
func (s *SingleSession) Init() {
	p2log.Debug("server session init, ID:", s.ID)
	go s.Listener()
	go s.Writer()
	go s.Router()
}

// read the messages from the stream, strip the padding, discard the dummy requests and put the rest in the Incoming chan
func (s *SingleSession) Listener() {
	for {
		data, err := transmission.ReadMessage(s.Stream)
		if err != nil {
			select {
			case <-s.StopRead:
				p2log.Debug("server session listener closed correctly, ID:", s.ID)
				return
			default:
			}
			p2log.Error("server session listener closed, ID:", s.ID, err)
			s.ForceClose()
			return
		}

		p2log.Debug("server session received tag:", s.Tag, "\tlen:", len(data))
		// ignore the dummy requests, doesnt even put it in the Incoming chan
		if data[0] == 0x00 {
			continue
		}

		select {
		case s.Incoming <- data:
		case <-s.Done:
			return
		case <-s.StopRead:
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
			if len(msg) == 0 {
				continue
			}
			if msg[0] != 0x00 {
				s.DummyBase.Store(int64(len(msg)))
			}
			delay()
			p2log.Debug("server session sending tag:", string(msg[0]), "len:", len(msg))
			err := transmission.WriteMessage(s.Stream, msg)
			s.WaitGroup.Done()
			if err != nil {
				s.NotTransmitted.Add(1)
				p2log.Error("error writing message", err)
				s.ForceClose()
				return
			}
		case <-s.Done:
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

// ForceClose abruptly terminates the session on error: it closes the stream and
// signals the shutdown to every goroutine. It only touches the session, never the
// connection.
func (s *SingleSession) ForceClose() {
	s.Once.Do(func() {
		p2log.Warning("server force closing session, ID:", s.ID)
		s.Stream.Close()
		close(s.Done)
		select {
		case s.DeadSessions <- s.ID:
		default:
		}
	})
}

// GoodClose gracefully terminates the session after a completed phase: it stops the
// listener, waits for every pending real message to be transmitted, then signals the
// shutdown. It keeps the stream writable while flushing.
func (s *SingleSession) GoodClose() {
	s.Once.Do(func() {
		close(s.StopRead)
		s.Stream.SetReadDeadline(time.Now())
		s.Flush(15 * time.Second)
		close(s.Done)
	})
}

// Flush wait until all the messages into the OutGoing are transmitted using the WaitGroup
// the timeout avoid the deadlock in case the messages are NOT transmitted
func (s *SingleSession) Flush(timeout time.Duration) {
	done := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	go func() {
		s.WaitGroup.Wait()
		close(done)
	}()

	select {
	case <-timer.C:
		p2log.Warning("warning timeout, not all the messages were transmitted, ID:", s.ID)
	case <-done:
	}

	if n := s.NotTransmitted.Load(); n > 0 {
		p2log.Warning("messages NOT transmitted, ID:", s.ID, "count:", n)
	}
}

// Router is the only consumer of Incoming and applies the phase result.
func (s *SingleSession) Router() error {

	var result *phases.Result

	// the timer is created and is stopped
	timer := time.NewTimer(time.Hour)
	timer.Stop()

	for {
		select {
		case <-s.Done:
			p2log.Error("session closed")
			return apperr.New("session closed")

		case <-timer.C:
			s.ForceClose()
			p2log.Error("stream closed, timeout error")
			return apperr.New("error timeout")

		case msg := <-s.Incoming:
			
			if !timer.Stop() {
				select {
				case <-timer.C:		// drain timer
				default:
				}
			}

			if len(msg) < 1 {
				s.ForceClose()
				p2log.Error("session closed")
				return apperr.New("payload received is not valid")
			}

			p2log.Debug("server router received tag: ", fmt.Sprintf("0x%02x", msg[0]), "\tlen:", len(msg)-1)

			result = s.Handler(msg[0], msg[1:], &s.phaseState)

			if result == nil {
				s.ForceClose()
				return apperr.New("result is nil, something wrong")
			}

			if result.Err != nil {
				s.ForceClose()
				p2log.Error("server phase error", result.Err.Error())
				return apperr.Wrap("server phase error", result.Err)
			}

			if result.CloseStream {
				s.ForceClose()
				p2log.Error("stream closed, session with ID :" , s.ID , "closed")
				return apperr.New("stream closed, session with ID :" + fmt.Sprint(s.ID) + "closed" )
			}

			for _, value := range result.Replies {
				p2log.Debug("server router sending reply tag: ", fmt.Sprintf("0x%02x", value[0]), "\tlen:", len(value))
				s.PutOutgoing(value)
			}

			if result.Completed {
				if len(result.Replies) > 0 {
					s.Flush(5 * time.Second)
				}

				// close the connection after a random time (symmetric with client)
				timeRandom := network.CryptoInt(500) + 200
				time.Sleep(time.Duration(timeRandom) * time.Microsecond)

				s.GoodClose()
				p2log.Info("stream closed, phase completed with success")
				return nil
			}

			if result.NextDeadline > 0 {
				timeout := result.NextDeadline.Abs()
				timer.Reset(timeout)
			}
		}
	}
}
