package session

import (
	"P2Chat/cmd/client/internals/network/transmission"
	"P2Chat/cmd/client/internals/p2log"
)

func (s *SingleSession) Init() {
	p2log.Debug("server session init, ID:", s.ID)
	go s.Listener()
	go s.Writer()
}

func (s *SingleSession) Listener() {
	for {
		data, err := transmission.ReadMessage(s.Stream)
		if err != nil {
			s.Close()
			return
		}

		select {
		case s.Incoming <- data:
		case <-s.Done:
			return
		}
	}
}

func (s *SingleSession) Writer() {
	for {
		select {
		case msg := <-s.Outgoing:
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

func (s *SingleSession) Close() {
	s.Once.Do(func() {
		s.Stream.Close()
		close(s.Done)
	})
}
