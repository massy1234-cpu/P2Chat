package structs

import (
	"P2Chat/cmd/client/internals/network/transmission"
	"P2Chat/cmd/client/internals/p2log"
	"github.com/hashicorp/yamux"
)

func NewSession(ID uint32, stream *yamux.Stream) (session *Session) {
	session = &Session{
		ID:       ID,
		Stream:   stream,
		Incoming: make(chan []byte),
		Outgoing: make(chan []byte),
		Done:     make(chan struct{}),
	}

	go session.Listener()
	go session.Writer()

	return session
}

func (session *Session) Listener() {
	for {
		data, err := transmission.ReadMessage(session.Stream)
		if err != nil {
			session.Close()
			return
		}

		select {
		case session.Incoming <- data:
		case <-session.Done:
			return
		}
	}
}

func (session *Session) Writer() {
	for {
		select {
		case msg := <-session.Outgoing:
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

func (session *Session) Dispatcher() {
	for {
		select {
		case msg := <-session.Incoming:
			if session.Handler != nil {
				session.Handler(session, msg)
			}
		case <-session.Done:
			return
		}
	}
}

func (session *Session) Close() {
	session.Once.Do(func() {
		session.Stream.Close()
		close(session.Done)
	})
}
