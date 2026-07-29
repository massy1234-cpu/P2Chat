package structs

import (
	"P2Chat/cmd/client/internals/network/transmission"
	"P2Chat/cmd/client/internals/p2log"
	"github.com/hashicorp/yamux"
)

// wrap the new stream inside the struct
func NewSession(ID uint32, stream *yamux.Stream, globalOut chan<- []byte) (session *SingleSession) {

	session = &SingleSession{
		ID:        ID,
		Tag:       "",
		Stream:    stream,
		Incoming:  make(chan []byte),
		Outgoing:  make(chan []byte),
		GlobalOut: globalOut,
		Done:      make(chan struct{}),
	}

	go session.Listener()
	go session.Writer()

	return session
}

// function listener for the session, keep listen all the messages and put it in the buffer chan
func (session *SingleSession) Listener() {

	for {
		data, err := transmission.ReadMessage(session.Stream)
		if err != nil {
			session.Close()
			return // error handling in network
		}

		// if the Tag is empty so is the first message and i extract the tag from data
		if session.Tag == "" {
			tag := data[0]
			data = data[1:]
			session.Tag = string(tag)
		}

		// i put the data inside the buffer
		select {
		case session.Incoming <- data :
		case <-session.Done:
			return
		}
	}
}

// function writer that handle all the messages in the Outgoing buffer and use the correct
// convention for send messages
func (session *SingleSession) Writer() {
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


// put the messages inside the Outgoing chan 
func (session *SingleSession) OutMsg(msg []byte) {
	if msg == nil {
		return
	}
	header := transmission.CreateHeader(msg)
	session.Outgoing<-msg
}

// Close the chan and the connection
func (session *SingleSession) Close() {
	session.Once.Do(func() { 
		session.Stream.Close()
		close(session.Done) 
	})
}