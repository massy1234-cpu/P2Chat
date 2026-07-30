package session

import (
	"P2Chat/cmd/client/internals/network"
	"P2Chat/cmd/client/internals/network/transmission"
	"P2Chat/cmd/client/internals/p2log"
	"crypto/rand"
	"time"
)

func (session *SingleSession) Init() {
	p2log.Debug("session init, ID:", session.ID)
	go session.Listener()
	go session.Writer()
	go session.dummyRequests()
}

func (session *SingleSession) Listener() {
	for {
		data, err := transmission.ReadMessage(session.Stream)
		if err != nil {
			p2log.Debug("session listener closed, ID:", session.ID, err)
			session.Close()
			return
		}

		// tag is not usefull in app context but could be in debugging or other uses 
		if session.Tag == "" {
			tag := data[0]
			data = data[1:]
			session.Tag = string(tag)
		}
		p2log.Debug("session received tag:", session.Tag, "len:", len(data))
		select {
		case session.Incoming <- data:
		case <-session.Done:
			return
		}
	}
}

func delay() {
	time.Sleep(time.Duration(network.CryptoInt(500)+200) * time.Millisecond)
}

func (session *SingleSession) Writer() {
	session.DummyBase.Store(500)
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

func (session *SingleSession) PutOutgoing(data []byte) {
	if data == nil {
		return
	}
	session.Outgoing <- data
}

func (session *SingleSession) Close() {
	session.Once.Do(func() {
		p2log.Debug("session closed, ID:", session.ID)
		session.Stream.Close()
		close(session.Done)
	})
}

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
