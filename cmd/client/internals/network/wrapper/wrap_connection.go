package wrapper

import (
	"P2Chat/cmd/client/internals/network/transmission"
	"errors"
	"io"
	"net"
)


// wrap the net.Conn in a struct that handle the messages Incoming and Outgoing  
func Wrapper(connection net.Conn) ( wrap *Connection ) {

	if connection == nil {
		return nil
	}

	wrap = &Connection{
		Connection: connection,
		Incoming: make(chan []byte, 128),
		Outgoing: make(chan []byte, 128 ),
		done: make(chan struct{}),
	}

	go wrap.Listener()
	go wrap.Writer()

	return wrap

}


// terminate the connection
func (c *Connection) Close() {
	c.Connection.Close()
	close(c.Incoming)
	close(c.Outgoing)
}


func isTimeout(err error) bool {
    var nerr net.Error
    return errors.As(err, &nerr) && nerr.Timeout()
}


// is a function that is in loop and listen all the messages from the server
// it operates asynchronously for garantee that all packages are NOT lost
// put all the messages that come from the server in the chan
func (c *Connection) Listener() {
	for {
		// wait until a packet arrives
		msg, err := transmission.ReadMessage(c.Connection)
        
		// retry only if was a Timeout excedeed, else close the connection
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				c.Close()
			case errors.Is(err, net.ErrClosed):
				c.Close()
			case isTimeout(err):
				continue
			default:
				c.Close()
				return
			}
		}

		// what a message from the ReadMessage func or terminate in case c.Close()
        select {
			case c.Incoming <- msg:
			case <-c.done:
				return
        }
	}
}