package tor

import (
	"P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
)

// Initialize the bootstrap Tor ( quite long process )
// create a temporary directory for data
// start the tor deamon
// open the control connection on 127.0.0.1
func TorProcess(dataDir ...string) (torObject *tor.Tor,err error) {

	// TOR network bootstrap
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dir := filepath.Join(storage.BasePath,"Tor")
	if len(dataDir) > 0 && dataDir[0] != "" {
		dir = dataDir[0]
	}
	
	// specify the path where store data
	conf := &tor.StartConf{
		DataDir: dir,
		TempDataDirBase: filepath.Join(dir,"Tmp"),
		RetainTempDataDir: false,
	}

	// start the bootstrap
	torObj,err := tor.Start(ctx,conf)
	if err != nil {
		return nil, apperr.Wrap("error during opnening of a TOR connection",err)
	}

	return torObj,nil

}


// connect the tor with the local proxy ( must use once )
func DialTor(torObject *tor.Tor) (dialer *tor.Dialer, err error) {

	// if the connection doesnt create in 2m the connection will close
	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// connect the Tor service with the local proxy SOCKS5 ( 127.0.0.1:9050 )
	dialer, err = torObject.Dialer(dialCtx, nil)
	if err != nil {
		return nil, apperr.Wrap("error with linked the local proxy ",err)
	}

	return dialer,nil
}


// initialize the tor process ( proxy + deamon )
// must call once
func InitializeTor() (dialer *tor.Dialer,torObj *tor.Tor,err error) {
	obj,err := TorProcess()
	if err != nil {
		return nil,nil,apperr.Wrap("error in Tor initialization",err)
	}

	dialer,err = DialTor(obj)
	if err != nil {
		obj.Close()
		return nil,nil,apperr.Wrap("error in Tor initialization",err)
	}

	return dialer,obj,err
}

// create the connection with the address using the tor network
func EstablishTor(dialer *tor.Dialer,address string,port int) (connection net.Conn,err error) {

	if dialer == nil {
		return nil,apperr.New("dialer is null, not valid")
	}

	// enstablish the tor connection using the tor nodes
	address = strings.TrimSpace(address)
	endpoint := fmt.Sprintf("%s:%d",address,port)
	conn,err := dialer.Dial("tcp",endpoint)

	return conn,err

}

// close the tor process if it is running
func CloseTor(torObj *tor.Tor) error {
	if torObj == nil {
		return nil
	}
	return torObj.Close()
}

// force new circuit for the registration phase