package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
)

var (
	errDone = errors.New("done")
)

// TODO(bluecmd): See https://github.com/golang/go/issues/36673 to make this easier
type singleConnListener struct {
	conn net.Conn
	done chan bool
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used {
		// Block until the first connection has been handled to avoid the server shuting down too early
		<-l.done
		return nil, errDone
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	// nop
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func backendServeConn(c *tls.Conn, svc *Service) error {
	if svc.pb == nil {
		// This is not a user-defined service, so treat it as a authentication domain.
		return authServeConn(c, svc)
	}

	return fmt.Errorf("backend not implemented")
}

func authServeConn(c *tls.Conn, svc *Service) error {
	done := make(chan bool)
	err := http.Serve(&singleConnListener{conn: c, done: done}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHTTPHandler(w, r)
		done <- true
	}))
	if err == errDone {
		return nil
	}
	return err
}

func authHTTPHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
