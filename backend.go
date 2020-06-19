package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	pb "github.com/bluecmd/fest/proto"
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

	be := svc.pb.GetBackend()
	if be == nil {
		return fmt.Errorf("configuration missing")
	}

	// TODO(bluecmd): Implement authn and authz here.
	// For connections that do not present a client certificate we will have to
	// become a HTTP proxy for the first request in order to extract the
	// authentication cookie.
	// This will be a bit tricky.

	user := "<todo>"
	tlsLog(c, "authz ok, principal=%q", user)

	var bc net.Conn
	var err error
	if tls := be.GetTls(); tls != nil {
		bc, err = newTLSBackendConn(tls, c.ConnectionState().NegotiatedProtocol)
	} else {
		return fmt.Errorf("type not implemented")
	}

	if err != nil {
		return err
	}

	defer bc.Close()

	go io.Copy(bc, c)
	io.Copy(c, bc)
	return nil
}

func newTLSBackendConn(pb *pb.TLSBackend, alpn string) (net.Conn, error) {
	np := []string{}
	if alpn != "" {
		np = append(np, alpn)
	}
	return tls.Dial("tcp", pb.GetEndpoint(), &tls.Config{
		InsecureSkipVerify: pb.GetSkipVerify(),
		NextProtos:         np,
	})
}

func authHttpLog(r *http.Request, format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	l := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	log.Printf("AuthHTTP %s -> %s, host=%q, method=%q, path=%q, %s", r.RemoteAddr, l, r.Host, r.Method, r.URL.Path, s)
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
	authHttpLog(r, "not-found")
	http.NotFound(w, r)
}
