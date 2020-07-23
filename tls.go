package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	activeConns = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fest_active_connections",
			Help: "Current number of active connections",
		},
		[]string{"service"},
	)
)

type tlsLogger struct {
	c *tls.Conn
}

func (l *tlsLogger) Infof(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	cs := l.c.ConnectionState()
	var pre string
	if cs.ServerName != "" {
		pre = fmt.Sprintf("TLS[sni=%q]", cs.ServerName)
	} else {
		pre = fmt.Sprintf("TLS")
	}
	log.Printf("%s %s -> %s, %s", pre, l.c.RemoteAddr(), l.c.LocalAddr(), s)
}

func (l *tlsLogger) Debugf(format string, v ...interface{}) {
	l.Infof(fmt.Sprintf("[DEBUG] %s", format), v...)
}

func tlsHandler(rc net.Conn) {
	defer rc.Close()
	c := rc.(*tls.Conn)
	l := &tlsLogger{c}
	defer l.Infof("close")

	l.Infof("handshake")

	if err := c.Handshake(); err != nil {
		l.Infof("handshake failed: %v", err)
		return
	}

	cs := c.ConnectionState()
	svc, ok := serviceMap[cs.ServerName]
	if !ok {
		l.Infof("handshake failed: server %q not known", cs.ServerName)
		return
	}

	activeConns.WithLabelValues(cs.ServerName).Add(1)
	defer activeConns.WithLabelValues(cs.ServerName).Sub(1)
	l.Infof("open, alpn=%q", cs.NegotiatedProtocol)

	buf := &bytes.Buffer{}
	tee := io.TeeReader(c, buf)

	if svc.pb == nil {
		// This is not a user-defined service, so treat it as a authentication domain.
		if err := authServeConn(c, svc); err != nil {
			l.Infof("auth error: %v", err)
			return
		}
		return
	}

	s, proto, err := authConn(l, c.ConnectionState(), tee)
	if err != nil {
		l.Infof("auth error: %v", err)
	}
	if s == nil || s.User == "" {
		if proto == Protocol_HTTP1 || proto == Protocol_HTTP2 {
			l.Infof("no auth, redirecting")
			if err := redirectAuthn(c, proto, svc); err != nil {
				l.Infof("redirect error: %v", err)
				return
			}
			return
		} else {
			l.Infof("no auth, terminating")
			return
		}
	}
	l.Infof("authn ok, principal=%q, provider=%q", s.User, s.Provider)
	if !authz(s, svc.pb.GetAuthorization()) {
		if proto == Protocol_HTTP1 || proto == Protocol_HTTP2 {
			l.Infof("authz failed, returning error")
			if err := authzError(c, proto, svc); err != nil {
				l.Infof("error page error: %v", err)
				return
			}
		} else {
			l.Infof("authz failed, terminating")
			return
		}
	}
	l.Infof("authz ok, principal=%q, provider=%q", s.User, s.Provider)
	if err := backendServeConn(l, c, buf, svc.pb.GetBackend(), s); err != nil {
		l.Infof("serve error: %v", err)
	}
}

func frontendTLSConfig(ci *tls.ClientHelloInfo) (*tls.Config, error) {
	if ci.ServerName == "" {
		return nil, fmt.Errorf("no SNI present in request")
	}
	svc, ok := serviceMap[ci.ServerName]
	if !ok {
		return nil, fmt.Errorf("server %q not configured", ci.ServerName)
	}
	np := []string{"h2", "http/1.1"}
	if svc.pb != nil {
		if fe := svc.pb.GetFrontend(); fe != nil {
			if fe.GetDisableHttp2() {
				np = []string{"http/1.1"}
			}
		}
	}
	return &tls.Config{
		GetCertificate:           frontendTLSCertificate,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		NextProtos:               np,
	}, nil
}

func frontendTLSCertificate(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if ci.ServerName == "" {
		return nil, fmt.Errorf("no SNI present in request")
	}
	svc, ok := serviceMap[ci.ServerName]
	if !ok {
		return nil, fmt.Errorf("server %q not configured", ci.ServerName)
	}
	return svc.cert, nil
}

func tlsServer(s net.Listener) {
	for {
		c, err := s.Accept()
		if err != nil {
			log.Fatalf("Unable to accept new TLS client: %v", err)
		}
		go tlsHandler(c)
	}
}
