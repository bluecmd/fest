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

func tlsLog(c net.Conn, format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	log.Printf("TLS %s -> %s, %s", c.RemoteAddr(), c.LocalAddr(), s)
}

func tlsHandler(rc net.Conn) {
	defer rc.Close()
	defer tlsLog(rc, "close")

	c, ok := rc.(*tls.Conn)
	if !ok {
		tlsLog(rc, "handshake failed: not TLS connection")
		return
	}

	tlsLog(c, "handshake")

	if err := c.Handshake(); err != nil {
		tlsLog(c, "handshake failed: %v", err)
		return
	}

	cs := c.ConnectionState()
	svc, ok := serviceMap[cs.ServerName]
	if !ok {
		tlsLog(c, "handshake failed: server %q not known", cs.ServerName)
		return
	}

	activeConns.WithLabelValues(cs.ServerName).Add(1)
	defer activeConns.WithLabelValues(cs.ServerName).Sub(1)
	tlsLog(c, "open, sni=%q, alpn=%q", cs.ServerName, cs.NegotiatedProtocol)

	buf := &bytes.Buffer{}
	tee := io.TeeReader(c, buf)

	if svc.pb == nil {
		// This is not a user-defined service, so treat it as a authentication domain.
		if err := authServeConn(c, svc); err != nil {
			tlsLog(c, "auth error: %v", err)
			return
		}
	}

	user, err := authConn(c, tee)
	if err != nil {
		tlsLog(c, "auth error: %v", err)
	}

	tlsLog(c, "authz ok, principal=%q", user)

	if err := backendServeConn(c, buf, svc.pb.GetBackend()); err != nil {
		tlsLog(c, "serve error: %v", err)
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
