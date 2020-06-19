package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
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

	tlsLog(c, "open, sni=%q, protocol=%q", cs.ServerName, cs.NegotiatedProtocol)

	if err := backendServeConn(c, svc); err != nil {
		tlsLog(c, "backend error: %v", err)
	}
}

func frontendTLSConfig(ci *tls.ClientHelloInfo) (*tls.Config, error) {
	if ci.ServerName == "" {
		return nil, fmt.Errorf("no SNI present in request")
	}
	return &tls.Config{
		GetCertificate:           frontendTLSCertificate,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
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
