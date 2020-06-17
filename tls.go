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
	tlsLog(rc, "handshake")

	c, ok := rc.(*tls.Conn)
	if !ok {
		tlsLog(rc, "handshake failed: not TLS connection")
		return
	}
	if err := c.Handshake(); err != nil {
		tlsLog(rc, "handshake failed: %v", err)
		return
	}
	tlsLog(rc, "open")
}

func frontendTLSConfig(ci *tls.ClientHelloInfo) (*tls.Config, error) {
	if ci.ServerName == "" {
		return nil, fmt.Errorf("no SNI present in request")
	}
	return nil, fmt.Errorf("server %q not configured", ci.ServerName)
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
