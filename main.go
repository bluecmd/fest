package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

func main() {
	// Let's Encrypt server to handle HTTP-01 challenges as well as serve
	// redirects.
	hs, err := net.Listen("tcp", "[::]:80")
	if err != nil {
		log.Fatalf("Unable to listen on HTTP port: %v", err)
	}

	go func() {
		log.Fatalf("HTTP serving error: %v", http.Serve(hs, http.HandlerFunc(httpHandler)))
	}()

	tc := &tls.Config{
		GetConfigForClient:       frontendTLSConfig,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}

	// TODO(#1): Support TPROXY
	s, err := tls.Listen("tcp", "[::]:443", tc)
	if err != nil {
		log.Fatalf("Unable to listen on TLS port: %v", err)
	}

	go tlsServer(s)

	log.Printf("Running...")

	select {}
}
