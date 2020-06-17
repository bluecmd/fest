package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/bluecmd/fest/acme"
)

var (
	acmeTerms = flag.String("acme_terms", "", "set if user agrees with the ACME server's T&C")
	acmeDirectory = flag.String("acme_directory", "https://acme-staging-v02.api.letsencrypt.org/directory", "which ACME directory to register to")
	acmeContact = flag.String("acme_contact", "", "which contact to register ACME account to, e.g. mailto:operator@dns.domain")
)

func startACMEManager() *acme.Manager {
	akey, err := acme.LoadOrGenerateKey("acme.key")
	if err != nil {
		log.Fatalf("Failed to load ACME key: %v", err)
	}

	if *acmeContact == "" {
		log.Fatalf("--acme_contact must be set")
	}

	cm := &acme.Manager{
		AccountKey:   akey,
		Config: &acme.Config{
			Directory:   *acmeDirectory,
			AgreedTerms: *acmeTerms,
			Contact:     *acmeContact,
		},
	}

	tc, err := cm.CurrentTerms(context.Background())
	if err != nil {
		log.Fatalf("Failed to retrieve ACME T&C: %v", err)
	}
	log.Printf("ACME INFO: Current ACME T&C is %q", tc)

	if err := cm.Login(context.Background()); err != nil {
		log.Fatalf("Failed to login or register to ACME server: %v", err)
	}
	return cm
}

func main() {
	flag.Parse()

	log.Printf("")
	log.Printf(`  ███████╗███████╗███████╗████████╗`)
	log.Printf(`  ███╔════╝██╔════╝██╔════╝╚══██╔══╝`)
	log.Printf(`  ██████╗  █████╗  ███████╗   ██║`)
	log.Printf(`  ███╔══╝  ██╔══╝  ╚════██║   ██║`)
	log.Printf(`  ███║     ███████╗███████║   ██║`)
	log.Printf(`   ╚═╝     ╚══════╝╚══════╝   ╚═╝`)
	log.Printf("")
	log.Printf("FEST is starting up")
	log.Printf("")

	_ = startACMEManager()

	// Let's Encrypt server to handle HTTP-01 challenges as well as serve
	// redirects. While TLS-ALPN-01 would work to run on :443, it seems cleaner
	// to separate the traffic out to the HTTP server. This means that the HTTP
	// traffic handled is either ACME HTTP-01 or 301 redirects.
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
