package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/bluecmd/fest/acme"
	pb "github.com/bluecmd/fest/proto"
	"github.com/golang/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	acmeTerms     = flag.String("acme_terms", "", "set if user agrees with the ACME server's T&C")
	acmeDirectory = flag.String("acme_directory", "https://acme-staging-v02.api.letsencrypt.org/directory", "which ACME directory to register to")
	acmeContact   = flag.String("acme_contact", "", "which contact to register ACME account to, e.g. mailto:operator@dns.domain")
	configFile    = flag.String("config_file", "config.textpb", "path to configuration file")

	config *pb.Config
)

func startACMEManager() *acme.Manager {
	akey, err := acme.LoadOrGenerateKey("acme.key")
	if err != nil {
		log.Fatalf("Failed to load ACME key: %v", err)
	}

	cm := &acme.Manager{
		AccountKey:    akey,
		HTTP01Handler: registerHTTP01Challenge,
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

	if *acmeContact == "" {
		log.Fatalf("--acme_contact must be set")
	}

	if err := cm.Login(context.Background()); err != nil {
		log.Fatalf("Failed to login or register to ACME server: %v", err)
	}
	return cm
}

func loadConfig(path string) (*pb.Config, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	sysconf := &pb.Config{}
	if err := proto.UnmarshalText(string(f), sysconf); err != nil {
		return nil, err
	}

	return sysconf, nil
}

func main() {
	flag.Parse()

	log.Printf("")
	log.Printf(`  ████████╗███████╗███████╗████████╗`)
	log.Printf(`  ███╔════╝██╔════╝██╔════╝╚══██╔══╝`)
	log.Printf(`  ██████╗  █████╗  ███████╗   ██║`)
	log.Printf(`  ███╔══╝  ██╔══╝  ╚════██║   ██║`)
	log.Printf(`  ███║     ███████╗███████║   ██║`)
	log.Printf(`   ╚═╝     ╚══════╝╚══════╝   ╚═╝`)
	log.Printf("")
	log.Printf("FEST is starting up")
	log.Printf("")

	// Prometheus Metrics comes first
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Printf("Starting Prometheus Metrics endpoint at http://[::]:9723/metrics")
		log.Fatalf("Prometheus Metrics endpoint failed: %v", http.ListenAndServe("[::]:9723", nil))
	}()

	_ = startACMEManager()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	go func() {
		for _ = range c {
			log.Printf("SIGHUP received, reloading configuration")
			nc, err := loadConfig(*configFile)
			if err != nil {
				log.Printf("Failed to load new configuration: %v (old configuration still active)", err)
				continue
			}
			// TODO(bluecmd): Might need some locking here
			config = nc
			log.Printf("New configuration successfully loaded")
		}
	}()

	var err error
	config, err = loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load initial configuration: %v", err)
	}
	log.Printf("Configuration file loaded")

	_ = config

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
