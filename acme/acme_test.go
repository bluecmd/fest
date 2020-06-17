package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
	"github.com/letsencrypt/pebble/wfe"
	"github.com/spf13/afero"
)

type fakeACMEHandler struct {
}

func (h *fakeACMEHandler) HandleDNS01Challenge(string, string) error {
	return nil
}

func Logger(tb testing.TB, what string) *log.Logger {
	return log.New(Writer(tb), what+" ", log.LstdFlags)
}

type writer struct {
	tb testing.TB
}

func Writer(tb testing.TB) io.Writer {
	return writer{tb}
}

func (w writer) Write(p []byte) (n int, err error) {
	w.tb.Log(string(p))
	return len(p), nil
}

func newTrustingHTTPClient(c *tls.Certificate) *http.Client {
	xc, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		log.Fatalf("Failed to parse internal cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(xc)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
	}
}

func genCert() tls.Certificate {
	// From https://golang.org/src/crypto/tls/generate_cert.go
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"u-bmc Unit Test Company"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IPAddresses: []net.IP{net.IPv6loopback, net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("x509.CreateCertificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func newManager(t *testing.T) *Manager {
	cert := genCert()
	ctx := context.Background()
	logger := Logger(t, "Pebble")
	db := db.NewMemoryStore()
	ca := ca.New(logger, db, "", 0)


	// Enable strict mode to test upcoming API breaking changes
	strictMode := true
	va := va.New(logger, 80, 443, strictMode, "")
	wfeImpl := wfe.New(logger, db, va, ca, strictMode, false)
	muxHandler := wfeImpl.Handler()

	var tc tls.Config
	tc.Certificates = make([]tls.Certificate, 1)
	tc.Certificates[0] = cert

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	go func() {
		tl := tls.NewListener(l, &tc)
		if err := http.Serve(tl, muxHandler); err != nil {
			t.Fatalf("http.Serve failed: %v", err)
		}
	}()

	fs := afero.NewMemMapFs()
	pk, _ := loadOrGenerateKey(fs, "account.key")

	m := &Manager{
		AccountKey: pk,
		Config: &Config{
			Directory:   fmt.Sprintf("https://%s/dir", l.Addr().String()),
			Contact:     "mailto:nobody@localhost",
		},
		HTTPClient: newTrustingHTTPClient(&cert),
	}

	m.Config.AgreedTerms, err = m.CurrentTerms(ctx)
	if err != nil {
		t.Fatalf("Failed to CurrentTerms(): %v", err)
	}
	return m
}

func TestACME(t *testing.T) {
	ctx := context.Background()

	// Responding to challenges is tested in the integration test
	os.Setenv("PEBBLE_VA_ALWAYS_VALID", "1")
	os.Setenv("PEBBLE_VA_NOSLEEP", "1")

	m := newManager(t)
	if err := m.Login(ctx); err != nil {
		t.Fatalf("Failed to Login(): %v", err)
	}

	now := time.Now()
	kp, err := m.Mint(ctx, "server.local")
	if err != nil {
		t.Fatalf("Failed to load cert: %v", err)
	}

	// Try to renew just a bit after
	now = now.AddDate(0, 0, 1)
	kp2, err := m.maybeRenew(ctx, now, kp)
	if err != nil {
		t.Fatalf("Failed to load cert: %v", err)
	}

	if kp != kp2 {
		t.Fatalf("Certificate changed when it should not have, %v != %v", kp, kp2)
	}

	// Pebble mints 5 year certificates by default
	// Pebble sometimes re-use the ID and fails, so let's retry
	for i := 0; i < 5; i++ {
		now = now.AddDate(5, 0, 0)
		kp2, err = m.maybeRenew(ctx, now, kp)
		if err == nil {
			break
		}
		t.Logf("Failed to load cert: %v, retrying", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		t.Fatalf("Failed to load cert: %v", err)
	}
	if kp == kp2 {
		t.Fatalf("Certificate remained the same when it should have been renewed")
	}
}

func TestFailedACME(t *testing.T) {
	ctx := context.Background()

	// Responding to challenges is tested in the integration test
	os.Setenv("PEBBLE_VA_ALWAYS_VALID", "0")
	os.Setenv("PEBBLE_VA_NOSLEEP", "1")

	m := newManager(t)
	if err := m.Login(ctx); err != nil {
		t.Fatalf("Failed to Login(): %v", err)
	}

	// TODO: This will reach out to the actual "server.local:80", it's not really
	// nice to do that in tests, but oh well.
	_, err := m.Mint(ctx, "server.local")
	if err == nil {
		t.Fatalf("Expected Mint to fail, succeeded")
	}
	if err != ErrRejected {
		t.Fatalf("Error should have been ErrRejected, was %+v", err)
	}
}
