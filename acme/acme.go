package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/acme"
)

const (
	lifetimePadding = 7 * 24 * time.Hour
)

var (
	ErrRejected = errors.New("order was rejected")

	opsChalsAccepted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fest_acme_challanges_accepted_total",
			Help: "The total number of ACME challenges accepted",
		},
		[]string{"type"},
	)
	opsFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fest_acme_rejected_mints_total",
			Help: "The total number of ACME minting requests which were rejected",
		},
		[]string{"challenge", "name"},
	)
	opsSucceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fest_acme_succeeded_mints_total",
			Help: "The total number of ACME minting requests which completed successfully",
		},
		[]string{"challenge", "name"},
	)
	opsTries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fest_acme_tried_mints_total",
			Help: "The total number of attempts for ACME minting requests",
		},
		[]string{"name"},
	)
)

type Config struct {
	Directory   string
	Contact     string
	AgreedTerms string
}

type Manager struct {
	AccountKey    *ecdsa.PrivateKey
	Config        *Config
	HTTPClient    *http.Client
	HTTP01Handler func(path, value string)

	acct *acme.Account
}

func (m *Manager) MaybeRenew(ctx context.Context, kp *tls.Certificate) (*tls.Certificate, error) {
	return m.maybeRenew(ctx, time.Now(), kp)
}

func (m *Manager) maybeRenew(ctx context.Context, n time.Time, kp *tls.Certificate) (*tls.Certificate, error) {
	if len(kp.Certificate) == 0 {
		return nil, fmt.Errorf("tls.Certificate is empty")
	}

	c, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return nil, err
	}

	validFrom := c.NotBefore
	expires := c.NotAfter.Add(lifetimePadding * -1)

	if validFrom.After(n) || expires.Before(n) {
		// Not yet valid, or has expired
		return m.Mint(ctx, c.DNSNames...)
	}
	return kp, nil
}

func (m *Manager) tosCallback(tosURL string) bool {
	return m.Config.AgreedTerms == tosURL
}

func (m *Manager) client() *acme.Client {
	return &acme.Client{
		Key:          m.AccountKey,
		DirectoryURL: m.Config.Directory,
		HTTPClient:   m.HTTPClient,
	}
}

func (m *Manager) CurrentTerms(ctx context.Context) (string, error) {
	c := m.client()
	d, err := c.Discover(ctx)
	if err != nil {
		return "", err
	}
	return d.Terms, nil
}

// Ensure the account is registered with the ACME server
func (m *Manager) Login(ctx context.Context) error {
	c := m.client()
	a := &acme.Account{
		Contact: []string{m.Config.Contact},
	}

	na, err := c.GetReg(ctx, "")
	if err == acme.ErrNoAccount {
		na, err = c.Register(ctx, a, m.tosCallback)
		if err != nil {
			return fmt.Errorf("acme.Register: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("acme.GetReg: %v", err)
	}
	m.acct = na
	return nil
}

func (m *Manager) Mint(ctx context.Context, names ...string) (*tls.Certificate, error) {
	if m.acct == nil {
		return nil, fmt.Errorf("tried renew without calling Login() first")
	}
	c := m.client()
	var authz []acme.AuthzID
	for _, n := range names {
		authz = append(authz, acme.AuthzID{Type: "dns", Value: n})
		opsTries.WithLabelValues(n).Add(1)
	}

	order, err := c.AuthorizeOrder(ctx, authz)
	if err != nil {
		return nil, fmt.Errorf("acme.AuthorizeOrder: %v", err)
	}

	auth, err := c.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		return nil, fmt.Errorf("acme.GetAuthorization: %v", err)
	}

	var challenge *acme.Challenge
	for _, ch := range auth.Challenges {
		if ch.Type == "http-01" {
			challenge = ch
			break
		}
	}
	if challenge == nil {
		return nil, fmt.Errorf("missing http-01 challenge")
	}

	_, err = c.Accept(ctx, challenge)
	if err != nil {
		return nil, fmt.Errorf("acme.Accept: %v", err)
	}

	chpath := c.HTTP01ChallengePath(challenge.Token)
	chresp, err := c.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return nil, fmt.Errorf("acme.HTTP01ChallengeResponse: %v", err)
	}

	m.HTTP01Handler(chpath, chresp)

	_, err = c.WaitOrder(ctx, order.AuthzURLs[0])
	if err != nil {
		_, ok := err.(*acme.OrderError)
		if ok {
			for _, n := range names {
				opsFailed.WithLabelValues("http-01", n).Add(1)
			}
			return nil, ErrRejected
		} else {
			return nil, fmt.Errorf("WaitOrder: %v", err)
		}
	}

	var cert tls.Certificate
	cert.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificateRequest: %v", err)
	}

	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true /* bundle */)
	if err != nil {
		return nil, fmt.Errorf("acme.CreateOrderCert: %v", err)
	}

	for _, n := range names {
		opsSucceeded.WithLabelValues("http-01", n).Add(1)
	}
	cert.Certificate = der
	return &cert, nil
}
