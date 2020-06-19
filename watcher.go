package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bluecmd/fest/acme"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	certMap      = map[string]*Certificate{}
	watcherPoker = make(chan struct{}, 1)

	loadedCerts = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fest_service_certificate_loaded",
			Help: "Whether or not a service's certificate has been successfully loaded",
		},
		[]string{"service"},
	)
	certExpires = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fest_service_certificate_expires",
			Help: "UNIX timestamp when the loaded certificate expires",
		},
		[]string{"service"},
	)
)

type Certificate struct {
	t *tls.Certificate
}

func pokeWatcher() {
	watcherPoker <- struct{}{}
}

func loadCert(domain string) (*tls.Certificate, error) {
	cf := fmt.Sprintf("certs/%s.crt", domain)
	kf := fmt.Sprintf("certs/%s.key", domain)
	skp, err := tls.LoadX509KeyPair(cf, kf)

	if os.IsNotExist(err) {
		// continue
	} else if err != nil {
		log.Printf("tls.LoadX509KeyPair: %v", err)
	} else {
		xc, err := x509.ParseCertificate(skp.Certificate[0])
		if err != nil {
			log.Panicf("Internal error: failed to read validity of certificate for %q", domain)
		}
		skp.Leaf = xc
		return &skp, nil
	}

	log.Printf("Missing or invalid certificate for %q, requesting new one", domain)
	crt, err := certManager.Mint(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	if err := acme.SaveKeyPair(crt, cf, kf); err != nil {
		log.Printf("Failed to save new certificate for %q: %v", domain, err)
	}
	return crt, nil
}

func scheduleRenew(domain string, c *Certificate) {
	for {
		xc := c.t.Leaf
		certExpires.WithLabelValues(domain).Set(float64(xc.NotAfter.Unix()))
		expires := xc.NotAfter.Add(acme.LifetimePadding * -1)
		log.Printf("Scheduling renewal for %q at %s", domain, expires)
		time.Sleep(expires.Sub(time.Now()) + 10*time.Minute)
		log.Printf("Renewal due for %q", domain)

		nt, err := certManager.MaybeRenew(context.Background(), c.t)
		if err != nil {
			log.Printf("Renewal for %q failed: %v", domain, err)
			loadedCerts.WithLabelValues(domain).Set(0)
			c.t = nil
			return
		}

		cf := fmt.Sprintf("certs/%s.crt", domain)
		kf := fmt.Sprintf("certs/%s.key", domain)
		if err := acme.SaveKeyPair(nt, cf, kf); err != nil {
			log.Printf("Failed to save renewed certificate for %q: %v", domain, err)
		}

		c.t = nt
		log.Printf("Successfully renewed certificate for %q", domain)
	}
}

func startWatcher() {
	err := os.MkdirAll("certs", os.FileMode(0700))
	if err != nil {
		log.Fatalf("Failed to create certificate cache directory %q: %v", "certs", err)
	}

	fi, err := os.Lstat("certs")
	if err != nil {
		log.Fatalf("Failed to inspect certificate cache directory %q: %v", "certs", err)
	}

	if fi.Mode().Perm()&0007 != 0 {
		log.Fatalf("Insecure permissions on certificate cache directory %q, set to 0770 or stricter", "certs")
	}

	go func() {
		for {
			<-watcherPoker
			c := config
			domains := []string{*authDomain}
			for _, svc := range c.GetService() {
				domains = append(domains, svc.GetName())
			}

			for _, domain := range domains {
				tc, ok := certMap[domain]
				if !ok {
					tc = &Certificate{}
					certMap[domain] = tc
				}

				if tc.t == nil {
					loadedCerts.WithLabelValues(domain).Set(0)
					c, err := loadCert(domain)
					if err != nil {
						log.Printf("Failed to load certificate for %q: %v", domain, err)
						log.Printf("Rejecting service %q until operator can fix the issue. Send SIGHUP to retry.", domain)
						c = nil
					} else {
						log.Printf("Successfully loaded certificate for %q", domain)
						loadedCerts.WithLabelValues(domain).Set(1)
						go scheduleRenew(domain, tc)
					}
					tc.t = c
				}
			}
		}
	}()
}
