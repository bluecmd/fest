package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	pb "github.com/bluecmd/fest/proto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	idSize = 64
)

var (
	sessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "fest_sessions",
			Help: "Current number of sessions in memory",
		},
	)

	ErrExpiredSession = errors.New("session is expired")
	ErrReusedSession  = errors.New("session is cancelled due to reuse")
	ErrUnknownSession = errors.New("unknown session")

	sessionDefaultAge = 24 * time.Hour * 7

	sessionMap   = map[[idSize]byte]*session{}
	sessionMutex sync.RWMutex

	ephSessionKey cipher.AEAD
)

type session struct {
	Provider pb.Provider
	User     string
	Callback string

	id  [idSize]byte
	exp time.Time
	ctr int
}

func newSession() *session {
	s := newEphemeralSession()
	return s
}

func newEphemeralSession() *session {
	s := &session{
		exp: time.Now().Add(sessionDefaultAge),
	}
	for {
		if n, err := rand.Read(s.id[:]); n != len(s.id) || err != nil {
			panic(fmt.Sprintf("not enough entropy: %v", err))
		}
		sessionMutex.Lock()
		_, ok := sessionMap[s.id]
		if !ok {
			sessionMap[s.id] = s
			sessions.Set(float64(len(sessionMap)))
		}
		sessionMutex.Unlock()
		if ok {
			// Collision
			continue
		}
		break
	}
	return s
}

func validateSessionCookie(cookie string) (*session, error) {
	id, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		return nil, err
	}
	var idb [idSize]byte
	copy(idb[:], id)
	return validateSession(idb)
}

func validateSession(id [idSize]byte) (*session, error) {
	sessionMutex.RLock()
	s, ok := sessionMap[id]
	sessionMutex.RUnlock()
	if !ok {
		return nil, ErrUnknownSession
	}
	if s.ctr > 1 {
		return nil, ErrReusedSession
	}
	if !s.IsValid() {
		s.Forget()
		return nil, ErrExpiredSession
	}
	return s, nil
}

func validateEncryptedSessionID(id string, nonce string) (*session, error) {
	i, err := base64.URLEncoding.DecodeString(id)
	if err != nil {
		return nil, err
	}
	n, err := base64.URLEncoding.DecodeString(nonce)
	if err != nil {
		return nil, err
	}
	b, err := ephSessionKey.Open(nil, n, i, nil)
	if err != nil {
		return nil, err
	}
	var idb [idSize]byte
	copy(idb[:], b)
	return validateSession(idb)
}

func (s *session) ID() string {
	return base64.URLEncoding.EncodeToString(s.id[:])
}

func (s *session) Cookie(domain string) string {
	age := int(s.exp.Sub(time.Now()).Seconds())
	id := base64.URLEncoding.EncodeToString(s.id[:])
	return fmt.Sprintf("%s=%s; Domain=%s; Secure; Max-Age=%d", festCookie, id, domain, age)
}

func (s *session) AuthCookie(domain string) string {
	age := 300
	id := base64.URLEncoding.EncodeToString(s.id[:])
	return fmt.Sprintf("%s-IM=%s; Domain=%s; Secure; Max-Age=%d", festCookie, id, domain, age)
}

func (s *session) IsValid() bool {
	return time.Now().Before(s.exp)
}

func (s *session) Forget() {
	sessionMutex.Lock()
	_, ok := sessionMap[s.id]
	if ok {
		delete(sessionMap, s.id)
		sessions.Set(float64(len(sessionMap)))
	}
	sessionMutex.Unlock()
}

func (s *session) EncryptedID() (string, string) {
	// Since we do not implement any explicit counter scheme out of laziness
	// we block the use of encrypted ID to at most once. It is useful for our
	// goal to be able to transfer the session ID to the auth domain, which will
	// always require exactly just one jump.
	s.ctr = s.ctr + 1

	// From https://golang.org/pkg/crypto/cipher/#NewGCM
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(fmt.Sprintf("failed to read entropy: %v", err))
	}
	b := ephSessionKey.Seal(nil, nonce, s.id[:], nil)
	return base64.URLEncoding.EncodeToString(b), base64.URLEncoding.EncodeToString(nonce)
}

func initSessionStore() {
	// Generate ephemeral session AES key
	var ak [32]byte
	if n, err := rand.Read(ak[:]); n != len(ak) || err != nil {
		panic(fmt.Sprintf("not enough entropy: %v", err))
	}

	aesc, err := aes.NewCipher(ak[:])
	if err != nil {
		panic(err)
	}
	ephSessionKey, err = cipher.NewGCM(aesc)
	if err != nil {
		panic(err)
	}
}
