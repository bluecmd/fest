package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/afero"
)

func SaveKeyPair(kp *tls.Certificate, crt, key string) error {
	return saveKeyPair(afero.NewOsFs(), kp, crt, key)
}

func saveKeyPair(fs afero.Fs, kp *tls.Certificate, crt, key string) error {
	b, err := encodeCert(kp.Certificate)
	if err != nil {
		return fmt.Errorf("Failed to encode certificate, please file a bug about this: %v", err)
	} else {
		if err := afero.WriteFile(fs, crt, b, 0644); err != nil {
			return fmt.Errorf("Failed to save system certificate %s: %v", crt, err)
		}
	}

	b, err = encodeKey(kp.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return fmt.Errorf("Failed to encode certificate, please file a bug about this")
	} else {
		if err := afero.WriteFile(fs, key, b, 0600); err != nil {
			return fmt.Errorf("Failed to save system certificate key %s: %v", key, err)
		}
	}
	return nil
}

func encodeCert(der [][]byte) ([]byte, error) {
	var res bytes.Buffer

	for _, c := range der {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c,
		}
		if err := pem.Encode(&res, block); err != nil {
			return []byte{}, err
		}
	}
	return res.Bytes(), nil
}

func encodeKey(pk *ecdsa.PrivateKey) ([]byte, error) {
	var res bytes.Buffer

	der, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return []byte{}, err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	if err := pem.Encode(&res, block); err != nil {
		return []byte{}, err
	}
	return res.Bytes(), nil
}

func LoadOrGenerateKey(file string) (*ecdsa.PrivateKey, error) {
	return loadOrGenerateKey(afero.NewOsFs(), file)
}

func loadOrGenerateKey(fs afero.Fs, file string) (*ecdsa.PrivateKey, error) {
	b, err := afero.ReadFile(fs, file)
	if os.IsNotExist(err) {
		return generateAndSaveKey(fs, file)
	}
	return x509.ParseECPrivateKey(b)
}

func generateAndSaveKey(fs afero.Fs, file string) (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, afero.WriteFile(fs, file, b, 0400)
}
