// Package testca mints ephemeral CA and leaf certificates for tests.
package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// Cert bundles a certificate with its key and common encodings.
type Cert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  []byte
	PEM  []byte
	TLS  tls.Certificate
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// NewCA returns a self-signed CA certificate.
func NewCA(t *testing.T, cn string) *Cert {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return finish(t, der, key)
}

// Issue signs a client leaf certificate with clientAuth EKU. Optional mutators
// can adjust the template (e.g. to make it expired).
func (ca *Cert) Issue(t *testing.T, cn string, opts ...func(*x509.Certificate)) *Cert {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, o := range opts {
		o(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return finish(t, der, key)
}

// Expired is an Issue mutator that produces an already-expired certificate.
func Expired(c *x509.Certificate) {
	c.NotBefore = time.Now().Add(-2 * time.Hour)
	c.NotAfter = time.Now().Add(-time.Minute)
}

func finish(t *testing.T, der []byte, key *ecdsa.PrivateKey) *Cert {
	t.Helper()
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &Cert{Cert: crt, Key: key, DER: der, PEM: certPEM, TLS: tlsc}
}

// Chain returns the raw DER chain (leaf first) for the given certs.
func Chain(certs ...*Cert) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.DER
	}
	return out
}

// ClientTLS builds a tls.Certificate presenting leaf then the given CAs, for use
// as an http client certificate (so the server sees the full chain).
func ClientTLS(leaf *Cert, cas ...*Cert) tls.Certificate {
	c := tls.Certificate{Certificate: [][]byte{leaf.DER}, PrivateKey: leaf.Key}
	for _, ca := range cas {
		c.Certificate = append(c.Certificate, ca.DER)
	}
	return c
}

// WritePEM writes the certificate PEM to path.
func (c *Cert) WritePEM(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, c.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
}
