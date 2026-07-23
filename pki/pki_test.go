package pki_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/brywil/truemtls/pki"
)

func TestEnsureServerCert(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")

	if err := pki.EnsureServerCert(crt, key, []string{"localhost", "127.0.0.1"}); err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		t.Fatalf("load generated pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.DNSNames; len(got) == 0 || got[0] != "localhost" {
		t.Fatalf("expected DNS SAN localhost, got %v", got)
	}
	if !containsIP(leaf.IPAddresses, "127.0.0.1") {
		t.Fatalf("expected IP SAN 127.0.0.1, got %v", leaf.IPAddresses)
	}
	if !hasServerAuth(leaf.ExtKeyUsage) {
		t.Fatalf("expected ExtKeyUsageServerAuth, got %v", leaf.ExtKeyUsage)
	}
}

func TestEnsureServerCertIdempotent(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "s.crt")
	key := filepath.Join(dir, "s.key")
	if err := pki.EnsureServerCert(crt, key, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(crt)
	if err := pki.EnsureServerCert(crt, key, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(crt)
	if !bytes.Equal(before, after) {
		t.Fatal("EnsureServerCert rewrote an existing cert; expected no-op")
	}
}

func containsIP(ips []net.IP, want string) bool {
	for _, ip := range ips {
		if ip.String() == want {
			return true
		}
	}
	return false
}

func hasServerAuth(eku []x509.ExtKeyUsage) bool {
	for _, u := range eku {
		if u == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}
