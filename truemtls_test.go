package truemtls_test

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/brywil/truemtls"
	"github.com/brywil/truemtls/internal/testca"
	"github.com/brywil/truemtls/pki"
	"github.com/brywil/truemtls/proxy"
	"github.com/brywil/truemtls/trust"
)

// TestEndToEnd exercises the full stack: a transparent proxy behind mandatory
// mTLS, with an untrusted client rejected at the handshake, then trusted after
// out-of-band authority approval, then verified identity injected downstream.
func TestEndToEnd(t *testing.T) {
	testca.RequireLoopback(t)
	dir := t.TempDir()
	store, err := trust.Load(filepath.Join(dir, "trust"), nil, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	if err := pki.EnsureServerCert(crt, key, []string{"127.0.0.1", "localhost"}); err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}

	// backend records the identity header the proxy forwards
	var mu sync.Mutex
	var seenCN string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenCN = r.Header.Get("X-Client-CN")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	burl, _ := url.Parse(backend.URL)

	front := httptest.NewUnstartedServer(proxy.New(burl, proxy.Options{IdentityHeader: "X-Client-CN"}))
	front.TLS = truemtls.ServerTLSConfig(store, serverCert)
	front.StartTLS()
	defer front.Close()

	ca := testca.NewCA(t, "Test Org CA")
	leaf := ca.Issue(t, "agent-alice")
	clientCert := testca.ClientTLS(leaf, ca) // present leaf + CA

	get := func(spoof string) (*http.Response, error) {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{Certificates: []tls.Certificate{clientCert}, InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
		req, _ := http.NewRequest("GET", front.URL, nil)
		if spoof != "" {
			req.Header.Set("X-Client-CN", spoof)
		}
		return (&http.Client{Transport: tr}).Do(req)
	}

	// 1) untrusted client cert -> handshake rejected
	if _, err := get(""); err == nil {
		t.Fatal("expected handshake rejection for untrusted client cert")
	}

	// 2) cert was queued -> approve its CA
	pend := waitPending(t, store)
	if pend[0].CN != "agent-alice" {
		t.Fatalf("pending CN = %q", pend[0].CN)
	}
	if _, err := store.ApproveAuthority(pend[0].Fingerprint); err != nil {
		t.Fatalf("ApproveAuthority: %v", err)
	}

	// 3) trusted now, and the client tries to spoof its identity header
	resp, err := get("i-am-root")
	if err != nil {
		t.Fatalf("expected success after approval: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenCN != "agent-alice" {
		t.Fatalf("backend should see verified CN agent-alice (spoof stripped), got %q", seenCN)
	}
}

func waitPending(t *testing.T, s *trust.Store) []trust.Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p, err := s.Pending(); err == nil && len(p) > 0 {
			return p
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no pending cert was queued")
	return nil
}
