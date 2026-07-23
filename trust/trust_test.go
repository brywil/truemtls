package trust_test

import (
	"crypto/x509"
	"io"
	"log"
	"path/filepath"
	"testing"

	"github.com/brywil/truemtls/internal/testca"
	"github.com/brywil/truemtls/trust"
)

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func newStore(t *testing.T, seeds ...string) *trust.Store {
	t.Helper()
	s, err := trust.Load(t.TempDir(), seeds, quietLogger())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

func TestUntrustedRejectedAndQueued(t *testing.T) {
	s := newStore(t)
	ca := testca.NewCA(t, "Test CA")
	leaf := ca.Issue(t, "alice")

	if err := s.Verify(testca.Chain(leaf, ca), nil); err == nil {
		t.Fatal("expected untrusted cert to be rejected")
	}
	pend, err := s.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pend) != 1 || pend[0].CN != "alice" {
		t.Fatalf("expected 1 pending cert cn=alice, got %+v", pend)
	}
}

func TestApproveAuthorityTrustsChain(t *testing.T) {
	s := newStore(t)
	ca := testca.NewCA(t, "Test CA")
	leaf := ca.Issue(t, "alice")
	chain := testca.Chain(leaf, ca)

	_ = s.Verify(chain, nil) // queue it
	pend, _ := s.Pending()
	if _, err := s.ApproveAuthority(pend[0].Fingerprint); err != nil {
		t.Fatalf("ApproveAuthority: %v", err)
	}
	if err := s.Verify(chain, nil); err != nil {
		t.Fatalf("cert should be trusted after approving its CA: %v", err)
	}
	if pend, _ := s.Pending(); len(pend) != 0 {
		t.Fatalf("pending should be empty after approval, got %d", len(pend))
	}
	if auth, _ := s.Authorities(); len(auth) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(auth))
	}
	// a *different* leaf from the same CA is now also trusted (CA trust)
	if err := s.Verify(testca.Chain(ca.Issue(t, "bob"), ca), nil); err != nil {
		t.Fatalf("sibling cert from trusted CA should verify: %v", err)
	}
}

func TestApproveAuthorityFailsWithoutCAInChain(t *testing.T) {
	s := newStore(t)
	ca := testca.NewCA(t, "Test CA")
	leaf := ca.Issue(t, "solo")
	_ = s.Verify(testca.Chain(leaf), nil) // leaf only, no CA presented
	pend, _ := s.Pending()
	if _, err := s.ApproveAuthority(pend[0].Fingerprint); err == nil {
		t.Fatal("expected ApproveAuthority to fail when no CA is in the chain")
	}
}

func TestPinLeaf(t *testing.T) {
	s := newStore(t)
	ca := testca.NewCA(t, "Test CA")
	leaf := ca.Issue(t, "pinme")
	chain := testca.Chain(leaf) // no CA — pinning does not need one

	_ = s.Verify(chain, nil)
	pend, _ := s.Pending()
	if _, err := s.Pin(pend[0].Fingerprint); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if err := s.Verify(chain, nil); err != nil {
		t.Fatalf("pinned leaf should verify: %v", err)
	}
	// a sibling from the same CA is NOT trusted by a leaf pin
	if err := s.Verify(testca.Chain(ca.Issue(t, "other")), nil); err == nil {
		t.Fatal("leaf pin must not trust siblings")
	}
}

func TestPinnedExpiredRejected(t *testing.T) {
	s := newStore(t)
	ca := testca.NewCA(t, "Test CA")
	expired := ca.Issue(t, "stale", testca.Expired)
	chain := testca.Chain(expired)

	_ = s.Verify(chain, nil)
	pend, _ := s.Pending()
	if _, err := s.Pin(pend[0].Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(chain, nil); err == nil {
		t.Fatal("expired pinned cert must be rejected")
	}
}

func TestSeedCATrustedWithoutApproval(t *testing.T) {
	ca := testca.NewCA(t, "Seed CA")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	ca.WritePEM(t, caFile)
	s := newStore(t, caFile)

	if err := s.Verify(testca.Chain(ca.Issue(t, "carol"), ca), nil); err != nil {
		t.Fatalf("seed CA should trust its leaf without approval: %v", err)
	}
}

func TestCheckReportsApprovalAndQueuesPending(t *testing.T) {
	s := newStore(t)
	ca := testca.NewCA(t, "Test CA")
	leaf := ca.Issue(t, "dave")
	chain := []*x509.Certificate{leaf.Cert, ca.Cert}

	dec := s.Check(chain)
	if dec.Trusted {
		t.Fatal("expected not-approved for an unknown cert")
	}
	if dec.CN != "dave" {
		t.Fatalf("CN = %q, want dave", dec.CN)
	}
	if len(dec.Fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 hex chars", len(dec.Fingerprint))
	}
	if p, _ := s.Pending(); len(p) != 1 {
		t.Fatalf("Check should queue a pending entry; got %d", len(p))
	}

	if _, err := s.ApproveAuthority(dec.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if dec := s.Check(chain); !dec.Trusted {
		t.Fatal("expected approved after trusting the CA")
	}
}

func TestFingerprintPrefixAmbiguityAndMiss(t *testing.T) {
	s := newStore(t)
	if _, err := s.ApproveAuthority("deadbeef"); err == nil {
		t.Fatal("expected error approving a non-existent fingerprint")
	}
}
