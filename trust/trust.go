// Package trust implements mymcp's mTLS authentication: a directory tree of PEM
// files (hand-manageable, no database) plus a TOFU pending queue. See DESIGN.md.
//
//	<root>/authorities/  trusted CA certs (one PEM per CA)
//	<root>/pinned/       exact leaf certs (self-authenticating)
//	<root>/pending/      unknown certs captured at handshake, awaiting approval
//
// This layer answers "is this certificate authentic?" only. Authorization
// (what the CN may do) lives in package policy.
package trust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Store is a directory-backed mTLS trust store.
type Store struct {
	authoritiesDir, pinnedDir, pendingDir string
	seed                                  []*x509.Certificate
	logger                                *log.Logger
}

// Load builds a Store rooted at root, creating subdirectories if absent.
// seedCAPaths are optional always-trusted CA PEM files (e.g. a corporate CA).
func Load(root string, seedCAPaths []string, logger *log.Logger) (*Store, error) {
	if logger == nil {
		logger = log.Default()
	}
	s := &Store{
		authoritiesDir: filepath.Join(root, "authorities"),
		pinnedDir:      filepath.Join(root, "pinned"),
		pendingDir:     filepath.Join(root, "pending"),
		logger:         logger,
	}
	for _, d := range []string{s.authoritiesDir, s.pinnedDir, s.pendingDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	for _, p := range seedCAPaths {
		if p == "" {
			continue
		}
		certs, err := readCertsFile(p)
		if err != nil {
			return nil, fmt.Errorf("client CA %q: %w", p, err)
		}
		s.seed = append(s.seed, certs...)
	}
	return s, nil
}

type snapshot struct {
	roots  *x509.CertPool
	pinned map[string]bool
}

func (s *Store) load() *snapshot {
	snap := &snapshot{roots: x509.NewCertPool(), pinned: map[string]bool{}}
	for _, c := range s.seed {
		snap.roots.AddCert(c)
	}
	for _, c := range readCertsDir(s.authoritiesDir) {
		snap.roots.AddCert(c)
	}
	for _, c := range readCertsDir(s.pinnedDir) {
		snap.pinned[fingerprint(c)] = true
	}
	return snap
}

// Verify is installed as tls.Config.VerifyPeerCertificate. It authenticates the
// presented chain (leaf first): accepted if the leaf is pinned or chains to a
// trusted authority; otherwise queued to pending/ and rejected.
func (s *Store) Verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate presented")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("unparseable client certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			inter.AddCert(c)
		}
	}

	snap := s.load()
	fp := fingerprint(leaf)
	if snap.pinned[fp] {
		if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return fmt.Errorf("pinned client certificate is outside its validity period")
		}
		return nil
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         snap.roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}); err == nil {
		return nil
	}

	s.recordPending(leaf, rawCerts)
	s.logger.Printf("REJECTED client cert cn=%q issuer=%q fp=%s — approve out of band: `trust approve authority %s` (or `trust pin %s`)",
		leaf.Subject.CommonName, leaf.Issuer.CommonName, fp, fp[:16], fp[:16])
	return fmt.Errorf("untrusted client certificate (pending: %s)", fp[:16])
}

// Decision is the result of Check: whether a presented client chain is on the
// approved list, plus the leaf's identity — without rejecting the connection.
type Decision struct {
	Trusted     bool
	CN          string
	Fingerprint string
}

// Check classifies a presented client chain (leaf first) as approved or not,
// recording a pending entry for out-of-band approval when it is not. Unlike
// Verify it never rejects the connection — use it when the TLS handshake is
// allowed to complete and the decision is made at the application layer (e.g.
// to serve a "pending approval" page to unapproved clients).
func (s *Store) Check(chain []*x509.Certificate) Decision {
	if len(chain) == 0 {
		return Decision{}
	}
	leaf := chain[0]
	fp := fingerprint(leaf)
	dec := Decision{CN: leaf.Subject.CommonName, Fingerprint: fp}

	snap := s.load()
	if snap.pinned[fp] {
		if now := time.Now(); !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter) {
			dec.Trusted = true
			return dec
		}
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         snap.roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}); err == nil {
		dec.Trusted = true
		return dec
	}
	raw := make([][]byte, len(chain))
	for i, c := range chain {
		raw[i] = c.Raw
	}
	s.recordPending(leaf, raw)
	s.logger.Printf("PENDING client cert cn=%q issuer=%q fp=%s — approve: `trust approve authority %s` or `trust pin %s`",
		leaf.Subject.CommonName, leaf.Issuer.CommonName, fp, fp[:16], fp[:16])
	return dec
}

func (s *Store) recordPending(leaf *x509.Certificate, rawCerts [][]byte) {
	path := filepath.Join(s.pendingDir, fingerprint(leaf)+".pem")
	if _, err := os.Stat(path); err == nil {
		return
	}
	var buf strings.Builder
	for _, raw := range rawCerts {
		_ = pem.Encode(&stringBuilderWriter{&buf}, &pem.Block{Type: "CERTIFICATE", Bytes: raw})
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		s.logger.Printf("warn: could not write pending cert: %v", err)
	}
}

// Entry describes a certificate for listing.
type Entry struct {
	Fingerprint string
	CN          string
	Issuer      string
	NotAfter    time.Time
	IsCA        bool
	Path        string
}

// Pending lists certs awaiting approval.
func (s *Store) Pending() ([]Entry, error) { return listDir(s.pendingDir) }

// Authorities lists trusted CA certs.
func (s *Store) Authorities() ([]Entry, error) { return listDir(s.authoritiesDir) }

// Pins lists pinned leaf certs.
func (s *Store) Pins() ([]Entry, error) { return listDir(s.pinnedDir) }

func (s *Store) findPending(fpPrefix string) (Entry, []*x509.Certificate, error) {
	pend, err := s.Pending()
	if err != nil {
		return Entry{}, nil, err
	}
	var match *Entry
	for i := range pend {
		if strings.HasPrefix(pend[i].Fingerprint, strings.ToLower(fpPrefix)) {
			if match != nil {
				return Entry{}, nil, fmt.Errorf("fingerprint prefix %q is ambiguous", fpPrefix)
			}
			match = &pend[i]
		}
	}
	if match == nil {
		return Entry{}, nil, fmt.Errorf("no pending cert matches %q", fpPrefix)
	}
	chain, err := readCertsFile(match.Path)
	if err != nil || len(chain) == 0 {
		return Entry{}, nil, fmt.Errorf("read pending chain: %v", err)
	}
	return *match, chain, nil
}

// ApproveAuthority trusts the CA(s) from a pending cert's chain.
func (s *Store) ApproveAuthority(fpPrefix string) (Entry, error) {
	match, chain, err := s.findPending(fpPrefix)
	if err != nil {
		return Entry{}, err
	}
	var cas []*x509.Certificate
	for _, c := range chain {
		if c.IsCA {
			cas = append(cas, c)
		}
	}
	if len(cas) == 0 {
		return Entry{}, fmt.Errorf("client presented no CA in its chain; place the issuing CA PEM in %s directly", s.authoritiesDir)
	}
	for _, ca := range cas {
		if err := writeCert(filepath.Join(s.authoritiesDir, certFileName(ca)), ca); err != nil {
			return Entry{}, err
		}
	}
	_ = os.Remove(match.Path)
	return match, nil
}

// Pin adds a pending leaf as an exact pin.
func (s *Store) Pin(fpPrefix string) (Entry, error) {
	match, chain, err := s.findPending(fpPrefix)
	if err != nil {
		return Entry{}, err
	}
	if err := writeCert(filepath.Join(s.pinnedDir, certFileName(chain[0])), chain[0]); err != nil {
		return Entry{}, err
	}
	_ = os.Remove(match.Path)
	return match, nil
}

// --- helpers ---

var slugRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func certFileName(c *x509.Certificate) string {
	slug := strings.Trim(slugRe.ReplaceAllString(c.Subject.CommonName, "-"), "-")
	if slug == "" {
		slug = "cert"
	}
	kind := "leaf"
	if c.IsCA {
		kind = "ca"
	}
	return fmt.Sprintf("%s.%s.%s.pem", slug, kind, fingerprint(c)[:12])
}

func writeCert(path string, c *x509.Certificate) error {
	var buf strings.Builder
	if err := pem.Encode(&stringBuilderWriter{&buf}, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(buf.String()), 0o600)
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func listDir(dir string) ([]Entry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		certs, err := readCertsFile(p)
		if err != nil || len(certs) == 0 {
			continue
		}
		c := certs[0]
		out = append(out, Entry{Fingerprint: fingerprint(c), CN: c.Subject.CommonName,
			Issuer: c.Issuer.CommonName, NotAfter: c.NotAfter, IsCA: c.IsCA, Path: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CN < out[j].CN })
	return out, nil
}

func readCertsDir(dir string) []*x509.Certificate {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var certs []*x509.Certificate
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		if cs, err := readCertsFile(filepath.Join(dir, e.Name())); err == nil {
			certs = append(certs, cs...)
		}
	}
	return certs
}

func readCertsFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				certs = append(certs, c)
			}
		}
	}
	return certs, nil
}

type stringBuilderWriter struct{ b *strings.Builder }

func (w *stringBuilderWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
