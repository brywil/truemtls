// Package truemtls provides the library surface for mutual-TLS termination with
// a hand-manageable, directory-based trust store — mutual TLS done properly,
// minus the operational tax. Import trust + pki (+ proxy) and drop the returned
// *tls.Config onto any net/http server to require and enforce mTLS.
package truemtls

import (
	"crypto/tls"

	"github.com/brywil/truemtls/trust"
)

// ServerTLSConfig returns a *tls.Config that mandates a client certificate and
// delegates the trust decision to the store (pinned leaf or chain to a trusted
// authority; unknown certs are queued to the store's pending directory and the
// handshake is rejected).
func ServerTLSConfig(store *trust.Store, cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert, // the trust decision is ours, in store.Verify
		VerifyPeerCertificate: store.Verify,
		MinVersion:            tls.VersionTLS12,
	}
}
