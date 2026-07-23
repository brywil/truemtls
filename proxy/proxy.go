// Package proxy is a transparent reverse proxy. It forwards every incoming
// request — method, path, query, headers, cookies, and body — to a backend
// unchanged. Its only job is to be the mandatory-mTLS front door for a backend
// that speaks plain HTTP, with zero backend changes.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

// Options tunes the proxy behavior.
type Options struct {
	// IdentityHeader, if non-empty, is set to the authenticated client
	// certificate CN before forwarding — and first stripped from the inbound
	// request so a client cannot spoof it. Empty means inject nothing (fully
	// transparent).
	IdentityHeader string

	// XForwarded adds X-Forwarded-For/Host/Proto headers. Default true.
	XForwarded bool

	// PreserveHost forwards the client's Host header to the backend instead of
	// rewriting it to the backend's host. Default true (transparent).
	PreserveHost bool

	// BackendInsecure skips TLS verification when the backend URL is https.
	BackendInsecure bool
}

// New returns a transparent reverse-proxy handler targeting backend.
func New(backend *url.URL, opts Options) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend) // backend scheme+host; path = backend.Path + inbound path, query merged
			if opts.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			if opts.XForwarded {
				pr.SetXForwarded()
			}
			if opts.IdentityHeader != "" {
				pr.Out.Header.Del(opts.IdentityHeader) // anti-spoof: never trust an inbound value
				if cn := clientCN(pr.In); cn != "" {
					pr.Out.Header.Set(opts.IdentityHeader, cn)
				}
			}
		},
		// Flush immediately so SSE / streaming / chunked responses pass through
		// without buffering. ReverseProxy handles WebSocket upgrades natively.
		FlushInterval: -1,
	}
	if backend.Scheme == "https" && opts.BackendInsecure {
		rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return rp
}

func clientCN(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// ClientOptions configures the client-side (sidecar) proxy.
type ClientOptions struct {
	// ClientCertFile/ClientKeyFile is the client certificate this sidecar
	// presents to the upstream (its mTLS identity).
	ClientCertFile string
	ClientKeyFile  string
	// ServerCAFile verifies the upstream server certificate. Empty uses the
	// system roots (unless Insecure).
	ServerCAFile string
	// Insecure skips upstream server verification (self-signed servers in dev).
	Insecure bool
	// PreserveHost forwards the caller's Host header. Default caller sets it.
	PreserveHost bool
}

// Client returns a transparent reverse proxy that originates an mTLS connection
// to upstream, presenting the configured client certificate. It is the
// client-side counterpart to New: run it on the client host listening on plain
// localhost HTTP, so any client (a browser, a CLI) can reach an mTLS-protected
// upstream with no mTLS support of its own.
func Client(upstream *url.URL, o ClientOptions) (http.Handler, error) {
	tlsc := &tls.Config{InsecureSkipVerify: o.Insecure, MinVersion: tls.VersionTLS12}
	if o.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(o.ClientCertFile, o.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("client cert: %w", err)
		}
		tlsc.Certificates = []tls.Certificate{cert}
	}
	if o.ServerCAFile != "" {
		pemBytes, err := os.ReadFile(o.ServerCAFile)
		if err != nil {
			return nil, fmt.Errorf("server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("server CA %q: no certificates parsed", o.ServerCAFile)
		}
		tlsc.RootCAs = pool
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			if o.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			pr.SetXForwarded()
		},
		Transport:     &http.Transport{TLSClientConfig: tlsc},
		FlushInterval: -1,
	}
	return rp, nil
}
