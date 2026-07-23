// Package proxy is a transparent reverse proxy. It forwards every incoming
// request — method, path, query, headers, cookies, and body — to a backend
// unchanged. Its only job is to be the mandatory-mTLS front door for a backend
// that speaks plain HTTP, with zero backend changes.
package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
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

// New returns a transparent reverse-proxy handler targeting backend. It is the
// server side of truemtls: place it behind ServerTLSConfig so clients must
// present a trusted certificate, and it forwards to a plain-HTTP backend on the
// same host.
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
