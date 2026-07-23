// Command truemtls is a transparent reverse proxy that adds mandatory mutual TLS
// in front of any plain-HTTP backend, with a hand-manageable directory trust
// store and TOFU-style out-of-band approval. See github.com/brywil/truemtls.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/brywil/truemtls"
	"github.com/brywil/truemtls/pki"
	"github.com/brywil/truemtls/proxy"
	"github.com/brywil/truemtls/trust"
)

const version = "0.1.0"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "trust":
		err = runTrust(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `truemtls — transparent mutual-TLS front door for any HTTP backend

usage:
  truemtls serve --backend URL [flags]      require mTLS, transparently proxy to backend
  truemtls trust list                       show authorities, pins, and pending
  truemtls trust approve authority <fp>     trust the CA from a pending cert
  truemtls trust pin <fp>                   pin a pending leaf (ad-hoc, no CA)

serve flags:
  --backend URL         backend to forward to (e.g. http://127.0.0.1:8080)   [required]
  --listen ADDR         listen address (default 0.0.0.0:8443)
  --config-dir DIR      config dir (default ~/.config/truemtls)
  --client-ca FILES     comma-separated CA PEM files always trusted
  --client-id-header H  inject the client CN under header H (stripped from inbound first)
  --no-xforwarded       do not add X-Forwarded-* headers
  --backend-insecure    skip TLS verification to an https backend
  --approval-page       serve a 403 "pending approval" page to unapproved certs
                        instead of rejecting them at the TLS handshake
`)
}

func defaultConfigDir() string {
	if c, err := os.UserConfigDir(); err == nil {
		return filepath.Join(c, "truemtls")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "truemtls")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	backend := fs.String("backend", "", "backend URL to forward to (required)")
	listen := fs.String("listen", "0.0.0.0:8443", "listen address")
	configDir := fs.String("config-dir", defaultConfigDir(), "config directory")
	clientCA := fs.String("client-ca", "", "comma-separated CA PEM files (always trusted)")
	idHeader := fs.String("client-id-header", "", "inject client CN under this header")
	noXFwd := fs.Bool("no-xforwarded", false, "do not add X-Forwarded-* headers")
	backendInsecure := fs.Bool("backend-insecure", false, "skip TLS verify to https backend")
	serverCert := fs.String("server-cert", "", "server cert PEM (default <config-dir>/server.crt)")
	serverKey := fs.String("server-key", "", "server key PEM (default <config-dir>/server.key)")
	approvalPage := fs.Bool("approval-page", false, "on an unapproved client cert, serve a 403 'pending approval' page instead of rejecting at the TLS handshake")
	_ = fs.Parse(args)

	if *backend == "" {
		return fmt.Errorf("--backend is required (e.g. http://127.0.0.1:8080)")
	}
	burl, err := url.Parse(*backend)
	if err != nil || burl.Host == "" {
		return fmt.Errorf("invalid --backend %q", *backend)
	}
	trustDir := filepath.Join(*configDir, "trust")
	if *serverCert == "" {
		*serverCert = filepath.Join(*configDir, "server.crt")
	}
	if *serverKey == "" {
		*serverKey = filepath.Join(*configDir, "server.key")
	}

	store, err := trust.Load(trustDir, splitCSV(*clientCA), log.Default())
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(*listen)
	if err := pki.EnsureServerCert(*serverCert, *serverKey, serverHosts(host)); err != nil {
		return fmt.Errorf("server cert: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		return err
	}

	// The transparent proxy itself stays pure (untouched forwarder).
	var handler http.Handler = proxy.New(burl, proxy.Options{
		IdentityHeader:  *idHeader,
		XForwarded:      !*noXFwd,
		PreserveHost:    true,
		BackendInsecure: *backendInsecure,
	})

	// Strict (default): unapproved certs are rejected at the TLS handshake.
	// Approval-page: the handshake completes for any client cert and the trust
	// decision is made per-request, serving a friendly 403 to clients not on the
	// approved list. Either way, only approved clients ever reach the backend.
	var tlsConf *tls.Config
	if *approvalPage {
		handler = approvalGate(store, handler)
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		tlsConf = truemtls.ServerTLSConfig(store, cert)
	}

	mode := "strict (reject at handshake)"
	if *approvalPage {
		mode = "approval-page"
	}
	srv := &http.Server{Addr: *listen, Handler: handler, TLSConfig: tlsConf}
	log.Printf("truemtls %s: mTLS on https://%s  ->  %s  [%s]", version, *listen, *backend, mode)
	log.Printf("trust dir: %s", trustDir)
	return srv.ListenAndServeTLS("", "")
}

// approvalGate serves a "pending approval" page to clients whose certificate is
// not on the approved list, and forwards approved clients to next. An unapproved
// client never reaches the backend.
func approvalGate(store *trust.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		if dec := store.Check(r.TLS.PeerCertificates); dec.Trusted {
			next.ServeHTTP(w, r)
		} else {
			writeApprovalPage(w, dec)
		}
	})
}

func writeApprovalPage(w http.ResponseWriter, dec trust.Decision) {
	cn := dec.CN
	if cn == "" {
		cn = "(certificate has no Common Name)"
	}
	short := dec.Fingerprint
	if len(short) > 16 {
		short = short[:16]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, approvalHTML, html.EscapeString(cn), html.EscapeString(short), html.EscapeString(dec.Fingerprint))
}

const approvalHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approval required</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1.5rem;line-height:1.6;color:#1a1a1a}
  h1{font-size:1.5rem;margin-bottom:.5rem}
  .box{background:#f4f4f5;border-radius:.5rem;padding:.5rem .75rem;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
  .id{font-size:1.15rem;font-weight:600}
  .muted{color:#666;font-size:.9rem}
  @media (prefers-color-scheme:dark){body{color:#e5e5e5;background:#0f0f10}.box{background:#1c1c1f}.muted{color:#9a9a9a}}
</style></head><body>
<h1>Approval required</h1>
<p>You are authenticated as:</p>
<p class="box id">%s</p>
<p>&hellip;but you are <strong>not on the approved list</strong> for this service yet.</p>
<p>Ask your system administrator to approve you, and give them this certificate fingerprint:</p>
<p class="box id">%s</p>
<p class="muted">Full SHA-256 fingerprint:</p>
<p class="box muted">%s</p>
</body></html>
`

func runTrust(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: truemtls trust <list|approve|pin> ...")
	}
	trustDir := filepath.Join(configDirFromEnv(), "trust")
	store, err := trust.Load(trustDir, nil, log.Default())
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		auth, _ := store.Authorities()
		pins, _ := store.Pins()
		pend, _ := store.Pending()
		for _, s := range []struct {
			title string
			es    []trust.Entry
		}{{"authorities", auth}, {"pinned", pins}, {"pending", pend}} {
			fmt.Printf("%s (%d):\n", s.title, len(s.es))
			for _, e := range s.es {
				fmt.Printf("  %-16s cn=%q issuer=%q ca=%v\n", e.Fingerprint[:16], e.CN, e.Issuer, e.IsCA)
			}
		}
		return nil
	case "approve":
		if len(args) != 3 || args[1] != "authority" {
			return fmt.Errorf("usage: truemtls trust approve authority <fp>")
		}
		e, err := store.ApproveAuthority(args[2])
		if err != nil {
			return err
		}
		fmt.Printf("trusted authority from pending cert cn=%q (%s)\n", e.CN, e.Fingerprint[:16])
		return nil
	case "pin":
		if len(args) != 2 {
			return fmt.Errorf("usage: truemtls trust pin <fp>")
		}
		e, err := store.Pin(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("pinned leaf cn=%q (%s)\n", e.CN, e.Fingerprint[:16])
		return nil
	default:
		return fmt.Errorf("unknown: trust %s", args[0])
	}
}

func configDirFromEnv() string {
	if d := os.Getenv("TRUEMTLS_CONFIG_DIR"); d != "" {
		return d
	}
	return defaultConfigDir()
}

func serverHosts(addrHost string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, _ := os.Hostname(); h != "" {
		hosts = append(hosts, h)
	}
	if addrHost != "" && addrHost != "0.0.0.0" && addrHost != "::" {
		hosts = append(hosts, addrHost)
	}
	if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			if ipnet, ok := a.(*net.IPNet); ok {
				hosts = append(hosts, ipnet.IP.String())
			}
		}
	}
	return hosts
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
