// Command truemtls is a transparent reverse proxy that adds mandatory mutual TLS
// in front of any plain-HTTP backend, with a hand-manageable directory trust
// store and TOFU-style out-of-band approval. See github.com/brywil/truemtls.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
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

	handler := proxy.New(burl, proxy.Options{
		IdentityHeader:  *idHeader,
		XForwarded:      !*noXFwd,
		PreserveHost:    true,
		BackendInsecure: *backendInsecure,
	})
	srv := &http.Server{
		Addr:      *listen,
		Handler:   handler,
		TLSConfig: truemtls.ServerTLSConfig(store, cert),
	}
	log.Printf("truemtls %s: mTLS on https://%s  ->  %s", version, *listen, *backend)
	log.Printf("trust dir: %s", trustDir)
	return srv.ListenAndServeTLS("", "")
}

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
