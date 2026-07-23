package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/brywil/truemtls/internal/testca"
	"github.com/brywil/truemtls/proxy"
)

func TestTransparentPassthrough(t *testing.T) {
	testca.RequireLoopback(t)
	var (
		gotMethod, gotPath, gotHeader, gotCookie, gotBody string
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		gotHeader = r.Header.Get("X-Test")
		if c, err := r.Cookie("s"); err == nil {
			gotCookie = c.Value
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "backend-ok")
	}))
	defer backend.Close()

	burl, _ := url.Parse(backend.URL)
	front := httptest.NewServer(proxy.New(burl, proxy.Options{XForwarded: true, PreserveHost: true}))
	defer front.Close()

	req, _ := http.NewRequest("POST", front.URL+"/api/v1/thing?q=42&sort=asc", strings.NewReader("hello-body"))
	req.Header.Set("X-Test", "hello-world")
	req.AddCookie(&http.Cookie{Name: "s", Value: "abc123"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if gotMethod != "POST" {
		t.Errorf("method: got %q", gotMethod)
	}
	if gotPath != "/api/v1/thing?q=42&sort=asc" {
		t.Errorf("path+query: got %q", gotPath)
	}
	if gotHeader != "hello-world" {
		t.Errorf("header X-Test: got %q", gotHeader)
	}
	if gotCookie != "abc123" {
		t.Errorf("cookie: got %q", gotCookie)
	}
	if gotBody != "hello-body" {
		t.Errorf("body: got %q", gotBody)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status: got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Backend") != "yes" {
		t.Errorf("response header not passed through")
	}
	if string(respBody) != "backend-ok" {
		t.Errorf("response body: got %q", respBody)
	}
}

func TestIdentityHeaderStrippedWhenNoClientCert(t *testing.T) {
	testca.RequireLoopback(t)
	var seen string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Client-CN")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	burl, _ := url.Parse(backend.URL)
	front := httptest.NewServer(proxy.New(burl, proxy.Options{IdentityHeader: "X-Client-CN"}))
	defer front.Close()

	// A client tries to spoof the identity header over plain HTTP (no client cert).
	req, _ := http.NewRequest("GET", front.URL, nil)
	req.Header.Set("X-Client-CN", "attacker")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seen != "" {
		t.Fatalf("spoofed identity header must be stripped; backend saw %q", seen)
	}
}
