# truemtls

**Mutual TLS done properly — minus the operational tax.**

`truemtls` puts mandatory mutual TLS in front of any HTTP service, with a trust
model you administer by moving PEM files around instead of running a CA
appliance. It is a **transparent reverse proxy** and a small **Go library**,
with zero third-party dependencies (Go stdlib only).

- **Transparent** — forwards method, path, query, headers, cookies, and body
  unchanged. Your backend speaks plain HTTP and needs no changes.
- **Mandatory mTLS** — every connection must present a client certificate that
  is pinned or chains to a trusted authority, or the TLS handshake is rejected.
- **Hand-manageable trust** — trusted CAs and pins are just `.pem` files in a
  directory. Trust one by dropping it in; revoke it by deleting it.
- **TOFU approval** — an unknown client cert is captured to a pending queue and
  rejected; you approve it out of band (`truemtls trust approve …`), then it
  works. Like `known_hosts`, for client CAs.

## Prerequisites: a working Go environment

> If you don't do Go development day to day, read this first — it's the #1
> reason a freshly `go install`ed tool reports "command not found".

`go install` writes binaries to `$GOBIN` (or `$GOPATH/bin` when `GOBIN` is
unset). If that directory isn't on your `PATH`, the installed `truemtls` (and
`task`, below) exist but your shell can't find them. Set this up once in
`~/.bashrc`:

```bash
export GOROOT=/usr/local/go            # the Go toolchain (provides `go`)
export GOPATH="$HOME/go"               # your Go workspace (module cache, etc.)
export GOBIN="$GOPATH/bin"             # where `go install` puts binaries
export PATH="$GOROOT/bin:$GOPATH/bin:$HOME/.local/bin:$PATH"
```

Then reload and verify:

```bash
source ~/.bashrc
go env GOROOT GOPATH GOBIN
```

- **`GOROOT`** — where the toolchain lives. Usually auto-detected; set it only
  if `go` isn't already on your `PATH`.
- **`GOPATH`** — your workspace, default `~/go`.
- **`GOBIN`** — where `go install` drops binaries. **This is the one that must
  be on `PATH`**, or nothing you install is runnable.

If `~/.bashrc` already has Go lines, edit those instead of adding duplicates.

## Install

```bash
go install github.com/brywil/truemtls/cmd/truemtls@latest
```

## Quick start

Front a service listening on `127.0.0.1:8080` with mandatory mTLS on `:8443`:

```bash
truemtls serve --backend http://127.0.0.1:8080 --listen 0.0.0.0:8443
```

On first connect, an untrusted client is rejected and queued:

```bash
truemtls trust list                       # see the pending cert + fingerprint
truemtls trust approve authority <fp>     # trust its issuing CA, or…
truemtls trust pin <fp>                    # …pin just that one leaf certificate
```

To trust an existing corporate CA up front, either drop its PEM into
`~/.config/truemtls/trust/authorities/` or pass `--client-ca /path/to/ca.pem`.

## Trust model

```
~/.config/truemtls/trust/
  authorities/   trusted CA certs (one PEM per CA) — a client chaining to any is authenticated
  pinned/        exact leaf certs — self-authenticating, no CA needed
  pending/       unknown certs captured at handshake, awaiting approval
```

Everything is a file. There is no database and no daemon state to back up.

## Optional flags

| Flag | Meaning |
|------|---------|
| `--client-ca FILES` | comma-separated CA PEMs to trust in addition to the directory |
| `--client-id-header H` | set header `H` to the verified client CN before forwarding (any inbound value is stripped first, so it can't be spoofed) |
| `--no-xforwarded` | do not add `X-Forwarded-*` headers (byte-for-byte transparency) |
| `--backend-insecure` | skip TLS verification to an `https` backend |

The server provisions its own self-signed server certificate on first run
(`~/.config/truemtls/server.{crt,key}`); replace those files to use your own.

## Library use

```go
store, _ := trust.Load("~/.config/truemtls/trust", nil, log.Default())
cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")

srv := &http.Server{
    Addr:      ":8443",
    Handler:   myHandler,
    TLSConfig: truemtls.ServerTLSConfig(store, cert), // requires + enforces mTLS
}
srv.ListenAndServeTLS("", "")
```

`store.Verify` is a drop-in `tls.Config.VerifyPeerCertificate`: unknown certs are
queued to `pending/` and rejected; trusted ones pass. Authorization (what an
authenticated principal may *do*) is intentionally out of scope — layer it on top
by the client-cert CN. (See [`mymcp`](https://github.com/brywil/mymcp) for an
example that gates MCP tools per CN.)

## Build & run as a user service

With [go-task](https://taskfile.dev/) — install it with
`go install github.com/go-task/task/v3/cmd/task@latest` (it lands in `$GOBIN`;
see [Prerequisites](#prerequisites-a-working-go-environment)):

```bash
task build            # -> build/truemtls
task test             # go test ./...
task install          # -> ~/.local/bin/truemtls
task install-unit     # systemd --user service (no sudo); enables but doesn't start
# edit ~/.config/truemtls/truemtls.env (BACKEND, LISTEN), then:
systemctl --user start truemtls
task deploy           # build + test + install + restart the user service if present
```

Everything is per-user: the binary lands in `~/.local/bin`, the unit in
`~/.config/systemd/user/`, config in `~/.config/truemtls/`. No root required.

## Security notes

- Because a CN may be honored regardless of which trusted CA issued the cert (a
  common desire so re-issuing a user's token/CAC does not require re-onboarding),
  **only put CAs you control in `authorities/`** — any of them can assert a CN.
- A pinned leaf is trusted by exact certificate bytes; its validity window is
  still enforced, but it is not tied to any issuer.
- mTLS is **mandatory**: there is no unauthenticated mode.

## Status

Early but working: transparent proxy, directory trust store, TOFU approval, and
the library API are implemented and tested. MIT licensed.
