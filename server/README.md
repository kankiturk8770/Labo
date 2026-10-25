# Edge Gateway + Control Panel

A complete source package for an Ubuntu/Debian systemd deployment: the supplied
Go gateway, a Persian RTL management panel, installer, recovery journal, and tests.

**Start here: [راهنمای فارسی نصب و استفاده](README-FA.md).**

## Quick installation

Upload/extract this repository on a fresh Ubuntu/Debian server, then:

```bash
sudo bash install.sh
```

From your own computer, keep an SSH tunnel open:

```bash
ssh -L 9090:127.0.0.1:9090 USER@SERVER_IP
```

Open `http://127.0.0.1:9090`. Read the generated initial password on the server:

```bash
sudo cat /root/edge-panel-credentials.txt
```

The installer fetches the current stable Go toolchain from `go.dev`, checks its
published SHA256, builds/tests the source and installs both systemd units. The
panel starts immediately; the gateway starts **only after valid settings are
applied** in the panel. Import a trusted certificate, set your real decoy origin
and internal backends, then validate/apply. The installer creates only a short-lived
self-signed localhost certificate for initial testing.

Default panel access is local HTTP through SSH, never public plaintext HTTP.
The gateway itself always serves HTTPS. No firewall rules are changed.

## Preservation contract

`original/main.go` is byte-for-byte the uploaded source. The production
`main.go` changes only startup validation and replacement of operational constants
with typed settings from `tuning.go`. Original defaults are preserved. AST tests
compare the original authentication, routing, reverse-proxy and config parsing
functions. No change to the canonical HMAC string, fallback decision,
round-robin selection, WebSocket forwarding or credential header removal.

Nine original environment settings plus nine new tuning settings are exposed.
The routing algorithm and signing contract are deliberately not editable code in
the browser. This remains a gateway; it does not add a VPN tunnel or Android client.

## Tests

Go >=1.22; Python >=3.10; OpenSSL; no third-party Python or Go dependencies.

```bash
go test -race -v ./...
go vet ./...
python3 -m unittest discover -s tests -v
go build -buildvcs=false -o /tmp/edge-current .
go build -buildvcs=false -o /tmp/edge-original ./original
python3 tests/integration_gateway.py /tmp/edge-original /tmp/edge-current
```

`go run .` includes the companion tuning module. **Do not use `go run main.go`**
with the new version, because that omits `tuning.go`.

Preview the UI locally without systemd:

```bash
python3 scripts/demo.py
```

The generated demo password is printed. Demo state is separate; its status is
simulated, and it never starts/stops real services. Node and Playwright are only
needed for the optional browser smoke test, not for installation.

## Repository installation

Publish the **contents** of this directory as the repository root. Then on the server:

```bash
git clone https://github.com/YOUR_ACCOUNT/YOUR_REPO.git
cd YOUR_REPO
# Select the reviewed commit/tag before installation.
git checkout YOUR_TAG_OR_COMMIT
sudo bash install.sh
```

`bootstrap.sh` also accepts an HTTPS GitHub repository and a reviewed ref. No
repository has been created or published by this package. GitHub Actions checks
are supplied; the optional actual installation job runs on manual dispatch.

See `TEST-REPORT.md` for executed checks and deployment limitations.
