# Verification report — 2026-10-24

Environment: Linux amd64, Go 1.27.3, Python 3.12.14, OpenSSL, Chrome Headless
Shell 156.0.8078.47 driven by Playwright.

## Passed

| Check | Result |
|---|---|
| Original source byte comparison against uploaded ZIP | Exact match |
| Go unit tests with race detector | 8 test functions, including 10 signature subcases, passed |
| AST comparison of protected original functions | Passed |
| `go vet ./...` | Passed |
| Build current and original executables | Passed |
| Python management/API tests | 22 tests passed |
| Real HTTPS original/current comparison | 6 cases matched for status and observed routing, body bytes and selected headers |
| Actual executable `--check-config` | Valid input accepted; invalid header limit rejected |
| JavaScript syntax / shell syntax | Passed |
| Browser workflow at 1440px and 390px | Login, 18 controls, validation, apply, history rollback, logs, source, invalid-secret handling, reload and logout passed |
| Browser console | No uncaught page errors in the exercised workflow |
| Mobile layout | No horizontal document overflow at 390px; screenshots visually inspected |

Original SHA256:

```text
41cb1b87dbba32a27f1282a5a08a502b6b04955d71fa544a2fe184df900e5b9b
```

Go tests exercise HMAC timestamp validity and tampering, optional signature prefix,
round-robin/fallback routing, request/response body preservation, credential header
stripping, forwarding metadata, bidirectional upgraded bytes, streaming response
flush, defaults and invalid configuration.

Python tests exercise schema coverage, env escaping/roundtrip, forbidden inputs,
secret redaction, success/failure apply, rollback of running/stopped service state,
failed rollback journal retention, crash recovery, backups, certificates, file
modes, path traversal, concurrency, credential verification, Host/Origin checks,
CSRF enforcement, session logout and login rate limiting.

The real HTTPS comparison starts both original and extended Go binaries against
local backends with the same toolchain. Cases: two successive authenticated
requests, bad signature, expired signature, no signature, then another valid
request. The binary tests also cover configuration preflight.

The browser workflow uses the explicitly labelled **demo service adapter**;
service operations there are simulated. HTTP authentication, forms and API
requests are real. Screenshots are internal QA, not bundled deliverables.

## Not verified in this environment

- A complete apt/systemd installation on a real Ubuntu/Debian server. This
  container does not run systemd as PID 1. Unit syntax was inspected with
  `systemd-analyze verify`; the uninstalled target executable was reported as
  absent, as expected. This is not a live service verification.
- External firewall/routing, production TLS issuance/renewal, Android transport,
  real-world availability, network censorship conditions or a sustained load test.
- Docker image build/run and an actual arm64 installation.
- The optional public HTTPS management deployment, after a server operator has
  chosen a hostname/certificate/firewall configuration.
- GitHub Actions have been supplied, not run on a published repository. The
  manual-dispatch job provides the next actual Ubuntu installation smoke check.

Tests establish the listed behavior; they do not prove absence of all bugs or
exact wire-byte identity under every protocol/network condition. The gateway's
original standard reverse-proxy handling of hop-by-hop headers is retained.

## Commands

```bash
go test -race -v ./...
go vet ./...
python3 -m unittest discover -s tests -v
go build -buildvcs=false -o /tmp/edge-current .
go build -buildvcs=false -o /tmp/edge-original ./original
python3 tests/integration_gateway.py /tmp/edge-original /tmp/edge-current
bash -n install.sh bootstrap.sh
node --check panel/static/app.js
# Optional, with Playwright installed:
CHROME_PATH=/path/to/chromium node tests/browser-smoke.cjs
```
