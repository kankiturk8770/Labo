# Edge Gateway

A standard-library-only Go edge gateway with HTTPS termination, HMAC-SHA-256 request validation, round-robin internal routing, public-origin fallback, streaming responses, WebSocket proxying, and graceful shutdown.

## Requirements

- Go 1.22 or newer for source builds.
- A TLS certificate and private key for the gateway.
- One or more reachable internal backends.
- An HTTPS decoy origin. Plain HTTP is accepted only when `EDGE_ALLOW_INSECURE_DECOY=true` for local testing.

## Project files

- `main.go`: complete gateway implementation.
- `go.mod`: Go module definition.
- `Dockerfile`: multi-stage container build.
- `deploy/edge-gateway.env.example`: configuration template.
- `deploy/edge-gateway.service`: systemd unit.

## Build

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o edge-gateway .
```

No third-party Go dependencies are required.

## Local test setup

Generate a self-signed certificate for local testing only:

```bash
openssl req -x509 \
  -newkey rsa:2048 \
  -nodes \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Configure and run:

```bash
export EDGE_HMAC_SECRET="$(openssl rand -hex 32)"
export EDGE_ADDR=":8443"
export EDGE_CERT_FILE="$PWD/cert.pem"
export EDGE_KEY_FILE="$PWD/key.pem"
export EDGE_DECOY_ORIGIN="https://target-decoy-domain.com"
export EDGE_INTERNAL_BACKENDS="http://127.0.0.1:8081,http://127.0.0.1:8082"

./edge-gateway
```

The internal services must already be running. Use a publicly trusted gateway certificate in production.

## Authenticated requests

The signature is the lowercase hexadecimal HMAC-SHA-256 of:

```text
<unix-timestamp>\n<HTTP-method>\n<request-URI>\n<Sec-WebSocket-Key-or-empty>
```

Send the timestamp in `X-Signature-Timestamp` and the signature in `X-Signature`. The optional `sha256=` signature prefix is accepted.

Example for `GET /`:

```bash
TS="$(date +%s)"
SIG="$(
  printf '%s\n%s\n%s\n%s' "$TS" "GET" "/" "" |
    openssl dgst -sha256 -hmac "$EDGE_HMAC_SECRET" -hex |
    awk '{print $NF}'
)"

curl --insecure \
  "https://localhost:8443/" \
  -H "X-Signature-Timestamp: $TS" \
  -H "X-Signature: $SIG"
```

For `/chat?room=1`, sign that exact request URI instead of `/`. Missing, expired, malformed, or invalid signatures are routed to the decoy origin.

## Docker

```bash
docker build -t edge-gateway:latest .
cp deploy/edge-gateway.env.example edge-gateway.env
```

Edit `edge-gateway.env`, setting the HMAC secret, decoy origin, and container-reachable backend addresses. Set these TLS paths in that file:

```bash
EDGE_CERT_FILE=/tls/tls.crt
EDGE_KEY_FILE=/tls/tls.key
```

Run:

```bash
docker run --rm \
  --name edge-gateway \
  --env-file edge-gateway.env \
  -p 8443:8443 \
  -v "$PWD/cert.pem:/tls/tls.crt:ro" \
  -v "$PWD/key.pem:/tls/tls.key:ro" \
  edge-gateway:latest
```

Do not use `127.0.0.1` for backends running on the Docker host; use a host or service-network address reachable from the container.

## systemd deployment

Build and install:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o edge-gateway .

sudo useradd --system --home /opt/edge-gateway \
  --shell /usr/sbin/nologin edge-gateway 2>/dev/null || true

sudo mkdir -p /opt/edge-gateway /etc/edge-gateway
sudo cp edge-gateway /opt/edge-gateway/edge-gateway
sudo chown root:edge-gateway /opt/edge-gateway/edge-gateway
sudo chmod 0750 /opt/edge-gateway/edge-gateway

sudo cp cert.pem /etc/edge-gateway/tls.crt
sudo cp key.pem /etc/edge-gateway/tls.key
sudo chown root:edge-gateway /etc/edge-gateway/tls.crt
sudo chown root:edge-gateway /etc/edge-gateway/tls.key
sudo chmod 0644 /etc/edge-gateway/tls.crt
sudo chmod 0640 /etc/edge-gateway/tls.key

sudo cp deploy/edge-gateway.env.example /etc/edge-gateway/edge-gateway.env
sudo chown root:edge-gateway /etc/edge-gateway/edge-gateway.env
sudo chmod 0640 /etc/edge-gateway/edge-gateway.env
sudo editor /etc/edge-gateway/edge-gateway.env

sudo cp deploy/edge-gateway.service /etc/systemd/system/edge-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now edge-gateway
sudo systemctl status edge-gateway
sudo journalctl -u edge-gateway -f
```

For upgrades, replace `/opt/edge-gateway/edge-gateway` and run:

```bash
sudo systemctl restart edge-gateway
```

## Operational notes

- The gateway validates signatures for routing; it does not sign or verify HTTP request bodies.
- Timestamps limit signature lifetime but do not provide a server-side replay cache within the allowed time window.
- Response application content is not modified. Standard HTTP proxy processing still removes hop-by-hop headers as required.
- WebSocket upgrades and bidirectional traffic are handled by `httputil.ReverseProxy`.
- Browser WebSocket APIs cannot set arbitrary `X-Signature` headers. Browser deployments need another credential carrier, such as a short-lived ticket in an allowed WebSocket subprotocol.
- Certificate private keys and environment files containing secrets must remain access-controlled.
