# Labo

Two components that together form an authenticated, decoy-routed tunnel:

- **[`server/`](server/)** — the Linux edge gateway + Persian RTL control panel,
  installer, systemd units, and tests. An HMAC-authenticated reverse proxy:
  signed requests are routed to internal backends, everything else is proxied to
  a decoy origin. See [`server/README.md`](server/README.md) and the Persian
  guide [`server/README-FA.md`](server/README-FA.md).

- **[`android/`](android/)** — a complete Android `VpnService` client that speaks
  the gateway's exact HMAC signing contract, opens an authenticated WebSocket
  tunnel, and relays device traffic through it. See
  [`android/README.md`](android/README.md).

The HMAC signing contract is the interop boundary between the two, and the
Android unit tests pin the client output to the server's own test vectors.
