# Edge VPN — Android client

A complete Android `VpnService` client for the edge gateway in [`../server`](../server).
It authenticates to the gateway with the gateway's exact HMAC contract, opens an
authenticated WebSocket tunnel, and relays all device IP traffic through it.

The gateway is a decoy-routing reverse proxy: a request carrying a valid
`X-Signature` / `X-Signature-Timestamp` pair is forwarded to an internal
backend, and everything else is transparently proxied to a decoy origin so the
endpoint looks like an ordinary website to probes. This client produces exactly
that signed credential and never changes the routing or signing contract — those
remain server-side.

## What's implemented

| Layer | File | Status |
|-------|------|--------|
| HMAC signing (gateway contract) | `Signer.kt` | Complete, unit-tested against the server's own test vectors |
| TLS with SNI / fronting | `Tls.kt` | Complete |
| Signed reachability probe | `GatewayProbe.kt` | Complete |
| Authenticated WebSocket tunnel (RFC 6455, client-masked, owns `Sec-WebSocket-Key`) | `GatewayTunnel.kt` | Complete |
| L3 packet relay (TUN ⇄ tunnel) | `PacketBridge.kt` | Complete |
| `VpnService` (TUN setup, reconnect/backoff, foreground notification) | `EdgeVpnService.kt` | Complete |
| Compose UI (profile, test, connect/disconnect, live traffic) | `MainActivity.kt` | Complete |
| Encrypted-at-rest profile storage | `SettingsStore.kt` | Complete (DataStore) |

### The signing contract

The gateway (`server/main.go`, `SignatureValidator`) authenticates this
canonical byte sequence:

```
<unix-timestamp> "\n" <method> "\n" <request-uri> "\n" <Sec-WebSocket-Key>
```

`X-Signature` carries the lowercase-hex HMAC-SHA-256 of those bytes and
`X-Signature-Timestamp` the Unix-seconds timestamp. `request-uri` is the raw
(percent-encoded) path plus raw query — identical to Go's `URL.RequestURI()`.
`SignerTest.kt` pins the output to the same vectors the server's `main_test.go`
produces, so the two sides are byte-for-byte compatible.

Because the signature is bound to `Sec-WebSocket-Key`, the client performs its
own RFC 6455 handshake (OkHttp hides the key it generates), computes the HMAC
over the exact key it puts on the wire, and verifies `Sec-WebSocket-Accept`.

### Tunnel framing (L3-over-WebSocket)

Every WebSocket **binary message** carries exactly one IP packet, verbatim, with
no extra header, in both directions. The client reads packets from the Android
TUN interface and sends one message per packet; reply messages are written back
to TUN. The internal backend the gateway forwards to is expected to implement
the mirror image: decapsulate each packet, run NAT / a userspace TCP-UDP stack
against the real network, and return reply packets as one binary message each.

This keeps the Android side a faithful, self-contained L3 endpoint. Any backend
that speaks this one-packet-per-frame contract completes the data path; the
choice of backend netstack (for example a `tun2socks`-style relay, or a gVisor
netstack) is deliberately left to the server deployment and does not change the
client.

## Build

Requires Android Studio (Koala+) or the command-line SDK with:

- Android Gradle Plugin 8.5.2, Kotlin 1.9.24 (declared in `build.gradle`)
- `compileSdk` 34, `minSdk` 24
- A `local.properties` with `sdk.dir=/path/to/Android/Sdk` (not committed)

```bash
cd android
./gradlew :app:assembleDebug      # build the APK
./gradlew :app:testDebugUnitTest  # run SignerTest (contract vectors)
```

The Gradle wrapper jar is not committed; run `gradle wrapper --gradle-version 8.9`
once (or open the project in Android Studio) to generate it.

## Use

1. In the app, enter the gateway host, port, tunnel path, and the shared HMAC
   secret (the gateway's `EDGE_HMAC_SECRET`, ≥ 32 bytes). Set SNI / Host when
   fronting behind a decoy hostname.
2. Tap **Test** — a signed HTTPS request confirms TLS, reachability, and that
   the gateway accepts the credential, without starting the VPN.
3. Tap **Connect** — Android shows the system VPN consent dialog, then the
   service establishes the TUN and tunnels traffic. Live up/down counters and a
   foreground notification show status; it reconnects with backoff on drops.

**Allow insecure TLS** disables certificate verification and is only for local
testing against the installer's short-lived self-signed certificate. Leave it
off against a real deployment with a trusted certificate.
