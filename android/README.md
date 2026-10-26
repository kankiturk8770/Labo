# KLINK VPN — Android client

A full-device Android VPN client for the KLINK server in [`../klink`](../klink).

It reuses the **exact same Go core** as the desktop client (same genuine
Chrome TLS fingerprint via uTLS) compiled to an Android library with gomobile,
driven by an Android `VpnService` so **all** device traffic goes through the
tunnel with no leaks.

## Architecture

```
Apps on phone ─► VpnService TUN (all IPv4+IPv6+DNS) ─► tun2socks ─► KLINK SOCKS
                                                              │ (Go core, klinkmobile.aar)
                                                              ▼
                                   genuine Chrome TLS 1.3 handshake ─► KLINK server ─► internet
```

- **`klinkmobile.aar`** — the Go core (`klink/mobile`) built with
  `gomobile bind`. Exposes `Start(fd, sub, server, session, master, sni)`,
  `Stop()`, `IsRunning()`.
- **`KlinkVpnService`** — builds the TUN with default routes for IPv4 (`0.0.0.0/0`)
  and IPv6 (`::/0`), DNS servers inside the tunnel, and excludes only this app's
  own UID (`addDisallowedApplication`) so the core's upstream sockets don't loop
  back. The TUN fd is handed to the Go core, which runs tun2socks + the KLINK
  SOCKS client in-process.
- **No leaks:** every packet (TCP, UDP, DNS) is captured by the TUN; nothing but
  this app's own traffic bypasses it.

## Build

CI (`.github/workflows/android.yml`) does the whole build on GitHub runners:
installs Go + the Android NDK, runs `gomobile bind` to produce
`app/libs/klinkmobile.aar`, then builds the APK and publishes it to a Release.

Locally (needs Android SDK + NDK + Go):

```bash
cd klink
gomobile bind -target=android/arm64 -androidapi 24 -o ../android/app/libs/klinkmobile.aar ./mobile
cd ../android
./gradlew :app:assembleDebug
```

> Current builds target **arm64** devices (virtually all modern phones).

## Use

1. In the KLINK panel, create a user and copy its subscription link
   (`https://SERVER:8443/sub/TOKEN`).
2. Paste it into the app and tap **اتصال** (Connect). Accept the Android VPN
   consent dialog. All traffic now flows through KLINK.
3. The manual fields (server/session/master/SNI) are an alternative to the link.

## Device leak checklist (please verify on your phone)

I cannot run this on a real device from here, so after installing, confirm:
- With VPN on, visit an IP-check site → shows the **server** IP, not yours.
- A DNS-leak test shows no local ISP resolver.
- Toggle airplane/Wi-Fi/mobile → traffic stays inside the tunnel or stops (no leak).
