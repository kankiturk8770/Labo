# Labo

Anti-censorship tunnel components.

- **[`klink/`](klink/)** — **KLINK v2**, the full server core with a web control
  panel. Installs on a fresh Ubuntu server with one command and is then driven
  entirely from the panel (live SNI/decoy switching, TLS certificate mirroring,
  upstream tunnel, anti-probe test, and user/subscription management). Includes
  the Go server and client. See [`klink/README.md`](klink/README.md) and
  [`klink/COMMANDS.txt`](klink/COMMANDS.txt).

  **One-command install:**
  ```bash
  git clone https://github.com/kankiturk8770/Labo.git && cd Labo/klink && sudo bash install.sh
  ```
  Panel: `http://SERVER_IP:8443`

- **[`server/`](server/)** — the earlier edge-gateway (HMAC-authenticated,
  decoy-routing reverse proxy) + Persian RTL panel. Kept for reference.

- **[`android/`](android/)** — an Android `VpnService` client built for the
  edge-gateway's HMAC contract. The CI in `.github/workflows/android.yml` builds
  its APK on every change and publishes it to a GitHub Release.
