# 1.0.0 — Management panel package

## Gateway changes

- `original/main.go`: exact original uploaded bytes, SHA256 recorded alongside it.
- `main.go`: add `--check-config`; load tuning at startup; replace nine fixed
  operational values with their validated equivalents. Existing defaults are
  unchanged. No modifications to the original routing, HMAC verification,
  reverse proxy, backend selection, config parsing or URL parsing functions.
- `tuning.go`: nine additional typed environment options.
- `Dockerfile`: compile the companion file and use a current Go build image.
  Docker runs the gateway only; the panel deployment uses systemd on the host.

## Management plane

- Responsive Persian RTL UI with 18 settings and explicit mutation confirmations.
- Service start/stop/restart, boot enable/disable, status, memory and journal view.
- TLS certificate/key pair validation and immutable imports.
- Validation through the actual Go executable before applying.
- Atomic settings writes, stale revision rejection, previous-version history,
  rollback on failed startup and recovery journal after interrupted operations.
- Configuration/certificate backups, preview-before-apply import, TCP diagnostics.
- PBKDF2 password storage, bounded sessions, HttpOnly/SameSite cookies, CSRF and
  Host/Origin checks, login attempt limits, audit trail, controlled subprocesses.
- Loopback default and SSH access; optional directly served HTTPS management.
- Ubuntu/Debian installer, official Go SHA256 verification, systemd units,
  logrotate, GitHub bootstrap and CI configuration.

## Deliberate boundaries

No Android app, TUN tunnel, VPN user accounting, auto-renewing ACME client,
public repository publication, remote deployment, arbitrary source editor or
zero-downtime restarts are claimed. Existing proxy semantics and existing core
limitations remain. All 18 gateway environment settings are exposed, rather than
arbitrary control over every operating-system or dependency setting.
