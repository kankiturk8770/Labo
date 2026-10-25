#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run: sudo bash install.sh'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd installation is required.'; exit 1; }
source /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || { echo 'Supported installer targets: Ubuntu / Debian'; exit 1; }
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ ! -e /opt/edge-gateway ]] || { echo 'Existing installation preserved. See README-FA.md for controlled source upgrades; installer does not overwrite a running deployment.'; exit 1; }
for filename in main.go tuning.go go.mod panel/server.py; do
 [[ -f "$SOURCE_DIR/$filename" ]] || { echo "Missing source: $filename"; exit 1; }
done
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates python3 openssl curl git tar logrotate
GO_BIN="$(python3 "$SOURCE_DIR/scripts/install-go.py")"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf -- "$BUILD_DIR"' EXIT
(
 cd "$SOURCE_DIR"
 "$GO_BIN" test ./...
 "$GO_BIN" vet ./...
 CGO_ENABLED=0 "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$BUILD_DIR/edge-gateway" .
 python3 -m unittest discover -s tests -v
)
getent group edge-gateway >/dev/null || groupadd --system edge-gateway
id edge-gateway >/dev/null 2>&1 || useradd --system --gid edge-gateway --home-dir /opt/edge-gateway --shell /usr/sbin/nologin edge-gateway
install -d -m 0755 /opt/edge-gateway
cp -a "$SOURCE_DIR/." /opt/edge-gateway/
chown -R root:root /opt/edge-gateway
chmod -R go-w /opt/edge-gateway
# Source is readable by the service; secrets never live in this tree.
find /opt/edge-gateway -type d -exec chmod 0755 {} +
find /opt/edge-gateway -type f -exec chmod 0644 {} +
install -o root -g edge-gateway -m 0750 "$BUILD_DIR/edge-gateway" /opt/edge-gateway/edge-gateway
install -d -o root -g edge-gateway -m 0750 /etc/edge-gateway /etc/edge-gateway/certs
install -d -o root -g root -m 0700 /var/lib/edge-panel /var/lib/edge-panel/revisions
# First-install files are created only when absent; preserve credentials/config.
if [[ ! -f /etc/edge-gateway/certs/tls.crt && ! -f /etc/edge-gateway/certs/tls.key ]]; then
 openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/edge-gateway/certs/tls.key -out /etc/edge-gateway/certs/tls.crt -days 30 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
 chown root:edge-gateway /etc/edge-gateway/certs/tls.*
 chmod 0640 /etc/edge-gateway/certs/tls.*
fi
PYTHONPATH=/opt/edge-gateway/panel python3 - <<'PY'
import json,secrets
from pathlib import Path
from schema import DEFAULTS
from control import Controller,atomic
from server import password_record
c=Controller()
if not c.config.exists():
 cfg=dict(DEFAULTS);cfg['EDGE_HMAC_SECRET']=secrets.token_hex(32);c.write(cfg)
if not (c.state/'auth.json').exists():
 pw=secrets.token_urlsafe(24);atomic(c.state/'auth.json',json.dumps(password_record(pw)))
 atomic('/root/edge-panel-credentials.txt','Panel: http://127.0.0.1:9090\nPassword: '+pw+'\n')
PY
install -m 0644 "$SOURCE_DIR/deploy/edge-gateway.service" /etc/systemd/system/edge-gateway.service
install -m 0644 "$SOURCE_DIR/deploy/edge-panel.service" /etc/systemd/system/edge-panel.service
install -m 0644 "$SOURCE_DIR/deploy/edge-panel.logrotate" /etc/logrotate.d/edge-panel
systemctl daemon-reload
systemctl enable --now edge-panel.service
systemctl is-active --quiet edge-panel.service
printf '\nPanel installed. Gateway stays stopped until valid configuration is applied.\n'
printf 'On your computer: ssh -L 9090:127.0.0.1:9090 USER@SERVER_IP\n'
printf 'Then open: http://127.0.0.1:9090\n'
printf 'Password: sudo cat /root/edge-panel-credentials.txt\n'
printf 'Import a trusted gateway TLS certificate in the panel before real client use.\n'
