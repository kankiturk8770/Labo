#!/bin/bash
# microtun installer.
#   Server:  sudo bash install.sh server SERVER_PUBLIC_IP [PORT] [CLIENTS]
#   Client:  sudo bash install.sh client /path/to/client1.json
#   Remove:  sudo bash install.sh uninstall
set -e

GO_VERSION=1.24.7
RELEASE=https://github.com/kankiturk8770/Labo/releases/download/microtun-latest
HERE=$(cd "$(dirname "$0")" && pwd)
CONF=/etc/microtun

[ "$EUID" -eq 0 ] || { echo "run as root: sudo bash $0 $*"; exit 1; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU: $(uname -m)"; exit 1 ;;
esac

install_binary() {
  if [ -f "$HERE/go.mod" ] && grep -q '^module microtun' "$HERE/go.mod"; then
    if ! command -v go >/dev/null && [ ! -x /usr/local/go/bin/go ]; then
      echo "[*] installing Go $GO_VERSION"
      curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
      rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
    fi
    GO=$(command -v go || echo /usr/local/go/bin/go)
    echo "[*] building microtun from source"
    (cd "$HERE" && CGO_ENABLED=0 "$GO" build -trimpath -ldflags='-s -w' -o /usr/local/bin/microtun .)
  else
    echo "[*] downloading microtun-linux-$ARCH"
    curl -fsSL "$RELEASE/microtun-linux-$ARCH" -o /usr/local/bin/microtun
    chmod +x /usr/local/bin/microtun
  fi
  command -v ip >/dev/null || apt-get install -y iproute2
  modprobe tun 2>/dev/null || true
  echo "[*] $(/usr/local/bin/microtun version)"
}

unit() { # name mode
  cat > /etc/systemd/system/microtun-$1.service <<EOF
[Unit]
Description=microtun $1
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/microtun $1 -c $CONF/$1.json
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now microtun-$1
  systemctl restart microtun-$1
}

case "$1" in
  server)
    IP=$2; PORT=${3:-51820}; N=${4:-1}
    [ -n "$IP" ] || { echo "usage: $0 server SERVER_PUBLIC_IP [PORT] [CLIENTS]"; exit 1; }
    install_binary
    command -v iptables >/dev/null || apt-get install -y iptables
    mkdir -p $CONF && chmod 700 $CONF
    if [ -f $CONF/server.json ]; then
      echo "[*] keeping existing $CONF/server.json"
    else
      (cd $CONF && /usr/local/bin/microtun gen -endpoint "$IP:$PORT" -clients "$N" -out .)
    fi
    if command -v ufw >/dev/null && ufw status | grep -q active; then ufw allow "$PORT/udp"; fi
    unit server
    sleep 1; systemctl --no-pager -l status microtun-server | tail -5
    echo
    echo "Client configs (copy one to the client machine):"
    ls $CONF/client*.json
    ;;
  client)
    [ -f "$2" ] || { echo "usage: $0 client /path/to/client1.json"; exit 1; }
    install_binary
    mkdir -p $CONF && chmod 700 $CONF
    install -m 600 "$2" $CONF/client.json
    unit client
    sleep 2; journalctl -u microtun-client -n 5 --no-pager
    ;;
  uninstall)
    for m in server client; do systemctl disable --now microtun-$m 2>/dev/null || true; rm -f /etc/systemd/system/microtun-$m.service; done
    systemctl daemon-reload
    rm -f /usr/local/bin/microtun
    echo "removed (configs left in $CONF)"
    ;;
  *)
    sed -n '2,5p' "$0"; exit 1 ;;
esac
