#!/bin/bash
set -e

echo "============================================================"
echo "   KLINK v2 - Full Panel-Controlled Anti-Censorship Core    "
echo "============================================================"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo bash install.sh)"
  exit 1
fi

REPO_URL="${KLINK_REPO_URL:-}"
MIMIC_DOMAIN="${KLINK_MIMIC_DOMAIN:-www.aparat.com}"
PANEL_PORT="${KLINK_PANEL_PORT:-8443}"
TCP_PORT="${KLINK_TCP_PORT:-443}"
UDP_PORT="${KLINK_UDP_PORT:-50000}"

echo "[1/6] Updating system and installing dependencies..."
apt-get update -y && apt-get upgrade -y
apt-get install -y curl wget git ufw build-essential openssl ca-certificates

echo "[2/6] Checking and installing Go 1.22..."
GO_VERSION="1.22.2"
if ! command -v /usr/local/go/bin/go &> /dev/null; then
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin
if ! grep -q "/usr/local/go/bin" /etc/profile; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
fi

echo "[3/6] Setting up /opt/klink directory..."
mkdir -p /opt/klink

if [ -f "./go.mod" ] && [ -d "./cmd" ]; then
    echo " -> Copying project files from current directory to /opt/klink..."
    cp -r ./* /opt/klink/
elif [ -n "$REPO_URL" ]; then
    echo " -> Cloning repository from $REPO_URL ..."
    rm -rf /tmp/klink_clone
    git clone "$REPO_URL" /tmp/klink_clone
    # The project may live at the repo root or inside a klink/ subfolder
    # (as in the Labo monorepo). Pick whichever holds go.mod + cmd/.
    if [ -f "/tmp/klink_clone/klink/go.mod" ] && [ -d "/tmp/klink_clone/klink/cmd" ]; then
        cp -r /tmp/klink_clone/klink/* /opt/klink/
    else
        cp -r /tmp/klink_clone/* /opt/klink/
    fi
    rm -rf /tmp/klink_clone
fi

cd /opt/klink

echo "[4/6] Downloading Go modules & compiling KLINK v2 Server and Client..."
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -ldflags="-s -w" -o /opt/klink/klink-server ./cmd/server
/usr/local/go/bin/go build -ldflags="-s -w" -o /opt/klink/klink-client ./cmd/client
chmod +x /opt/klink/klink-server /opt/klink/klink-client

echo "[5/6] Configuring UFW Firewall..."
ufw allow 22/tcp
ufw allow ${TCP_PORT}/tcp
ufw allow ${PANEL_PORT}/tcp
ufw allow 50000:60000/udp
ufw --force enable

echo "[6/6] Creating and starting systemd service (klink.service)..."
SECRET_KEY=$(openssl rand -hex 16)

cat > /etc/systemd/system/klink.service <<EOF
[Unit]
Description=KLINK v2 Full Panel-Controlled Anti-Censorship Core
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/klink
Environment="KLINK_SECRET=${SECRET_KEY}"
Environment="KLINK_MIMIC_DOMAIN=${MIMIC_DOMAIN}"
Environment="KLINK_TCP_PORT=${TCP_PORT}"
Environment="KLINK_UDP_PORT=${UDP_PORT}"
Environment="KLINK_PANEL_PORT=${PANEL_PORT}"
Environment="KLINK_DB_PATH=/opt/klink/klink.db"
ExecStart=/opt/klink/klink-server
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable klink.service
systemctl restart klink.service

SERVER_IP=$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')

echo "============================================================"
echo " ✅ KLINK v2 Installed and Started Successfully!"
echo "------------------------------------------------------------"
echo " 🌐 Full Control Web Panel : https://${SERVER_IP}:${PANEL_PORT}"
echo " 🎭 Default Masquerade     : ${MIMIC_DOMAIN} (Changeable in Panel)"
echo " 📄 Commands Cheat-Sheet   : /opt/klink/COMMANDS.txt"
echo "============================================================"
