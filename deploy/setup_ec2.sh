#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# ResilientAI — AWS EC2 Stockholm Production Deployment
# Server: 13.50.16.19 (eu-north-1) — Free Tier
# Port: 8003
# Neighbours: ThreatFade:8000 | FusionOps:8080 | AI Shield:8002
#
# Usage:
#   chmod +x deploy/setup_ec2.sh
#   ./deploy/setup_ec2.sh
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

APP_DIR="/opt/tinlance/resilientai"
VENV_DIR="$APP_DIR/.venv"
SERVICE="resilientai"
PORT=8003
DOMAIN="api.resilientai.tinlance.com"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   ResilientAI — EC2 Stockholm Deploy         ║"
echo "║   Port: $PORT  | Server: 13.50.16.19        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. System dependencies ────────────────────────────────────────────
echo "[1/7] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
  python3.12 python3.12-venv python3-pip \
  nginx certbot python3-certbot-nginx \
  postgresql-client git curl

# ── 2. Clone / pull repo ──────────────────────────────────────────────
echo "[2/7] Syncing repository..."
if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR" && git pull origin main
else
  sudo mkdir -p /opt/tinlance
  sudo chown ubuntu:ubuntu /opt/tinlance
  git clone https://github.com/Tinlance/resilientai.git "$APP_DIR"
  cd "$APP_DIR"
fi

# ── 3. Python virtual environment ─────────────────────────────────────
echo "[3/7] Setting up Python environment..."
python3.12 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$APP_DIR/backend/requirements.txt" -q
echo "   ✅ Dependencies installed"

# ── 4. Environment file check ─────────────────────────────────────────
echo "[4/7] Checking environment..."
if [ ! -f "$APP_DIR/.env" ]; then
  echo ""
  echo "   ⚠️  No .env file found!"
  echo "   Run: cp $APP_DIR/.env.example $APP_DIR/.env"
  echo "   Then fill in: ANTHROPIC_API_KEY, LEMONSQUEEZY keys, CLERK keys"
  echo "   Then re-run this script."
  echo ""
  exit 1
fi
echo "   ✅ .env found"

# ── 5. Systemd service ────────────────────────────────────────────────
echo "[5/7] Installing systemd service..."
sudo tee /etc/systemd/system/${SERVICE}.service > /dev/null << SERVICE
[Unit]
Description=ResilientAI — Proactive IT Resilience SaaS
Documentation=https://github.com/Tinlance/resilientai
After=network.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=${APP_DIR}/backend
EnvironmentFile=${APP_DIR}/.env
ExecStart=${VENV_DIR}/bin/uvicorn main:app \
  --host 127.0.0.1 \
  --port ${PORT} \
  --workers 2 \
  --log-level info \
  --access-log
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=resilientai

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable $SERVICE
sudo systemctl restart $SERVICE
sleep 3

# ── 6. Nginx configuration ────────────────────────────────────────────
echo "[6/7] Configuring Nginx..."

NGINX_CONF="/etc/nginx/sites-available/tinlance"

# Check if tinlance nginx config exists, create if not
if [ ! -f "$NGINX_CONF" ]; then
  sudo tee "$NGINX_CONF" > /dev/null << 'NGINX'
server {
    listen 80;
    server_name 13.50.16.19 *.tinlance.com;

    # Existing services
    location /threatfade/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /fusionops/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /aishield/ {
        proxy_pass http://127.0.0.1:8002/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # ResilientAI (new)
    location /resilientai/ {
        proxy_pass http://127.0.0.1:8003/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    location / {
        return 200 'Tinlance EC2 Stockholm — OK';
        add_header Content-Type text/plain;
    }
}
NGINX
  sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/tinlance
  sudo rm -f /etc/nginx/sites-enabled/default
else
  # Add ResilientAI block if not already present
  if ! grep -q "resilientai" "$NGINX_CONF"; then
    sudo sed -i '/location \/ {/i\
    location /resilientai/ {\
        proxy_pass http://127.0.0.1:8003/;\
        proxy_http_version 1.1;\
        proxy_set_header Host $host;\
        proxy_set_header X-Real-IP $remote_addr;\
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\
        proxy_set_header X-Forwarded-Proto $scheme;\
        proxy_read_timeout 300s;\
    }\
' "$NGINX_CONF"
    echo "   ✅ ResilientAI block added to existing Nginx config"
  else
    echo "   ✅ ResilientAI block already present"
  fi
fi

sudo nginx -t && sudo systemctl reload nginx
echo "   ✅ Nginx configured and reloaded"

# ── 7. Health check ───────────────────────────────────────────────────
echo "[7/7] Running health check..."
sleep 2

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:$PORT/health/ 2>/dev/null || echo "000")

if [ "$HTTP_STATUS" = "200" ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ✅ ResilientAI deployed successfully                        ║"
  echo "║                                                              ║"
  echo "║  Local:   http://localhost:$PORT                           ║"
  echo "║  Public:  http://13.50.16.19/resilientai/                   ║"
  echo "║  Health:  http://13.50.16.19/resilientai/health/            ║"
  echo "║  Docs:    http://13.50.16.19/resilientai/docs               ║"
  echo "║  Bridges: http://13.50.16.19/resilientai/health/bridges     ║"
  echo "║                                                              ║"
  echo "║  Neighbours (localhost):                                     ║"
  echo "║    ThreatFade  → :8000  FusionOps → :8080                  ║"
  echo "║    AI Shield   → :8002                                      ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Next steps:"
  echo "  1. Set up SSL: sudo certbot --nginx -d $DOMAIN"
  echo "  2. Activate bridges: fill RECONOS_URL, BUGFLOW_URL in .env"
  echo "  3. Set Olvrix Widgets RESILIENTAI_API_URL=http://13.50.16.19:8003"
  echo "  4. Monitor: sudo journalctl -u $SERVICE -f"
else
  echo ""
  echo "  ⚠️  Health check returned HTTP $HTTP_STATUS"
  echo "  Check logs: sudo journalctl -u $SERVICE -n 50 --no-pager"
  echo "  Check port: ss -tlnp | grep $PORT"
fi
