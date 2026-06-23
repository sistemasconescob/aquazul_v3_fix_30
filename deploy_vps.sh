#!/bin/bash
# Deploy Aquazul en Ubuntu 22.04
set -e
APP_DIR="/opt/aquazul"
echo "════════════════════════════════════"
echo " AQUAZUL — Deploy VPS Ubuntu/Debian"
echo "════════════════════════════════════"

apt-get update -qq
apt-get install -y python3 nginx certbot python3-certbot-nginx ufw -qq

mkdir -p $APP_DIR
cp -r . $APP_DIR/
mkdir -p $APP_DIR/frontend/uploads
chmod 755 $APP_DIR/frontend/uploads

[ ! -f "$APP_DIR/.env" ] && cp $APP_DIR/.env.example $APP_DIR/.env && echo "⚠️  Edita: nano $APP_DIR/.env"

cat > /etc/systemd/system/aquazul.service << SERVICE
[Unit]
Description=Aquazul Piscinas Sanas v3
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/backend
EnvironmentFile=${APP_DIR}/.env
ExecStart=/usr/bin/python3 ${APP_DIR}/backend/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aquazul
systemctl restart aquazul

DOMAIN="${APP_URL:-localhost}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN#http://}"

cat > /etc/nginx/sites-available/aquazul << NGINX
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    client_max_body_size 20M;

    location /uploads/ {
        alias ${APP_DIR}/frontend/uploads/;
        expires 1d;
        add_header Cache-Control "public";
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/aquazul /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

ufw --force enable
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp

if [ "$DOMAIN" != "localhost" ] && [ -n "$DOMAIN" ]; then
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m "admin@${DOMAIN}" || echo "⚠️  SSL: configura DNS primero"
fi

echo ""
echo "✅ Deploy completado!"
echo "   App: http://$DOMAIN"
echo "   Logs: journalctl -u aquazul -f"
echo "   Config: nano $APP_DIR/.env"
