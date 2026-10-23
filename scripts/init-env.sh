#!/usr/bin/env bash
# Creates .env from .env.example, filling in freshly generated secrets.
# Refuses to overwrite an existing .env.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo ".env already exists; delete it first to regenerate." >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
openssl genpkey -algorithm ed25519 -out "$tmp/private.pem" 2>/dev/null
openssl pkey -in "$tmp/private.pem" -pubout -out "$tmp/public.pem"

b64() { base64 < "$1" | tr -d '\n'; }
private=$(b64 "$tmp/private.pem")
public=$(b64 "$tmp/public.pem")
internal=$(openssl rand -hex 32)
pepper=$(openssl rand -base64 32)
grafana=$(openssl rand -hex 16)

sed -e "s|^INTERNAL_SERVICE_TOKEN=.*|INTERNAL_SERVICE_TOKEN=${internal}|" \
    -e "s|^JWT_PRIVATE_KEY=.*|JWT_PRIVATE_KEY=${private}|" \
    -e "s|^JWT_PUBLIC_KEY=.*|JWT_PUBLIC_KEY=${public}|" \
    -e "s|^OTP_PEPPER=.*|OTP_PEPPER=${pepper}|" \
    -e "s|^GRAFANA_ADMIN_PASSWORD=.*|GRAFANA_ADMIN_PASSWORD=${grafana}|" \
    .env.example > .env
chmod 600 .env
echo "Created .env with new secrets. Set the database password in DATABASE_URL."
