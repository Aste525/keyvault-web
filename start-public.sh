#!/usr/bin/env bash
# Menjalankan Key Vault dan membuka link HTTPS publik lewat Cloudflare Tunnel (gratis, tanpa domain, tanpa buka port router)
cd "$(dirname "$0")"
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared belum terpasang. Termux: pkg install cloudflared"
  exit 1
fi
node secure-start.cjs &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT INT TERM
sleep 1
echo "Cari baris https://xxxx.trycloudflare.com di bawah. Itu link website publikmu."
cloudflared tunnel --url http://localhost:28836
