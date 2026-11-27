#!/usr/bin/env bash
# Start Hyblis in production on https://hyblis.com: gateway (127.0.0.1:9850), public site
# (127.0.0.1:9851) and Hyblis's own Cloudflare Tunnel (metrics on 127.0.0.1:9855).
# Run as pinc (or as root: it drops to pinc). Touches nothing outside /home/pinc/Hyblis and never
# the other tunnel or web server on this host. Stop with scripts/stop_production.sh.
set -euo pipefail
ROOT="/home/pinc/Hyblis"
if [ "$(id -un)" != "pinc" ]; then exec runuser -u pinc -- bash "$0" "$@"; fi
cd "$ROOT"

# production settings (same origin behind the tunnel; Cloudflare sends the visitor's address)
export HYBLIS_NETWORK=mainnet
export HYBLIS_PUBLIC_API_BASE=""
export HYBLIS_CORS_ORIGINS="https://hyblis.com,https://www.hyblis.com"
export HYBLIS_TRUSTED_PROXIES="127.0.0.1,::1"
export HYBLIS_CLIENT_IP_HEADER="CF-Connecting-IP"

bash scripts/start_platform.sh

# the tunnel: token from run/tunnel.token (written by scripts/deploy/cloudflare_tunnel.py), passed
# through the environment so it never shows in the process list
TOK="$ROOT/run/tunnel.token"
PIDF="$ROOT/run/tunnel.pid"
[ -s "$TOK" ] || { echo "no run/tunnel.token: run scripts/deploy/cloudflare_tunnel.py first"; exit 1; }
if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null && grep -q "hyblis-tunnel" "/proc/$(cat "$PIDF")/cmdline" 2>/dev/null; then
  echo "tunnel already running (pid $(cat "$PIDF"))"
else
  if ss -tlnH "sport = :9855" 2>/dev/null | grep -q .; then echo "port 9855 in use; aborting"; exit 1; fi
  TUNNEL_TOKEN="$(cat "$TOK")" nohup /usr/local/bin/cloudflared tunnel --no-autoupdate \
    --metrics 127.0.0.1:9855 --label hyblis-tunnel run >> logs/tunnel.log 2>&1 &
  echo $! > "$PIDF"
  sleep 4
  if kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "tunnel started (pid $(cat "$PIDF"))"
  else echo "tunnel failed to start; see logs/tunnel.log"; tail -5 logs/tunnel.log; exit 1; fi
fi
echo "live: https://hyblis.com"
