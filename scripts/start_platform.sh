#!/usr/bin/env bash
# Start the Hyblis platform services (gateway 9850 + public site 9851), bound to
# 127.0.0.1. PID files in run/, logs in logs/. Run as pinc from anywhere.
set -euo pipefail
ROOT="/home/pinc/Hyblis"
source "$ROOT/env.sh"
cd "$ROOT"
mkdir -p run logs platform/data platform/public

GATEWAY_PORT="${HYBLIS_GATEWAY_PORT:-9850}"
SITE_PORT="${HYBLIS_SITE_PORT:-9851}"

# refuse to collide with anything already listening (protects other services); a port held by our
# own running gateway or site (its PID file, running a hyblis_platform module) is fine: start() below
# then just reports it as already running, so a partial restart still reaches the later steps
for pair in "$GATEWAY_PORT:gateway" "$SITE_PORT:site"; do
  p="${pair%%:*}"; name="${pair#*:}"
  if ss -tlnH "sport = :$p" 2>/dev/null | grep -q .; then
    pid="$(cat "run/$name.pid" 2>/dev/null)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "-m hyblis_platform."; then
      continue
    fi
    echo "port $p is already in use — aborting (pick another in docs/ports.md)"; exit 1
  fi
done

# shared internal token for the runner machine (generated once, git-ignored)
TOKEN_FILE="$ROOT/run/dispatch.token"
if [ ! -s "$TOKEN_FILE" ]; then
  python - <<'PY' > "$TOKEN_FILE"
import secrets; print(secrets.token_hex(32))
PY
  chmod 600 "$TOKEN_FILE"
  echo "generated run/dispatch.token (give this to the runner machine)"
fi
export HYBLIS_DISPATCH_TOKEN="$(cat "$TOKEN_FILE")"

# A PID file is ours only while that PID runs a hyblis_platform module: after a reboot or a
# crash the number may belong to another service, which must never be touched.
is_ours() {  # pid
  local cmd
  [[ "$1" =~ ^[0-9]+$ ]] || return 1
  cmd="$(tr '\0' ' ' 2>/dev/null < "/proc/$1/cmdline")" || return 1
  [[ "$cmd" == *"-m hyblis_platform."* ]]   # started as: python -m hyblis_platform.<module>
}

start() {  # name module port
  local name="$1" mod="$2" port="$3" pidf="run/$1.pid"
  if [ -f "$pidf" ]; then
    if is_ours "$(cat "$pidf")"; then
      echo "$name already running (pid $(cat "$pidf"))"; return
    fi
    rm -f "$pidf"   # stale: that process is gone or is not ours
  fi
  HYBLIS_GATEWAY_PORT="$GATEWAY_PORT" HYBLIS_SITE_PORT="$SITE_PORT" \
    nohup python -m "$mod" >> "logs/$name.log" 2>&1 &
  echo $! > "$pidf"
  sleep 1
  if is_ours "$(cat "$pidf")"; then
    echo "$name started (pid $(cat "$pidf")) on 127.0.0.1:$port"
  else
    rm -f "$pidf"
    echo "$name failed to start — see logs/$name.log"; tail -5 "logs/$name.log"; exit 1
  fi
}

start gateway hyblis_platform.gateway "$GATEWAY_PORT"
start site    hyblis_platform.publicsite "$SITE_PORT"
echo "ready: gateway http://127.0.0.1:$GATEWAY_PORT  site http://127.0.0.1:$SITE_PORT"
