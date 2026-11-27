#!/usr/bin/env bash
# Stop Hyblis production: its own tunnel (only the process recorded in run/tunnel.pid, checked by
# its label) and the gateway + site (scripts/stop_platform.sh). Never touches any other process.
set -uo pipefail
ROOT="/home/pinc/Hyblis"
cd "$ROOT"
PIDF="run/tunnel.pid"
if [ -f "$PIDF" ]; then
  pid="$(cat "$PIDF")"
  if kill -0 "$pid" 2>/dev/null && grep -q "hyblis-tunnel" "/proc/$pid/cmdline" 2>/dev/null; then
    kill "$pid" && echo "stopped tunnel (pid $pid)"
  else
    echo "tunnel: stale pid file, nothing stopped"
  fi
  rm -f "$PIDF"
else
  echo "tunnel: not running"
fi
bash scripts/stop_platform.sh
