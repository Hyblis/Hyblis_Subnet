#!/usr/bin/env bash
# Stop the testnet weight loop started by scripts/start_weights.sh (its own PID file only).
set -uo pipefail
cd /home/pinc/Hyblis
PIDF="run/weights.pid"
if [ -f "$PIDF" ]; then
  pid="$(cat "$PIDF")"
  if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "validator/weights.py"; then kill "$pid" && echo "stopped weight loop (pid $pid)"; else echo "weight loop: stale pid file, nothing stopped"; fi
  rm -f "$PIDF"
else
  echo "weight loop: not running"
fi
