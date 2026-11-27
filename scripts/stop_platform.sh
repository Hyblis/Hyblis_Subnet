#!/usr/bin/env bash
# Stop Hyblis platform services started by start_platform.sh (via their PID files only).
# A PID file is trusted only while that PID runs a hyblis_platform module; a stale file
# (the number may now belong to another service) is removed and nothing is signalled.
set -euo pipefail
ROOT="/home/pinc/Hyblis"
cd "$ROOT"
is_ours() {  # pid
  local cmd
  [[ "$1" =~ ^[0-9]+$ ]] || return 1
  cmd="$(tr '\0' ' ' 2>/dev/null < "/proc/$1/cmdline")" || return 1
  [[ "$cmd" == *"-m hyblis_platform."* ]]   # started as: python -m hyblis_platform.<module>
}
for name in gateway site; do
  pidf="run/$name.pid"
  if [ -f "$pidf" ]; then
    pid="$(cat "$pidf")"
    if is_ours "$pid"; then kill "$pid" && echo "stopped $name (pid $pid)"; else echo "$name not running (stale pid file removed)"; fi
    rm -f "$pidf"
  else
    echo "$name: no pid file"
  fi
done
