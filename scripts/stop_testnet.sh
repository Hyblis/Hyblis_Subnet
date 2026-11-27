#!/usr/bin/env bash
# Stop the testnet platform started by scripts/start_testnet.sh (its own PID files only).
set -uo pipefail
cd /home/pinc/Hyblis
for n in runner:runner/agent.py gateway:hyblis_platform.gateway site:hyblis_platform.publicsite; do
  name="${n%%:*}"; pat="${n#*:}"; pidf="run/testnet/$name.pid"
  if [ -f "$pidf" ]; then
    pid="$(cat "$pidf")"
    if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "$pat"; then kill "$pid" && echo "stopped $name (pid $pid)"; else echo "$name: stale pid file"; fi
    rm -f "$pidf"
  else echo "$name: not running"; fi
done
