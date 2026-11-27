#!/usr/bin/env bash
# Start the TESTNET platform on https://testnet.hyblis.com (Bittensor testnet, subnet in run/testnet.netuid):
#   gateway 127.0.0.1:9860 and site 127.0.0.1:9861 (as pinc; data in run/testnet/, intake open),
#   runner agent (as root: each proof runs in its own net + mount + pid namespaces as the bare uid 64123,
#   with /home, /root and /tmp hidden; see runner/tests/host_sandbox_check.py).
# Reached through the Hyblis tunnel (scripts/deploy/cloudflare_tunnel.py). Run as root. Never touches the
# mainnet services (9850/9851), other products or shared configuration. Stop: scripts/stop_testnet.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (the runner needs it for its sandbox)"; exit 1; }
ROOT=/home/pinc/Hyblis
cd "$ROOT"
T=run/testnet
mkdir -p logs run/runner-jobs run/runner-sockets
chown pinc:pinc logs run/runner-jobs run/runner-sockets
is_ours() { [[ "${1:-}" =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | grep -q -- "$2"; }
for port in 9860 9861; do
  if ss -ltn | grep -q "127.0.0.1:$port "; then
    pidf="$T/$([ $port = 9860 ] && echo gateway || echo site).pid"
    if [ -f "$pidf" ] && is_ours "$(cat "$pidf")" "hyblis_platform"; then continue; fi
    echo "port $port is in use by something else; aborting"; exit 1
  fi
done
PENV=(HOME="$ROOT/.home" PATH="$ROOT/.venv/bin:/usr/bin:/bin" LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
      PYTHONPATH="$ROOT/platform:$ROOT/scoring" HYBLIS_ROOT="$ROOT"
      HYBLIS_NETWORK=testnet HYBLIS_INTAKE_OPEN=1 HYBLIS_NETUID="$(cat run/testnet.netuid)"
      HYBLIS_DATA_DIR="$ROOT/$T/data" HYBLIS_PUBLIC_DIR="$ROOT/$T/public" HYBLIS_TASKS_DIR="$ROOT/$T/tasks"
      HYBLIS_GATEWAY_PORT=9860 HYBLIS_SITE_PORT=9861 HYBLIS_DISPATCH_TOKEN="$(cat $T/dispatch.token)"
      HYBLIS_PUBLIC_API_BASE="" HYBLIS_CORS_ORIGINS="https://testnet.hyblis.com"
      HYBLIS_TRUSTED_PROXIES="127.0.0.1,::1" HYBLIS_CLIENT_IP_HEADER="CF-Connecting-IP" HYBLIS_PRIVATE_PAGES=0)
start_pinc() {  # name module
  local pidf="$T/$1.pid"
  if [ -f "$pidf" ] && is_ours "$(cat "$pidf")" "$2"; then echo "$1 already running (pid $(cat "$pidf"))"; return; fi
  runuser -u pinc -- env -i "${PENV[@]}" nohup "$ROOT/.venv/bin/python" -m "$2" >> "logs/testnet-$1.log" 2>&1 &
  echo $! > "$pidf"; chown pinc:pinc "$pidf"; sleep 1
  is_ours "$(cat "$pidf")" "$2" && echo "$1 started (pid $(cat "$pidf"))" || { echo "$1 failed: logs/testnet-$1.log"; tail -5 "logs/testnet-$1.log"; exit 1; }
}
start_pinc gateway hyblis_platform.gateway
start_pinc site hyblis_platform.publicsite
# runner: root, isolated sandbox, idle priority, one job at a time
pidf="$T/runner.pid"
if [ -f "$pidf" ] && is_ours "$(cat "$pidf")" "runner/agent.py"; then echo "runner already running (pid $(cat "$pidf"))"; else
  env -i HOME="$ROOT/run/runner-jobs" PATH="/usr/bin:/bin" LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 HYBLIS_ROOT="$ROOT" \
    HYBLIS_RUNNER=1 HYBLIS_DISPATCH_TOKEN="$(cat $T/dispatch.token)" HYBLIS_TASKS_DIR="$ROOT/$T/tasks" \
    nohup "$ROOT/.venv/bin/python" "$ROOT/runner/agent.py" --gateway http://127.0.0.1:9860 \
      --projects "$ROOT/runner-data/projects" --snapshots "$ROOT/runner-data/snapshots" \
      --forge-user 64123 --isolate --max-memory-gb 8 --foundry-bin "$ROOT/tools/foundry/bin" --svm-dir "$ROOT/.home/.svm" \
      --socket-dir "$ROOT/run/runner-sockets" --jobs-dir "$ROOT/run/runner-jobs" --poll 10 \
      >> logs/testnet-runner.log 2>&1 &
  echo $! > "$pidf"; sleep 2
  is_ours "$(cat "$pidf")" "runner/agent.py" && echo "runner started (pid $(cat "$pidf"))" || { echo "runner failed: logs/testnet-runner.log"; tail -5 logs/testnet-runner.log; exit 1; }
fi
echo "testnet: https://testnet.hyblis.com (gateway 9860, site 9861)"
