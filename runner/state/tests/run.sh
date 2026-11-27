#!/usr/bin/env bash
# State-layer test entry point (runner/state). Safe to call from the main test suite.
#
#   runner/state/tests/run.sh                 # unit tests + end-to-end test
#   runner/state/tests/run.sh state.tests.test_mpt
#
# - Runs as user pinc (re-executes itself through runuser when started as root), at idle CPU priority.
# - No network: the end-to-end test uses a local anvil (127.0.0.1:9864, else 9865, plus an IPC socket)
#   that it starts and stops itself. Every forge/anvil process it starts runs in a private temp dir.
# - forge-std comes from HYBLIS_FORGE_STD, else the first tasks/upstream/*/lib/forge-std at 1.15.0.
# - Env: HYBLIS_STATE_KEEP=1 keeps the work dir; HYBLIS_STATE_WRITE_FIXTURES=1 rewrites
#   tests/fixtures/anvil_proofs.json from the toy chain.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

if [ "$(id -un)" != "pinc" ]; then
  if [ "$(id -u)" = "0" ]; then
    exec runuser -u pinc -- "$HERE/run.sh" "$@"
  fi
  echo "run.sh: run as pinc (or root, which drops to pinc)" >&2
  exit 2
fi

# shellcheck disable=SC1091
source "$ROOT/env.sh"
unset HYBLIS_ETH_RPC HYBLIS_ETH_RPC_FALLBACK   # the tests never touch a public RPC

PORT=""
for p in 9864 9865; do
  if [ -z "$(ss -Htln "sport = :$p" 2>/dev/null)" ]; then PORT=$p; break; fi
done
if [ -z "$PORT" ]; then echo "run.sh: ports 9864 and 9865 are both in use" >&2; exit 2; fi
export HYBLIS_STATE_ANVIL_PORT=$PORT

if [ -z "${HYBLIS_FORGE_STD:-}" ]; then
  for d in "$ROOT"/tasks/upstream/*/lib/forge-std; do
    if grep -q '"version": "1.15.0"' "$d/package.json" 2>/dev/null; then HYBLIS_FORGE_STD="$d"; break; fi
  done
fi
export HYBLIS_FORGE_STD="${HYBLIS_FORGE_STD:-}"
export TMPDIR="${TMPDIR:-/tmp}"

echo "state-layer tests: forge $(forge --version | head -1 | awk '{print $3}'), anvil port $PORT, forge-std ${HYBLIS_FORGE_STD:-missing}"
exec chrt --idle 0 nice -n 19 python -I -B "$HERE/runtests.py" -v "$@"
