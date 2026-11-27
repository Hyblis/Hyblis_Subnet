#!/usr/bin/env bash
# The Python suites (what CI runs): scoring, weights, gateway end to end, pipeline, site privacy and HTTPS rules.
# No Foundry, no chain, no network. The full set, with the runner's Foundry and toy-chain suites, is run_tests.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1 HYBLIS_ROOT="$PWD" PYTHONPATH="$PWD/platform:$PWD/scoring:${PYTHONPATH:-}"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
export HYBLIS_DATA_DIR="$TMP/data" HYBLIS_PUBLIC_DIR="$TMP/public" HYBLIS_DISPATCH_TOKEN="test-token-123"
export HYBLIS_NETWORK=testnet HYBLIS_INTAKE_OPEN=1
unset HYBLIS_CLIENT_IP_HEADER
fail=0
run() { echo "== $1 =="; shift; "$@" || fail=1; echo; }
run "scoring: policy unit"          python -m unittest discover -s scoring/tests -p 'test_*.py'
run "validator: weights"            python validator/test_weights.py
run "platform: core smoke"          python platform/tests/smoke_core.py
run "platform: gateway e2e"         python platform/tests/e2e.py
run "pipeline: runner retries"      python platform/tests/test_requeue.py
run "pipeline: warm-up track"       python platform/tests/test_warmup.py
run "site: https redirect + HSTS"   python platform/tests/test_edge.py
run "site: private pages"           python platform/tests/test_private_pages.py
run "runner: verdict engine unit"   python -B runner/test_impact.py
run "runner: static screen"         python -B platform/tests/test_policy_check.py
run "runner: RPC rate limits"       python -B runner/state/tests/test_ratelimit.py
run "runner: fresh-account bases"   python -B runner/state/tests/test_fresh_bases.py
if [ "$fail" -eq 0 ]; then echo "ALL CI SUITES PASSED"; else echo "SOME CI SUITES FAILED"; fi
exit $fail
