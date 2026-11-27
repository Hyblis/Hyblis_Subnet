#!/usr/bin/env bash
# Run the whole Hyblis test suite (platform + scoring + runner + vault). Isolated
# DBs under a temp dir; never touches platform/data. Run as pinc.
set -uo pipefail
ROOT="/home/pinc/Hyblis"
source "$ROOT/env.sh"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
TMP="$(mktemp -d)"
export HYBLIS_DATA_DIR="$TMP/data" HYBLIS_PUBLIC_DIR="$TMP/public" HYBLIS_DISPATCH_TOKEN="test-token"
# The suites file reports to the testnet reference program (cap, networks=["testnet"]) with intake open.
# HYBLIS_INTAKE_OPEN=1 is honoured on testnet only. The e2e suite also checks mainnet launch mode itself.
export HYBLIS_NETWORK=testnet HYBLIS_INTAKE_OPEN=1
unset HYBLIS_CLIENT_IP_HEADER
fail=0

run() { echo "== $1 =="; shift; "$@"; [ $? -ne 0 ] && fail=1; echo; }

run "platform: core smoke"   python platform/tests/smoke_core.py
run "runner: policy check"   python platform/tests/test_policy_check.py
run "platform: gateway e2e"  python platform/tests/e2e.py
run "scoring: policy unit"   python -m unittest discover -s scoring/tests -p 'test_*.py'
run "runner: impact unit"    python runner/test_impact.py
run "runner: trace e2e (toy chain)" chrt --idle 0 nice -n 19 python -I -B runner/tests/test_e2e.py
run "settlement: unit"       python platform/tests/test_settlement.py
run "pipeline: runner retries" python platform/tests/test_requeue.py
run "pipeline: warm-up track" python platform/tests/test_warmup.py
run "runner: review hardening" python runner/tests/test_hardening.py
run "site: hyblis check bundle" python platform/tests/test_check_bundle.py
run "site: https redirect + HSTS" python platform/tests/test_edge.py
run "site: private pages" python platform/tests/test_private_pages.py
run "validator: weights (vault lookup)" python validator/test_weights.py
if command -v node >/dev/null 2>&1; then
  run "site: wallet.js parity" python platform/tests/test_wallet_js.py
else
  echo "== site: wallet.js parity =="; echo "SKIPPED: node is not installed (needed to run wallet.js)"; echo
fi

echo "== vault: foundry =="
( cd chain/vault && FOUNDRY_FFI=false forge test ) || fail=1

rm -rf "$TMP"
echo
if [ "$fail" -eq 0 ]; then echo "ALL SUITES PASSED"; else echo "SOME SUITES FAILED"; fi
exit $fail
