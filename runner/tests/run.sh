#!/usr/bin/env bash
# Hyblis runner test suite (trace-verified validation). Toy contracts on a local anvil chain only:
# no mainnet, no public RPC, no network. anvil binds 127.0.0.1:9866 or 9867 (whichever is free) and an
# IPC socket in a temp dir, and is stopped by its own PID. Heavy work runs at idle priority.
#
#   as pinc: engine unit tests, static screen tests, every variant end to end (sandbox "none"),
#            broken fork source, CLI, misses file, spec self-check, hyblis check;
#   as root: the same, with forge in an empty network namespace (unshare -n) running as pinc, plus the
#            check that a PoC cannot reach the network from inside it.
#
# Usage: runner/tests/run.sh [--only v01,v40] [--update-fixtures]
set -uo pipefail
ROOT=/home/pinc/Hyblis
source "$ROOT/env.sh"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
fail=0
run() { echo "== $1 =="; shift; "$@" || fail=1; echo; }
run "runner: verdict engine unit tests (no forge)" python -B runner/test_impact.py
run "runner: static screen (policy_check.py)" python -B platform/tests/test_policy_check.py
run "runner: end to end on a toy chain" chrt --idle 0 nice -n 19 python -I -B runner/tests/test_e2e.py "$@"
if [ "$(id -u)" = 0 ]; then chown -R pinc:pinc "$ROOT/runner"; fi
if [ "$fail" -eq 0 ]; then echo "RUNNER SUITE PASSED"; else echo "RUNNER SUITE FAILED"; fi
exit $fail
