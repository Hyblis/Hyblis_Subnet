#!/usr/bin/env bash
# Run a task's OWN control PoCs (trusted files written by us) against the pinned fork, on this server.
# This checks the plain forge result and the static screen only; the expected runner VERDICTS in
# controls/expected.json are checked with runner/run_submission.py on the runner VM.
# Never use this for miner submissions: those run only on the isolated runner machine (roadmap Phase 5).
# Usage: runner/local_controls.sh <task_id>      e.g. runner/local_controls.sh cap
set -u
source /home/pinc/Hyblis/env.sh
TASK="$1"; T="$HYBLIS_ROOT/tasks/$TASK"; M="$T/manifest.json"
read -r UP ROOT PDIR < <(python3 -I -c "import json;m=json.load(open('$M'));print(m['code']['upstream_checkout'], m['code']['foundry_root'], m['submission']['poc_dir'])")
WORK="$HYBLIS_ROOT/$UP"; FROOT="$WORK/$ROOT"; DEST="$WORK/$PDIR"
[ "$(git -C "$WORK" status --porcelain --untracked-files=no | wc -l)" = "0" ] || { echo "upstream checkout is modified; refusing"; exit 3; }
mkdir -p "$DEST"; RESULTS=(); OK=1
# Swap in a sanitized foundry.toml (ffi off, no file access, no rpc_endpoints); restored from git at the end.
ORIG="$HYBLIS_ROOT/.cache/foundry-orig-$TASK.toml"; cp "$FROOT/foundry.toml" "$ORIG"
python3 -I "$HYBLIS_ROOT/runner/sanitize_foundry_toml.py" "$ORIG" "$FROOT/foundry.toml" || { cp "$ORIG" "$FROOT/foundry.toml"; echo "cannot sanitize foundry.toml"; exit 3; }
# Controls of trace-design tasks import ./HyblisBase.sol: put the task's copy next to them (removed at the end).
[ -f "$T/poc/HyblisBase.sol" ] && cp "$T/poc/HyblisBase.sol" "$DEST/HyblisBase.sol"
trap 'cp "$ORIG" "$FROOT/foundry.toml"; rm -f "$DEST/Control.t.sol" "$DEST/HyblisBase.sol"' EXIT
for f in "$T"/controls/*.t.sol; do
  name=$(basename "$f")
  pol=$(python3 -I "$HYBLIS_ROOT/runner/policy_check.py" "$M" "$f" | python3 -I -c "import json,sys;print(json.load(sys.stdin)['verdict'])")
  cp "$f" "$DEST/Control.t.sol"
  ( cd "$FROOT" && FOUNDRY_FFI=false nice -n 15 timeout 900 forge test --match-path "${PDIR#$ROOT/}/Control.t.sol" >"$HYBLIS_ROOT/logs/control-$TASK-$name.log" 2>&1 )
  rc=$?; forge_res=$([ $rc = 0 ] && echo pass || echo fail)
  exp=$(python3 -I -c "import json;e=json.load(open('$T/controls/expected.json'))['$name'];print(e['forge'],e['policy'])")
  read -r ef ep <<< "$exp"
  match="OK"; { [ "$ef" != any ] && [ "$ef" != "$forge_res" ]; } && match="MISMATCH"; [ "$ep" != "$pol" ] && match="MISMATCH"
  [ "$match" = OK ] || OK=0
  printf "%-36s forge=%-4s (exp %-4s)  policy=%-6s (exp %-6s)  %s\n" "$name" "$forge_res" "$ef" "$pol" "$ep" "$match"
done
rm -f "$DEST/Control.t.sol" "$DEST/HyblisBase.sol"; cp "$ORIG" "$FROOT/foundry.toml"; rmdir "$DEST" 2>/dev/null
[ "$(git -C "$WORK" status --porcelain --untracked-files=no | wc -l)" = "0" ] && echo "upstream checkout left clean"
[ $OK = 1 ] && echo "ALL CONTROLS MATCH" || { echo "SOME CONTROLS DID NOT MATCH"; exit 1; }
