#!/usr/bin/env bash
# Start the TESTNET validator weight loop: direct mode, scoring policy v2 (since 2026-11-23), on the
# subnet in run/testnet.netuid, signed by hyblis-sn/validator. Miners are paid straight through weights
# from the testnet scoring ledger (run/testnet/data, written by the testnet platform, scripts/start_testnet.sh); keys under the
# owner coldkey never receive miner weight; the owner hotkey gets the pool only when nobody earned.
# Runs as pinc, PID in run/weights.pid, log in logs/weights.log.
# Stop with scripts/stop_weights.sh. Touches nothing outside /home/pinc/Hyblis.
set -euo pipefail
ROOT="/home/pinc/Hyblis"
if [ "$(id -un)" != "pinc" ]; then exec runuser -u pinc -- bash "$0" "$@"; fi
cd "$ROOT"
source env.sh
export PYTHONDONTWRITEBYTECODE=1
PIDF="run/weights.pid"
is_ours() { [[ "${1:-}" =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | grep -q "validator/weights.py"; }
if [ -f "$PIDF" ] && is_ours "$(cat "$PIDF")"; then echo "weight loop already running (pid $(cat "$PIDF"))"; exit 0; fi
rm -f "$PIDF"
NETUID="$(cat run/testnet.netuid)"
OWNER_HOTKEY="$(python -c 'import json,os; print(json.load(open(os.environ["BT_WALLET_PATH"]+"/hyblis-sn/hotkeys/validatorpub.txt"))["ss58Address"])')"
# the testnet scoring ledger (public events only: validated, paid, rejected, warm-up)
export HYBLIS_DATA_DIR="$ROOT/run/testnet/data" HYBLIS_PUBLIC_DIR="$ROOT/run/testnet/public" HYBLIS_NETWORK=testnet
# every 25 minutes: above the subnet's 100-block (20 min) weights_rate_limit, far inside the 2-day activity cutoff
nohup python validator/weights.py --mode direct --policy v2 --owner-hotkey "$OWNER_HOTKEY" \
  --network test --netuid "$NETUID" --wallet hyblis-sn --wallet-hotkey validator --commit --loop 1500 \
  >> logs/weights.log 2>&1 &
echo $! > "$PIDF"
sleep 2
if is_ours "$(cat "$PIDF")"; then echo "weight loop started (pid $(cat "$PIDF")): testnet netuid $NETUID, direct mode, policy v2"; else echo "weight loop failed: see logs/weights.log"; tail -5 logs/weights.log; exit 1; fi
