# Validator guide

A Hyblis validator does one thing on chain: it sets weights from the public scoring ledger using the published
scoring code. It never has to run a miner's proof: verification happens in the runner, and its verdicts are
recorded on the ledger.

## What runs each round

1. Read the subnet's metagraph (UIDs, hotkeys, coldkeys).
2. Load the scoring ledger and compute miner shares with policy v2
   ([incentive-mechanism.md](incentive-mechanism.md)).
3. Drop any recipient that holds no UID or sits under the owner's coldkey; their share goes to the other miners.
4. Convert to u16 weights and submit them with `set_weights`.

## Run it

```bash
source env.sh
python validator/weights.py --mode direct --policy v2 \
    --owner-hotkey <subnet owner hotkey ss58> \
    --network test --netuid 626 \
    --wallet <your wallet> --wallet-hotkey <your validator hotkey> \
    --commit --loop 1500
```

- `--loop 1500` repeats every 25 minutes, above the subnet's 100-block weights rate limit and well inside the
  activity cutoff.
- Without `--commit` it only prints the weights it would set.
- A failed round (rate limit, network) is logged and retried after 10 minutes.

## Requirements

- Python 3.12 with `requirements.lock`, a registered hotkey with a validator permit, and enough stake to set weights.
- Read access to the scoring ledger. Every validator computes the same weights from the same ledger; the tests in
  `validator/test_weights.py` and `scoring/tests/` cover the conversion and the scoring.

> **Status:** the scoring ledger is not yet published as a public feed, so today only the subnet owner's validator
> can compute weights from it. Publishing it, so outside validators can run this loop independently, is planned
> before mainnet.

## Operator tool

`validator/operator_cli.py` is the subnet operator's tool for the filing queue (`queue`, `report`, `file`,
`accept`, `reject`), for reports waiting on fork state (`waiting`, `state-misses`, `release`) and for settlement.
Outside validators do not need it.
