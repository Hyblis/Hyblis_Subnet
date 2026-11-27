# Programs

One folder per program. Only programs listed as `featured` or `open` in [`releases.json`](releases.json) are
published; programs queued for release are kept outside this repository.

| Program | State | Fork state |
|---|---|---|
| [`cap`](cap) | Open on testnet | Ethereum mainnet at block 26,429,948; verified live sources in `cap/live-sources/`; 8 control proofs with results in `cap/controls/RESULTS.md` |
| [`aave-v4`](aave-v4) | Featured for mainnet, not yet ready | Verification pass pending (fork block and in-scope addresses) |

## What a program folder holds

| File | Purpose |
|---|---|
| `manifest.json` | Pinned chain (block, block hash, snapshot digest), deployed in-scope addresses, submission rules |
| `impact-spec.json` | What the runner measures: tokens, holders, in-scope contracts and functions, views, invariants, probes, thresholds |
| `program-rules.json` | The public rules shown on the program page |
| `poc/HyblisPoC.t.sol` | The proof template miners start from |
| `poc/HyblisBase.sol` | The helper base contract (the runner uses its own copy) |
| `controls/` | Known-good and known-bad proofs with their expected verdicts |
