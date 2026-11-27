# Aave V4 controls through the runner: results of the 2026-11-27 release

Every control in this folder was run through `runner/run_submission.py` exactly as the runner VM runs a job: as
root, forge as `pinc` inside an empty network namespace (`--sandbox netns`), a fresh read-only fork proxy per job
over the verified snapshot, the job's fresh accounts registered with the proxy, and the prepared project
`runner-data/projects/aave-v4` built with the runner's foundry.toml. Command:
`python -I tasks/cap/release/release.py --task aave-v4 controls --snapshot <S>` (as root).
Raw output: `runner-data/aave-v4/pins/26508006/controls-run1.json`.

| Item | Value |
|---|---|
| Pinned block | 26,508,006, hash `0x4b06deb027d15195f93348a0dbb3b68f303718a083e185881057157c9c12da09`, timestamp 1795800083 |
| Snapshot | `sha256:2b58f4aa25e51bfb4c238ae18b3a9c025924efb0de77e572e20c0dd7363d17e5` (version 3: built in the window, extended with the window's runs and one weETH slot), 15.9 MB |
| Snapshot counts | 478 accounts (359 existing, 279 with code, 2.1 MB code), 28,255 slots (10,159 non-zero), 27,525 trie nodes, 257 headers |
| Window | pinned +0 s, snapshot from the rehearsal +133 s, code verified from proven state +163 s (112 contracts, all match), runs collected +606 s, final +614 s; 55 blocks behind the head at the end |
| Spec | `tasks/aave-v4/impact-spec.json`, status verified, spec_sha256 `346275a08abd938be4a50c1570cd15a61a632aa97ef160cc9a1296c9c8b8e0b7` |
| Self-check | `release.py selfcheck`: ok, empty PoC `no_impact`, 0 state misses, 602 fresh reads |
| Engine | forge 1.9.0, runner files as in `runner/sol/SHA256SUMS` |

Each control ran twice. **runner** = what a submission gets (static screen first, then the trace engine).
**engine** = the same with the static screen skipped: the trace engine must reach the recorded verdict on its own.

| Control | Screen (exp) | Mode | Expected | Actual | Detail | Time | Misses | Fresh reads |
|---|---|---|---|---|---|---|---|---|
| flag_attacker_capital | FLAG (FLAG) | runner | no_impact | no_impact | no measured impact | 5.9 s | 0 | 908 |
|  |  | engine | no_impact | no_impact | no measured impact | 4.7 s | 0 | 908 |
| invalid_deal_protocol_token | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
|  |  | engine | capital | capital | token 0x531e90a2376902de8915789fcc1075e3b0c153e7 is not a capital token of this task | 3.6 s | 0 | 302 |
| invalid_ffi | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
|  |  | engine | policy:ffi(string[]) | policy:ffi(string[]) | cheatcode not allowed | 3.6 s | 0 | 303 |
| invalid_mock | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
|  |  | engine | policy:mockCall(address,bytes,bytes) | policy:mockCall(address,bytes,bytes) | cheatcode not allowed | 3.6 s | 0 | 303 |
| invalid_prank_protocol | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
|  |  | engine | impersonation | impersonation | prank(address) as protected address 0x94e7a5dcbe816e498b89ab752661904e2f56c485 | 3.5 s | 0 | 302 |
| invalid_step_gap | PASS (PASS) | runner | poc_shape | poc_shape | steps must be step1() .. stepN() without gaps | 1.5 s | 0 | 0 |
|  |  | engine | poc_shape | poc_shape | steps must be step1() .. stepN() without gaps | 1.5 s | 0 | 0 |
| invalid_store_hidden | FLAG (FLAG) | runner | policy:store(address,bytes32,bytes32) | policy:store(address,bytes32,bytes32) | cheatcode not allowed | 3.6 s | 0 | 307 |
|  |  | engine | policy:store(address,bytes32,bytes32) | policy:store(address,bytes32,bytes32) | cheatcode not allowed | 3.6 s | 0 | 305 |
| valid_sanity | PASS (PASS) | runner | no_impact | no_impact | no measured impact | 4.6 s | 0 | 909 |
|  |  | engine | no_impact | no_impact | no measured impact | 4.7 s | 0 | 907 |
| valid_supply_withdraw | FLAG (FLAG) | runner | no_impact | no_impact | no measured impact | 4.6 s | 0 | 914 |
|  |  | engine | no_impact | no_impact | no measured impact | 4.6 s | 0 | 910 |

All 18 runs match (`all_match: true`).

`valid_supply_withdraw` (an ordinary 100,000 USDC supply and withdrawal on the main spoke) measures attacker gain -1e-06 USD, capital 99994.656 USD, custody loss 0.0 USD, victim loss 0.0 USD over a TVL of 883,542,493 USD: the attacker's own position (attacker claims with a reserve id) nets out, as it must.
