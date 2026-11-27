# Cap controls through the runner: results of the 2026-11-16 release

Every control in this folder was run through `runner/run_submission.py` exactly as the runner
VM runs a job: as root, forge as `pinc` inside an empty network namespace (`--sandbox netns`), a fresh
read-only fork proxy per job (`runner/state/fork_proxy.serve`, Unix socket) over the verified snapshot,
the job's fresh accounts registered with the proxy (what `agent.py --snapshots` does), the prepared
project `runner-data/projects/cap` built with the runner's foundry.toml. Command:
`HYBLIS_RUNNER=1 python -I tasks/cap/release/release.py controls --snapshot <S2>` (as root).
Raw output: `runner-data/cap/pins/26429948/controls-run2.json`.

| Item | Value |
|---|---|
| Pinned block | 26,429,948, hash `0x6beda9fc624cf8f81b5f1f860a892108415880a693eb5a5169c0d1d805389df6`, timestamp 1794860495 (2026-11-16 20:21:35 UTC) |
| Snapshot | `sha256:e852e36fa99191df46d676f1a5544003e7d183c27a98eee594c0f57272542fde` (version 2, parent `sha256:567a7a61…6d09`), `runner-data/snapshots/cap/e852e36f…2fde/`, 11.1 MB |
| Snapshot counts | 450 accounts (331 existing, 304 with code, 1.2 MB code), 19,281 slots (10,292 non-zero), 21,682 trie nodes, 257 headers (pinned + 256 ancestors), full EIP-2935 ring |
| Spec | `tasks/cap/impact-spec.json`, status verified, spec_sha256 `e94bf6890b9c9a87e3702b782117fd46692c5e9af6cd19d5db812f47bf370ae1` |
| Self-check | `release.py selfcheck`: ok, no problems, empty PoC `no_impact`, 0 state misses, 12 fresh reads, 6.7 s |
| Engine | trace-1.0, forge 1.9.0-6056c58, runner files as in `runner/sol/SHA256SUMS` |

Each control ran twice. **runner** = what a submission gets (static screen first, then the trace engine).
**engine** = the same with the static screen skipped: the trace engine must reach the recorded verdict
on its own, because the screen is only a pre-filter. Expected values are `expected.json` (`policy` for the
screen, `verdict` for the engine).

| Control | Screen (exp) | Mode | Expected | Actual | Detail (runner-written) | Time | Misses | Fresh reads |
|---|---|---|---|---|---|---|---|---|
| flag_attacker_capital | FLAG (FLAG) | runner | no_impact | no_impact | no measured impact | 6.5 s | 0 | 16 |
| | | engine | no_impact | no_impact | no measured impact | 4.1 s | 0 | 16 |
| invalid_deal_protocol_token | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
| | | engine | capital | capital | token 0xcccc…cccc is not a capital token of this task | 3.6 s | 0 | 8 |
| invalid_ffi | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
| | | engine | policy:ffi(string[]) | policy:ffi(string[]) | cheatcode not allowed | 3.4 s | 0 | 5 |
| invalid_mock | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
| | | engine | policy:mockCall(address,bytes,bytes) | policy:mockCall(address,bytes,bytes) | cheatcode not allowed | 3.4 s | 0 | 7 |
| invalid_prank_protocol | REJECT (REJECT) | runner | screen | screen | static screen | 0.0 s | 0 | 0 |
| | | engine | impersonation | impersonation | prank(address) as protected address 0x15622c3d…01fc (the Lender) | 3.5 s | 0 | 8 |
| invalid_step_gap | PASS (PASS) | runner | poc_shape | poc_shape | steps must be step1() .. stepN() without gaps | 2.4 s | 0 | 0 |
| | | engine | poc_shape | poc_shape | same | 2.4 s | 0 | 0 |
| invalid_store_hidden | FLAG (FLAG) | runner | policy:store(address,bytes32,bytes32) | policy:store(address,bytes32,bytes32) | cheatcode not allowed | 3.5 s | 0 | 11 |
| | | engine | policy:store(address,bytes32,bytes32) | policy:store(address,bytes32,bytes32) | cheatcode not allowed | 3.5 s | 0 | 9 |
| valid_sanity | PASS (PASS) | runner | no_impact | no_impact | no measured impact | 4.0 s | 0 | 15 |
| | | engine | no_impact | no_impact | no measured impact | 4.1 s | 0 | 21 |

**16/16 match, 0 state misses, 0 refused requests** (besides forge's `anvil_nodeInfo` probe), one attempt
each, sandbox `netns` for every run that reached forge.

Why each verdict is right (and not an accident):

- `flag_attacker_capital`: 100,000 USDC through the faucet (capital, within the 281.3M cap), one-day warp
  (within the 3-day limit). Capital is subtracted from the gain, nothing moved: no impact. After the warp
  the cUSD burn probe fails in both the exploited and the clean fork (the oracle goes stale about 14 h after
  the pin, see the spec's horizon_basis), so it is unhealthy and ignored, never counted as a freeze; the
  stcUSD redeem probe does not use the oracle and succeeds in both.
- `invalid_deal_protocol_token`: `deal(cUSD, …)` is routed to the faucet; cUSD is issued by the protocol,
  never capital, so the engine rejects the faucet call itself.
- `invalid_ffi`, `invalid_mock`, `invalid_store_hidden`: the forbidden cheatcode is found in forge's raw
  trace, also when hidden in a helper contract with a computed selector (`invalid_store_hidden`, which the
  static screen only flags).
- `invalid_prank_protocol`: `vm.prank(Lender)` then `cUSD.borrow` (a fake theft of 1M USDC): the Lender is
  an in-scope contract, so the prank is impersonation, even though plain forge test "passes".
- `invalid_step_gap`: `step1`, `step3` -> shape error from the compiled ABI before any run.
- `valid_sanity`: read-only checks of the fork pass, nothing measured.

Timings per job (runner mode, from the verdicts): build 0.9-1.0 s (only the PoC and runner files compile;
the prepared project's cache is reused), fresh-set registration 0.75 s (3.1 s on the first job: discovery
of the snapshot's mapping bases, cached per digest), each forge pass 0.26-0.31 s against the snapshot.

## Re-run after the runner conformance fixes (2026-11-16, later the same day)

The runner conformance review (findings F1-F9) changed the harness and HyblisBase, so every control was run again,
with the same command, snapshot and spec as above: engine **trace-1.1**, forge 1.9.0 commit
`6056c5845d34205a83cf7108042adb137325c9df` (now pinned exactly), runner files `HyblisBase.sol` `31d0fce2…7354`,
`HyblisRuntime.sol` `abcd8776…47d1` (unchanged), `HyblisHarness.t.sol` `4e1289b0…213f`. What changed for a Cap job:
the PoC is deployed inside the harness's own `hyblisDeploy()` call capped at `poc_gas` (same salted address);
`_fund`/`deal`/`_asRole`/`_setPrice` run in their own call frame on the PoC (`hyblisFund` etc.), which calls the
faucet; the harness gas budget is the task's `(2 + max_steps) x poc_gas` + measurement reserve (10.14e9 for Cap,
was a flat 4e9); the standalone run is compared on outcomes, state-changing cheatcodes and helper calls too.

| Control | Mode | Expected | Actual | Time | Misses | Fresh reads |
|---|---|---|---|---|---|---|
| flag_attacker_capital | runner | no_impact | no_impact | 5.9 s | 0 | 22 |
|  | engine | no_impact | no_impact | 4.2 s | 0 | 20 |
| invalid_deal_protocol_token | runner | screen | screen | 0.0 s | 0 | 0 |
|  | engine | capital | capital | 3.6 s | 0 | 8 |
| invalid_ffi | runner | screen | screen | 0.0 s | 0 | 0 |
|  | engine | policy:ffi(string[]) | policy:ffi(string[]) | 3.6 s | 0 | 7 |
| invalid_mock | runner | screen | screen | 0.0 s | 0 | 0 |
|  | engine | policy:mockCall(address,bytes,bytes) | policy:mockCall(address,bytes,bytes) | 3.6 s | 0 | 5 |
| invalid_prank_protocol | runner | screen | screen | 0.0 s | 0 | 0 |
|  | engine | impersonation | impersonation | 3.6 s | 0 | 6 |
| invalid_step_gap | runner | poc_shape | poc_shape | 2.5 s | 0 | 0 |
|  | engine | poc_shape | poc_shape | 2.5 s | 0 | 0 |
| invalid_store_hidden | runner | policy:store(address,bytes32,bytes32) | policy:store(address,bytes32,bytes32) | 3.6 s | 0 | 11 |
|  | engine | policy:store(address,bytes32,bytes32) | policy:store(address,bytes32,bytes32) | 3.6 s | 0 | 9 |
| valid_sanity | runner | no_impact | no_impact | 4.1 s | 0 | 15 |
|  | engine | no_impact | no_impact | 4.2 s | 0 | 15 |

**16/16 match (`"all_match": true`), 0 state misses, 0 refused requests**, one attempt each, sandbox `netns` for
every run that reached forge. Every verdict and every runner-written detail is identical to the release run
above; only the fresh-read counts move (they depend on each job's random salt: they also differed between the
runner and engine modes of the release run). Timings are unchanged (build 1.0 s, fresh-set registration 0.73 s,
2.5 s on the first job, each forge pass 0.26-0.32 s). The table is the final run on the final code; an earlier
run during the fixes gave the same 16 verdicts and details. The raw output of this run was not added to
`runner-data/cap/pins/26429948/` (the release record there stays as it was).

## Earlier runs during this release (for the record)

- Rehearsal at block 26,429,808 (no proofs; recording proxy in front of eth.drpc.org, sandbox none): the
  first pass gave `template` for every harness run. Cause: an engine bug (forge deploys the project's 12
  linked libraries in leading Deployment arenas; fixed in `runner/trace_verdict.py`, see the report).
  After the fix all 8 controls gave their expected engine verdicts there too.
- Before the fresh-account fix (`runner/state/fresh.py`), every job against a snapshot ended in
  `state_miss` (the harness measures the salted PoC address), including the empty PoC.
- At the pin, a first control run without the engine-only mode showed `screen` for the four REJECT
  controls (correct: the runner screens first); the table above runs both modes.
