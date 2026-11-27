# Hyblis runner: trace-verified validation

The runner decides whether a submitted proof of concept (PoC) shows a real, in-scope impact. It runs
**only on the separate runner machine** (`HYBLIS_RUNNER=1`). Design: `docs/runner-impact-design.md` and
`docs/research/runner-design/trace/design.md` (sections 4 to 15); this file documents what is built.

Nothing the PoC prints, asserts, labels or returns is read. The verdict comes from:
1. forge's raw JSON trace (`forge test --json -vvvv`, `decoded: null`), parsed with a size cap;
2. runner-owned code in frames the PoC cannot reach (the harness root, the probe, the faucet);
3. a runner-owned environment (no network, scrubbed environment, no files, no ffi, a read-only fork).

## Files

| File | Role |
|---|---|
| `run_submission.py` | One job: static screen, disposable job dir, `forge build`, harness pass 1, pass 2, standalone run, determinism and conformance, limits, verdict |
| `trace_verdict.py` | The verdict engine (template, cheatcode policy, attacker set, capital, measurements, classification, severity, changed function, conformance, error vocabulary) |
| `gen_spec.py` | impact-spec v2 -> generated `HyblisSpec.sol` + compiled spec; `--self-check` on a clean fork |
| `check.py` | `hyblis check`: the same flow on a researcher's machine against their own RPC, with plain-words reasons |
| `agent.py` | Daemon: claims jobs from the gateway, starts a per-job read-only fork proxy (`runner/state`), posts verdicts |
| `sol/HyblisHarness.t.sol` | The fixed harness test (hashed; pinned in `sol/SHA256SUMS`) |
| `sol/HyblisRuntime.sol` | `HyblisFaucet` (capital, attacker keys, trusted-role actions, price moves) and `HyblisProbe` (measurements) |
| `sol/HyblisBase.sol` | Researcher-visible base; identical copies in `tasks/<id>/poc/HyblisBase.sol` |
| `vm_selectors.json` | Cheatcode selector table (forge-std 1.15.0 `Vm`, 543 selectors); unknown selectors are rejected |
| `sanitize_foundry_toml.py` | Hardened `foundry.toml` (`--runner`: allowlisted compile keys + hardened runtime keys) |
| `policy_check.py` | Static screen of the file (pre-filter and filing screen only, not the security boundary) |
| `test_impact.py` | Engine unit tests on golden fixtures and tampered forge output (no forge) |
| `tests/` | Toy protocol, 97 PoC variants with expected verdicts (v61-v97: the 2026-11-16 conformance review's controls), end-to-end suite (`tests/run.sh`) |

`runner/state/` (fork snapshots and the read-only proxy) belongs to the state layer, not to this code.

## Flow of one job (`run_submission.py`)

| Step | What | Rejects with |
|---|---|---|
| R1 | Static screen (`policy_check.py`) and shape check (size, `contract HyblisPoC`, no imports of runner files) | `screen`, `poc_shape`, `limits` |
| R2 | Job dir: hard-linked copy of the prepared project (no `.git`, `broadcast`, `.env*`), real copies of `out/` and `cache/`, the PoC, the runner files, generated `HyblisSpec.sol` and `foundry.toml`; file hashes recorded | `runner_error` |
| R3 | `forge build --offline` | `compile` (line numbers in the PoC only), `poc_shape` |
| R3b | ABI shape: `setUp()`, `test_exploit()`, no other `test*`/`invariant*`, steps `step1()..stepN()` without gaps (N <= 16) | `poc_shape`, `limits` |
| R4 | Pass 1: harness test (`--json -vvvv --offline --no-storage-caching --disable-block-gas-limit --fuzz-seed 1`, anchored `--match-test '^test_hyblis\(\)$'`), analysed | any engine error |
| R6 | Pass 2: same, with `HYBLIS_ATTACKER_SET` = the attacker set of pass 1 | any engine error |
| R8 | Determinism: same PoC fingerprint and same spec measurements in both passes; one retry on a fresh job dir | `nondeterministic` |
| R9 | Standalone: plain `forge test` of `HyblisPoC.t.sol` (`test_exploit()`, default gas settings) must pass and do what was validated, with the PoC, attacker accounts and created contracts normalised: the same calls into in-scope code with the same outcome (success or revert); the same state-changing cheatcodes (`prank`/`startPrank`/`stopPrank`, `warp`, `roll`, `createSelectFork`) and HyblisBase helper calls, in the same order; and no cheatcode the policy denies, in the constructor, `setUp()` or `test_exploit()` (with steps, `test_exploit()` itself is checked here, since the runner only runs the steps). See "Conformance" below | `standalone_fails`, `standalone_differs` |
| R10 | Program rules: impact type in scope, not a known issue, not only through a benign entry point, severity cap | `out_of_scope`, `known_issue` |
| R11 | Verdict; job dir deleted. A non-empty misses list overrides everything | `state_miss` |

The harness root program (checked node by node by the engine): `envString(HYBLIS_ETH_RPC)`,
`envBytes32(HYBLIS_SALT)`, `envUint(HYBLIS_STEPS)`, probe CREATE, `makePersistent`, faucet `etch`, salt `store`,
`makePersistent`, `allowCheatcodes`, `startStateDiffRecording`, the harness's call to its own
`hyblisDeploy(salt)` with gas `poc_gas` (its only child is the PoC's salted `CREATE2`, so the PoC's address is
unpredictable and its constructor is capped like every other PoC call), `makePersistent`, `setUp()`,
`test_exploit()` or `step1()..stepN()` (each its own isolated transaction, each called with gas `poc_gas`),
`stopAndReturnStateDiff`, `stopPrank`, `clearMockedCalls`, `envOr(HYBLIS_ATTACKER_SET)`,
POST `measure` with its read set, probes, `revokePersistent`, baseline `createSelectFork(rpc, FORK_BLOCK)`,
`warp`/`roll` to the same final time and height, BASE `measure`, probes.

### Conformance (R9, `trace_verdict.standalone_check`)

The standalone run is plain `forge test` of the file the platform files, so it must do what the runner
validated. With the PoC (the standalone test contract), the attacker accounts (the faucet records the address
plain forge test gives each name) and the created contracts (by position) replaced by tokens:

1. the in-scope entries `(target, value, calldata, success)` (calls into in-scope code from outside it, not
   STATICCALL) are equal, so a call that only reverts (or only succeeds) in plain forge test differs;
2. the ordered list of state-changing cheatcodes and helper calls is equal: `prank`/`startPrank` (1 or 2 args),
   `stopPrank`, `warp`, `roll`, `createSelectFork` with their arguments and success, and each HyblisBase helper
   frame (`hyblisFund`, `hyblisDeal`, `hyblisAsRole`, `hyblisSetPrice`, a CALL to the PoC itself) with its
   arguments. Under the runner the helper frame calls the faucet; a faucet call outside such a frame has no
   counterpart in plain forge test, so it never matches;
3. every cheatcode of the standalone run passes the same default-deny policy: inside a helper frame only what
   the faucet may do for that helper (e.g. `record`/`accesses`/`load`/`store` on that token, `deal` of ETH to
   that account, `prank` of that role, `mockCall` on that feed), elsewhere only allowed cheatcodes issued by the
   PoC or contracts it created. This covers the constructor, `setUp()` and `test_exploit()`, which with steps
   never runs under the runner.

Anything else is `standalone_differs`.

### Command line

```
HYBLIS_RUNNER=1 python runner/run_submission.py --task cap --poc HyblisPoC.t.sol \
    --project /opt/hyblis-tasks/cap --fork-url /run/hyblis-fork/job.ipc [--misses-file misses.json] \
    [--sandbox netns --forge-user hyblis-forge] [--submission <id>] [--out verdict.json]
```

* `--fork-url` is what `HYBLIS_ETH_RPC` is set to for every forge run: normally the Unix socket path of the
  read-only fork proxy. The engine requires the PoC's single fork and the baseline fork to use exactly it.
* `--misses-file`: read after the runs (the state proxy's miss document `{"misses": [...]}`, a JSON list, or
  JSON lines). Non-empty means `{"reproduced": false, "error": "state_miss", "state_misses": [...]}` and
  nothing else is decided. From Python, `reproduce(..., fork=<handle>)` reads `handle.misses()` instead
  (`agent.py --snapshots` starts one proxy per job and does this).
* `--sandbox netns` (default) needs root: each forge process runs as
  `unshare --net -- setpriv --reuid=<forge-user> ... -- chrt --idle 0 nice -n 19 env -i <scrubbed> prlimit --fsize=<cap> --core=0 --as=32G -- forge ...`.
  The namespace has no interfaces, so a PoC cannot reach any network (an IPC socket path still works).
  `--sandbox none` exists for tests and `hyblis check`; the verdict records which sandbox ran.
* Environment of forge: `PATH` (Foundry and /usr/bin:/bin), `HOME` and `TMPDIR` inside the job, `LANG`,
  `NO_COLOR`, `FOUNDRY_DISABLE_NIGHTLY_WARNING`, `HYBLIS_ETH_RPC`, and for harness runs `HYBLIS_SALT`,
  `HYBLIS_STEPS`, `HYBLIS_ATTACKER_SET`. Nothing else (no dispatch token).
* Limits: forge output `limits.json_max_mb` (default 256 MiB; RLIMIT_FSIZE and a parse cap), each forge run
  `limits.forge_timeout_s` (900 s), whole job `limits.job_timeout_s` (2700 s), `poc_gas` per PoC call
  (300M default, <= 1e9), at most 64 attacker accounts and 16 steps, PoC file <= 256 KiB.
  * `poc_gas` caps every PoC call: the constructor (the harness deploys the PoC inside its own call to
    `hyblisDeploy`, given `poc_gas`; a CREATE cannot be given a gas cap itself, so the constructor gets 63/64 of
    what is left of it), `setUp()`, and `test_exploit()` or each step. A PoC call that runs out of it (its frame
    ends out of gas, e.g. `OutOfGas`/`MemoryOOG`/`MemoryLimitOOG`, or reverts after a sub-call took its last
    gas), or a constructor whose `gas_used` is above it, is rejected as `limits`, not `poc_reverted`.
  * The harness test's own budget (`gas_limit` of the generated `foundry.toml`, also used by the standalone run)
    is `gen_spec.harness_gas_limit(spec)` = `(2 + max_steps) x poc_gas` + both measurements at their worst
    case (every balance/view read at the probe's 5M cap, with 64 attacker accounts) + every probe's gas twice
    + a 1e9 reserve for the harness itself, so a PoC within every documented limit never runs short. If a PoC
    call is still given less than `poc_gas`, the verdict is `limits` ("total gas budget"), never a guess.
* `--no-idle` on a dedicated runner VM; by default forge runs at idle CPU priority.

### What the runner VM needs

* Root for the network namespace (or run inside a container started with `--network none`), and an
  unprivileged `--forge-user` (forge never runs as root).
* Foundry 1.9.0, exactly the build `run_submission.FORGE_COMMIT` (`forge --version` must print the lines
  `forge Version: 1.9.0` and `Commit SHA: 6056c5845d34205a83cf7108042adb137325c9df`; a nightly, a dev build or
  another commit is refused as `runner_error`), and the solc versions the tasks pin, under
  `$HYBLIS_ROOT/.home/.svm/<v>/solc-<v>` (never downloaded).
* Python 3.12 with `eth-abi`, `eth-utils` (the Hyblis venv).
* Prepared task projects under `--projects/<task>`: the program's repo with dependencies installed, no secrets
  and no `.env` files, built once with the runner's generated `foundry.toml` so `out/`/`cache/` are reused.
* Verified snapshots per task for `runner/state` (`--snapshots`), or another read-only fork source.
* Recommended: cgroup limits around the agent (memory 8 GB, CPU quota, pids limit), one job per VM at a
  time, the VM itself as the outer boundary (disposable, no secrets besides the dispatch token).

### Fork from a verified snapshot (option B): fresh accounts

With a snapshot (`agent.py --snapshots`, `gen_spec.py --self-check --snapshot`, or any `fork=<handle>` passed to
`reproduce`), run_submission registers the job's **fresh set** with the proxy right after the build: the PoC's
salted CREATE2 address, attacker accounts 1..64 and the contracts they create (`fresh_set`). The proxy answers
those accounts as absent and slots keyed by them as zero, because they derive from the job's secret drawn long
after the pinned block (runner/state/README.md, "Fresh accounts of a job"). Without this every job missed state
(the harness measures the PoC's token balances), found on the first real-chain run (Cap, 2026-11-16).
For that, `HyblisFaucet.attackerKey` hands out keys by index (`keccak256(abi.encode(salt, index))`, one index per
distinct name, first-call order) instead of by name, so the runner knows every attacker address in advance;
same name, same key, as before. `timings.fresh_s` records the cost (about 0.2 s).

**Projects with linked libraries** (found on Cap, 2026-11-16): forge 1.9.0 deploys every external library of
the project before the test contract, each in its own leading `Deployment` arena (a CALL from forge's library
deployer `0x1F95…7353` to the CREATE2 factory with one CREATE2 child). The engine used to accept exactly one
Deployment arena, so every Cap PoC was rejected as `template`. It now accepts leading library arenas in exactly
that shape (`trace_verdict._check_library_arena`; anything else, or one after the test contract, is still
`template`); the last Deployment arena must be the harness, as before. Tested in `test_impact.py` with a real
arena from Cap (`tests/fixtures/library_arena.json`).

`agent.py --snapshots DIR` serves `DIR/<task>/<digest hex>` when the task manifest records
`chain.snapshot_digest` (else `DIR/<task>`) and refuses any snapshot with another digest.

## Verdict JSON

```json
{"submission_id": "...", "reproduced": true, "deterministic": true,
 "impact_type": "funds_loss", "measured_severity": "medium",
 "changed_function": "withdrawFor(address,uint256)", "changed_contract": "0x9fe4...",
 "evidence": {"amount_usd": 50.0, "victim_loss_usd": 50.0, "custody_loss_usd": 50.0, "claims_loss_usd": 50.0,
              "attacker_gain_usd": 50.0, "capital_usd": 0.0, "tvl_usd": 109580.0,
              "broken_invariants": [], "probe_flips": [], "unbacked_mint": null, "price_moves": {},
              "final_timestamp": 1794853664, "helpers": {}},
 "state_misses": [], "error": null, "detail": "",
 "attacker_set": ["0x...", "0x..."], "fingerprints": {"poc": "...", "measure": "..."},
 "runner": {"version": "trace-1.1", "foundry": "1.9.0-6056c58", "spec_sha256": "...", "files": {"...": "sha256"},
            "salt": "0x...", "steps": 0, "sandbox": "netns", "timings": {...}, "attempts": 1, "elapsed_s": 0.9}}
```

A rejection has `reproduced: false`, an `error` code and a runner-written `detail` (never PoC-controlled
text). The static screen adds `policy: [{"reason", "line"}]` about the miner's own file. Keys the pipeline
consumes: `reproduced`, `deterministic`, `impact_type`, `measured_severity`, `changed_function`,
`changed_contract`, `evidence`, `error`, `state_misses`.

### What the fork proxy saw decides last (`run_submission.finalize`)

1. A request the read-only proxy refused (anything other than forge's own `anvil_nodeInfo` probe)
   rejects the job as `fork`.
2. A rule violation (`policy:*`, `screen`, `poc_shape`, `compile`, `limits`, `impersonation`, `fork`,
   `env`, `time`, `reentry`, `capital`, `helper`) stands even if the run also read outside the
   snapshot: such jobs never wait, so their misses never reach a snapshot extension.
3. Otherwise any miss means nothing is decided: `state_miss`, and the platform holds the job until the
   operator extends the snapshot. (Outcomes such as `template`, `harness_failed` or `poc_reverted`
   can be caused by a missing read, so they wait too.)

The platform keeps at most 32 missing items per job (`RUNNER_MAX_MISSES_PER_JOB`).

### Error vocabulary (fixed; plain-words text in `trace_verdict.ERRORS`)

| Code | Meaning |
|---|---|
| `state_miss` | fork read outside the snapshot; held until the snapshot is extended (retry, not a judgement) |
| `runner_error` | runner/infrastructure fault (retry, not a judgement) |
| `screen` | static screen rejected the file |
| `poc_shape` | not one `HyblisPoC` with `setUp()` + `test_exploit()` (+ numbered steps), or imports a runner file |
| `compile` | does not compile |
| `no_json` | forge produced no readable output (`vm.pauseTracing`, crash) |
| `limits` | output, time, gas (a PoC call, constructor included, above `poc_gas`), attacker-account, step or file-size limit |
| `template` | the harness did not run exactly its program, or forge's output format changed: unknown keys, or a value of another type than forge 1.9.0 writes (fail closed, never a retried crash) |
| `harness_failed` | the harness failed after the PoC returned (pending expectation) |
| `policy:<cheatcode signature>` | forbidden or unknown cheatcode, even attempted; or a cheatcode/faucet call whose arguments are not canonical ABI and cannot be read the way forge reads them (forge ignores the high bytes of an address word, and so does the engine: such a `prank` is judged by the low 20 bytes) |
| `impersonation` | prank or signature as an account the PoC does not control |
| `fork` | not exactly one fork, in `setUp()`, at the pinned block, through the runner's URL |
| `env` | environment read other than `HYBLIS_ETH_RPC` |
| `time` | warp/roll backwards or beyond the task's limits |
| `reentry` | runner contracts reached (harness, probe, faucet by delegatecall) or cheatcodes outside the PoC's frames |
| `capital` | faucet misuse: token not capital, recipient not controlled, above the cap |
| `helper` | `_asRole` / `_setPrice` outside what the spec allows |
| `poc_reverted` | constructor, `setUp()`, `test_exploit()` or a step reverted under the harness |
| `measurement_failed` | a balance read failed, watched code changed, or an attacker account held state at the block |
| `nondeterministic` | the two passes differ (after one retry) |
| `standalone_fails` / `standalone_differs` | plain forge test fails / makes other in-scope calls (or with another outcome), other state-changing cheatcodes or helper calls, or uses a denied cheatcode |
| `no_impact` | nothing measured above the threshold |
| `out_of_scope` | impact type not in scope, not caused by an in-scope contract, or only via a benign entry point |
| `known_issue` | matches a known issue |

## What researchers write (rules on the program page)

1. One file `test/hyblis/HyblisPoC.t.sol`, `contract HyblisPoC is HyblisBase`, importing `./HyblisBase.sol`.
2. `setUp()` forks exactly once: `vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK)`.
3. One test, `test_exploit()`. Exploits that need separate transactions put each one in a public
   `step1()..stepN()`; `test_exploit()` calls them in order. The runner calls each step as its own
   depth-1 (isolated) transaction, and checks that the standalone run makes the same calls (and that
   `test_exploit()` itself uses no cheatcode the policy denies).
4. Act only as accounts from `makeAddr`/`makeAddrAndKey` (under the runner they are derived from a
   per-submission secret, so they are unpredictable and empty at the pinned block), contracts the PoC or
   those accounts deploy, or the PoC itself. `vm.addr(<fixed key>)` accounts are not controlled.
5. Capital only through `_fund(token, to, amount)` (or `deal()`, which HyblisBase routes to the faucet),
   only capital tokens of the task, within `capital_cap`. Capital is subtracted from the measured gain.
6. `_asRole(role, target, data)`: one call as a trusted role, only if `trusted_actions` lists it.
   `_setPrice(feed, answer)`: a Chainlink-style feed move, only listed feeds within `max_move_bps`;
   the moved price is also used to value that token. Both fall back to `vm.prank` / `vm.mockCall` in
   plain forge test, so the filed file still runs. `_fund`, `deal`, `_asRole` and `_setPrice` each run
   in their own call frame on the PoC (`hyblisFund`, `hyblisDeal`, `hyblisAsRole`, `hyblisSetPrice`;
   the faucet under the runner, forge-std cheatcodes in plain forge test), so the runner can match the
   two runs helper by helper; use them from `HyblisPoC` itself, not from its constructor (they revert
   there) or from helper contracts.
7. Allowed cheatcodes (default deny, checked call by call): `prank`/`startPrank`(1 or 2 args, own
   accounts), `stopPrank`, `warp`/`roll` (forward, within limits), `addr`, `label`, `getLabel`,
   `sign`/`signCompact` (own keys), `load`, `recordLogs`/`getRecordedLogs`, `getBlockTimestamp`,
   `getBlockNumber`, `getNonce`, `getChainId`, `assume`, `computeCreate*Address`, `toString`,
   `lastCallGas`, every `assert*`, `expectRevert*`, `expectPartialRevert*`, `expectEmit*`,
   `expectEmitAnonymous*`, `expectCall*`, `expectCallMinGas*`, and `envString("HYBLIS_ETH_RPC")`.
8. Asserts and logs are ignored; the file must pass in plain `forge test` (it is the file that is filed),
   and do there what it did under the runner (R9): no code path that only runs outside the runner may
   call in-scope code differently, change the outcome of such a call, or use other cheatcodes.
9. Every PoC call (constructor, `setUp()`, `test_exploit()` or each step) may use at most the task's
   `poc_gas`.

`python runner/check.py --task <id> --poc <file> --project <task project> --rpc <your archive RPC>` gives
the runner's verdict locally (same harness, same engine; no network sandbox). Security never depends on the
runner files being secret: researchers get them with `hyblis check`.

## impact-spec v2 (`tasks/<id>/impact-spec.json`)

Written by Hyblis per task. `gen_spec.py` validates it strictly (unknown keys are errors; keys starting with
`_` or ending in `_note` are comments), resolves references (`"@<holder id>"`, `"@<token symbol>"`,
`"@<in-scope name>"`), and refuses specs whose `status` is not `verified` or that still list
`pending_verification`, unless `--allow-draft`.

| Key | Content |
|---|---|
| `task_id`, `spec_version: 2`, `status` | `verified` / `draft` / `scaffold` |
| `pending_verification` | list of open items (drafts only) |
| `fork` | `chain_id`, `block`, `block_hash`, `timestamp`, `rpc_env: "HYBLIS_ETH_RPC"` |
| `limits` | `max_warp_s`, `max_roll` and `horizon_basis` (which protocol horizon they come from: cooldowns, vesting, interest; not the damage window), `poc_gas`, `max_attackers`, `max_steps`, `json_max_mb`, `forge_timeout_s`, `job_timeout_s` |
| `harness` | `poc_test: "test_exploit()"` |
| `tokens[]` | `symbol`, `address` (`0x0` = ETH), `decimals`, `usd` (price at the block, decimal string), `capital` + `capital_cap` (raw units), or `issued_by_protocol` + `supply_view` (never both) |
| `holders[]` | `id`, `address`, `role`: `custody` (value-holding protocol address; every one must be listed), `victim`, `watch`; optional `value_views: [{view, token}]` (receivables counted as custody value, e.g. total borrows) |
| `in_scope[]` | `name`, `address`, optional `implementation`, `functions` (signatures) or `abi_file` (names for the changed function) |
| `protected_extra[]` | more addresses that may never be pranked or funded (admins, role holders, sinks) |
| `views[]` | `id`, `target`, `sig`, `args`, `type` (uint/int/bool/address/bytes32), `role`: `state` or `victim_claim` (+ `token`: a decrease is a victim loss) |
| `attacker_claims[]` | `id`, `target`, `sig`, `type`, `token`, `sign` (+1 asset such as a deposit, -1 liability such as debt) measured for every attacker account. A one-address `sig` needs nothing more; any other takes `args` with exactly one `"@account"` (an address argument) and static types only, e.g. `getUserTotalDebt(uint256,address)` with `[7, "@account"]` |
| `invariants[]` | `id`, `class` (`solvency` -> insolvency, `accounting` -> accounting_error), `holds` (expression over view ids and `bal_<SYMBOL>_<holder id>`: arithmetic, comparisons, and/or/not), `shortfall` + `units` (solvency) |
| `probes[]` | `id`, `class` (`freeze` -> funds_freeze, `liveness` -> dos), `actor`, `target`, `sig`, `args`, `gas`, `at_risk` (view id) and `at_risk_token` |
| `trusted_actions[]` | `id`, `role`, `target`, `sig`, `args` (per argument `null` or `{eq|min|max}`), `max_calls` |
| `price_feeds[]` | `id`, `feed`, `token`, `decimals`, `answer` (at the block), `max_move_bps` |
| `benign_entry_points[]` | `{contract: <in-scope name>, function: <sig>}` (by-design value transfers, e.g. liquidations) |
| `known_issues[]` | `{id, contract, function, impact}` |
| `thresholds` | `min_usd` |
| `severity` | `max`, and per impact `default`, optional `high_if_tvl_share`, `high_if_usd`, `critical_if_tvl_share`, `critical_if_usd` |
| `in_scope_impacts` | subset of `funds_loss, unauthorized_mint, insolvency, funds_freeze, griefing, accounting_error, dos` |

Classification (first match; θ = `min_usd`; values at the spec's fixed prices, or a feed's moved price):
`funds_loss` (gain >= θ and loss >= θ; amount min of the two), `unauthorized_mint`, `insolvency` (a solvency
invariant breaks and a balance effect or probe flip corroborates it; amount = its shortfall minus what the
protocol owes the attacker accounts themselves in that token, i.e. their own deposits), `funds_freeze` (freeze
probe flips with >= θ at risk; at risk = the probe's `at_risk` view on the clean fork and on the exploited fork,
whichever is lower: funds still owed but not withdrawable. A claim that was taken, not frozen, is no freeze),
`griefing` (loss >= θ, gain < θ), `accounting_error` (capped at low without corroboration), `dos`, else
`no_impact`. Loss = max(custody loss per holder, victim-claim decreases). Gain = attacker accounts' value change
+ attacker claims (signed) - capital. Invariants and probes count only if they hold / succeed on the clean fork;
a failed read is unknown, never broken.

Changed function (`trace_verdict._anchor`, design 7.9): the first in-scope entry frame of the exploit whose writes
back the measured impact. For a loss, griefing or insolvency: it decreases a victim-claim slot, or value leaves
custody (token balance slots, ETH sent by a custody account) beyond what the attacker accounts' claims fell by,
or the attacker accounts' claims rise beyond what entered custody (balance slots, ETH paid into a custody
account by the call that opens the frame). Claims are signed: a liability such as debt counts negative, so a
borrow (custody out, debt up) or a collateral deposit (ETH in, collateral up) is not an anchor. For a freeze: it
writes the slot the flipped probe last read (else any slot it read); for a mint: it raises an attacker balance or
a state view. Only `accounting_error` and `dos` fall back to the first in-scope frame that wrote a measured slot,
then any write; any other impact without an anchor was not caused by in-scope code: `out_of_scope`.

Self-check before release (also the CI rule "an empty PoC gets no impact"):
`python runner/gen_spec.py tasks/<id>/impact-spec.json --self-check --project <prepared project> --snapshot <snapshot dir> --task-manifest tasks/<id>/manifest.json`
(serves the snapshot in-process so the job's fresh accounts are registered; a separate `fork_proxy.py serve`
process cannot register them, so `--fork-url <its socket>` misses on the harness's own reads)
checks the block hash and timestamp, every view, invariant, probe and feed answer on the clean fork.

## Maintenance

* **Runner files** (`sol/*.sol`): after any change, `cd runner/sol && sha256sum HyblisBase.sol HyblisRuntime.sol HyblisHarness.t.sol > SHA256SUMS`,
  copy `HyblisBase.sol` to every `tasks/<id>/poc/`, regenerate fixtures, run `runner/tests/run.sh`.
* **Selector table**: in a project with forge-std 1.15.0,
  `FOUNDRY_SOLC=<solc> forge inspect lib/forge-std/src/Vm.sol:Vm methodIdentifiers --json` -> `vm_selectors.json` (`selectors`).
* **Foundry upgrade**: the engine depends on 1.9.0's JSON arena format (unknown keys, `ignored`, new trace
  fields fail closed) and on its defaults; re-run the full variant suite and the design's experiments first.
* **Fixtures**: `runner/tests/test_e2e.py --update-fixtures --only v01,v14,v24,v35,v36,v40,v42` (as root or pinc).
* **Task compile check**: `runner/tests/compile_task.py cap` compiles the template, the controls and the
  runner files against the prepared project without running anything.
* **Tests**: `runner/tests/run.sh` (as root it also tests the network namespace); `scripts/run_tests.sh`
  runs the engine unit tests and the end-to-end suite as pinc.
