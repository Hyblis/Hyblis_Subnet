# runner/state: verified state snapshots and the read-only fork proxy

Fork state on the runner comes from a **per-program verified state snapshot**. The runner has no network. forge forks from a Unix socket
served by `fork_proxy.py` from a snapshot that the operator built and that the proxy re-verifies
from the pinned block hash every time it starts. Nothing is ever guessed: a read outside the
snapshot is a JSON-RPC error, the run fails, the miss is recorded, and the job is re-queued after
`snapshot.py extend`. A third-party RPC is never used during a miner's run.

| File | Role |
|---|---|
| `mpt.py` | Merkle-Patricia proof verification (inclusion and exclusion), account/storage decoding, block-header RLP and hash (London to Prague fields) |
| `store.py` | Snapshot format: deterministic writer, in-memory loader, full offline verifier, content digest |
| `fork_proxy.py` | Runner side. `serve(snapshot_dir, socket_path) -> handle` (`.misses()`, `.refusals()`, `.stats()`, `.write_misses()`, `.close()`) and a CLI |
| `snapshot.py` | Operator side. `collect`, `build`, `extend`, `verify`, `info` |
| `jsonrpc.py` | JSON stream framing, upstream clients (http(s) or IPC), the asyncio Unix-socket server |
| `fresh.py` | Fresh accounts of a runner job (addresses derived from the job's secret): answered without a snapshot entry, see below |
| `tests/run.sh` | Single entry point for the tests (unit and end-to-end; anvil and forge, no network) |

## Trust model

Only one value is trusted: the pinned block hash in `tasks/<id>/manifest.json` (`chain.fork_block_hash`).
Everything else is derived from it on every load:

1. `keccak(rlp(header fields)) == pinned hash` gives the trusted header, and with it `stateRoot`.
2. Each stored account is re-walked from `stateRoot` through the stored trie nodes (each node keyed by
   its own keccak). The walk ends either at the account's leaf, whose fields must equal the stored
   row, or at a proof of absence, in which case the row must say `exists = 0`.
3. Each stored slot is re-walked from the account's proven `storageRoot`. Zero slots are proven by
   exclusion.
4. `keccak(code) == codeHash`.
5. Ancestor headers are checked by the `parentHash` chain down from the pinned header.
6. Every stored trie node must be used by some walk. Orphan nodes are refused.
7. The content digest, file sha256s and manifest fields must all match.

The pinned block must be final (it is days old for every program), so a reorg cannot change it.

## Snapshot format (`hyblis-state-snapshot/1`)

A directory with three read-only files:

```
manifest.json   identity, header fields, counts, sha256 of the other two files, content digest
header.json     the pinned block object exactly as fetched (eth_getBlockByNumber(N, false)), sorted keys
state.sqlite    the state (schema below)
```

### manifest.json

Canonical JSON (sorted keys, indent 1). Fields:

- **Identity:** `format`, `digest` (`sha256:` content digest, defined below), `version` (1 for a
  build, +1 per extend), `parent_digest` (`null` for a build).
- **Block:** `chain_id`, `block_number`, `block_hash`, `state_root`, `parent_hash`.
- **Header fields forge uses:** `timestamp`, `base_fee_per_gas`, `gas_limit`, `gas_used`,
  `coinbase`, `difficulty`, `prev_randao` (`mixHash`), `blob_gas_used`, `excess_blob_gas`,
  `parent_beacon_block_root`, `withdrawals_root`, `requests_hash`. Integers are decimal, hashes hex.
- `header`: every header field in JSON-RPC naming, plus `hash`. It is re-derived from the verified
  header RLP on every load.
- `created_at`: from `$SOURCE_DATE_EPOCH` if set, else now.
- `source_rpc`: the host of the upstream only (never a path, key or query string); `ipc` for a socket.
- `counts`: `accounts`, `existing_accounts`, `accounts_with_code`, `code_bytes`, `storage_slots`,
  `nonzero_slots`, `trie_nodes`, `headers`. `ancestors`: `{count, lowest}`.
- `files`: `{state.sqlite: sha256, header.json: sha256}`. `state_sha256` repeats the first one.
- `proofs_verified: true`.
- `notes`: build options and inputs. Informational; not part of the digest.

### state.sqlite

```sql
meta       (key TEXT PRIMARY KEY, value TEXT)            -- format, chain_id, block_number, block_hash, state_root, proofs_verified='1'
headers    (number INTEGER PRIMARY KEY, hash TEXT UNIQUE, rlp BLOB)          -- pinned header + ancestors
accounts   (address TEXT PRIMARY KEY, "exists" INTEGER, nonce TEXT, balance TEXT,
            code_hash TEXT, storage_root TEXT, code BLOB)                    -- also proven-absent accounts (exists=0)
storage    (address TEXT, slot TEXT, value TEXT, PRIMARY KEY (address, slot)) -- zero values included
trie_nodes (hash TEXT PRIMARY KEY, rlp BLOB)                                 -- the Merkle proofs, de-duplicated
```

Encodings:

- **Text columns:** addresses are lower-case `0x` + 40 hex; slots, values and hashes are `0x` + 64
  hex; `nonce` and `balance` are canonical hex quantities (`0x0`, `0x1a`).
- **Proofs:** stored once as a node set (`trie_nodes`), not per item. The proxy rebuilds
  `eth_getProof` answers from it.
- **Slot rows:** stored only for existing accounts with a non-empty storage root. For a proven-absent
  account, or one with the empty storage root, every slot is provably zero, and the proxy answers 0.
- **Proofs-verified flag:** `meta.proofs_verified = '1'` and `manifest.proofs_verified = true`. A
  snapshot is written only after everything in it was verified, and it is verified again from disk
  before the directory is renamed into place.

### Determinism

- **Build process:** rows are inserted in sorted order in one transaction with a fixed page size,
  then `VACUUM`.
- **Same SQLite library:** the same content gives a byte-identical `state.sqlite`. With
  `SOURCE_DATE_EPOCH` fixed, the whole directory is byte-identical (tested).
- **Digest:** the content digest is SQLite-version independent. It is sha256 over:
  - `hyblis-state-snapshot/1\n`;
  - then the sorted lines `M key value` (meta), `H number hash rlp` (headers),
    `A address exists nonce balance storage_root code_hash keccak(code)` (accounts),
    `S address slot value` (storage), `N hash` (trie nodes).
- **Excluded from the digest:** `version`, `created_at` and `notes`. Building directly from the
  same inputs as a chain of extends gives the same digest (tested).

## Operator workflow

```bash
source /home/pinc/Hyblis/env.sh
S=runner/state; M=tasks/cap/manifest.json; UP=<archive RPC that serves eth_getProof at the pinned block>

# 1. collect: run ONLY Hyblis-owned code through the recording proxy (template, controls, spec self-checks)
python -I $S/snapshot.py collect --task-manifest $M --upstream $UP --socket /tmp/collect.ipc \
    --out access.json [--append] -- forge test --offline --no-storage-caching --match-path test/hyblis/HyblisPoC.t.sol
#    repeat with --append for every Hyblis-owned test; never a miner's PoC

# 2. build: one eth_getProof per account (all its slots, 256 per call), eth_getCode, header chain
python -I $S/snapshot.py build --task-manifest $M --access access.json --upstream $UP --out snap-v1
#    defaults: --ancestors 256, --history-ring auto, --forge-defaults, --prefetch; --jobs N for parallel fetches

# 3. on the runner (no network)
python -I $S/fork_proxy.py serve --snapshot snap-v1 --socket /run/hyblis/fork.ipc --task-manifest $M \
    --miss-file job/misses.json --stats-file job/proxy-stats.json
#    forge: HYBLIS_ETH_RPC=/run/hyblis/fork.ipc forge test --no-storage-caching ...  (fresh HOME per job)

# 4. a job missed state: extend, then re-queue the job against the new version
python -I $S/snapshot.py extend --task-manifest $M --snapshot snap-v1 --misses job/misses.json \
    --upstream $UP --out snap-v2
python -I $S/snapshot.py verify snap-v2 --task-manifest $M      # offline re-verification, exit 0/1
```

What `build` adds besides the access lists:

- **Headers:** the pinned header and its 256 ancestors (BLOCKHASH window).
- **History ring** (`--history-ring auto`): all 8191 slots of the EIP-2935 history contract,
  because `vm.roll(+k)` reads k of them.
- **Forge defaults** (`--forge-defaults`):
  - Foundry's own accounts: test contract, default sender, cheatcode address and its `failed` slot,
    console, CREATE2 deployer, precompiles, system contracts;
  - their first CREATE addresses;
  - 38 common `makeAddr` labels and their first two CREATE addresses;
  - the block's coinbase.
- **Prefetch** (`--prefetch`): when a contract first enters a snapshot, also slots 0..31 and the
  EIP-1967 implementation, admin and beacon slots, and one hop to the implementation or beacon account.

None of these requests reveals anything about a finding.

The collect proxy answers through exactly the same request handler as the runner's proxy (same
methods, same block rules, same refusals), so the access list matches what the runner will be
asked. It does not verify values; `build` verifies everything it stores.

## What forge 1.9.0 asks for, and how the proxy answers

Established by experiment: forge 1.9.0 (6056c58), forge-std 1.15.0, a toy chain on anvil 1.9.0
behind a logging proxy, `vm.createSelectFork(<ipc path>, N)` in `setUp`. Method sequence:

1. `anvil_nodeInfo`.
2. `eth_chainId`.
3. `eth_getBlockByNumber(N, false)`.
4. `anvil_nodeInfo` and `eth_chainId` again.
5. Account and storage reads with an EIP-1898 block object `{"blockHash": <pinned hash>}`, not a
   number.

There is no `eth_gasPrice`, `eth_feeHistory`, `net_version`, `web3_clientVersion`, `eth_getProof`
or batch request; `tx.gasprice` is 0 in the test.

| forge sends | when | proxy answer |
|---|---|---|
| `anvil_nodeInfo` | every fork creation (detects anvil) | `-32601` method not allowed (what any non-anvil node says); forge continues |
| `eth_chainId` | fork creation | `chain_id` from the snapshot |
| `eth_getBlockByNumber(N, false)` | fork creation | header fields of the verified header + `hash`, `transactions: []`, `uncles: []` |
| `eth_getBalance` / `eth_getTransactionCount` / `eth_getCode` `(addr, {blockHash})` | first touch of an account (forge sends all three, and also probes `eth_getAccountInfo` on the first account) | from `accounts`; absent accounts answer 0 / 0 / `0x`; not in snapshot: **miss** |
| `eth_getAccountInfo(addr, {blockHash})` | same; against anvil forge uses it for every account | `{balance, nonce, code}`, same rules |
| `eth_getStorageAt(addr, slot, {blockHash})` | every cold SLOAD (slot sent as a short quantity, e.g. `0x1`) | 32-byte word from `storage`; absent account or empty storage root: 0; else not in snapshot: **miss** |
| `eth_getStorageAt(0x7109…D12D, "failed")` | every forge-std test | served like any slot (proven absent account, so 0) |
| `eth_getBlockByHash(h, false)` | `blockhash(N-k)`: forge walks the parent chain by hash, k calls | stored ancestor headers (256); unknown hash: refused |
| EIP-2935 history contract balance/nonce/code + slots | `vm.roll(+k)` reads k ring slots | served from the full ring (8191 slots) |
| `eth_getBlockByNumber("latest", false)` | `vm.createSelectFork(url)` without a block | refused (`-32002`, tags are not served): unpinned forks fail closed |
| any state read at another block | `vm.createSelectFork(url, M)` with M ≠ N | `eth_getBlockByNumber(M)` is served if M is a stored ancestor, but every state read at M is refused (`-32002`) |
| `anvil_*`, `evm_*`, `hardhat_*`, `debug_*`, `eth_send*`, `eth_call`, `eth_blockNumber`, `eth_gasPrice`, `eth_feeHistory`, everything else | e.g. `vm.rpc` from a PoC | `-32601` method not allowed |

Also served (forge 1.9.0 does not call them): `net_version`, `web3_clientVersion`, and `eth_getProof`.
`eth_getProof` answers are rebuilt from the stored nodes and verify against the state root.

Block parameter rules for state reads:

- **Accepted:** the pinned number (`"0x…"`), `{"blockHash": pinned}` (with or without
  `requireCanonical`), and `{"blockNumber": pinned}`.
- **Refused:** every tag (`latest`, `pending`, `safe`, `finalized`, `earliest`), every other number
  or hash, and a missing parameter.
- **Why "latest" is not mapped to the pinned block:** forge with a pinned fork never sends "latest".
  Answering it would let an unpinned PoC pass on the runner but fork a different state at the bounty platform.

Batches (≤ 1000 items) and notifications are handled. Messages are framed by bracket depth, because
alloy's IPC writes JSON values back to back.

**What a miss does to forge:** the test fails with `EVM error; database error: failed to get
storage for … hyblis-state-miss …` and gas 0. This happens even inside `try/catch` (the EVM stops),
so a PoC cannot use a miss as an oracle. forge does not retry: the error codes avoid alloy's retry
list (429, -32005, "rate limit", "header not found").

**forge's own RPC cache:** an IPC path counts as a "remote" endpoint, so forge caches fork state in
`$HOME/.foundry/cache/rpc/<chain>/<block>`. With a warm cache only 5 requests reach the proxy. The
cache is keyed by chain and block only, so a stale cache from another source would be served
silently. Run every job with `--no-storage-caching` and a fresh `HOME`.

## Fresh accounts of a job (added 2026-11-16, Cap release)

**Problem found on the first real-chain run.** The runner deploys every PoC at a CREATE2 address salted
with a per-job secret and derives the attacker keys from the same secret (unpredictable by design). A
snapshot built at release can never hold those addresses, so every job missed state, even an empty PoC:
the harness itself reads `balanceOf(<PoC>)` of every spec token, and the attacker accounts' balances and
code. `extend` could not help (new addresses every job, and no historical proofs on public RPCs).

**Rule.** The runner registers the job's fresh set before pass 1 (`handle.set_fresh(accounts, keys,
partners)`, called by `run_submission._run_job`; `clear_fresh()` after the job). For an item the snapshot
does **not** hold, the proxy answers:

- a fresh account: absent (balance 0, nonce 0, no code, every slot 0);
- a slot equal to `keccak(pad32(f) . x) + i` for a fresh key `f` and a precomputed base `x`, or a nested
  `keccak(pad32(y) . keccak(pad32(f) . x))` / `keccak(pad32(f) . keccak(pad32(y) . x))` (allowance-like
  mappings, `y` = in-scope contracts, tokens, holders and fresh keys): zero.

**Why this is not a guess.** Every fresh address derives from 32 random bytes drawn by the runner for the
job, long after the pinned block. No transaction before the pinned block could have created that account
or written a slot whose key hashes that address (short of a keccak collision). The answer is right for
*every* base `x`; which bases are precomputed only decides coverage. Anything not covered is a miss, as
before. The snapshot always wins (a fresh answer is given only for an item it does not hold), and
`set_fresh` refuses an address that exists in the snapshot (a runner bug, never answered for).

**What is fresh** (`run_submission.fresh_set`): the PoC (CREATE2 from the harness with the job salt and
the compiled init code), attacker accounts 1..64 (the faucet now hands out keys by index:
`keccak256(abi.encode(salt, index))`, one index per distinct name, see `runner/sol/HyblisRuntime.sol`),
the contracts these create with CREATE (PoC nonces 1..32, attacker nonces 0..7, one level of nesting) and
CREATE2 deployments of the PoC file's own contracts (no constructor arguments) with salts 0..31. Bases:
slots 0..63 (struct fields 0..3) plus the address-keyed mapping bases discovered in the snapshot
(`fresh.mapping_bases`: a base `b` is found when `keccak(pad32(k) . b) + i` is a stored slot for a known
address `k`; ERC-7201 roots are candidates; cached per digest), with struct fields 0..15.

**Not covered (still misses, re-queued after `extend`):** CREATE2 through a public factory or with other
salts, contracts with constructor arguments deployed by CREATE2, more than 32 contracts per creator, keys
beyond the first 256 fresh addresses for flat mappings / 24 for nested ones, mapping bases that no known
address uses in the snapshot. The standalone run (plain `forge test`) uses forge-std's public `makeAddr`
addresses, which are not fresh: they are served from the snapshot (forge defaults + collect), or miss.

**Collect sessions.** `snapshot.CollectSession` is the recording proxy as an in-process object with the
same `set_fresh`/`misses` interface, so Hyblis-owned code can run through `run_submission` at release
(fresh items are answered locally and never sent upstream or recorded). `prefill=<loaded snapshot>` answers
from a verified snapshot of the same block first (`PrefilledBackend`) and records every access, so a
release can build from an earlier access list, collect quickly, and `extend` with only the new items.

Tests: `tests/test_e2e.py::test_12_fresh_accounts` (rules, guard, snapshot-wins, collect session);
`runner/tests/test_e2e.py` "snapshot" section (11 toy variants through collect -> build -> proxy with
no miss; without fresh registration an empty PoC misses).

## Misses: data shape and how to get them

The Python API returns `h.misses()`: a list in first-seen order, de-duplicated, at most `max_misses`
entries (default 10,000; `truncated: true` beyond that, and `extend` refuses a truncated list). Each entry is one of:

```json
{"kind": "account", "address": "0x…40 hex"}
{"kind": "storage", "address": "0x…", "slot": "0x…64 hex"}
{"kind": "block",   "number": 123}
```

`h.write_misses(path)`, or the CLI's `--miss-file`, writes the document that `extend` takes. The
file exists from start-up (empty list). It is rewritten at most every 0.5 s while new misses arrive,
and again at close:

```json
{"format": "hyblis-state-misses/1", "snapshot_digest": "sha256:…", "chain_id": 1, "block_number": N,
 "block_hash": "0x…", "misses": [ … ], "truncated": false}
```

`h.refusals()` lists requests that can never be served, as `[{"method", "reason", "count"}]`:
another block, a tag, a write or unknown method, an unknown block hash, a full-transaction block
request. They are not misses. A job with refusals other than `anvil_nodeInfo` did something the
policy forbids and should be rejected, not re-queued.

`h.stats()` gives:

- request counters: `requests`, `by_method`, `errors`;
- timing: `busy_ms`, `max_request_ms`;
- `misses`, `miss_hits`, `refusals`;
- connection counters: `connections_total`, `connections_open`, `connections_rejected`,
  `framing_errors`, `bytes_in`, `bytes_out`;
- `snapshot_digest`.

The runner's loop:

1. Pass 1 fails.
2. If `h.misses()` is non-empty (and there are no policy refusals), record `infra:state_miss`, not a
   rejection.
3. The operator runs `extend` (manually or with an automated service).
4. Re-queue the job against the new digest.

## Privacy: what the upstream RPC learns

- **`collect` and `build`:** the RPC sees the program's own contracts, generic defaults and the
  slots that Hyblis-owned code reads. This is public information about a public program.
- **`extend` (the residual leak):** the RPC learns which accounts and slots a researcher's PoC read
  outside the snapshot, at which block, and roughly when. That can point at the vulnerable contract
  and storage before the bounty platform has the report. What the RPC still does not see:
  - the PoC's calldata;
  - the transaction order;
  - any value the PoC writes.

  `extend` keeps the leak minimal:
  - only the missed items are requested;
  - one `eth_getProof` per missed account, carrying all its missed slots;
  - `eth_getCode` only for a newly added contract;
  - the prefetch adds only generic slots (0..31, EIP-1967).

  Mitigations available to the operator:
  - use a self-hosted archive node for `extend` (no leak);
  - batch the misses of several jobs into one extend;
  - delay extends;
  - rotate providers.

  Decoy requests were not implemented: random decoy addresses are easy to tell apart (they do not
  exist).
- **During a miner's run:** none of this applies. The runner has no network and never calls an RPC.

## Hardening after the 2026-11-16 review

- JSON-RPC quantities are hex digits only (Python's `int()` also accepted `0x-1`, `0x_1` and spaces).
- `extend` fetches headers only within 8,191 blocks below the pin (`HEADER_WINDOW`, the EIP-2935
  window); lower block misses are recorded as unservable. Every header it would fetch counts toward
  `--max-items`, so one block entry cannot mean millions of RPC calls.
- Fresh-account discovery: zero-valued slots cannot add ERC-7201 roots (extend adds zero slots from
  miss lists), at most 64 roots and 256 mapping bases are kept per snapshot.
- The proxy answers any arithmetic error in a request as invalid params instead of dropping the
  connection.

## Limitations and open risks

1. **Historical proofs on public RPCs.** On 2026-11-16 both endpoints in `env.sh` refused
   `eth_getProof` at the cap pinned block 26414000 (15,364 blocks behind head):
   - eth.drpc.org: `code 27 "Unknown state. First available state is 1"`;
   - 1rpc.io: `-32000 "historical state … is not available"`.

   At head, drpc served proofs that verify. So:
   - `build` must run while the pinned block is still inside the provider's proof window (geth
     path-scheme nodes keep about 128 blocks), or against an archive node that serves historical
     proofs;
   - `extend` always needs such an archive.

   The cap snapshot cannot be built from these public endpoints today.
2. **One miss per run.** The EVM stops at the first missing read, so each run reveals about one
   item. The toy outside-read test needed 5 extend rounds. `--prefetch` and `--forge-defaults` cut
   the common cases. A "discovery" mode that answers misses with placeholder values (to find all
   misses in one pass, with the run's verdict discarded) would bend the no-guess rule, so it was
   not built; it needs the owner's decision.
3. **Misses a PoC can force.** A PoC can create misses directly with `vm.rpc("eth_getStorageAt", …)`,
   which is catchable and so does not stop the run. That can push arbitrary addresses and slots into
   an extend request (a small exfiltration channel to the RPC operator, and work for the operator).
   Mitigations:
   - misses are capped (10,000 per job) and the miss file is rate-limited;
   - `extend --max-items` (default 5000) refuses large lists;
   - extend only for jobs whose trace passed the cheatcode policy (`vm.rpc` is banned there), and
     have an operator look at unusual miss lists.
4. **Block bodies are not served.** `transactions` and `uncles` are always `[]`, and there is no
   `withdrawals`. forge 1.9.0 needs only header fields; `vm.rollFork(txHash)` and
   `vm.transact` would fail (they are banned anyway). `header.json` keeps the original body lists;
   its header fields are verified, its tx-hash list is not.
5. **Header fields of future forks.** An unknown header field fails closed with
   `unknown field(s) …; add them to HEADER_FIELDS`. Amsterdam's new fields need a one-line update
   when they activate. Block 26414000 has exactly the Prague field set.
6. **Values after `vm.roll`.** For block numbers at or above the pinned block, forge serves
   `blockhash` from the EIP-2935 ring, which at block N still holds hashes from 8191 blocks
   earlier. This is forge's behaviour, identical with any RPC, but worth knowing for time-based
   exploits.
7. **`tx.gasprice` is 0** in forked tests (forge 1.9.0 does not ask `eth_gasPrice`). Same as with a
   normal RPC.
8. **Forge defaults are a heuristic.** Any other `makeAddr` label, or a contract a PoC deploys from
   another account, is a miss on first use in the standalone run. Those are absent accounts, so their
   extend leaks nothing useful. Under the harness, the runner's own salted accounts are fresh accounts
   (section above), not snapshot entries.
9. **Memory.** The proxy holds the snapshot in memory (`state.sqlite` is deserialized after its
   sha256 is checked, so the bytes served are the bytes verified). That is about 7.7 MB for a
   synthetic 500-account, 6,600-slot snapshot; the toy snapshot is 1.6 MB, mostly the history ring.
10. **Byte identity across machines** needs the same SQLite library version (the file header records
    it). The content digest does not.
11. **Collect values are unverified** (build verifies). A lying upstream during collect can only
    cause missing items later, never a wrong value.
12. **Toolchain pin.** The method list was established on forge 1.9.0. Re-run `tests/run.sh` after
    any Foundry upgrade. The end-to-end test fails if forge starts asking for something the proxy
    does not serve.
13. **The socket has no authentication** beyond filesystem permissions (mode 0660). It serves only
    public chain state.

## Measured (toy chain, this server, idle priority)

- **Build:** about 0.7 s for 163 accounts and 8.3k slots against local anvil (most of the slots
  are the history ring).
- **Load and full verification:**
  - 0.07 s for the toy snapshot;
  - 0.24 s for a synthetic 500-account, 6,600-slot, 15.7k-node snapshot (state trie of 50k
    accounts).
- **Proxy:**
  - about 14-35 µs of server time per request; 14-19k requests/s with the client in the same
    Python process;
  - max request time below 1 ms.
- **forge run:** the toy template took 0.08 s through the proxy against 0.07 s direct to anvil.

## Tests

`runner/state/tests/run.sh` drops to user `pinc` and runs at idle priority. It uses anvil on
127.0.0.1:9864, or 9865 if 9864 is busy, plus an IPC socket, and makes no network calls.

- **`test_ratelimit.py`** (offline, a local HTTP stub): HTTP 429 and JSON-RPC rate-limit errors (codes 429,
  -32005, 15 or a "rate limit" message) are retried on their own budget (`Client.RATE_DELAYS`, about 4 minutes,
  at least the upstream's Retry-After), the budget is finite, `retries=0` never waits, other errors are unchanged.
- **`test_mpt.py`** (offline):
  - the cap header against `tasks/cap/manifest.json`;
  - real mainnet proofs, with every tampering kind: wrong value, wrong root, truncated, extra node,
    reordered or flipped node, wrong address or slot set, absent account claiming a balance;
  - anvil proofs, including exclusions;
  - a reference trie with embedded nodes;
  - malformed nodes.
- **`test_e2e.py`:**
  - toy chain;
  - collect, build, serve and forge;
  - (a) 8.8k values compared with anvil;
  - (b) and (c) the miss and extend loop;
  - deterministic builds;
  - (d) 18 kinds of snapshot tampering and 9 kinds of lying upstream refused;
  - refusals;
  - protocol edge cases;
  - concurrency and the connection cap;
  - the CLI and its miss file.

Fixtures are in `tests/fixtures/`. `HYBLIS_STATE_WRITE_FIXTURES=1` regenerates the anvil fixture,
and `HYBLIS_STATE_KEEP=1` keeps the work directory.
