<p align="center"><img src="design/logo/hyblis-mark.svg" width="64" alt="Hyblis"></p>

<h1 align="center">Hyblis</h1>

<p align="center"><b>A Bittensor subnet for proven smart-contract vulnerabilities.</b><br>
Researchers attack live, deployed protocols. A finding counts only when our runner reproduces the exploit on real
mainnet state and measures the loss itself.</p>

<p align="center">
<a href="https://hyblis.com">hyblis.com</a> ·
<a href="https://testnet.hyblis.com">testnet</a> ·
<a href="docs/miners.md">Miner guide</a> ·
<a href="docs/validators.md">Validator guide</a> ·
<a href="docs/incentive-mechanism.md">Incentive mechanism</a>
</p>

---

## Status

| Network | Subnet | State |
|---|---|---|
| Bittensor testnet | **626** | Live. Intake open at [testnet.hyblis.com](https://testnet.hyblis.com) |
| Mainnet (Finney) | — | Pre-launch. Intake opens at launch |

## How it works

```
 miner ──signed report + Foundry PoC──▶ gateway ──▶ runner ──verdict──▶ public ledger ──▶ validators ──weights──▶ chain
                                        (intake)   (isolated,           (hash, status,     (same scoring
                                                    pinned mainnet       severity)          code, same result)
                                                    fork, trace-checked)
```

1. **A researcher writes a proof of concept** as an ordinary Foundry test against a program's pinned block, signs
   it with a Bittensor hotkey and submits it on the site or with the miner CLI.
2. **The runner reproduces it** in an isolated sandbox (no network, no host files) on chain state that is proven,
   value by value, against the pinned block hash. It runs the proof twice through a measuring harness and once as
   plain `forge test`, and takes the verdict only from Foundry's execution trace: storage edits, impersonation of
   protocol contracts, mocked calls and other forbidden cheatcodes are rejected, even inside helper contracts.
3. **Impact is measured, not claimed.** Balances, invariants and "can a holder still withdraw" probes are compared
   between the exploited fork and a clean fork of the same block. Asserts and logs in the proof are ignored.
4. **The result goes on the public ledger**: hash, time, status and severity. The report itself stays private
   until the vulnerability is fixed and disclosure is cleared.
5. **Validators set weights** from the public scoring ledger with the published scoring code
   ([policy v2](docs/incentive-mechanism.md)). The same inputs always give the same weights.

Researchers can run the exact same check locally before submitting: each program page offers a `hyblis check`
download that runs the runner's harness, verdict engine and the program's impact spec on their own machine.

## Repository layout

| Path | What it is |
|---|---|
| [`runner/`](runner) | The verifier: trace-verified reproduction, sandbox, verified state snapshots, `hyblis check` |
| [`platform/`](platform) | Gateway (intake, signatures, rate limits), validation pipeline, scoring ledger, public site |
| [`scoring/`](scoring) | Scoring policy (v2) with tests and the two-year simulation |
| [`validator/`](validator) | Weight setting and the operator tool |
| [`miner/`](miner) | Miner CLI: package, sign and submit a report |
| [`chain/vault/`](chain/vault) | Payout vault contract (Foundry) and its tests |
| [`tasks/`](tasks) | Program packs: manifest, impact spec, PoC template |
| [`docs/`](docs) | Miner, validator and incentive documentation, system overview |

## Quick start

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
source env.sh
bash scripts/ci_tests.sh          # Python suites (what CI runs)
bash scripts/run_tests.sh         # everything, including the Foundry and toy-chain suites (needs Foundry 1.9.0)
```

- **Miners:** [docs/miners.md](docs/miners.md)
- **Validators:** [docs/validators.md](docs/validators.md)

## Toolchain

- Python 3.12, exact versions in `requirements.lock` (`bittensor==11.3.2`).
- Foundry **1.9.0** (the runner refuses any other build) with pinned solc versions; nothing is downloaded at run time.
- The site has no build step; three.js and the fonts are self-hosted.

## Security

Found a vulnerability in Hyblis itself? Please report it privately, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
