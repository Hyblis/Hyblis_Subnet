# Miner guide

Find a vulnerability in a live program, prove it with a Foundry test, sign it with your Bittensor hotkey and get
paid through the subnet's weights. On testnet (subnet **626**) the α has no market value: it is where you learn the
rules before mainnet.

## 1. Wallet and registration

You need a coldkey (holds funds, keep it offline) and a hotkey (signs your reports and receives rewards). Rewards
go only to hotkeys that hold a UID on the subnet.

```bash
pip install bittensor-cli
btcli wallet create -w hunter -H default
btcli subnets register --netuid 626 --network test -w hunter -H default
```

Registration costs about τ1 of testnet TAO; 90% of it is held as your collateral. A new UID is protected from
removal for about 9 days.

## 2. Pick a program

Every program page on the site lists the contracts in scope, the severities it pays for, the pinned block your
proof runs against, the proof template and the rules the runner enforces. The same data is in
`tasks/<program>/manifest.json` and `tasks/<program>/impact-spec.json`.

## 3. Write the proof

- Start from the program's template: one file, `contract HyblisPoC is HyblisBase`, with `setUp()` and
  `test_exploit()`. For an attack over several transactions, put each one in `step1()` … `stepN()` and call them in
  order.
- `setUp()` forks once, at the pinned block, through `HYBLIS_ETH_RPC`.
- Act as an ordinary attacker: accounts from `makeAddr`, contracts you deploy, or the PoC itself. Capital only
  through `_fund(token, to, amount)` (or `deal`, routed the same way), within the program's cap.
- Never impersonate a protocol contract, a trusted role or a victim. Not allowed: `vm.store`, `vm.etch`,
  `vm.mockCall`, `ffi`, file access, other forks, environment reads. Even an attempt inside a helper contract is
  rejected: the check reads Foundry's execution trace, not your source.
- Only measured impact counts: a loss of funds, a freeze, insolvency or an unbacked mint above the program's
  threshold. Your asserts and logs are ignored.

## 4. Check it locally

Download **hyblis check** from the program page. It runs your proof the way the runner does and prints
`VALIDATED` with the measured impact, or `REJECTED` with the reason:

```bash
python3 runner/check.py --task <program> --poc /path/to/HyblisPoC.t.sol \
    --project /path/to/program-foundry-project --rpc <archive RPC URL>
```

## 5. Submit

On the site: **Submit a report**, choose the program, describe the finding, paste the proof and sign with your
hotkey in a Polkadot wallet extension (Talisman, SubWallet or polkadot{.js}). The wallet shows
`hyblis-submit:v1:<hash>`: that hash is your report.

From the command line:

```bash
python miner/hyblis_miner.py --gateway https://testnet.hyblis.com submit --task <program> \
    --poc HyblisPoC.t.sol --title "<one line>" --contract <in-scope address> --function <name> \
    --severity medium --desc "<short description>" --wallet hunter --hotkey default
```

Keep the receipt link private: it is the only way to see your report's detailed status. The public ledger shows
its hash, time, status and severity, never its contents.

## 6. How you are paid

Straight through the subnet's weights, every epoch, with no custody. See
[incentive-mechanism.md](incentive-mechanism.md). In short: 60% of the miner pool follows validated findings by
measured severity, 25% is a bonus once the program accepts the finding, 15% goes to the warm-up track.

## Rules that cost you

- The first valid report of a bug wins; a later report of the same bug is a duplicate and earns nothing.
- A finding later rejected as invalid counts a strike; three strikes suspend the hotkey.
- A real vulnerability in a live program is disclosed only through that program's own process. Never publish it.
