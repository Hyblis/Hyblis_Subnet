#!/usr/bin/env python3
"""Validator weight-setting.

Two modes. `direct` (current, policy v2 since 2026-11-23): miners are paid straight through weights
from the public scoring ledger: when the runner validates a finding, a bonus when the platform
accepts it, and a warm-up track; no custody. `vault` (the first design, option A): all miner
emission to one published vault hotkey until platform results are known. A single UID taking the
whole miner pool is what the chain's reviewers flag, so vault mode is kept only for reference.

Chain writes happen only with --commit and a wallet that lives in Hyblis
(.home/.bittensor/wallets). Pure weight computation has no chain dependency and
is unit-tested.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scoring"))
sys.path.insert(0, str(ROOT / "platform"))

U16 = 65535


def vault_weights(vault_uid: int) -> dict[int, int]:
    """All miner emission to the vault UID."""
    return {int(vault_uid): U16}


def eligible_weights(shares: dict, owner_hotkey: str, neurons, owner_coldkey: str, burn: float = 0.0) -> tuple[dict, dict]:
    """{uid: u16} from policy shares {hotkey: share}. A recipient is dropped when its hotkey holds no
    UID (pruned) or sits under the owner coldkey (the chain burns incentive paid to owner keys); the
    remaining shares are renormalised, so a dropped share goes to the other miners, not to burn. Only
    when nobody is left does the whole vector go to the owner hotkey (burn).
    `neurons` is an iterable of (uid, hotkey, coldkey). Returns (weights, info)."""
    from hyblis_scoring.policy import to_u16_weights  # type: ignore
    uid_of = {hk: int(uid) for uid, hk, _ in neurons}
    cold_of = {hk: ck for _, hk, ck in neurons}
    keep, dropped = {}, {}
    for hk, sh in shares.items():
        if sh <= 0:
            continue
        if hk not in uid_of:
            dropped[hk] = "no UID"
        elif owner_coldkey and cold_of.get(hk) == owner_coldkey:
            dropped[hk] = "owner coldkey"
        else:
            keep[hk] = sh
    total = sum(keep.values())
    burn = min(max(float(burn), 0.0), 1.0)
    # the policy's miner burn (owner UID) stays as it is; the miners' part is shared among eligible miners only
    result = {"miners": {hk: v / total * (1.0 - burn) for hk, v in keep.items()} if total else {},
              "burn": burn if total else 1.0}
    if owner_hotkey not in uid_of:
        raise VaultError("the owner hotkey holds no UID on this subnet")
    by_hk = to_u16_weights(result, owner_hotkey)
    return {uid_of[hk]: w for hk, w in by_hk.items()}, {"dropped": dropped, "burn": result["burn"]}


def direct_weights(owner_hotkey: str, neurons, owner_coldkey: str, policy: str = "v2",
                   now_ts: float | None = None) -> tuple[dict, dict]:
    """Pay miners straight through weights from the public scoring ledger (store.load_events).
    v2 (default): validated / accepted / warm-up pools, relative; v1: the original absolute scale."""
    from hyblis_scoring import policy as pol  # type: ignore
    from hyblis_platform import store  # type: ignore
    now_day = store.to_day(now_ts if now_ts is not None else store.now())
    events = store.load_events()
    if policy == "v2":
        res = pol.compute_v2(events, now=now_day, policy=pol.PolicyV2())
    else:
        res = pol.compute(events, now=now_day, policy=pol.Policy())
    shares = dict(res["miners"])
    w, info = eligible_weights(shares, owner_hotkey, neurons, owner_coldkey, burn=res["burn"] if shares else 1.0)
    info.update(policy=res["policy"], pools=res.get("pools"), events=len(events),
                shares={hk[:8]: round(v, 4) for hk, v in shares.items()})
    return w, info


class VaultError(Exception):
    """The vault hotkey cannot safely receive the miner pool this round."""


def resolve_vault_uid(neurons, vault_hotkey: str, owner_coldkey: str,
                      expect_uid: int | None = None) -> int:
    """The vault's UID, looked up by its hotkey on every round, never trusted from a fixed number:
    a UID is reused when a hotkey is pruned, and a stale UID would send the whole miner pool to
    whoever registered next. Refuses (VaultError) when the hotkey holds no UID, when it sits under
    the owner coldkey (the chain burns incentive paid to owner keys, and the subnet's TAO emission
    falls with it), or when it differs from the UID the operator expects.
    `neurons` is an iterable of (uid, hotkey, coldkey)."""
    hits = [(int(uid), ck) for uid, hk, ck in neurons if hk == vault_hotkey]
    if not hits:
        raise VaultError(f"vault hotkey {vault_hotkey} holds no UID on this subnet (pruned or never registered)")
    uid, coldkey = hits[0]
    if owner_coldkey and coldkey == owner_coldkey:
        raise VaultError("vault hotkey is under the owner coldkey: its incentive would be burned")
    if expect_uid is not None and uid != int(expect_uid):
        raise VaultError(f"vault hotkey is at UID {uid}, not the expected UID {expect_uid}")
    return uid


# ---- chain I/O (guarded; bittensor SDK 11) ----------------------------------
def read_subnet(network: str, netuid: int):
    """(neurons as (uid, hotkey, coldkey), owner_coldkey, block) from the subnet's metagraph."""
    import bittensor as bt
    st = bt.Subtensor(network=network)
    try:
        mg = st.subnets.metagraph(netuid)
        return [(n.uid, n.hotkey, n.coldkey) for n in mg.neurons], mg.owner_coldkey, mg.block
    finally:
        try:
            st.close()
        except Exception:
            pass


def uid_map(network: str, netuid: int) -> dict[str, int]:
    neurons, _, _ = read_subnet(network, netuid)
    return {hk: uid for uid, hk, _ in neurons}


def commit_weights(network: str, netuid: int, wallet_name: str, wallet_hotkey: str,
                   weights: dict[int, int]):
    """Signed by the validator hotkey. bt.set_weights conforms the vector to the subnet's limits,
    preflights registration and the rate limit, and raises ChainError on any failure."""
    import bittensor as bt
    res = bt.set_weights(netuid, {int(u): float(w) for u, w in weights.items()},
                         wallet=wallet_name, hotkey=wallet_hotkey, network=network)
    _log(f"set_weights ok: extrinsic {getattr(res, 'extrinsic_id', '?')} block {getattr(res, 'block_hash', '?')}")
    return res


def _log(msg: str) -> None:
    import time
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def one_round(a) -> None:
    if a.mode == "vault":
        if a.vault_hotkey:
            neurons, owner_ck, block = read_subnet(a.network, a.netuid)
            uid = resolve_vault_uid(neurons, a.vault_hotkey, owner_ck, a.vault_uid)
            _log(f"block {block}: vault {a.vault_hotkey[:8]}... at UID {uid}")
        elif a.vault_uid is not None and not a.commit:
            uid = a.vault_uid          # offline preview only
        else:
            raise SystemExit("--vault-hotkey is required to write vault weights (the UID is looked up by hotkey)")
        weights = vault_weights(uid)
    else:
        if not a.owner_hotkey:
            raise SystemExit("--owner-hotkey is required in direct mode (it takes the pool only when nobody earned)")
        neurons, owner_ck, block = read_subnet(a.network, a.netuid)
        weights, info = direct_weights(a.owner_hotkey, neurons, owner_ck, a.policy)
        _log(f"block {block}: {json.dumps(info)}")
    _log(json.dumps({"mode": a.mode, "weights": weights}))
    if a.commit:
        commit_weights(a.network, a.netuid, a.wallet, a.wallet_hotkey, weights)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["vault", "direct"], default="vault")
    ap.add_argument("--vault-hotkey", default="", help="ss58 of the vault hotkey; its UID is looked up every round")
    ap.add_argument("--vault-uid", type=int, help="the UID the vault is expected at (a cross-check)")
    ap.add_argument("--owner-hotkey", default="")
    ap.add_argument("--policy", choices=["v1", "v2"], default="v2", help="direct mode: scoring policy")
    ap.add_argument("--network", default="test")
    ap.add_argument("--netuid", type=int)
    ap.add_argument("--wallet", default="")
    ap.add_argument("--wallet-hotkey", default="")
    ap.add_argument("--commit", action="store_true", help="write weights on chain")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="repeat every SECONDS (keep it above the subnet's weights_rate_limit)")
    a = ap.parse_args()
    if a.commit and (a.netuid is None or not a.wallet or not a.wallet_hotkey):
        raise SystemExit("--commit needs --netuid, --wallet and --wallet-hotkey")
    if not a.loop:
        one_round(a)
        return
    import time
    _log(f"weight loop: {a.mode} mode, {a.network} netuid {a.netuid}, every {a.loop}s")
    while True:
        wait = a.loop
        try:
            one_round(a)
        except VaultError as ex:      # nothing is written this round; the operator must look
            _log(f"REFUSED: {ex}")
        except Exception as ex:       # chain or network trouble: one line, try again sooner
            _log(f"round failed: {type(ex).__name__}: {' '.join(str(ex).split())[:300]}")
            wait = min(a.loop, 600)
        time.sleep(wait)


if __name__ == "__main__":
    main()
