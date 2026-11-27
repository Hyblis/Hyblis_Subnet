"""Unit tests for validator/weights.py (no chain)."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scoring'))
from weights import VaultError, eligible_weights, resolve_vault_uid, vault_weights  # noqa: E402

OWNER_CK, VAULT_CK, OTHER_CK = "5Owner", "5VaultCk", "5Other"
NEURONS = [(0, "5Validator", OWNER_CK), (1, "5Vault", VAULT_CK), (2, "5Miner", OTHER_CK)]
fails = 0


def check(name, fn):
    global fails
    try:
        ok = fn()
    except Exception as ex:   # a check that raises unexpectedly fails
        ok = False
        name += f" (raised {type(ex).__name__}: {ex})"
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


def raises(fn):
    try:
        fn()
    except VaultError:
        return True
    return False


check("vault found by hotkey", lambda: resolve_vault_uid(NEURONS, "5Vault", OWNER_CK) == 1)
check("expected UID matches", lambda: resolve_vault_uid(NEURONS, "5Vault", OWNER_CK, 1) == 1)
check("UID moved -> refused", lambda: raises(lambda: resolve_vault_uid(
    [(0, "5Validator", OWNER_CK), (1, "5Stranger", OTHER_CK), (7, "5Vault", VAULT_CK)], "5Vault", OWNER_CK, 1)))
check("pruned vault -> refused (never pays the new UID 1)", lambda: raises(lambda: resolve_vault_uid(
    [(0, "5Validator", OWNER_CK), (1, "5Stranger", OTHER_CK)], "5Vault", OWNER_CK)))
check("vault under owner coldkey -> refused", lambda: raises(lambda: resolve_vault_uid(
    [(0, "5Validator", OWNER_CK), (1, "5Vault", OWNER_CK)], "5Vault", OWNER_CK)))
check("vault weights: all to the vault UID", lambda: vault_weights(1) == {1: 65535})
NE = [(0, "5Owner", OWNER_CK), (1, "5Vault", VAULT_CK), (2, "5Miner", OTHER_CK), (3, "5Miner2", "5Ck3"), (4, "5OwnerMiner", OWNER_CK)]
check("direct: shares become u16 weights on the miners' UIDs",
      lambda: eligible_weights({"5Miner": 0.75, "5Miner2": 0.25}, "5Owner", NE, OWNER_CK) == ({2: 49151, 3: 16384}, {"dropped": {}, "burn": 0.0}))
check("direct: a key under the owner coldkey is dropped, its share goes to the others",
      lambda: eligible_weights({"5Miner": 0.5, "5OwnerMiner": 0.5}, "5Owner", NE, OWNER_CK)[0] == {2: 65535})
check("direct: nobody eligible -> owner hotkey only (burn)",
      lambda: eligible_weights({"5Gone": 1.0}, "5Owner", NE, OWNER_CK) == ({0: 65535}, {"dropped": {"5Gone": "no UID"}, "burn": 1.0}))
check("direct: a 20% miner burn goes to the owner UID, the rest to the miners",
      lambda: eligible_weights({"5Miner": 0.6, "5Miner2": 0.2}, "5Owner", NE, OWNER_CK, burn=0.2)[0] == {0: 13107, 2: 39321, 3: 13107})
check("direct: owner hotkey without a UID -> refused",
      lambda: raises(lambda: eligible_weights({"5Miner": 1.0}, "5Nobody", NE, OWNER_CK)))
print("weights: all passed" if not fails else f"weights: {fails} FAILED")
sys.exit(1 if fails else 0)
