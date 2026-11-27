"""Signing and verification using Bittensor sr25519 keypairs.

Miners sign submissions with their hotkey; the gateway verifies against the
claimed ss58 address. The server signs receipts so a miner (or an auditor) can
prove the gateway accepted a package at a given time.

Two signature schemes are accepted for a submission (both sr25519, both bound to
the whole package):

  raw        The signature covers the canonical JSON bytes of the package. Used by
             the command-line miner (miner/hyblis_miner.py).
  wallet-v1  The signature covers the short ASCII message
                 hyblis-submit:v1:<submission_id>
             where submission_id = sha256(canonical JSON of the package). Used by
             browser wallet extensions, which show the message to the user and
             wrap it as <Bytes>message</Bytes> before signing. Signing a digest
             keeps the wallet prompt short and readable; the fixed prefix is the
             domain separator.

The two schemes can never be confused: a raw message is a JSON object (it starts
with "{"), a wallet-v1 message starts with the fixed prefix.
"""
from __future__ import annotations

from bittensor_wallet import Keypair

from .canonical import canonical_bytes

SCHEME_RAW = "raw"
SCHEME_WALLET = "wallet-v1"
SIG_SCHEMES = (SCHEME_RAW, SCHEME_WALLET)
WALLET_PREFIX = "hyblis-submit:v1:"
_WRAP_PRE, _WRAP_POST = b"<Bytes>", b"</Bytes>"


def _sig_bytes(signature_hex: str) -> bytes:
    return bytes.fromhex(signature_hex[2:] if signature_hex.startswith("0x") else signature_hex)


def verify_bytes(ss58_address: str, message: bytes, signature_hex: str) -> bool:
    """True iff signature_hex is a valid sr25519 signature of `message`, or of
    `<Bytes>message</Bytes>` (how wallet extensions sign raw data), by the holder
    of ss58_address. Never raises on a bad signature or address."""
    try:
        kp = Keypair(ss58_address=ss58_address)
        sig = _sig_bytes(signature_hex)
    except Exception:
        return False
    for candidate in (message, _WRAP_PRE + message + _WRAP_POST):
        try:
            if kp.verify(candidate, sig):
                return True
        except Exception:
            continue
    return False


def verify(ss58_address: str, payload: dict, signature_hex: str) -> bool:
    """Raw scheme: the signature covers canonical(payload)."""
    try:
        message = canonical_bytes(payload)
    except Exception:
        return False
    return verify_bytes(ss58_address, message, signature_hex)


def wallet_message(submission_id: str) -> bytes:
    """The exact bytes a browser wallet is asked to sign for a submission."""
    return (WALLET_PREFIX + submission_id).encode("ascii")


def verify_submission(ss58_address: str, package: dict, signature_hex: str, scheme: str, submission_id: str) -> bool:
    """Verify a submission envelope under the named scheme. `submission_id` must be
    the server-computed sha256 of the canonical package (never a client value)."""
    if scheme == SCHEME_RAW:
        return verify(ss58_address, package, signature_hex)
    if scheme == SCHEME_WALLET:
        return verify_bytes(ss58_address, wallet_message(submission_id), signature_hex)
    return False


def sign(keypair: Keypair, payload: dict) -> str:
    """Hex signature (0x-prefixed) of canonical(payload)."""
    return "0x" + keypair.sign(canonical_bytes(payload)).hex()


def sign_wallet(keypair: Keypair, submission_id: str, wrap: bool = True) -> str:
    """What a browser wallet produces for a submission (used by tests and tools)."""
    msg = wallet_message(submission_id)
    return "0x" + keypair.sign(_WRAP_PRE + msg + _WRAP_POST if wrap else msg).hex()


def keypair_from_seed(seed_hex: str) -> Keypair:
    return Keypair.create_from_seed(seed_hex if seed_hex.startswith("0x") else "0x" + seed_hex)


def is_valid_ss58(address: str) -> bool:
    try:
        Keypair(ss58_address=address)
        return True
    except Exception:
        return False


def is_hotkey(address) -> bool:
    """True iff `address` is a Bittensor hotkey address: SS58 format 42 (the form the
    metagraph uses) of a non-zero public key. The same key written for another network
    decodes too, but would count as a separate researcher; the all-zero key verifies a
    constant signature for any message. Never raises."""
    if not isinstance(address, str) or not 47 <= len(address) <= 49:
        return False
    try:
        pk = Keypair(ss58_address=address).public_key
        return pk != bytes(32) and Keypair(public_key=pk.hex(), ss58_format=42).ss58_address == address
    except Exception:
        return False
