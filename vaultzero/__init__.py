"""VaultZero — zero-knowledge encrypted vault with a forward-secure ratchet."""

from .crypto import (
    CryptoError,
    IdentityKeyPair,
    RatchetState,
    agree,
    derive_from_passphrase,
    initial_ratchet,
    open_sealed,
    seal,
)
from .vault import Envelope, Relay, VaultClient, VaultError, vault_id

__version__ = "1.0.0"

__all__ = [
    "CryptoError",
    "IdentityKeyPair",
    "RatchetState",
    "agree",
    "derive_from_passphrase",
    "initial_ratchet",
    "open_sealed",
    "seal",
    "Envelope",
    "Relay",
    "VaultClient",
    "VaultError",
    "vault_id",
]
