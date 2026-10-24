"""Cryptographic core for VaultZero.

The design goal is that the server never holds anything that can decrypt a
vault. Everything here runs on the client; the relay only ever sees opaque
blobs and public keys.

Primitives:
  * X25519 for key agreement
  * HKDF-SHA256 for key derivation and the symmetric ratchet
  * AES-256-GCM for authenticated encryption
  * PBKDF2-HMAC-SHA256 for turning a passphrase into a key-encryption key

The ratchet is a simple forward-secure construction: each message advances the
chain key with HKDF, and the message key is derived from the chain key with a
different info string. A compromised message key therefore does not expose
earlier or later messages.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16
TAG_LEN = 16

# Domain separation strings. Changing any of these breaks compatibility, which
# is the point: a key derived for one purpose can never be reused for another.
INFO_ROOT = b"vaultzero/v1/root"
INFO_CHAIN = b"vaultzero/v1/chain"
INFO_MESSAGE = b"vaultzero/v1/message"
INFO_VAULT = b"vaultzero/v1/vault"
INFO_INDEX = b"vaultzero/v1/index"


class CryptoError(Exception):
    """Raised when a cryptographic operation cannot be completed safely."""


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_from_passphrase(passphrase: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Stretch a passphrase into a 32-byte key-encryption key.

    The iteration count is deliberately high; callers that need to stay
    responsive on weak hardware can lower it, but the default is the one that
    should ship.
    """
    if not isinstance(passphrase, str) or not passphrase:
        raise CryptoError("passphrase must be a non-empty string")
    if len(salt) != SALT_LEN:
        raise CryptoError("salt must be %d bytes" % SALT_LEN)
    if iterations < 10_000:
        raise CryptoError("iteration count is too low to be meaningful")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


@dataclass
class IdentityKeyPair:
    """A long-lived X25519 identity."""

    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        priv = X25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "IdentityKeyPair":
        if len(raw) != KEY_LEN:
            raise CryptoError("private key must be %d bytes" % KEY_LEN)
        priv = X25519PrivateKey.from_private_bytes(raw)
        return cls(private_key=priv, public_key=priv.public_key())

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def fingerprint(self) -> str:
        """Short human-comparable digest of the public key.

        Two people reading this aloud should be able to tell whether they hold
        the same key, which is what makes it useful for out-of-band checks.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.public_bytes())
        raw = digest.finalize()[:10]
        return "-".join("%02x" % b for b in raw)


@dataclass
class RatchetState:
    """Symmetric ratchet state for one direction of a conversation."""

    chain_key: bytes
    message_number: int = 0
    skipped: Dict[int, bytes] = field(default_factory=dict)

    def advance(self) -> bytes:
        """Return the next message key and move the chain forward."""
        msg_key = _hkdf(self.chain_key, b"", INFO_MESSAGE)
        self.chain_key = _hkdf(self.chain_key, b"", INFO_CHAIN)
        self.message_number += 1
        return msg_key

    def skip_to(self, target: int, max_skip: int = 1000) -> List[bytes]:
        """Advance to `target`, retaining the keys we stepped over.

        Out-of-order delivery is normal on a real network, so the keys for
        messages we have not seen yet have to be kept. The cap stops a hostile
        peer from making us allocate an unbounded number of keys by claiming a
        huge message number.
        """
        if target < self.message_number:
            raise CryptoError("cannot rewind a ratchet")
        gap = target - self.message_number
        if gap > max_skip:
            raise CryptoError("refusing to skip %d messages" % gap)
        keys = []
        while self.message_number < target:
            keys.append(self.advance())
        return keys


def initial_ratchet(shared_secret: bytes, salt: bytes) -> RatchetState:
    root = _hkdf(shared_secret, salt, INFO_ROOT)
    return RatchetState(chain_key=root)


def agree(private: X25519PrivateKey, peer_public: bytes) -> bytes:
    """X25519 agreement with a length check on the peer key."""
    if len(peer_public) != KEY_LEN:
        raise CryptoError("peer public key must be %d bytes" % KEY_LEN)
    try:
        pub = X25519PublicKey.from_public_bytes(peer_public)
    except ValueError as exc:
        raise CryptoError("peer public key is not a valid curve point") from exc
    return private.exchange(pub)


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM encrypt. Returns nonce || ciphertext || tag."""
    if len(key) != KEY_LEN:
        raise CryptoError("key must be %d bytes" % KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    blob = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + blob


def open_sealed(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt. Raises CryptoError on any tampering."""
    if len(key) != KEY_LEN:
        raise CryptoError("key must be %d bytes" % KEY_LEN)
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise CryptoError("ciphertext is too short to be valid")
    nonce, body = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, body, aad)
    except Exception as exc:  # cryptography raises InvalidTag
        raise CryptoError("authentication failed: ciphertext was altered") from exc


def pack_uint32(value: int) -> bytes:
    if not 0 <= value < 2**32:
        raise CryptoError("value out of range for uint32")
    return struct.pack(">I", value)


def unpack_uint32(raw: bytes) -> int:
    if len(raw) != 4:
        raise CryptoError("expected 4 bytes")
    return struct.unpack(">I", raw)[0]
