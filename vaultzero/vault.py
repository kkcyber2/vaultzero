"""Vault storage and the zero-knowledge relay.

The relay is the interesting part. It stores envelopes it cannot read, and it
enforces a few invariants that a real service would need:

  * a vault id is derived from the owner's public key, so two clients that
    agree on a key agree on the vault without a lookup
  * envelopes are append-only and numbered, so a client can detect a gap
  * the relay refuses to serve an envelope to a key that is not on the
    recipient list, and it cannot tell what is inside one
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .crypto import (
    CryptoError,
    IdentityKeyPair,
    RatchetState,
    agree,
    initial_ratchet,
    open_sealed,
    seal,
    _hkdf,
    INFO_VAULT,
    SALT_LEN,
)


class VaultError(Exception):
    """Raised for vault-level problems (access, ordering, corruption)."""


def vault_id(owner_public: bytes) -> str:
    """Deterministic vault identifier derived from a public key."""
    if len(owner_public) != 32:
        raise VaultError("owner public key must be 32 bytes")
    return hashlib.sha256(INFO_VAULT + owner_public).hexdigest()[:32]


@dataclass
class Envelope:
    """One opaque message held by the relay."""

    seq: int
    sender: str
    recipients: List[str]
    nonce_blob: bytes
    created_at: float = field(default_factory=time.time)

    def to_wire(self) -> dict:
        return {
            "seq": self.seq,
            "sender": self.sender,
            "recipients": list(self.recipients),
            "blob": self.nonce_blob.hex(),
            "created_at": self.created_at,
        }

    @classmethod
    def from_wire(cls, data: dict) -> "Envelope":
        try:
            return cls(
                seq=int(data["seq"]),
                sender=str(data["sender"]),
                recipients=list(data["recipients"]),
                nonce_blob=bytes.fromhex(data["blob"]),
                created_at=float(data.get("created_at", 0.0)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError("malformed envelope") from exc


class Relay:
    """A store-and-forward relay that cannot read what it stores."""

    def __init__(self) -> None:
        self._vaults: Dict[str, List[Envelope]] = {}
        self._members: Dict[str, set] = {}

    def create_vault(self, owner_public: bytes, members: Optional[List[str]] = None) -> str:
        vid = vault_id(owner_public)
        if vid in self._vaults:
            raise VaultError("vault already exists")
        self._vaults[vid] = []
        self._members[vid] = set(members or [])
        self._members[vid].add(owner_public.hex())
        return vid

    def add_member(self, vid: str, public_hex: str) -> None:
        if vid not in self._vaults:
            raise VaultError("no such vault")
        if len(public_hex) != 64:
            raise VaultError("member key must be 32 bytes of hex")
        self._members[vid].add(public_hex)

    def members(self, vid: str) -> List[str]:
        if vid not in self._vaults:
            raise VaultError("no such vault")
        return sorted(self._members[vid])

    def append(self, vid: str, envelope: Envelope) -> int:
        """Append an envelope, enforcing sequence continuity."""
        if vid not in self._vaults:
            raise VaultError("no such vault")
        if envelope.sender not in self._members[vid]:
            raise VaultError("sender is not a member of this vault")
        for r in envelope.recipients:
            if r not in self._members[vid]:
                raise VaultError("recipient %s is not a member" % r[:12])
        log = self._vaults[vid]
        expected = len(log)
        if envelope.seq != expected:
            raise VaultError(
                "out-of-order append: expected seq %d, got %d" % (expected, envelope.seq)
            )
        log.append(envelope)
        return envelope.seq

    def fetch(self, vid: str, requester_hex: str, since: int = 0) -> List[Envelope]:
        """Return envelopes addressed to `requester_hex` from `since` onward."""
        if vid not in self._vaults:
            raise VaultError("no such vault")
        if requester_hex not in self._members[vid]:
            raise VaultError("requester is not a member of this vault")
        if since < 0:
            raise VaultError("since must not be negative")
        return [
            e
            for e in self._vaults[vid][since:]
            if requester_hex in e.recipients or e.sender == requester_hex
        ]

    def head(self, vid: str) -> int:
        if vid not in self._vaults:
            raise VaultError("no such vault")
        return len(self._vaults[vid])

    def detect_gaps(self, vid: str, requester_hex: str) -> List[int]:
        """Report sequence numbers the requester is missing.

        A relay that silently drops messages is a real threat model, so the
        client needs a way to notice rather than assume completeness.
        """
        seen = {e.seq for e in self.fetch(vid, requester_hex)}
        return [n for n in range(self.head(vid)) if n not in seen]


class VaultClient:
    """Client-side vault: holds keys, seals and opens messages."""

    def __init__(self, identity: IdentityKeyPair, relay: Relay) -> None:
        self.identity = identity
        self.relay = relay
        self.vid: Optional[str] = None
        self._sessions: Dict[str, RatchetState] = {}
        self._send_counters: Dict[str, int] = {}

    def open_vault(self, members: Optional[List[str]] = None) -> str:
        self.vid = self.relay.create_vault(self.identity.public_bytes(), members)
        return self.vid

    def join(self, vid: str) -> None:
        self.relay.add_member(vid, self.identity.public_bytes().hex())
        self.vid = vid

    def _session(self, peer_public: bytes, salt: bytes) -> RatchetState:
        key = peer_public.hex()
        if key not in self._sessions:
            shared = agree(self.identity.private_key, peer_public)
            self._sessions[key] = initial_ratchet(shared, salt)
        return self._sessions[key]

    def send(self, peer_public: bytes, plaintext: bytes, salt: bytes) -> int:
        """Seal a message for one peer and append it to the vault."""
        if self.vid is None:
            raise VaultError("client has not opened or joined a vault")
        if len(salt) != SALT_LEN:
            raise VaultError("salt must be %d bytes" % SALT_LEN)
        state = self._session(peer_public, salt)
        msg_key = state.advance()
        aad = self.identity.public_bytes() + peer_public
        blob = seal(msg_key, plaintext, aad)
        env = Envelope(
            seq=self.relay.head(self.vid),
            sender=self.identity.public_bytes().hex(),
            recipients=[peer_public.hex()],
            nonce_blob=blob,
        )
        return self.relay.append(self.vid, env)

    def receive(self, peer_public: bytes, salt: bytes) -> List[bytes]:
        """Open every message from `peer_public` that we have not read yet."""
        if self.vid is None:
            raise VaultError("client has not opened or joined a vault")
        state = self._session(peer_public, salt)
        out: List[bytes] = []
        aad = peer_public + self.identity.public_bytes()
        for env in self.relay.fetch(self.vid, self.identity.public_bytes().hex()):
            if env.sender != peer_public.hex():
                continue
            if env.seq < state.message_number:
                continue
            # Advance the ratchet to this message, keeping skipped keys so a
            # later-arriving earlier message can still be read.
            while state.message_number < env.seq:
                state.skipped[state.message_number] = state.advance()
            msg_key = state.advance()
            out.append(open_sealed(msg_key, env.nonce_blob, aad))
        return out
