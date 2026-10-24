# VaultZero

Zero-knowledge encrypted vault with a forward-secure message ratchet.

The relay stores envelopes it cannot read. Keys never leave the client, and each
message advances a symmetric ratchet so a single compromised message key does
not expose the rest of the conversation.

## What it does

- **X25519** key agreement for each pair of participants
- **HKDF-SHA256** for key derivation, with a distinct info string per purpose
- **AES-256-GCM** authenticated encryption, fresh nonce per message
- **PBKDF2-HMAC-SHA256** (200k iterations by default) to turn a passphrase into a key
- A **symmetric ratchet** that derives a new message key per message and keeps
  skipped keys so out-of-order delivery still works
- A **relay** that enforces membership, sequence continuity and gap detection
  while remaining unable to decrypt anything

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Run the tests

```bash
python -m pytest -q
```

## Use it

```python
import os
from vaultzero import IdentityKeyPair, Relay, VaultClient
from vaultzero.crypto import SALT_LEN

alice = IdentityKeyPair.generate()
bob = IdentityKeyPair.generate()
relay = Relay()

ca = VaultClient(alice, relay)
cb = VaultClient(bob, relay)

vid = ca.open_vault()          # alice creates the vault
cb.join(vid)                   # bob joins it

salt = os.urandom(SALT_LEN)    # shared out of band, or derived from a handshake
ca.send(bob.public_bytes(), b"meet at the usual place", salt)

print(cb.receive(alice.public_bytes(), salt))
# [b'meet at the usual place']
```

The relay only ever holds `Envelope` objects whose `nonce_blob` is ciphertext.
`relay.fetch(...)` returns nothing to a key that is not a member.

## Design notes

**Why a ratchet rather than one long-lived key.** A single key that encrypts a
whole conversation is a single point of failure: one leak exposes everything
ever sent. Here each message key is derived from the chain key and then
discarded, so recovering a message key tells an attacker nothing about the
messages before or after it.

**Why the relay enforces sequence numbers.** A relay that silently drops
messages is a realistic adversary. Numbering every envelope and exposing
`detect_gaps()` means a client can tell the difference between "no new
messages" and "messages were withheld".

**Why the skip cap exists.** Out-of-order delivery requires retaining keys for
messages not yet seen. Without a cap, a hostile peer could claim message number
10^9 and make the client allocate keys until it runs out of memory. The cap
refuses anything beyond 1000 skipped messages.

## Layout

```
vaultzero/
  crypto.py   primitives: agreement, KDF, AEAD, ratchet
  vault.py    relay, envelopes, client sessions
tests/
  test_crypto.py
  test_vault.py
```

## Licence

MIT. See `LICENSE`.

## Author

Konain Sultan Khan (KK) — https://github.com/kkcyber2
LinkedIn: _add your profile URL here_
