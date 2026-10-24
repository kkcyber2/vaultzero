"""Tests for the vault and the zero-knowledge relay."""

import os

import pytest

from vaultzero.crypto import IdentityKeyPair, SALT_LEN
from vaultzero.vault import Envelope, Relay, VaultClient, VaultError, vault_id


def pair():
    a = IdentityKeyPair.generate()
    b = IdentityKeyPair.generate()
    relay = Relay()
    ca = VaultClient(a, relay)
    cb = VaultClient(b, relay)
    return a, b, relay, ca, cb


def test_vault_id_is_deterministic():
    a = IdentityKeyPair.generate()
    assert vault_id(a.public_bytes()) == vault_id(a.public_bytes())


def test_vault_id_differs_per_key():
    assert vault_id(IdentityKeyPair.generate().public_bytes()) != vault_id(
        IdentityKeyPair.generate().public_bytes()
    )


def test_vault_id_rejects_bad_key():
    with pytest.raises(VaultError):
        vault_id(b"short")


def test_create_and_join_vault():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    assert a.public_bytes().hex() in relay.members(vid)
    assert b.public_bytes().hex() in relay.members(vid)


def test_duplicate_vault_creation_is_refused():
    a, b, relay, ca, cb = pair()
    ca.open_vault()
    with pytest.raises(VaultError):
        ca.open_vault()


def test_end_to_end_message_roundtrip():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    salt = os.urandom(SALT_LEN)
    ca.send(b.public_bytes(), b"meet at the usual place", salt)
    got = cb.receive(a.public_bytes(), salt)
    assert got == [b"meet at the usual place"]


def test_multiple_messages_arrive_in_order():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    salt = os.urandom(SALT_LEN)
    for i in range(5):
        ca.send(b.public_bytes(), ("msg %d" % i).encode(), salt)
    got = cb.receive(a.public_bytes(), salt)
    assert got == [b"msg 0", b"msg 1", b"msg 2", b"msg 3", b"msg 4"]


def test_relay_cannot_read_the_payload():
    """The stored blob must not contain the plaintext."""
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    salt = os.urandom(SALT_LEN)
    secret = b"ACCOUNT-NUMBER-4417"
    ca.send(b.public_bytes(), secret, salt)
    stored = relay.fetch(vid, b.public_bytes().hex())[0]
    assert secret not in stored.nonce_blob
    assert b"4417" not in stored.nonce_blob


def test_non_member_cannot_fetch():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    outsider = IdentityKeyPair.generate()
    with pytest.raises(VaultError):
        relay.fetch(vid, outsider.public_bytes().hex())


def test_non_member_cannot_send():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    outsider = IdentityKeyPair.generate()
    env = Envelope(seq=0, sender=outsider.public_bytes().hex(),
                   recipients=[a.public_bytes().hex()], nonce_blob=b"x" * 40)
    with pytest.raises(VaultError):
        relay.append(vid, env)


def test_recipient_must_be_a_member():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    outsider = IdentityKeyPair.generate()
    env = Envelope(seq=0, sender=a.public_bytes().hex(),
                   recipients=[outsider.public_bytes().hex()], nonce_blob=b"x" * 40)
    with pytest.raises(VaultError):
        relay.append(vid, env)


def test_out_of_order_append_is_refused():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    env = Envelope(seq=7, sender=a.public_bytes().hex(),
                   recipients=[b.public_bytes().hex()], nonce_blob=b"x" * 40)
    with pytest.raises(VaultError):
        relay.append(vid, env)


def test_gap_detection_reports_missing_sequence():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    salt = os.urandom(SALT_LEN)
    ca.send(b.public_bytes(), b"one", salt)
    ca.send(b.public_bytes(), b"two", salt)
    # Simulate the relay losing the first envelope.
    relay._vaults[vid].pop(0)
    gaps = relay.detect_gaps(vid, b.public_bytes().hex())
    assert gaps == [0]


def test_tampered_envelope_fails_to_open():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    salt = os.urandom(SALT_LEN)
    ca.send(b.public_bytes(), b"transfer 100", salt)
    env = relay._vaults[vid][0]
    blob = bytearray(env.nonce_blob)
    blob[-1] ^= 0xFF
    env.nonce_blob = bytes(blob)
    with pytest.raises(Exception):
        cb.receive(a.public_bytes(), salt)


def test_envelope_wire_roundtrip():
    env = Envelope(seq=3, sender="ab" * 32, recipients=["cd" * 32], nonce_blob=b"\x00" * 40)
    back = Envelope.from_wire(env.to_wire())
    assert back.seq == env.seq
    assert back.sender == env.sender
    assert back.recipients == env.recipients
    assert back.nonce_blob == env.nonce_blob


def test_envelope_rejects_malformed_wire():
    with pytest.raises(VaultError):
        Envelope.from_wire({"seq": "not-a-number"})


def test_head_tracks_appends():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    salt = os.urandom(SALT_LEN)
    assert relay.head(vid) == 0
    ca.send(b.public_bytes(), b"x", salt)
    assert relay.head(vid) == 1


def test_unknown_vault_operations_raise():
    relay = Relay()
    with pytest.raises(VaultError):
        relay.head("nope")
    with pytest.raises(VaultError):
        relay.members("nope")


def test_add_member_validates_key_length():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    with pytest.raises(VaultError):
        relay.add_member(vid, "tooshort")


def test_negative_since_is_refused():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    with pytest.raises(VaultError):
        relay.fetch(vid, a.public_bytes().hex(), since=-1)


def test_send_requires_open_vault():
    a, b, relay, ca, cb = pair()
    with pytest.raises(VaultError):
        ca.send(b.public_bytes(), b"x", os.urandom(SALT_LEN))


def test_send_validates_salt_length():
    a, b, relay, ca, cb = pair()
    vid = ca.open_vault()
    cb.join(vid)
    with pytest.raises(VaultError):
        ca.send(b.public_bytes(), b"x", b"short")
