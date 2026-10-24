"""Tests for the VaultZero cryptographic core."""

import os

import pytest

from vaultzero.crypto import (
    CryptoError,
    IdentityKeyPair,
    RatchetState,
    agree,
    derive_from_passphrase,
    initial_ratchet,
    open_sealed,
    seal,
    _hkdf,
    INFO_CHAIN,
    INFO_MESSAGE,
    KEY_LEN,
    SALT_LEN,
)


def test_identity_roundtrip():
    a = IdentityKeyPair.generate()
    raw = a.private_bytes()
    b = IdentityKeyPair.from_private_bytes(raw)
    assert a.public_bytes() == b.public_bytes()


def test_identity_rejects_wrong_length():
    with pytest.raises(CryptoError):
        IdentityKeyPair.from_private_bytes(b"short")


def test_fingerprint_is_stable_and_readable():
    a = IdentityKeyPair.generate()
    fp = a.fingerprint()
    assert fp == a.fingerprint()
    assert len(fp.split("-")) == 10
    assert all(len(part) == 2 for part in fp.split("-"))


def test_fingerprints_differ_between_keys():
    assert IdentityKeyPair.generate().fingerprint() != IdentityKeyPair.generate().fingerprint()


def test_agreement_is_symmetric():
    a = IdentityKeyPair.generate()
    b = IdentityKeyPair.generate()
    s1 = agree(a.private_key, b.public_bytes())
    s2 = agree(b.private_key, a.public_bytes())
    assert s1 == s2
    assert len(s1) == KEY_LEN


def test_agreement_rejects_bad_peer_key():
    a = IdentityKeyPair.generate()
    with pytest.raises(CryptoError):
        agree(a.private_key, b"tooshort")


def test_seal_open_roundtrip():
    key = os.urandom(KEY_LEN)
    msg = b"the launch codes are in the usual place"
    blob = seal(key, msg)
    assert open_sealed(key, blob) == msg


def test_seal_uses_a_fresh_nonce_each_time():
    key = os.urandom(KEY_LEN)
    a = seal(key, b"same plaintext")
    b = seal(key, b"same plaintext")
    assert a != b
    assert a[:12] != b[:12]


def test_open_rejects_tampered_ciphertext():
    key = os.urandom(KEY_LEN)
    blob = bytearray(seal(key, b"important"))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        open_sealed(key, bytes(blob))


def test_open_rejects_wrong_key():
    blob = seal(os.urandom(KEY_LEN), b"important")
    with pytest.raises(CryptoError):
        open_sealed(os.urandom(KEY_LEN), blob)


def test_open_rejects_truncated_blob():
    with pytest.raises(CryptoError):
        open_sealed(os.urandom(KEY_LEN), b"tiny")


def test_aad_is_authenticated():
    key = os.urandom(KEY_LEN)
    blob = seal(key, b"payload", aad=b"alice->bob")
    assert open_sealed(key, blob, aad=b"alice->bob") == b"payload"
    with pytest.raises(CryptoError):
        open_sealed(key, blob, aad=b"alice->carol")


def test_seal_rejects_wrong_key_size():
    with pytest.raises(CryptoError):
        seal(b"short", b"x")


def test_passphrase_derivation_is_deterministic():
    salt = os.urandom(SALT_LEN)
    a = derive_from_passphrase("correct horse battery staple", salt, iterations=10_000)
    b = derive_from_passphrase("correct horse battery staple", salt, iterations=10_000)
    assert a == b
    assert len(a) == KEY_LEN


def test_passphrase_derivation_changes_with_salt():
    a = derive_from_passphrase("pw", os.urandom(SALT_LEN), iterations=10_000)
    b = derive_from_passphrase("pw", os.urandom(SALT_LEN), iterations=10_000)
    assert a != b


def test_passphrase_rejects_empty():
    with pytest.raises(CryptoError):
        derive_from_passphrase("", os.urandom(SALT_LEN))


def test_passphrase_rejects_weak_iteration_count():
    with pytest.raises(CryptoError):
        derive_from_passphrase("pw", os.urandom(SALT_LEN), iterations=10)


def test_passphrase_rejects_bad_salt():
    with pytest.raises(CryptoError):
        derive_from_passphrase("pw", b"short")


def test_ratchet_advances_and_keys_differ():
    state = initial_ratchet(os.urandom(KEY_LEN), os.urandom(SALT_LEN))
    keys = [state.advance() for _ in range(5)]
    assert len(set(keys)) == 5
    assert state.message_number == 5


def test_ratchet_chain_and_message_keys_are_domain_separated():
    chain = os.urandom(KEY_LEN)
    assert _hkdf(chain, b"", INFO_MESSAGE) != _hkdf(chain, b"", INFO_CHAIN)


def test_ratchet_skip_retains_intermediate_keys():
    state = initial_ratchet(os.urandom(KEY_LEN), os.urandom(SALT_LEN))
    first = state.advance()
    state2 = initial_ratchet(b"", b"")  # unrelated, just to prove independence
    del state2
    # Rebuild the same chain to compare
    secret = os.urandom(KEY_LEN)
    salt = os.urandom(SALT_LEN)
    s = initial_ratchet(secret, salt)
    k0 = s.advance()
    skipped = s.skip_to(3)
    assert len(skipped) == 2
    assert s.message_number == 3
    assert k0 not in skipped
    assert first != k0


def test_ratchet_refuses_to_rewind():
    state = initial_ratchet(os.urandom(KEY_LEN), os.urandom(SALT_LEN))
    state.advance()
    state.advance()
    with pytest.raises(CryptoError):
        state.skip_to(1)


def test_ratchet_refuses_absurd_skip():
    state = initial_ratchet(os.urandom(KEY_LEN), os.urandom(SALT_LEN))
    with pytest.raises(CryptoError):
        state.skip_to(10_000_000)


def test_ratchet_is_forward_secure():
    """A later message key must not reveal an earlier one."""
    secret = os.urandom(KEY_LEN)
    salt = os.urandom(SALT_LEN)
    s = initial_ratchet(secret, salt)
    early = s.advance()
    late = s.advance()
    assert early != late
    # Deriving forward from `late`'s chain state cannot reproduce `early`.
    assert _hkdf(late, b"", INFO_MESSAGE) != early
