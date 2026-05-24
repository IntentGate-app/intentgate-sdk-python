"""Tests for the memory provenance module.

The critical assertion is the cross-implementation KAT: Python's HKDF
and length-prefixed Canonical bytes must match the Go gateway's
output byte-for-byte. If they drift, the SDK and gateway will silently
disagree on HMACs and no test in either codebase will catch it without
this one.

The HKDF KAT vector here was computed against:

  - Go: golang.org/x/crypto/hkdf, info="intentgate-memory-v1"
  - Python: cryptography.hazmat.primitives.kdf.hkdf.HKDF

Both produce the same 32-byte output for the inputs below; the Go
gateway's TestDeriveSessionKey_KnownAnswer pins the same value. If
this test fails the SDK and the gateway are no longer compatible.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from intentgate.memory import (
    SESSION_KEY_SIZE,
    ZERO_HASH,
    Envelope,
    MemoryStore,
    ProvenanceError,
    canonical,
    derive_session_key,
    sign,
    verify,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Cross-implementation KAT — the most important test in this file
# ---------------------------------------------------------------------------


def test_hkdf_kat_matches_go_gateway():
    # Same inputs as the Go gateway's TestDeriveSessionKey_KnownAnswer.
    # Same expected output, byte-for-byte. Different language, same
    # primitive — proof the wire contract holds across the SDK/gateway
    # boundary.
    master = b"intentgate-test-master-key-32-by"
    session_id = "test-session-jti-abc"
    expected_hex = "e8b49e3464de329ffdf2bdb5e3e557a762281292daab04b0fc8b6aede03a422e"
    got = derive_session_key(master, session_id)
    assert len(got) == SESSION_KEY_SIZE
    assert got.hex() == expected_hex, (
        f"\n  Python: {got.hex()}\n  Go:     {expected_hex}\n"
        "If this differs, the SDK and gateway can no longer verify "
        "each other's HMACs. Check _DERIVATION_INFO matches the "
        "gateway's derivationInfo constant."
    )


def test_derive_session_key_deterministic():
    k1 = derive_session_key(b"master-key-bytes-here-okay", "session-1")
    k2 = derive_session_key(b"master-key-bytes-here-okay", "session-1")
    assert k1 == k2


def test_derive_session_key_distinct_sessions_distinct_keys():
    master = b"master-key-bytes-here-okay"
    assert derive_session_key(master, "session-A") != derive_session_key(master, "session-B")


def test_derive_session_key_empty_inputs():
    with pytest.raises(ValueError, match="master_key is empty"):
        derive_session_key(b"", "session")
    with pytest.raises(ValueError, match="session_id is empty"):
        derive_session_key(b"some-key", "")


# ---------------------------------------------------------------------------
# Canonical bytes — also cross-implementation-critical
# ---------------------------------------------------------------------------


def test_canonical_deterministic():
    e = Envelope(
        id="01HG-test-id",
        session_id="jti-abc",
        timestamp=1716530400000,
        data=b'{"vendor":"Acme","account":"NL00ACME0000000001"}',
        prev_hash=ZERO_HASH,
    )
    assert canonical(e) == canonical(e)


def test_canonical_excludes_hmac():
    e1 = Envelope(
        id="id",
        session_id="sid",
        timestamp=1,
        data=b"data",
        prev_hash=ZERO_HASH,
        hmac=b"\x01" * 32,
    )
    e2 = Envelope(
        id="id",
        session_id="sid",
        timestamp=1,
        data=b"data",
        prev_hash=ZERO_HASH,
        hmac=b"\xff" * 32,
    )
    assert canonical(e1) == canonical(e2)


@pytest.mark.parametrize(
    ("name", "modified"),
    [
        (
            "id",
            Envelope(id="id-b", session_id="sid-a", timestamp=1, data=b"d", prev_hash=ZERO_HASH),
        ),
        (
            "session_id",
            Envelope(id="id-a", session_id="sid-b", timestamp=1, data=b"d", prev_hash=ZERO_HASH),
        ),
        (
            "timestamp",
            Envelope(id="id-a", session_id="sid-a", timestamp=2, data=b"d", prev_hash=ZERO_HASH),
        ),
        (
            "data",
            Envelope(id="id-a", session_id="sid-a", timestamp=1, data=b"e", prev_hash=ZERO_HASH),
        ),
        (
            "prev_hash",
            Envelope(id="id-a", session_id="sid-a", timestamp=1, data=b"d", prev_hash=b"\x99" * 32),
        ),
    ],
)
def test_canonical_distinguishes_all_fields(name: str, modified: Envelope):
    base = Envelope(
        id="id-a",
        session_id="sid-a",
        timestamp=1,
        data=b"d",
        prev_hash=ZERO_HASH,
    )
    assert canonical(base) != canonical(modified), (
        f"Canonical does not distinguish {name} — would allow attacker substitution"
    )


def test_canonical_byte_layout_matches_spec():
    # Spot-check the encoding follows the documented format:
    #   uint32(len(session_id)) || session_id_utf8
    #   uint32(len(id))         || id_utf8
    #   uint64(timestamp)       (big-endian)
    #   uint32(len(prev_hash))  || prev_hash
    #   uint32(len(data))       || data
    e = Envelope(
        id="a",
        session_id="b",
        timestamp=0x0102030405060708,
        data=b"xy",
        prev_hash=ZERO_HASH,
    )
    out = canonical(e)

    # Length: 4 + 1 (session_id "b") + 4 + 1 (id "a") + 8 (ts) +
    #         4 + 32 (zero hash) + 4 + 2 (data "xy") = 60
    assert len(out) == 60

    # session_id
    assert out[0:4] == b"\x00\x00\x00\x01"
    assert out[4:5] == b"b"
    # id
    assert out[5:9] == b"\x00\x00\x00\x01"
    assert out[9:10] == b"a"
    # timestamp (big-endian uint64)
    assert out[10:18] == b"\x01\x02\x03\x04\x05\x06\x07\x08"
    # prev_hash
    assert out[18:22] == b"\x00\x00\x00\x20"  # 32 = 0x20
    assert out[22:54] == ZERO_HASH
    # data
    assert out[54:58] == b"\x00\x00\x00\x02"
    assert out[58:60] == b"xy"


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------


def test_sign_verify_round_trip():
    key = derive_session_key(b"some-master-key-bytes-foobarbaz", "session-1")
    env = Envelope(
        id="e0",
        session_id="session-1",
        timestamp=1,
        data=b"hello",
        prev_hash=ZERO_HASH,
    )
    signed = sign(key, env)
    assert len(signed.hmac) == 32
    verify(key, signed)  # no exception


def test_verify_detects_data_tamper():
    # The sophisticated AAI03 case in Python form: attacker swaps the
    # data field but keeps the HMAC. Verify must catch this.
    key = derive_session_key(b"some-master-key-bytes-foobarbaz", "tamper-session")
    signed = sign(
        key,
        Envelope(
            id="e0",
            session_id="tamper-session",
            timestamp=1,
            data=b'{"vendor":"Acme","account":"NL00ACME0000000001"}',
            prev_hash=ZERO_HASH,
        ),
    )
    tampered = Envelope(
        id=signed.id,
        session_id=signed.session_id,
        timestamp=signed.timestamp,
        data=b'{"vendor":"Acme","account":"NL66ATTACKER000000"}',
        prev_hash=signed.prev_hash,
        hmac=signed.hmac,
    )
    with pytest.raises(ProvenanceError, match="hmac mismatch"):
        verify(key, tampered)


def test_verify_detects_wrong_key():
    key_a = derive_session_key(b"master-bytes-padded-out-just-enough", "session-A")
    key_b = derive_session_key(b"master-bytes-padded-out-just-enough", "session-B")
    signed = sign(
        key_a,
        Envelope(
            id="e0",
            session_id="session-A",
            timestamp=1,
            data=b"x",
            prev_hash=ZERO_HASH,
        ),
    )
    with pytest.raises(ProvenanceError):
        verify(key_b, signed)


def test_verify_rejects_short_hmac():
    key = derive_session_key(b"key-padding-here-okay-fine-just-do", "s")
    env = Envelope(
        id="e",
        session_id="s",
        timestamp=1,
        data=b"x",
        prev_hash=ZERO_HASH,
        hmac=b"\x01\x02",
    )
    with pytest.raises(ProvenanceError, match="hmac field is 2 bytes"):
        verify(key, env)


def test_verify_empty_key_raises_value_error():
    env = Envelope(
        id="e",
        session_id="s",
        timestamp=1,
        data=b"x",
        prev_hash=ZERO_HASH,
        hmac=bytes(32),
    )
    with pytest.raises(ValueError, match="session_key is empty"):
        verify(b"", env)


def test_sign_empty_key_raises_value_error():
    with pytest.raises(ValueError, match="session_key is empty"):
        sign(b"", Envelope(id="e", session_id="s", timestamp=1, data=b"x"))


# ---------------------------------------------------------------------------
# VerifyChain
# ---------------------------------------------------------------------------


def test_verify_chain_happy_path():
    key = derive_session_key(b"master-padding-bytes-here-please-ok", "chain-session")
    e0 = sign(
        key,
        Envelope(
            id="e0",
            session_id="chain-session",
            timestamp=1,
            data=b"first",
            prev_hash=ZERO_HASH,
        ),
    )
    h0 = hashlib.sha256(canonical(e0)).digest()
    e1 = sign(
        key,
        Envelope(
            id="e1",
            session_id="chain-session",
            timestamp=2,
            data=b"second",
            prev_hash=h0,
        ),
    )
    verify_chain(key, [e0, e1])  # no exception


def test_verify_chain_detects_broken_link():
    key = derive_session_key(b"master-padding-bytes-here-please-ok", "broken-session")
    e0 = sign(
        key,
        Envelope(
            id="e0",
            session_id="broken-session",
            timestamp=1,
            data=b"first",
            prev_hash=ZERO_HASH,
        ),
    )
    # e1 claims a different predecessor than e0.
    e1 = sign(
        key,
        Envelope(
            id="e1",
            session_id="broken-session",
            timestamp=2,
            data=b"second",
            prev_hash=b"\xab" * 32,
        ),
    )
    with pytest.raises(ProvenanceError, match="prev_hash"):
        verify_chain(key, [e0, e1])


def test_verify_chain_first_entry_must_have_zero_prev():
    key = derive_session_key(b"master-padding-bytes-here-please-ok", "first-session")
    e0 = sign(
        key,
        Envelope(
            id="e0",
            session_id="first-session",
            timestamp=1,
            data=b"first",
            prev_hash=b"\xcc" * 32,
        ),
    )
    with pytest.raises(ProvenanceError):
        verify_chain(key, [e0])


def test_verify_chain_empty_is_ok():
    # Tool call without any memory backing — valid case, let policy
    # decide whether the tool requires provenance.
    key = derive_session_key(b"master-padding-bytes-here-please-ok", "empty")
    verify_chain(key, [])  # no exception


# ---------------------------------------------------------------------------
# MemoryStore — agent-side facade
# ---------------------------------------------------------------------------


def _store() -> MemoryStore:
    key = derive_session_key(b"store-test-master-key-padding-okay", "store-jti")
    return MemoryStore(session_id="store-jti", memory_signing_key=key)


def test_memorystore_write_then_read_round_trip():
    store = _store()
    eid = store.write({"vendor": "Acme", "account": "NL00ACME0000"})
    env = store.read(eid)
    assert env.id == eid
    assert env.session_id == "store-jti"
    # Data round-tripped through JSON, sorted keys.
    assert json.loads(env.data.decode("utf-8")) == {
        "vendor": "Acme",
        "account": "NL00ACME0000",
    }


def test_memorystore_read_unknown_id_raises():
    store = _store()
    with pytest.raises(KeyError):
        store.read("does-not-exist")


def test_memorystore_write_accepts_bytes_str_dict():
    store = _store()
    a = store.write(b"\x00\x01\x02")
    b = store.write("hello world")
    c = store.write({"a": 1})
    assert store.read(a).data == b"\x00\x01\x02"
    assert store.read(b).data == b"hello world"
    assert store.read(c).data == b'{"a":1}'  # sorted-keys + no-whitespace JSON


def test_memorystore_chain_links_correctly():
    # Two consecutive writes should chain: the second's prev_hash
    # equals SHA-256 of the first's canonical bytes.
    store = _store()
    a = store.write({"step": 1})
    b = store.write({"step": 2})
    ea = store.read(a)
    eb = store.read(b)
    expected_prev = hashlib.sha256(canonical(ea)).digest()
    assert eb.prev_hash == expected_prev


def test_memorystore_detects_storage_layer_tamper():
    # Simulate an attacker tampering with the entry IN the underlying
    # store (not via MemoryStore.write). Read must catch it.
    store = _store()
    eid = store.write({"vendor": "Acme", "account": "NL00ACME0000000001"})

    # Reach into the fallback store and swap the data byte for byte
    # but keep the HMAC. read() must reject.
    tampered = Envelope(
        id=store._fallback[eid].id,
        session_id=store._fallback[eid].session_id,
        timestamp=store._fallback[eid].timestamp,
        data=b'{"vendor":"Acme","account":"NL66ATTACKER0"}',
        prev_hash=store._fallback[eid].prev_hash,
        hmac=store._fallback[eid].hmac,
    )
    store._fallback[eid] = tampered
    with pytest.raises(ProvenanceError, match="hmac mismatch"):
        store.read(eid)


def test_memorystore_provenance_for_round_trip():
    # provenance_for() output is the structure the SDK packs into the
    # X-Intent-Memory-Provenance header. Decoding it should reproduce
    # the same envelope.
    store = _store()
    eid = store.write({"payload": "x"})
    entries = store.provenance_for([eid])
    assert len(entries) == 1
    w = entries[0]
    assert w["id"] == eid
    assert w["session_id"] == "store-jti"

    # base64url-no-padding round-trip
    def _b64_decode_padded(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    assert _b64_decode_padded(w["data"]) == b'{"payload":"x"}'
    assert len(_b64_decode_padded(w["hmac"])) == 32


def test_memorystore_rejects_wrong_size_signing_key():
    with pytest.raises(ValueError, match="must be 32 bytes"):
        MemoryStore(session_id="s", memory_signing_key=b"too-short")


def test_memorystore_with_custom_backend():
    # External backend exposed via callables. Simulates the customer
    # plugging pgvector / Redis / etc. into the wrapper.
    storage: dict[str, Any] = {}

    def write_hook(entry_id: str, env: Envelope) -> None:
        storage[entry_id] = env

    def read_hook(entry_id: str) -> Envelope:
        return storage[entry_id]

    key = derive_session_key(b"backend-test-padding-bytes-okay-ya", "backend-jti")
    store = MemoryStore(
        session_id="backend-jti",
        memory_signing_key=key,
        write_hook=write_hook,
        read_hook=read_hook,
    )
    eid = store.write({"backend": "custom"})
    assert eid in storage
    env = store.read(eid)
    assert env.id == eid
