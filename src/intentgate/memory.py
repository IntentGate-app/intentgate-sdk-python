"""Memory provenance primitives for the IntentGate SDK.

This module implements the SDK side of the AAI03 (Memory Poisoning)
defense. The agent wraps its memory backend (vector DB, Redis, an
in-memory dict — anything) with :class:`MemoryStore`, which signs
every write with an HMAC-SHA256 keyed by a per-session signing key
derived from the capability token. At tool-call time the agent
declares which memory entries influenced the call via the
``memory_provenance`` parameter on :meth:`Gateway.tool_call`; the
gateway re-derives the session key and verifies each entry.

# Cross-implementation contract

The byte encoding of an :class:`Envelope` (see :func:`canonical`) MUST
match the Go gateway's ``internal/provenance.Canonical`` byte-for-byte.
The KDF MUST be HKDF-SHA256 with info=``intentgate-memory-v1`` to
match the gateway's ``DeriveSessionKey``. The HMAC MUST be HMAC-SHA256.
If any of these contracts drifts the SDK and the gateway will silently
disagree on signatures — a class of bug worth catching with the cross-
implementation KAT test in ``tests/test_memory.py``.

# Zero new runtime dependencies

The SDK runtime deps are httpx and Python stdlib. We deliberately do
NOT take a dep on the ``cryptography`` package — it's compiled, heavy,
and HKDF is a thin construction over HMAC that's about 10 lines.
:func:`_hkdf_sha256` is that 10-line implementation. KAT-verified
against Go's ``golang.org/x/crypto/hkdf`` in the test suite.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

# Version tag baked into the HKDF info parameter. Bumping this forces
# a key-derivation cutover: old and new keys are computed from the
# same master + jti but produce different bytes. Future versions could
# accept multiple labels during a grace window; v1 is the only one
# defined today.
_DERIVATION_INFO = b"intentgate-memory-v1"

# Output length of the derived session signing key in bytes. Matches
# the Go gateway's SessionKeySize. 32 bytes = 256 bits, the natural
# output range of HKDF-SHA256.
SESSION_KEY_SIZE = 32

# Output length of SHA-256 and HMAC-SHA256.
_HASH_SIZE = 32

# The conventional PrevHash value for the first entry in a session.
# Named so the special-case is obvious at the call site.
ZERO_HASH = bytes(_HASH_SIZE)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProvenanceError(Exception):
    """Raised when the SDK cannot produce or verify a memory envelope.

    Distinct from :class:`intentgate.exceptions.ProvenanceError` (which
    is raised by :meth:`Gateway.tool_call` when the GATEWAY rejected
    the provenance check). This class is for SDK-internal failures —
    a tampered entry detected at read time, a malformed envelope, etc.
    """


# ---------------------------------------------------------------------------
# HKDF — RFC 5869 extract-and-expand with SHA-256
# ---------------------------------------------------------------------------


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Derive ``length`` bytes from ``ikm`` using HKDF-SHA256.

    This is a faithful implementation of RFC 5869 extract-and-expand.
    Kept in stdlib (hmac + hashlib) so the SDK doesn't take a dep on
    the ``cryptography`` package for one primitive.
    """
    if length <= 0:
        raise ValueError("hkdf: length must be > 0")
    if length > 255 * _HASH_SIZE:
        raise ValueError(f"hkdf: length {length} exceeds maximum {255 * _HASH_SIZE}")

    # Extract step: PRK = HMAC-SHA256(salt, IKM)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand step: T(0) = empty, T(i) = HMAC(PRK, T(i-1) || info || i)
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(t)
        counter += 1
    return bytes(out[:length])


def derive_session_key(master_key: bytes, session_id: str) -> bytes:
    """Derive the per-session memory signing key.

    Matches the gateway's ``provenance.DeriveSessionKey``: HKDF-SHA256
    with salt = session_id (as UTF-8 bytes), info = ``intentgate-memory-v1``,
    length = 32.

    The agent SDK and the gateway both call this function with
    identical inputs and obtain identical output. The key never has
    to travel separately — both sides re-derive on demand.

    Raises:
        ValueError: master_key is empty or session_id is empty.
    """
    if not master_key:
        raise ValueError("derive_session_key: master_key is empty")
    if not session_id:
        raise ValueError("derive_session_key: session_id is empty")
    return _hkdf_sha256(
        ikm=master_key,
        salt=session_id.encode("utf-8"),
        info=_DERIVATION_INFO,
        length=SESSION_KEY_SIZE,
    )


# ---------------------------------------------------------------------------
# Envelope + canonical bytes
# ---------------------------------------------------------------------------


@dataclass
class Envelope:
    """One signed memory entry.

    Stored opaquely by the customer's memory backend. The agent SDK
    produces these on write via :meth:`MemoryStore.write`; the gateway
    verifies them at tool-call time.

    Attributes:
        id: Stable identifier for the entry. Usually a ULID generated
            at write time. Used as the lookup key on read and as the
            entry reference in the provenance header.
        session_id: The capability token's ``jti`` whose signing key
            signed this envelope. Identifies which session-key the
            gateway must re-derive to verify.
        timestamp: Creation time as Unix milliseconds. Part of the
            HMAC so two entries with the same payload but different
            times produce distinct signatures.
        data: The application-level payload. Bytes — the SDK does not
            interpret the contents.
        prev_hash: SHA-256 of the canonical bytes of the previous
            entry in this session, or :data:`ZERO_HASH` for the first
            entry. Forms the per-session hash chain.
        hmac: HMAC-SHA256 of :func:`canonical(envelope)` under the
            session signing key. Set by :func:`sign`; verified by
            :func:`verify`.
    """

    id: str
    session_id: str
    timestamp: int
    data: bytes
    prev_hash: bytes = field(default_factory=lambda: ZERO_HASH)
    hmac: bytes = b""


def canonical(env: Envelope) -> bytes:
    """Produce the byte sequence the envelope's HMAC covers.

    The encoding is a length-prefixed concatenation of the immutable
    fields in this order: session_id (utf-8), id (utf-8), timestamp
    (big-endian uint64), prev_hash, data. Lengths for the variable-
    length fields are big-endian uint32.

    The encoding is deliberately NOT JSON. The same byte sequence the
    gateway computes in Go's ``internal/provenance.Canonical`` is what
    Python produces here — verified by KAT cross-test in the test
    suite. A JSON encoding would risk parser-confusion attacks where
    the signer and verifier disagree on canonical bytes.

    The ``hmac`` field is excluded (a signature cannot cover itself).
    """
    # Mirror Go's int64 → uint64 reinterpretation. For non-negative
    # timestamps (the normal case — Unix milliseconds) this is a
    # no-op. For the negative case it preserves byte-equality with Go.
    ts_u64 = env.timestamp & 0xFFFFFFFFFFFFFFFF

    sid = env.session_id.encode("utf-8")
    eid = env.id.encode("utf-8")

    parts = [
        struct.pack(">I", len(sid)),
        sid,
        struct.pack(">I", len(eid)),
        eid,
        struct.pack(">Q", ts_u64),
        struct.pack(">I", len(env.prev_hash)),
        env.prev_hash,
        struct.pack(">I", len(env.data)),
        env.data,
    ]
    return b"".join(parts)


def sign(session_key: bytes, env: Envelope) -> Envelope:
    """Return a copy of ``env`` with the ``hmac`` field populated.

    Used at memory-write time by :meth:`MemoryStore.write` and by
    tests. Computes ``HMAC-SHA256(session_key, canonical(env))``.

    Raises:
        ValueError: ``session_key`` is empty.
    """
    if not session_key:
        raise ValueError("sign: session_key is empty")
    sig = hmac.new(session_key, canonical(env), hashlib.sha256).digest()
    return Envelope(
        id=env.id,
        session_id=env.session_id,
        timestamp=env.timestamp,
        data=env.data,
        prev_hash=env.prev_hash,
        hmac=sig,
    )


def verify(session_key: bytes, env: Envelope) -> None:
    """Check ``env.hmac`` against ``session_key``.

    Returns ``None`` on a valid signature; raises :class:`ProvenanceError`
    otherwise. Comparison uses :func:`hmac.compare_digest`, which is
    constant-time with respect to signature contents.

    Raises:
        ProvenanceError: missing/short HMAC or signature mismatch.
        ValueError: ``session_key`` is empty.
    """
    if not session_key:
        raise ValueError("verify: session_key is empty")
    if len(env.hmac) != _HASH_SIZE:
        raise ProvenanceError(f"hmac field is {len(env.hmac)} bytes; expected {_HASH_SIZE}")
    expected = hmac.new(session_key, canonical(env), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, env.hmac):
        raise ProvenanceError("hmac mismatch")


def verify_chain(session_key: bytes, chain: Iterable[Envelope]) -> None:
    """Check a sequence of envelopes as a per-session chain.

    Each entry's HMAC must verify and each entry's ``prev_hash`` must
    equal SHA-256 of the canonical bytes of the previous entry. The
    first entry's ``prev_hash`` must equal :data:`ZERO_HASH`.

    Raises:
        ProvenanceError: any individual HMAC fails OR any prev_hash
            mismatches OR (the first entry doesn't have ZERO_HASH).
    """
    chain_list = list(chain)
    if not chain_list:
        return  # empty chain is valid — let policy decide whether that's OK
    for i, env in enumerate(chain_list):
        try:
            verify(session_key, env)
        except ProvenanceError as e:
            raise ProvenanceError(f"entry {i}: {e}") from e
        if i == 0:
            expected_prev = ZERO_HASH
        else:
            expected_prev = hashlib.sha256(canonical(chain_list[i - 1])).digest()
        if not hmac.compare_digest(expected_prev, env.prev_hash):
            raise ProvenanceError(
                f"entry {i}: prev_hash does not match previous entry's canonical hash",
            )


# ---------------------------------------------------------------------------
# MemoryStore — agent-side facade
# ---------------------------------------------------------------------------


class MemoryStore:
    """Sign-on-write, verify-on-read wrapper around a memory backend.

    The customer plugs their underlying memory store (pgvector, Redis,
    Pinecone, an in-memory dict, anything) into this wrapper by
    supplying two callables: a write-hook and a read-hook. The
    wrapper signs entries on write and verifies them on read, so a
    tampered entry surfaces immediately at the agent's read site
    rather than waiting until the gateway rejects the tool call.

    The default storage backend is an in-memory dict — suitable for
    SDK tests, demos, and small agents. Production agents pass their
    real backend's read/write callables.

    Args:
        session_id: The ``jti`` of the capability token this store is
            bound to. Used as the HKDF salt to derive the signing key.
        memory_signing_key: The base64url-decoded signing key returned
            by ``POST /v1/admin/mint`` when ``with_memory_signing_key``
            was true. This is the per-session key; the SDK never sees
            the gateway's master key.
        write_hook: Optional callable ``(entry_id, envelope_bytes) ->
            None`` for the customer's backend. When ``None``, an
            in-memory dict is used.
        read_hook: Optional callable ``(entry_id) -> bytes`` returning
            the previously-written envelope bytes. When ``None``, the
            in-memory dict is used. Must raise :class:`KeyError` for
            missing entries.

    Example::

        # Mint a token with the signing key bundled in:
        # POST /v1/admin/mint {"subject": "agent", "with_memory_signing_key": true}
        # → {"token": "...", "jti": "abc123...", "memory_signing_key": "..."}

        from intentgate.memory import MemoryStore
        import base64

        store = MemoryStore(
            session_id="abc123...",
            memory_signing_key=base64.urlsafe_b64decode("<key from mint>"),
        )
        eid = store.write({"vendor": "Acme", "account": "NL00ACME0000000001"})

        # ... later, when constructing a tool call:
        gw.tool_call(
            "send_payment",
            arguments={"amount": 1000, "account": store.read(eid)["account"]},
            intent_prompt="pay the monthly Acme invoice",
            memory_provenance=[eid],
            memory_store=store,
        )
    """

    def __init__(
        self,
        session_id: str,
        memory_signing_key: bytes,
        *,
        write_hook: Any = None,
        read_hook: Any = None,
    ) -> None:
        if not session_id:
            raise ValueError("MemoryStore: session_id is required")
        if len(memory_signing_key) != SESSION_KEY_SIZE:
            raise ValueError(
                f"MemoryStore: memory_signing_key must be {SESSION_KEY_SIZE} bytes, "
                f"got {len(memory_signing_key)}"
            )
        self._session_id = session_id
        self._key = memory_signing_key
        # In-memory fallback storage used when the customer didn't
        # supply hooks. Keyed by entry id; values are the canonical
        # bytes plus the HMAC (so a tamper at the bytes level surfaces
        # in verify()).
        self._fallback: dict[str, Envelope] = {}
        self._write_hook = write_hook
        self._read_hook = read_hook
        # The chain head — SHA-256 of the canonical bytes of the most
        # recently written envelope. Used to populate prev_hash on the
        # next write so the chain link is correct without requiring the
        # caller to track it.
        self._chain_head: bytes = ZERO_HASH

    def write(self, data: dict[str, Any] | bytes | str) -> str:
        """Sign ``data`` into a new :class:`Envelope` and store it.

        The envelope's id is a fresh UUID4 (URL-safe, no padding) so
        each write is uniquely addressable. The envelope's prev_hash
        is the chain head from the previous write (or ZERO_HASH for
        the first), so the chain is contiguous without caller
        bookkeeping.

        ``data`` may be:
            - ``bytes`` (passed verbatim)
            - ``str`` (UTF-8 encoded)
            - any JSON-serializable dict (encoded with ``json.dumps``
              using sorted keys + no whitespace, so two equivalent
              dicts produce the same envelope bytes)

        Returns the entry id, which the caller passes to
        :meth:`Gateway.tool_call` via the ``memory_provenance`` list.
        """
        import json

        if isinstance(data, bytes):
            payload = data
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

        entry_id = uuid.uuid4().hex
        env = sign(
            self._key,
            Envelope(
                id=entry_id,
                session_id=self._session_id,
                timestamp=int(time.time() * 1000),
                data=payload,
                prev_hash=self._chain_head,
            ),
        )

        if self._write_hook is not None:
            self._write_hook(entry_id, env)
        else:
            self._fallback[entry_id] = env

        # Update chain head to point at the just-written envelope.
        self._chain_head = hashlib.sha256(canonical(env)).digest()
        return entry_id

    def read(self, entry_id: str) -> Envelope:
        """Fetch and verify the envelope identified by ``entry_id``.

        Raises:
            KeyError: no such entry.
            ProvenanceError: HMAC verification failed — the entry was
                tampered with after writing.
        """
        env = self._read_hook(entry_id) if self._read_hook is not None else self._fallback[entry_id]
        verify(self._key, env)
        return env

    def provenance_for(self, entry_ids: Iterable[str]) -> list[dict[str, Any]]:
        """Build the wire-format provenance entries for a tool call.

        Returns a list of dicts in the shape the gateway parses out
        of the ``X-Intent-Memory-Provenance`` header. Used internally
        by :meth:`Gateway.tool_call`; exposed publicly for testing.

        Each entry is verified before inclusion — if any envelope was
        tampered with at the storage layer, :class:`ProvenanceError`
        is raised here rather than at the gateway.
        """
        import base64

        out = []
        for eid in entry_ids:
            env = self.read(eid)
            out.append(
                {
                    "id": env.id,
                    "session_id": env.session_id,
                    "ts": env.timestamp,
                    "data": base64.urlsafe_b64encode(env.data).rstrip(b"=").decode("ascii"),
                    "prev_hash": base64.urlsafe_b64encode(env.prev_hash)
                    .rstrip(b"=")
                    .decode("ascii"),
                    "hmac": base64.urlsafe_b64encode(env.hmac).rstrip(b"=").decode("ascii"),
                }
            )
        return out

    def __iter__(self) -> Iterator[str]:
        """Iterate entry IDs in the fallback in-memory store.

        Only meaningful when the wrapper is using its in-memory
        fallback (no write_hook/read_hook supplied). Used by tests and
        demo code.
        """
        return iter(self._fallback)

    def __len__(self) -> int:
        return len(self._fallback)
