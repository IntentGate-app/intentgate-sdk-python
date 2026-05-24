"""Exception hierarchy for the IntentGate SDK.

Every gateway response that isn't a clean allow becomes an exception.
The hierarchy lets callers catch broadly (``except IntentGateError``) or
narrowly (``except CapabilityError``) depending on whether they want to
distinguish *which* check fired.

The pipeline-stage exceptions correspond one-to-one with the
gateway's JSON-RPC error codes:

==================  =================  =========
Exception           JSON-RPC code      Stage
==================  =================  =========
CapabilityError     -32010             capability
IntentError         -32011             intent
PolicyError         -32012             policy
BudgetError         -32013             budget
ProvenanceError     -32014             provenance (opt-in, AAI03)
==================  =================  =========
"""

from __future__ import annotations


class IntentGateError(Exception):
    """Base class for every error this SDK raises.

    Attributes:
        code: JSON-RPC error code returned by the gateway, or 0 if the
            error originated client-side (network, JSON parse, etc.).
        message: Human-readable summary from the gateway's "message"
            field. Stable across versions; safe to show in user-facing
            UIs.
        data: The optional "data" field — typically a one-line reason
            string explaining which caveat or rule fired.
    """

    code: int = 0
    message: str = ""
    data: object | None = None

    def __init__(self, message: str, *, code: int = 0, data: object | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def __str__(self) -> str:  # pragma: no cover — trivial
        if self.data:
            return f"{self.message}: {self.data}"
        return self.message


class GatewayError(IntentGateError):
    """Network / transport error reaching the gateway, or an HTTP
    response that isn't well-formed JSON-RPC.

    Use this to distinguish "the gateway is unreachable" from "the
    gateway said no" — the four stage-specific exceptions below mean
    the gateway was reachable and chose to deny.
    """


class ProtocolError(IntentGateError):
    """JSON-RPC error returned by the gateway that isn't one of the
    four stage codes — typically -32600..-32603 from the spec
    (parse error, invalid request, method not found, invalid params,
    internal error).
    """


# --- Stage-specific errors ---------------------------------------------


class CapabilityError(IntentGateError):
    """The capability check denied the call: token signature invalid,
    expired, agent mismatch, tool not in caveat allow-list, etc.
    JSON-RPC code -32010.
    """


class IntentError(IntentGateError):
    """The intent check denied the call: the requested tool isn't in
    the structured intent the extractor produced from the user prompt.
    JSON-RPC code -32011.
    """


class PolicyError(IntentGateError):
    """The OPA policy denied the call. The reason carries the Rego
    rule's explanation. JSON-RPC code -32012.
    """


class BudgetError(IntentGateError):
    """A max_calls caveat in the token has been exhausted. JSON-RPC
    code -32013.
    """


class ProvenanceError(IntentGateError):
    """The opt-in memory-provenance check denied the call.

    Raised when the gateway's AAI03 memory-poisoning defense (the
    fifth check, between intent and policy, gated on the gateway's
    INTENTGATE_PROVENANCE_ENABLED flag) rejects a tools/call because
    the ``X-Intent-Memory-Provenance`` header carries an entry whose
    HMAC does not verify, whose prev_hash chain is broken, or whose
    envelope is structurally malformed.

    The ``data`` attribute carries the gateway's specific rejection
    reason (e.g. "entry 0: hmac mismatch", "entry 1: prev_hash does
    not match previous entry's canonical hash") — useful for
    forensics, not safe to show to end users.

    JSON-RPC code -32014. Not raised by gateways with provenance
    disabled, which is the default.
    """


# --- Internal helper ---------------------------------------------------


_CODE_TO_EXC: dict[int, type[IntentGateError]] = {
    -32010: CapabilityError,
    -32011: IntentError,
    -32012: PolicyError,
    -32013: BudgetError,
    -32014: ProvenanceError,
}


def for_code(code: int) -> type[IntentGateError]:
    """Return the exception class that corresponds to a JSON-RPC code.

    Stage codes (-32010 through -32013) map to their stage-specific
    subclass. Everything else (parse error, method not found, internal
    error, custom server errors not in the stage range) maps to
    :class:`ProtocolError`.
    """
    return _CODE_TO_EXC.get(code, ProtocolError)
