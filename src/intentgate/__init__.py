"""Python SDK for the IntentGate authorization gateway.

The intent of this package is the "three lines of agent code" promise
from the IntentGate pitch:

    from intentgate import Gateway
    gw = Gateway(url="http://localhost:8080", token=os.environ["INTENTGATE_TOKEN"])
    result = gw.tool_call("read_invoice", arguments={"id": "123"},
                          intent_prompt="Process today's AP invoices")

`tool_call` raises a typed exception when the gateway blocks; the
exception carries which check fired and why. See `exceptions` for the
full hierarchy.
"""

from intentgate.capability import (
    AttenuationError,
    Caveat,
    attenuate,
    decode_token,
)
from intentgate.client import (
    ROUTE_MCP_GOVERNED,
    ROUTE_MCP_LEGACY,
    ContentBlock,
    Gateway,
    IntentGateMetadata,
    RouteNotChosenError,
    RouteNotFoundError,
    ToolCallResult,
)

# S4-WP-22. The value-returning decision contract (ODR-R1-018), alongside the exception
# hierarchy rather than replacing it: an obtained answer is a VALUE, and an exception is
# reserved for the state in which no answer exists.
from intentgate.decision import (
    ANSWER_REFUSALS,
    ASSERTION_CLASSES,
    AUTHORITY_KINDS,
    CANONICAL_ANSWER_VERSION,
    NEGOTIATION_HEADER,
    VERDICTS,
    BatchDecision,
    Decision,
    NotPermittedError,
    UnavailableError,
    validate_answer,
)
from intentgate.exceptions import (
    BudgetError,
    CapabilityError,
    GatewayError,
    IntentError,
    IntentGateError,
    PolicyError,
    ProtocolError,
    ProvenanceError,
)
from intentgate.memory import (
    Envelope,
    MemoryStore,
    derive_session_key,
)

__all__ = [
    # S4-WP-22 — the decision contract.
    "ANSWER_REFUSALS",
    "ASSERTION_CLASSES",
    "AUTHORITY_KINDS",
    "BatchDecision",
    "CANONICAL_ANSWER_VERSION",
    "Decision",
    "NEGOTIATION_HEADER",
    "NotPermittedError",
    "UnavailableError",
    "VERDICTS",
    "validate_answer",
    "ROUTE_MCP_GOVERNED",
    "ROUTE_MCP_LEGACY",
    "RouteNotChosenError",
    "RouteNotFoundError",
    "Gateway",
    "ToolCallResult",
    "ContentBlock",
    "IntentGateMetadata",
    "IntentGateError",
    "GatewayError",
    "ProtocolError",
    "CapabilityError",
    "IntentError",
    "PolicyError",
    "BudgetError",
    "ProvenanceError",
    "attenuate",
    "Caveat",
    "AttenuationError",
    "decode_token",
    "MemoryStore",
    "Envelope",
    "derive_session_key",
]

__version__ = "0.3.0"
