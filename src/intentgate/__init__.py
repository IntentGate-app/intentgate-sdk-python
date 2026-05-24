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
    ContentBlock,
    Gateway,
    IntentGateMetadata,
    ToolCallResult,
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
