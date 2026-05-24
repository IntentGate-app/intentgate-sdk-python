"""HTTP client for the IntentGate gateway.

The :class:`Gateway` wraps the JSON-RPC envelope, the Authorization
header, and the X-Intent-Prompt header so callers can invoke
``gw.tool_call(...)`` like any other method and have errors materialize
as typed Python exceptions.

Sync only in v0.1. An async variant (anyio / httpx.AsyncClient) is
straightforward to add behind the same Gateway facade if a customer
asks; not on the v0.1 critical path.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from intentgate import exceptions

# JSON-RPC method we currently use. The MCP spec defines others
# (tools/list, initialize, ping); the gateway proxies those in a later
# session and the SDK will gain helpers for them then.
_TOOLS_CALL_METHOD = "tools/call"

# Default timeout for a single tool-call. Most policy decisions are
# millisecond-scale; LLM-backed intent extraction can push to a few
# hundred milliseconds. 10s is forgiving for cold starts and slow CI.
_DEFAULT_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class ContentBlock:
    """One piece of the tool's response, in MCP shape.

    v0.1 only emits ``type="text"`` blocks; future tool servers may
    return ``image``, ``resource``, etc.
    """

    type: str
    text: str = ""


@dataclass(frozen=True)
class IntentGateMetadata:
    """The gateway's per-call decision summary.

    Pulled from the ``_intentgate`` vendor extension on the JSON-RPC
    result. Always present on a successful tool_call, since the gateway
    populates it for every allowed call.
    """

    decision: str
    reason: str = ""
    check: str = ""
    latency_ms: int = 0


@dataclass(frozen=True)
class ToolCallResult:
    """Successful tool-call response.

    ``content`` is the upstream tool's output; ``is_error`` reflects
    the MCP-level ``isError`` flag (a tool indicating its own failure
    versus the gateway transport-level errors that raise exceptions);
    ``intentgate`` is the gateway's decision metadata.
    """

    content: list[ContentBlock] = field(default_factory=list)
    is_error: bool = False
    intentgate: IntentGateMetadata | None = None


class Gateway:
    """Thin client for the IntentGate gateway.

    Example::

        from intentgate import Gateway
        gw = Gateway(url="http://localhost:8080", token=os.environ["INTENTGATE_TOKEN"])
        result = gw.tool_call(
            "read_invoice",
            arguments={"id": "123"},
            intent_prompt="Process today's AP invoices",
        )

    The constructor binds the gateway URL and an optional capability
    token; supply both once and the client uses them for every call.

    Args:
        url: Base URL of the gateway, e.g. ``http://localhost:8080``.
            Trailing slash is tolerated.
        token: Capability token from ``igctl mint`` (or your tenant's
            mint service). When ``None``, no Authorization header is
            sent; the gateway will reject with CapabilityError if it's
            in strict mode.
        timeout: Per-request timeout in seconds.
        client: Optional pre-configured httpx.Client. Useful for
            test injection, custom transports, or shared connection
            pooling. When supplied, the SDK does NOT close it in
            ``close``; the caller owns its lifecycle.
    """

    def __init__(
        self,
        url: str,
        token: str | None = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT_S,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)
        self._ids: Iterator[int] = itertools.count(1)

    # --- public API ---------------------------------------------------

    def tool_call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        intent_prompt: str | None = None,
        request_id: int | str | None = None,
        memory_provenance: list[str] | None = None,
        memory_store: Any = None,
    ) -> ToolCallResult:
        """Invoke a tool through the gateway.

        Args:
            tool: Tool name (e.g. ``"read_invoice"``). Required.
            arguments: Arguments to pass through to the tool. The
                gateway logs only the keys, never the values.
            intent_prompt: The user's original prompt. Sent in the
                ``X-Intent-Prompt`` header; the gateway feeds it to the
                intent extractor and verifies the requested tool is
                consistent with the extracted intent. Optional, but
                strongly recommended in production — without it the
                intent check is skipped (or denies in strict mode).
            request_id: JSON-RPC ``id`` for the request. When ``None``,
                a sequential per-Gateway counter is used.
            memory_provenance: Optional list of memory entry IDs that
                influenced the tool call. When supplied together with
                ``memory_store``, the SDK packs the corresponding
                signed envelopes into the ``X-Intent-Memory-Provenance``
                header — the gateway re-derives the session key from
                the capability token's jti, verifies each HMAC, and
                walks the chain. Used only when the gateway has
                provenance enabled (the operator sets
                ``INTENTGATE_PROVENANCE_ENABLED=true``); otherwise the
                header is ignored. See :mod:`intentgate.memory`.
            memory_store: A :class:`intentgate.memory.MemoryStore`
                instance the SDK queries for the envelopes named in
                ``memory_provenance``. Required iff ``memory_provenance``
                is non-empty.

        Returns:
            :class:`ToolCallResult` for an allowed call.

        Raises:
            CapabilityError: capability stage denied (-32010).
            IntentError: intent stage denied (-32011).
            PolicyError: policy stage denied (-32012).
            BudgetError: budget stage denied (-32013).
            ProvenanceError: provenance stage denied (-32014). Only
                possible when the gateway has provenance enabled and
                the request carried a provenance header that failed
                verification.
            ProtocolError: any other JSON-RPC error (parse, method not
                found, invalid params, internal error).
            GatewayError: network or HTTP transport error reaching
                the gateway.
        """
        if not tool:
            raise ValueError("tool is required")
        if memory_provenance and memory_store is None:
            raise ValueError(
                "memory_provenance is non-empty but memory_store is None; "
                "supply a MemoryStore so the SDK can look up the envelopes",
            )

        rid: int | str = request_id if request_id is not None else next(self._ids)
        body = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": _TOOLS_CALL_METHOD,
            "params": {
                "name": tool,
                "arguments": arguments or {},
            },
        }
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if intent_prompt:
            headers["X-Intent-Prompt"] = intent_prompt
        if memory_provenance:
            # Look up envelopes, verify locally (an SDK-side tamper
            # check that surfaces the issue here rather than at the
            # gateway), encode the wire-format entries, then base64url-
            # encode the JSON array for the header value.
            import base64
            import json

            wire_entries = memory_store.provenance_for(memory_provenance)
            raw_json = json.dumps(wire_entries, separators=(",", ":")).encode("utf-8")
            headers["X-Intent-Memory-Provenance"] = (
                base64.urlsafe_b64encode(raw_json).rstrip(b"=").decode("ascii")
            )

        try:
            resp = self._client.post(self._url + "/v1/mcp", json=body, headers=headers)
        except httpx.HTTPError as e:
            raise exceptions.GatewayError(f"transport error: {e!s}", code=0, data=None) from e

        if resp.status_code // 100 != 2:
            raise exceptions.GatewayError(
                f"gateway returned HTTP {resp.status_code}",
                code=0,
                data=resp.text[:500] if resp.text else None,
            )

        try:
            payload = resp.json()
        except ValueError as e:
            raise exceptions.GatewayError(f"non-JSON response: {e!s}", code=0) from e

        return _parse_response(payload)

    # --- lifecycle ----------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP client.

        Only meaningful when ``Gateway`` constructed its own client
        (i.e. the caller didn't pass one in). When the caller supplied
        an ``httpx.Client``, ``close`` is a no-op.
        """
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Gateway:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# --- response parsing -------------------------------------------------


def _parse_response(payload: dict) -> ToolCallResult:
    """Translate a JSON-RPC response into a ToolCallResult or raise."""
    if not isinstance(payload, dict):
        raise exceptions.ProtocolError("response is not a JSON object", code=0)

    if "error" in payload and payload["error"] is not None:
        err = payload["error"]
        code = int(err.get("code", 0))
        message = str(err.get("message", "gateway error"))
        data = err.get("data")
        exc_cls = exceptions.for_code(code)
        raise exc_cls(message, code=code, data=data)

    result = payload.get("result")
    if not isinstance(result, dict):
        raise exceptions.ProtocolError("response missing 'result' object", code=0, data=payload)

    raw_content = result.get("content") or []
    content = [
        ContentBlock(type=str(b.get("type", "")), text=str(b.get("text", "")))
        for b in raw_content
        if isinstance(b, dict)
    ]

    ig: IntentGateMetadata | None = None
    raw_ig = result.get("_intentgate")
    if isinstance(raw_ig, dict):
        ig = IntentGateMetadata(
            decision=str(raw_ig.get("decision", "")),
            reason=str(raw_ig.get("reason", "")),
            check=str(raw_ig.get("check", "")),
            latency_ms=int(raw_ig.get("latency_ms", 0)),
        )

    return ToolCallResult(
        content=content,
        is_error=bool(result.get("isError", False)),
        intentgate=ig,
    )
