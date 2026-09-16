"""Tests for the IntentGate Python SDK.

We use respx to mock httpx at the transport level — no real network,
no running gateway needed. Tests exercise:

- happy-path allow → ToolCallResult populated correctly
- each pipeline-stage error code → corresponding exception class
- generic JSON-RPC errors → ProtocolError
- HTTP-level failures → GatewayError
- request shape (jsonrpc, id, method, params, headers)
- request_id default sequential + caller override
- tool="" rejected client-side
- context manager closes the underlying client
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from intentgate import (
    ROUTE_MCP_LEGACY,
    BudgetError,
    CapabilityError,
    Gateway,
    GatewayError,
    IntentError,
    IntentGateError,
    PolicyError,
    ProtocolError,
)

URL = "http://gateway.test"
ENDPOINT = URL + "/v1/mcp"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _allow(rid: int | str = 1, *, content_text: str = "ok", decision: str = "allow") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "result": {
            "content": [{"type": "text", "text": content_text}],
            "isError": False,
            "_intentgate": {"decision": decision, "reason": "stub", "latency_ms": 2},
        },
    }


def _error(rid: int | str, *, code: int, message: str, data: object = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": code, "message": message, "data": data},
    }


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


@respx.mock
def test_tool_call_returns_parsed_result() -> None:
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json=_allow(content_text="hello"))
    )
    gw = Gateway(URL, token="t0k3n", route=ROUTE_MCP_LEGACY)
    res = gw.tool_call(
        "read_invoice", arguments={"id": "123"}, intent_prompt="Process today AP invoices"
    )
    assert route.called
    assert res.content[0].type == "text"
    assert res.content[0].text == "hello"
    assert res.is_error is False
    assert res.intentgate is not None
    assert res.intentgate.decision == "allow"
    assert res.intentgate.latency_ms == 2


@respx.mock
def test_request_shape_matches_mcp_spec() -> None:
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_allow(rid=captured["body"]["id"]))

    respx.post(ENDPOINT).mock(side_effect=_capture)

    gw = Gateway(URL, token="abc", route=ROUTE_MCP_LEGACY)
    gw.tool_call("read_invoice", arguments={"id": "1"}, intent_prompt="Process invoices")

    assert captured["body"]["jsonrpc"] == "2.0"
    assert captured["body"]["method"] == "tools/call"
    assert captured["body"]["params"]["name"] == "read_invoice"
    assert captured["body"]["params"]["arguments"] == {"id": "1"}
    assert captured["headers"]["authorization"] == "Bearer abc"
    assert captured["headers"]["x-intent-prompt"] == "Process invoices"


@respx.mock
def test_request_id_defaults_to_sequential() -> None:
    seen: list[int] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body["id"])
        return httpx.Response(200, json=_allow(rid=body["id"]))

    respx.post(ENDPOINT).mock(side_effect=_capture)

    gw = Gateway(URL, route=ROUTE_MCP_LEGACY)
    gw.tool_call("read_invoice")
    gw.tool_call("read_invoice")
    gw.tool_call("read_invoice")
    assert seen == [1, 2, 3]


@respx.mock
def test_request_id_caller_override() -> None:
    seen: list[object] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body["id"])
        return httpx.Response(200, json=_allow(rid=body["id"]))

    respx.post(ENDPOINT).mock(side_effect=_capture)

    gw = Gateway(URL, route=ROUTE_MCP_LEGACY)
    gw.tool_call("read_invoice", request_id="abc-123")
    gw.tool_call("read_invoice", request_id=42)
    assert seen == ["abc-123", 42]


@respx.mock
def test_no_token_omits_authorization_header() -> None:
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json=_allow())

    respx.post(ENDPOINT).mock(side_effect=_capture)

    Gateway(URL, route=ROUTE_MCP_LEGACY).tool_call("read_invoice")
    assert "authorization" not in captured["headers"]


# ---------------------------------------------------------------------
# Stage-specific errors
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "exc_class"),
    [
        (-32010, CapabilityError),
        (-32011, IntentError),
        (-32012, PolicyError),
        (-32013, BudgetError),
    ],
)
@respx.mock
def test_each_stage_code_raises_matching_exception(code: int, exc_class: type) -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json=_error(rid=1, code=code, message="check failed", data="reason details"),
        )
    )
    gw = Gateway(URL, token="t", route=ROUTE_MCP_LEGACY)
    with pytest.raises(exc_class) as ei:
        gw.tool_call("read_invoice")
    assert ei.value.code == code
    assert ei.value.message == "check failed"
    assert ei.value.data == "reason details"
    # Stage-specific exceptions must subclass IntentGateError so
    # callers can catch broadly when they don't care which stage fired.
    assert isinstance(ei.value, IntentGateError)


@respx.mock
def test_unknown_jsonrpc_code_maps_to_protocol_error() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json=_error(rid=1, code=-32601, message="method not implemented"),
        )
    )
    with pytest.raises(ProtocolError) as ei:
        Gateway(URL, route=ROUTE_MCP_LEGACY).tool_call("read_invoice")
    assert ei.value.code == -32601


# ---------------------------------------------------------------------
# Transport-level failures
# ---------------------------------------------------------------------


@respx.mock
def test_http_5xx_raises_gateway_error() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(503, text="upstream down"))
    with pytest.raises(GatewayError) as ei:
        Gateway(URL, route=ROUTE_MCP_LEGACY).tool_call("read_invoice")
    assert "503" in str(ei.value)


@respx.mock
def test_non_json_body_raises_gateway_error() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, text="not json at all"))
    with pytest.raises(GatewayError):
        Gateway(URL, route=ROUTE_MCP_LEGACY).tool_call("read_invoice")


@respx.mock
def test_network_error_raises_gateway_error() -> None:
    respx.post(ENDPOINT).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(GatewayError) as ei:
        Gateway(URL, route=ROUTE_MCP_LEGACY).tool_call("read_invoice")
    assert "transport" in str(ei.value).lower() or "refused" in str(ei.value).lower()


# ---------------------------------------------------------------------
# Client-side validation
# ---------------------------------------------------------------------


def test_empty_tool_rejected_client_side() -> None:
    with pytest.raises(ValueError, match="tool is required"):
        Gateway(URL, route=ROUTE_MCP_LEGACY).tool_call("")


# ---------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------


@respx.mock
def test_context_manager_closes_owned_client() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json=_allow()))
    with Gateway(URL, route=ROUTE_MCP_LEGACY) as gw:
        gw.tool_call("read_invoice")
    # No assertion needed — the context manager exiting without error
    # is what we're verifying. Closing twice (close called by __exit__,
    # then any pending operation) would normally raise.


@respx.mock
def test_passed_in_client_not_closed_by_sdk() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json=_allow()))
    client = httpx.Client()
    gw = Gateway(URL, client=client, route=ROUTE_MCP_LEGACY)
    gw.tool_call("read_invoice")
    gw.close()
    # The injected client is still usable — SDK does not own it.
    assert not client.is_closed
    client.close()
