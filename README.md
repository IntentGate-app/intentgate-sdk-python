# IntentGate Python SDK

[![CI](https://github.com/IntentGate-app/intentgate-sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/IntentGate-app/intentgate-sdk-python/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/intentgate.svg)](https://pypi.org/project/intentgate/)
[![Python versions](https://img.shields.io/pypi/pyversions/intentgate.svg)](https://pypi.org/project/intentgate/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

The official Python client for the
[IntentGate authorization gateway](https://github.com/IntentGate-app/intentgate-gateway).

## Companion repositories

| Repo | Purpose |
| ---- | ------- |
| [intentgate-gateway](https://github.com/IntentGate-app/intentgate-gateway) | Go gateway with the four-check pipeline. The thing this SDK talks to. |
| [intentgate-extractor](https://github.com/IntentGate-app/intentgate-extractor) | Optional FastAPI service that turns user prompts into structured intent. |
| [intentgate-sdk-python](https://github.com/IntentGate-app/intentgate-sdk-python) | Python SDK for agents (this repo). |
| [intentgate-helm](https://github.com/IntentGate-app/intentgate-helm) | Helm chart that deploys the gateway, extractor, and Redis to Kubernetes. |

## What it is

A thin client that lets your AI agent call tools through the
IntentGate gateway with a Pythonic API. The SDK handles the JSON-RPC
envelope, the Bearer token, the `X-Intent-Prompt` header, and turns
gateway error responses into typed Python exceptions.

## Three lines of agent code

```python
from intentgate import Gateway

gw = Gateway(url="http://localhost:8080", token=os.environ["INTENTGATE_TOKEN"])
result = gw.tool_call(
    "read_invoice",
    arguments={"id": "123"},
    intent_prompt="Process today's AP invoices",
)
```

That's it. Construct once, call as many times as you like. When the
gateway blocks the call, `tool_call` raises a typed exception you can
catch.

## Install

```sh
pip install intentgate
```

Released versions are published to [PyPI](https://pypi.org/project/intentgate/)
on every `vX.Y.Z` git tag via signed OIDC trusted publishing — see
`.github/workflows/release.yml`.

To install the development tip:

```sh
pip install git+https://github.com/IntentGate-app/intentgate-sdk-python.git
```

## Exception hierarchy

Every blocked call raises an exception. The class tells you which
gateway check fired:

| Exception          | JSON-RPC code | When                                                                              |
| ------------------ | ------------- | --------------------------------------------------------------------------------- |
| `CapabilityError`  | `-32010`      | Token signature invalid, expired, agent mismatch, tool not in caveat allow-list.  |
| `IntentError`      | `-32011`      | Tool isn't in the intent extracted from the user prompt.                          |
| `PolicyError`      | `-32012`      | OPA policy returned deny. The reason carries the Rego rule's explanation.         |
| `BudgetError`      | `-32013`      | A `max_calls` caveat in the token has been exhausted.                             |
| `ProtocolError`    | other JSON-RPC| Malformed request, method not found, etc. Usually means an SDK ↔ gateway version mismatch. |
| `GatewayError`     | n/a           | Couldn't reach the gateway, or got a non-2xx HTTP response.                       |
| `IntentGateError`  | (base)        | Catch this if you don't care which check fired.                                   |

```python
from intentgate import Gateway, PolicyError, BudgetError, IntentGateError

try:
    result = gw.tool_call("transfer_funds", arguments={"amount_eur": 50_000})
except PolicyError as e:
    log.warning("policy blocked: %s (%s)", e.message, e.data)
except BudgetError:
    log.error("agent ran out of budgeted calls")
except IntentGateError as e:
    # everything else: re-raise or surface to user
    raise
```

## API reference

### `Gateway(url, token=None, *, timeout=10.0, client=None)`

Construct a client.

- `url` — base URL of the gateway, e.g. `http://localhost:8080`. Trailing slash is tolerated.
- `token` — capability token from `igctl mint`. When `None`, no `Authorization` header is sent.
- `timeout` — per-request timeout in seconds.
- `client` — pre-configured `httpx.Client` for advanced use (test injection, custom transports). The SDK only closes the client it created itself.

`Gateway` is also a context manager:

```python
with Gateway(url="...", token="...") as gw:
    gw.tool_call(...)
# client closed automatically
```

### `Gateway.tool_call(tool, arguments=None, *, intent_prompt=None, request_id=None) -> ToolCallResult`

Invoke a tool through the gateway.

- `tool` — tool name like `"read_invoice"`. Required.
- `arguments` — pass-through dict to the tool. The gateway logs only the keys, never the values.
- `intent_prompt` — the user's natural-language request. Sent as the `X-Intent-Prompt` header. Strongly recommended in production; without it the intent check is skipped (or denies in strict mode).
- `request_id` — JSON-RPC `id`. Defaults to a per-Gateway sequential integer.

Returns a `ToolCallResult` with:

- `content: list[ContentBlock]` — what the upstream tool returned (MCP shape, currently `type="text"` only).
- `is_error: bool` — MCP-level "tool reported an error" flag (distinct from gateway-level errors that raise exceptions).
- `intentgate: IntentGateMetadata | None` — gateway decision summary (`decision`, `reason`, `check`, `latency_ms`).

## Typical usage in an agent

The pitch's "three lines" referred to the SDK setup. In practice an
agent wraps each tool through the gateway:

```python
from intentgate import Gateway

class FinanceAgent:
    def __init__(self, gateway_url: str, token: str, prompt: str) -> None:
        self.gw = Gateway(url=gateway_url, token=token)
        self.prompt = prompt

    def read_invoice(self, invoice_id: str) -> str:
        result = self.gw.tool_call(
            "read_invoice",
            arguments={"id": invoice_id},
            intent_prompt=self.prompt,
        )
        return result.content[0].text

    def transfer_funds(self, amount_eur: int, recipient: str) -> None:
        self.gw.tool_call(
            "transfer_funds",
            arguments={"amount_eur": amount_eur, "recipient": recipient},
            intent_prompt=self.prompt,
        )
```

## Develop locally

```sh
make install     # creates .venv, installs -e ".[dev]"
make lint        # ruff check + ruff format --check
make lint-fix    # auto-fix lint + format
make test        # pytest
make build       # sdist + wheel into dist/ (sanity check before tagging a release)
```

Tests use `respx` to mock httpx at the transport level — no real
network required, no running gateway needed.

## Project layout

```
src/intentgate/
  __init__.py         # public API: Gateway, exceptions, dataclasses
  client.py           # Gateway client + ToolCallResult dataclasses
  exceptions.py       # IntentGateError hierarchy (CapabilityError, IntentError, ...)
tests/
  test_client.py      # respx-mocked HTTP behavior
.github/workflows/    # CI (lint + tests across Python 3.10–3.13) and release (publish to PyPI on tag)
Makefile              # install / lint / lint-fix / test / build / clean
pyproject.toml        # hatchling build, ruff config, pytest config
```

## Versioning

Pre-release. The wire protocol with the gateway is stable (JSON-RPC
2.0 + the IntentGate-specific error codes), but the Python API surface
may change before `1.0.0`. Pin to a minor version when integrating.

## Contributing

Apache 2.0 and welcomes community contributions. A formal `CONTRIBUTING.md`
is coming with the v0.1 → v1.0 polish pass. For now, please open an
issue to discuss any non-trivial change before sending a PR.

## Security

If you find a security vulnerability, please **do not** open a public
issue. Email security@intentgate.app (or open a GitHub Security Advisory
on this repo) and we'll respond within two business days.
