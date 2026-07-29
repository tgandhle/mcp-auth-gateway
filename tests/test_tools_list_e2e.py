"""Integration tests for tools/list filtering through the proxy."""

from __future__ import annotations

import gzip
import json
import logging

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.tool_policy import ToolPolicy, ToolRule
from mcp_gateway.verifier import JwksVerifier

UPSTREAM = "http://upstream.test/mcp"
LIST_BODY = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
).encode()


def _settings(**overrides) -> Settings:
    values = {
        "upstream_url": UPSTREAM,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "https://issuer.test/jwks.json",
    }
    values.update(overrides)
    return Settings(**values)


def _verifier(monkeypatch, jwks) -> JwksVerifier:
    verifier = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
    )
    monkeypatch.setattr(verifier, "_fetch_jwks", lambda: jwks)
    return verifier


def _policy() -> ToolPolicy:
    return ToolPolicy(
        allowed_tools=frozenset({"list_directory"}),
        claim="groups",
        rules=(
            ToolRule(
                "readers",
                frozenset({"readers"}),
                frozenset({"read_file"}),
            ),
        ),
    )


def _client(monkeypatch, jwks, policy, **overrides) -> TestClient:
    app = create_app(
        _settings(**overrides),
        _verifier(monkeypatch, jwks),
        ScopePolicy.builtin(),
        policy,
    )
    return TestClient(app)


def _tool(name: str) -> dict:
    return {"name": name, "description": name}


def _result(tools, **extra) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": tools, **extra},
    }


def _post(client: TestClient, rsa_key):
    token = mint(
        rsa_key,
        scope="mcp:read",
        extra_claims={"groups": ["readers"]},
    )
    return client.post(
        "/mcp",
        content=LIST_BODY,
        headers={"Authorization": f"Bearer {token}"},
    )


@respx.mock
def test_filters_list_and_rebuilds_headers(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            json=_result([_tool("read_file"), _tool("write_file")]),
            headers={
                "ETag": '"old"',
                "X-Upstream": "drop",
                "Mcp-Session-Id": "session-1",
            },
        )
    )
    response = _post(
        _client(monkeypatch, jwks, _policy()),
        rsa_key,
    )
    assert response.status_code == 200
    assert [
        tool["name"]
        for tool in response.json()["result"]["tools"]
    ] == ["read_file"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["mcp-session-id"] == "session-1"
    assert "etag" not in response.headers
    assert "x-upstream" not in response.headers
    assert int(response.headers["content-length"]) == len(response.content)


@respx.mock
def test_audit_records_counts_without_tool_names(
    monkeypatch,
    jwks,
    rsa_key,
    caplog,
):
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            json=_result([_tool("read_file"), _tool("write_file")]),
        )
    )
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        response = _post(
            _client(monkeypatch, jwks, _policy()),
            rsa_key,
        )
    assert response.status_code == 200
    event = json.loads(
        [
            record.message
            for record in caplog.records
            if record.name == "mcp_gateway.audit"
        ][-1]
    )
    assert event["tools_returned"] == 1
    assert event["tools_filtered"] == 1
    assert "read_file" not in json.dumps(event)
    assert "write_file" not in json.dumps(event)


@respx.mock
def test_gzip_is_decoded_filtered_and_not_relabelled(monkeypatch, jwks, rsa_key):
    raw = json.dumps(
        _result([_tool("read_file"), _tool("write_file")])
    ).encode()
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            content=gzip.compress(raw),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
    )
    response = _post(
        _client(monkeypatch, jwks, _policy()),
        rsa_key,
    )
    assert response.status_code == 200
    assert [
        tool["name"]
        for tool in response.json()["result"]["tools"]
    ] == ["read_file"]
    assert "content-encoding" not in response.headers


@respx.mock
def test_empty_page_preserves_next_cursor(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            json=_result([_tool("write_file")], nextCursor="page-2"),
        )
    )
    response = _post(
        _client(monkeypatch, jwks, _policy()),
        rsa_key,
    )
    assert response.json()["result"] == {
        "tools": [],
        "nextCursor": "page-2",
    }


@respx.mock
def test_sse_fails_closed_without_leaking(monkeypatch, jwks, rsa_key):
    leak = (
        'data: {"jsonrpc":"2.0","id":1,"result":'
        '{"tools":[{"name":"write_file"}]}}\n\n'
    )
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            text=leak,
            headers={"Content-Type": "text/event-stream"},
        )
    )
    response = _post(
        _client(monkeypatch, jwks, _policy()),
        rsa_key,
    )
    assert response.status_code == 502
    assert (
        response.json()["error"]
        == "tools_list_filter_unsupported_media_type"
    )
    assert "write_file" not in response.text


@respx.mock
def test_decoded_body_over_cap_fails_closed(monkeypatch, jwks, rsa_key):
    raw = json.dumps(
        _result([_tool("read_file") for _ in range(30)])
    ).encode()
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            content=gzip.compress(raw),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
    )
    response = _post(
        _client(
            monkeypatch,
            jwks,
            _policy(),
            max_tools_list_bytes=256,
        ),
        rsa_key,
    )
    assert response.status_code == 502
    assert response.json()["error"] == "tools_list_response_too_large"
    assert "read_file" not in response.text


@respx.mock
def test_malformed_and_http_200_error_fail_closed(
    monkeypatch,
    jwks,
    rsa_key,
    caplog,
):
    route = respx.post(UPSTREAM)
    client = _client(monkeypatch, jwks, _policy())
    route.mock(
        return_value=httpx.Response(
            200,
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    )
    malformed = _post(client, rsa_key)
    assert malformed.status_code == 502
    assert malformed.json()["error"] == "tools_list_filter_failed"

    route.mock(
        return_value=httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32603,
                    "data": {"tools": ["write_file"]},
                },
            },
        )
    )
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        error = _post(client, rsa_key)
    assert error.status_code == 502
    assert error.json()["error"] == "tools_list_upstream_error"
    assert "write_file" not in error.text
    event = json.loads(
        [
            record.message
            for record in caplog.records
            if record.name == "mcp_gateway.audit"
        ][-1]
    )
    assert event["error_code"] == "tools_list_upstream_error"
    assert "upstream returned a JSON-RPC error" in event["reason"]


@respx.mock
def test_no_policy_and_non_200_keep_streaming_behavior(
    monkeypatch,
    jwks,
    rsa_key,
):
    route = respx.post(UPSTREAM)
    route.mock(
        return_value=httpx.Response(
            200,
            json=_result([_tool("read_file"), _tool("write_file")]),
        )
    )
    unfiltered = _post(
        _client(monkeypatch, jwks, None),
        rsa_key,
    )
    assert len(unfiltered.json()["result"]["tools"]) == 2

    route.mock(
        return_value=httpx.Response(
            503,
            json={"detail": "upstream unavailable"},
        )
    )
    unavailable = _post(
        _client(monkeypatch, jwks, _policy()),
        rsa_key,
    )
    assert unavailable.status_code == 503


@respx.mock
def test_other_methods_remain_on_streaming_path(
    monkeypatch,
    jwks,
    rsa_key,
):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/list"}
    ).encode()
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"resources": [{"name": "anything"}]},
            },
        )
    )
    client = _client(monkeypatch, jwks, _policy())
    token = mint(
        rsa_key,
        scope="mcp:read",
        extra_claims={"groups": ["readers"]},
    )
    response = client.post(
        "/mcp",
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["result"]["resources"][0]["name"] == "anything"


@respx.mock
def test_visible_tools_are_callable_and_removed_tools_are_denied(
    monkeypatch,
    jwks,
    rsa_key,
):
    advertised = [
        _tool("read_file"),
        _tool("write_file"),
        _tool("list_directory"),
    ]
    route = respx.post(UPSTREAM)
    route.mock(return_value=httpx.Response(200, json=_result(advertised)))
    client = _client(monkeypatch, jwks, _policy())
    token = mint(
        rsa_key,
        scope="mcp:read mcp:invoke",
        extra_claims={"groups": ["readers"]},
    )
    headers = {"Authorization": f"Bearer {token}"}
    listed = client.post("/mcp", content=LIST_BODY, headers=headers)
    visible = {
        tool["name"]
        for tool in listed.json()["result"]["tools"]
    }
    removed = {tool["name"] for tool in advertised} - visible

    route.mock(
        return_value=httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": "ok"},
        )
    )
    for name in visible:
        call = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name},
            }
        ).encode()
        assert client.post("/mcp", content=call, headers=headers).status_code == 200
    for name in removed:
        call = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name},
            }
        ).encode()
        denied = client.post("/mcp", content=call, headers=headers)
        assert denied.status_code == 403
        assert denied.json()["error"] == "tool_not_allowed"
