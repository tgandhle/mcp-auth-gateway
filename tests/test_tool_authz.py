"""End-to-end tool-call authorization tests.

Exercises the ToolPolicy wired into the proxy: allow, deny, unknown-tool, and
malformed-name, plus the opt-in behavior (no tool policy configured leaves
tools/call to scope alone). Upstream is mocked with respx.

The four claim classes at the HTTP layer:
  allow        -> allow-listed tool, valid invoke token -> 200, forwarded
  deny/unknown -> tool not on allow-list                -> 403 tool_not_allowed
  malformed    -> tools/call with no string params.name -> 400 invalid_tool_call
  bypass       -> covered by the malformed + case tests here and in
                  test_tool_policy.py at the policy level
"""

from __future__ import annotations

import json

import httpx
import jwt
import respx
from fastapi.testclient import TestClient

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.tool_policy import ToolPolicy
from mcp_gateway.verifier import JwksVerifier

UPSTREAM = "http://upstream.test/mcp"


def _settings() -> Settings:
    return Settings(
        upstream_url=UPSTREAM,
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.test/jwks.json",
        host="127.0.0.1",
        port=8080,
    )


def _verifier(monkeypatch, jwks) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER, audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
    )
    from jwt import PyJWKSet

    def fake(token):
        keyset = PyJWKSet.from_dict(jwks)
        header = jwt.get_unverified_header(token)
        for k in keyset.keys:
            if k.key_id == header.get("kid"):
                return k
        raise jwt.PyJWKClientError("no kid")

    monkeypatch.setattr(v._client, "get_signing_key_from_jwt", fake)
    return v


def _client(monkeypatch, jwks, tool_policy: ToolPolicy | None) -> TestClient:
    app = create_app(
        _settings(),
        _verifier(monkeypatch, jwks),
        ScopePolicy.builtin(),
        tool_policy,
    )
    return TestClient(app)


def _tool_call(name) -> bytes:
    # name may be a str, or intentionally malformed (None / non-string) to
    # exercise the 400 path. json.dumps handles None -> null.
    params = {} if name is _OMIT else {"name": name}
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    ).encode()


_OMIT = object()  # sentinel: omit params.name entirely


@respx.mock
def test_allowed_tool_forwarded(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call("read_file"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert route.called


@respx.mock
def test_disallowed_tool_denied_403(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call("delete_file"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["error"] == "tool_not_allowed"
    assert r.json()["tool"] == "delete_file"
    # Denied requests must never reach the upstream.
    assert not route.called


@respx.mock
def test_unknown_tool_denied_by_default(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    # allow-list has one tool; a different, unlisted tool is unknown -> denied.
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call("some_unlisted_tool"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert not route.called


@respx.mock
def test_missing_tool_name_is_400_not_403(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call(_OMIT),
               headers={"Authorization": f"Bearer {token}"})
    # Malformed request: cannot resolve a tool. 400, not an authz 403.
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_tool_call"
    assert not route.called


@respx.mock
def test_non_string_tool_name_is_400(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call(123),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert not route.called


@respx.mock
def test_case_variant_denied(monkeypatch, jwks, rsa_key):
    # A casing variant of an allowed tool is a different tool -> denied.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call("Read_File"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert not route.called


@respx.mock
def test_scope_denied_before_tool_check(monkeypatch, jwks, rsa_key):
    # A read-only token is stopped at the scope check (needs mcp:invoke), so it
    # returns insufficient_scope, not tool_not_allowed, even though the tool is
    # also not on the allow-list. Scope is the outer gate.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    policy = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    c = _client(monkeypatch, jwks, policy)
    token = mint(rsa_key, scope="mcp:read")  # lacks invoke
    r = c.post("/mcp", content=_tool_call("delete_file"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["error"] == "insufficient_scope"
    assert not route.called


@respx.mock
def test_no_tool_policy_leaves_tools_call_to_scope(monkeypatch, jwks, rsa_key):
    # Opt-in: with no tool policy configured, a valid invoke token calling any
    # tool is forwarded. Backward-compatible with pre-tool-authz behavior.
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    c = _client(monkeypatch, jwks, None)  # no tool policy
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call("any_tool_at_all"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert route.called


@respx.mock
def test_empty_allowlist_denies_all_tools(monkeypatch, jwks, rsa_key):
    # A configured-but-empty allow-list (builtin) denies every tool.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, ToolPolicy.builtin())
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_tool_call("read_file"),
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert not route.called
