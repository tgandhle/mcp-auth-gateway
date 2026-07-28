"""End-to-end claim-bound tool-call authorization tests.

Companion to test_tool_authz.py, which covers the unconditional allow-list.
This file covers the second form: rules that bind a set of tools to a set of
claim values, normally group membership.

The classes exercised at the HTTP layer:
  allow          -> caller's group grants the tool                -> 200, forwarded
  wrong group    -> group matches a rule, tool is another's       -> 403 tool_not_allowed
  unknown group  -> no rule matches at all                        -> 403 tool_not_allowed
  absent claim   -> issuer never stamped the claim                -> 403 tool_not_allowed
  unusable claim -> claim present but malformed                   -> 403 tool_not_allowed
In every denial the upstream must not be reached.
"""

from __future__ import annotations

import json

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
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
    return v


def _client(monkeypatch, jwks, tool_policy: ToolPolicy | None) -> TestClient:
    app = create_app(_settings(), _verifier(monkeypatch, jwks), ScopePolicy.builtin(), tool_policy)
    return TestClient(app)


def _tool_call(name: str) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name}}
    ).encode()


def _policy(claim: str = "groups") -> ToolPolicy:
    return ToolPolicy(
        allowed_tools=frozenset({"list_directory"}),
        claim=claim,
        rules=(
            ToolRule("readers", frozenset({"mcp-readers"}), frozenset({"read_file"})),
            ToolRule("operators", frozenset({"mcp-operators"}), frozenset({"write_file"})),
        ),
    )


def _call(c: TestClient, rsa_key, tool: str, **claims):
    token = mint(rsa_key, scope="mcp:invoke", extra_claims=claims or None)
    return c.post("/mcp", content=_tool_call(tool), headers={"Authorization": f"Bearer {token}"})


@respx.mock
def test_group_grants_its_tool(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    c = _client(monkeypatch, jwks, _policy())
    r = _call(c, rsa_key, "read_file", groups=["mcp-readers"])
    assert r.status_code == 200
    assert route.called


@respx.mock
def test_group_does_not_get_another_groups_tool(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, _policy())
    r = _call(c, rsa_key, "write_file", groups=["mcp-readers"])
    assert r.status_code == 403
    assert r.json()["error"] == "tool_not_allowed"
    assert not route.called


@respx.mock
def test_multiple_groups_union_their_tools(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    c = _client(monkeypatch, jwks, _policy())
    both = ["mcp-readers", "mcp-operators"]
    assert _call(c, rsa_key, "read_file", groups=both).status_code == 200
    assert _call(c, rsa_key, "write_file", groups=both).status_code == 200


@respx.mock
def test_unconditional_tool_needs_no_group(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    c = _client(monkeypatch, jwks, _policy())
    r = _call(c, rsa_key, "list_directory")
    assert r.status_code == 200
    assert route.called


@respx.mock
def test_unknown_group_denied(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, _policy())
    r = _call(c, rsa_key, "read_file", groups=["some-other-team"])
    assert r.status_code == 403
    assert not route.called


@respx.mock
def test_absent_groups_claim_denied(monkeypatch, jwks, rsa_key):
    # The ADR-style failure: the issuer never stamped the claim, or stamped it
    # under a different name. Everything is denied, and it must be denied
    # rather than fall open.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, _policy())
    r = _call(c, rsa_key, "read_file")
    assert r.status_code == 403
    assert not route.called


@respx.mock
def test_wrong_claim_name_denies_everything(monkeypatch, jwks, rsa_key):
    # Policy reads memberOf, token carries groups. Same values, no match.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, _policy(claim="memberOf"))
    r = _call(c, rsa_key, "read_file", groups=["mcp-readers"])
    assert r.status_code == 403
    assert not route.called


@respx.mock
def test_malformed_groups_claim_denied_not_coerced(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, _policy())
    r = _call(c, rsa_key, "read_file", groups={"nested": "object"})
    assert r.status_code == 403
    assert not route.called


@respx.mock
def test_scope_still_the_outer_gate(monkeypatch, jwks, rsa_key):
    # A read-only token is stopped at the scope check before any claim is read,
    # even though its group would have granted the tool.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, _policy())
    token = mint(rsa_key, scope="mcp:read", extra_claims={"groups": ["mcp-readers"]})
    r = c.post("/mcp", content=_tool_call("read_file"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["error"] == "insufficient_scope"
    assert not route.called
