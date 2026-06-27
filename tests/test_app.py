"""End-to-end app tests. Upstream MCP server is mocked with respx so we can
assert the gateway forwards correctly and strips the Authorization header."""

from __future__ import annotations

import json

import httpx
import jwt
import pytest
import respx
from fastapi.testclient import TestClient

from mcp_gateway.app import create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.verifier import JwksVerifier
from conftest import ISSUER, AUDIENCE, KID, mint


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


def _client(monkeypatch, jwks) -> TestClient:
    app = create_app(_settings(), _verifier(monkeypatch, jwks), ScopePolicy.builtin())
    return TestClient(app)


def _rpc(method: str) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()


def test_missing_token_401(monkeypatch, jwks):
    c = _client(monkeypatch, jwks)
    r = c.post("/mcp", content=_rpc("tools/list"))
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")


def test_invalid_token_401(monkeypatch, jwks):
    c = _client(monkeypatch, jwks)
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


@respx.mock
def test_valid_read_token_proxied(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    )
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert route.called
    # Authorization header must NOT be forwarded upstream; identity goes via X-Forwarded-*.
    sent = route.calls.last.request
    assert "authorization" not in {k.lower() for k in sent.headers}
    assert sent.headers.get("X-Forwarded-Sub") == "user-123"


@respx.mock
def test_read_token_cannot_invoke(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")  # lacks mcp:invoke
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers.get("www-authenticate", "")


@respx.mock
def test_invoke_token_can_invoke(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "done"})
    )
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert route.called


def test_metadata_endpoint_public(monkeypatch, jwks):
    c = _client(monkeypatch, jwks)
    r = c.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == AUDIENCE
    assert ISSUER in body["authorization_servers"]


@respx.mock
def test_upstream_down_502(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(side_effect=httpx.ConnectError("refused"))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 502
