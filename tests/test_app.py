"""End-to-end app tests. Upstream MCP server is mocked with respx so we can
assert the gateway forwards correctly and strips the Authorization header."""

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


@respx.mock
def test_batch_rejected_not_forwarded(monkeypatch, jwks, rsa_key):
    # A batch containing tools/call must be refused, not proxied, even with a
    # valid token. This is the authorization-bypass case the review flagged.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")  # not even invoke scope
    batch = json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
    ]).encode()
    r = c.post("/mcp", content=batch, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "batch_not_supported"
    assert not route.called  # never reached upstream


@respx.mock
def test_malformed_json_rejected_not_forwarded(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=b"{not valid json", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_json"
    assert not route.called


@respx.mock
def test_object_without_method_rejected(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=b'{"jsonrpc":"2.0","id":1}', headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_jsonrpc"
    assert not route.called


@respx.mock
def test_inbound_identity_header_stripped(monkeypatch, jwks, rsa_key):
    # A client that sets X-Forwarded-Sub itself must not have it reach upstream;
    # the gateway overwrites it with the verified subject.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read", sub="real-user")
    r = c.post(
        "/mcp",
        content=_rpc("tools/list"),
        headers={
            "Authorization": f"Bearer {token}",
            "X-Forwarded-Sub": "admin-spoof",
            "X-User-Id": "spoof-2",
        },
    )
    assert r.status_code == 200
    sent = route.calls.last.request
    assert sent.headers.get("X-Forwarded-Sub") == "real-user"
    assert "x-user-id" not in {k.lower() for k in sent.headers}


@respx.mock
def test_client_request_id_not_trusted(monkeypatch, jwks, rsa_key, caplog):
    # A client-supplied X-Request-Id must not become the gateway's audit
    # correlation id, and must not leak upstream. The gateway mints its own id,
    # forwards that, and records the client's value separately as
    # client_request_id for tracing only.
    import logging

    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:invoke")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post(
            "/mcp",
            content=_rpc("tools/call"),
            headers={"Authorization": f"Bearer {token}", "X-Request-Id": "client-chosen-id"},
        )
    assert r.status_code == 200

    sent = route.calls.last.request
    forwarded = sent.headers.get("X-Request-Id")
    # The gateway forwards its own id, never the client's.
    assert forwarded is not None
    assert forwarded != "client-chosen-id"
    assert len(forwarded) == 32  # uuid4().hex
    # The client's value must not survive anywhere in the upstream headers.
    assert "client-chosen-id" not in " ".join(sent.headers.values())

    # The audit record uses the gateway id as request_id and keeps the client's
    # value as a separate, clearly-labelled field.
    audit_line = [r.message for r in caplog.records if r.name == "mcp_gateway.audit"][-1]
    audit = json.loads(audit_line)
    assert audit["request_id"] == forwarded
    assert audit["request_id"] != "client-chosen-id"
    assert audit["client_request_id"] == "client-chosen-id"


@respx.mock
def test_request_id_minted_when_client_sends_none(monkeypatch, jwks, rsa_key, caplog):
    # With no inbound X-Request-Id, the gateway still mints one and does not
    # emit a client_request_id field.
    import logging

    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:invoke")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    audit_line = [r.message for r in caplog.records if r.name == "mcp_gateway.audit"][-1]
    audit = json.loads(audit_line)
    assert len(audit["request_id"]) == 32
    # client_request_id is dropped from output when None (to_dict strips None).
    assert "client_request_id" not in audit
